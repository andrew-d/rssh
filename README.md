# rssh

This program is a simple reverse shell over SSH.  Essentially, it opens a
connection to a remote computer over SSH, starts listening on a port on the
remote computer, and when connections are made to that port, starts a command
locally and copies data to and from it.

## Why?

This is useful in the cases where you cannot listen on the local computer
(restricted firewall, NAT, whatever), but still want to use SSH.  Using this
command, you can emulate this:

On the local machine (where you want the shell):

    ./rssh -a '127.0.0.1:2222' -u user -i id_remote_rsa IP.OF.REMOTE.MACHINE

This creates a listening socket on the `localhost` of the remote machine.
Then, on the remote machine, you can run:

    nc -c 127.0.0.1 2222

Which will give you shell.  Note that the `-c` flag is important, to ensure
that EOF is properly propagated over the network connection and to the remote
host.
