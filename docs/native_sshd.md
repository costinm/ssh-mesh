# Using native ssh for mesh

SSH has been used for secure communication for a very long time, including tunnels and remote file access. OpenSSH and Dropbear are good enough for small servers - including OpenWRT routers or small containers using SSH mainly for control and management.

This document starts to document how to use dropbear/openssh instead of ssh-mesh
with similar opinionated layout.

## User per service

One of the core ideas is to split all services - even those running on behalf of a user - to separate directories, like Android, without access to user HOME.

So we need to create a /home/APP or /home/USER_APP (this is not really meant for
systems with multiple 'users'). It is possible to use sub-uids, but more complicated than it should be and harder to manage. 

A script can create the users/dirs and set the .ssh directory.

## File access

- create user - $USER
- create a dir, owned by root - $FILE_ROOT
- create the home dir - owned by user, with authorized keys


```
UsePAM no


Match User $USER
  ChrootDirectory $FILE_ROOT
  ForceCommand internal-sftp
  # Yes to allow the user to use the device as jump or forwarder.
  AllowTcpForwarding no
  X11Forwarding no
  PermitTTY no
  PermitTunnel no
  
  
```

# SSH Clients and ssh-mesh

ssh-mesh supports control master protocol - but requires a separate command 
to 'pair' and create the UDS socket. 

The ControlMaster protocol is very interesting - and similar to what the JSON protocol used by this package is doing. It uses u32 LEN, u32 TYPE framing, like
SSH, with a 'client request ID'.

Many commands get an immediate response. Forward requests create local listeners that a client can use to talk with the other side, remote forwards creates remote listener that forward to a local listener - that's standard SSH and can be controlled trough the SSH protocol.

The 'proxy' mode is also interesting - client sends/receives SSH frames (plain
text), with full access to the protocol - and it can be forwarded as plain text.
Server still translates channel numbers (across clients). Not supported right
now in the mesh - but may be. It is a great way to separate the encryption
layer - could be used to move more logic to mesh-init and minimize code in the
networking/encryption layer.

## Passenger session

The interesting one is 'passenger' mode - passing a stdio file descriptor, 
than wait. The server is reading/writing to the passed sockets. This is used for 'sessions' (shell) or forwarding.

MUX_C_NEW_SESSION takes 'want tty' flag, termina type, command and list of env -
along with 3 descriptors.

The 'mesh' crates implement a similar protocol, but with arbitrary number of sockets. The extended activation does a similar thing with accepted connections.

"Session" is the SSH term for the shell stream. It has an exit value at the end,
and the client may mux multiple sessions. Server may also fail to create a pty -
client would need to fallback.

Same mechanism for STDIO_FWD - but 2 sockets.

## Possible extensions

The biggest problem is the one control master per peer. There is no way for a client to connect to the master and indicate it wants a specific peer to be 
connected and use. 

One possible trick is to use an env in the session, and special naming for hosts
in the FWD.

Note that port=-2 indicates UDS - but the format for UDS can be 'mangled' with
prefixes like /virtio/ or /mesh/NAME/.....

The end result is using a ssh client pointing the ssh-mesh or even mesh-init main 'control master' socket, using normal forwarding requests - with the ssh-mesh or mesh-init picking a connection and opening a stream.

Security for ssh-mesh is based on host-to-host trust, each host can assert 
user@myhost.domain.mesh (not necessarily identical with user@desthost), and
most policies can be enforced by the mesh nodes.

As binary protocol the mux (and ssh transport) is as good as any framing protocol. Bad alignment, etc - but not worse than protobuf or others.

Detection: [0 0 0 8] [0 0 0 1] 0 0 0 4 ( 'hello' version = 4 )
Since a legit hello will never be large - 0 0 0 is enough to switch to 'u32 Len Type Value' mode, with 'type=1' v=4 indicating the control master and other
binary protocols possible, in particular CBOR.


## H2T

This includes websocket and H2 - as possible tunnels for openssh clients.
May also be used for testing. It is standalone, no ssh-mesh server used - 
as such not very efficient and needs access to some apikeys.

A better option: turn it into a 'passenger', with a mangled forward like
UDS /h2/DEST - leaving ssh-mesh and mesh-init figure the tunnel route and
transport. This is implemented by the dependency-light `mesh` client.

## mesh client

`mesh` owns the former `sshmc` ControlMaster client. `mux:///path` and `-S
path` use the native local mux protocol; unresolved bare hosts fall back to the
real OpenSSH client. Explicit UDS/TCP endpoints use the common JSON/text/CBOR
RPC codecs instead of service-specific client code.

## meshkeys

Currently standalone - but may be turned into a service, using the common
client for interactions. Mostly equivalent to openssh/openssl, focused on certs.
