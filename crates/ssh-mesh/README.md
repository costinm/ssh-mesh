# SSH Mesh

The create combines russh and H2 stacks for a common 'mesh' transport, providing 
encryption and authentication on the wire along with forwarding.

It does act as a SSH server and client - including support for program execution 
and PTYs, remote and local forwarding, but with mesh style configuration: a single
key per host (not per user), authorized keys and configs handled at mesh level instead 
of user.

## mesh-init

The 'root' features are separated into mesh-init. SSH-mesh crate has heavy networking
dependencies - it should never run as root.

## Gateway and protocol adaptation

## Local routing

For inbound streams, the routing is delegated to mesh-init. 