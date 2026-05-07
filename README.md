# ssh-mesh

This is basically local 'serverless' combined with Android and Istio concepts.

Each node (physical machine or VM) runs a mesh-init server that coordinates the process
lifecycle - it should be the only component that requires root and is as small as
it can be, no features that can be implemented in a non-root process.

The nodes are passive - the config is pushed or pulled (git or remote filesystems) and
stored on local disk. 

The K8S concept of 'Pod' is used - as a set of isolated processes running as the
same user ID. This is similar to an Android application, with minimal access to other
pods and the host.


## SSH and HTTP transports

SSH is used as a base L4 proxy, with Istio-like certificates - both ends can use regular
ssh client/server implementations. ssh-mesh server just simplifies the 'opinionated'
layout and removes the ability to use it in an arbitrary way. It also supports
HTTP tunneling - both 'SSH of HTTP/2', SSH over websocket and full Istio-like tunnels
over H2C plus websocket. 

A ssh-mesh server includes both client and server, and can maintain connections to
other nodes and forward ports using a local http API.  

Extra features for ssh-mesh server side:
- allows multiple clients to 'remote forward' (-R) ports 22, 80 and 443

Features for ssh-mesh client side:
- auto-register the forwarding ports and maintains connection. 

## Opinionated layout

Each workload (or namespace, application, profile, pod) has a home directory, identified with $HOME. By default this is in /home/$USER - where USER is the name of the application.  On android - it is the /data/... standard
location.

All relevant files in $HOME. Or almost - binaries can be in /nix or some OCI rootfs, /apex - or /opt. They can also be in $HOME/bin - mounted from a signed Erofs disk.

Configs used by mesh go to $HOME/.config - with subdirectories for each component. All components run 
with the user ID or subuids for the main UID.

Other locations: $HOME/.logs, $HOME/.run, $HOME/.cache, $HOME/.ssh (all secrets go here, not only ssh).

## No background daemons

The goal is to not allow installed application to run as daemons - instead they should run as Jobs, UI/Frontend apps or Services, activated by events and frozen/terminated when idle. 


## User mode

mesh-init can also run as a normal user - for example in a K8S pod or container running
as not-root user. It will manage processes and may use subuid - but with less power. This is intended for containers and development, the main use case is running as root to allow changing the UID of the process.

In user mode it can delegate execution to bubblewrap or podman or similar tools, it is a solved problem. Note that root in a user container has access to user home/ssh if shared,
and all containers share same IDs.
