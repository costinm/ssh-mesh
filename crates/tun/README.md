# TUN support

The intent of TUN is to support:

- Android VPN
- user-only VMs - no root - as an addition/alternative to passt, with further encryption and tunneling.

Note that Passt is a better option - it is designed for Qemu in UDS or vhost-user
mode, with no CAN_NET_ADMIN (which tun requires). vhost-device-net provides a library for handling the vhost-user.

The passt integration - UDS receiving L2 frames from qemu/crosvm - can also be 
used with the TUN interface. 

The smoltcp library is used for some experimental termination - but the intent is
to use it to help 'sniff' the content and route to a H2 or ztunnel VM/namespace some
of the traffic.

## Passt and Pasta

The core idea in Pasta is to use AF_SOCKET instead of TPROXY/REDIRECT. This requires
the same permissions in the container namespace - not so different from ztunnel or
sidecar as permissions - but it avoids going trough the TCP stack to re-create a
stream, along with contrack, double port use, etc.

The core idea in Passt is also to avoid a full TCP stack by doing light parsing/generation for the packets between VM/container and host - while using the host
real address and ports for the connection.

Besides the performance benefits - the infrastructure doesn't have to handle the
VM VIPs - only host IPs, and with a mesh overlay the only connections are H2 or SSH
multiplexed connections between hosts.

The main change between original Passt/Pasta and this package is the handling of 
the host networking - instead of proxying to an actual TCP socket for egress, it 
is going to the ssh-mesh server (or ztunnel in future).

This is obviously an experiment - I love Passt/Pasta simplicity and focus, but 
policy and encryption are also important, and having the host traffic go trough 
ztunnel/etc is cutting both performance/simplicity and is losing information needed
by mesh.


## TODO

Transform this package into a subset of Istio ztunnel - but using TUN and vhost-user 
for capture instead of iptables, and a passt socket handling instead of terminating TCP and starting a second TCP stream over H2/HBONE.

The flow will be:
1. TUN or vhost-user capture TCP/UDP connections from a VM or namespace.
2. the mesh-tun creates the equivalent passt sockets - with hooks for policies (limits, throttling, monitoring) 

[] Implement the Passt mechanisms in the TUN - so Android (or the VM or host using TUN) use regular sockets on the public net, while still intercepting the traffic


[] add vhost-user mode, with multiple VMs supported (unlike passt) - supporting
coordianted policies across all VMs.

[] map the passt-like 'sockets' to SSH/H2 tunnels - and decode/route this on the other end. In this mode, for mesh-local traffic it is like hbone - but with raw IP
frames in the stream, without passing through the extra TCP stack. This adds encryption and the common policy control - like ztunnel

