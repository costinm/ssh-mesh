# cert-ssh

This is an opinionated SSH library, with a Istio-like
certificate-based infrastructure and hbone-compatible transport.

The SSH CA maintains a root CA (backed by a k8s or other Secret), and signs
host and user certificates. The format is similar with Spiffe:

  ${KSA}@${Namespace}.svc.${TrustDomain}
  ${KSA}.${Namespace}.svc.${TrustDomain}

The client (sshc), server(sshd) use the SSH CA to setup the config.

Library can interoperate with OpenSSH and dropbear clients and servers.

Both client and server can wrap a net.Conn - which may be a tunnel.

# Mesh communication

Client will initiate a forward accept, with :0 port. Server will accept
forward request of this type but will not open new ports.

Clients can register in discovery the assigned IP and port - if the
server is ssh-mesh, it will be the HBONE port, if it is a regular 
ssh server - a random port. 

The forwarded requests are expected to be HTTP/2 / TLS, with SNI 
header encoding the destination.

# Certificate signing

This is similar with Istiod/Citadel signing of workload certificates,
but for SSH certificates. The library only provides signing primitives, 
it is intentded as an extension to an Istio-compatible signer.

Authentication uses same K8S JWT token as Istiod-CA.
In a secure network (Wireguard, IPSec, other secure CNIs and VPNs) the 
token is not required - the certificate will be issued for the 
IP address, which is expected to be secure and stable. 

# Usage with Openssh


```shell

ssh -v  -p 15022   -i id_ecdsa  -o "UserKnownHostsFile known_hosts" costin@localhost

# To disable host checking:
# -F /dev/null -o "UserKnownHostsFile /dev/null" -o StrictHostKeyChecking=no
```

# Alternatives

- use an extension is appealing - for example allow servers to initiate direct-tcpip 
channels will make the code simpler. However interop with existing ssh tools is the
main goal - otherwise H2/H3 should be used.

- provide a rich API with support for global requests, extensions, etc - nice but 
not required.
