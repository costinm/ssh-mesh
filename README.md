# cert-ssh

This is an opinionated set of SSH tools, intended for use with 
Istio, CloudRun, mobile and other environments, with a Istio-like
certificate-based infrastructure.

The SSH CA maintains a root CA (backed by a k8s Secret), and signs
host and user certificates based on the K8S JWT or istio mTLS 
certificate.

The client (sshc), server(sshd) use the SSH CA to setup the config.
Both are equivalent and exchangeable with OpenSSH (TODO: dropbear).
A CLI command is provided to initiate config for OpenSSH.

# ssh-signerd

Signs SSH certificates for host and client.

This is similar with Istiod/Citadel signing of workload certificates,
but for SSH certificates.

Authentication uses same K8S JWT token as Istiod-CA.

In a secure network (Wireguard, IPSec, other secure CNIs and VPNs) the 
token is not required - the certificate will be issued for the 
IP address, which is expected to be secure and stable. 


Host certs use the canonical service, namespace and domain.
User certs use the KSA, namespace and domain.



## Istio integration  

The components are intended to be used with Istio, which provides
the identity and security for the SSH cert signing. 



```shell

```

## CloudRun

All 3 components can also be used with CloudRun, either directly
or using Istio. 

```shell

```



# Code organization

- sshca - gRPC client and server for signing SSH certificates.
Because the signing code is very small and doesn't add deps, it is in the same directory.
  
- sshd - ssh server, with exec, shell ('pty'), port forwarding and sftp support.
All authentication is based on certificates - both host and user auth.
  
- sshca/ssh-signer - CLI to generate ssh configs for typical SSH client.

# Usage with Openssh


```shell
# Use real domain ( with real certificate )
# SSH_CA=sshca.example.com:443
SSH_CA=localhost:14001

go install github.com/costinm/cert-ssh/sshca/ssh-signer

mkdir ${HOME}/.ssh/${SSH_CA}
cd ${HOME}/.ssh/${SSH_CA}

# Will create both user and host config files for ssh
ssh-signer

ssh -v  -p 15022   -i id_ecdsa  -o "UserKnownHostsFile known_hosts" costin@localhost

# To disable host checking:
# -F /dev/null -o "UserKnownHostsFile /dev/null" -o StrictHostKeyChecking=no
```

