# ssh-mesh

This is an opinionated SSH library and L4 proxy, with a Istio-like
certificate and JWT based authentication and providing a secure L4 transport.

The implementation is compatible with OpenSSH, dropbear and other libraries
and clients/servers. 

Special features for sshm in gateway mode:
- allows multiple clients to remote forward 22, 80 and 443
- allows the password to be a JWT token with audience ssh://HOSTNAME, issued
  by one of the configured issuers (with normalization for k8s and google tokens)
- certificate based authentication

In progress/TODO:
- auto-register the forwarding clients in EndpointSlice and support sharding (for scale).
  Until this is done - a single (large) instance must be run per IP. In K8S it 
  means 1 replica if LoadBalancer service is used.

Special features for sshm in workload mode:
- auto-register the forwarding ports and maintains connection. This is optional
  and should be used for CloudRun or home machines behind a firewall.
- can chain a second command, so it can be added to a docker image and Pod.
- includes a sshd server and exec/shell for the configured owner key, equivalent
  to running openssh or dropbear ssh server with custom config and as regular user.

A SSH CA maintains a root CA (backed by a k8s or other Secret), and signs
host and user certificates. The format has same information as Istio Spiffe,
a trust domain, namespace and service account, but 2 certificates are issued,
one for server and one for client (with same key). The certificates can be 
generated from a JWT with a trusted issuer, mapping the "sub" claim. Any 
other SSH CA or `keygen` can be used to generate certs.  

For K8S, the identity will be:

  ${KSA}@${Namespace}.${TrustDomain}
  ${KSA}.${Namespace}.svc.${TrustDomain}

TODO: watch Service and ServiceEntry and allow KSA configured to get cert for the service.

# WIP: Mesh communication

Client will initiate a remote forward, with *:MESH_PORT address. Server will accept
forward request of this type but will not open new ports.

Depending on MESH_PORT, SSH-mesh Gateway it should support Ztunnel HBONE 
protocol, HAProxy or SNI routing. Port 22, 80 and 443 are multiplexing the expected protocols.


## Automatic certificate signing

This is similar with Istiod/Citadel signing of workload certificates,
but for SSH certificates. To simplify the deployment and optimize strtup time,
the gate includes cert signing code - but a separate CA can also be used.


# Usage with Openssh/dropbear

Useful ssh args:

- "-N" - don't start a shell/terminal - just port forwards
- UserKnownHostsFile /dev/null - don't save the key
- StrictHostKeyChecking=no - don't check server key (for example if a tunnel authenticates)
- "-F /dev/null" - ignore host config

```shell
export SSH_ASKPASS=... # script doing /usr/bin/curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/identity?audience=ssh://

ssh -v  -p 15022 -i id_ecdsa  -o "UserKnownHostsFile known_hosts" costin@localhost

ssh -v -p 15022 s.webinf.duckdns.org -R NAME:22:localhost:22 

# To disable host checking:
# -F /dev/null -o "UserKnownHostsFile /dev/null" -o StrictHostKeyChecking=no
```

# Alternatives

- use an extension is appealing - for example allow servers to initiate direct-tcpip 
channels will make the code simpler. However interop with existing ssh tools is the
main goal - otherwise H2/H3 should be used.

- provide a rich API with support for global requests, extensions, etc - nice but 
not required.

# SSH certificates - manually 

```shell

ssh-keygen -t ecdsa -f ca 

ssh-keygen -f user-key -t ecdsa 
ssh-keygen -s ca -I user@domain -n user,honda -V +1y user-key.pub

# Host config
ssh-keygen -s ca -I host.example.com -h -n host,host.example.com -V +1y ssh_host_rsa_key.pub

#  /etc/ssh/sshd_config
# TrustedUserCAKeys /etc/ssh/ssh_user_key.pub
# HostCertificate /etc/ssh/ssh_host_ecdsa_key-cert.pub

# .ssh/known-hosts
# @cert-authority *.example.com ecdsa-sha2-nistp256 AAAAE...=  



# Debug - print cert
ssh-keygen -L -f id_ecdsa-cert.pub



```
