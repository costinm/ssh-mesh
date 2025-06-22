# Other implementations and docs

- https://openwrt.org/docs/guide-user/services/ssh/sshtunnel - OpenWRT client side, with dropbear or openssh.
- https://github.com/yurt-page/awesome-tunneling#ssh-services - linked from there.
- https://github.com/fasmide/remotemoe  - has free server too
- 
- https://ssh-j.com/ - dropbear based, jump host only (.ru domain, on tor too), ssh only.
  `ssh any-username@ssh-j.com -N -R laptop-behind-nat:22:localhost:22` - recommends sish

- sish is hosted (free/paid $2/mo, with storge) - interesting extra services:
  - pipes - pubsub over ssh: `ssh HOST pub topic`, `ssho HOST sub topic`
    - "-b=false" - pub doesn't block waiting for a sub
    - "sub -k" - keep sub alive even if pub exists (default: notified the pub is out)
    - "pipe" command - just a 2way pipe between 2 clients
    - web interface as well, websocket too  
  - pastebin - stored files, just "echo foo" | ssh pipes...
- srv.us 
  - accepts github/gitlabs identities (authorized keys -> user name) 
  - either github or sha(pubkey) based FQDNS
  - single host
  - certbot for DNS certs (cloudflare)
  - super simple file: https://github.com/pcarrier/srv.us/blob/main/backend/main.go


- https://github.com/Netflix/bless - python, AWS lambda
  - KMS used for the root CA, `ssh-keygen -t rsa -b 4096 -m PEM -f bless-ca- -C "SSH CA Key"`
  - JSON input ('bastion_user', 'bastion_user_ip' 'remote_usernames', 'bastion_ips', 
    'command': bastion_command, 'public_key_to_sign': public_key), JSON output (certificate)

- https://www.vaultproject.io/docs/secrets/ssh
  - Same protocol as all other vault providers

- https://github.com/nsheridan/cashier
  - user logins, gets token, token exchanged with cert.

- sish - very nice proxy with too many features (auto get certs, etc).
  Interesting use of viper - all configs are dynamic, env, remote, etc.

- gvisor-tap-vsock implements ssh tunnel for vsock - qemu and other VMs supported. 
  Interesting API for Dial(url), including exec abstraction in stdin:// scheme

- https://github.com/jpillora/chisel - over http2

## Teleport

- https://goteleport.com/ - very similar, but far too large to embed in a launcher app.
  Ideally it should interoperate (as well as openssh).

Git repo size: 337M (97M in vendor).
Teleport binary is ~130M (92M stripped).

Config and feature set is complex - it even includes eBPF.

https://goteleport.com/blog/ssh-restricted-shells/
 
# Microsoft

https://github.com/microsoft/dev-tunnels-ssh/blob/main/README.md

- extension for faster channel open !
- browser ( typescript )
- 'over any stream' - 
- piping between channels/sessions
- 'forward non requested port' - server can return different port

# Mutagen

https://github.com/mutagen-io/mutagen

- sidecar - injected as binary via ssh or docker/kube exec
- ssh protocol with somethig like syncthing (rsync variant with daemon watching and keeping state) 
- docker and local sync - don't seem very useful
- 

# SSHocker

https://github.com/lima-vm/sshocker - mostly wrapper around ssh port forward and sshfs.

```shell
curl -o sshocker --fail -L https://github.com/lima-vm/sshocker/releases/latest/download/sshocker-$(uname -s)-$(uname -m)
chmod +x sshocker
sudo apt-get install -y sshfs
sshocker -debug=true -p 8080:80 -v .:/mnt/sshfs user@example.com

-v LOCALDIR:REMOTEDIR[:ro]: Mount a reverse SSHFS
-p [[LOCALIP:]LOCALPORT:]REMOTEPORT: Expose a port
--sshfs-noempty (default: false): enable sshfs nonempty

-F, --ssh-config=FILE: specify SSH config file used for ssh -F
--ssh-persist=(true|false) (default: true): enable ControlPersist
--driver=DRIVER (default: auto): SFTP server driver. builtin (legacy) or openssh-sftp-server (robust and secure, recommended). openssh-sftp-server is chosen by default when the OpenSSH SFTP Server binary is detected.
--openssh-sftp-server=BINARY: OpenSSH SFTP Server binary. Automatically detected when installed in well-known locations such as /usr/libexec/sftp-server.
```

# Other projects

- https://github.com/xnuter/http-tunnel
- IPFS / libP2P - one of the supported transports is a modified H2, also Quic. Reinvents cert format.
- Syncthing - reverse tunnels, custom protocol, certs
- Tor - of course.
- BitTorrent
- [Konectivity](https://github.com/kubernetes-sigs/apiserver-network-proxy.git)
  Narrow use case of 'reverse connections' for Nodes (agents) getting calls from the APIserver via proxy, when the
  APIserver doesn't have direct connectivity to the node.

  gRPC or HTTP CONNECT based on the agent-proxy connection, and gRPC for APIserver to proxy.

   ``` 
   service AgentService {
     // Agent Identifier?
     rpc Connect(stream Packet) returns (stream Packet) {}
   }
   service ProxyService {
     rpc Proxy(stream Packet) returns (stream Packet) {}
   }
   
   Packet can be Data, Dial Req/Res, Close Req/Res
   ```

# Gost

[gost](https://github.com/ginuerzh/gost/blob/master/README_en.md) provides multiple integration points, focuses on
similar TCP proxy modes.

Usage:

```shell

# socks+http proxy
gost -L=:8080


```



