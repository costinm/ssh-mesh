# Other implementations and docs

- https://github.com/Netflix/bless - python, AWS lambda
  - KMS used for the root CA, `ssh-keygen -t rsa -b 4096 -m PEM -f bless-ca- -C "SSH CA Key"`
  - JSON input ('bastion_user', 'bastion_user_ip' 'remote_usernames', 'bastion_ips', 
    'command': bastion_command, 'public_key_to_sign': public_key), JSON output (certificate)

- https://www.vaultproject.io/docs/secrets/ssh
  - Same protocol as all other vault providers

- https://github.com/nsheridan/cashier
  - user logins, gets token, token exchanged with cert.

## Teleport

- https://goteleport.com/ - very similar, but far too large to embed in a launcher app.
  Ideally it should interoperate (as well as openssh).

Git repo size: 337M (97M in vendor).
Teleport binary is ~130M (92M stripped).

Config and feature set is complex - it even includes eBPF.

 

- 
