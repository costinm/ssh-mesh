# Ssh-config mapping to json

This is a fork of russh-config crate, modified to just dump the config to json.

May also add support to toml - the main point is to skip parsing the old ssh config
and map this to mesh terms.

The 'ssh config' defines 'hosts' - as FQDNs or naked domains - with trust and
connection info (IP, trusted keys, identities to use, proxies, commands to connect).

Long term - the host source of truth should be the mesh config and discovery,
converted back to ssh-config for backward compat and use with ssh clients.
The generated config can use h2t mesh proxy and the UDS sockets, etc - this 
crate will remain to migrate existing configs.