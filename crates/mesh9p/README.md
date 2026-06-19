# 9p server

This is used as an alternative to sshfs:

- has a native kernel driver
- better for VM-to-host sharing - no encryption needed.
- works well with ssh - as a normal UDS forward, no changes to ssh, as well as stdin/stderr.
- it is slightly more efficient
- may work better with TLS ('hbone') or wireguard - not so coupled with the SSH protocol an encryption - currently TCP is only possible via mesh-init.

Requirements:
- expose filesystem to other nodes.
- let the mesh handle crypto/auth
- light

Idea based on 'cpu' project: each peer exports and mount their filesystem via 9p. 

Not sure if this is best choice long term - virtiofs and
exposing 'FUSE' as a protocol seem better suited for the task, but initially 9p is a reasonable choice and is hidden (implementation detail).

The main decision is what to export on each node: 
Common (top level):
- read-only repos (nix, etc)
- root fs is possible if one host is accessed by a control plane server

Per pod (container):
- a R/W "workspace"



```bash
unpfs --listen '/tmp/unpfs-socket' /exportdir
```

Mounting:

```bash

mount -t 9p -o version=9p2000.L,trans=tcp,port=15101,uname=$USER $HOST /mountdir

mount -t 9p -o version=9p2000.L,trans=unix,uname=$USER /tmp/unpfs-socket:0 /mountdir
```


Original code from https://github.com/u-root/cpu/tree/main/p9cpu - implementing 9P2000.L protocol

Based on https://github.com/rs9p/rs9p which is a fork of https://github.com/pfpacket/rust-9p

## License
rust-9p is distributed under the BSD 3-Clause License.
See LICENSE for details.
