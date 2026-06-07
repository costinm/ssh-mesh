# ssh-mesh local examples

This directory contains a multi-node example mesh for an installed ssh-mesh
system. The scripts expect the binaries to be installed already:

- `mesh-init`
- `ssh-mesh`
- `h2t`
- `pmond`
- `mcp-pmond`
- `lmesh`
- `bwrap`
- `qemu-system-x86_64` for the bob VM example

Each script prepends `/out/ssh-mesh/bin` and `/opt/ssh-mesh/bin` to `PATH`, so packaged installs in that
location work without extra setup. The examples do not depend on source-tree
build outputs or helper scripts.

## Topology

The example starts three nodes and defines one on-demand environment:

| Name | Mode | SSH port | HTTP port | Trusted socket |
|------|------|----------|-----------|----------------|
| bwrap-net | bwrap user namespace, uid 0 inside sandbox, host network | 18222 | 18280 | `shared/bwrap-net/trusted.sock` |
| bob | QEMU VM using this repo's cloud-kernel artifact | 18322 | 18380 | SSH/HTTP host forwards |
| user | non-root mesh-init user mode, host network | 18422 | 18480 | `shared/user/trusted.sock` |
| bwrap-nonet | bwrap user namespace, private network namespace | stdin only | stdin only | `shared/bwrap-nonet/trusted.sock` owned by user mesh-init |

Bwrap-net and user use bubblewrap and share the host network namespace. User
keeps a configured trusted-UDS client connection to bwrap-net at
`/tmp/mesh/shared/bwrap-net/trusted.sock`; bwrap-net also keeps a reciprocal
trusted-UDS connection to user. Those maintained clients create the example
local and remote forwards.

Bob boots the local `linux#kernel-cloud` kernel and EROFS rootfs packaged by
`.#bob-vm`, then starts ssh-mesh through Bob's checked-in `initos-pod` script.
QEMU user networking provides host port forwards for SSH and HTTP.

User owns the maintained client connections. It reaches Bwrap-net over trusted UDS
and reaches Bob over SSH-over-vsock, then opens local forwards into both nodes.
Bob also exposes forwarded SSH and HTTP ports for host smoke checks. Bob is not
reached through a shared Unix socket over the 9p filesystem.

Bwrap-nonet is not started by `start_all.sh`. User's mesh-init loads
`config/mesh-init/bwrap-nonet.toml`, which listens on
`/tmp/mesh/shared/bwrap-nonet/trusted.sock`. A connection to that socket causes
mesh-init to start `/examples/bwrap-nonet/start.sh --stdio`. The child enters a
no-network bubblewrap sandbox and runs `ssh-mesh` with
`SSH_MESH_TRUSTED_STDIO=1`, so the accepted stdin/stdout stream is its only
trusted transport.

User's ssh-mesh also has an `ssh_routes` entry for
`system@bwrap-nonet.example.m`. The first exec request for that SSH username
prepares mesh-init context, connects to the bwrap-nonet activation socket, and
runs the command over the trusted stdio connection. Later exec requests reuse
the existing routed SSH client connection. The same route also maps jump-host
requests for `bwrap-nonet.example.m:22` to `127.0.0.1:22` from inside the
activated environment, so the user node can act as an OpenSSH jump host for a
target that has no network path from the host. PTY and interactive shell routing
are still separate follow-up work.

Each node also starts:

- `pmond` over UDS for process monitoring
- `mcp-pmond` over UDS as an MCP facade for process monitoring
- `lmesh` over UDS plus multicast UDP discovery
- `ssh-mesh` TCP SSH, HTTP/H2C admin/tunnel endpoints, trusted UDS transport,
  maintained client connections, local forwards, and remote forwards

## Directory layout

Each node directory has:

- `config/mesh-init/ssh-mesh.toml`  
  mesh-init service config that starts and supervises `ssh-mesh`.

- `config/mesh-init/pmond.toml`  
  starts `pmond --uds control.sock`.

- `config/mesh-init/mcp-pmond.toml`  
  starts MCP access to pmond over UDS.

- `config/mesh-init/lmesh.toml`  
  starts local signed-discovery experiments and a UDS API.

- `user/config/mesh-init/bwrap-nonet.toml`  
  user-side mesh-init socket activation config for the no-network bwrap target.

- `config/ssh-mesh/mesh.yaml`  
  ssh-mesh node config, including listener ports, trusted UDS socket, maintained
  client connections, and example local/remote forwards.

- `config/ssh/config`  
  OpenSSH examples for TCP SSH and SSH-over-HTTP with `h2t`.

- `start.sh`  
  Starts that single node using installed binaries.

`start_all.sh` starts all three nodes together and writes logs under the
example state directory. Bob requires `SSH_MESH_BOB_VM_DIR`, or explicit
`SSH_MESH_BOB_KERNEL` and `SSH_MESH_BOB_ROOTFS` paths, unless the artifact is
installed at `/opt/ssh-mesh/share/bob-vm`. `SSH_MESH_BOB_INITRD` is optional
for custom boot experiments.

## Runtime state

By default, writable state is created under:

```bash
$HOME/.local/share/ssh-mesh/examples
```

Override it with:

```bash
export SSH_MESH_EXAMPLE_ROOT=/path/to/state
```

The scripts copy configs into each node's real runtime layout:

```text
$HOME/.config/mesh-init
$HOME/.config/ssh-mesh
$HOME/.ssh
$HOME/.run
```

The local shared trusted sockets are created under the host state root:

```bash
$SSH_MESH_EXAMPLE_ROOT/shared
```

Bob is intentionally not represented by a socket in that directory; user reaches
Bob through the VM's vsock device.

Per-node writable state includes ssh keys, mux sockets, mesh-init runtime
sockets, copied ssh-mesh config, logs, and example home directories.

## Start all nodes

```bash
cd docs/examples
export SSH_MESH_BOB_VM_DIR=/opt/ssh-mesh/share/bob-vm
./start_all.sh
```

Press `Ctrl-C` to stop all three nodes.

## Start one node

```bash
cd docs/examples
./bwrap-net/start.sh
./user/start.sh
```

Start `bwrap-net` and `user` in separate terminals if running them manually. For bob:

```bash
export SSH_MESH_BOB_VM_DIR=/opt/ssh-mesh/share/bob-vm
./bob/start.sh
```

You can also point Bob at direct artifact paths:

```bash
export SSH_MESH_BOB_KERNEL=/path/to/bzImage
export SSH_MESH_BOB_ROOTFS=/path/to/initos.erofs
./bob/start.sh
```

The bob VM artifact must follow [bob/guest-README.md](bob/guest-README.md).

Build the artifact from the repository with:

```bash
nix build .#bob-vm
```

## What is enabled

The examples enable:

- mesh-init supervision
- ssh-mesh TCP SSH server listeners
- ssh-mesh HTTP/H2C listeners
- SSH-over-HTTP with `h2t`
- trusted SSH transport over Unix domain sockets
- maintained ssh-mesh client connections with reconnect
- local forwards over maintained connections
- remote forwards over maintained connections
- mux socket directory via `MUX_DIR`
- pmond process monitor over UDS
- mcp-pmond over UDS
- lmesh multicast discovery and UDS query API
- separate HOME-relative SSH, config, and runtime directories per node
- user-home lookup roots under private `/home` layouts
- Bob boot through the vendored `initos-init-vm` shim and Bob's checked-in `initos-pod`
  adapter
- on-demand trusted-stdio activation of `bwrap-nonet` from the user
  environment's mesh-init

The trusted UDS transport exercises the same trusted SSH mux path as vsock
without requiring VM support. Bob attaches a virtio-vsock device when the host
exposes `/dev/vhost-vsock`.

Bob uses this repo's generated EROFS rootfs as a read-only QEMU block device.
Its writable state and packaged ssh-mesh binaries are exposed through a QEMU 9p
share mounted by the vendored VM init script as `/src`. The Bob adapter starts
`mesh-init` with `/out/ssh-mesh/bin` on `PATH` and HOME backed by the example
state tree at `/src/bob/home/bob`.

## Ports and forwards

Base listeners:

- bwrap-net: SSH `127.0.0.1:18222`, HTTP `127.0.0.1:18280`
- bob: SSH `127.0.0.1:18322`, HTTP `127.0.0.1:18380`
- user: SSH `127.0.0.1:18422`, HTTP `127.0.0.1:18480`
- bwrap-nonet: no TCP listeners; activated over
  `shared/bwrap-nonet/trusted.sock`

Example local forwards use ports `19001` through `19006`.

Example remote forwards use ports `19101` through `19106`.

If a port is already in use, edit the corresponding
`config/ssh-mesh/mesh.yaml` before starting the node.

## Useful checks

HTTP/admin:

```bash
curl http://127.0.0.1:18280/_m/api/ssh/clients
curl http://127.0.0.1:18380/_m/api/ssh/clients
curl http://127.0.0.1:18480/_m/api/ssh/clients
```

SSH over HTTP/H2C:

```bash
ssh -o 'ProxyCommand h2t http://127.0.0.1:18280/_m/_ssh' bwrap-net@ignored
```

lmesh discovery from inside a node:

```bash
curl --unix-socket "$HOME/.run/lmesh/control.sock" -X POST http://localhost/nodes
```

pmond from inside a node:

```bash
curl --unix-socket "$HOME/.run/pmond/control.sock" http://localhost/ps
```
