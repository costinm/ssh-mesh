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

The example creates three independent nodes:

| Node | Mode | SSH port | HTTP port | Trusted socket |
|------|------|----------|-----------|----------------|
| alice | bwrap user namespace, uid 0 inside sandbox | 18222 | 18280 | `shared/alice/trusted.sock` |
| bob | QEMU VM using an Initos-based Nix artifact | 18322 | 18380 | `shared/bob/trusted.sock` |
| user | non-root mesh-init user mode | 18422 | 18480 | `shared/user/trusted.sock` |

Alice and user use bubblewrap and share the host network namespace. Bob boots
the Initos rolling-release kernel, initrd, and EROFS rootfs packaged by
`.#bob-vm`, then starts ssh-mesh through Bob's checked-in `initos-pod` script.
QEMU user networking provides host port forwards for SSH and HTTP.

Each ssh-mesh node also exposes a trusted UDS transport. The nodes maintain
outgoing SSH-mesh client connections to each other over those UDS sockets using
SSH as the mux, with trusted none-auth and no SSH payload encryption on that
transport. This exercises the client-maintained connection path without needing
certificates. When bob's VM has `/dev/vhost-vsock`, `bob/start.sh` also attaches
a virtio-vsock device for vsock experiments.

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

- `config/ssh-mesh/mesh.yaml`  
  ssh-mesh node config, including listener ports, trusted UDS socket, maintained
  client connections, and example local/remote forwards.

- `config/ssh/config`  
  OpenSSH examples for TCP SSH and SSH-over-HTTP with `h2t`.

- `start.sh`  
  Starts that single node using installed binaries.

`start_all.sh` starts all three nodes together and writes logs under the
example state directory. Bob requires `SSH_MESH_BOB_VM_DIR`, or explicit
`SSH_MESH_BOB_KERNEL`, `SSH_MESH_BOB_INITRD`, and `SSH_MESH_BOB_ROOTFS` paths,
unless the artifact is installed at `/opt/ssh-mesh/share/bob-vm`.

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

The shared trusted sockets are created under the host state root:

```bash
$SSH_MESH_EXAMPLE_ROOT/shared
```

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
./alice/start.sh
./user/start.sh
```

Start `alice` and `user` in separate terminals if running them manually. For bob:

```bash
export SSH_MESH_BOB_VM_DIR=/opt/ssh-mesh/share/bob-vm
./bob/start.sh
```

You can also point Bob at direct artifact paths:

```bash
export SSH_MESH_BOB_KERNEL=/path/to/bzImage
export SSH_MESH_BOB_INITRD=/path/to/initrd.img
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
- Bob boot through Initos `initos-init-vm` and Bob's checked-in `initos-pod`
  adapter

The trusted UDS transport exercises the same trusted SSH mux path as vsock
without requiring VM support. Bob attaches a virtio-vsock device when the host
exposes `/dev/vhost-vsock`.

Bob uses the Initos EROFS rootfs as a read-only QEMU block device. Its writable
state and packaged ssh-mesh binaries are exposed through a QEMU 9p share mounted
by Initos as `/src`. The Bob adapter starts `mesh-init` with `/out/ssh-mesh/bin` on
`PATH` and HOME backed by the example state tree at `/src/bob/home/bob`.

## Ports and forwards

Base listeners:

- alice: SSH `127.0.0.1:18222`, HTTP `127.0.0.1:18280`
- bob: SSH `127.0.0.1:18322`, HTTP `127.0.0.1:18380`
- user: SSH `127.0.0.1:18422`, HTTP `127.0.0.1:18480`

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
ssh -o 'ProxyCommand h2t http://127.0.0.1:18280/_m/_ssh' alice@ignored
```

lmesh discovery from inside a node:

```bash
curl --unix-socket "$HOME/.run/lmesh/control.sock" -X POST http://localhost/nodes
```

pmond from inside a node:

```bash
curl --unix-socket "$HOME/.run/pmond/control.sock" http://localhost/ps
```
