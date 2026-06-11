# ssh-mesh local examples

This directory contains a multi-node example mesh for an installed ssh-mesh
system. The scripts expect the binaries to be installed already:

- `mesh-init`
- `ssh-mesh`
- `h2t`
- `pmond`
- `mcp-pmond`
- `lmesh`
- `meshkeys` to regenerate checked-in example keys and certificates
- `bwrap`
- `qemu-system-x86_64`, `crosvm`, `cloud-hypervisor` for VM examples

Each script prepends the staged example bin directory and the staged
`/opt/ssh-mesh/bin` to `PATH`. By default, `start_all.sh` stages mutable
example data under `target/examples`, including a package-style
`target/examples/opt` tree that is bind-mounted as `/opt`.

`/nix` and a profile under `target/nix/profiles` are used for the binaries.

## Target Model

The examples are meant to demonstrate two layers:

- Networked hosts that communicate over real SSH with certificates and encrypted
  TCP transports.
- Isolated apps launched by a host-local `mesh-init`, using trusted local
  transports for the hop between the host sshd and the app boundary.

`mesh-init` is the process manager for both layers. It owns service startup,
activation sockets, VM/container lifecycle, restart policy, and runtime
directories. `ssh-mesh` should route SSH sessions and ask the local `mesh-init`
to activate a target when needed; it should not grow per-hypervisor process
management.

Each host or app gets a writable application home:

```text
/home/APPNAME
```

On Android the corresponding layout is:

```text
/data/data/APPNAME
```

The application home is owned by the app identity and contains mutable runtime
state:

```text
$HOME/.config/mesh-init
$HOME/.config/ssh-mesh
$HOME/.ssh
$HOME/.run
```

The shared package/runtime input is read-only:

```text
/nix
/nix-profile
/opt/ssh-mesh
```

For VMs, `/nix` should be available through a VM-friendly mechanism. The target
example path is to include `mesh9p` as the read-only `/nix` provider so this
flow is covered by the examples instead of relying only on host bind mounts.

## Target Topology

The target names describe roles rather than implementation details:

| Target name | Current source name | Role | Transport |
|-------------|---------------------|------|-----------|
| host1 | user | gateway or entry point host | real SSH with certs |
| host2 | bwrap-net | remote networked host | real SSH with certs |
| host3-vm | vm-net | worker host running inside a VM | real SSH with certs |
| host1/app-bwrap | bwrap-nonet | app isolated by bwrap under host1 | trusted local mux |
| host1/app-vm-* | vm-nonet-* | app isolated by VM under host1 | trusted local mux |
| host3-vm/app-* | not yet split out | app isolated under host3-vm | trusted local mux |

Host1 is the gateway example. It may be internet-connected and owns the entry
SSH port users connect to. It maintains encrypted SSH client connections to
host2 and host3-vm using certificates. It can also activate local constrained
apps through its own `mesh-init`.

Host2 is a remote-node example. It is intentionally reached by host1 over real
TCP SSH and certificates, not through trusted local transports.

Host3-vm is the worker-machine example. It is a networked VM with the same
host-level responsibilities as host1, including the ability to run isolated apps
under its own guest `mesh-init`. This is the preferred place to test VM
activation when the host machine has unreliable or missing host-side vsock/vport
support, because the VM guest environment can provide a controlled driver and
device layout.

The isolated app examples are not independent hosts on the public network. They
are children of a host `mesh-init`. Their trust boundary is the local
host-to-app transport:

- bwrap apps can use accepted stdin/stdout or a maintained vport.
- VM apps can use virtio-vsock, virtio-serial/vport, or a vhost-user backend.
- All trusted app transports carry the same SSH mux semantics.

## Current Topology

The current scripts still use the older names while the layout is being
migrated:

| Name | Mode | SSH port | HTTP port | Transport |
|------|------|----------|-----------|-----------|
| user | non-root mesh-init user mode, host network | 18422 | 18480 | TCP SSH and `shared/user/trusted.sock` |
| bwrap-net | bwrap user namespace, uid 0 inside sandbox, host network | 18222 | 18280 | TCP SSH |
| vm-net | QEMU VM using this repo's cloud-kernel artifact | 18322 | 18380 | SSH/HTTP host forwards |
| bwrap-nonet | bwrap user namespace, private network namespace | stdin only | stdin only | `shared/bwrap-nonet/trusted.sock` owned by user mesh-init |
| vm-nonet-qemu | QEMU VM, no network namespace | trusted only | trusted only | `shared/vm-nonet-qemu/trusted.sock` activation, then VM local transport |
| vm-nonet-crosvm | crosvm VM, no network namespace | trusted only | trusted only | `shared/vm-nonet-crosvm/trusted.sock` activation, then VM local transport |
| vm-nonet-ch | Cloud Hypervisor VM, no network namespace | trusted only | trusted only | `shared/vm-nonet-ch/trusted.sock` activation, then VM local transport |

Bwrap-net is the remote-node example: user reaches it through normal TCP SSH on
`127.0.0.1:18222`, not through a trusted local transport. The no-network
examples below are the ones that use trusted local activation for bwrap and VMs.

The main networked hosts have checked-in example keys and OpenSSH certificates
under:

```bash
docs/examples/bwrap-net/home/bwrap-net/.ssh
docs/examples/user/home/user/.ssh
docs/examples/vm-net/home/vm-net/.ssh
```

Regenerate the example CA, node keys, and certs with:

```bash
docs/examples/generate_keys.sh
```

The script uses the built `meshkeys` binary and writes `authorized_cas` into
each main node home. The checked-in private keys are for local examples only.

VM-Net boots the local `linux#kernel-cloud` kernel and EROFS rootfs packaged by
`.#vm-net-vm`, then starts ssh-mesh through VM-Net's checked-in `initos-pod`
script. QEMU user networking provides host port forwards for SSH and HTTP.

The three current network-enabled nodes - bwrap-net, user, and vm-net - can
communicate using TCP/IP.

User owns the maintained client connections. It reaches Bwrap-net and VM-Net
over normal TCP SSH, then opens local forwards into both nodes. VM-Net also
exposes forwarded SSH and HTTP ports for host smoke checks. VM-Net is not
reached through a shared Unix socket.

Bwrap-nonet is not started by `start_all.sh`. User's mesh-init loads
`config/mesh-init/bwrap-nonet.toml`, which listens on
`/tmp/mesh/shared/bwrap-nonet/trusted.sock`. A connection to that socket causes
mesh-init to start `/tmp/mesh/state/examples/bwrap-nonet/start.sh --stdio`.
The child enters a no-network bubblewrap sandbox and runs `ssh-mesh` with
`SSH_MESH_TRUSTED_STDIO=1`, so the accepted stdin/stdout stream is its trusted
transport.

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

- `pmond` over UDS for process monitoring and as example.
- `lmesh` over UDS plus multicast UDP discovery for nodes with networking.
- `ssh-mesh` TCP SSH, HTTP/H2C admin/tunnel endpoints, trusted UDS transport,
  maintained client connections, local forwards, and remote forwards

## Source Layout

The current source tree is intentionally still close to the old names while the
target names settle:

```text
docs/examples/
  user/            current host1 gateway source
  bwrap-net/       current host2 remote host source
  vm-net/          current host3-vm worker host source
  bwrap-nonet/     current host1 isolated bwrap app source
  vm-nonet/        current isolated VM app source shared by qemu/crosvm/ch
```

The final source layout should make host ownership explicit:

```text
docs/examples/
  host1/
    apps/bwrap/
    apps/vm-qemu/
    apps/vm-crosvm/
    apps/vm-ch/
  host2/
  host3-vm/
    apps/bwrap/
    apps/vm-qemu/
    apps/vm-crosvm/
    apps/vm-ch/
```

Duplication is acceptable in this directory. The examples are easier to
understand when each host/app config can be opened directly instead of being
generated by a template.

Each host or app directory has:

- `config/mesh-init/ssh-mesh.toml`  
  mesh-init service config that starts and supervises `ssh-mesh`.

- `config/mesh-init/pmond.toml`  
  starts `pmond --uds control.sock`.

- `config/mesh-init/mcp-pmond.toml`  
  starts MCP access to pmond over UDS.

- `config/mesh-init/lmesh.toml`  
  starts local signed-discovery experiments and a UDS API.

- `user/config/mesh-init/bwrap-nonet.toml`  
  current host1-side mesh-init socket activation config for the no-network
  bwrap app target.

- `config/ssh-mesh/mesh.yaml`  
  ssh-mesh node config, including listener ports, route clients, and example
  local/remote forwards.

- `config/ssh/config`  
  OpenSSH examples for TCP SSH and SSH-over-HTTP with `h2t`.

- `start.sh`  
  Starts that single host or app using installed binaries.

`start_all.sh` starts all three current networked hosts together and writes logs
under the example state directory. VM-Net requires `SSH_MESH_VM_NET_VM_DIR`, or
explicit `SSH_MESH_VM_NET_KERNEL` and `SSH_MESH_VM_NET_ROOTFS` paths, unless the
artifact is available from `result-default` or the current legacy package path
`share/bob-vm` under `NIX_PROFILE/opt/ssh-mesh` or host `/opt/ssh-mesh`.

## Runtime Layout

By default, writable state is created under:

```bash
target/examples
```

Override it with:

```bash
export SSH_MESH_EXAMPLE_ROOT=/path/to/state
```

The runtime layout should be the same for host processes, bwrap apps, and VM
apps:

```text
target/examples/
  host-or-app/
    home/APPNAME/
      .config/mesh-init/
      .config/ssh-mesh/
      .ssh/
      .run/
  shared/
  opt/
```

Inside the sandbox or VM, that maps to:

```text
/home/APPNAME
/tmp/mesh/shared
/opt/ssh-mesh
/nix or /nix-profile
```

By default, the scripts look for a Nix profile at:

```bash
target/nix/profiles
```

When `SSH_MESH_OPT_DIR` is set, that directory is bind-mounted as `/opt`.
Otherwise the bwrap scripts bind `NIX_PROFILE/opt` if it exists, then fall back
to host `/opt`.

The target invariant is that `mesh-init` and `ssh-mesh` do not need to know
whether the app is a bwrap container, QEMU VM, crosvm VM, or Cloud Hypervisor
VM. They see an app home, package paths, an activation request, and a trusted
local transport.

The local shared trusted sockets are created under the host state root:

```bash
$SSH_MESH_EXAMPLE_ROOT/shared
```

Per-node writable state includes ssh keys, mux sockets, mesh-init runtime
sockets, copied ssh-mesh config, logs, and example home directories.

## Migration Plan

1. Document and stabilize roles.
   Keep current script names for now, but treat `user` as host1, `bwrap-net` as
   host2, and `vm-net` as host3-vm in docs and comments.

2. Move activation ownership under hosts.
   Keep host1 activations working, then add the same app activation configs
   under host3-vm. The host3-vm path should be the primary automated VM
   activation test path because it can run with a controlled guest device model.

3. Normalize runtime homes.
   All launched apps should use `/home/APPNAME` in Linux examples and
   `/data/data/APPNAME` for Android-oriented examples. Avoid `$HOME` as a source
   of staging truth; stage writable homes under `target/examples`.

4. Normalize read-only package inputs.
   Bind `/opt/ssh-mesh` from the staged package tree. Bind or provide `/nix`
   read-only. For VM examples, add a mesh9p-backed `/nix` flow so examples cover
   the eventual runtime mechanism.

5. Make VM local transport explicit.
   Keep virtio-vsock as one supported trusted transport, but add focused vport
   coverage for hosts where `/dev/vhost-vsock` is broken or unavailable. The
   test matrix should cover creating, naming, listing, connecting, and cleaning
   up a small set of vports.

6. Rename source directories.
   After the host/app split is working, rename source directories to `host1`,
   `host2`, `host3-vm`, and app subdirectories. Update `meshkeys`,
   certificates, README commands, and smoke scripts together.

7. Tighten smoke tests.
   The top-level SSH smoke should verify the three networked hosts through
   host1. App smoke tests should run once under host1 and once nested under
   host3-vm, with first-run timings separated from warm-run timings.

## Start all nodes

```bash
cd docs/examples
export SSH_MESH_VM_NET_VM_DIR=/path/to/result-default
./start_all.sh
```

Press `Ctrl-C` to stop all three nodes.

## Start one node

```bash
cd docs/examples
./bwrap-net/start.sh
./user/start.sh
```

Start `bwrap-net` and `user` in separate terminals if running them manually. For vm-net:

```bash
export SSH_MESH_VM_NET_VM_DIR=/path/to/result-default
./vm-net/start.sh
```

You can also point VM-Net at direct artifact paths:

```bash
export SSH_MESH_VM_NET_KERNEL=/path/to/bzImage
export SSH_MESH_VM_NET_ROOTFS=/path/to/initos.erofs
./vm-net/start.sh
```

The vm-net VM artifact must follow [vm-net/guest-README.md](vm-net/guest-README.md).

Build the artifact from the repository with:

```bash
nix build .#vm-net-vm
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
- VM-Net boot through the vendored `initos-init-vm` shim and VM-Net's checked-in `initos-pod`
  adapter
- on-demand trusted-stdio activation of `bwrap-nonet` from the user
  environment's mesh-init

The trusted UDS and vsock transports exercise the same trusted SSH mux path.
VM-Net is the pure networked VM example; the vm-nonet variants cover no-network
vsock activation.

VM-Net uses this repo's generated EROFS rootfs as a read-only QEMU block device.
Its writable state and packaged ssh-mesh binaries are exposed through a QEMU 9p
share mounted by the vendored VM init script as `/src`. The VM-Net adapter starts
`mesh-init` with `/out/ssh-mesh/bin` on `PATH` and HOME backed by the example
state tree at `/src/vm-net/home/vm-net`.

## Ports and forwards

Base listeners:

- bwrap-net: SSH `127.0.0.1:18222`, HTTP `127.0.0.1:18280`
- vm-net: SSH `127.0.0.1:18322`, HTTP `127.0.0.1:18380`
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
