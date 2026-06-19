# ssh-mesh local examples

This directory contains a local multi-host mesh for an installed ssh-mesh
system. The examples use checked-in keys and certificates so the startup scripts
can stay simple.

Required binaries:

- `mesh-init`
- `ssh-mesh`
- `h2t`
- `pmond`
- `mcp-pmond`
- `lmesh`
- `meshkeys` to regenerate checked-in example keys and certificates
- `bwrap`
- `qemu-system-x86_64`, `crosvm`, and `cloud-hypervisor` for VM examples

`scripts/build.sh` creates distributable artifacts under `target/dist`:
`target/dist/opt` is the package tree used as `/opt`, and
`target/dist/img/ssh-mesh.erofs` embeds that same `/opt` for VMs. By default
`start_all.sh` uses `target/examples` only for mutable state.

## Model

The examples demonstrate two layers:

- Networked hosts communicate over real SSH with OpenSSH certificates and
  encrypted TCP transports.
- Isolated apps are launched by a host-local `mesh-init` and use trusted local
  transports between the host sshd and the app boundary.

`mesh-init` owns process and service management: starting hosts, activating
apps, launching bwrap and VM runtimes, maintaining sockets, and writing logs.
`ssh-mesh` routes SSH sessions and asks the local `mesh-init` to activate a
target when needed.

Every host uses `/home/system` as its primary user home. Every app runtime sees
its own `/home/appN` plus read-only package inputs:

```text
/home/system                  host home
/home/app1                    app1-bwrap runtime home
/home/app2                    app2-qemu runtime home
/home/app3                    app3-crosvm runtime home
/home/app4                    app4-ch runtime home
/home/app5                    app5-vm runtime home
/nix                          read-only package store when available
/opt/ssh-mesh                 read-only package install
```

Host and app configuration lives under the runtime home:

```text
.config/mesh-init
.config/ssh-mesh
.ssh
.run
```

On Android the same model maps to `/data/data/APPNAME`.

## Topology

| Name | Role | Transport |
|------|------|-----------|
| host1 | gateway or entry point host | real SSH with certs |
| host2 | remote networked host | real SSH with certs |
| host3-vm | worker host running inside a VM | real SSH with certs |
| app1-bwrap | host1 isolated app | trusted local activation |
| app2-qemu | host3-vm isolated app, QEMU backend | trusted local activation over vsock |
| app3-crosvm | host3-vm isolated app, crosvm backend | trusted local activation over vsock |
| app4-ch | host3-vm isolated app, Cloud Hypervisor backend | trusted local activation over vsock |
| app5-vm | host1 isolated app, VM backend selected by vrun | trusted local activation over vsock |

Host1 is the gateway. Users connect to host1's SSH port and can reach host2,
host3-vm, and all apps through ssh-mesh routes.

Host1 intentionally runs in bubblewrap as the invoking user without a user
namespace. It is the example for running ssh-mesh and mesh-init without root or
extra privileges. App1-bwrap shows that user-mode mesh-init can start isolated
containers. App5-vm shows the same user-mode mesh-init starting a no-network VM:
`vrun` picks crosvm when `/dev/kvm` is usable and falls back to QEMU otherwise.

Host2 is the remote-node example. It is reached by host1 over normal TCP SSH
with certificates, not through trusted local transports.

Host3-vm is the worker-machine example. It is a networked VM and owns the VM app
activation configs for app2/app3/app4. This is the preferred place to test
on-demand VM activation because it keeps the app runtimes nested under a
controlled worker host.

## Source Layout

```text
docs/examples/
  host1/
    home/system/              host1 home and config
    home/app1-bwrap/          source for app1, runtime home is /home/app1
    home/app5-vm/             source for app5, runtime home is /home/app5
  host2/
    home/system/              host2 home and config
  host3-vm/
    home/system/              host3-vm home, config, and app activation jobs
    home/app2-qemu/           source for app2, runtime home is /home/app2
    home/app3-crosvm/         source for app3, runtime home is /home/app3
    home/app4-ch/             source for app4, runtime home is /home/app4
```

Duplication is intentional in this directory. Each example should be easy to
open directly without following a template generator.

## Runtime Layout

By default writable state is created under:

```bash
target/examples
```

Override it with:

```bash
export SSH_MESH_STATE_ROOT=/path/to/state
```

Runtime state is staged like this:

```text
target/examples/
  host1/home/system/
  host2/home/system/
  host3-vm/home/system/
  app1-bwrap/home/app1/
  app2-qemu/home/app2/
  app3-crosvm/home/app3/
  app4-ch/home/app4/
  app5-vm/home/app5/
  shared/
```

App source directories under `docs/examples/*/home/app*` are home/config
templates only. Host mesh-init starts app isolation through the shared launchers
installed in `target/dist/opt`: host1, host2, and app1 use
`/opt/ssh-mesh/bin/run_bwrap.sh`; host3-vm and VM apps use
`/opt/ssh-mesh/bin/vrun start`.

The local trusted sockets are created under:

```bash
$SSH_MESH_STATE_ROOT/shared
```

For VMs, the host3-vm state root is exposed as `/src` through `vrun`. Host3-vm
mounts its system home from `/src/host3-vm/home/system`. Nested VM apps do not
receive the whole host3-vm `/src`; `vrun` creates a per-app VM share containing
only the app home, shared socket directory, init script, and read-only `/nix`
when available.

Host3-vm also starts a one-shot diagnostic job on boot. It writes to the VM
console and reports the kernel, command line, memory, interfaces, routes, virtio
devices, kvm/vsock devices, `/nix`, and `/home`.

## 9P Filesystem Exports

`mesh9p` can export more than one host directory through one server. Each
argument has this form:

```bash
mesh9p '/source/dir[:/guest/path][:rw]' ...
```

When `/guest/path` is omitted, the directory is exported at the same absolute
path. Exports are read-only by default, so `/nix` exports the host `/nix` as
guest `/nix` read-only. Add `:rw` only for per-app writable state.

Bubblewrap exporter on host1:

```bash
mesh9p \
  /nix \
  "${SSH_MESH_STATE_ROOT}/app1-bwrap/home/app1:/home/app1:rw" \
  "${SSH_MESH_STATE_ROOT}/shared:/run/ssh-mesh/shared:rw" \
  --listen "${SSH_MESH_STATE_ROOT}/shared/mesh9p-app1.sock"
```

No-network VM over stdio activation:

```toml
[service]
name = "app5-mesh9p-stdio"
command = "/opt/ssh-mesh/bin/mesh9p"
args = [
  "/nix",
  "/src/home/app5:/home/app5:rw",
  "/src/shared:/run/ssh-mesh/shared:rw",
]

[[activation]]
socket = "/home/system/.run/mesh-init/app5-9p.sock"
wait = false
```

No-network VM over vsock uses the same `mesh9p` arguments. In this mode vsock is
the trusted carrier used by ssh-mesh or mesh-init to deliver a bidirectional
stdio stream to `mesh9p`; the mount side should expose that stream through an
fd, UDS, or virtio-9p front-end because Linux v9fs does not have a direct
`trans=vsock` mount option:

```bash
# exporter side, normally launched by mesh-init or trusted-vsock exec
mesh9p /nix /src/home/app5:/home/app5:rw /src/shared:/run/ssh-mesh/shared:rw

# direct virtio-9p front-end in the guest
mount -t 9p -o version=9p2000.L,trans=virtio,access=any mesh9p /mnt/host
```

Networked VM over TCP:

```bash
mesh9p \
  /nix \
  "${SSH_MESH_STATE_ROOT}/host3-vm/home/system:/home/system:rw" \
  "${SSH_MESH_STATE_ROOT}/shared:/run/ssh-mesh/shared:rw" \
  --tcp 127.0.0.1:15101
```

Inside a VM with network access to the exporter:

```bash
mkdir -p /mnt/host
mount -t 9p -o version=9p2000.L,trans=tcp,port=15101,uname=root \
  127.0.0.1 /mnt/host
ls /mnt/host/nix /mnt/host/home/system
```

## Keys

The three networked hosts have checked-in example keys and certificates:

```text
docs/examples/host1/home/system/.ssh
docs/examples/host2/home/system/.ssh
docs/examples/host3-vm/home/system/.ssh
docs/examples/root/home/root/.ssh
```

Regenerate the example CA, node keys, and OpenSSH certificates with:

```bash
docs/examples/generate_keys.sh
```

The script uses the built `meshkeys` binary. The checked-in private keys are for
local examples only. The root example key has the certificate principal
`root@example.m`; ssh-mesh authz rules allow it to act as routed identities such
as `root@host3-vm.example.m`.

## Build From a Clean Target

From the repository root:

```bash
scripts/build.sh profile
scripts/build.sh
docs/examples/start_all.sh
```

`profile` builds the repo-local Nix profile with the VM kernel/rootfs assets and
hypervisors. It defaults to `target/nix/profile`, or reuses an existing
`target/nix/profiles`. The default `scripts/build.sh` command builds the musl
Rust binaries and creates `target/dist/opt` plus `target/dist/img`.

## Start All Nodes

```bash
cd docs/examples
./start_all.sh
```

Press `Ctrl-C` to stop all nodes and their child services.

After `scripts/build.sh profile`, `scripts/build.sh` copies the VM kernel into
`target/dist/img` and builds `target/dist/img/ssh-mesh.erofs` from
`target/dist/opt`. The example launchers use those dist artifacts directly:

```text
target/dist/opt
target/dist/img/vmlinux-cloud
target/dist/img/ssh-mesh.erofs
```

After config-only edits, reload the relevant running daemon instead of
restarting binaries. For example, inside a host/app environment:

```bash
mesh-init reload
```

From the host, point `MESH_INIT_RUN` at the daemon run directory:

```bash
MESH_INIT_RUN="$SSH_MESH_STATE_ROOT/host1/home/system/.run/mesh-init" mesh-init reload
```

## Ports

| Node | SSH | HTTP |
|------|-----|------|
| host2 | `127.0.0.1:18222` | `127.0.0.1:18280` |
| host3-vm | `127.0.0.1:18322` | `127.0.0.1:18380` |
| host1 | `127.0.0.1:18422` | `127.0.0.1:18480` |

Example local forwards use ports `19001` through `19006`.
Example remote forwards use ports `19101` through `19106`.

## Useful Checks

HTTP/admin:

```bash
curl http://127.0.0.1:18280/_m/api/ssh/clients
curl http://127.0.0.1:18380/_m/api/ssh/clients
curl http://127.0.0.1:18480/_m/api/ssh/clients
```

SSH to host1 and route through the user port:

```bash
cd docs/examples
ssh -F ssh_config host1
ssh -F ssh_config host2
ssh -F ssh_config host3-vm
ssh -F ssh_config host3-vm-root
ssh -F ssh_config app1-bwrap
ssh -F ssh_config app2-qemu
ssh -F ssh_config app3-crosvm
ssh -F ssh_config app4-ch
ssh -F ssh_config app5-vm
```

Pmond through a local forward:

```bash
cd docs/examples
ssh -N -F ssh_config \
  -L 127.0.0.1:19284:/home/system/.run/pmond/control.sock \
  host1

curl http://127.0.0.1:19284/_m/pmon/_ps
```
