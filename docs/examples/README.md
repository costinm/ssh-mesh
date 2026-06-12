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

Host1 is the gateway. Users connect to host1's SSH port and can reach host2,
host3-vm, and all apps through ssh-mesh routes.

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
export SSH_MESH_EXAMPLE_ROOT=/path/to/state
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
  shared/
```

App source directories under `docs/examples/*/home/app*` are home/config
templates only. Host mesh-init starts app isolation through the shared launchers
installed in `target/dist/opt`: host1, host2, and app1 use
`/opt/ssh-mesh/bin/run_bwrap.sh`; host3-vm and VM apps use
`/opt/ssh-mesh/bin/vrun start`.

The local trusted sockets are created under:

```bash
$SSH_MESH_EXAMPLE_ROOT/shared
```

For VMs, the host3-vm state root is exposed as `/src` through `vrun`. Host3-vm
mounts its system home from `/src/host3-vm/home/system`. Nested VM apps do not
receive the whole host3-vm `/src`; `vrun` creates a per-app VM share containing
only the app home, shared socket directory, init script, and read-only `/nix`
when available.

Host3-vm also starts a one-shot diagnostic job on boot. It writes to the VM
console and reports the kernel, command line, memory, interfaces, routes, virtio
devices, kvm/vsock devices, `/nix`, and `/home`.

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
MESH_INIT_RUN="$SSH_MESH_EXAMPLE_ROOT/host1/home/system/.run/mesh-init" mesh-init reload
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
```

Pmond through a local forward:

```bash
cd docs/examples
ssh -N -F ssh_config \
  -L 127.0.0.1:19284:/home/system/.run/pmond/control.sock \
  host1

curl http://127.0.0.1:19284/_m/pmon/_ps
```
