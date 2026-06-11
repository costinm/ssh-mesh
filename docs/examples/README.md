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

Each script prepends the staged example bin directory, `/out/ssh-mesh/bin`,
`/opt/ssh-mesh/bin`, and the selected Nix profile to `PATH`. By default
`start_all.sh` stages mutable data under `target/examples` and uses
`target/nix/profiles` when it exists.

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
/out/ssh-mesh                 staged build output, when present
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
  host1/home/app1/
  host2/home/system/
  host3-vm/home/system/
  app2-qemu/home/app2/
  app3-crosvm/home/app3/
  app4-ch/home/app4/
  shared/
  opt/
```

The local trusted sockets are created under:

```bash
$SSH_MESH_EXAMPLE_ROOT/shared
```

For VMs, the host state root is exposed as `/src`. Host3-vm mounts its system
home from `/src/host3-vm/home/system`, and VM apps mount their app home from
`/src/appN-backend/home/appN`. When host `/nix` is available, launchers expose it
read-only through the VM share so guests can mount `/nix`.

Host3-vm also starts a one-shot diagnostic job on boot. It writes to the VM
console and reports the kernel, command line, memory, interfaces, routes, virtio
devices, kvm/vsock devices, `/nix`, and `/home`.

## Keys

The three networked hosts have checked-in example keys and certificates:

```text
docs/examples/host1/home/system/.ssh
docs/examples/host2/home/system/.ssh
docs/examples/host3-vm/home/system/.ssh
```

Regenerate the example CA, node keys, and OpenSSH certificates with:

```bash
docs/examples/generate_keys.sh
```

The script uses the built `meshkeys` binary. The checked-in private keys are for
local examples only.

## Start All Nodes

```bash
cd docs/examples
export SSH_MESH_HOST3_VM_DIR=/path/to/result-default
./start_all.sh
```

Press `Ctrl-C` to stop all nodes and their child services.

Host3-vm needs VM artifacts from `SSH_MESH_HOST3_VM_DIR`, or explicit paths:

```bash
export SSH_MESH_HOST3_VM_KERNEL=/path/to/vmlinux-or-bzImage
export SSH_MESH_HOST3_VM_ROOTFS=/path/to/ssh-mesh.erofs
./host3-vm/start.sh
```

`start_all.sh` also checks `result-default`, `docs/examples/share/host3-vm-vm`,
`$NIX_PROFILE/opt/ssh-mesh/share/host3-vm-vm`, and `/opt/ssh-mesh`.

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
