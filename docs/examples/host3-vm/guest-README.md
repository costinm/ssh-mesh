# Host3-vm guest contract

Host3-vm is a QEMU VM artifact built from this repo's cloud kernel, a small local
EROFS rootfs, and ssh-mesh example files:

```text
share/host3-vm-vm/bzImage
share/host3-vm-vm/host3-vm-rootfs.erofs
share/host3-vm-vm/initos.erofs
share/host3-vm-vm/initos-pod
share/host3-vm-vm/config/
share/host3-vm-vm/bin/
bin/run-host3-vm-vm
```

Build it from the repository with:

```bash
nix build .#host3-vm-vm
```

`host3-vm/start.sh` delegates to `host3-vm/run-host3-vm-vm`. The installed package exposes the
same runner as `bin/run-host3-vm-vm`.

The runner boots the local cloud kernel and generated EROFS rootfs, and passes:

```text
init=/opt/initos/bin/initos-init-vm
root=/dev/vda
rootfstype=erofs
```

It prepares a writable QEMU 9p share with mount tag `src`. The vendored
`initos-init-vm` script mounts that share at `/src` and executes:

```text
/src/initos/initos-pod start
```

Host3-vm's checked-in `initos-pod` script then starts `mesh-init` with:

```bash
export PATH=/out/ssh-mesh/bin:/opt/initos/bin:/opt/busybox/bin
export HOME=/home/system
export USER=system
export LOGNAME=system
export RUST_LOG=info
export MESH_INIT_SOCK=$HOME/.run/mesh-init/control.sock
mesh-init
```

With that contract, host3-vm uses the same HOME-relative layout as host2 and host1:

```text
$HOME/.config/mesh-init/*.toml
$HOME/.config/ssh-mesh/mesh.yaml
$HOME/.ssh/config
$HOME/.run/*
```

Persistent config and runtime state come from the host example state tree,
exposed to the guest as `/src/host3-vm/home/system`. The packaged configs under
`share/host3-vm-vm/config` are copied into that HOME before `mesh-init` starts.

When QEMU host1 networking is used, `run-host3-vm-vm` forwards:

```text
127.0.0.1:18322 -> guest:18322
127.0.0.1:18380 -> guest:18380
```

The host-side ports can be changed with `SSH_MESH_HOST3_VM_HOST_SSH_PORT` and
`SSH_MESH_HOST3_VM_HOST_HTTP_PORT`; guest ports remain `18322` and `18380`. The
example uses QEMU host1 networking only. The shared 9p filesystem is for config,
state, and binaries, not for a host-visible Host3-vm trusted Unix socket.
