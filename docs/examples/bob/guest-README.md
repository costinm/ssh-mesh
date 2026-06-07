# Bob guest contract

Bob is a QEMU VM artifact built from this repo's cloud kernel, a small local
EROFS rootfs, and ssh-mesh example files:

```text
share/bob-vm/bzImage
share/bob-vm/bob-rootfs.erofs
share/bob-vm/initos.erofs
share/bob-vm/initos-pod
share/bob-vm/config/
share/bob-vm/bin/
bin/run-bob-vm
```

Build it from the repository with:

```bash
nix build .#bob-vm
```

`bob/start.sh` delegates to `bob/run-bob-vm`. The installed package exposes the
same runner as `bin/run-bob-vm`.

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

Bob's checked-in `initos-pod` script then starts `mesh-init` with:

```bash
export PATH=/out/ssh-mesh/bin:/opt/initos/bin:/opt/busybox/bin
export HOME=/home/bob
export USER=bob
export LOGNAME=bob
export RUST_LOG=info
export MESH_INIT_SOCK=$HOME/.run/mesh-init/control.sock
mesh-init
```

With that contract, bob uses the same HOME-relative layout as bwrap-net and user:

```text
$HOME/.config/mesh-init/*.toml
$HOME/.config/ssh-mesh/mesh.yaml
$HOME/.ssh/config
$HOME/.run/*
```

Persistent config and runtime state come from the host example state tree,
exposed to the guest as `/src/bob/home/bob`. The packaged configs under
`share/bob-vm/config` are copied into that HOME before `mesh-init` starts.

When QEMU user networking is used, `run-bob-vm` forwards:

```text
127.0.0.1:18322 -> guest:18322
127.0.0.1:18380 -> guest:18380
```

The host-side ports can be changed with `SSH_MESH_BOB_HOST_SSH_PORT` and
`SSH_MESH_BOB_HOST_HTTP_PORT`; guest ports remain `18322` and `18380`. The
example's maintained mesh client uses SSH-over-vsock from user to Bob, with Bob
listening on vsock port `18322` and guest CID `42` by default. The shared 9p
filesystem is for config, state, and binaries, not for a host-visible Bob
trusted Unix socket.

If `/dev/vhost-vsock` is available, the script also attaches a virtio-vsock
device with guest CID `42` by default.

Set `SSH_MESH_BOB_ENABLE_VSOCK=0` to disable vsock attachment on hosts where
`/dev/vhost-vsock` exists but QEMU cannot open it.
Set `SSH_MESH_BOB_ENABLE_VSOCK=1` to require vsock and fail early when the host
cannot provide `/dev/vhost-vsock`.
