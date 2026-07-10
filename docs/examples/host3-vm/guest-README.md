# Host3-vm guest contract

Host3-vm is a QEMU VM launched from the repo-local dist artifacts:

```text
target/dist/img/ssh-mesh.erofs
target/nix/profile/opt/ssh-mesh-kernel
target/dist/opt
```

Build those artifacts from the repository with:

```bash
scripts/build.sh profile
scripts/build.sh
```

`docs/examples/start_all.sh` launches `docs/examples/host3-vm/run-host3-vm`.
That wrapper sets the example-specific environment and then execs
`/opt/ssh-mesh/bin/vrun start`. `vrun` boots the dist cloud kernel, generated
EROFS rootfs, and modules EROFS, and passes:

```text
init=/opt/initos/bin/initos-init-vm
root=/dev/vda
rootfstype=erofs
initos_modules=/dev/vdb
```

It prepares a writable virtiofs share with tag `src`. The vendored
`initos-init-vm` script mounts that share at `/src`, mounts the modules image at
`/lib/modules/$(uname -r)`, and executes:

```text
/src/initos/initos-pod start
```

Host3-vm's checked-in `initos-pod` script then starts `mesh-init` with:

```bash
export PATH=/opt/ssh-mesh/bin:/opt/initos/bin:/opt/busybox/bin
export HOME=/home/system
export USER=system
export LOGNAME=system
export RUST_LOG=info
export MESH_INIT_SOCK=$HOME/run/mesh-init/control.sock
mesh-init
```

With that contract, host3-vm uses the same HOME-relative layout as host2 and host1:

```text
$HOME/etc/mesh-init/*.toml
$HOME/etc/ssh-mesh/mesh.yaml
$HOME/.ssh/config
$HOME/run/*
```

Persistent config and runtime state come from the host example state tree,
exposed to the guest as `/src/host3-vm/home/system`.

When QEMU user networking is used, `vrun` forwards:

```text
127.0.0.1:18322 -> guest:18322
127.0.0.1:18380 -> guest:18380
```

Host3-vm imports the host1 and host2 `mesh9p` exports through the QEMU host
gateway:

```text
10.0.2.2:15101 -> /tmp/mesh/9p/host1
10.0.2.2:15102 -> /tmp/mesh/9p/host2
```

The guest also starts `mesh9p-host3-vm`, exporting `/home/system`,
`/tmp/mesh/9p`, and `/opt` on guest TCP port `15103`.

The host-side ports can be changed with `SSH_MESH_HOST3_VM_HOST_SSH_PORT` and
`SSH_MESH_HOST3_VM_HOST_HTTP_PORT`; guest ports remain `18322` and `18380`. The
example uses QEMU user networking only. The shared 9p filesystem is for config
and state. Runtime binaries come from `/opt` in the EROFS rootfs.
