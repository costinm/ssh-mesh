# App VM debugging

These commands are for manually debugging app VM activation from a running
`docs/examples/start_all.sh` environment.

## SSH Into Host3 As Root

From the repository root:

```bash
cd /ws/rust/ssh-mesh/docs/examples
ssh -F ssh_config host3-vm-root
```

Directly through host3-vm's forwarded SSH port:

```bash
cd /ws/rust/ssh-mesh/docs/examples
ssh -F ssh_config host3-vm-root-direct
```

If the environment was started with a non-default forwarded port, pass it
explicitly:

```bash
cd /ws/rust/ssh-mesh/docs/examples
ssh -F ssh_config -p 29322 host3-vm-root-direct
```

## Mesh-Init Commands

Inside host3-vm, `mesh-init` supports:

```bash
mesh-init status [SERVICE]
mesh-init start SERVICE [ARGS...]
mesh-init stop SERVICE [--signal SIGNAL]
mesh-init reload
mesh-init freeze SERVICE
mesh-init unfreeze SERVICE
mesh-init shutdown
```

Check and start app2/app3:

```bash
mesh-init status activate-app2-qemu
mesh-init start activate-app2-qemu
mesh-init status activate-app2-qemu

mesh-init status activate-app3-crosvm
mesh-init start activate-app3-crosvm
mesh-init status activate-app3-crosvm
```

If `mesh-init status activate-app2-qemu` or `activate-app3-crosvm` returns
`service not found`, check that host3-vm is running with the current example
configs:

```bash
ls -la /home/system/etc/mesh-init/
cat /home/system/etc/mesh-init/app2-qemu.toml
cat /home/system/etc/mesh-init/app3-crosvm.toml
mesh-init reload
```

## Trigger Activation Manually

The normal routed SSH path connects to host3-vm's activation sockets. You can
trigger the same listener from inside host3-vm:

```bash
/opt/busybox/bin/nc -U /tmp/mesh/shared/app2-qemu/trusted.sock </dev/null
/opt/busybox/bin/nc -U /tmp/mesh/shared/app3-crosvm/trusted.sock </dev/null
```

A bare socket connect may fail as an SSH session, but it should still cause
`mesh-init` to spawn the activation service.

## Logs And State

Host3-vm mesh-init:

```bash
ls -l /home/system/run/mesh-init/control.sock
cat /home/system/run/mesh-init/mesh-init.log
```

App2 QEMU state:

```bash
ls -la /src/app2-qemu/vm/
cat /src/app2-qemu/vm/launch.log
cat /src/app2-qemu/vm/virtiofs.log
cat /src/app2-qemu/vm/console.log
```

App3 crosvm state:

```bash
ls -la /src/app3-crosvm/vm/
cat /src/app3-crosvm/vm/launch.log
cat /src/app3-crosvm/vm/virtiofs.log
cat /src/app3-crosvm/vm/console.log
```

From the host, if the default state root is used, the same files are under:

```bash
target/examples/app2-qemu/vm/
target/examples/app3-crosvm/vm/
target/examples/logs/host3-vm.log
```
