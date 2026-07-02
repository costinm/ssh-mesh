# mesh-init Usage Guide

`mesh-init` manages local background services, lifecycle, cgroup resources, and
socket activation. Service configs use systemd-style `.service` and `.socket`
files with a small set of mesh-init extensions.

See `CONFIG.md` for the complete supported field list.

## Quick Start

You can test `mesh-init` without installing it system-wide by providing a custom
config directory.

```bash
TEST_DIR=$(mktemp -d)

cat <<EOF > "$TEST_DIR/echo-service.service"
[Service]
ExecStart = "/bin/sleep 3600"
OOMScoreAdjust = -900

[Resources]
MemoryMax = "64M"
EOF

export MESH_INIT_DIR="$TEST_DIR"
export RUST_LOG="info"
./target/debug/mesh-init &
```

As a regular user, `$HOME/etc/mesh-init` is used for configs and
`$HOME/run/mesh-init` for sockets. The top cgroup slice is
`/sys/fs/cgroup/mesh.slice` and must be writable by the user running
`mesh-init`.

## Tests

```bash
bash crates/mesh-init/test.sh
```

Test configs live in `crates/mesh-init/testdata/`; built artifacts go under the
workspace `target/` directory.

## Client Commands

```bash
./target/debug/mesh mesh-init status
./target/debug/mesh mesh-init start echo-service
./target/debug/mesh mesh-init status echo-service
./target/debug/mesh mesh-init stop echo-service
./target/debug/mesh-init reload
./target/debug/mesh mesh-init shutdown
```

## Socket Activation

Sockets are declared only with `.socket` files. A matching `name.socket` targets
`name.service` unless `Service=` is set in the socket file.

`Accept=false` passes listener FDs to the service using systemd activation
(`LISTEN_FDS`, starting at fd 3). `Accept=true` accepts each connection in
`mesh-init` and passes the accepted socket as stdin/stdout/stderr.

```toml
# activated_svc.service
[Service]
ExecStart = "/bin/sh -c 'echo SUCCESS'"
```

```ini
# activated_svc.socket
[Socket]
ListenStream=14022
Accept=true
```

Hybrid activation also uses `.socket` files, but accepted sockets are forwarded
to the service's JSONL Unix socket with `SCM_RIGHTS`.

```toml
# hybrid_svc.service
[Service]
ExecStart = "/opt/ssh-mesh/bin/hybrid_svc"
MeshActivationMode = "hybrid"
MeshActivationSocket = "/run/hybrid_svc/control.sock"
```

```ini
# hybrid_svc.socket
[Socket]
ListenStream=/run/hybrid_svc/public.sock
Accept=true
```

## Execution Mode

If you run `mesh-init` with arguments, it executes the command in the foreground,
then cleans up and exits.

```bash
./target/debug/mesh-init sleep 5
```

In execution mode, `default.service` in `$MESH_INIT_DIR` provides defaults for
the foreground command.

```toml
# $MESH_INIT_DIR/default.service
[Service]
ExecStart = "_placeholder_"
User = "1000"
Group = "1000"
OOMScoreAdjust = -1000

[Resources]
MemoryMax = "256M"
CPUWeight = 100

[Environment]
RUST_LOG = "info"
```

Files named `init-*.service` run before the main command and regular services.
Use `Type = "oneshot"` when `mesh-init` should wait for completion and avoid
restarting the init service.

```toml
# $MESH_INIT_DIR/init-setup.service
[Service]
ExecStart = "/bin/sh -c 'mkdir -p /data/app && chown 1000:1000 /data/app'"
OOMScoreAdjust = -990
Type = "oneshot"
```

## Jobs

The job scheduler persists job definitions as TOML files under
`$HOME/etc/mesh/jobs/`. Job files use the same `[Service]` command shape as
service units, plus mesh-specific schedule and constraint sections.

```toml
MeshPersisted = true
MeshSaveResult = true

[Service]
ExecStart = "mesh-init start sync-service"
OOMScoreAdjust = -700

[Schedule]
periodic_secs = 3600
flex_secs = 900

[Constraints]
network_type = "unmetered"
requires_battery_not_low = true

[Backoff]
initial_secs = 30
policy = "exponential"
max_retries = 5
```

Work items remain separate TOML files inside each job's `work/` directory.
