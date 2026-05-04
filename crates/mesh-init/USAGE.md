# mesh-init Usage Guide

`mesh-init` is a lightweight daemon that manages local background services, their lifecycle, resources (using cgroups v2), and supports socket activation.

## Quick Start

### Running the Daemon manually in a test directory

You can test `mesh-init` without installing it system-wide by providing a custom config directory.

```bash
# 1. Create a temporary configs directory
TEST_DIR=$(mktemp -d)

# 2. Add a simple service config
cat <<EOF > $TEST_DIR/echo-service.toml
[service]
name = "echo-service"
command = "/bin/sleep"
args = ["3600"]
priority = 100

[resources]
memory_max = "64M"
EOF

# 3. Start the mesh-init daemon in the background
export MESH_INIT_DIR="$TEST_DIR"
export RUST_LOG="info"
./target/debug/mesh-init &
```

As regular user, '$HOME/.config/mesh-init' is used as default for configs and
'$HOME/.run/mesh-init' for sockets.

Top slice is /sys/fs/cgroup/mesh.slice is used for cgroups and should be owned by the 
user. TODO: make this customizable so different users can manage their groups (like /run/user).


### Running the automated test environment

The project includes an integration script that runs tests and starts up test config examples. 

```bash
# This builds the project and runs the test suite
bash crates/mesh-init/test_bwrap.sh
```
Test configs are located at `crates/mesh-init/testdata/` and the built artifacts go to `target/debug/testdata/`.

## Client Commands (CLI via `mesh`)

Once the `mesh-init` daemon is running, you can interact with it using the `mesh` CLI. 

```bash
# Get the status of all services
./target/debug/mesh mesh-init status

# Start a specific service
./target/debug/mesh mesh-init start echo-service

# Get the status of a specific service
./target/debug/mesh mesh-init status echo-service

# Stop a running service
./target/debug/mesh mesh-init stop echo-service

# Reload all service configurations (e.g. after editing a .toml file)
./target/debug/mesh mesh-init reload

# Shutdown the daemon and all services
./target/debug/mesh mesh-init shutdown
```

## Socket Activation Configuration

`mesh-init` supports inetd-style (accepting) and xinetd-style (passing listeners) socket activation. When configured, `mesh-init` defers starting the service until traffic hits the socket.

```toml
[service]
name = "activated_svc"
command = "/bin/sh"
args = ["-c", "echo SUCCESS"]

[[activation]]
# Listen on TCP port 14022
port = 14022
# wait = false means mesh-init calls accept() and passes the conn down via stdin/stdout
wait = false 
```

To use `wait = true` (xinetd-style), your program must be able to adopt a raw listening socket via standard the `LISTEN_FD` environment variable instead of binding itself.

### UDS Socket Activation

You can also use Unix Domain Sockets for activation:

```toml
[service]
name = "uds_svc"
command = "/bin/sh"
args = ["-c", "echo SUCCESS"]

[[activation]]
# Listen on a Unix Domain Socket instead of TCP
socket = "/tmp/uds_svc.sock"
wait = false
```

## Control Socket (UDS)

`mesh-init` listens for control commands (like `start`, `stop`, `status` via the `mesh` CLI) on a Unix Domain Socket. The location of this socket is determined as follows:

1. If the `MESH_INIT_RUN` environment variable is set, the socket will be created at `$MESH_INIT_RUN/control.sock`.
2. Otherwise, if the daemon is running as `root` (UID 0), the socket is created at `/run/mesh-init/control.sock`.
3. If running as a non-root user, the socket is created at `$HOME/.run/mesh-init/control.sock` (or `/tmp/.run/mesh-init/control.sock` if `HOME` is unset).

## Execution Mode

If you run `mesh-init` with arguments, it runs in **command execution mode**: it executes the command in the foreground, then cleans up and exits.

```bash
./target/debug/mesh-init sleep 5
```

In execution mode, `mesh-init` still loads configs from `$MESH_INIT_DIR` (or `$HOME/.config/mesh-init`):

### `default.toml`

If a `default.toml` exists in the config directory, its settings are applied to the main command. This allows you to configure UID, GID, resource limits, and environment variables for the executed process without specifying them on the command line.

```toml
# $MESH_INIT_DIR/default.toml
[service]
name = "default"
command = "_placeholder_"
uid = 1000
gid = 1000
priority = 0

[resources]
memory_max = "256M"
cpu_weight = 100

[environment]
RUST_LOG = "info"
```

### `init-*` Services

Any config file named `init-*.toml` (e.g. `init-setup.toml`, `init-network.toml`) is treated as an **init service**. These are:

- Started **before** the main command and all other services.
- Sorted by `priority` (lower = runs first).
- If `oneshot = true`, `mesh-init` waits for them to complete before proceeding.

This is also true in daemon mode: `init-*` services always start before regular services.

```toml
# $MESH_INIT_DIR/init-setup.toml
[service]
name = "init-setup"
command = "/bin/sh"
args = ["-c", "mkdir -p /data/app && chown 1000:1000 /data/app"]
priority = 10
oneshot = true
```

## Job Execution (Android-Style JobScheduler)

`mesh-init` embeds a fully-featured job scheduler inspired by the Android `JobScheduler` API. Jobs are executed as isolated services based on constraints and triggers, ensuring reliability and system health (e.g. deferring work until a specific network type is available or the device is charging).

Jobs are defined using TOML files and are persisted across reboots. By default, `mesh-init` loads jobs from `$HOME/.config/mesh/jobs/`. 

### Defining a Job

A job definition sets up the command to run, timing schedules, system constraints, and backoff policies for retries. 

Create a job file at `$HOME/.config/mesh/jobs/sync-data.toml`:

```toml
name = "sync-data"
command = "mesh-init"
args = ["start", "sync-service"]
priority = 300
persisted = true
# If true, work item results will be saved back to disk when completed
save_result = true 

[schedule]
periodic_secs = 3600       # Run every hour
flex_secs = 900            # Allow a ±15 minute execution window

[constraints]
network_type = "unmetered"     # "none", "any", "unmetered", "notroaming", "cellular"
requires_charging = false
requires_battery_not_low = true

[constraints.custom]
# You can define custom boolean conditions that must be met
vpn_connected = true

[backoff]
initial_secs = 30
policy = "exponential"     # "linear" or "exponential"
max_retries = 5

[environment]
SYNC_MODE = "incremental"
```

### Work Items

You can enqueue specific, discrete pieces of work into a job. The job service receives these items and processes them. Work items are saved as separate TOML files inside a `work/` directory for that job (e.g., `$HOME/.config/mesh/jobs/sync-data/work/item-001.toml`).

```toml
id = "item-001"
enqueued_at = "2026-04-26T22:00:00Z"
delivery_count = 0

[data]
source = "/data/uploads/file1.dat"
destination = "remote:/backup/"
```

### Job Lifecycle
- **Evaluation:** `mesh-init` automatically evaluates constraints (e.g. checking if the battery is no longer low) through UDS system events.
- **Execution:** When all constraints and timing schedules are satisfied, `mesh-init` executes the target process and passes any pending work item IDs via the `MESH_JOB_WORK_ITEMS` environment variable.
- **Completion:** Completed work items can either be deleted or stored in the `completed/` subdirectory with an associated result blob/map if `save_result = true` is enabled on the job.
