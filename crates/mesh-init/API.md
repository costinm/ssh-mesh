# `mesh-init` — UDS Control Protocol API

`mesh-init` exposes a JSONL (JSON lines) control interface over a Unix Domain Socket (UDS) located at `/run/system/mesh-init/control.sock` (or `$HOME/run/mesh-init/control.sock` in user mode).

Clients can interact using flat JSON structures where the `method` field defines the action. The protocol supports standard control requests as well as file descriptor-passing requests via Unix domain socket ancillary data (`SCM_RIGHTS`).

---

## Response Structure

Every request returns a single JSON object line with the following shape:

```json
{
  "success": true,
  "error": "Error message string if success is false",
  "data": { ... } // Optional key-value payload returned by the method
}
```

---

## 1. Core Service Lifecycle Methods

### `start`
Start a configured service by name. If not already running, loads config and spawns.
*   **Parameters:**
    *   `name` (String, Required): Name of the service (e.g. `ssh-mesh`).
    *   `args` (Array of Strings, Optional): Additional arguments to append to the command.
    *   `env` (Object of key-value String pairs, Optional): Additional environment variables.
    *   `context` (Object, Optional): Caller's activation context.

### `stop`
Gracefully terminate or forcibly kill a running service.
*   **Parameters:**
    *   `name` (String, Required): Name of the service.
    *   `signal` (Integer, Optional): Specific signal to send (defaults to `SIGTERM`).

### `freeze`
Freeze (suspend) a running service via SIGSTOP or cgroup.freeze.
*   **Parameters:**
    *   `name` (String, Required): Name of the service.

### `unfreeze`
Unfreeze (resume) a suspended service.
*   **Parameters:**
    *   `name` (String, Required): Name of the service.

### `status`
Query status of a specific service or list all loaded services.
*   **Parameters:**
    *   `name` (String, Optional): If omitted, returns statuses for all services.
*   **Returns:**
    *   `data`: Map of service names to service state and PID information.

### `reload`
Reload all service configurations from disk and restart modified services.

### `shutdown`
Gracefully shut down all services and exit the daemon.

---

## 1b. Impersonation Protocol

Trusted peers (sshd, ssh-mesh, system) may start processes running as a
different UID than their own. This is how SSH users get shells as their
target UID, and how the ssh-mesh admin web UI runs commands as `system`.

### Connection-level authentication

When a UDS connection is accepted, mesh-init reads the peer's UID/GID via
`SO_PEERCRED` (kernel-verified, unforgeable). The peer UID must be in the
builtin allowlist:

| UID  | Identity     | Env var                | Capabilities                                     |
|------|--------------|------------------------|--------------------------------------------------|
| 0    | root         | —                      | All operations, any target UID                   |
| 1000 | system       | `MESH_SYSTEM_UID`      | All operations, any target UID (root-equivalent) |
| 103  | sshd         | `MESH_TRUSTED_SSHD_UID`| Terminal/start/stop/freeze, any target UID       |
| 150  | ssh-mesh     | `MESH_SSH_MESH_UID`    | Terminal/start/stop/freeze, any target UID       |

**UID 1000 (system) is root-equivalent.** It can call system-wide observer
methods (`freeze_process`, `move_process`, `cgroup_high`, `clear_refs`,
`freeze_cgroup`) on any PID or cgroup. The sshd and ssh-mesh UIDs are
**not** authorized for those methods — they must use the named-service APIs
(`start`/`stop`/`freeze`/`unfreeze`).

Each env var can be set to `none` or `off` to disable that UID. The full
list can be overridden with `MESH_INIT_PRIVILEGED_UIDS` (comma-separated).

### Per-request impersonation

Impersonation is specified in the request body, not in the connection. The
peer's UID (from `SO_PEERCRED`) is the *acting* identity; the request's
`uid`/`gid` fields are the *target* identity. mesh-init verifies that the
acting UID is in `privileged_uids()` before allowing a target that differs.

#### `start_terminal` — impersonation fields

| Field       | Type   | Purpose                                         |
|-------------|--------|-------------------------------------------------|
| `uid`       | u32    | Target UID to run the shell/command as.         |
| `gid`       | u32?   | Target GID. If `None`, uses the target UID.     |
| `name`      | String | Service/config name (also used as `USER`/`LOGNAME`). |
| `home`      | String | Home directory (must exist; becomes `HOME`).    |
| `command`   | String?| Shell command (`sh -c <command>`). If `None`, interactive shell. |
| `context`   | Object?| `ActivationContext` carrying provenance (see below). |
| `env`       | Object?| Additional environment variables merged into the child. |
| `pty`       | bool?  | If `true`, the passed fd becomes the controlling terminal. |
| `fd_count`  | u32?   | Number of FDs passed via `SCM_RIGHTS` (default 1). |

#### `start` — impersonation fields

| Field      | Type   | Purpose                                              |
|------------|--------|------------------------------------------------------|
| `name`     | String | Service name. The service config's `User=` determines the target UID. |
| `args`     | [String]? | Extra args appended to `ExecStart`.               |
| `env`      | Object?| Additional env merged with the config's environment. |
| `context`  | Object?| `ActivationContext` carrying provenance (see below). |

For `start`, the target UID comes from the service config (`User=` field),
not from the request. mesh-init re-checks `check_impersonation` after
reloading the config from disk to prevent TOCTOU escalation.

#### `prepare_activation` — pre-staging context for socket activation

When a socket-activated service is triggered by an incoming connection
(rather than an explicit `start` call), the trusted peer can pre-stage an
`ActivationContext` so that the service receives provenance information when
it spawns:

```json
{"method":"prepare_activation","name":"my-service","context":{...}}
```

The context is queued (max 32 per service) and consumed by the next
socket-activation spawn for that service.

### `ActivationContext` fields

The `context` object carries **provenance** — who triggered the activation
and why. It does not affect the target UID (that's `uid`/`gid` in the
request, or `User=` in the config). It is metadata that gets injected as
environment variables into the child process.

| Field               | Type    | Set by     | Env var(s) generated                          |
|---------------------|---------|------------|-----------------------------------------------|
| `kind`              | String  | ssh-mesh   | `MESH_INIT_CONTEXT_KIND`                      |
| `user`              | String  | ssh-mesh   | `MESH_INIT_CONTEXT_USER`, `SSH_MESH_ROUTE_USER` |
| `command`           | String? | ssh-mesh   | `MESH_INIT_CONTEXT_COMMAND`, `SSH_MESH_ROUTE_COMMAND` |
| `certificate_user`  | String? | ssh-mesh   | `SSH_MESH_ROUTE_CERTIFICATE_USER`             |
| `peer_key_sha`      | String? | ssh-mesh   | `SSH_MESH_ROUTE_PEER_KEY_SHA`                 |
| `client_id`         | u64?    | ssh-mesh   | `SSH_MESH_ROUTE_CLIENT_ID`                    |
| `env`               | Object? | caller     | Merged directly into child env                |

The full context is also serialized as `MESH_INIT_CONTEXT_JSON`.

When `kind = "ssh"`, `user` is the SSH-authenticated username (from the
certificate principal or `authorized_keys`), `certificate_user` is the
cert principal (if any), and `peer_key_sha` is the SHA-256 fingerprint of
the peer's public key.

### Concrete flows

#### sshd → mesh-init (SSH terminal)

sshd (UID 103) authenticates an SSH user, then sends `start_terminal` with
the user's UID/GID:

```json
{
  "method": "start_terminal",
  "name": "alice",
  "home": "/home/alice",
  "uid": 1001,
  "gid": 1001,
  "pty": true,
  "env": {"TERM": "xterm-256color"},
  "context": {
    "kind": "ssh",
    "user": "alice",
    "certificate_user": "alice@corp.example.com",
    "peer_key_sha": "SHA256:abc123...",
    "client_id": 42
  },
  "fd_count": 1
}
```

mesh-init verifies `check_impersonation(peer_uid=103, target_uid=1001)` →
allowed (103 is in `privileged_uids`). The child runs as UID 1001 with
`SSH_MESH_ROUTE_USER=alice` in its environment.

#### ssh-mesh admin web UI → mesh-init (exec as system)

The ssh-mesh admin HTTP interface (`POST /_m/_exec/<cmd>`) impersonates
`system` (UID 1000) when calling mesh-init:

```json
{
  "method": "start_terminal",
  "name": "system",
  "home": "/tmp",
  "uid": 1000,
  "gid": 1000,
  "pty": false,
  "env": {},
  "context": null,
  "command": "ls -la /data"
}
```

mesh-init verifies `check_impersonation(peer_uid=150, target_uid=1000)` →
allowed (150 is in `privileged_uids`). The child runs as UID 1000 (system).

#### system (UID 1000) → mesh-init (direct control)

A process running as `system` connects to the control socket directly. It
can start/stop/freeze any service, call observer methods, and manage
cgroups — it is root-equivalent.

#### Non-privileged peer → mesh-init

A non-privileged peer (e.g., UID 5000) can only connect if listed in a
`[[peer]]` entry in `default.service` or `auth.toml`. Once connected, it
may only `start`/`stop`/`freeze` services whose config UID matches its own
(`check_impersonation` rejects UID mismatch). It cannot call observer
methods (`require_system_or_root` rejects).

---

## 2. File Descriptor-Passing Methods

These requests must be sent over the UDS accompanied by a file descriptor using `SCM_RIGHTS` ancillary data.

### `start_terminal`
Spawns a shell or command with its stdin/stdout/stderr attached to a passed PTY descriptor.
*   **Parameters:**
    *   `name` (String, Required): Name of the target configuration or service.
    *   `home` (String, Required): Shell home directory path.
    *   `uid` (Integer, Required): Run-as User ID.
    *   `gid` (Integer, Optional): Run-as Group ID.
    *   `pty` (Boolean, Optional): Treat the passed fd as a controlling terminal.
    *   `env` (Object, Optional): Environment variables.
    *   `command` (String, Optional): Execution command.
*   **Returns:**
    *   `data`: `{"pid": <child_pid>}`

### `register_namespace`
Exposes the network namespace descriptor of an in-container `mesh-init` process to the host.
*   **Parameters:**
    *   `name` (String, Required): Service name.
    *   `kind` (String, Optional): Namespace kind (`net` / `user`).
    *   `target_pid` (Integer, Optional): PID context of the container.

---

## 3. Terminal Control Methods

### `terminal_resize`
Resize the dimensions of a PTY associated with an active terminal session.
*   **Parameters:**
    *   `terminal_id` (String, Required): Terminal session ID.
    *   `col_width` (Integer, Required): Columns.
    *   `row_height` (Integer, Required): Rows.
    *   `pix_width` (Integer, Required): Pixels width.
    *   `pix_height` (Integer, Required): Pixels height.

### `terminal_command`
Send a control instruction (e.g. `close`, `hup`, `signal`) to a terminal session.
*   **Parameters:**
    *   `terminal_id` (String, Required): Terminal session ID.
    *   `command` (String, Required): Command verb.
    *   `data` (JSON value, Optional): Command parameters.

---

## 4. Process Observer Methods

These endpoints expose system diagnostics from the process observer.

### `processes` (Alias: `list_processes`)
Retrieve a snapshot of all observed processes.
*   **Returns:**
    *   `data`: Array of process records.

### `process` (Alias: `get_process`)
Retrieve comprehensive details for a single PID including cgroup association.
*   **Parameters:**
    *   `pid` (Integer, Required): Process ID.

### `process_only` (Alias: `ps_one`)
Retrieve a fast process record without cgroup structure expansion.
*   **Parameters:**
    *   `pid` (Integer, Required): Process ID.

### `cgroups` (Alias: `list_cgroups`)
List all active control groups.
*   **Returns:**
    *   `data`: Array of cgroups.

### `cgroup` (Alias: `get_cgroup`)
Retrieve resource consumption details for a specific cgroup.
*   **Parameters:**
    *   `path` (String, Required): Cgroup v2 folder path.

### `pressure` (Aliases: `psi`, `psi_watches`)
Retrieve memory pressure watch registers and current classifications.

### `cgroup_high`
Set `memory.high` limit on a cgroup for a specific period.
*   **Parameters:**
    *   `path` (String, Required): Target cgroup path.
    *   `percentage` (Float, Required): Memory threshold percentage.
    *   `interval` (Integer, Required): Duration in seconds before resetting.

### `cgroup_procs`
List processes currently running in a target cgroup path.
*   **Parameters:**
    *   `path` (String, Required): Cgroup path.

### `move_process`
Migrate a process into a target cgroup slice.
*   **Parameters:**
    *   `pid` (Integer, Required): Target process ID.
    *   `cgroup_name` (String, Optional): Target cgroup folder name.

### `clear_refs`
Instruct kernel to clear memory reference tables (`/proc/<pid>/clear_refs`).
*   **Parameters:**
    *   `pid` (Integer, Required): Process ID.
    *   `value` (String, Required): Reference clear type ("1"-"5" or "7").

### `freeze_process`
Suspend or resume a single process.
*   **Parameters:**
    *   `pid` (Integer, Required): Target process ID.
    *   `freeze` (Boolean, Required): True to freeze, False to thaw.

### `freeze_cgroup`
Suspend or resume all processes inside a cgroup.
*   **Parameters:**
    *   `path` (String, Required): Cgroup path.
    *   `freeze` (Boolean, Required): True to freeze, False to thaw.
