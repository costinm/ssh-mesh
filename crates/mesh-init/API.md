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
