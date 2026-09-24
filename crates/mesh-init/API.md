# `mesh-init` API (3)

Transport, framing, JSON-RPC, tagged-CBOR, and descriptor-passing rules are
shared in [mesh-api/PROTOCOLS.md](../mesh-api/PROTOCOLS.md). Root-run mesh-init
exposes the legacy stream endpoint at `/run/mesh/mesh-init/mesh.sock` and its
tagged-CBOR seqpacket endpoint at `/run/mesh/mesh-init/mesh.sock.cbor`.

Field tags are stable wire identities. The generated public catalog is
`resources/tools.json`; regenerate it and `src/api.rs` after changing this
document.

## 1. `status` — Query status for one service or all loaded services

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `name` | `string` | |

## 2. `start` — Start a configured service by name

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `name` | `string` | |
| 2 | `args` | `array` | |
| 3 | `env` | `object` | |

## 3. `stop` — Gracefully terminate or signal a running service

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `name` | `string` | |
| 2 | `signal` | `i32` | |

## 4. `freeze` — Suspend a running service

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `name` | `string` | |

## 5. `unfreeze` — Resume a frozen service

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `name` | `string` | |

## 6. `reload` — Reload service configuration from disk

## 14. `reconcile` — Reconcile managed services after host resume or recovery

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `checked` | `u64` | |
| 2 | `reconciled` | `u64` | |
| 3 | `failed` | `u64` | |

## 15. `shutdown` — Gracefully stop all services and shut down mesh-init

## 7. `processes` — List observed processes from the process observer

## 8. `process` — Return detailed information for one process

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `pid` | `u32` | |

## 9. `cgroups` — Return all observed cgroups

## 10. `cgroup` — Return detailed information for one cgroup path

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `path` | `string` | |

## 11. `pressure` — Return pressure watch state

## 12. `cgroup_high` — Set memory.high for a cgroup based on current memory usage

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `path` | `string` | |
| 2 | `percentage` | `f64` | |
| 3 | `interval` | `u64` | |

## 13. `move_process` — Move a process to a named cgroup

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `pid` | `u32` | |
| 2 | `cgroup_name` | `string` | |

## 16. `start_terminal` — Start a terminal with descriptors attached to its CBOR seqpacket request

The caller supplies an already-authorized target identity and its home. For a
user command this is the authenticated user's UID/GID/home. When a gateway has
resolved a registered service and authorized the caller for it, the target is
that service's configured identity and service home. mesh-init verifies that
the supplied home belongs to the requested UID before spawning; it does not
silently substitute the control client's home.

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `name` | `string` | |
| 2 | `home` | `string` | |
| 3 | `uid` | `u32` | |
| 4 | `gid` | `u32` | |
| 5 | `pty` | `bool` | |
| 6 | `env` | `object` | |
| 7 | `context` | `object` | |
| 8 | `command` | `string` | |
| 9 | `fd_count` | `u32` | |

## 17. `register_namespace` — Register a namespace descriptor attached to its CBOR seqpacket request

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `name` | `string` | |
| 2 | `kind` | `string` | |
| 3 | `target_pid` | `u32` | |
