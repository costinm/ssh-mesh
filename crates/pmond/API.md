# pmond API

`pmond` exposes its control API as newline-delimited JSON over a Unix domain socket. The
socket is normally provided by mesh-init systemd-style socket activation at:

```text
/home/pmond/run/pmond/control.sock
```

The same methods can be called using flat JSONL or JSON-RPC 2.0. One request is sent per
line and one response is returned per line.

Flat request:

```json
{"method":"ps"}
```

JSON-RPC request:

```json
{"jsonrpc":"2.0","method":"ps","id":1}
```

Flat success responses use the mesh response shape:

```json
{"success":true,"data":...}
```

JSON-RPC success responses put the payload in `result`; errors use either the mesh
`success:false,error` shape or JSON-RPC `error`, depending on the request format.

## Lightweight MCP Methods

All pmond JSONL connections also support the shared mesh MCP-compatible methods:

| Method | Result |
| --- | --- |
| `initialize` | Protocol version, server info, and `tools`/`resources` capabilities. |
| `tools/list` | Built-in pmond tools from `resources/tools.json`, recovered from the former `crates/mcp` wrapper. Generic mesh services may instead use `MESH_RES_DIR/tools.json` or the standard `/home/<app>/etc/resources` over `/opt/<app>/resources` lookup. |
| `tools/call` | Calls the native pmond method named by `name`, with `arguments` mapped to normal method params. |
| `resources/list` | File resources from the shared resource lookup plus registered resources. |
| `resources/read` | Reads a listed `file://` resource when it is under the resolved resource directories. |

Example:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"process","arguments":{"pid":1}}}
```

## Methods

| Method | Params | Result |
| --- | --- | --- |
| `ps` | none | Array of process snapshots from pmond's cached process view. Alias: `list_processes`. |
| `process` | `pid: u32` | Detailed process record including process info, current cgroup detail, and parent cgroups. Alias: `get_process`. |
| `process_only` | `pid: u32` | Single process record without cgroup expansion. Alias: `ps_one`. |
| `cgroup` | `path: string` | Detailed cgroup memory information for one cgroup path. Alias: `get_cgroup`. |
| `cgroups` | none | Map of all known cgroups with memory information. Alias: `list_cgroups`. |
| `psi` | none | Current PSI watch state. Alias: `psi_watches`. |
| `cgroup_high` | `path: string`, `percentage: f64`, `interval: u64` | Sets `memory.high` for the cgroup from current usage and returns success. |
| `cgroup_procs` | `path: string` | Array of process records currently in the cgroup. |
| `move_process` | `pid: u32`, `cgroup_name: string \| null` | Moves a process to the named cgroup, or the default target when null. |
| `clear_refs` | `pid: u32`, `value: string` | Writes to `/proc/<pid>/clear_refs` and returns a status message. |
| `freeze_process` | `pid: u32`, `freeze: bool` | Freezes or thaws the process cgroup. |
| `freeze_cgroup` | `path: string`, `freeze: bool` | Freezes or thaws the cgroup. |

## Events

Push-style operational events are emitted through normal `tracing` output and mesh local
trace handling. Clients should use the common mesh trace subscription path instead of a
pmond-specific subscribe method.

## HTTP Compatibility

`pmond` does not link or serve HTTP. The `ssh-mesh` crate provides HTTP compatibility
routes under `/_m/pmon/*` by forwarding HTTP requests to this JSONL socket.
