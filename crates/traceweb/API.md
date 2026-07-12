# traceweb API

`traceweb` is an activated JSONL service. It does not link or serve HTTP. The
browser-facing UI and REST/SSE adapters live in `ssh-mesh`.

The control socket is normally provided by mesh-init systemd-style socket activation at:

```text
/home/traceweb/run/traceweb/control.sock
```

Requests may use flat JSONL or JSON-RPC 2.0. One JSON object is sent per line.

Flat request:

```json
{"method":"discover"}
```

JSON-RPC request:

```json
{"jsonrpc":"2.0","id":1,"method":"discover","params":{}}
```

Flat success responses use the mesh `success/data` shape. JSON-RPC success responses
place the payload in `result`.

## Lightweight MCP Methods

All traceweb JSONL connections also support the shared mesh MCP-compatible methods:

The `tools/list` command catalog is the hand-maintained
`resources/tools.json`. Keep it in sync with this document when the public
command surface changes; do not generate it from Rust code.

| Method | Result |
| --- | --- |
| `initialize` | Protocol version, server info, and `tools`/`resources` capabilities. |
| `tools/list` | Contents of `tools.json` from `MESH_RES_DIR`, otherwise `/home/traceweb/etc/resources` overlaying `/opt/traceweb/resources`. |
| `tools/call` | Calls the native traceweb method named by `name`, with `arguments` mapped to normal method params. |
| `resources/list` | File resources from the same resource lookup plus registered resources. |
| `resources/read` | Reads a listed `file://` resource when it is under the resolved resource directories. |

## Methods

| Method | Params | Result |
| --- | --- | --- |
| `discover` | none | Array of discovered trace producer sockets. Alias: `discover_sockets`. |
| `sources` | none | Array of currently connected trace sources. Alias: `list_sources`. |
| `connect_source` | `name: string`, `path: string \| null` | `{ "connected": name }`. If `path` is omitted, uses `<base_dir>/<name>.sock`. |
| `disconnect_source` | `name: string` | `{ "disconnected": name }` or an error if not connected. |
| `set_source_level` | `name: string`, `level: string` | Producer acknowledgement from the trace socket. |
| `subscribe` | `sources: string[] \| null` | Streaming method. Sends JSON-RPC notifications on the same connection. |

Discovered socket entries:

| Field | Type | Description |
| --- | --- | --- |
| `name` | `string` | Source name, derived from the socket filename stem. |
| `path` | `string` | Full socket path. |
| `connected` | `boolean` | Whether traceweb currently has a reader connected. |

Connected source entries:

| Field | Type | Description |
| --- | --- | --- |
| `name` | `string` | Source name. |
| `socket_path` | `string` | Connected producer socket path. |
| `connected` | `boolean` | Always `true` while listed. |

## Notifications

`subscribe` keeps the connection open and emits JSON-RPC notifications:

```json
{"jsonrpc":"2.0","method":"trace_entry","params":{"source":"mesh-init","timestamp":"...","level":"info","target":"...","message":"...","fields":{}}}
```

`params` contains a source-tagged `mesh::local_trace::LogEntry`:

| Field | Type | Description |
| --- | --- | --- |
| `source` | `string` | Connected source name. |
| `timestamp` | `string` | RFC3339 timestamp from the producer. |
| `level` | `string` | `trace`, `debug`, `info`, `warn`, or `error`. |
| `target` | `string` | Rust tracing target/module. |
| `message` | `string` | Event message. |
| `fields` | `object \| null` | Structured tracing fields when present. |

## Trace Producer Protocol

Trace producers expose sockets under the trace base directory, usually
`$TRACE_SOCKET_DIR` or `/home/traceweb/run/traceweb`. `traceweb` sends a `TraceConfig` line to a
producer before reading log entries. `set_source_level` sends a control `TraceConfig`
with `control: true` and waits for one acknowledgement line.
