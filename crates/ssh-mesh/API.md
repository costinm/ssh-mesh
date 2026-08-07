# ssh-mesh API

`ssh-mesh` owns the HTTP-facing API surface for the workspace. Components such as
`mesh-init` expose local JSONL/JSON-RPC over activated Unix
sockets; ssh-mesh maps selected HTTP routes to those sockets.

## JSONL Proxying

Internal proxy calls use newline-delimited JSON over UDS. `ssh-mesh` can send either:

```json
{"method":"ps"}
```

or JSON-RPC 2.0:

```json
{"jsonrpc":"2.0","id":1,"method":"discover","params":{}}
```

Responses are unwrapped for HTTP clients:

| Upstream shape | HTTP JSON body |
| --- | --- |
| JSON-RPC `{ "result": ... }` | `result` |
| mesh `{ "success": true, "data": ... }` | `data` |
| JSON-RPC or mesh error | `502` with `{ "error": string }` |

## MCP JSON-RPC

Base route: `POST /_m/mcp/`

This endpoint uses the same `mesh::jsonl` lightweight MCP dispatcher over HTTP JSON. It
supports:

The `tools/list` command catalog is generated as `resources/tools.json` from
the public structured blocks in each component's `API.md`. Component catalogs
live beside their crates and may be served by the generic app proxy; `API.md`
is the source of truth.

| Method | Result |
| --- | --- |
| `initialize` | Protocol version, server info, and `tools`/`resources` capabilities. |
| `tools/list` | Contents of `tools.json` from `MESH_RES_DIR`, otherwise `/home/ssh-mesh/etc/resources` overlaying `/opt/ssh-mesh/resources`. |
| `tools/call` | Calls a native ssh-mesh MCP method by `name`. |
| `resources/list` | File resources from the same resource lookup plus registered resources. |
| `resources/read` | Reads a listed `file://` resource when it is under the resolved resource directories. |

Native ssh-mesh MCP method:

| Method | Params | Result |
| --- | --- | --- |
| `jsonl_call` | `socket_path: string`, `method_name: string`, `params: object \| null` | Sends a JSON-RPC request to a component UDS and returns the unwrapped result. |

## Trace Proxy

Base route: `/_m/trace`

`ssh-mesh` serves its own telemetry and trace viewer directly using the `mesh` telemetry API.

| HTTP route | Description |
| --- | --- |
| `GET /_m/trace/` | Serves the trace viewer from ssh-mesh web assets. |
| `GET /_m/trace/web/*path` | Serves trace viewer assets. |
| `GET /_m/trace/level` | Returns current tracing filter level info. |
| `POST /_m/trace/level` / `PUT /_m/trace/level` | JSON body: `{ "level": "debug" }`. Updates tracing level. |
| `POST /_m/trace/api/sources/:name/level` | JSON body: `{ "level": "debug" }`. Updates tracing level. |
| `GET /_m/trace/api/stream` | Streams live trace log events via Server-Sent Events (SSE). |


## Generic App Proxy

Base route: `/_m/proxy`

The upstream UDS path comes from `<APP>_UDS` when set. Otherwise `mesh-init`
defaults to the shared mesh endpoint:

```text
/run/mesh/mesh-init/mesh.sock
```

| HTTP route | Description |
| --- | --- |
| `POST /_m/proxy/jsonl/:app` | Sends the JSON body as one flat JSONL request. |
| `POST /_m/proxy/jsonrpc/:app` | Sends a JSON-RPC request to the app UDS. |
| `POST /_m/proxy/mcp/:app?tools=mesh/tools.json` | Serves generic MCP methods and maps `tools/call` to the app UDS. |

## SSH Routes

The existing SSH, TCP, UDS, exec, ssh-client, and OpenAPI routes remain under `/_m`.
They are documented in `AGENTS.md` and generated OpenAPI output where available.
