# lmesh API

`lmesh` exposes local mesh discovery control as newline-delimited JSON over a Unix
domain socket. The socket is normally provided by mesh-init systemd-style socket
activation at:

```text
/home/lmesh/run/lmesh/control.sock
```

The same methods can be called using flat JSONL or JSON-RPC 2.0. One request is sent per
line and one response is returned per line.

Flat request:

```json
{"method":"nodes"}
```

JSON-RPC request:

```json
{"jsonrpc":"2.0","method":"nodes","id":1}
```

Flat success responses use the mesh response shape:

```json
{"success":true,"data":...}
```

JSON-RPC success responses put the payload in `result`; errors use either the mesh
`success:false,error` shape or JSON-RPC `error`, depending on the request format.

## Lightweight MCP Methods

All lmesh JSONL connections also support the shared mesh MCP-compatible methods:

| Method | Result |
| --- | --- |
| `initialize` | Protocol version, server info, and `tools`/`resources` capabilities. |
| `tools/list` | Contents of `tools.json` from `MESH_RES_DIR`, otherwise `/home/lmesh/etc/resources` overlaying `/opt/lmesh/resources`. |
| `tools/call` | Calls the native lmesh method named by `name`, with `arguments` mapped to normal method params. |
| `resources/list` | File resources from the same resource lookup plus registered resources. |
| `resources/read` | Reads a listed `file://` resource when it is under the resolved resource directories. |

## Methods

| Method | Params | Result |
| --- | --- | --- |
| `nodes` | none | Array of currently discovered nodes. Alias: `list_nodes`. |
| `get_node` | `public_key: string` | One discovered node, or an error when not found. |
| `announce` | `metadata: object<string,string> \| null` | Sends a multicast announcement for the local node and returns success. |

Node results contain:

| Field | Type | Description |
| --- | --- | --- |
| `public_key` | `string` | Base64url-encoded P-256 public key. |
| `address` | `string` | Last observed `IP:port` for the peer. |
| `metadata` | `object<string,string>` | Optional metadata from the peer announcement. |

## Discovery Storage

Discovered peers are persisted under:

```text
/home/lmesh/files/nodes/<sha256(public_key)>.json
```

Each file stores `public_key`, latest `address`, and up to 16 `announces`. Each
announcement entry is an array:

```json
[timestamp_millis, public_key, "ip:port", {"public_key":"...","metadata":{}}]
```

## Structured Traces

Push-style discovery events are emitted through normal `tracing` output and mesh local
trace handling. Consumers should subscribe through the common mesh trace path; there is
no lmesh-specific subscribe method.

Relevant structured events:

| Level | Message | Fields | Meaning |
| --- | --- | --- | --- |
| `debug` | `service_started` | `public_key` | Server startup; identifies the local announcement key. |
| `debug` | `mcast_v4` | `multicast_ip`, `multicast_port` | IPv4 multicast receive path is active. |
| `debug` | `mcast_v6` | `multicast_ip`, `multicast_port` | IPv6 multicast receive path is active. |
| `debug` | `mcast_none` | none | Neither multicast socket could be opened. |
| `info` | `node_seen` | `public_key`, `address`, `metadata` | A new peer was discovered. |
| `info` | `node_updated` | `public_key`, `address`, `metadata` | An existing peer announced again or changed address/metadata. |
| `warn` | `persist_fail` | `public_key`, `address`, `error` | Discovery worked, but the node JSON file could not be updated. |
| `debug` | `bad_request` | `error` | A malformed JSONL/JSON-RPC request was received. |

The multicast wire announcement is JSON:

```json
{"public_key":"base64url-spki","metadata":{"key":"value"}}
```
