# mesh CLI environment

`mesh` is supplied by the dependency-light `mesh-cli` crate. It has no
`russh`, HTTP, TLS, WebSocket, or mesh-init dependency.

| Variable | Default | Effect |
| --- | --- | --- |
| `MESH_DEST_FORMAT` | `auto` | When the selected method resolves to numeric component and method tags, outbound RPC uses tagged-CBOR. Otherwise it uses JSON-RPC. `cbor` explicitly requires numeric tags; `json-rpc` is the explicit gateway selection. `mesh` does not emit flat JSONL or text requests. Replies are detected from their first byte. `mux` is a transport selector and is rejected as an RPC codec. |
| `MESH_TOOLS` | unset | Explicit generated `tools.json` catalog for numeric tags and option/positional mapping. If unset, `mesh` uses the logical destination service's configured `[Mesh].Tools` catalog, then its packaged `resources/tools.json`, when available. |
| `MESH_SERVICE_DIR` | unset | Common mesh service TOML file, or directory containing `<service>.toml`. A bare service name resolves its `[Mesh].Address` or standard mesh socket from this definition. |
| `MESH_SSH_COMMAND` | `/usr/bin/ssh` | Real OpenSSH binary used for an unresolved bare host. This avoids recursion when `mesh` is symlinked as `ssh`. |

`--rpc-format auto|cbor|json-rpc` overrides `MESH_DEST_FORMAT` for one call.

Explicit UDS/TCP endpoints are RPC calls:

```sh
mesh unix:///run/mesh/example/mesh.sock example status
MESH_DEST_FORMAT=json-rpc mesh unix:///run/mesh/gateway.sock device listen
```

Configured local mesh endpoints under `/run/mesh` also have a namespace form:

```sh
mesh service1.example status
```

This resolves to `/run/mesh/example/service1.sock` and sends `example.status`.
The same rule applies to every runtime directory. Longer names such as
`service1.example.host.example` are reserved for remote
namespace routing and are not treated as local sockets.

`mesh FQDN help` is local discovery. It reads `[Mesh].Tools` from the
node-local service definition and does not connect to, activate, or query the
service. `mesh FQDN help COMMAND` prints the complete static descriptor for one
command.

`mesh` is intentionally not an interactive text gateway. Use an explicit
command for typed tagged-CBOR RPC; use `dmesh-cli` for UART/device interaction
or a dedicated JSON/text gateway tool for manual debugging.

`mux:///path` or `-S /path` selects the native ControlMaster client. A bare
host retains normal SSH command and forwarding syntax.
