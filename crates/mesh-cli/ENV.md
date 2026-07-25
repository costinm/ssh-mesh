# mesh CLI environment

`mesh` is supplied by the dependency-light `mesh-cli` crate. It has no
`russh`, HTTP, TLS, WebSocket, or mesh-init dependency.

| Variable | Default | Effect |
| --- | --- | --- |
| `MESH_DEST_FORMAT` | `auto` | Outbound RPC encoding: `auto`/`json`, `cbor`, or `text`. Replies are always detected from their first byte. `mux` is a transport selector and is rejected as an RPC codec. |
| `MESH_TOOLS` | unset | Explicit generated `tools.json` catalog for numeric tags and option/positional mapping. Without it, names remain strings. |
| `MESH_SERVICE_DIR` | unset | Common mesh service TOML file, or directory containing `<service>.toml`. A bare service name resolves its `[Mesh].Address` or standard mesh socket from this definition. |
| `MESH_SSH_COMMAND` | `/usr/bin/ssh` | Real OpenSSH binary used for an unresolved bare host. This avoids recursion when `mesh` is symlinked as `ssh`. |

Explicit UDS/TCP endpoints are RPC calls:

```sh
mesh unix:///run/mesh/lmesh/mesh.sock lmesh nodes
MESH_DEST_FORMAT=cbor mesh unix:///run/mesh/device.sock wifi listen -listen_sec=1 wlan0
```

Configured local mesh endpoints under `/run/mesh` also have a namespace form:

```sh
mesh lora1.lmesh status
mesh lora1.lmesh dtr 500
mesh lora1.lmesh rst
```

This resolves to `/run/mesh/lmesh/lora1.sock` and sends `lmesh.status`.
The same rule applies to every runtime directory, for example
`radio1.radio` resolves to `/run/mesh/radio/radio1.sock`.
Longer names such as `lora1.lmesh.host.example` are reserved for remote
namespace routing and are not treated as local sockets.

`mesh FQDN help` is local discovery. It reads `[Mesh].Tools` from the
node-local service definition and does not connect to, activate, or query the
service. `mesh FQDN help COMMAND` prints the complete static descriptor for one
command. For locally forwarded ESP devices in the `lmesh` namespace, the
packaged `firmware-tools.json` is the default when no exact FQDN override is
present.

With no command, `mesh` keeps the RPC connection open and bridges stdin/stdout:

```sh
mesh lora1.lmesh
```

The session accepts newline-delimited JSON, text, or the selected CBOR stream
format and forwards responses and asynchronous notifications until stdin or
the service closes. This is the RPC equivalent of an SSH interactive session.

`mux:///path` or `-S /path` selects the native ControlMaster client. A bare
host retains normal SSH command and forwarding syntax; local serial ownership
and permissions remain lmesh responsibilities.
