# ssh-mesh activation with named fds

This example uses one `.toml` file with every listener surface.
Each `[[Socket.Listen]]` entry can name its own fd while preserving listener
order:

```toml
[Socket]
Accept = false

[[Socket.Listen]]
Type = "stream"
Address = "8443"
Name = "http-secure"

[[Socket.Listen]]
Type = "stream"
Address = "vsock:2:5000"
Name = "vm-ipc"
```

`ssh-mesh` consumes these names:

| Surface | FileDescriptorName |
| --- | --- |
| SSH TCP | `ssh` |
| Mesh H2/mTLS TCP | `mesh-mtls` |
| Public HTTP static web | `http` |
| Public HTTPS static web | `https` |
| Admin HTTP/API | `admin` |
| Common mesh endpoint UDS | `jsonl` |
| Trusted SSH UDS | `ssh-uds` |
| Trusted SSH VSOCK | `vsock` |

If admin/API should be served over UDS instead of TCP, replace the `admin`
listener `Address` with a Unix socket path and keep the descriptor name
`admin`.

The `jsonl` fd name selects the common `mesh::server::MeshListener` endpoint.
The socket path is protocol-neutral (`mesh.sock`); current apps can speak
line JSON, JSON-RPC/MCP-shaped calls, or text protocols on the same endpoint.

`ssh-uds` and `vsock` are both trusted SSH transports. They are grouped after
the JSONL/admin surfaces because they are not control APIs.
