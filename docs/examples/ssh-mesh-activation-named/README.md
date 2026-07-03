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
| Common mesh JSONL UDS | `jsonl` |
| Trusted SSH UDS | `ssh-uds` |
| Trusted SSH VSOCK | `vsock` |

If admin/API should be served over UDS instead of TCP, replace the `admin`
listener `Address` with a Unix socket path and keep the descriptor name
`admin`.

The `jsonl` listener is the common `mesh::server::MeshListener` JSONL/JSON-RPC
surface. Apps that are not `ssh-mesh` should use the same name in their own
service TOML file.

`ssh-uds` and `vsock` are both trusted SSH transports. They are grouped after
the JSONL/admin surfaces because they are not control APIs.
