# ssh-mesh activation with named fds

This example uses one `.toml` file with every listener surface.
`FileDescriptorName` names every fd from the `[Socket]` table. `mesh-init`
accepts a TOML list and maps that list to listeners in fd order:

```toml
[Socket]
ListenStream = ["8443", "vsock:2:5000"]
FileDescriptorName = ["http-secure", "vm-ipc"]
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
`ListenStream=127.0.0.1:15080` entry with a Unix socket path and keep the
descriptor name `admin`.

The `jsonl` listener is the common `mesh::server::MeshListener` JSONL/JSON-RPC
surface. Apps that are not `ssh-mesh` should use the same name in their own
service TOML file.

`ssh-uds` and `vsock` are both trusted SSH transports. They are grouped after
the JSONL/admin surfaces because they are not control APIs.
