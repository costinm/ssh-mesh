# ssh-mesh activation by fd order

This example intentionally does not use `FileDescriptorName`.

`ssh-mesh` can consume all supported startup listeners by order. The order is
documented as comments in `ssh-mesh.toml`; keep that file in sync with the
startup order if surfaces are added.

The common mesh endpoint UDS entry uses `mesh::server::MeshListener`. Its
socket path is protocol-neutral (`mesh.sock`); current apps can speak line
JSON, JSON-RPC/MCP-shaped calls, or text protocols there. Trusted UDS and
VSOCK are both trusted SSH transports and are grouped after that endpoint.

Named activation is less fragile for production because optional or missing
listeners do not shift later surfaces.
