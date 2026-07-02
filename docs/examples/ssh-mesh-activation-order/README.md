# ssh-mesh activation by fd order

This example intentionally does not use `FileDescriptorName=`.

`ssh-mesh` can consume all supported startup listeners by order. The order is
documented as comments in `ssh-mesh.socket`; keep that file in sync with the
startup order if surfaces are added.

The JSONL UDS entry is the common `mesh::server::MeshListener` JSONL/JSON-RPC
surface. Trusted UDS and VSOCK are both trusted SSH transports and are grouped
after JSONL.

Named activation is less fragile for production because optional or missing
listeners do not shift later surfaces.
