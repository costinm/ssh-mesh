# ssh-mesh API

This file is the machine-readable contract for ssh-mesh's local MCP surface.
HTTP route descriptions, proxy behavior, and operational guidance live in
[README.md](README.md).

```mesh-api
id = "ssh-mesh.jsonl_call"
component = "ssh-mesh"
method = "jsonl_call"
component-index = 4
method-index = 1
visibility = "public"
summary = "Send a JSON-RPC request to a component Unix socket and return the unwrapped result"

[request]
fields = [
  { name = "socket_path", index = 1, type = "string", required = true, position = 1 },
  { name = "method_name", index = 2, type = "string", required = true, position = 2 },
  { name = "params", index = 3, type = "object" },
]
```
