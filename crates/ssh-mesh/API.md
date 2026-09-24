# `ssh-mesh` API (4)

This is the machine-readable contract for ssh-mesh's local service surface.
HTTP route descriptions, proxy behavior, and operational guidance live in
[README.md](README.md).

## 1. `jsonl_call` — Send a JSON-RPC request to a component Unix socket and return the unwrapped result

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `socket_path` | `string` | |
| 2 | `method_name` | `string` | |
| 3 | `params` | `object` | |
