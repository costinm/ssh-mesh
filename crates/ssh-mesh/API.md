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

## 2. `certs/reload` — Reload the HTTPS certificate files without restarting

Local admin JSONL command, available through the activated `jsonl` Unix socket.
Omit `certificates` to reread the paths discovered at startup or installed by the
last successful reload. Supply explicit paths to replace that set, including
newly issued domains. Reload never scans directories or runs periodically.
Certificate keys are sibling `<stem>.key` files, or `privkey` beside `fullchain`.
Every certificate must contain DNS SANs and match its private key. Any read or
validation error leaves the entire active set unchanged and returns an error.
Existing connections stay open; new TLS handshakes use the replacement set.
No notifications or traces are pushed by this command.

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `certificates` | `string[]` | Optional certificate paths; when present, replaces the active set. Must not be empty. |

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `loaded` | `u32` | Number of certificate files installed. |

Example JSONL: `{"method":"certs/reload"}` or
`{"method":"certs/reload","certificates":["/home/acme/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/example.org/example.org.crt"]}`.
