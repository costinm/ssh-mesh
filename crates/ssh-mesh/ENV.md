# ssh-mesh environment variables

Runtime variables read by `ssh-mesh` and its companion binaries in this crate.

Common variables inherited from the `mesh` crate are documented in
[`../mesh/ENV.md`](../mesh/ENV.md). That includes `MESH_HOME`,
`MESH_HOME_BASE`, `MESH_OPT_BASE`, `MESH_APP_HOME`, `MESH_APP_OPT`,
`MESH_RES_DIR`, `RUST_LOG`, `MESH_LOG_FILE`, `MESH_LOG_DIR`,
`TRACE_SOCKET_DIR`, `LISTEN_FD`, `LISTEN_FDS`, and `LISTEN_FDNAMES`.

`ssh-mesh` starts daemon listeners only from systemd-style activated listener
FDs. It does not bind startup TCP/UDS ports from environment variables. The
common activation variables are documented in [`../mesh/ENV.md`](../mesh/ENV.md).

## Listeners And Activation

`ssh-mesh` can own several listener surfaces. `LISTEN_FDNAMES` is preferred
when available. For compatibility with a single unnamed socket unit, fd order is
still accepted for the historical SSH+HTTP pair: put the SSH listener first and
the HTTP listener second. Optional surfaces require names so they do not consume
the wrong fd by order.

```ini
[Socket]
ListenStream=0.0.0.0:15022
ListenStream=0.0.0.0:15080
Accept=false
```

For named activation with one socket file, use one space-separated
`FileDescriptorName=` value in listener order. A single name applies to all fds
in that socket unit, matching the documented systemd shape.

| Surface | FD names | Socket type | Notes |
| --- | --- | --- | --- |
| SSH TCP | `ssh`, `ssh-tcp` | `ListenStream=` TCP | Falls back to first inherited TCP fd if unnamed. |
| Mesh H2/mTLS TCP | `h2`, `mesh`, `mesh-mtls`, `mtls` | `ListenStream=` TCP | Uses the admin/proxy router over the HTTPS/TLS stack with ALPN `h2` and `http/1.1`; requires server cert/key. |
| HTTP TCP static web | `http` | `ListenStream=` TCP | Serves files from `<ssh-mesh_home>/web`. Falls back to the next inherited TCP fd after SSH if unnamed. Use `ListenStream=0.0.0.0:80` when root should expose HTTP on port 80. |
| HTTPS TCP static web | `https` | `ListenStream=` TCP | Serves files from `<ssh-mesh_home>/web` over TLS. Requires server cert/key. Use `ListenStream=0.0.0.0:443` when root should expose HTTPS on port 443. |
| Admin HTTP TCP | `admin` | `ListenStream=` TCP | Serves the same admin/proxy router on a separately activated TCP listener. |
| Admin HTTP UDS | `admin` | `ListenStream=` Unix path | Same admin/API router as the admin TCP surface, served over UDS instead of TCP. |
| Mesh app endpoint | `jsonl` | `ListenStream=` Unix path | Common protocol-neutral `mesh::server::MeshListener` endpoint. Current handlers accept line JSON, JSON-RPC/MCP-shaped calls, and text protocols; future encodings can reuse the same socket. |
| Trusted SSH UDS | `ssh-uds`, `trusted-ssh-uds` | `ListenStream=` Unix path | Trusted SSH transport over Unix-domain socket. |
| Trusted SSH VSOCK | `vsock`, `ssh-vsock`, `trusted-ssh-vsock` | `ListenStream=vsock:CID:PORT` | Trusted SSH transport over AF_VSOCK. Use `vsock::PORT` to omit CID and bind `VMADDR_CID_ANY`. |
| Trusted SSH stdio | disabled | stdin/stdout | Enabled by `SSH_MESH_TRUSTED_STDIO=1`; skips normal listeners. |

## SSH Specific

| Variable | Default | Effect |
| --- | --- | --- |
| `SSH_BASEDIR` | `<ssh-mesh_home>/etc` | Directory for server keys, certificates, `authorized_keys`, `authorized_cas`, and default SSH config. |
| `HOME` | process environment | Used as the default home in mesh-init exec requests. |
| `USER` | `system` for HTTP exec; `root` for `sshmc` destination parsing | User name used when constructing mesh-init exec requests or mux socket names. |
| `SFTP_ROOT` | unset; effective root falls back to `SSH_BASEDIR` | Optional SFTP root path. |
| `SSH_MESH_CONFIG` | `<ssh-mesh_home>/etc` | Directory for `mesh.yaml`, `mesh.json`, or `mesh.toml`, plus per-user SSH authorization. |
| `SSH_MESH_TRUSTED_STDIO` | `false` | When `1` or `true`, serve trusted SSH transport over stdin/stdout and skip normal listeners. |
| `APP_HTTP_PORT` | unset | Optional reverse-proxy target used by the fallback HTTP proxy. |
| `SSH_CONFIG` | `$SSH_BASEDIR/config` | SSH client config path. If the file does not exist, no config file is used. |
| `SSH_MUX` | `<ssh-mesh_home>/run/ssh-mesh/mux` for `sshmc`; unset for server client manager | Directory for OpenSSH-style mux control sockets. |
| `SSH_MESH_HTTPS_CA` | `$SSH_BASEDIR/authorized_cas` | CA bundle used to require and validate HTTPS client certificates. If missing, HTTPS starts without client-cert auth. |
| `EXEC_USER` | `1000` | UID used by the legacy foreground command path. |
| `MESH_INIT_SOCK` | `/run/mesh/mesh-init/mesh.sock` for root systems | mesh-init mesh endpoint used for HTTP exec, SSH terminal delegation, and route activation. |
| `SSH_MESH_HOME_ROOT` | shared `mesh` home base | Root used to find certificate terminal homes by SSH username. |

## Companion Binaries

| Variable | Default | Effect |
| --- | --- | --- |
| `MESH_LOG_FILE` | `<h2t_home>/run/h2t/h2t.log` | Log file path used by the `h2t` binary. This is not a common `mesh` setting. |

## App Specific

| Variable | Default | Effect |
| --- | --- | --- |
| `TUN_TOKEN` | unset | Bearer token sent by `h2t` for WebSocket and HTTP/2 tunnel requests. |

## Deprecated

| Variable | Default | Effect |
| --- | --- | --- |
| `SFTP_SERVER_PATH` | unset | Optional external SFTP server binary path. |
| `<APP>_UDS` | app-specific | Optional app UDS override for `/_m/proxy/*/:app` generic proxy routes, for example `MESH_INIT_UDS`. |
| `TRACEWEB_UDS` | `/run/mesh/traceweb/mesh.sock` for root systems | traceweb mesh endpoint for `/_m/trace` proxy routes. |


# Generated Variables

Generated variables passed to activated services.

| Variable | Default | Effect |
| --- | --- | --- |
| `SSH_MESH_JUMP_HOST` | unset | Direct-tcpip jump host from a matched SSH route. |
| `SSH_MESH_JUMP_PORT` | unset | Direct-tcpip jump port from a matched SSH route. |
| `SSH_MESH_JUMP_ORIGINATOR_IP` | unset | Originator IP for a direct-tcpip jump activation. |
| `SSH_MESH_JUMP_ORIGINATOR_PORT` | unset | Originator port for a direct-tcpip jump activation. |
| `SSH_MESH_ROUTE_USER` | unset | Compatibility alias for activation context user. |
| `SSH_MESH_ROUTE_COMMAND` | unset | Compatibility alias for activation-triggering command. |
| `SSH_MESH_ROUTE_CERTIFICATE_USER` | unset | Certificate principal/user from SSH activation context, when present. |
| `SSH_MESH_ROUTE_PEER_KEY_SHA` | unset | Authenticated peer key fingerprint from SSH activation context, when present. |
| `SSH_MESH_ROUTE_CLIENT_ID` | unset | Caller connection ID from SSH activation context, when present. |
