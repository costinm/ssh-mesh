# mesh-init environment variables

Runtime variables read by the `mesh-init` daemon, CLI, and service activation code.

Common variables inherited from the `mesh` crate are documented in
[`../mesh/ENV.md`](../mesh/ENV.md). That includes `MESH_HOME`,
`MESH_HOME_BASE`, `MESH_OPT_BASE`, `MESH_APP_HOME`, `MESH_APP_OPT`,
`MESH_RES_DIR`, `MESH_TRUSTED_SSHD_UID`, `RUST_LOG`, `MESH_LOG_FILE`,
`MESH_LOG_DIR`, `LISTEN_FD`, `LISTEN_FDS`, and `LISTEN_FDNAMES`.

## mesh-init

| Variable | Default | Effect |
| --- | --- | --- |
| `MESH_INIT_PRIVILEGED_UIDS` | `0,1000,103` | Comma-separated UIDs allowed to operate on services for other UIDs/GIDs. If set to a non-empty parsed list, it fully replaces the default. |
| `MESH_INIT_MAX_ACTIVATION_CHILDREN` | `64` | Maximum concurrent inetd-style activation children. Invalid, zero, or unset values use `64`. |
| `MESH_INIT_REAP_ALL` | `false` unless running as PID 1 | When `1` or `true`, the child reaper uses `waitpid(-1)` even when not PID 1. |

## Socket Activation Syntax

`mesh-init` implements a small systemd-compatible `[Socket]` subset inside each
service `.toml` file. For VSOCK stream listeners, use:

```toml
[Service]
ExecStart = "/opt/example/bin/server"

[Socket]
ListenStream = "vsock:2:5000"
FileDescriptorName = "vsock"
Accept = false
```

Use `ListenStream = "vsock::5000"` to omit the CID and bind `VMADDR_CID_ANY`.
`FileDescriptorName` follows the systemd shape: a single value names every
descriptor, while a list names multiple listeners in fd order:

```toml
[Service]
ExecStart = "/opt/example/bin/server"

[Socket]
ListenStream = ["8443", "vsock:2:5000"]
FileDescriptorName = ["http-secure", "vm-ipc"]
Accept = false
```

Specialized:
| `MESH_TUN_CONTROL_SOCKET` | `/tmp/mesh-tun-control.sock` | Fallback control socket used when attaching a service namespace to mesh-tun and no service config `control_socket` is set. |
| `LISTEN_PID` | unset | Process ID that owns systemd-style inherited socket FDs. FDs are collected only when it matches the current process. |


Deprecated - use 'mesh' envs:

| `MESH_INIT_DIR` | `<system_home>/etc/mesh-init` | Directory scanned for service configuration. |
| `MESH_INIT_RUN` | `<system_home>/run/mesh-init` | Runtime directory for the control socket; socket path is `<MESH_INIT_RUN>/control.sock`. |
| `USER_INIT` | `/data/mesh` | Base directory for on-demand per-user service configs at `<USER_INIT>/<name>/init.toml`. |


## Generated Variables

Generated variables passed to child processes or activated services.

| Variable | Default | Effect |
| --- | --- | --- |
| `HOME` | service home from config or terminal request | Child process home. |
| `USER` | service/user name | Child process user name. |
| `LISTEN_FDS` | unset | Set to the number of listener FDs for Accept=false socket activation children. |
| `LISTEN_FDNAMES` | unset | Listener fd names for Accept=false children. `mesh-init` emits colon-separated names; receivers also accept spaces. Names come from `[Socket]` `FileDescriptorName` when set, otherwise from the service filename. |
| `MESH_INIT_CONTEXT_KIND` | unset | Activation context kind, when present. |
| `MESH_INIT_CONTEXT_USER` | unset | Activation context user, when present. |
| `MESH_INIT_CONTEXT_COMMAND` | unset | Activation-triggering command, when present. |
| `MESH_INIT_CONTEXT_JSON` | unset | Full activation context JSON, when serializable. |
| `SSH_MESH_ROUTE_USER` | unset | Compatibility alias for activation context user. |
| `SSH_MESH_ROUTE_COMMAND` | unset | Compatibility alias for activation-triggering command. |
| `SSH_MESH_ROUTE_CERTIFICATE_USER` | unset | Certificate principal/user from SSH activation context, when present. |
| `SSH_MESH_ROUTE_PEER_KEY_SHA` | unset | Authenticated peer key fingerprint from SSH activation context, when present. |
| `SSH_MESH_ROUTE_CLIENT_ID` | unset | Caller connection ID from SSH activation context, when present. |
