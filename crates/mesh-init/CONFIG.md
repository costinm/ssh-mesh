# mesh-init Config

`mesh-init` loads services from `*.toml` files. Service names come from the
filename stem: `worker.toml` defines service `worker`. Socket activation is
declared in the same file with an optional `[Socket]` table.

## TOML Service Files

Service files are TOML documents. The required table is `[Service]`.

### `[Service]`

Systemd-compatible fields:

- `ExecStart` (string, required): command line. The first word is the executable;
  remaining words become argv. Single quotes, double quotes, and backslash
  escaping are supported.
- `ExecStartPre`, `ExecStartPost`, `ExecStop`, `ExecReload` (string or string
  list): hook commands run through `/bin/sh -c`.
- `Type` (string): only `oneshot` is interpreted specially. Omitted or `simple`
  means a long-running service.
- `User` (string): user name or numeric UID string. Names are resolved with passwd.
- `Group` (string): group name or numeric GID string. Names are resolved with the group database. When omitted, a named `User` uses its primary passwd GID.
- `WorkingDirectory` (string): child working directory.
- `Restart` (string): `no`, `always`, `on-success`, `on-failure`,
  `on-abnormal`, or `on-abort`.
- `RestartSec`, `TimeoutStartSec`, `TimeoutStopSec` (duration string): seconds
  by default; `ms`, `s`, `min`, and `h` suffixes are accepted.
- `KillSignal` (string): common signal name such as `SIGTERM`, `TERM`, or a
  numeric signal.
- `KillMode` (string): parsed as `control-group`, `mixed`, `process`, or
  `none`. Current enforcement is process-oriented except `none`, which skips
  signalling the main process.
- `SendSIGKILL` (boolean): controls final SIGKILL after `TimeoutStopSec`.
- `UMask` (octal string): child umask.
- `SupplementaryGroups` (string or string list): group names or numeric GID
  strings.
- `OOMScoreAdjust` (integer, -1000..1000): applied as the Linux OOM score
  adjustment and used as mesh priority. Internal priority is
  `OOMScoreAdjust + 1000`, clamped to `0..2000`; lower is more protected.
- `NoNewPrivileges` (boolean): applied with `prctl(PR_SET_NO_NEW_PRIVS)`.
- `PrivateNetwork` (boolean): applied with `unshare(CLONE_NEWNET)`.

Parsed but not yet enforced sandboxing/capability fields:

- `PrivateTmp`, `PrivateDevices`, `ProtectSystem`, `ProtectHome`,
  `ReadWritePaths`, `ReadOnlyPaths`, `InaccessiblePaths`,
  `CapabilityBoundingSet`, and `AmbientCapabilities`.

mesh-init extension fields:

- `MeshActivationMode` (string): `stdio` or `hybrid`. `stdio` passes accepted
  sockets as stdin/stdout/stderr. `hybrid` forwards accepted sockets to the
  service JSONL Unix socket.
- `MeshActivationSocket` (string): Unix socket path used by `hybrid` activation.
  If omitted, mesh-init uses the service's default JSONL socket path.

Removed fields: `MeshName`, `MeshArgs`, `MeshPriority`, and `MeshOneshot`.
Use the filename, `ExecStart`, `OOMScoreAdjust`, and `Type = "oneshot"`.

### `[Resources]`

mesh-init extension table for cgroup v2 resource controls:

- `MemoryMin` (string): maps to `memory.low`.
- `MemoryHigh` (string): maps to `memory.high`.
- `MemoryMax` (string): maps to `memory.max`.
- `CPUWeight` (integer): maps to `cpu.weight`.

Memory strings may use raw bytes or `K`, `M`, `G`, `T` suffixes.

### `[Environment]`

mesh-init extension table. Each key/value pair is passed as an environment
variable to the service.

### `[Network]`

mesh-init extension table for service network setup:

- `backend`: `none`, `pasta`, or `mesh-tun`.
- `command`: sidecar command for backends such as `pasta`.
- `args`: sidecar argv list.
- `env`: sidecar environment map.
- `control_socket`: shared mesh-tun control socket.
- `if_name`: interface name inside the service namespace.
- `address`: service-side address, for example `10.5.0.2/24`.
- `gateway`: default-route gateway.
- `mtu`: service-side interface MTU.
- `default_route`: boolean.
- `egress_redirect_port`: TCP redirect listener port.
- `egress_redirect_uid`: uid excluded from egress redirects.

### Auth Tables

mesh-init extension tables:

- `[[Peer]]`: embedded auth peer. Supported fields are the same as `auth.toml`,
  including `uid`, `id`, `email`, and `delegate`.
- `[[MeshImpersonation]]`: embedded impersonation rule with `from` and `to`.

### Job Fields

Job definitions use the same TOML parser and add mesh-init extension fields:
place these top-level fields before the first table header.

- `MeshPersisted`
- `MeshPrefetch`
- `MeshSaveResult`
- `MeshTraceTag`
- `MeshUserInitiated`
- `MeshExpedited`
- `MeshEstimatedDownloadBytes`
- `MeshEstimatedUploadBytes`
- `MeshMinimumNetworkChunkBytes`

Job extension tables:

- `[Schedule]`: `periodic_secs`, `flex_secs`, `minimum_latency_secs`,
  `override_deadline_secs`.
- `[Constraints]`: `network_type`, `requires_charging`,
  `requires_device_idle`, `requires_battery_not_low`,
  `requires_storage_not_low`, `triggers`, `trigger_max_delay_secs`, and
  `[Constraints.custom]`.
- `[Backoff]`: `initial_secs`, `policy`, `max_retries`, `max_secs`.

### `[Socket]`

Optional systemd-compatible socket activation table in the same TOML document
as `[Service]`.

Systemd-compatible fields:

- `ListenStream`: TCP port/address, Unix stream socket path, or `vsock:CID:PORT`.
- `ListenDatagram`: UDP port/address or Unix datagram socket path.
- `Accept`: boolean. `false` passes listener FDs with systemd activation;
  `true` accepts connections in mesh-init. `ListenDatagram` only supports
  `Accept=false`.
- `SocketMode`: Unix socket mode, for example `0660`.
- `SocketUser`: Unix socket owner.
- `SocketGroup`: Unix socket group.
- `FileDescriptorName`: descriptor name or descriptor name list for
  `Accept=false` activation.

No xinetd-style listener-fd mode is supported. Hybrid accepted-fd forwarding is
selected in `[Service]` with `MeshActivationMode = "hybrid"`.

When a service has multiple `Accept=false` listeners, mesh-init passes all of
them to the child in declaration order using the systemd convention:
`LISTEN_FDS=N` and descriptors starting at fd 3.
