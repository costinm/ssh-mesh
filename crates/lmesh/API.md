# lmesh API

`lmesh` exposes local mesh discovery control as newline-delimited JSON over a Unix
domain socket. Under mesh-init it uses systemd-style socket activation and takes
the activated listener fd. When started standalone without activation, it binds
`./lmesh/mesh.sock` by default.

The same methods can be called using flat JSONL or JSON-RPC 2.0. One request is sent per
line and one response is returned per line.

Flat request:

```json
{"method":"nodes"}
```

JSON-RPC request:

```json
{"jsonrpc":"2.0","method":"nodes","id":1}
```

Flat success responses use the mesh response shape:

```json
{"success":true,"data":...}
```

JSON-RPC success responses put the payload in `result`; errors use either the mesh
`success:false,error` shape or JSON-RPC `error`, depending on the request format.

## Environment

| Variable | Default | Description |
| --- | --- | --- |
| `LMESH_ANNOUNCE_INTERVAL_SECS` | `60` | Positive integer interval, in seconds, between automatic multicast announcements sent by the lmesh server. Invalid or zero values fall back to `60`. |
| `LMESH_CONTROL_SOCKET` | `./lmesh/mesh.sock` | Standalone fallback UDS path used only when no activation listener is provided. Relative paths resolve against the working directory. |
| `LMESH_DEVICE_ID` | derived | Optional 6-byte hex DMesh radio device id, for example `001122334455` or `00:11:22:33:44:55`. |
| `LMESH_SERIAL_DEVICES` | unset | Comma-separated ESP serial radio devices, for example `/dev/ttyUSB0,/dev/ttyUSB1`. Devices default to 115200 baud and are listed as `esp-serial-*` adapters. |
| `LMESH_WIFI_IFACE` | `wlan1` | Default Wi-Fi interface used by the NAN/WPA control methods. |
| `LMESH_WPA_CTRL_DIR` | `/run/ssh-mesh-wpa` | WPA control socket directory used by NAN methods. The mesh-init examples use `/run/mesh/wpa-supplicant-nan`. |

When `MESH_HOME/lmesh.toml` exists, `lmesh` also reads additional radio
adapters:

```toml
[[radios]]
id = "lab-esp0"
kind = "esp-serial"
medium = "serial"
path = "/dev/ttyUSB0"
network = "lab"
baud = 115200

[[radios]]
id = "remote-a"
kind = "remote-uds"
medium = "remote"
path = "/tmp/ssh-forwarded/lmesh.sock"
```

Known adapter kinds are `host-mcast`, `host-ble`, `host-nan`, `esp-serial`,
`remote-uds`, `android-ble`, and `android-nan`. Android kinds are contract
placeholders for future platform adapters.

## Lightweight MCP Methods

All lmesh JSONL connections also support the shared mesh MCP-compatible methods:

The `tools/list` command catalog is the hand-maintained
`resources/tools.json`. Keep it in sync with this document when the public
command surface changes; do not generate it from Rust code.

| Method | Result |
| --- | --- |
| `initialize` | Protocol version, server info, and `tools`/`resources` capabilities. |
| `tools/list` | Contents of `tools.json` from `MESH_RES_DIR`, otherwise `/home/lmesh/etc/resources` overlaying `/opt/lmesh/resources`. |
| `tools/call` | Calls the native lmesh method named by `name`, with `arguments` mapped to normal method params. |
| `resources/list` | File resources from the same resource lookup plus registered resources. |
| `resources/read` | Reads a listed `file://` resource when it is under the resolved resource directories. |

## Methods

| Method | Params | Result |
| --- | --- | --- |
| `nodes` | none | Array of currently discovered nodes. Alias: `list_nodes`. |
| `get_node` | `public_key: string` | One discovered node, or an error when not found. |
| `announce` | `metadata: object<string,string> \| null` | Sends a multicast announcement for the local node and returns success. |
| `status` | none | Reports process capabilities, HCI raw-socket probe, and optional WPA control status through the control UDS. |
| `radios.list` | none | Lists configured host, serial, remote UDS, and future Android radio adapters. |
| `neighbors` | `seen_within_sec: integer = 21600` | Returns the normalized neighbor table from recent radio messages. |
| `discovery.ping` | `medium: string = "all"` | Pings matching configured media. ESP serial radios are opened at their configured baud, sent shared mesh text, and reply/log lines are normalized through `mesh::message`; other media record the fanout intent for their adapters. |
| `messages.history` | `keys: string = "messages,net,wifi,BLE,N"`, `limit: integer = 40` | Returns recent radio method results recorded by this process. |
| `wifi.raw.listen` | `iface: string = LMESH_WIFI_IFACE`, `ctrl_dir: string = LMESH_WPA_CTRL_DIR`, `channel: integer = 6`, `listen_sec: integer = 60`, `rx_variant: string = "nl80211"` | Uses wpa_supplicant control to set P2P listen channel and start a listen window. `nl80211` registers an action-frame match for ESP32 DMesh vendor action bytes `7f:50:6f:9a:42`; `monitor` captures radiotap monitor frames and parses both action and multicast data frames with that marker. Records received payloads as `wifi.raw.rx` events in `messages.history`. Requires `CAP_NET_ADMIN`/`CAP_NET_RAW`. |
| `wifi.raw.send` | `iface: string = LMESH_WIFI_IFACE`, `ctrl_dir: string = LMESH_WPA_CTRL_DIR`, `channel: integer = 6`, `listen_sec: integer = 60`, `destination: mac = ff:ff:ff:ff:ff:ff`, `tx_variant: string = "standard"`, `tx_duration_ms: integer \| null`, `payload: string` | Sends an ESP32-compatible DMesh frame. nl80211 variants probe action-frame `FRAME` TX; `pyroute2` matches the common `ifindex/freq/duration/frame` shape; `roc` first issues `REMAIN_ON_CHANNEL` on the same nl80211 socket and skips the wpa_supplicant P2P listen command; `monitor` injects an action frame through AF_PACKET monitor mode; `multicast_data` injects a non-QoS multicast data frame through AF_PACKET monitor mode and defaults `destination` to `01:00:5e:44:4d:01`. Requires `CAP_NET_ADMIN`/`CAP_NET_RAW`. |
| `ble.scan` | `dev_id: integer = 0`, `reason: string = "jsonl"` | Enables passive LE scanning through raw Linux HCI sockets. Requires `CAP_NET_RAW`. |
| `ble.adv` | `dev_id: integer = 0`, `on: bool = true`, `payload: string = "lmesh"` | Enables or disables BLE advertising with DMesh service UUID `0xFD5D` and current DMesh service-data layout. Requires `CAP_NET_RAW`. |
| `wifi.nan.start` | `iface: string = LMESH_WIFI_IFACE`, `ctrl_dir: string = LMESH_WPA_CTRL_DIR` | Brings the interface up through native rtnetlink, then probes the WPA control socket with `STATUS` and `DRIVER_FLAGS2`. |
| `wifi.nan.stop` | `iface`, `ctrl_dir` | Sends best-effort raw `NAN_CANCEL_PUBLISH publish_id=1` and `NAN_CANCEL_SUBSCRIBE subscribe_id=1`. |
| `wifi.nan.adv` | `iface`, `ctrl_dir` | Sends `NAN_PUBLISH service_name=dmesh ... ssi=<DMesh NAN service info>` through the WPA control UDS. |
| `wifi.nan.sub` | `iface`, `ctrl_dir` | Sends `NAN_SUBSCRIBE service_name=dmesh active=1 ...` through the WPA control UDS. |
| `wifi.nan.ping` | `iface`, `ctrl_dir`, `peer: hex device id`, `payload: string = "ping"` | Sends a DMesh NAN follow-up with raw `NAN_TRANSMIT`; when `peer` is omitted the frame target is broadcast-like `ff:ff:ff:ff:ff:ff`. |

Node results contain:

| Field | Type | Description |
| --- | --- | --- |
| `public_key` | `string` | Base64url-encoded P-256 public key. |
| `address` | `string` | Last observed `IP:port` for the peer. |
| `metadata` | `object<string,string>` | Optional metadata from the peer announcement. |

## Discovery Storage

Discovered peers are persisted under:

```text
./lmesh/nodes/<sha256(public_key)>.json
```

Each file stores `public_key`, latest `address`, and up to 16 `announces`. Each
announcement entry is an array:

```json
[timestamp_millis, public_key, "ip:port", {"public_key":"...","metadata":{}}]
```

## Structured Traces

Push-style discovery events are emitted through normal `tracing` output and mesh local
trace handling. Consumers should subscribe through the common mesh trace path; there is
no lmesh-specific subscribe method.

Relevant structured events:

| Level | Message | Fields | Meaning |
| --- | --- | --- | --- |
| `debug` | `service_started` | `public_key` | Server startup; identifies the local announcement key. |
| `debug` | `mcast_v4` | `multicast_ip`, `multicast_port` | IPv4 multicast receive path is active. |
| `debug` | `mcast_v6` | `multicast_ip`, `multicast_port` | IPv6 multicast receive path is active. |
| `debug` | `mcast_none` | none | Neither multicast socket could be opened. |
| `info` | `node_seen` | `public_key`, `address`, `metadata` | A new peer was discovered. |
| `info` | `node_updated` | `public_key`, `address`, `metadata` | An existing peer announced again or changed address/metadata. |
| `warn` | `persist_fail` | `public_key`, `address`, `error` | Discovery worked, but the node JSON file could not be updated. |
| `debug` | `bad_request` | `error` | A malformed JSONL/JSON-RPC request was received. |

The multicast wire announcement is JSON:

```json
{"public_key":"base64url-spki","metadata":{"key":"value"}}
```

## Radio Wire Protocol

`mesh::message` owns shared text/JSON/JSON-RPC parsing and normalized
`MeshMessage` records. It parses mesh text records such as
`kind key=value flag payload=hex:...`, firmware reply/log lines such as
`stats ...`, `messages ...`, `ev=...`, and `event type=...`, and WPA control
responses through a WPA adapter parser. WPA remains text-like but does not use
mesh `key=value` command syntax: requests are plain ASCII commands such as
`STATUS` or `NAN_PUBLISH ...`, responses are plain text such as `OK`, `FAIL`,
or key/value-ish status lines, and asynchronous events look like
`<3>CTRL-EVENT-...`.

`lmesh::radio_protocol` owns the DMesh BLE/NAN `DM` v1 frame format. It is a
library API. Linux BLE/NAN JSONL methods use it for frame encoding while keeping
platform-specific raw HCI sockets and `wpa_supplicant` control outside the
protocol module.

JNI or local adapter boundaries should stay message-oriented: text method/args
for routing and metadata, raw bytes for payload frames, and an FD slot where
needed. CBOR is the intended future structured binary format when JSON/text is
too verbose; protobuf is not planned for this path. Evaluate `minicbor` first on
ESP firmware and host Rust together, comparing firmware build size, allocation
behavior, ESP-IDF/no-std compatibility, and round-trip parity. Text remains the
mandatory debug and UDS-test baseline until CBOR passes that evaluation.

Public helpers:

| Helper | Purpose |
| --- | --- |
| `DMESH_BLE_SERVICE_UUID16` | DMesh BLE service UUID16, `0xFD5D`. |
| `build_ble_service_data` / `parse_ble_service_data` | BLE service-data wake and payload-hint frames. |
| `build_nan_service_info` / `parse_nan_service_info` | WiFi Aware/NAN service-specific info frames. |
| `build_nan_followup` / `parse_nan_followup` | WiFi Aware/NAN follow-up message frames. |

The direct ESP32 Wi-Fi command path currently uses vendor-specific 802.11 action
frames, not NAN. Firmware builds frames as:

```text
fc=d0:00 duration=00:00 addr1=<destination> addr2=<station_mac> addr3=<destination> seq=00:00
body=7f 50 6f 9a 42 <payload bytes>
```

`wifi.raw.listen rx_variant=nl80211` receives nl80211 `FRAME` notifications
after registering an action-frame match for that body prefix.

`wifi.raw.send tx_variant=multicast_data` uses the same five-byte body marker,
but places it in the payload of a non-QoS data frame with frame control
`08:00`. Multicast and broadcast destinations avoid normal unicast MAC ACK and
retry behavior.

## Real-Hardware Radio Setup

Install repo-local helpers into the normal development profile:

```bash
nix profile add .#radio-deps --profile target/nix/profile
```

Run preflight before live tests:

```bash
lmesh-radio-preflight
```

The preflight reports Wi-Fi interfaces/phys, driver-visible NAN markers from
`iw phy`, current process capabilities, and WPA control socket status.

Recommended development permission path:

1. Let `mesh-init` start `wpa-supplicant-nan` as `build` with ambient
   `CAP_NET_ADMIN` and `CAP_NET_RAW`. Its WPA config should contain:

   ```text
   ctrl_interface=DIR=/run/mesh/wpa-supplicant-nan GROUP=plugdev
   ```

2. Run `lmesh` as `build` under a `mesh-init` service with ambient and bounding
   capabilities containing `CAP_NET_ADMIN` and `CAP_NET_RAW`. The example
   configs assume mesh-init starts with `PATH` containing `lmesh` and
   `wpa_supplicant`; persistent logs and state belong under `HOME`,
   `MESH_HOME`, or a test directory such as `target/`, not `/run`.

mesh-init creates `/run/mesh/<service>/`, sets ownership from the service
`User`/`Group`, and leaves the directory world-traversable/writable. The UDS
server performs its own peer-credential identity checks; the directory
permission is only for socket creation and connection reachability.

For production, use the same layout with a dedicated `net` user instead of
`build`.

Fallback for direct local testing:

```bash
sudo setcap cap_net_admin,cap_net_raw+ep target/debug/lmesh
sudo setcap cap_net_admin,cap_net_raw+ep target/release/lmesh
getcap target/debug/lmesh target/release/lmesh
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)' /proc/$(pidof lmesh)/status
```

For the attached lab adapters, start with `wlan1` / MediaTek `mt76x2u` because
that is the interface expected to show NAN TX/RX frame sections in `iw phy`;
verify `wlan0` / Atheros `ath9k_htc` separately.
