# `probe` API (8)

Transport-neutral throughput, ordering, and flow-control probe (`quic-tools::probe`)
over any multiplexed or single-stream byte transport (`quic-mux`, `quic-link`,
TCP, or UDS).

Requests and responses use the standard tagged-CBOR envelope
(`{1: component, 2: method, 3: id, 5: fields}` for requests; `{1, 2, 3, 6: result}`
or `{1, 2, 3, 7: error}` for responses). On streams, the self-delimiting CBOR
header is followed directly by the deterministic probe payload (`ProbePayload`)
and closed with `FIN`.

## 1. `start` — Initiate a probe toward a target peer

Asks a local or remote controller node to run a probe against `peer` and return
the measured transfer summary.

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `bytes` | `uint` | Total payload bytes per direction (`1..=16_777_216`). |
| 2 | `packet_size` | `u16` | Nominal chunk/frame payload size in bytes (`>= 4`). |
| 6 | `ack_frequency` | `u8` | Optional ACK-eliciting packet threshold (`1..=8`). |
| 7 | `ack_delay_ms` | `u8` | Optional maximum receiver ACK delay in milliseconds (`1..=25`). |
| 8 | `low_priority_bytes` | `u32` | Optional background low-priority stream bytes. |
| 9 | `high_priority_bytes` | `u32` | Optional urgent high-priority stream bytes. |
| 10 | `parallel_streams` | `u8` | Optional concurrent normal streams (`1..=4`). |
| 11 | `initial_consume_delay_ms` | `u32` | Optional initial receiver delay before reading payload. |
| 12 | `consume_delay_ms` | `u32` | Optional per-chunk receiver delay in milliseconds. |
| 13 | `peer` | `string` | Target destination URI (`mesh://...`, `udp://...`, `espnow://...`). |
| 14 | `direction` | `string` | Optional `"download"` (default), `"upload"`, or `"both"`. |
| 16 | `verify` | `bool` | Optional deterministic byte-pattern verification (`false` by default). |

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `status` | `string` | `"ok"` or `"error"`. |
| 2 | `peer` | `string` | Normalized target destination URI. |
| 3 | `requested_bytes` | `uint` | Requested payload bytes. |
| 4 | `received_bytes` | `uint` | Verified payload bytes transferred. |
| 5 | `elapsed_us` | `uint` | Total transfer duration in microseconds. |

## 2. `handler` — Stream probe responder

**Execution:** stream

The probed node's stream handler. For `upload`, the caller sends the request
header followed by `bytes` of `ProbePayload` and `FIN`; the responder validates
the upload through `FIN` and answers with a response header. For `download`,
the responder answers with the response header followed by `bytes` of
`ProbePayload` and `FIN`. Duplex (`both`) uses two concurrent streams (`upload`
+ `download`).

### Request

Uses the same field tags (`1..16`, with `peer` omitted) as `probe.start`.

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `bytes` | `uint` | Download payload bytes that follow the response header. |
| 2 | `packet_size` | `uint` | Chunk size used to generate the deterministic `ProbePayload`. |
| 3 | `uploaded_bytes` | `uint` | Optional: upload payload bytes verified before `FIN`. |
