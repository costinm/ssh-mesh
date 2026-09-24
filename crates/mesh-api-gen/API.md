# `full` API (3)

This document exercises the complete proposed `mesh-api-gen` Markdown syntax.
It is both a readable example and the parser/generator fixture. The
operations are illustrative; no service implements this API.

## 1. `initialize` — Initialize the example service

Initializes service state. Calling this operation again is safe and returns
the current state.

**Response:** [ServiceState](#servicestate)

**Access:** any of `system`, `mesh.owner`, `mesh.admin`
**Recommended timeout:** `8s`

### Example: first initialization

Response:

```json
{"state":"ready","generation":1}
```

## 2. `echo` — Return a value unchanged

Demonstrates method-local request and response records. These tables normalize
to `FullEchoRequest` and `FullEchoResponse`; they are wire-equivalent to named
types under [Types](#types).

### Request

**Max encoded size:** `1000 B`

| Tag | Field | Type | Max | Description |
|---:|---|---|---|---|
| 1 | `value` | `string` | `960 B` | Text to return. |

### Response

**Max encoded size:** `1000 B`

| Tag | Field | Type | Max | Description |
|---:|---|---|---|---|
| 1 | `value` | `string` | `960 B` | The returned text. |

### Example: text

Request:

```json
{"value":"hello"}
```

Response:

```json
{"value":"hello"}
```

## 3. `configure` — Apply service configuration

Demonstrates reusable messages, enums, defaults, repeated values, nested
records, maps, and bytes.

**Request:** [ConfigureRequest](#configurerequest)
**Response:** [ConfigureResponse](#configureresponse)

**Execution:** blocking
**Recommended timeout:** `8s`
**Access:** any of `mesh.owner`, `mesh.admin`

### Example: change mode and labels

Request:

```json
{
  "mode": "active",
  "peers": ["sensor-a", "sensor-b"],
  "labels": {"site": "lab", "rack": "7"}
}
```

Response:

```json
{"changed":true,"state":{"state":"ready","generation":2}}
```

### Errors

| Error | Meaning |
|---|---|
| `invalid_argument` | A supplied value is outside its documented range. |
| `conflict` | The expected generation does not match current state. |

## 4. `list` — List known entries

**Request:** [ListRequest](#listrequest)
**Response:** [ListResponse](#listresponse)

**UI:** default

The response may include a cursor even when fewer than `limit` entries were
returned. Callers should treat only an absent cursor as end-of-list.

## 5. `reset` — Reset private service state

**Visibility:** private
**Execution:** blocking
**Recommended timeout:** `8s`
**Access:** any of `system`, `mesh.owner`, `mesh.admin`

This administrative method has no request or response value.

# `host.diagnostics` API

Host-only diagnostics demonstrate that components and methods do not require
numeric IDs when they are not carried over a constrained embedded link.

## `version` — Return build information

**Response:** [BuildInfo](#buildinfo)

## `snapshot` — Capture a diagnostic snapshot

**Access:** `com.example.permission.DIAGNOSTICS`
**Recommended timeout:** `2s`

### Request

**Max encoded size:** `128 B`

| Tag | Field | Type | Default | Description |
|---:|---|---|---|---|
| 1 | `include_logs` | `bool` | `false` | Include recent structured logs. |
| 2 | `max_bytes` | `u32` | `1048576` | Maximum returned payload size. |

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `content_type` | `string` | Media type of `data`. |
| 2 | `data` | `bytes` | Snapshot contents. |

# Types

## `ServiceState`

Current lifecycle state and its monotonic revision.

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `state` | [`State`](#enum-state) | Current lifecycle state. |
| 2 | `generation` | `u64` | Monotonic configuration generation. |

## enum `State`

| Value | Name | Description |
|---:|---|---|
| 0 | `unknown` | State has not been observed. |
| 1 | `starting` | Initialization is in progress. |
| 2 | `ready` | The service can handle requests. |
| 3 | `stopping` | Shutdown is in progress. |

## `ConfigureRequest`

Every field is optional on the wire. Omitted fields retain their current
values, except fields with an explicit default.

**Reserved tags:** 4, 7-9

| Tag | Field | Type | Default | Description |
|---:|---|---|---|---|
| 1 | `mode` | [`Mode`](#enum-mode) | `passive` | Requested operating mode. |
| 2 | `peers` | `string[]` | | Complete peer-name list. |
| 3 | `limits` | [`Limits`](#limits) | | Resource limits to replace. |
| 5 | `labels` | `map<string,string>` | | Operator labels keyed by name. |
| 6 | `expected_generation` | `u64` | | Apply only to this generation. |
| 10 | `opaque` | `bytes` | | Application-defined extension data. |

### `expected_generation`

This is an optimistic-concurrency guard. If present and different from the
current generation, `full.configure` returns `conflict` without applying any
other field.

### `opaque`

The service stores these bytes unchanged. Their internal format is outside
this API and gateways must not reinterpret them.

## enum `Mode`

| Value | Name | Description |
|---:|---|---|
| 0 | `passive` | Observe without initiating work. |
| 1 | `active` | Initiate work as needed. |

## `Limits`

This record demonstrates the complete integer and floating-point scalar
vocabulary. Real APIs should choose the narrowest type that represents the
domain rather than include redundant forms.

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `tiny_unsigned` | `u8` | Unsigned 8-bit example. |
| 2 | `small_unsigned` | `u16` | Unsigned 16-bit example. |
| 3 | `count` | `u32` | Unsigned 32-bit example. |
| 4 | `total` | `u64` | Unsigned 64-bit example. |
| 5 | `tiny_signed` | `i8` | Signed 8-bit example. |
| 6 | `small_signed` | `i16` | Signed 16-bit example. |
| 7 | `offset` | `i32` | Signed 32-bit example. |
| 8 | `balance` | `i64` | Signed 64-bit example. |
| 9 | `ratio` | `f32` | 32-bit floating-point example. |
| 10 | `threshold` | `f64` | 64-bit floating-point example. |
| 11 | `enabled` | `bool` | Boolean example. |

## `ConfigureResponse`

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `changed` | `bool` | Whether configuration changed. |
| 2 | `state` | [`ServiceState`](#servicestate) | State after the operation. |

## `ListRequest`

| Tag | Field | Type | Default | Description |
|---:|---|---|---|---|
| 1 | `limit` | `u32` | `100` | Maximum entries to return. |
| 2 | `cursor` | `bytes` | | Opaque continuation token. |

### `cursor`

A cursor is valid only for the service instance that returned it. Callers must
not inspect or persist it across a service restart.

## `ListResponse`

**Max encoded size:** `1000 B`

| Tag | Field | Type | Max | Description |
|---:|---|---|---|---|
| 1 | `entries` | [`Entry[]`](#entry) | `16 items` | Entries in stable service order. |
| 2 | `cursor` | `bytes` | `64 B` | Cursor for the next page, if any. |

## `Entry`

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `id` | `u64` | Stable entry identifier. |
| 2 | `name` | `string` | Human-readable name. |
| 3 | `attributes` | `map<string,string>` | String attributes keyed by name. |

## `BuildInfo`

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `version` | `string` | Human-readable version. |
| 2 | `revision` | `string` | Source revision, when available. |
| 3 | `features` | `string[]` | Enabled build features. |
