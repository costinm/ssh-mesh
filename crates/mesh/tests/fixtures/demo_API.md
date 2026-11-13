# `demo` API (15)

Fixture exercising passive `ComponentSpec` tables, dual-key CBOR codecs,
JSON dispatch, and `FramedStream` handler dispatch.

## 1. `greet` — Greet a caller

### Request

| Tag | Field | Type | Required | Description |
|---:|---|---|---|---|
| 1 | `name` | `string` | yes | Caller name. |
| 2 | `repeat` | `u8` | no | Optional repetition count. |

### Response

| Tag | Field | Type | Required | Description |
|---:|---|---|---|---|
| 1 | `message` | `string` | yes | Formatted greeting. |

## 2. `upper_stream` — Uppercase a byte stream with an optional prefix

**Execution:** stream

### Request

| Tag | Field | Type | Required | Description |
|---:|---|---|---|---|
| 1 | `prefix` | `string` | no | Optional prefix written before uppercased body. |

# `host.info` API

String-only host component without numeric wire IDs.

## `status` — Return component health

### Response

| Tag | Field | Type | Required | Description |
|---:|---|---|---|---|
| 1 | `healthy` | `bool` | yes | Whether the component is healthy. |
| 2 | `calls` | `u64` | yes | Number of status calls served by this instance. |
