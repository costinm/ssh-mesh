# `echo` API (10)

The JSON-RPC echo example. Its semantic method definition is shared with the
tagged-CBOR example; the transport adapter chooses the envelope.

## 1. `echo` — Return the supplied string

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `value` | `string` | |

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `value` | `string` | |
