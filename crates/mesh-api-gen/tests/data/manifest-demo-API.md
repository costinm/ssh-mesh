# `demo` API (7)

The demo module.

## 1. `ping` — Return the supplied string

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `value` | `string` | |
| 2 | `wait` | `uint` | |

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `value` | `string` | |

## 20. `list` — Rows

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `value` | `string` | |
| 2 | `wait` | `uint` | |

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `rows` | `Row[]` | |
| 2 | `ok` | `bool` | |

`Row` fields:

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `name` | `string` | |
| 2 | `n` | `int` | |
