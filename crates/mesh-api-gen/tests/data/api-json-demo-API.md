# `demo` API (7)

The demo component.

## 1. `set` — Store a value

**C function:** demo/Table.set

Stores `value`; returns the new generation.

**Access:** authenticated

**Request:** [Item](#item)

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `generation` | `u32` | Increases on every change. |

# Types

## `Item`

**C type:** Item

An item.

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `name` | `string` | The name. |
| 2 | `mode` | [`Mode`](#enum-mode) | |

## enum `Mode`

| Value | Name | Description |
|---:|---|---|
| 0 | `off` | Not running. |
| 1 | `on` | Running. |
