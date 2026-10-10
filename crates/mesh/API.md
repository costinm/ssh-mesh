# `mesh` API (2000)

Core methods supplied by `mesh::registry::ServiceRegistry`. They are common
service discovery, lifecycle, and trace controls; each service documents its
own component methods separately. These components use the reserved numbers
2000 (`mesh`), 2001 (`trace`) and 2002 (`http`), outside any service's own range, so a
service can register them beside its own numbered methods. They dispatch by
number; a gateway that addresses methods by name translates them to the numbers at the
edge. Transport and encoding rules are in
[mesh-api/PROTOCOLS.md](../mesh-api/PROTOCOLS.md); handler streams (a header, then an
optional body) are defined in its
[Handler streams](../mesh-api/PROTOCOLS.md#handler-streams-header-and-body) section. The generated public catalog
is `resources/tools.json` and can be adapted by any gateway (CLI, HTTP, RPC or MCP)
without changing these handlers.

`mesh.lifecycle` is private supervisor-to-service traffic. Services that need
to react call `mesh::lifecycle::subscribe()` before accepting requests. Public
`mesh.initialize` returns common identity and metadata, while `mesh.tools`
returns the generated method catalog.

## 3. `lifecycle` — Receive a supervisor freeze or unfreeze notification

**Visibility:** private

**Tier:** internal

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `action` | `string` | |
| 2 | `cause` | `string` | |
| 3 | `observed` | `bool` | |

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `subscribers` | `u64` | |

## 1. `initialize` — Return common service identity and descriptive metadata

**Tier:** core

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `name` | `string` | |
| 2 | `version` | `string` | |
| 3 | `title` | `string` | |
| 4 | `instructions` | `string` | |

## 2. `tools` — Return the service's generated method catalog

**Tier:** core

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `tools` | `array` | |


# `trace` API (2001)

## 1. `subscribe` — Acknowledge trace-subscription capability on this control endpoint

**Tier:** debug

This acknowledges trace capability only. Live trace delivery uses the separate
local-trace subscription protocol.

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `subscribed` | `bool` | |
| 2 | `service` | `string` | |

## 2. `set_level` — Set this process's reloadable tracing EnvFilter

**Tier:** debug

Updates the reloadable process-wide tracing filter. An empty level restores
the configured default.

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `level` | `string` | |

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `level` | `string` | |
| 2 | `message` | `string` | |

## 3. `get_level` — Return this process's current configured tracing EnvFilter

**Tier:** debug

Returns the last successfully configured filter.

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `level` | `string` | |
| 2 | `message` | `string` | |


# `http` API (2002)

REST-style requests in the common envelope: the method is the verb, `params` is the path (an array of
numbers or text), the request `fields` are the headers, and the body follows on the stream. The
component adds no handler of its own: a service registers a handler at the dispatch key
`[http, verb, path...]` and the longest registered prefix of a request's key wins, as for every other
method. The rules (path, headers, status, dispatch key) are in
[mesh-api/PROTOCOLS.md](../mesh-api/PROTOCOLS.md#http-component-rest-style-requests); the numbers are
in `mesh::http_ids`. The verb numbers are the CoAP request codes.

Header keys `0`..`63` are reserved: `0` `status` (a response header: an HTTP status number), `1`
`content-length`, `2` `content-type`. A resource defines its own headers from `64` upward, or uses text
keys, and documents them beside its path. The tables below list the reserved request headers a verb
accepts; `status` is response-only, so it has no request tag.

## 1. `get` — Read a resource

**Tier:** core

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 2 | `content_type` | `string` | Accepted media type, when the resource has several. |

## 2. `post` — Send a body to a resource

**Tier:** core

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `content_length` | `u64` | Number of body bytes that follow the header. |
| 2 | `content_type` | `string` | Media type of the body. |

## 3. `put` — Replace a resource

**Tier:** core

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `content_length` | `u64` | Number of body bytes that follow the header. |
| 2 | `content_type` | `string` | Media type of the body. |

## 4. `delete` — Remove a resource

**Tier:** core

## 5. `fetch` — Read a resource selected by a body

**Tier:** core

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `content_length` | `u64` | Number of body bytes that follow the header. |
| 2 | `content_type` | `string` | Media type of the body. |

## 6. `patch` — Change part of a resource

**Tier:** core

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `content_length` | `u64` | Number of body bytes that follow the header. |
| 2 | `content_type` | `string` | Media type of the body. |
