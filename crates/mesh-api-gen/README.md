# mesh-api-gen

`mesh-api-gen` is a standalone host build tool. It is not linked by `mesh`,
`dmesh-server`, firmware, or service binaries.

The normative input is fenced `mesh-api` TOML in an `API.md` file:

````markdown
```mesh-api
id = "wifi.raw.check"
component = "wifi"
method = "raw.check"
component-index = 7
method-index = 2
summary = "Read radio state"

[[request.fields]]
name = "channel"
index = 1
type = "u8"
required = true
```
````

Generate checked-in host catalog and no-std ID artifacts:

```sh
cargo run -p mesh-api-gen -- \
  --api crates/service/API.md \
  --out-tools crates/service/tools.json \
  --out-schema crates/service/schema.json \
  --out-ids crates/dmesh-server/src/generated/service_ids.rs

# CI drift check
cargo run -p mesh-api-gen -- \
  --api crates/service/API.md \
  --out-tools crates/service/tools.json \
  --out-schema crates/service/schema.json \
  --out-ids crates/dmesh-server/src/generated/service_ids.rs \
  --check
```

Rust structs may be an authoring convenience, not a runtime schema mechanism.
Document a struct immediately with a compact TOML annotation vocabulary, then
generate an API fragment for review and check-in:

```rust
/// mesh-api: id = "wifi.raw.check"
/// mesh-api: component = "wifi"
/// mesh-api: method = "raw.check"
/// mesh-api: component-index = 7
/// mesh-api: method-index = 2
pub struct RawCheckRequest {
    /// mesh-api-field: index = 1
    /// mesh-api-field: required = true
    pub channel: u8,
}

/// mesh-api: id = "wifi.raw.check"
/// mesh-api: component = "wifi"
/// mesh-api: method = "raw.check"
/// mesh-api: shape = "response"
pub struct RawCheckResponse {
    /// mesh-api-field: index = 1
    pub ok: bool,
}
```

```sh
cargo run -p mesh-api-gen -- \
  --rust crates/dmesh-server/src/wifi_api.rs \
  --out-api crates/dmesh-server/API.generated.md
```

An older hand-maintained `tools.json` can be imported as an API.md migration
draft. The import intentionally creates no numeric identifiers; review and add
them before the draft becomes the API source of truth.

```sh
cargo run -p mesh-api-gen -- \
  --tools crates/service/resources/tools.json \
  --component service \
  --out-api crates/service/API.migration.md
```

`--component` supplies the component name for older catalogs with bare method
names such as `status`; dotted names keep their existing component.

The source form deliberately parses comments only. `mesh-api-field` comments
immediately before public fields emit `[[request.fields]]`; a second struct
with the same identity and `shape = "response"` emits `[[response.fields]]`.
Their Rust types map to the API primitives (`String`/`&str`, integers, `bool`,
`Vec<u8>`, and `Vec<T>`). It introduces no proc macro, reflection, OpenAPI
generator, or schema dependency into handler or firmware code. The next
extension generates bounded CBOR marshal/unmarshal functions in `dmesh-server`.
