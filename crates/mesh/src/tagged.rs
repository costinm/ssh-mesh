//! Schema-optional records shared by text, JSON, CBOR, and future binary codecs.
//!
//! Numeric tags are an encoding-independent identity. A catalog is optional:
//! unknown numeric tags are represented in text/JSON as `@<decimal>`.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value};

/// A name which may have a compact numeric representation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NameOrTag {
    Name(String),
    Tag(u32),
}

impl NameOrTag {
    /// Parse `@<decimal>` as a tag; all other names remain text.
    pub fn parse(value: &str) -> Self {
        value
            .strip_prefix('@')
            .and_then(|id| id.parse().ok())
            .map(Self::Tag)
            .unwrap_or_else(|| Self::Name(value.to_owned()))
    }

    /// Render a schema-independent, shell-safe spelling.
    pub fn text(&self) -> String {
        match self {
            Self::Name(value) => value.clone(),
            Self::Tag(id) => format!("@{id}"),
        }
    }
}

/// The common representation used by generic gateways.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TaggedRecord {
    pub component: NameOrTag,
    pub method: NameOrTag,
    pub id: Option<Value>,
    pub params: Vec<Value>,
    pub env: BTreeMap<NameOrTag, Value>,
    /// Present only on a successful response; requests leave it unset.
    pub result: Option<Value>,
    /// Present only on a failed response. Keeping it in the common envelope
    /// lets JSON-RPC gateways translate failures mechanically.
    pub error: Option<Value>,
    /// Optional mesh destination. When present, a mesh-capable dispatcher
    /// forwards the request to this destination instead of executing the
    /// method locally. It is envelope routing metadata, not a handler field.
    pub to: Option<Value>,
    /// Opaque binary payload outside `env`. Keeping this borrowed/owned byte
    /// lane distinct from normal typed fields lets proxy stubs forward large
    /// records without base64 or an intermediate JSON value.
    pub data: Option<Vec<u8>>,
}

/// The envelope kind is derived from field presence; there is intentionally no
/// extra discriminator on the wire. This keeps requests small while making a
/// malformed response impossible to mistake for a command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    Request,
    Message,
    Response,
    Error,
}

impl TaggedRecord {
    /// Validate and classify the common command envelope.
    ///
    /// * `method` + `id` is a request expecting a reply.
    /// * `method` without `id` is a one-way message or event.
    /// * `id` + `result` or `id` + `error` is a reply.
    pub fn kind(&self) -> Result<RecordKind> {
        let has_method = !matches!(&self.method, NameOrTag::Name(value) if value.is_empty());
        match (
            has_method,
            self.id.is_some(),
            self.result.is_some(),
            self.error.is_some(),
        ) {
            (true, true, false, false) => Ok(RecordKind::Request),
            (true, false, false, false) => Ok(RecordKind::Message),
            (false, true, true, false) => Ok(RecordKind::Response),
            (false, true, false, true) => Ok(RecordKind::Error),
            _ => bail!("invalid tagged record envelope"),
        }
    }
}

impl Default for NameOrTag {
    fn default() -> Self {
        Self::Name(String::new())
    }
}

/// Per-method dictionary data extracted from the API catalog.
#[derive(Clone, Debug, Default)]
pub struct MethodSchema {
    pub component: NameOrTag,
    pub method: NameOrTag,
    pub fields: BTreeMap<String, FieldSchema>,
}

#[derive(Clone, Debug)]
pub struct FieldSchema {
    pub tag: u32,
    /// One-based, at most three slots for readable text invocations.
    pub positional: Option<u8>,
}

/// Catalog used for format translation. It intentionally permits unknown values.
#[derive(Clone, Debug, Default)]
pub struct TaggedCatalog {
    methods: BTreeMap<String, MethodSchema>,
}

impl TaggedCatalog {
    /// Read the generated numeric metadata from `tools.json`.
    ///
    /// New API.md-derived artifacts use `x-component-index`,
    /// `x-method-index`, and `x-protobuf-index`. The older mesh/DMesh
    /// annotations remain accepted here so every host adapter can migrate to
    /// the one catalog without a wire-format flag day.
    pub fn from_tools_json(value: &Value) -> Result<Self> {
        let tools = value
            .as_array()
            .or_else(|| value.get("tools").and_then(Value::as_array))
            .ok_or_else(|| anyhow!("tools catalog must be an array"))?;
        let mut catalog = Self::default();
        for tool in tools {
            let Some(name) = tool.get("name").and_then(Value::as_str) else {
                continue;
            };
            let wire = tool.get("x-mesh-wire");
            let (default_component, default_method) = name.split_once('.').unwrap_or(("", name));
            let component = name_or_index(
                tool.get("x-component-index")
                    .or_else(|| wire.and_then(|wire| wire.get("component"))),
                default_component,
            );
            let method = name_or_index(
                tool.get("x-method-index")
                    .or_else(|| wire.and_then(|wire| wire.get("method")))
                    .or_else(|| wire.and_then(|wire| wire.get("method_id"))),
                default_method,
            );
            let mut schema = MethodSchema {
                component,
                method,
                fields: BTreeMap::new(),
            };
            if let Some(properties) = tool
                .pointer("/inputSchema/properties")
                .and_then(Value::as_object)
            {
                for (field, property) in properties {
                    let annotation = property.get("x-mesh-wire");
                    if let Some(tag) = property
                        .get("x-protobuf-index")
                        .and_then(Value::as_u64)
                        .or_else(|| {
                            property
                                .get("x-mesh-cbor")
                                .and_then(|value| value.get("id"))
                                .and_then(Value::as_u64)
                        })
                        .or_else(|| {
                            annotation
                                .and_then(|value| value.get("tag"))
                                .and_then(Value::as_u64)
                        })
                    {
                        let positional = property
                            .get("x-cli-position")
                            .and_then(Value::as_u64)
                            .or_else(|| {
                                annotation
                                    .and_then(|value| value.get("positional"))
                                    .and_then(Value::as_u64)
                            })
                            .and_then(|slot| u8::try_from(slot).ok())
                            .filter(|slot| (1..=3).contains(slot));
                        schema.fields.insert(
                            field.clone(),
                            FieldSchema {
                                tag: tag as u32,
                                positional,
                            },
                        );
                    }
                }
            }
            catalog.methods.insert(name.to_owned(), schema);
        }
        Ok(catalog)
    }

    pub fn method(&self, name: &str) -> Option<&MethodSchema> {
        self.methods.get(name)
    }

    /// Resolve a numeric or textual record identity to its documented method
    /// name. Service dispatchers use this when an inbound tagged-CBOR request
    /// needs to enter an existing typed serde handler.
    pub fn method_name(&self, record: &TaggedRecord) -> Option<&str> {
        self.methods
            .iter()
            .find(|(_, schema)| {
                schema.component == record.component && schema.method == record.method
            })
            .map(|(name, _)| name.as_str())
    }

    /// Parse `component.method name=value positional...` into a tagged record.
    pub fn parse_text(&self, line: &str) -> Result<TaggedRecord> {
        let tokens = text_tokens(line)?;
        self.parse_tokens(&tokens)
    }

    /// Parse a method name and already shell-split arguments into a tagged record.
    ///
    /// Command-line clients must use this rather than joining argv back into a
    /// text line: a field value such as `command=ble stats=true` is one argv
    /// token and must remain one value when a generated tools catalog supplies
    /// its wire tags.
    pub fn parse_argv(&self, method_name: &str, arguments: &[String]) -> Result<TaggedRecord> {
        let mut tokens = Vec::with_capacity(arguments.len() + 1);
        tokens.push(method_name);
        tokens.extend(arguments.iter().map(String::as_str));
        self.parse_tokens(&tokens)
    }

    /// Build a record from a structured Rust/JSON request value.
    ///
    /// This is the non-text counterpart to [`Self::parse_argv`]. Rust clients
    /// serialize their typed request struct once, then this catalog applies
    /// the reviewed field tags without inventing a `key=value` intermediate.
    /// Unknown methods or fields remain named so callers can deliberately use
    /// the JSON-RPC compatibility path until they have reviewed API IDs.
    pub fn record_from_value(&self, method_name: &str, value: &Value) -> Result<TaggedRecord> {
        let schema = self.methods.get(method_name);
        let (component, method) = schema
            .map(|schema| (schema.component.clone(), schema.method.clone()))
            .unwrap_or_else(|| {
                let (component, method) = method_name.split_once('.').unwrap_or(("", method_name));
                (
                    NameOrTag::Name(component.to_owned()),
                    NameOrTag::Name(method.to_owned()),
                )
            });
        let object = value
            .as_object()
            .ok_or_else(|| anyhow!("structured request for {method_name:?} must be an object"))?;
        let mut record = TaggedRecord {
            component,
            method,
            ..Default::default()
        };
        for (name, value) in object {
            match name.as_str() {
                "id" => record.id = Some(value.clone()),
                "to" => record.to = Some(value.clone()),
                // `data` is deliberately a CBOR byte field in the envelope.
                // The Rust wire adapter accepts an array of octets here so
                // binary data does not cross a base64/text conversion.
                "data" => {
                    let bytes = value
                        .as_array()
                        .ok_or_else(|| anyhow!("structured request data must be an octet array"))?
                        .iter()
                        .map(|value| {
                            value
                                .as_u64()
                                .and_then(|value| u8::try_from(value).ok())
                                .ok_or_else(|| {
                                    anyhow!("structured request data contains a non-octet")
                                })
                        })
                        .collect::<Result<Vec<_>>>()?;
                    record.data = Some(bytes);
                }
                _ => {
                    let key = schema
                        .and_then(|schema| schema.fields.get(name))
                        .map(|field| NameOrTag::Tag(field.tag))
                        .unwrap_or_else(|| NameOrTag::parse(name));
                    record.env.insert(key, value.clone());
                }
            }
        }
        Ok(record)
    }

    fn parse_tokens(&self, tokens: &[&str]) -> Result<TaggedRecord> {
        let (method_name, rest) = tokens
            .split_first()
            .ok_or_else(|| anyhow!("missing method"))?;
        let schema = self.methods.get(*method_name);
        let (component, method) = schema
            .map(|schema| (schema.component.clone(), schema.method.clone()))
            .unwrap_or_else(|| {
                let (component, method) = method_name.split_once('.').unwrap_or(("", method_name));
                (
                    NameOrTag::Name(component.to_owned()),
                    NameOrTag::Name(method.to_owned()),
                )
            });
        let mut record = TaggedRecord {
            component,
            method,
            ..Default::default()
        };
        let mut options = true;
        for &token in rest {
            if options && token == "--" {
                options = false;
                continue;
            }
            if options && token.starts_with('-') {
                let option = token.trim_start_matches('-');
                let (name, value) = option
                    .split_once('=')
                    .ok_or_else(|| anyhow!("option {token} requires =value"))?;
                if name == "to" {
                    record.to = Some(text_value(value));
                    continue;
                }
                let key = schema
                    .and_then(|schema| schema.fields.get(name))
                    .map(|field| NameOrTag::Tag(field.tag))
                    .unwrap_or_else(|| NameOrTag::parse(name));
                record.env.insert(key, text_value(value));
            } else if options
                && let Some((name, value)) = token.split_once('=')
                && !name.is_empty()
            {
                if name == "to" {
                    record.to = Some(text_value(value));
                    continue;
                }
                let key = schema
                    .and_then(|schema| schema.fields.get(name))
                    .map(|field| NameOrTag::Tag(field.tag))
                    .unwrap_or_else(|| NameOrTag::parse(name));
                record.env.insert(key, text_value(value));
            } else {
                record.params.push(text_value(token));
            }
        }
        if let Some(schema) = schema {
            for field in schema.fields.values() {
                if let Some(slot) = field.positional {
                    if let Some(value) = record.params.get(usize::from(slot - 1)).cloned() {
                        record.env.entry(NameOrTag::Tag(field.tag)).or_insert(value);
                    }
                }
            }
        }
        Ok(record)
    }

    /// Produce the established flat JSONL request form for an endpoint.
    pub fn to_jsonl(&self, record: &TaggedRecord) -> Value {
        let mut value = Map::new();
        let documented_name = self.method_name(record);
        let component = record.component.text();
        let method = record.method.text();
        value.insert(
            "method".to_owned(),
            Value::String(documented_name.map(str::to_owned).unwrap_or_else(|| {
                if component.is_empty() {
                    method.clone()
                } else {
                    format!("{component}.{method}")
                }
            })),
        );
        if let Some(id) = &record.id {
            value.insert("id".to_owned(), id.clone());
        }
        let schema = documented_name.and_then(|name| self.methods.get(name));
        for (key, item) in &record.env {
            let name = match key {
                NameOrTag::Name(name) => name.clone(),
                NameOrTag::Tag(tag) => schema
                    .and_then(|schema| {
                        schema
                            .fields
                            .iter()
                            .find(|(_, field)| field.tag == *tag)
                            .map(|(name, _)| name.clone())
                    })
                    .unwrap_or_else(|| format!("@{tag}")),
            };
            value.insert(name, item.clone());
        }
        if !record.params.is_empty() {
            value.insert("params".to_owned(), Value::Array(record.params.clone()));
        }
        if let Some(result) = &record.result {
            value.insert("result".to_owned(), result.clone());
        }
        if let Some(error) = &record.error {
            value.insert("error".to_owned(), error.clone());
        }
        if let Some(to) = &record.to {
            value.insert("to".to_owned(), to.clone());
        }
        if let Some(data) = &record.data {
            value.insert(
                "data".to_owned(),
                Value::String(format!("base64:{}", crate::cbor::base64(data))),
            );
        }
        Value::Object(value)
    }
}

fn name_or_index(value: Option<&Value>, fallback: &str) -> NameOrTag {
    match value {
        Some(Value::Number(value)) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .map(NameOrTag::Tag)
            .unwrap_or_else(|| NameOrTag::Name(fallback.to_owned())),
        Some(Value::String(value)) => NameOrTag::parse(value),
        _ => NameOrTag::Name(fallback.to_owned()),
    }
}

/// Convert CLI `COMPONENT METHOD key=value` arguments into a common record.
/// With a catalog this produces numeric identifiers; without one the record is
/// still self-describing and can be forwarded as tagged CBOR.
pub fn record_from_argv(
    arguments: &[String],
    catalog: Option<&TaggedCatalog>,
) -> Result<TaggedRecord> {
    let component = arguments
        .first()
        .ok_or_else(|| anyhow!("RPC endpoints require COMPONENT METHOD [options/parameters]"))?;
    let (method_name, invocation_args) = if component.contains('.') {
        (component.clone(), arguments[1..].to_vec())
    } else {
        let method = arguments.get(1).ok_or_else(|| {
            anyhow!("RPC endpoints require COMPONENT METHOD [options/parameters]")
        })?;
        (format!("{component}.{method}"), arguments[2..].to_vec())
    };
    if let Some(catalog) = catalog {
        return catalog.parse_argv(&method_name, &invocation_args);
    }
    let (component, method) = if component.contains('.') {
        component
            .split_once('.')
            .ok_or_else(|| anyhow!("dotted RPC method must contain a component and method"))?
    } else {
        (
            component.as_str(),
            arguments
                .get(1)
                .ok_or_else(|| {
                    anyhow!("RPC endpoints require COMPONENT METHOD [options/parameters]")
                })?
                .as_str(),
        )
    };
    let mut record = TaggedRecord {
        component: NameOrTag::parse(component),
        method: NameOrTag::parse(method),
        ..Default::default()
    };
    let mut options = true;
    for value in invocation_args {
        if options && value == "--" {
            options = false;
        } else if options && value.starts_with('-') {
            let (key, value) = value
                .trim_start_matches('-')
                .split_once('=')
                .ok_or_else(|| anyhow!("option {value} requires =value"))?;
            record.env.insert(NameOrTag::parse(key), text_value(value));
        } else if options
            && let Some((key, value)) = value.split_once('=')
            && !key.is_empty()
        {
            record.env.insert(NameOrTag::parse(key), text_value(value));
        } else {
            record.params.push(text_value(&value));
        }
    }
    Ok(record)
}

/// Convert a tagged record to flat JSON without duplicating client-specific
/// translation logic. Catalog names are preferred; unknown numeric keys use
/// the stable `@N` spelling.
pub fn to_json(record: &TaggedRecord, catalog: Option<&TaggedCatalog>) -> Value {
    if let Some(catalog) = catalog {
        return catalog.to_jsonl(record);
    }
    let mut value = Map::new();
    let component = record.component.text();
    let method = record.method.text();
    value.insert(
        "method".to_owned(),
        Value::String(if component.is_empty() {
            method
        } else {
            format!("{component}.{method}")
        }),
    );
    if let Some(id) = &record.id {
        value.insert("id".to_owned(), id.clone());
    }
    for (key, item) in &record.env {
        value.insert(key.text(), item.clone());
    }
    if !record.params.is_empty() {
        value.insert("params".to_owned(), Value::Array(record.params.clone()));
    }
    if let Some(result) = &record.result {
        value.insert("result".to_owned(), result.clone());
    }
    if let Some(error) = &record.error {
        value.insert("error".to_owned(), error.clone());
    }
    Value::Object(value)
}

/// Render a tagged record as a structured-text command for operator and
/// gateway compatibility. Rust callers should select the CBOR codec.
pub fn to_text(record: &TaggedRecord) -> String {
    let mut values = vec![format!(
        "{}.{}",
        record.component.text(),
        record.method.text()
    )];
    values.extend(
        record
            .env
            .iter()
            .map(|(key, value)| format!("{}={}", key.text(), render_text_value(value))),
    );
    values.extend(record.params.iter().map(render_text_value));
    format!("{}\n", values.join(" "))
}

fn text_value(value: &str) -> Value {
    if let Ok(value) = value.parse::<i64>() {
        Value::from(value)
    } else if let Ok(value) = value.parse::<f64>() {
        Value::from(value)
    } else if matches!(value, "true" | "false") {
        Value::Bool(value == "true")
    } else {
        Value::String(value.to_owned())
    }
}

fn render_text_value(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        _ => value.to_string(),
    }
}

fn text_tokens(line: &str) -> Result<Vec<&str>> {
    // Shell quoting is intentionally delegated to the invoking shell. This is
    // a record grammar, not a shell interpreter.
    let tokens: Vec<_> = line.split_whitespace().collect();
    if tokens
        .iter()
        .any(|token| token.contains('"') || token.contains('\''))
    {
        bail!("quote values in the shell before passing a mesh invocation");
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn text_options_and_positional_values_share_tagged_env() {
        let catalog = TaggedCatalog::from_tools_json(&json!([{
            "name":"wifi.listen", "x-mesh-wire":{"component":"wifi","method":"listen"},
            "inputSchema":{"properties":{"iface":{"x-mesh-wire":{"tag":1,"positional":1}},"listen_sec":{"x-mesh-wire":{"tag":2,"positional":2}}}}
        }])).unwrap();
        let record = catalog
            .parse_text("wifi.listen -listen_sec=1 wlan0")
            .unwrap();
        assert_eq!(record.params, vec![json!("wlan0")]);
        assert_eq!(record.env.get(&NameOrTag::Tag(1)), Some(&json!("wlan0")));
        assert_eq!(record.env.get(&NameOrTag::Tag(2)), Some(&json!(1)));
    }

    #[test]
    fn text_bare_named_values_are_fields() {
        let catalog = TaggedCatalog::default();
        let record = catalog.parse_text("service.stop name=lmesh").unwrap();
        assert!(record.params.is_empty());
        assert_eq!(
            record.env.get(&NameOrTag::Name("name".to_owned())),
            Some(&json!("lmesh"))
        );
    }

    #[test]
    fn argv_preserves_space_containing_field_value() {
        let catalog = TaggedCatalog::from_tools_json(&json!([{
            "name":"esp.serial.command",
            "x-mesh-wire":{"component":"esp","method":"serial.command"},
            "inputSchema":{"properties":{"command":{"x-mesh-wire":{"tag":1}}}}
        }]))
        .unwrap();
        let record = catalog
            .parse_argv("esp.serial.command", &["command=ble stats=true".to_owned()])
            .unwrap();
        assert_eq!(
            record.env.get(&NameOrTag::Tag(1)),
            Some(&json!("ble stats=true"))
        );
    }

    #[test]
    fn structured_request_uses_catalog_tags_without_text_round_trip() {
        let catalog = TaggedCatalog::from_tools_json(&json!([{
            "name":"wifi.status",
            "x-component-index":5,
            "x-method-index":1,
            "inputSchema":{"properties":{"iface":{"x-protobuf-index":1}}}
        }]))
        .unwrap();
        let record = catalog
            .record_from_value("wifi.status", &json!({"iface": "wlan0"}))
            .unwrap();
        assert_eq!(record.component, NameOrTag::Tag(5));
        assert_eq!(record.method, NameOrTag::Tag(1));
        assert_eq!(record.env.get(&NameOrTag::Tag(1)), Some(&json!("wlan0")));
    }

    #[test]
    fn common_helpers_keep_schema_less_calls_and_responses_structured() {
        let arguments = vec!["core.status".to_owned(), "verbose=true".to_owned()];
        let mut record = record_from_argv(&arguments, None).unwrap();
        record.id = Some(json!(9));
        assert_eq!(record.component.text(), "core");
        assert_eq!(record.method.text(), "status");
        assert_eq!(
            to_json(&record, None),
            json!({"method":"core.status", "id":9, "verbose":true})
        );
    }

    #[test]
    fn envelope_kind_is_unambiguous() {
        let request = TaggedRecord {
            component: NameOrTag::Name("core".to_owned()),
            method: NameOrTag::Name("status".to_owned()),
            id: Some(json!(1)),
            ..Default::default()
        };
        assert_eq!(request.kind().unwrap(), RecordKind::Request);

        let response = TaggedRecord {
            id: Some(json!(1)),
            result: Some(json!({"ready": true})),
            ..Default::default()
        };
        assert_eq!(response.kind().unwrap(), RecordKind::Response);

        let malformed = TaggedRecord {
            id: Some(json!(1)),
            result: Some(json!(true)),
            error: Some(json!("no")),
            ..Default::default()
        };
        assert!(malformed.kind().is_err());
    }

    #[test]
    fn generated_protobuf_indices_produce_compact_tagged_records() {
        let catalog = TaggedCatalog::from_tools_json(&json!([{
            "name": "radio.control",
            "x-component-index": 0,
            "x-method-index": 72,
            "inputSchema": {"properties": {
                "channel": {"x-protobuf-index": 2},
                "promiscuous": {"x-protobuf-index": 10, "x-cli-position": 1}
            }}
        }]))
        .unwrap();
        let record = catalog
            .parse_argv(
                "radio.control",
                &["channel=6".to_owned(), "true".to_owned()],
            )
            .unwrap();
        assert_eq!(record.component, NameOrTag::Tag(0));
        assert_eq!(record.method, NameOrTag::Tag(72));
        assert_eq!(record.env.get(&NameOrTag::Tag(2)), Some(&json!(6)));
        assert_eq!(record.env.get(&NameOrTag::Tag(10)), Some(&json!(true)));
        assert_eq!(
            catalog.to_jsonl(&record),
            json!({
                "method": "radio.control",
                "channel": 6,
                "promiscuous": true,
                "params": [true]
            })
        );
    }
}
