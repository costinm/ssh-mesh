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
    /// Read the `x-mesh-wire` annotations in generated `tools.json`.
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
            let (component, method) = wire
                .map(|wire| {
                    let component = wire.get("component").and_then(Value::as_str).unwrap_or("");
                    let method = wire.get("method").and_then(Value::as_str).unwrap_or(name);
                    (NameOrTag::parse(component), NameOrTag::parse(method))
                })
                .unwrap_or_else(|| {
                    let (component, method) = name.split_once('.').unwrap_or(("", name));
                    (
                        NameOrTag::Name(component.to_owned()),
                        NameOrTag::Name(method.to_owned()),
                    )
                });
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
                    if let Some(tag) = annotation
                        .and_then(|value| value.get("tag"))
                        .and_then(Value::as_u64)
                    {
                        let positional = annotation
                            .and_then(|value| value.get("positional"))
                            .and_then(Value::as_u64)
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

    /// Parse `component.method -name=value positional...` into a tagged record.
    pub fn parse_text(&self, line: &str) -> Result<TaggedRecord> {
        let tokens = text_tokens(line)?;
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
        let component = record.component.text();
        let method = record.method.text();
        value.insert(
            "method".to_owned(),
            Value::String(if component.is_empty() {
                method.clone()
            } else {
                format!("{component}.{method}")
            }),
        );
        if let Some(id) = &record.id {
            value.insert("id".to_owned(), id.clone());
        }
        let schema = self
            .methods
            .values()
            .find(|schema| schema.component == record.component && schema.method == record.method);
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
        Value::Object(value)
    }
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
}
