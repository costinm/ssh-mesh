//! `api.json`: the full-fidelity, generated form of an API, from which the other forms are derived (the trimmed
//! `tools.json` for MCP and LLM clients, the schema, the manifest, the Markdown). It carries what `tools.json` leaves out:
//! prose, field descriptions, enums, named records, and the native layout of the types and functions a native host
//! implements (`x-c`). It is never edited.

use std::collections::BTreeSet;

use anyhow::{Result, bail};
use serde_json::{Map, Value, json};

use crate::document::DocIndex;
use crate::rustdoc::{Kind, RustCatalog, Struct, c_name};
use crate::{ApiField, ApiMethod, ApiShape};

pub const FORMAT: &str = "mesh-api/1";

/// The native C prefix cbindgen puts before a Rust type name.
const C_PREFIX: &str = "xip_";

pub fn api_json(methods: &[ApiMethod], docs: &DocIndex, rust: Option<&RustCatalog>) -> Result<Value> {
    let enums: BTreeSet<&str> = docs.enums.iter().map(|e| e.name.as_str()).collect();
    let mut problems = Vec::new();

    let mut components = Vec::new();
    let mut seen = BTreeSet::new();
    for method in methods {
        if seen.insert(method.component.clone()) {
            let mut c = Map::new();
            c.insert("name".into(), json!(method.component));
            if let Some(index) = method.component_index {
                c.insert("index".into(), json!(index));
            }
            if let Some(doc) = docs.component_docs.get(&method.component).filter(|d| !d.is_empty()) {
                c.insert("doc".into(), json!(doc));
            }
            components.push(Value::Object(c));
        }
    }

    // named records, in order of first use
    let mut records: Vec<(String, &ApiShape)> = Vec::new();
    for method in methods {
        for (names, shape) in [(&docs.request_types, &method.request), (&docs.response_types, &method.response)] {
            if let Some(name) = names.get(&method.id) {
                if !records.iter().any(|(n, _)| n == name) {
                    records.push((name.clone(), shape));
                }
            }
        }
    }
    let mut types = Vec::new();
    for (name, shape) in &records {
        let mut t = Map::new();
        t.insert("kind".into(), json!("record"));
        t.insert("name".into(), json!(name));
        if let Some(doc) = docs.record_docs.get(name).filter(|d| !d.is_empty()) {
            t.insert("doc".into(), json!(doc));
        }
        let owner = format!("type:{name}");
        let native = match docs.c_types.get(name) {
            Some(rust_name) => {
                let Some(catalog) = rust else {
                    bail!("{name} names the native type {rust_name}, but no rustdoc JSON was given");
                };
                let Some(native) = catalog.structs.get(rust_name) else {
                    bail!("{name}: native type {rust_name} is not in the rustdoc JSON{}", catalog.skipped.get(rust_name).map(|why| format!(" ({why})")).unwrap_or_default());
                };
                Some(native)
            }
            None => None,
        };
        t.insert("fields".into(), fields_json(&shape.fields, docs.descriptions.get(&owner), native, &enums, name, &mut problems));
        if let Some(native) = native {
            let mut x = json!({"rust": native.name, "c": c_name(&native.name, C_PREFIX), "size": native.size, "align": native.align});
            // a leading `size` member (the caller sets sizeof, so the struct can grow)
            if let Some(first) = native.fields.first().filter(|f| f.name == "size" && f.offset == 0 && f.size == 4) {
                x["size_field"] = json!({"offset": first.offset, "size": first.size});
            }
            t.insert("x-c".into(), x);
        }
        types.push(Value::Object(t));
    }
    for method in methods {
        for row in &method.row_types {
            let owner = format!("row:{}", row.name);
            types.push(json!({
                "kind": "row",
                "name": row.name,
                "fields": fields_json(&row.fields, docs.descriptions.get(&owner), None, &enums, &row.name, &mut problems),
            }));
        }
    }
    for e in &docs.enums {
        let mut t = Map::new();
        t.insert("kind".into(), json!("enum"));
        t.insert("name".into(), json!(e.name));
        if !e.doc.is_empty() {
            t.insert("doc".into(), json!(e.doc));
        }
        t.insert(
            "values".into(),
            Value::Array(
                e.values
                    .iter()
                    .map(|v| {
                        let mut o = Map::new();
                        o.insert("value".into(), json!(v.value));
                        o.insert("name".into(), json!(v.name));
                        if !v.description.is_empty() {
                            o.insert("description".into(), json!(v.description));
                        }
                        Value::Object(o)
                    })
                    .collect(),
            ),
        );
        types.push(Value::Object(t));
    }

    let mut out_methods = Vec::new();
    for method in methods {
        let mut m = Map::new();
        m.insert("name".into(), json!(method.id));
        m.insert("component".into(), json!(method.component));
        m.insert("method".into(), json!(method.method));
        if let Some(index) = method.method_index {
            m.insert("index".into(), json!(index));
        }
        m.insert("summary".into(), json!(method.summary));
        if let Some(doc) = docs.method_docs.get(&method.id).filter(|d| !d.is_empty()) {
            m.insert("doc".into(), json!(doc));
        }
        m.insert("visibility".into(), json!(method.visibility));
        for (key, value) in [
            ("ui", &method.ui_visibility),
            ("execution", &method.execution),
            ("recommended_timeout", &method.recommended_timeout),
            ("access", &method.access),
            ("tier", &method.tier),
        ] {
            if let Some(value) = value {
                m.insert(key.into(), json!(value));
            }
        }
        if !method.errors.is_empty() {
            m.insert("errors".into(), Value::Array(method.errors.iter().map(|e| json!({"name": e.name, "description": e.description})).collect()));
        }
        for (key, names, shape) in [("request", &docs.request_types, &method.request), ("response", &docs.response_types, &method.response)] {
            let mut s = Map::new();
            if let Some(name) = names.get(&method.id) {
                s.insert("type".into(), json!(name));
            } else {
                let owner = format!("{}#{key}", method.id);
                s.insert("fields".into(), fields_json(&shape.fields, docs.descriptions.get(&owner), None, &enums, &owner, &mut problems));
            }
            if let Some(max) = &shape.max_encoded_size {
                s.insert("max_encoded_size".into(), json!(max));
            }
            m.insert(key.into(), Value::Object(s));
        }
        if let Some(spec) = docs.c_functions.get(&method.id) {
            let Some(catalog) = rust else {
                bail!("{} names the native function {spec}, but no rustdoc JSON was given", method.id);
            };
            match function_json(method, spec, docs, catalog) {
                Ok(v) => {
                    m.insert("x-c".into(), v);
                }
                Err(e) => problems.push(format!("{}: {e}", method.id)),
            }
        }
        out_methods.push(Value::Object(m));
    }
    if !problems.is_empty() {
        bail!("the API and its native layout disagree:\n  {}", problems.join("\n  "));
    }
    Ok(json!({"format": FORMAT, "components": components, "types": types, "methods": out_methods}))
}

fn fields_json(
    fields: &[ApiField],
    descriptions: Option<&std::collections::BTreeMap<String, String>>,
    native: Option<&Struct>,
    enums: &BTreeSet<&str>,
    owner: &str,
    problems: &mut Vec<String>,
) -> Value {
    Value::Array(
        fields
            .iter()
            .map(|f| {
                let mut o = Map::new();
                o.insert("tag".into(), json!(f.index));
                o.insert("name".into(), json!(f.name));
                o.insert("type".into(), json!(f.value_type));
                let mut description = descriptions.and_then(|d| d.get(&f.name)).cloned().unwrap_or_default();
                if let Some(native) = native {
                    match native.fields.iter().find(|n| n.name == f.name) {
                        None => problems.push(format!("{owner}.{}: no field of that name in {}", f.name, native.name)),
                        Some(n) => {
                            if let Some(why) = incompatible(&f.value_type, &n.kind, n.size, enums) {
                                problems.push(format!("{owner}.{}: {} is {why}", f.name, native.name));
                            }
                            if description.is_empty() {
                                description = n.docs.clone();
                            }
                            let mut c = json!({"offset": n.offset, "size": n.size, "kind": n.kind.name()});
                            if let Some(len) = native.fields.iter().find(|l| l.name == format!("{}_len", f.name)) {
                                c["len_field"] = json!({"name": len.name, "offset": len.offset, "size": len.size});
                            }
                            o.insert("x-c".into(), c);
                        }
                    }
                }
                if !description.is_empty() {
                    o.insert("description".into(), json!(description));
                }
                if f.required {
                    o.insert("required".into(), json!(true));
                }
                if let Some(default) = &f.default {
                    o.insert("default".into(), default.clone());
                }
                if let Some(max) = &f.max {
                    o.insert("max".into(), json!(max));
                }
                Value::Object(o)
            })
            .collect(),
    )
}

/// Why a native field cannot carry an API field of this type, or None.
fn incompatible(api: &str, native: &Kind, size: u32, enums: &BTreeSet<&str>) -> Option<String> {
    let want_bits = match api {
        "bool" | "u8" | "i8" => Some(8),
        "u16" | "i16" => Some(16),
        "u32" | "i32" | "f32" => Some(32),
        "u64" | "i64" | "f64" => Some(64),
        _ => None,
    };
    match (api, native) {
        ("string" | "bytes", Kind::Bytes) => None,
        ("string" | "bytes", _) => Some(format!("{} bytes of {}, not a byte array", size, native.name())),
        (_, Kind::Int { bits, .. }) if enums.contains(api) => (*bits > 32).then(|| format!("{bits} bits for an enum")),
        (_, Kind::Int { bits, .. }) if want_bits == Some(*bits) => None,
        (_, Kind::Bool) if api == "bool" => None,
        (_, Kind::Int { bits, .. }) => Some(format!("{bits} bits, the API says {api}")),
        _ => Some(format!("{}, the API says {api}", native.name())),
    }
}

/// `component/Table.member`: where the native function is, and how it is called.
fn function_json(method: &ApiMethod, spec: &str, docs: &DocIndex, catalog: &RustCatalog) -> Result<Value> {
    let (component, rest) = spec.split_once('/').unwrap_or((method.component.as_str(), spec));
    let Some((table, member)) = rest.split_once('.') else {
        bail!("`{spec}` is not Table.member");
    };
    let Some(native) = catalog.structs.get(table) else {
        bail!("native table {table} is not in the rustdoc JSON{}", catalog.skipped.get(table).map(|why| format!(" ({why})")).unwrap_or_default());
    };
    let Some(field) = native.fields.iter().find(|f| f.name == member) else {
        bail!("{table} has no member {member}");
    };
    if field.kind != Kind::Function {
        bail!("{table}.{member} is not a function pointer");
    }
    let mut params = Vec::new();
    for p in &field.params {
        let mut o = json!({"name": p.name, "role": p.role, "type": p.target});
        if p.role == "in" || p.role == "out" {
            // a struct parameter is the request or the response record, a scalar one is a field of the response
            if let Some(s) = catalog.structs.get(&p.target) {
                let (names, shape) = if p.role == "in" { (&docs.request_types, "request") } else { (&docs.response_types, "response") };
                let ok = names.get(&method.id).and_then(|t| docs.c_types.get(t)).is_some_and(|c| *c == s.name);
                if !ok {
                    bail!("parameter {} is a {} but the {shape} of the method is not that C type", p.name, p.target);
                }
            } else if p.role == "out" && !method.response.fields.iter().any(|f| f.name == p.name) {
                // a scalar output that the response does not carry (the generation of `get`) is not mapped
                o["mapped"] = json!(false);
            }
            o["kind"] = json!(p.target);
        }
        params.push(o);
    }
    Ok(json!({
        "component": component,
        "table": table,
        "c_table": c_name(table, C_PREFIX),
        "member": member,
        "offset": field.offset,
        "params": params,
    }))
}
