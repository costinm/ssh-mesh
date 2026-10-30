//! The function tables a native host (or a module) implements, as part of `api.json`, and what is generated from them.
//!
//! Front end: the `#[repr(C)]` table structs of a crate (rustdoc's JSON, the same layout the console's native catalog uses) become
//! components with their methods in table order, each argument as a word, a pointer-free struct in or out, an inline string or bytes, or
//! an array out. Back end: from that `api.json` alone, the schema (a compact `no_std` byte string per component, for the wasm bridge,
//! gateways, `mod_con` and a proxy over a stream) and the module-side stubs (one forwarding function per method plus a static table of
//! the same layout). Any other front end that fills the same fields gets the same outputs.
//!
//! There are no component numbers: a caller finds a component by name at run time, and a method is its index in the table (the order
//! and the version of the table are what keep callers compatible). A module that hosts a table carries its schema and hands it to the
//! runtime, which reads it without compiled-in knowledge of the table.
//!
//! Which structs are tables is a small list (`api/vtables.conf`), needed only to regenerate (a build uses the checked-in output):
//!
//! ```text
//! component wifi Wifi WIFI_VERSION shims      # name, table struct, version constant (- if none), mode
//! ```
//!
//! Modes: `shims` (the host provides it; a wasm32 module gets forwarding stubs), `host` (the host provides it, no stubs), `hosted` (a module
//! provides it: only the schema).
//!
//! Everything else is written in the doc comments of the Rust declarations, as `key=value` lines of their own (they are not part of the
//! prose that is carried on):
//!
//! ```text
//! /// note=packet ownership moves to the link      on a table function: it does not fit the parcel model, a decision is needed
//! /// cbor=map                                     on a struct: it has a CBOR form, a map keyed by tags
//! /// tag=1                                        on a field of such a struct: its tag (a field without one is keyed by its name)
//! ```
//!
//! The byte string of a schema, per method: `name 0 note 0 nargs` then per argument a tag: `v` word, `i`/`o` struct in/out (u16 LE size),
//! `s` string, `b`/`B` bytes in/out (index of the length argument), `a` array out (u16 LE element size, index of the count); the end is a
//! 0 byte.

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};

use crate::rustdoc::{Kind, Param, RustCatalog, Struct};

/// Calls carry the context and this many words.
const MAX_ARGS: usize = 6;

pub struct Config {
    pub components: Vec<Entry>,
}

#[derive(PartialEq, Clone, Copy)]
pub enum Mode {
    Shims,
    Host,
    Hosted,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::Shims => "shims",
            Mode::Host => "host",
            Mode::Hosted => "hosted",
        }
    }
}

pub struct Entry {
    pub name: String,
    pub table: String,
    pub version: String,
    pub mode: Mode,
}

impl Config {
    pub fn parse(text: &str) -> Result<Config> {
        let mut config = Config { components: Vec::new() };
        for (n, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            let (word, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
            match word {
                "component" => {
                    let f: Vec<&str> = rest.split_whitespace().collect();
                    if f.len() != 4 {
                        bail!("line {}: component NAME TABLE VERSION shims|host|hosted", n + 1);
                    }
                    let mode = match f[3] {
                        "shims" => Mode::Shims,
                        "host" => Mode::Host,
                        "hosted" => Mode::Hosted,
                        other => bail!("line {}: mode {other} is not shims, host or hosted", n + 1),
                    };
                    let version = if f[2] == "-" { String::new() } else { f[2].to_owned() };
                    config.components.push(Entry { name: f[0].into(), table: f[1].into(), version, mode });
                }
                other => bail!("line {}: unknown directive {other}", n + 1),
            }
        }
        Ok(config)
    }
}

/// A doc comment split into its prose and its `key=value` marker lines (`note`, `cbor`, `tag`).
pub fn markers(docs: &str) -> (String, Vec<(String, String)>) {
    let mut prose = Vec::new();
    let mut found = Vec::new();
    for line in docs.lines() {
        let t = line.trim();
        match t.split_once('=') {
            Some((k, v)) if matches!(k, "note" | "cbor" | "tag") && !v.starts_with('=') => found.push((k.to_owned(), v.trim().to_owned())),
            _ => prose.push(line),
        }
    }
    (prose.join("\n").trim().to_owned(), found)
}

fn marker<'a>(found: &'a [(String, String)], key: &str) -> Option<&'a str> {
    found.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

#[derive(Debug, PartialEq)]
enum Arg {
    Val,
    In(u32),
    Out(u32),
    Str,
    Bytes(usize),
    OutBytes(usize),
    OutArr(u32, usize),
}

impl Arg {
    fn to_json(&self) -> Value {
        match self {
            Arg::Val => json!({"kind": "val"}),
            Arg::In(n) => json!({"kind": "in", "size": n}),
            Arg::Out(n) => json!({"kind": "out", "size": n}),
            Arg::Str => json!({"kind": "str"}),
            Arg::Bytes(i) => json!({"kind": "bytes", "len": i}),
            Arg::OutBytes(i) => json!({"kind": "out_bytes", "len": i}),
            Arg::OutArr(n, i) => json!({"kind": "out_array", "size": n, "count": i}),
        }
    }

    fn from_json(v: &Value) -> Result<Arg> {
        let n = |k: &str| v[k].as_u64().with_context(|| format!("argument {v}: {k}"));
        Ok(match v["kind"].as_str().context("argument without kind")? {
            "val" => Arg::Val,
            "in" => Arg::In(n("size")? as u32),
            "out" => Arg::Out(n("size")? as u32),
            "str" => Arg::Str,
            "bytes" => Arg::Bytes(n("len")? as usize),
            "out_bytes" => Arg::OutBytes(n("len")? as usize),
            "out_array" => Arg::OutArr(n("size")? as u32, n("count")? as usize),
            other => bail!("unknown argument kind {other}"),
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Arg::Val => out.push(b'v'),
            Arg::In(n) | Arg::Out(n) => {
                out.push(if matches!(self, Arg::In(_)) { b'i' } else { b'o' });
                out.extend((*n as u16).to_le_bytes());
            }
            Arg::Str => out.push(b's'),
            Arg::Bytes(i) => out.extend([b'b', *i as u8]),
            Arg::OutBytes(i) => out.extend([b'B', *i as u8]),
            Arg::OutArr(n, i) => {
                out.push(b'a');
                out.extend((*n as u16).to_le_bytes());
                out.push(*i as u8);
            }
        }
    }
}

fn last(path: &str) -> &str {
    path.rsplit("::").next().unwrap_or(path)
}

fn rust_type(p: &Param) -> String {
    match p.role {
        "in" => format!("*const {}", last(&p.target)),
        "out" => format!("*mut {}", last(&p.target)),
        _ => last(&p.target).to_owned(),
    }
}

fn scalar(t: &str) -> Option<u32> {
    Some(match t {
        "u8" | "i8" | "bool" | "c_char" => 1,
        "u16" | "i16" => 2,
        "u32" | "i32" | "c_int" | "c_uint" => 4,
        "u64" | "i64" => 8,
        _ => return None,
    })
}

/// Whether a struct (or one it contains) has a pointer or function member, so its layout depends on the pointer width.
fn has_pointer(catalog: &RustCatalog, name: &str) -> bool {
    catalog.structs.get(name).is_some_and(|s| {
        s.fields.iter().any(|f| match &f.kind {
            Kind::Pointer | Kind::Function => true,
            Kind::Struct(n) => has_pointer(catalog, n),
            _ => false,
        })
    })
}

/// The arguments of one table function after the context, and what to say about the layout of those that are structs.
fn args_of(table: &Struct, field: &crate::rustdoc::Field, catalog: &RustCatalog) -> Result<(Vec<Arg>, Vec<String>)> {
    let params: Vec<&Param> = field.params.iter().skip(1).collect();
    let names: Vec<&str> = params.iter().map(|p| p.name.as_str()).collect();
    let mut warnings = Vec::new();
    let mut args = Vec::new();
    for (i, p) in params.iter().enumerate() {
        let target = last(&p.target);
        let mut size = |what: &str| -> Result<u32> {
            if let Some(n) = scalar(what) {
                return Ok(n);
            }
            let s = catalog.structs.get(what).with_context(|| format!("{}.{}: the layout of {what} is not known", table.name, field.name))?;
            if has_pointer(catalog, what) {
                warnings.push(format!("{what} has pointer members: its layout depends on the pointer width"));
            }
            Ok(s.size)
        };
        args.push(match p.role {
            "value" => Arg::Val,
            _ if target == "c_char" => Arg::Str,
            _ if target == "u8" => {
                let len = [format!("{}_len", p.name), "len".into(), "key_len".into(), "max".into()]
                    .iter()
                    .find_map(|c| names.iter().position(|n| n == c).filter(|j| j + 3 > i))
                    .with_context(|| format!("{}.{}: no length for {}", table.name, field.name, p.name))?;
                if p.role == "in" { Arg::Bytes(len) } else { Arg::OutBytes(len) }
            }
            "in" => Arg::In(size(target)?),
            _ if names.get(i + 1) == Some(&"max") && scalar(target).is_none() => Arg::OutArr(size(target)?, i + 1),
            _ => Arg::Out(size(target)?),
        });
    }
    Ok((args, warnings))
}

/// The CBOR records the crate declares: every struct whose doc has `cbor=map`, with the `tag=N` of its fields.
fn records(catalog: &RustCatalog) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for s in catalog.structs.values() {
        let (prose, found) = markers(&s.docs);
        let tagged: Vec<_> = s.fields.iter().map(|f| (f, markers(&f.docs))).collect();
        match marker(&found, "cbor") {
            None => {
                if let Some((f, _)) = tagged.iter().find(|(_, (_, m))| marker(m, "tag").is_some()) {
                    bail!("{}.{} has tag= but {} is not cbor=map", s.name, f.name, s.name);
                }
            }
            Some("map") => {
                let mut seen = std::collections::BTreeSet::new();
                let mut fields = Vec::new();
                for (f, (doc, m)) in &tagged {
                    let mut field = Map::new();
                    field.insert("name".into(), json!(f.name));
                    if let Some(tag) = marker(m, "tag") {
                        let tag: u32 = tag.parse().with_context(|| format!("{}.{}: tag={tag} is not a number", s.name, f.name))?;
                        if !seen.insert(tag) {
                            bail!("{}: tag={tag} is used twice", s.name);
                        }
                        field.insert("tag".into(), json!(tag));
                    }
                    if !doc.is_empty() {
                        field.insert("doc".into(), json!(doc));
                    }
                    fields.push(Value::Object(field));
                }
                out.push(json!({"kind": "record", "name": s.name, "doc": prose, "x-c": {"size": s.size}, "fields": fields}));
            }
            Some(other) => bail!("{}: cbor={other} is not supported (map)", s.name),
        }
    }
    Ok(out)
}

/// The front end: the tables of `config` in the layout of `catalog`, as the components and methods of an `api.json`.
pub fn tables_json(config: &Config, catalog: &RustCatalog) -> Result<Value> {
    let mut components = Vec::new();
    let mut methods = Vec::new();
    for c in &config.components {
        let table = catalog.structs.get(&c.table).with_context(|| format!("table struct {} is not in the rustdoc layout", c.table))?;
        let (prose, _) = markers(&table.docs);
        components.push(json!({"name": c.name, "doc": prose, "x-c": {"table": c.table, "version": c.version, "mode": c.mode.name()}}));
        for (index, field) in table.fields.iter().filter(|f| f.kind == Kind::Function).enumerate() {
            let (args, warnings) = args_of(table, field, catalog)?;
            let (doc, found) = markers(&field.docs);
            let mut note = marker(&found, "note").unwrap_or_default().to_owned();
            for w in warnings {
                note = if note.is_empty() { w } else { format!("{note}; {w}") };
            }
            if args.len() > MAX_ARGS {
                let long = format!("{} arguments, more than a call carries: a struct parcel", args.len());
                note = if note.is_empty() { long } else { format!("{long}; {note}") };
            }
            let params: Vec<Value> = field.params.iter().skip(1).zip(&args).map(|(p, a)| json!({"name": p.name, "type": rust_type(p), "arg": a.to_json()})).collect();
            let summary = doc.lines().next().unwrap_or_default().to_owned();
            methods.push(json!({
                "component": c.name, "method": field.name, "name": format!("{}.{}", c.name, field.name), "summary": summary, "doc": doc,
                "note": note, "x-c": {"table": c.table, "index": index, "params": params},
            }));
        }
    }
    Ok(json!({"format": crate::apijson::FORMAT, "components": components, "methods": methods, "types": records(catalog)?}))
}

/// A Rust byte string literal: letters and digits as they are, every other byte as `\xNN`.
fn literal(bytes: &[u8]) -> String {
    let mut s = String::from("b\"");
    for b in bytes {
        if b.is_ascii_alphanumeric() || *b == b'_' {
            s.push(*b as char);
        } else {
            s.push_str(&format!("\\x{b:02x}"));
        }
    }
    s.push('"');
    s
}

fn ident(name: &str) -> String {
    name.replace('-', "_")
}

/// The back end: `(schema_data.rs, vt_shims.rs)` from the tables in an `api.json`.
pub fn generate(api: &Value, tool: &str) -> Result<(String, String)> {
    let mut s = format!("// GENERATED by {tool} from the table structs of the crate. Do not edit. Included by schema.rs.\n\n");
    let mut shims = format!("// GENERATED by {tool} from the table structs of the crate. Do not edit.\n// included by vt.rs: `shim!` and `Arg` are defined there\n\n");
    let empty = Vec::new();
    let all = api["methods"].as_array().unwrap_or(&empty);
    let mut provided = Vec::new();
    let mut stubs = Vec::new();
    for c in api["components"].as_array().unwrap_or(&empty) {
        let name = c["name"].as_str().context("component without name")?;
        let x = &c["x-c"];
        let (table, version, mode) = (x["table"].as_str().unwrap_or_default(), x["version"].as_str().unwrap_or_default(), x["mode"].as_str().unwrap_or_default());
        let ms: Vec<&Value> = all.iter().filter(|m| m["component"] == name).collect();
        let mut blob = Vec::new();
        let mut parsed = Vec::new();
        for m in &ms {
            let mname = m["method"].as_str().context("method without name")?;
            let args = m["x-c"]["params"].as_array().unwrap_or(&empty).iter().map(|p| Arg::from_json(&p["arg"])).collect::<Result<Vec<_>>>()?;
            blob.extend(mname.bytes());
            blob.push(0);
            blob.extend(m["note"].as_str().unwrap_or_default().bytes());
            blob.push(0);
            blob.push(args.len() as u8);
            for a in &args {
                a.encode(&mut blob);
            }
            parsed.push((mname, args));
        }
        blob.push(0);
        let var = format!("SCHEMA_{}", ident(name).to_uppercase());
        s.push_str(&format!("/// The schema of `{name}` ({} methods, in table order).\npub static {var}: &[u8] = {};\n\n", ms.len(), literal(&blob)));
        if mode != "hosted" {
            provided.push((name, var));
        }
        if mode == "shims" {
            let handle = format!("H_{}", ident(name).to_uppercase());
            shims.push_str(&format!("static {handle}: AtomicI32 = AtomicI32::new(0);\n"));
            let mut fields = Vec::new();
            for (idx, (m, (mname, args))) in ms.iter().zip(&parsed).enumerate() {
                if args.len() > MAX_ARGS {
                    fields.push(format!("{mname}: None"));
                    continue;
                }
                let f = format!("{}_{mname}", ident(name));
                let sig: Vec<String> = m["x-c"]["params"].as_array().unwrap_or(&empty).iter().map(|p| {
                    let n = p["name"].as_str().unwrap_or_default();
                    format!("{}: {}", if n == "type" { "r#type" } else { n }, p["type"].as_str().unwrap_or_default())
                }).collect();
                shims.push_str(&format!("shim!({f}, {handle}, {idx}, ({}));\n", sig.join(", ")));
                fields.push(format!("{mname}: Some({f})"));
            }
            shims.push_str(&format!("static {}: {table} = {table} {{ version: {version}, size: size_of::<{table}>() as u32, {} }};\n\n", ident(name).to_uppercase(), fields.join(", ")));
            stubs.push((name, handle));
        }
    }
    s.push_str(&format!("/// The components the host provides, by name.\npub static COMPONENTS: [(&str, &[u8]); {}] = [\n", provided.len()));
    for (name, var) in &provided {
        s.push_str(&format!("    (\"{name}\", {var}),\n"));
    }
    s.push_str("];\n");
    shims.push_str("/// The stub table for `name` and the cell that holds the handle the host gave it.\nfn stub(name: &[u8]) -> Option<(&'static AtomicI32, *const c_void)> {\n    Some(match name {\n");
    for (name, handle) in &stubs {
        shims.push_str(&format!("        b\"{name}\" => (&{handle}, &{} as *const _ as *const c_void),\n", ident(name).to_uppercase()));
    }
    shims.push_str("        _ => return None,\n    })\n}\n");
    Ok((s, shims))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_lists_components() {
        let c = Config::parse("# c\ncomponent wifi Wifi WIFI_VERSION shims\ncomponent ble Ble - hosted\n").unwrap();
        assert_eq!(c.components.len(), 2);
        assert!(c.components[0].mode == Mode::Shims && c.components[1].version.is_empty() && c.components[1].mode == Mode::Hosted);
        assert!(Config::parse("component wifi\n").is_err());
        assert!(Config::parse("note wifi.scan x\n").is_err());
    }

    #[test]
    fn markers_leave_the_prose() {
        let (prose, found) = markers("Radio on.\ntag=1\nnote=a=b\nMore text.");
        assert_eq!(prose, "Radio on.\nMore text.");
        assert_eq!(found, vec![("tag".to_owned(), "1".to_owned()), ("note".to_owned(), "a=b".to_owned())]);
        assert_eq!(markers("x == y").1, vec![]);
    }

    fn catalog(json: &str) -> RustCatalog {
        serde_json::from_str::<Value>(json).map(|_| RustCatalog::default()).unwrap()
    }

    #[test]
    fn records_need_cbor_map_and_distinct_tags() {
        use crate::rustdoc::{Field, Struct};
        let field = |name: &str, docs: &str| Field { name: name.into(), docs: docs.into(), offset: 0, size: 1, kind: Kind::Int { bits: 8, signed: false }, params: vec![] };
        let make = |docs: &str, a: &str, b: &str| {
            let mut c = catalog("{}");
            c.structs.insert("A".into(), Struct { name: "A".into(), docs: docs.into(), size: 2, align: 1, fields: vec![field("x", a), field("y", b)] });
            c
        };
        let ok = records(&make("The A.\ncbor=map", "tag=1", "")).unwrap();
        assert_eq!(ok[0]["fields"][0]["tag"], 1);
        assert!(ok[0]["fields"][1].get("tag").is_none());
        assert_eq!(ok[0]["doc"], "The A.");
        assert!(records(&make("cbor=map", "tag=1", "tag=1")).is_err());
        assert!(records(&make("", "tag=1", "")).is_err());
        assert!(records(&make("cbor=array", "", "")).is_err());
        assert!(records(&make("plain", "", "")).unwrap().is_empty());
    }
}
