//! The native layout of an API, read from the JSON that `rustdoc` writes for a crate that declares `#[repr(C)]` structs
//! and function tables (`RUSTC_BOOTSTRAP=1 cargo rustdoc -- -Z unstable-options --output-format json`; format 57).
//!
//! Layouts are computed here with the `repr(C)` rules, for a given pointer width, so no compiled binary is needed; the
//! crate's own `const _: () = assert!(size_of::<T>() == N)` lines are what keep the two honest.

use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Int { bits: u32, signed: bool },
    Bool,
    /// `[u8; N]`
    Bytes,
    Pointer,
    Function,
    Struct(String),
}

impl Kind {
    pub fn name(&self) -> String {
        match self {
            Kind::Int { bits, signed } => format!("{}{}", if *signed { "i" } else { "u" }, bits),
            Kind::Bool => "bool".to_owned(),
            Kind::Bytes => "bytes".to_owned(),
            Kind::Pointer => "ptr".to_owned(),
            Kind::Function => "fn".to_owned(),
            Kind::Struct(name) => name.clone(),
        }
    }
}

/// One parameter of a function-pointer member.
#[derive(Clone, Debug)]
pub struct Param {
    pub name: String,
    /// `ctx`, `in` (`*const T`) or `out` (`*mut T`), or `value`.
    pub role: &'static str,
    /// The struct name or the scalar kind.
    pub target: String,
}

#[derive(Clone, Debug)]
pub struct Field {
    pub name: String,
    pub docs: String,
    pub offset: u32,
    pub size: u32,
    pub kind: Kind,
    /// Set for a function-pointer member.
    pub params: Vec<Param>,
}

#[derive(Clone, Debug)]
pub struct Struct {
    pub name: String,
    pub docs: String,
    pub size: u32,
    pub align: u32,
    pub fields: Vec<Field>,
}

#[derive(Clone, Debug, Default)]
pub struct RustCatalog {
    pub structs: BTreeMap<String, Struct>,
    /// Public `repr(C)` structs whose layout could not be computed (opaque or non-C members), with the reason.
    pub skipped: BTreeMap<String, String>,
}

struct Layout {
    size: u32,
    align: u32,
    kind: Kind,
}

pub struct Reader<'a> {
    index: &'a serde_json::Map<String, Value>,
    pointer: u32,
    cache: BTreeMap<String, Struct>,
}

impl RustCatalog {
    /// Read every public `repr(C)` struct of the documented crate. `pointer_width` is in bytes (4 for the targets this API
    /// runs on).
    pub fn from_rustdoc(json: &Value, pointer_width: u32) -> Result<Self> {
        let version = json.get("format_version").and_then(Value::as_u64).unwrap_or(0);
        if version != 57 {
            bail!("rustdoc JSON format {version} is not supported (57)");
        }
        let index = json.get("index").and_then(Value::as_object).context("rustdoc JSON has no index")?;
        let mut reader = Reader { index, pointer: pointer_width, cache: BTreeMap::new() };
        let mut skipped = BTreeMap::new();
        for (id, item) in index {
            let is_struct = item.pointer("/inner/struct/kind/plain").is_some();
            let repr_c = item
                .get("attrs")
                .and_then(Value::as_array)
                .is_some_and(|attrs| attrs.iter().any(|a| a.pointer("/repr/kind").and_then(Value::as_str) == Some("c")));
            if is_struct && repr_c && item.get("visibility").and_then(Value::as_str) == Some("public") {
                if let Err(e) = reader.struct_of(id) {
                    let name = item.get("name").and_then(Value::as_str).unwrap_or(id).to_owned();
                    skipped.insert(name, format!("{e:#}"));
                }
            }
        }
        Ok(RustCatalog { structs: reader.cache, skipped })
    }
}

impl Reader<'_> {
    fn struct_of(&mut self, id: &str) -> Result<Layout> {
        let item = self.index.get(id).with_context(|| format!("unknown rustdoc id {id}"))?;
        let name = item.get("name").and_then(Value::as_str).context("unnamed struct")?.to_owned();
        if let Some(done) = self.cache.get(&name) {
            return Ok(Layout { size: done.size, align: done.align, kind: Kind::Struct(name) });
        }
        let packed = item
            .get("attrs")
            .and_then(Value::as_array)
            .is_some_and(|a| a.iter().any(|a| !a.pointer("/repr/packed").unwrap_or(&Value::Null).is_null()));
        let ids = item.pointer("/inner/struct/kind/plain/fields").and_then(Value::as_array).context("struct without fields")?.clone();
        let (mut offset, mut align) = (0u32, 1u32);
        let mut fields = Vec::new();
        for fid in ids {
            let fid = fid.as_u64().context("field id")?.to_string();
            let field = self.index.get(&fid).context("unknown field")?;
            let fname = field.get("name").and_then(Value::as_str).unwrap_or_default().to_owned();
            let ty = field.pointer("/inner/struct_field").context("field type")?.clone();
            let layout = self.layout(&ty).with_context(|| format!("{name}.{fname}"))?;
            let falign = if packed { 1 } else { layout.align };
            offset = offset.div_ceil(falign) * falign;
            let params = self.params(&ty);
            fields.push(Field {
                name: fname,
                docs: field.get("docs").and_then(Value::as_str).unwrap_or_default().trim().to_owned(),
                offset,
                size: layout.size,
                kind: layout.kind,
                params,
            });
            offset += layout.size;
            align = align.max(falign);
        }
        let size = offset.div_ceil(align) * align;
        self.cache.insert(
            name.clone(),
            Struct { name: name.clone(), docs: item.get("docs").and_then(Value::as_str).unwrap_or_default().trim().to_owned(), size, align, fields },
        );
        Ok(Layout { size, align, kind: Kind::Struct(name) })
    }

    fn layout(&mut self, ty: &Value) -> Result<Layout> {
        let int = |bits: u32, signed| Layout { size: bits / 8, align: bits / 8, kind: Kind::Int { bits, signed } };
        if let Some(p) = ty.get("primitive").and_then(Value::as_str) {
            return Ok(match p {
                "u8" => int(8, false),
                "i8" => int(8, true),
                "u16" => int(16, false),
                "i16" => int(16, true),
                "u32" => int(32, false),
                "i32" => int(32, true),
                "u64" => int(64, false),
                "i64" => int(64, true),
                "usize" => int(self.pointer * 8, false),
                "isize" => int(self.pointer * 8, true),
                "bool" => Layout { size: 1, align: 1, kind: Kind::Bool },
                other => bail!("primitive {other} has no C layout here"),
            });
        }
        if let Some(a) = ty.get("array") {
            let inner = self.layout(&a["type"])?;
            let len: u32 = a["len"].as_str().context("array length")?.parse().context("array length is not a number")?;
            let bytes = matches!(inner.kind, Kind::Int { bits: 8, signed: false });
            return Ok(Layout { size: inner.size * len, align: inner.align, kind: if bytes { Kind::Bytes } else { Kind::Struct(format!("[{};{len}]", inner.kind.name())) } });
        }
        if ty.get("raw_pointer").is_some() {
            return Ok(Layout { size: self.pointer, align: self.pointer, kind: Kind::Pointer });
        }
        if ty.get("function_pointer").is_some() {
            return Ok(Layout { size: self.pointer, align: self.pointer, kind: Kind::Function });
        }
        if let Some(path) = ty.get("resolved_path") {
            let name = path["path"].as_str().unwrap_or_default();
            let short = name.rsplit("::").next().unwrap_or(name);
            return Ok(match short {
                "Option" => {
                    // Option<fn> and Option<&T> are one pointer
                    let inner = &path["args"]["angle_bracketed"]["args"][0]["type"];
                    if inner.get("function_pointer").is_some() {
                        Layout { size: self.pointer, align: self.pointer, kind: Kind::Function }
                    } else {
                        Layout { size: self.pointer, align: self.pointer, kind: Kind::Pointer }
                    }
                }
                "c_int" => int(32, true),
                "c_uint" => int(32, false),
                "c_char" | "c_schar" => int(8, true),
                "c_uchar" => int(8, false),
                "c_short" => int(16, true),
                "c_ushort" => int(16, false),
                "c_long" => int(self.pointer * 8, true),
                "c_ulong" => int(self.pointer * 8, false),
                "c_longlong" => int(64, true),
                "c_ulonglong" => int(64, false),
                _ => {
                    let id = path["id"].as_u64().ok_or_else(|| anyhow!("{name} has no id"))?.to_string();
                    self.struct_of(&id)?
                }
            });
        }
        bail!("unsupported type in a repr(C) struct: {ty}")
    }

    fn params(&self, ty: &Value) -> Vec<Param> {
        let sig = ty
            .pointer("/function_pointer/sig")
            .or_else(|| ty.pointer("/resolved_path/args/angle_bracketed/args/0/type/function_pointer/sig"));
        let Some(inputs) = sig.and_then(|s| s.get("inputs")).and_then(Value::as_array) else {
            return Vec::new();
        };
        inputs
            .iter()
            .filter_map(|input| {
                let name = input[0].as_str()?.to_owned();
                let ty = &input[1];
                if let Some(p) = ty.get("raw_pointer") {
                    let target = p["type"]["resolved_path"]["path"]
                        .as_str()
                        .or_else(|| p["type"]["primitive"].as_str())
                        .unwrap_or("?");
                    let target = target.rsplit("::").next().unwrap_or(target).to_owned();
                    let role = if name == "ctx" { "ctx" } else if p["is_mutable"].as_bool() == Some(true) { "out" } else { "in" };
                    return Some(Param { name, role, target });
                }
                let target = ty["primitive"].as_str().or_else(|| ty["resolved_path"]["path"].as_str()).unwrap_or("?").to_owned();
                Some(Param { name, role: "value", target })
            })
            .collect()
    }
}

/// The C name cbindgen gives a Rust type with the `xip_` prefix rule of `cbindgen.toml` (`WifiIntent` -> `xip_wifi_intent`).
pub fn c_name(rust: &str, prefix: &str) -> String {
    let mut out = String::from(prefix);
    for (i, ch) in rust.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}
