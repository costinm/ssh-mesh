//! XIP hosted component vtable (`*_vtable.rs`) and module glue (`api_gen.rs`) generator.
//!
//! Replaces `esp-xip-modules/tools/gen_vtables.py` using `mesh-api-gen`'s canonical
//! `parse_api_markdown` and `document::scan` parsers.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};

use crate::{ApiField, ApiMethod, document, parse_api_markdown};

/// Options controlling XIP vtable and module glue generation.
#[derive(Clone, Debug, Default)]
pub struct XipVtableOptions {
    /// Emit wire adapter (`Api` + `dispatch`) only; preserve an existing runtime-owned native table.
    pub dispatch_only: bool,
    /// Emit only `API.local.md` methods in the vtable (no remote CBOR methods).
    pub local_only: bool,
    /// Optional subset of remote method names for `--xip-table-methods` or `--xip-methods`.
    pub selected_methods: Option<Vec<String>>,
}

/// Generated XIP artifacts.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct XipVtableOutput {
    /// `*_vtable.rs` (`#[repr(C)] pub struct <Component>`) when `!dispatch_only`.
    pub abi_rs: Option<String>,
    /// Module glue (`Api`, `dispatch`, `Ctx`, `Hosted`, `provide`).
    pub module_rs: String,
}

struct XipMethod {
    number: Option<u32>,
    name: String,
    doc: String,
    request_type: Option<String>,
    response_type: Option<String>,
    request_fields: Vec<ApiField>,
    response_fields: Vec<ApiField>,
    local_params: Vec<String>,
}

struct StructDef {
    fields: BTreeMap<String, String>,
}

#[derive(Clone, Copy)]
enum FieldCodecKind<'a> {
    Bool,
    Uint(&'a str),
    Sint(&'a str),
    Bytes(usize),
}

fn camel(name: &str) -> String {
    name.split(['_', '-'])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => {
                    let mut out = String::new();
                    out.push(first.to_ascii_uppercase());
                    out.push_str(chars.as_str());
                    out
                }
                None => String::new(),
            }
        })
        .collect()
}

fn first_sentence(prose: &str, fallback: &str) -> String {
    let para = prose
        .split("\n\n")
        .map(str::trim)
        .find(|p| !p.is_empty() && !p.starts_with("**") && !p.starts_with("###") && !p.starts_with('|'))
        .unwrap_or(fallback);
    let collapsed: String = para.split_whitespace().collect::<Vec<_>>().join(" ");
    let base = if collapsed.is_empty() { fallback.to_owned() } else { collapsed };
    match base.find(". ") {
        Some(idx) => base[..=idx].to_owned(),
        None => base,
    }
}

fn strip_rust_comments(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let mut block_depth = 0usize;
    let mut in_string = false;
    while i < bytes.len() {
        if block_depth > 0 {
            if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
                block_depth += 1;
                i += 2;
            } else if i + 1 < bytes.len() && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                block_depth -= 1;
                i += 2;
            } else {
                if bytes[i] == b'\n' {
                    out.push('\n');
                }
                i += 1;
            }
            continue;
        }
        if in_string {
            let ch = src[i..].chars().next().unwrap();
            out.push(ch);
            if ch == '\\' && i + 1 < bytes.len() {
                let next = src[i + 1..].chars().next().unwrap();
                out.push(next);
                i += 1 + next.len_utf8();
            } else {
                if ch == '"' {
                    in_string = false;
                }
                i += ch.len_utf8();
            }
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            block_depth += 1;
            i += 2;
            continue;
        }
        let ch = src[i..].chars().next().unwrap();
        if ch == '"' {
            in_string = true;
        }
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Extract `#[repr(C)] pub struct Name { pub field: Type, ... }` definitions from Rust source.
fn parse_repr_c_structs(src: &str) -> BTreeMap<String, StructDef> {
    let clean = strip_rust_comments(src);
    let mut structs = BTreeMap::new();
    let mut pos = 0usize;
    while let Some(rel) = clean[pos..].find("#[repr(C)]") {
        let attr_start = pos + rel + "#[repr(C)]".len();
        let rest = &clean[attr_start..];
        let Some(struct_kw) = rest.find("pub struct ") else {
            pos = attr_start;
            continue;
        };
        let after_kw = &rest[struct_kw + "pub struct ".len()..];
        let name: String = after_kw
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            pos = attr_start;
            continue;
        }
        let Some(brace_rel) = after_kw.find('{') else {
            pos = attr_start;
            continue;
        };
        // Ensure no `;` appears before `{` (tuple/unit struct).
        if after_kw[..brace_rel].contains(';') {
            pos = attr_start + struct_kw + brace_rel;
            continue;
        }
        let body_start = attr_start + struct_kw + "pub struct ".len() + brace_rel + 1;
        let mut depth = 1usize;
        let mut end = body_start;
        for (off, ch) in clean[body_start..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = body_start + off;
                        break;
                    }
                }
                _ => {}
            }
        }
        if depth != 0 {
            break;
        }
        let body = &clean[body_start..end];
        let mut fields = BTreeMap::new();
        for stmt in body.split(',') {
            let trimmed = stmt.trim();
            if let Some(after_pub) = trimmed.strip_prefix("pub ")
                && let Some((fname, ftype)) = after_pub.split_once(':')
            {
                let fname = fname.trim();
                let ftype = ftype.split_whitespace().collect::<Vec<_>>().join(" ");
                if !fname.is_empty() && !ftype.is_empty() {
                    fields.insert(fname.to_owned(), ftype);
                }
            }
        }
        structs.insert(name, StructDef { fields });
        pos = end + 1;
    }
    structs
}

fn parse_local_md(markdown: &str) -> Result<Vec<XipMethod>> {
    let mut out = Vec::new();
    let sections: Vec<&str> = markdown.split("\n## ").collect();
    for (idx, raw_sec) in sections.iter().enumerate() {
        let sec = if idx == 0 {
            match raw_sec.strip_prefix("## ") {
                Some(rest) => rest,
                None => continue,
            }
        } else {
            raw_sec
        };
        let Some((header_line, rest)) = sec.split_once('\n') else {
            continue;
        };
        let header_line = header_line.trim();
        let Some(after_tick) = header_line.strip_prefix('`') else {
            continue;
        };
        let Some((name, after_name)) = after_tick.split_once('`') else {
            bail!("API.local.md: bad method heading: {header_line}");
        };
        let title = after_name
            .trim()
            .strip_prefix('—')
            .or_else(|| after_name.trim().strip_prefix('-'))
            .map(str::trim)
            .unwrap_or("");
        let sig_marker = "**C function:**";
        let sig_start = rest
            .find(sig_marker)
            .with_context(|| format!("API.local.md: local method `{name}` has no `**C function:**`"))?;
        let after_marker = rest[sig_start + sig_marker.len()..].trim_start();
        let after_open_tick = after_marker
            .strip_prefix("`(")
            .with_context(|| format!("API.local.md: local method `{name}` bad C function signature"))?;
        let (sig_inner, _) = after_open_tick
            .split_once(")`")
            .with_context(|| format!("API.local.md: local method `{name}` missing closing `)`"))?;
        let params: Vec<String> = sig_inner
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if params.len() > 5 {
            bail!("API.local.md: `{name}` takes more than five words of arguments");
        }
        let doc = first_sentence(rest, if title.is_empty() { name } else { title });
        out.push(XipMethod {
            number: None,
            name: name.to_owned(),
            doc,
            request_type: None,
            response_type: None,
            request_fields: Vec::new(),
            response_fields: Vec::new(),
            local_params: params,
        });
    }
    Ok(out)
}

fn parse_byte_array_len(rust_ty: &str) -> Option<usize> {
    let inner = rust_ty.strip_prefix('[')?.strip_suffix(']')?;
    let (elem, len_str) = inner.split_once(';')?;
    if elem.trim() != "u8" {
        return None;
    }
    len_str.trim().parse().ok()
}

fn field_codec<'a>(
    type_name: &str,
    field: &'a ApiField,
    struct_def: &StructDef,
) -> Result<FieldCodecKind<'a>> {
    let rt = struct_def.fields.get(&field.name).with_context(|| {
        format!("C type of {type_name} has no field `{}`", field.name)
    })?;
    match field.value_type.as_str() {
        "bytes" => {
            let len = parse_byte_array_len(rt).with_context(|| {
                format!("{type_name}.{}: bytes needs a [u8; N] field, found {rt}", field.name)
            })?;
            Ok(FieldCodecKind::Bytes(len))
        }
        "bool" => {
            if rt != "u8" {
                bail!("{type_name}.{}: bool needs a u8 field, found {rt}", field.name);
            }
            Ok(FieldCodecKind::Bool)
        }
        api @ ("u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64") => {
            if rt != api {
                bail!(
                    "{type_name}.{}: API type {api} does not fit the field type {rt}",
                    field.name
                );
            }
            if api.starts_with('i') {
                Ok(FieldCodecKind::Sint(api))
            } else {
                Ok(FieldCodecKind::Uint(api))
            }
        }
        other => bail!(
            "{type_name}.{}: API type {other} does not fit the field type {rt}",
            field.name
        ),
    }
}

fn collect_param_type_names(methods: &[XipMethod], structs: &BTreeMap<String, StructDef>) -> Vec<String> {
    let mut set = BTreeSet::new();
    for m in methods {
        for param in &m.local_params {
            for token in param.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
                if token.starts_with(|c: char| c.is_ascii_uppercase()) && structs.contains_key(token) {
                    set.insert(token.to_owned());
                }
            }
        }
    }
    set.into_iter().collect()
}

fn render_abi(
    comp_name: &str,
    comp_number: u32,
    methods: &[XipMethod],
    c_types: &BTreeMap<String, String>,
    structs: &BTreeMap<String, StructDef>,
    api_display: &str,
    types_mod: &str,
) -> String {
    let cname = camel(comp_name);
    let mut lines = vec![
        format!("//! The `{comp_name}` component's table ({comp_number}), generated by `mesh-api-gen` from `{api_display}`; do not edit."),
        "//!".to_owned(),
        format!("//! The same table whether the runtime or a module implements the component: `get_component(\"{comp_name}\")` returns it, a module that hosts it"),
        "//! has the runtime hand callers a copy whose functions are thunks (`HOST_TABLE`). Every function takes `ctx` first and returns `OK` or".to_owned(),
        "//! a negative `ERR_*`; a request is read, a response is filled in (set its `size` first). The order of the members is part of the ABI.".to_owned(),
        "use core::ffi::{c_int, c_void};".to_owned(),
        String::new(),
    ];

    let mut imports = BTreeSet::new();
    for m in methods {
        if let Some(req) = &m.request_type {
            imports.insert(c_types[req].clone());
        }
        if let Some(res) = &m.response_type {
            imports.insert(c_types[res].clone());
        }
    }
    for extra in collect_param_type_names(methods, structs) {
        imports.insert(extra);
    }
    if !imports.is_empty() {
        let joined: Vec<String> = imports.into_iter().collect();
        lines.push(format!("use crate::{types_mod}::{{{}}};", joined.join(", ")));
    }
    lines.extend([
        String::new(),
        format!("/// The `{comp_name}` component table."),
        "#[repr(C)]".to_owned(),
        format!("pub struct {cname} {{"),
        "    /// Table version.".to_owned(),
        "    pub version: u32,".to_owned(),
        "    /// `sizeof` this table: members past it do not exist.".to_owned(),
        "    pub size: u32,".to_owned(),
    ]);
    for m in methods {
        let mut args = vec!["ctx: *mut c_void".to_owned()];
        if let Some(req) = &m.request_type {
            args.push(format!("request: *const {}", c_types[req]));
        }
        if let Some(res) = &m.response_type {
            args.push(format!("response: *mut {}", c_types[res]));
        }
        args.extend(m.local_params.iter().cloned());
        if let Some(num) = m.number {
            lines.push(format!("    /// {num}. {}", m.doc));
        } else {
            lines.push(format!("    /// Local only (no CBOR form, no envelope reaches it): {}", m.doc));
        }
        lines.push(format!(
            "    pub {}: Option<unsafe extern \"C\" fn({}) -> c_int>,",
            m.name,
            args.join(", ")
        ));
    }
    lines.push("}".to_owned());
    lines.join("\n") + "\n"
}

fn render_module(
    comp_name: &str,
    comp_number: u32,
    methods: &[XipMethod],
    c_types: &BTreeMap<String, String>,
    structs: &BTreeMap<String, StructDef>,
    api_display: &str,
    dispatch_only: bool,
) -> Result<String> {
    let cname = camel(comp_name);
    let mut lines = Vec::new();
    let has_remote = methods.iter().any(|m| m.number.is_some());
    let has_request = methods.iter().any(|m| m.request_type.is_some());

    let mut ctypes_set = BTreeSet::new();
    for m in methods {
        if let Some(req) = &m.request_type {
            ctypes_set.insert(c_types[req].clone());
        }
        if let Some(res) = &m.response_type {
            ctypes_set.insert(c_types[res].clone());
        }
    }
    for extra in collect_param_type_names(methods, structs) {
        ctypes_set.insert(extra);
    }

    lines.push(format!(
        "//! The glue of the `{comp_name}` component ({comp_number}) for the module that hosts it, generated by `mesh-api-gen` from `{api_display}`; do not edit."
    ));
    lines.push("//!".to_owned());
    lines.push("//! [`Api`] is what the module implements. [`dispatch`] serves a request (a method number and the fields map: the runtime has parsed the".to_owned());
    if dispatch_only {
        lines.push("//! envelope). The existing native table remains runtime-owned.".to_owned());
    } else {
        lines.push("//! envelope) and [`table`] is the module's vtable for other modules, whose functions enter the allocator context of the module (`Ctx`).".to_owned());
    }
    if has_remote {
        lines.push("#![allow(clippy::all, dead_code)]".to_owned());
    } else {
        lines.push("#![allow(clippy::all, dead_code, unused_imports)]".to_owned());
    }
    if !dispatch_only {
        lines.push("use core::ffi::{c_int, c_void};".to_owned());
    }
    if has_remote {
        lines.push("use xip_abi::cbor::Writer;".to_owned());
    }
    if has_request {
        lines.push("use xip_abi::fields as f;".to_owned());
    }
    let mut imports: Vec<String> = if dispatch_only {
        vec!["Hw", "ERR_ARG", "ERR_SIZE", "ERR_UNSUPPORTED"]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect()
    } else {
        vec![cname.clone(), "CallView".into(), "Hw".into(), "Host".into(), "ERR_ARG".into(), "ERR_SIZE".into(), "ERR_UNSUPPORTED".into()]
    };
    imports.extend(ctypes_set);
    lines.push(format!("use xip_abi::{{{}}};", imports.join(", ")));
    lines.push(String::new());

    lines.push(format!("pub const COMPONENT: i32 = {comp_number};"));
    for m in methods {
        if let Some(num) = m.number {
            lines.push(format!("pub const M_{}: i32 = {num};", m.name.to_ascii_uppercase()));
        }
    }
    lines.push(String::new());

    lines.push("/// What the module implements. Every method returns `Err(code)` with a negative `ERR_*`.".to_owned());
    lines.push("pub trait Api {".to_owned());
    for m in methods {
        let mut args = vec!["&mut self".to_owned(), "hw: &Hw".to_owned()];
        if let Some(req) = &m.request_type {
            args.push(format!("request: &{}", c_types[req]));
        }
        if let Some(res) = &m.response_type {
            args.push(format!("response: &mut {}", c_types[res]));
        }
        args.extend(m.local_params.iter().cloned());
        if let Some(num) = m.number {
            lines.push(format!("    /// {num}. {}", m.doc));
        } else {
            lines.push(format!("    /// Local only (reached by `get_component` callers, never by an envelope; the arguments are as given): {}", m.doc));
        }
        lines.push(format!("    fn {}({}) -> Result<(), i32>;", m.name, args.join(", ")));
    }
    lines.push("}".to_owned());
    lines.push(String::new());

    let mut seen_dec = Vec::new();
    let mut seen_enc = Vec::new();
    for m in methods {
        if let Some(req) = &m.request_type
            && !seen_dec.contains(req)
        {
            seen_dec.push(req.clone());
            let ctype = &c_types[req];
            let sf = structs.get(ctype).with_context(|| format!("no struct {ctype} in the types file"))?;
            lines.push(format!("fn decode_{}(fields: &[u8], r: &mut {ctype}) -> Result<(), i32> {{", req.to_ascii_lowercase()));
            for fl in &m.request_fields {
                let kind = field_codec(req, fl, sf)?;
                let tag = fl.index;
                let fname = &fl.name;
                match kind {
                    FieldCodecKind::Bool => {
                        lines.push(format!("    if let Some(v) = f::get_bool(fields, {tag})? {{ r.{fname} = v as u8; }}"));
                    }
                    FieldCodecKind::Uint(rt) => {
                        lines.push(format!("    if let Some(v) = f::get_uint(fields, {tag})? {{ r.{fname} = {rt}::try_from(v).map_err(|_| ERR_ARG)?; }}"));
                    }
                    FieldCodecKind::Sint(rt) => {
                        lines.push(format!("    if let Some(v) = f::get_int(fields, {tag})? {{ r.{fname} = {rt}::try_from(v).map_err(|_| ERR_ARG)?; }}"));
                    }
                    FieldCodecKind::Bytes(n) => {
                        let len_name = format!("{fname}_len");
                        if let Some(lenf) = sf.fields.get(&len_name) {
                            lines.push(format!("    if let Some(v) = f::get_bytes(fields, {tag}, &mut r.{fname})? {{ r.{len_name} = {lenf}::try_from(v).map_err(|_| ERR_ARG)?; }}"));
                        } else {
                            lines.push(format!("    if let Some(v) = f::get_bytes(fields, {tag}, &mut r.{fname})? {{ if v != {n} {{ return Err(ERR_ARG); }} }}"));
                        }
                    }
                }
            }
            lines.push("    Ok(())".to_owned());
            lines.push("}".to_owned());
            lines.push(String::new());
        }
    }

    for m in methods {
        if let Some(res) = &m.response_type
            && !seen_enc.contains(res)
        {
            seen_enc.push(res.clone());
            let ctype = &c_types[res];
            let sf = structs.get(ctype).with_context(|| format!("no struct {ctype} in the types file"))?;
            lines.push(format!("fn encode_{}(r: &{ctype}, out: &mut [u8]) -> Result<usize, i32> {{", res.to_ascii_lowercase()));
            lines.push("    let mut w = Writer::new(out);".to_owned());
            lines.push(format!("    w.map({});", m.response_fields.len()));
            for fl in &m.response_fields {
                let kind = field_codec(res, fl, sf)?;
                let tag = fl.index;
                let fname = &fl.name;
                match kind {
                    FieldCodecKind::Bool => {
                        lines.push(format!("    w.uint({tag}).boolean(r.{fname} != 0);"));
                    }
                    FieldCodecKind::Uint(_) => {
                        lines.push(format!("    w.uint({tag}).uint(r.{fname} as u64);"));
                    }
                    FieldCodecKind::Sint(_) => {
                        lines.push(format!("    w.uint({tag}).int(r.{fname} as i64);"));
                    }
                    FieldCodecKind::Bytes(n) => {
                        let len_name = format!("{fname}_len");
                        if sf.fields.contains_key(&len_name) {
                            lines.push(format!("    w.uint({tag}).bytes(&r.{fname}[..(r.{len_name} as usize).min({n})]);"));
                        } else {
                            lines.push(format!("    w.uint({tag}).bytes(&r.{fname});"));
                        }
                    }
                }
            }
            lines.push("    w.finish().map(|b| b.len()).ok_or(ERR_SIZE)".to_owned());
            lines.push("}".to_owned());
            lines.push(String::new());
        }
    }

    lines.push("/// Serve method `method` with the request `fields`; the response map goes to `out`. Returns its length. An unknown method is `ERR_UNSUPPORTED`.".to_owned());
    lines.push("pub fn dispatch<T: Api>(t: &mut T, hw: &Hw, method: i32, fields: &[u8], out: &mut [u8]) -> Result<usize, i32> {".to_owned());
    if !has_remote {
        lines.push("    let _ = (t, hw, fields, out);".to_owned());
    }
    lines.push("    match method {".to_owned());
    for m in methods {
        if m.number.is_none() {
            continue;
        }
        lines.push(format!("        M_{} => {{", m.name.to_ascii_uppercase()));
        let mut call_args = vec!["hw".to_owned()];
        if let Some(req) = &m.request_type {
            let ctype = &c_types[req];
            lines.push(format!("            let mut request = {ctype}::default();"));
            lines.push(format!("            decode_{}(fields, &mut request)?;", req.to_ascii_lowercase()));
            call_args.push("&request".to_owned());
        }
        if let Some(res) = &m.response_type {
            let ctype = &c_types[res];
            lines.push(format!("            let mut response = {ctype}::default();"));
            call_args.push("&mut response".to_owned());
        }
        lines.push(format!("            t.{}({})?;", m.name, call_args.join(", ")));
        if let Some(res) = &m.response_type {
            lines.push(format!("            encode_{}(&response, out)", res.to_ascii_lowercase()));
        } else {
            lines.push("            let mut w = Writer::new(out);".to_owned());
            lines.push("            w.map(0);".to_owned());
            lines.push("            w.finish().map(|b| b.len()).ok_or(ERR_SIZE)".to_owned());
        }
        lines.push("        }".to_owned());
    }
    lines.push("        _ => Err(ERR_UNSUPPORTED),".to_owned());
    lines.push("    }".to_owned());
    lines.push("}".to_owned());
    lines.push(String::new());

    if dispatch_only {
        return Ok(lines.join("\n") + "\n");
    }

    lines.extend([
        "/// The first argument of every function of the module's table: the host table and the module's state, both valid while the module runs.".to_owned(),
        "#[repr(C)]".to_owned(),
        "pub struct Ctx {".to_owned(),
        "    pub host: *const Host,".to_owned(),
        "    pub state: *mut u8,".to_owned(),
        "}".to_owned(),
        String::new(),
        "/// Run `body` in the allocator context of the module (the runtime's thunk has taken the module's lock).".to_owned(),
        "unsafe fn within<T: Api>(ctx: *mut c_void, body: impl FnOnce(&mut T, &Hw) -> Result<(), i32>) -> c_int {".to_owned(),
        "    let ctx = &*(ctx as *const Ctx);".to_owned(),
        "    let Some(hw) = Hw::new(ctx.host) else { return ERR_ARG };".to_owned(),
        "    let saved = xip_abi::heap::enter(ctx.host);".to_owned(),
        "    let rc = match body(&mut *(ctx.state as *mut T), &hw) { Ok(()) => 0, Err(rc) => rc };".to_owned(),
        "    xip_abi::heap::leave(saved);".to_owned(),
        "    rc".to_owned(),
        "}".to_owned(),
        String::new(),
    ]);

    for m in methods {
        let mut args = vec!["ctx: *mut c_void".to_owned()];
        let mut guard = Vec::new();
        let mut use_args = vec!["hw".to_owned()];
        if let Some(req) = &m.request_type {
            args.push(format!("request: *const {}", c_types[req]));
            guard.push("request".to_owned());
            use_args.push("&*request".to_owned());
        }
        if let Some(res) = &m.response_type {
            args.push(format!("response: *mut {}", c_types[res]));
            guard.push("response".to_owned());
            use_args.push("&mut *response".to_owned());
        }
        for prm in &m.local_params {
            args.push(prm.clone());
            use_args.push(prm.split(':').next().unwrap_or("").trim().to_owned());
        }
        lines.push(format!("unsafe extern \"C\" fn v_{}<T: Api>({}) -> c_int {{", m.name, args.join(", ")));
        if !guard.is_empty() {
            let checks: Vec<String> = guard.iter().map(|g| format!("{g}.is_null()")).collect();
            lines.push(format!("    if {} {{ return ERR_ARG; }}", checks.join(" || ")));
        }
        lines.push(format!("    within::<T>(ctx, |t, hw| t.{}({}))", m.name, use_args.join(", ")));
        lines.push("}".to_owned());
    }

    lines.extend([
        String::new(),
        format!("/// The module's table of the `{comp_name}` component and the context its functions take: a part of the module's state block. The table is built"),
        "/// when the module answers `HOST_TABLE`, not as a constant: the function addresses of a position-independent image (ESP32-C6) exist only at run time.".to_owned(),
        "#[repr(C)]".to_owned(),
        "pub struct Hosted {".to_owned(),
        "    pub ctx: Ctx,".to_owned(),
        format!("    pub table: {cname},"),
        "}".to_owned(),
        "impl Default for Hosted {".to_owned(),
        "    /// All zero: no table yet (the state block of a module starts zeroed).".to_owned(),
        "    fn default() -> Self {".to_owned(),
        "        unsafe { core::mem::zeroed() }".to_owned(),
        "    }".to_owned(),
        "}".to_owned(),
        String::new(),
        "/// Answer `HOST_TABLE` for this component with the module's table, whose functions call `T` in the module's allocator context, and the context".to_owned(),
        "/// they take. `hosted` points into the module's state block (it must stay valid while the module runs) and `state` is that block as `T`.".to_owned(),
        "pub fn provide<T: Api>(hw: &Hw, call: &CallView, hosted: *mut Hosted, state: *mut T) -> i32 {".to_owned(),
        "    unsafe {".to_owned(),
        "        (*hosted).ctx = Ctx { host: hw.as_ptr(), state: state.cast() };".to_owned(),
        format!("        (*hosted).table = {cname} {{"),
        "            version: 1,".to_owned(),
        format!("            size: core::mem::size_of::<{cname}>() as u32,"),
    ]);
    for m in methods {
        lines.push(format!("            {}: Some(v_{}::<T>),", m.name, m.name));
    }
    let schema_const = format!("SCHEMA_{}", comp_name.replace('-', "_").to_ascii_uppercase());
    lines.extend([
        "        };".to_owned(),
        format!("        hw.provide_table(call, core::ptr::addr_of!((*hosted).table).cast(), core::ptr::addr_of_mut!((*hosted).ctx).cast(), xip_abi::schema::{schema_const})"),
        "    }".to_owned(),
        "}".to_owned(),
    ]);

    Ok(lines.join("\n") + "\n")
}

/// Generate XIP vtable (`*_vtable.rs`) and module glue (`api_gen.rs`) from an `API.md` file
/// (plus optional sibling `API.local.md`) and a `#[repr(C)]` types `.rs` file.
pub fn generate_xip_vtable(
    api_path: &Path,
    types_path: &Path,
    options: &XipVtableOptions,
) -> Result<XipVtableOutput> {
    let api_markdown = std::fs::read_to_string(api_path)
        .with_context(|| format!("read {}", api_path.display()))?;
    let types_src = std::fs::read_to_string(types_path)
        .with_context(|| format!("read {}", types_path.display()))?;

    let api_methods: Vec<ApiMethod> = parse_api_markdown(&api_markdown)?;
    let docs = document::scan(&api_markdown)?;

    let first = api_methods
        .first()
        .ok_or_else(|| anyhow!("{}: no component methods found", api_path.display()))?;
    let comp_name = first.component.clone();
    let comp_number = first
        .component_index
        .ok_or_else(|| anyhow!("{}: title must be `# `{comp_name}` API (number)`", api_path.display()))?;

    let mut methods: Vec<XipMethod> = if options.local_only {
        Vec::new()
    } else {
        api_methods
            .into_iter()
            .map(|m| {
                let doc = docs
                    .method_docs
                    .get(&m.id)
                    .map(|p| first_sentence(p, &m.summary))
                    .unwrap_or_else(|| first_sentence("", &m.summary));
                XipMethod {
                    number: m.method_index,
                    name: m.method,
                    doc,
                    request_type: docs.request_types.get(&m.id).cloned(),
                    response_type: docs.response_types.get(&m.id).cloned(),
                    request_fields: m.request.fields,
                    response_fields: m.response.fields,
                    local_params: Vec::new(),
                }
            })
            .collect()
    };

    if let Some(selected) = &options.selected_methods {
        if options.local_only {
            bail!("--xip-local-only cannot combine with --xip-methods / --xip-table-methods");
        }
        let wanted: BTreeSet<&str> = selected.iter().map(String::as_str).collect();
        methods.retain(|m| wanted.contains(m.name.as_str()));
        let found: BTreeSet<&str> = methods.iter().map(|m| m.name.as_str()).collect();
        for w in &wanted {
            if !found.contains(w) {
                bail!("unknown selected method `{w}` in {}", api_path.display());
            }
        }
    }

    if !options.dispatch_only {
        let local_path = api_path.with_file_name("API.local.md");
        if local_path.exists() {
            let local_md = std::fs::read_to_string(&local_path)
                .with_context(|| format!("read {}", local_path.display()))?;
            methods.extend(parse_local_md(&local_md)?);
        }
    }

    for m in &methods {
        if let Some(req) = &m.request_type
            && !docs.c_types.contains_key(req)
        {
            bail!("{}: type `{req}` has no **C type:**", m.name);
        }
        if let Some(res) = &m.response_type
            && !docs.c_types.contains_key(res)
        {
            bail!("{}: type `{res}` has no **C type:**", m.name);
        }
    }

    let structs = parse_repr_c_structs(&types_src);
    let api_display = api_path.to_string_lossy();
    let types_mod = types_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("types");

    let abi_rs = if options.dispatch_only {
        None
    } else {
        Some(render_abi(
            &comp_name,
            comp_number,
            &methods,
            &docs.c_types,
            &structs,
            &api_display,
            types_mod,
        ))
    };
    let module_rs = render_module(
        &comp_name,
        comp_number,
        &methods,
        &docs.c_types,
        &structs,
        &api_display,
        options.dispatch_only,
    )?;

    Ok(XipVtableOutput { abi_rs, module_rs })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_repr_c_structs_ignoring_comments_and_multiline_fields() {
        let src = r#"
// #[repr(C)] pub struct Fake { pub x: u32 }
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BleStart {
    /// doc comment
    pub size: u32,
    pub paired:
        u8,
    pub addr: [u8; 6],
}
"#;
        let structs = parse_repr_c_structs(src);
        let s = structs.get("BleStart").unwrap();
        assert_eq!(s.fields.get("size").map(String::as_str), Some("u32"));
        assert_eq!(s.fields.get("paired").map(String::as_str), Some("u8"));
        assert_eq!(s.fields.get("addr").map(String::as_str), Some("[u8; 6]"));
    }

    #[test]
    fn generates_vtable_and_module_with_local_only_methods() {
        let dir = std::env::temp_dir().join(format!("mesh-api-gen-xip-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let api = dir.join("API.md");
        let local = dir.join("API.local.md");
        let types = dir.join("demo.rs");

        std::fs::write(
            &api,
            r#"# `demo` API (77)

## 1. `ping` — Ping the demo

Send a ping.

**Request:** [PingReq](#pingreq)

**Response:** [PingRes](#pingres)

# Types

## `PingReq`
**C type:** DemoPingReq

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `enabled` | `bool` | Enable flag. |

## `PingRes`
**C type:** DemoPingRes

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `count` | `u32` | Counter. |
"#,
        )
        .unwrap();
        std::fs::write(
            &local,
            "## `peek` — Local peek\n\nLocal only.\n\n**C function:** `(addr: u32, out: *mut u8)`\n",
        )
        .unwrap();
        std::fs::write(
            &types,
            r#"
#[repr(C)]
pub struct DemoPingReq {
    pub size: u32,
    pub enabled: u8,
}
#[repr(C)]
pub struct DemoPingRes {
    pub size: u32,
    pub count: u32,
}
"#,
        )
        .unwrap();

        let out = generate_xip_vtable(&api, &types, &XipVtableOptions::default()).unwrap();
        let abi = out.abi_rs.unwrap();
        assert!(abi.contains("pub struct Demo {"));
        assert!(abi.contains("pub ping: Option<unsafe extern \"C\" fn(ctx: *mut c_void, request: *const DemoPingReq, response: *mut DemoPingRes) -> c_int>,"));
        assert!(abi.contains("pub peek: Option<unsafe extern \"C\" fn(ctx: *mut c_void, addr: u32, out: *mut u8) -> c_int>,"));
        assert!(out.module_rs.contains("pub const COMPONENT: i32 = 77;"));
        assert!(out.module_rs.contains("pub const M_PING: i32 = 1;"));
        assert!(!out.module_rs.contains("M_PEEK"));
        assert!(out.module_rs.contains("fn peek(&mut self, hw: &Hw, addr: u32, out: *mut u8) -> Result<(), i32>;"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
