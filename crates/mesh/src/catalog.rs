//! Client-owned schema catalog discovery and process-lifetime caching.
//!
//! A service catalog is a set of MCP-style tool descriptors (`tools.json`
//! shape: a JSON array of tools, or an object with a `tools` array). The
//! resolver assembles one catalog per service from every JSON file found in
//! the standard schema directories, searched in priority order:
//!
//! 1. `$MESH_SCHEMA_DIR/<service>/` when `MESH_SCHEMA_DIR` is set, plus its
//!    `VERSION` subdirectory with the highest numeric name;
//! 2. `$HOME/.cache/schemas/<service>/` — the default cache that projects
//!    publish generated catalogs into, plus its highest numeric `VERSION`
//!    subdirectory;
//! 3. installed packages: `/opt/PACKAGE/etc/schemas/<service>/<VERSION>` and
//!    `$HOME/opt/PACKAGE/etc/schemas/<service>/<VERSION>`; every package is
//!    searched and the highest numeric `VERSION` wins;
//! 4. `/opt/<service>/etc/schemas/`, `$HOME/opt/<service>/etc/schemas/` and
//!    `$HOME/etc/schemas/` — the direct-file package and user layout.
//!
//! Within one directory, files load in sorted file-name order. A tool name
//! that appears in more than one file keeps the definition from the
//! higher-priority location, so a user file can extend but not shadow a
//! packaged catalog. JSON Schema files (top-level objects with `$schema`)
//! are inspection artifacts: they are skipped, not parsed as catalogs.
//!
//! The ssh-mesh admin gateway serves the same catalog for operator
//! discovery: `GET /_m/mesh/services` lists the registered services and
//! `GET /_m/mesh/services/<service>/tools` returns the catalog, where
//! `?view=all` includes every entry and the default view shows only tools
//! whose `x-ui-visibility` is `default` or unset. The visibility value is
//! presentation metadata only: catalog methods remain callable through the
//! policy-controlled record and named-call endpoints.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    ffi::OsString,
    path::{Component, Path, PathBuf},
    sync::{Arc, OnceLock, RwLock},
    time::SystemTime,
};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Map, Value, json};

use crate::tagged::TaggedSchema;

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileStamp {
    path: PathBuf,
    modified: Option<SystemTime>,
    len: u64,
}

impl FileStamp {
    /// Capture file size and modification timestamp. Note: a same-size edit within
    /// a single filesystem timestamp tick keeps the same stamp and is not reloaded,
    /// which is an acceptable trade-off to avoid hashing every file on each lookup.
    fn of(path: &Path) -> Option<Self> {
        let meta = std::fs::metadata(path).ok()?;
        Some(Self {
            path: path.to_path_buf(),
            modified: meta.modified().ok(),
            len: meta.len(),
        })
    }
}

/// One parsed catalog together with the source used to load it.
#[derive(Debug)]
pub struct ResolvedCatalog {
    pub component: String,
    pub path: PathBuf,
    pub tools: Arc<Value>,
    pub catalog: Arc<TaggedSchema>,
}

#[derive(Clone)]
struct CachedCatalog {
    resolved: Arc<ResolvedCatalog>,
    stamps: Vec<Option<FileStamp>>,
}

/// Lazy resolver shared by general clients and mesh gateway implementations.
///
/// Successful parses remain cached while underlying schema files keep the same
/// modification time and size. Updating, adding, or replacing a schema file
/// reloads it on the next access without restarting the gateway. If an in-place
/// edit leaves a file temporarily unreadable or malformed, the last valid
/// cached catalog is retained until a valid replacement lands.
#[derive(Clone, Default)]
pub struct CatalogResolver {
    cache: Arc<RwLock<HashMap<(String, Vec<PathBuf>), CachedCatalog>>>,
}

impl CatalogResolver {
    /// Resolve a required installed catalog using the standard search path.
    pub fn require(&self, component: &str) -> Result<Arc<ResolvedCatalog>> {
        self.resolve(component).ok_or_else(|| {
            anyhow!(
                "no {component} catalog found; install a .cbor or .json schema under \
                 $HOME/.cache/schemas/{component}/, /opt/PACKAGE/etc/schemas/{component}/VERSION, \
                 $HOME/opt/PACKAGE/etc/schemas/{component}/VERSION, /opt/{component}/etc/schemas, \
                 $HOME/opt/{component}/etc/schemas, or $HOME/etc/schemas, \
                 or set MESH_SCHEMA_DIR/MESH_TOOLS"
            )
        })?
    }
    /// Resolve a component using the standard client-side schema locations.
    ///
    /// `MESH_TOOLS` is an exact override. If it is set, failure to load that
    /// file is an error rather than permission to silently select another
    /// catalog. Other locations are searched in order and may be absent.
    pub fn resolve(&self, component: &str) -> Option<Result<Arc<ResolvedCatalog>>> {
        self.resolve_with(component, |key| std::env::var_os(key))
    }

    fn resolve_with<F>(&self, component: &str, mut env: F) -> Option<Result<Arc<ResolvedCatalog>>>
    where
        F: FnMut(&str) -> Option<OsString>,
    {
        if let Err(error) = validate_component(component) {
            return Some(Err(error));
        }

        if let Some(path) = env("MESH_TOOLS") {
            return Some(self.load_path(component, PathBuf::from(path)));
        }

        let files = catalog_files_with(component, env);
        if files.is_empty() {
            return None;
        }
        Some(self.load_files(component, files))
    }

    /// Load and cache one explicit catalog path.
    pub fn load_path(
        &self,
        component: &str,
        path: impl Into<PathBuf>,
    ) -> Result<Arc<ResolvedCatalog>> {
        self.load_files(component, vec![path.into()])
    }

    /// Load and cache the union of several catalog files, in priority order.
    pub fn load_files(&self, component: &str, files: Vec<PathBuf>) -> Result<Arc<ResolvedCatalog>> {
        validate_component(component)?;
        let key = (component.to_owned(), files.clone());
        let raw_stamps: Vec<Option<FileStamp>> = files.iter().map(|p| FileStamp::of(p)).collect();
        let existing = self
            .cache
            .read()
            .expect("schema catalog lock poisoned")
            .get(&key)
            .cloned();
        if let Some(cached) = &existing
            && cached.stamps == raw_stamps
        {
            return Ok(cached.resolved.clone());
        }

        match parse_catalog_files(component, &files) {
            Ok(resolved) => {
                let resolved = Arc::new(resolved);
                let mut cache = self.cache.write().expect("schema catalog lock poisoned");
                cache.insert(
                    key,
                    CachedCatalog {
                        resolved: resolved.clone(),
                        stamps: raw_stamps,
                    },
                );
                Ok(resolved)
            }
            Err(error) => {
                if let Some(cached) = existing {
                    tracing::warn!(
                        component,
                        error = %format!("{error:#}"),
                        "failed to reload schema catalog; retaining cached catalog"
                    );
                    // Record the attempted stamps so we do not re-read and re-parse
                    // the same broken file revision on every subsequent call.
                    let mut cache = self.cache.write().expect("schema catalog lock poisoned");
                    cache.insert(
                        key,
                        CachedCatalog {
                            resolved: cached.resolved.clone(),
                            stamps: raw_stamps,
                        },
                    );
                    return Ok(cached.resolved);
                }
                Err(error)
            }
        }
    }
}

fn parse_catalog_files(component: &str, files: &[PathBuf]) -> Result<ResolvedCatalog> {
    let mut merged_tools: Vec<Value> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut merged_schema = TaggedSchema::default();

    for path in files {
        let is_cbor = path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("cbor"));
        let value: Value = if is_cbor {
            let bytes = std::fs::read(path)
                .with_context(|| format!("read binary schema catalog {}", path.display()))?;
            crate::cbor::decode_value_bytes(&bytes)
                .with_context(|| format!("decode binary schema catalog {}", path.display()))?
        } else {
            let contents = std::fs::read_to_string(path)
                .with_context(|| format!("read schema catalog {}", path.display()))?;
            serde_json::from_str(&contents)
                .with_context(|| format!("parse schema catalog {}", path.display()))?
        };
        // JSON Schema files (the full-fidelity `schema.json` artifacts)
        // are not tool catalogs; they are inspection artifacts, skipped.
        if value.get("$schema").is_some() {
            continue;
        }
        let (file_tools, file_schema) =
            if value.get("format").and_then(Value::as_str) == Some("mesh-api/1") {
                let tools = tools_from_api_json(&value)
                    .with_context(|| format!("parse {} mesh-api/1 catalog", path.display()))?;
                let schema = TaggedSchema::from_tools_json(&Value::Array(tools.clone()))
                    .with_context(|| format!("parse {} mesh-api/1 catalog", path.display()))?;
                (tools, schema)
            } else {
                let tools = value
                    .as_array()
                    .cloned()
                    .or_else(|| value.get("tools").and_then(Value::as_array).cloned())
                    .with_context(|| {
                        format!(
                            "{} is not a schema catalog \
                             (mesh-api/1, tools array, or object with tools)",
                            path.display()
                        )
                    })?;
                let schema = TaggedSchema::from_tools_json(&Value::Array(tools.clone()))
                    .with_context(|| format!("parse {} tools catalog", path.display()))?;
                (tools, schema)
            };
        merged_schema.extend_missing(file_schema);
        for tool in file_tools {
            if let Some(name) = tool.get("name").and_then(Value::as_str) {
                if !seen.insert(name.to_owned()) {
                    continue;
                }
            }
            merged_tools.push(tool);
        }
    }
    Ok(ResolvedCatalog {
        component: component.to_owned(),
        path: files
            .first()
            .cloned()
            .expect("resolve() guarantees at least one file"),
        tools: Arc::new(Value::Array(merged_tools)),
        catalog: Arc::new(merged_schema),
    })
}

/// Project `mesh-api/1` (`api.json` / `api.cbor`) into the tool descriptor array
/// served by HTTP `/tools` and CLI `help` surfaces.
pub fn tools_from_api_json(api: &Value) -> Result<Vec<Value>> {
    let format = api
        .get("format")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("api catalog missing format"))?;
    if format != "mesh-api/1" {
        bail!("unsupported api catalog format {format:?}");
    }
    let mut comp_ids: BTreeMap<&str, u64> = BTreeMap::new();
    if let Some(comps) = api.get("components").and_then(Value::as_array) {
        for c in comps {
            if let (Some(name), Some(idx)) = (
                c.get("name").and_then(Value::as_str),
                c.get("index").and_then(Value::as_u64),
            ) {
                comp_ids.insert(name, idx);
            }
        }
    }
    let mut records: BTreeMap<&str, &[Value]> = BTreeMap::new();
    let mut enums: BTreeMap<&str, Vec<(String, u64)>> = BTreeMap::new();
    if let Some(types) = api.get("types").and_then(Value::as_array) {
        for ty in types {
            let Some(kind) = ty.get("kind").and_then(Value::as_str) else {
                continue;
            };
            let Some(name) = ty.get("name").and_then(Value::as_str) else {
                continue;
            };
            match kind {
                "record" | "row" => {
                    if let Some(fields) = ty.get("fields").and_then(Value::as_array) {
                        records.insert(name, fields.as_slice());
                    }
                }
                "enum" => {
                    if let Some(vals) = ty.get("values").and_then(Value::as_array) {
                        let pairs = vals
                            .iter()
                            .filter_map(|v| {
                                Some((
                                    v.get("name")?.as_str()?.to_owned(),
                                    v.get("value")?.as_u64()?,
                                ))
                            })
                            .collect();
                        enums.insert(name, pairs);
                    }
                }
                _ => {}
            }
        }
    }

    let shape_to_schema = |shape: Option<&Value>| -> Value {
        let mut properties = Map::new();
        let mut required = Vec::new();
        if let Some(shape) = shape {
            let fields = if let Some(tname) = shape.get("type").and_then(Value::as_str) {
                records.get(tname).copied()
            } else {
                shape
                    .get("fields")
                    .and_then(Value::as_array)
                    .map(Vec::as_slice)
            };
            if let Some(fields) = fields {
                for f in fields {
                    let Some(fname) = f.get("name").and_then(Value::as_str) else {
                        continue;
                    };
                    let Some(tag) = f.get("tag").and_then(Value::as_u64) else {
                        continue;
                    };
                    let raw_type = f.get("type").and_then(Value::as_str).unwrap_or("");
                    let ftype = if raw_type.is_empty() {
                        "string"
                    } else {
                        raw_type
                    };
                    let mut prop = Map::new();
                    prop.insert(
                        "type".to_owned(),
                        Value::String(api_json_type(ftype).to_owned()),
                    );
                    prop.insert("x-protobuf-index".to_owned(), Value::from(tag));
                    if !raw_type.is_empty() {
                        prop.insert(
                            "x-protobuf-type".to_owned(),
                            Value::String(raw_type.to_owned()),
                        );
                    }
                    if let Some(enum_vals) = enums.get(ftype) {
                        prop.insert(
                            "enum".to_owned(),
                            Value::Array(
                                enum_vals
                                    .iter()
                                    .map(|(n, _)| Value::String(n.clone()))
                                    .collect(),
                            ),
                        );
                        let mut val_map = Map::new();
                        for (n, v) in enum_vals {
                            val_map.insert(n.clone(), Value::from(*v));
                        }
                        prop.insert(
                            "x-mesh-cbor-type".to_owned(),
                            Value::String("enum".to_owned()),
                        );
                        prop.insert("x-mesh-values".to_owned(), Value::Object(val_map));
                    }
                    if let Some(desc) = f
                        .get("description")
                        .and_then(Value::as_str)
                        .filter(|d| !d.is_empty())
                    {
                        prop.insert("description".to_owned(), Value::String(desc.to_owned()));
                    }
                    if let Some(def) = f.get("default") {
                        prop.insert("default".to_owned(), def.clone());
                    }
                    if let Some(max) = f.get("max") {
                        prop.insert("x-max".to_owned(), max.clone());
                    }
                    if f.get("required").and_then(Value::as_bool) == Some(true) {
                        required.push(Value::String(fname.to_owned()));
                    }
                    properties.insert(fname.to_owned(), Value::Object(prop));
                }
            }
        }
        let mut out = json!({"type": "object", "properties": properties, "required": required});
        if let Some(max) = shape.and_then(|s| s.get("max_encoded_size")) {
            out["x-max-encoded-size"] = max.clone();
        }
        out
    };

    let methods = api
        .get("methods")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("api catalog missing methods array"))?;
    let mut tools = Vec::new();
    for m in methods {
        if m.get("visibility")
            .and_then(Value::as_str)
            .is_some_and(|v| v != "public")
        {
            continue;
        }
        let Some(name) = m.get("name").and_then(Value::as_str) else {
            continue;
        };
        let (default_comp, default_meth) = name.split_once('.').unwrap_or(("", name));
        let comp = m
            .get("component")
            .and_then(Value::as_str)
            .unwrap_or(default_comp);
        let meth = m
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or(default_meth);
        let mut tool = Map::new();
        tool.insert("name".to_owned(), Value::String(name.to_owned()));
        tool.insert(
            "description".to_owned(),
            Value::String(
                m.get("summary")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            ),
        );
        if let Some(&cidx) = comp_ids.get(comp).filter(|&&v| u32::try_from(v).is_ok()) {
            tool.insert("x-component-index".to_owned(), Value::from(cidx));
        } else if comp != default_comp {
            tool.insert(
                "x-component-index".to_owned(),
                Value::String(comp.to_owned()),
            );
        }
        if let Some(midx) = m
            .get("index")
            .and_then(Value::as_u64)
            .filter(|&v| u32::try_from(v).is_ok())
        {
            tool.insert("x-method-index".to_owned(), Value::from(midx));
        } else if meth != default_meth {
            tool.insert("x-method-index".to_owned(), Value::String(meth.to_owned()));
        }
        for (src, dst) in [
            ("ui", "x-ui-visibility"),
            ("execution", "x-execution"),
            ("recommended_timeout", "x-recommended-timeout"),
            ("access", "x-access"),
            ("tier", "x-tier"),
        ] {
            if let Some(val) = m.get(src) {
                tool.insert(dst.to_owned(), val.clone());
            }
        }
        if let Some(extra) = m.get("x-dmesh-device") {
            tool.insert("x-dmesh-device".to_owned(), extra.clone());
        }
        if let Some(errs) = m.get("errors") {
            tool.insert("x-errors".to_owned(), errs.clone());
        }
        tool.insert("inputSchema".to_owned(), shape_to_schema(m.get("request")));
        tool.insert(
            "outputSchema".to_owned(),
            shape_to_schema(m.get("response")),
        );
        tools.push(Value::Object(tool));
    }
    Ok(tools)
}

fn api_json_type(value_type: &str) -> &'static str {
    if value_type.ends_with("[]") || value_type == "array" {
        return "array";
    }
    if value_type.starts_with("map<") || matches!(value_type, "object" | "encoded") {
        return "object";
    }
    match value_type {
        "bool" => "boolean",
        "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64" => "integer",
        "f32" | "f64" => "number",
        _ => "string",
    }
}

/// Process-wide resolver used by compatibility helpers and gateway registries.
pub fn service_catalog_resolver() -> &'static CatalogResolver {
    static RESOLVER: OnceLock<CatalogResolver> = OnceLock::new();
    RESOLVER.get_or_init(CatalogResolver::default)
}

fn validate_component(component: &str) -> Result<()> {
    let mut parts = Path::new(component).components();
    if component.is_empty()
        || !matches!(parts.next(), Some(Component::Normal(_)))
        || parts.next().is_some()
        || component == "."
        || component == ".."
    {
        bail!("invalid schema component {component:?}");
    }
    Ok(())
}

fn catalog_dirs_with<F>(component: &str, env: &mut F) -> Vec<PathBuf>
where
    F: FnMut(&str) -> Option<OsString>,
{
    let home = env("HOME").map(PathBuf::from);
    let mut dirs = Vec::new();
    if let Some(root) = env("MESH_SCHEMA_DIR") {
        let root = PathBuf::from(root).join(component);
        dirs.push(root.clone());
        dirs.extend(highest_version_dir(&root));
    }
    if let Some(home) = &home {
        let cache = home.join(".cache").join("schemas").join(component);
        dirs.push(cache.clone());
        dirs.extend(highest_version_dir(&cache));
    }
    for base in [
        Some(PathBuf::from("/opt")),
        home.as_ref().map(|h| h.join("opt")),
    ] {
        let Some(base) = base else { continue };
        dirs.extend(best_package_version_dir(&base, component));
    }
    dirs.push(PathBuf::from("/opt").join(component).join("etc/schemas"));
    if let Some(home) = &home {
        dirs.push(
            PathBuf::from(home)
                .join("opt")
                .join(component)
                .join("etc/schemas"),
        );
        dirs.push(PathBuf::from(home).join("etc/schemas"));
    }
    dirs
}

/// The `VERSION` subdirectory of one schema root with the highest numeric name.
fn highest_version_dir(dir: &Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut best: Option<(u64, PathBuf)> = None;
    for entry in entries.flatten() {
        let Ok(version) = entry.file_name().to_string_lossy().parse::<u64>() else {
            continue;
        };
        let path = entry.path();
        if path.is_dir() && best.as_ref().is_none_or(|(v, _)| version > *v) {
            best = Some((version, path));
        }
    }
    best.map(|(_, path)| path)
}

/// `BASE/PACKAGE/etc/schemas/COMPONENT/VERSION`, searching every installed
/// package under `BASE` and keeping only the highest numeric `VERSION`.
fn best_package_version_dir(base: &Path, component: &str) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(base) else {
        return Vec::new();
    };
    let mut best: Option<(u64, PathBuf)> = None;
    for entry in entries.flatten() {
        let package = entry.path();
        if !package.is_dir() {
            continue;
        }
        let dir = highest_version_dir(&package.join("etc").join("schemas").join(component));
        let Some(dir) = dir else { continue };
        let version = dir
            .file_name()
            .and_then(|name| name.to_string_lossy().parse::<u64>().ok())
            .unwrap_or(0);
        if best.as_ref().is_none_or(|(v, _)| version > *v) {
            best = Some((version, dir));
        }
    }
    best.map(|(_, dir)| vec![dir]).unwrap_or_default()
}

fn catalog_files_with<F>(component: &str, env: F) -> Vec<PathBuf>
where
    F: FnMut(&str) -> Option<OsString>,
{
    let mut env = env;
    let mut files = Vec::new();
    for dir in catalog_dirs_with(component, &mut env) {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut dir_files: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.is_file()
                    && path.extension().is_some_and(|ext| {
                        ext.eq_ignore_ascii_case("cbor") || ext.eq_ignore_ascii_case("json")
                    })
            })
            .collect();
        dir_files.sort();
        files.extend(dir_files);
    }
    files
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_dirs_use_schema_root_then_cache_then_opt_then_home() {
        let dirs = catalog_dirs_with("demo", &mut |key| match key {
            "MESH_SCHEMA_DIR" => Some(OsString::from("/schemas")),
            "HOME" => Some(OsString::from("/home/client")),
            _ => None,
        });
        assert_eq!(
            dirs,
            vec![
                PathBuf::from("/schemas/demo"),
                PathBuf::from("/home/client/.cache/schemas/demo"),
                PathBuf::from("/opt/demo/etc/schemas"),
                PathBuf::from("/home/client/opt/demo/etc/schemas"),
                PathBuf::from("/home/client/etc/schemas"),
            ]
        );
    }

    #[test]
    fn catalog_files_scan_all_json_in_priority_order() {
        let temp = tempfile::tempdir().unwrap();
        let opt = temp.path().join("opt");
        let home = temp.path().join("home");
        for dir in [
            opt.join("demo/etc/schemas"),
            home.join("opt/demo/etc/schemas"),
            home.join("etc/schemas"),
        ] {
            std::fs::create_dir_all(&dir).unwrap();
        }
        std::fs::write(opt.join("demo/etc/schemas/zz-late.json"), "[]").unwrap();
        std::fs::write(opt.join("demo/etc/schemas/aa-first.json"), "[]").unwrap();
        std::fs::write(home.join("opt/demo/etc/schemas/extra.json"), "[]").unwrap();
        std::fs::write(home.join("etc/schemas/user.json"), "[]").unwrap();
        std::fs::write(home.join("etc/schemas/notes.txt"), "not json").unwrap();

        let files = catalog_files_with("demo", |key| match key {
            "HOME" => Some(home.as_os_str().to_os_string()),
            _ => None,
        });
        // /opt/demo/etc/schemas does not exist in this temp tree, so only the
        // HOME directories contribute, each in sorted file-name order.
        assert_eq!(
            files,
            vec![
                home.join("opt/demo/etc/schemas/extra.json"),
                home.join("etc/schemas/user.json"),
            ]
        );
    }

    #[test]
    fn versioned_schema_root_keeps_the_highest_numeric_version() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("schemas");
        for version in ["1", "7", "20", "abc"] {
            std::fs::create_dir_all(root.join("demo").join(version)).unwrap();
        }
        std::fs::write(root.join("demo").join("7").join("tools.json"), "[]").unwrap();
        std::fs::write(root.join("demo").join("20").join("tools.json"), "[]").unwrap();
        std::fs::write(root.join("demo").join("direct.json"), "[]").unwrap();
        let files = catalog_files_with("demo", |key| match key {
            "MESH_SCHEMA_DIR" => Some(root.as_os_str().to_os_string()),
            _ => None,
        });
        // Direct files first, then the highest numeric VERSION directory.
        assert_eq!(
            files,
            vec![
                root.join("demo").join("direct.json"),
                root.join("demo").join("20").join("tools.json"),
            ]
        );
    }

    #[test]
    fn package_int_version_search_keeps_the_highest_version() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        for (package, version) in [("dmesh", "3"), ("ssh-mesh", "11"), ("esp-xip-modules", "8")] {
            let pkg_root = home.join("opt").join(package).join("etc/schemas/demo");
            std::fs::create_dir_all(pkg_root.join("7")).unwrap();
            std::fs::create_dir_all(pkg_root.join(version)).unwrap();
            std::fs::write(
                pkg_root.join(version).join("tools.json"),
                format!(
                    "[{{\"name\":\"demo.{package}\",\
                     \"x-component-index\":1,\"x-method-index\":2}}]"
                ),
            )
            .unwrap();
        }
        let resolver = CatalogResolver::default();
        let resolved = resolver
            .resolve_with("demo", |key| match key {
                "HOME" => Some(home.as_os_str().to_os_string()),
                _ => None,
            })
            .unwrap()
            .unwrap();
        // Only the highest numeric VERSION (11, ssh-mesh) contributes.
        assert!(resolved.catalog.method("demo.ssh-mesh").is_some());
        assert!(resolved.catalog.method("demo.dmesh").is_none());
        assert!(resolved.catalog.method("demo.esp-xip-modules").is_none());
    }

    #[test]
    fn json_schema_files_are_skipped_as_inspection_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let schema = temp.path().join("schema.json");
        std::fs::write(
            &schema,
            r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","oneOf":[]}"#,
        )
        .unwrap();
        let tools = temp.path().join("tools.json");
        std::fs::write(
            &tools,
            r#"[{"name":"demo.ping","x-component-index":1,"x-method-index":2}]"#,
        )
        .unwrap();
        let resolver = CatalogResolver::default();
        let resolved = resolver.load_files("demo", vec![schema, tools]).unwrap();
        assert!(resolved.catalog.method("demo.ping").is_some());
    }

    #[test]
    fn component_cannot_escape_schema_root() {
        for component in ["", ".", "..", "../demo", "demo/other", "/demo"] {
            assert!(
                validate_component(component).is_err(),
                "accepted {component:?}"
            );
        }
        assert!(validate_component("mesh-init").is_ok());
    }

    #[test]
    fn successful_catalog_is_cached_by_component_and_path() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("tools.json");
        std::fs::write(
            &path,
            r#"[{"name":"demo.ping","x-component-index":1,"x-method-index":2}]"#,
        )
        .unwrap();
        let resolver = CatalogResolver::default();
        let first = resolver.load_path("demo", &path).unwrap();
        std::fs::write(&path, "not json").unwrap();
        let second = resolver.load_path("demo", &path).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert!(first.catalog.method("demo.ping").is_some());
    }

    #[test]
    fn merged_catalog_keeps_higher_priority_tool_on_name_conflict() {
        let temp = tempfile::tempdir().unwrap();
        let high = temp.path().join("high.json");
        let low = temp.path().join("low.json");
        std::fs::write(
            &high,
            r#"[{"name":"demo.ping","x-component-index":1,"x-method-index":2}]"#,
        )
        .unwrap();
        std::fs::write(
            &low,
            r#"[{"name":"demo.ping","x-component-index":9,"x-method-index":9},
                {"name":"demo.pong","x-component-index":1,"x-method-index":3}]"#,
        )
        .unwrap();
        let resolved = CatalogResolver::default()
            .load_files("demo", vec![high, low])
            .unwrap();
        let methods: Vec<String> = resolved
            .tools
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(methods, vec!["demo.ping", "demo.pong"]);
        assert_eq!(
            resolved.catalog.method("demo.ping").unwrap().method,
            crate::tagged::NameOrTag::Tag(2)
        );
    }

    #[test]
    fn resolve_uses_home_user_schemas_when_system_opt_is_absent() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        std::fs::create_dir_all(home.join("etc/schemas")).unwrap();
        std::fs::write(
            home.join("etc/schemas/lmesh.json"),
            r#"[{"name":"demo.ping","x-component-index":1,"x-method-index":2}]"#,
        )
        .unwrap();
        let resolver = CatalogResolver::default();
        let resolved = resolver
            .resolve_with("demo", |key| match key {
                "HOME" => Some(home.as_os_str().to_os_string()),
                _ => None,
            })
            .unwrap()
            .unwrap();
        assert!(resolved.catalog.method("demo.ping").is_some());
    }

    #[test]
    fn api_json_and_api_cbor_resolve_and_reload_dynamically() {
        let temp = tempfile::tempdir().unwrap();
        let cbor_path = temp.path().join("api.cbor");
        let api_v1 = json!({
            "format": "mesh-api/1",
            "components": [{"name": "demo", "index": 42}],
            "types": [{
                "kind": "enum",
                "name": "Mode",
                "values": [{"name": "fast", "value": 3}]
            }],
            "methods": [{
                "name": "demo.run",
                "component": "demo",
                "method": "run",
                "index": 1,
                "summary": "Run demo",
                "visibility": "public",
                "ui": "default",
                "tier": "core",
                "request": {
                    "fields": [
                        {"tag": 1, "name": "mode", "type": "Mode", "required": true},
                        {"tag": 2, "name": "payload", "type": "bytes"}
                    ]
                },
                "response": {
                    "fields": [
                        {"tag": 7, "name": "elapsed_us", "type": "u64"}
                    ]
                }
            }]
        });
        std::fs::write(
            &cbor_path,
            crate::cbor::encode_value_bytes(&api_v1).unwrap(),
        )
        .unwrap();
        let resolver = CatalogResolver::default();
        let first = resolver.load_path("demo", &cbor_path).unwrap();
        assert_eq!(
            first.catalog.method("demo.run").unwrap().component,
            crate::tagged::NameOrTag::Tag(42)
        );
        let parsed = first
            .catalog
            .parse_argv("demo.run", &["--mode=fast".into(), "--payload=0a0b".into()])
            .unwrap();
        assert_eq!(
            parsed.env.get(&crate::tagged::NameOrTag::Tag(1)),
            Some(&json!(3))
        );
        assert_eq!(
            parsed.env.get(&crate::tagged::NameOrTag::Tag(2)),
            Some(&json!("hex:0a0b"))
        );

        // Update file with an extra method and different length; resolver reloads dynamically.
        let api_v2 = json!({
            "format": "mesh-api/1",
            "components": [{"name": "demo", "index": 42}],
            "types": [],
            "methods": [
                {
                    "name": "demo.run",
                    "component": "demo",
                    "method": "run",
                    "index": 1,
                    "summary": "Run demo",
                    "visibility": "public",
                    "request": {"fields": []},
                    "response": {"fields": []}
                },
                {
                    "name": "demo.stop",
                    "component": "demo",
                    "method": "stop",
                    "index": 2,
                    "summary": "Stop demo",
                    "visibility": "public",
                    "request": {"fields": []},
                    "response": {"fields": []}
                }
            ]
        });
        std::fs::write(
            &cbor_path,
            crate::cbor::encode_value_bytes(&api_v2).unwrap(),
        )
        .unwrap();
        let second = resolver.load_path("demo", &cbor_path).unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        assert!(second.catalog.method("demo.stop").is_some());
    }

    #[test]
    fn invalid_reload_updates_stamps_and_recovers_on_valid_edit() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("tools.json");
        std::fs::write(
            &path,
            r#"[{"name":"demo.ping","x-component-index":1,"x-method-index":2}]"#,
        )
        .unwrap();
        let resolver = CatalogResolver::default();
        let first = resolver.load_path("demo", &path).unwrap();

        std::fs::write(&path, "not json").unwrap();
        let broken_stamp = FileStamp::of(&path);
        let second = resolver.load_path("demo", &path).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        {
            let cache = resolver.cache.read().unwrap();
            let cached = cache.get(&("demo".to_owned(), vec![path.clone()])).unwrap();
            assert_eq!(cached.stamps, vec![broken_stamp.clone()]);
        }

        // Subsequent call sees matching broken stamp and avoids re-parsing until fixed.
        let third = resolver.load_path("demo", &path).unwrap();
        assert!(Arc::ptr_eq(&first, &third));

        // Writing valid JSON with different size/mtime triggers a real reload.
        std::fs::write(
            &path,
            r#"[{"name":"demo.pong","x-component-index":1,"x-method-index":3}]"#,
        )
        .unwrap();
        let fourth = resolver.load_path("demo", &path).unwrap();
        assert!(!Arc::ptr_eq(&first, &fourth));
        assert!(fourth.catalog.method("demo.pong").is_some());
    }
}
