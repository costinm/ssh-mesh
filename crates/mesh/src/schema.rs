//! Shared schema loading for mesh services.
//!
//! Service-specific catalogs can be embedded by callers and extended with
//! files from `MESH_SCHEMA_FILES` or `MESH_SCHEMA_DIR`.

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use std::{fs, path::PathBuf};

pub fn load_json<T: DeserializeOwned>(embedded: Option<&str>) -> Result<Vec<T>> {
    let mut values = Vec::new();
    if let Some(contents) = embedded {
        values.push(serde_json::from_str(contents).context("parse embedded schema")?);
    }
    for path in configured_files() {
        let contents =
            fs::read_to_string(&path).with_context(|| format!("read schema {}", path.display()))?;
        values.push(
            serde_json::from_str(&contents)
                .with_context(|| format!("parse schema {}", path.display()))?,
        );
    }
    Ok(values)
}

pub fn configured_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    let value = std::env::var("MESH_SCHEMA_FILES").or_else(|_| std::env::var("LMESH_SCHEMA_FILES"));
    if let Ok(value) = value {
        files.extend(
            value
                .split(':')
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
        );
    }
    let dir = std::env::var("MESH_SCHEMA_DIR")
        .or_else(|_| std::env::var("LMESH_SCHEMA_DIR"))
        .unwrap_or_else(|_| "/etc/dmesh/lmesh/schemas".to_owned());
    if let Ok(entries) = fs::read_dir(dir) {
        files.extend(
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json")),
        );
    }
    files
}
