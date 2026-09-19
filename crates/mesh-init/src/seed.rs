//! First-start population of the mutable mesh-init configuration directory.
//!
//! The ssh-mesh package ships a canonical default set under
//! `share/mesh-init/defaults` (next to the installed binaries). On first start
//! mesh-init copies that set into the mutable configuration directory
//! (`/home/system/etc/mesh-init` when running as root), with these semantics:
//!
//! - missing directories are created;
//! - every default file is copied only when it does not already exist, so
//!   locally edited files are preserved byte-for-byte;
//! - individual files are staged and renamed into place, so a crash cannot
//!   leave a truncated file that later looks initialized;
//! - the `.seeded` completion marker is written only after every default file
//!   is present at the destination, so an interrupted first start is completed
//!   by the next startup;
//! - once the marker exists, startup seeding does nothing: package upgrades
//!   never merge new defaults automatically. Operators preview or copy them
//!   explicitly with `mesh-init seed [--preview]`.
//!
//! Every seeded or skipped file is logged.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

/// Marker file placed in the destination directory once the complete default
/// set has been populated.
pub const SEED_MARKER: &str = ".seeded";

/// Summary of one seeding pass.
#[derive(Debug, Default, Clone)]
pub struct SeedResult {
    /// Files copied from the defaults this pass.
    pub seeded: Vec<PathBuf>,
    /// Destination files that already existed and were left untouched.
    pub skipped: Vec<PathBuf>,
    /// True when the marker already existed before this pass.
    pub already_seeded: bool,
}

/// Resolve the packaged defaults directory.
///
/// `MESH_INIT_DEFAULTS_DIR` overrides the location for tests and unusual
/// layouts. By default the directory is resolved relative to the running
/// executable: `<exe>/../share/mesh-init/defaults`, which matches both the
/// `/opt/ssh-mesh/bin` production layout and the Nix store layout. Returns
/// `None` when no defaults directory exists, in which case seeding is a
/// no-op (development builds without the packaged share tree).
pub fn defaults_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("MESH_INIT_DEFAULTS_DIR") {
        let dir = dir.trim();
        if !dir.is_empty() {
            let path = PathBuf::from(dir);
            if path.is_dir() {
                return Some(path);
            }
            debug!(defaults_dir = %dir, "defaults_dir_env_missing");
            return None;
        }
    }

    let exe = std::env::current_exe().ok()?;
    let share = exe
        .parent()?
        .parent()?
        .join("share")
        .join("mesh-init")
        .join("defaults");
    if share.is_dir() {
        Some(share)
    } else {
        debug!(defaults_dir = %share.display(), "defaults_dir_not_packaged");
        None
    }
}

/// Seed the first mutable configuration directory from the packaged defaults
/// at daemon startup. Root-only: non-root users manage their own config.
pub fn seed_on_startup(config_dirs: &[String]) {
    if unsafe { libc::getuid() } != 0 {
        debug!("seeding_skipped_non_root");
        return;
    }
    if std::env::var("MESH_INIT_SEED")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v.eq_ignore_ascii_case("off") || v.eq_ignore_ascii_case("0")
        })
        .unwrap_or(false)
    {
        info!("seeding_disabled_by_env");
        return;
    }

    let Some(dest) = config_dirs.first() else {
        return;
    };
    let Some(defaults) = defaults_dir() else {
        return;
    };

    match seed_dest(Path::new(dest), &defaults) {
        Ok(result) if result.already_seeded => {}
        Ok(result) => {
            info!(
                dest = %dest,
                seeded = result.seeded.len(),
                skipped = result.skipped.len(),
                "configuration_seeded"
            );
        }
        Err(e) => {
            warn!(dest = %dest, error = %e, "configuration_seed_failed");
        }
    }
}

/// Seed `dest` from `defaults`, idempotently.
///
/// Copies every default file that does not already exist at the destination,
/// then verifies the complete set is present before writing the marker.
pub fn seed_dest(dest: &Path, defaults: &Path) -> Result<SeedResult> {
    let mut result = SeedResult::default();
    let marker = dest.join(SEED_MARKER);
    if marker.exists() {
        debug!(dest = %dest.display(), "seed_marker_present");
        result.already_seeded = true;
        return Ok(result);
    }

    let default_files = collect_files(defaults)?;
    if default_files.is_empty() {
        return Err(anyhow::anyhow!(
            "no default files found under {}",
            defaults.display()
        ));
    }

    fs::create_dir_all(dest).with_context(|| format!("create config dir {}", dest.display()))?;

    for src in &default_files {
        let rel = src
            .strip_prefix(defaults)
            .expect("collect_files returns paths under defaults");
        let target = dest.join(rel);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create dir {}", parent.display()))?;
        }
        if target.exists() {
            debug!(path = %target.display(), "seed_file_skipped");
            result.skipped.push(target);
            continue;
        }
        copy_file_atomic(src, &target)
            .with_context(|| format!("seed {} -> {}", src.display(), target.display()))?;
        info!(path = %target.display(), "seeded_file");
        result.seeded.push(target);
    }

    // Only mark initialization complete when every default file is present.
    // A failed copy leaves the marker unwritten so the next startup retries.
    let missing: Vec<String> = default_files
        .iter()
        .filter_map(|src| {
            let rel = src.strip_prefix(defaults).ok()?;
            let target = dest.join(rel);
            (!target.exists()).then(|| target.display().to_string())
        })
        .collect();
    if !missing.is_empty() {
        return Err(anyhow::anyhow!(
            "seed incomplete, missing: {}",
            missing.join(", ")
        ));
    }

    write_marker(&marker, defaults)?;
    Ok(result)
}

/// List default files that are missing at `dest` (the files `mesh-init seed`
/// would copy). No files are created or modified.
pub fn preview_seed(dest: &Path, defaults: &Path) -> Result<Vec<PathBuf>> {
    let default_files = collect_files(defaults)?;
    let mut missing = Vec::new();
    for src in &default_files {
        let rel = src
            .strip_prefix(defaults)
            .expect("collect_files returns paths under defaults");
        let target = dest.join(rel);
        if !target.exists() {
            missing.push(target);
        }
    }
    Ok(missing)
}

/// Copy missing default files into `dest` and write the marker when complete.
/// Unlike startup seeding this honors an explicit operator request, so it runs
/// even when the marker already exists.
pub fn seed_operator(dest: &Path, defaults: &Path) -> Result<SeedResult> {
    let marker = dest.join(SEED_MARKER);
    let result = seed_dest(dest, defaults)?;
    if !result.already_seeded {
        return Ok(result);
    }
    // The marker exists: copy only missing files, then refresh the marker.
    let default_files = collect_files(defaults)?;
    fs::create_dir_all(dest).with_context(|| format!("create config dir {}", dest.display()))?;
    let mut copied = SeedResult {
        already_seeded: true,
        ..Default::default()
    };
    for src in &default_files {
        let rel = src
            .strip_prefix(defaults)
            .expect("collect_files returns paths under defaults");
        let target = dest.join(rel);
        if target.exists() {
            copied.skipped.push(target);
            continue;
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create dir {}", parent.display()))?;
        }
        copy_file_atomic(src, &target)
            .with_context(|| format!("seed {} -> {}", src.display(), target.display()))?;
        info!(path = %target.display(), "seeded_file");
        copied.seeded.push(target);
    }
    write_marker(&marker, defaults)?;
    Ok(copied)
}

/// Recursively list files under `dir`, sorted for deterministic logging.
fn collect_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries =
            fs::read_dir(&current).with_context(|| format!("read dir {}", current.display()))?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                stack.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

/// Copy `src` to `target` through a sibling temp file so an interrupted copy
/// cannot leave a truncated file at the destination path.
fn copy_file_atomic(src: &Path, target: &Path) -> Result<()> {
    let tmp = sibling_temp_path(target);
    fs::copy(src, &tmp).with_context(|| format!("copy to {}", tmp.display()))?;
    if let Err(rename_error) = fs::rename(&tmp, target) {
        let _ = fs::remove_file(&tmp);
        return Err(anyhow::Error::from(rename_error).context(format!(
            "rename {} -> {}",
            tmp.display(),
            target.display()
        )));
    }
    Ok(())
}

fn sibling_temp_path(target: &Path) -> PathBuf {
    let file_name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    target.with_file_name(format!(".{}.tmp-{}", file_name, std::process::id()))
}

/// Write the `.seeded` marker with the source directory and a timestamp.
fn write_marker(marker: &Path, defaults: &Path) -> Result<()> {
    let content = format!(
        "seeded_from={}\nseeded_at={}\n",
        defaults.display(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    );
    let tmp = sibling_temp_path(marker);
    fs::write(&tmp, content).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, marker).with_context(|| format!("rename {}", marker.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Copy a nested default set and a marker-decorated destination layout.
    fn write_defaults(root: &Path) {
        let dir = root.join("share/mesh-init/defaults");
        fs::create_dir_all(dir.join("extra")).unwrap();
        fs::write(dir.join("ssh-mesh.toml"), "[Service]\nExecStart = \"x\"\n").unwrap();
        fs::write(dir.join("README.md"), "defaults\n").unwrap();
        fs::write(dir.join("extra/nested.toml"), "nested = true\n").unwrap();
    }

    #[test]
    fn seed_populates_missing_directory_completely() {
        let root = TempDir::new().unwrap();
        write_defaults(root.path());
        let defaults = root.path().join("share/mesh-init/defaults");
        let dest = root.path().join("dest");

        let result = seed_dest(&dest, &defaults).unwrap();
        assert_eq!(result.seeded.len(), 3);
        assert!(result.skipped.is_empty());
        assert!(!result.already_seeded);

        assert_eq!(
            fs::read_to_string(dest.join("ssh-mesh.toml")).unwrap(),
            "[Service]\nExecStart = \"x\"\n"
        );
        assert!(dest.join("extra/nested.toml").is_file());
        assert!(dest.join(SEED_MARKER).is_file());
    }

    #[test]
    fn seed_is_idempotent_and_preserves_edits_byte_for_byte() {
        let root = TempDir::new().unwrap();
        write_defaults(root.path());
        let defaults = root.path().join("share/mesh-init/defaults");
        let dest = root.path().join("dest");
        seed_dest(&dest, &defaults).unwrap();

        let edited = "locally edited\n";
        fs::write(dest.join("ssh-mesh.toml"), edited).unwrap();

        let result = seed_dest(&dest, &defaults).unwrap();
        assert!(result.already_seeded);
        assert_eq!(
            fs::read_to_string(dest.join("ssh-mesh.toml")).unwrap(),
            edited
        );
    }

    #[test]
    fn interrupted_seed_completes_on_next_pass_without_premature_marker() {
        let root = TempDir::new().unwrap();
        write_defaults(root.path());
        let defaults = root.path().join("share/mesh-init/defaults");
        let dest = root.path().join("dest");

        // Simulate an interrupted pass: only one file made it to disk.
        fs::create_dir_all(&dest).unwrap();
        fs::write(dest.join("README.md"), "defaults\n").unwrap();
        assert!(!dest.join(SEED_MARKER).exists());

        let result = seed_dest(&dest, &defaults).unwrap();
        assert_eq!(result.seeded.len(), 2);
        assert_eq!(result.skipped.len(), 1);
        assert!(dest.join("ssh-mesh.toml").is_file());
        assert!(dest.join(SEED_MARKER).is_file());
    }

    #[test]
    fn operator_seed_merges_new_defaults_after_marker() {
        let root = TempDir::new().unwrap();
        write_defaults(root.path());
        let defaults = root.path().join("share/mesh-init/defaults");
        let dest = root.path().join("dest");
        seed_dest(&dest, &defaults).unwrap();

        // A package upgrade ships an additional default file.
        fs::write(defaults.join("extra/late.toml"), "late = true\n").unwrap();

        let missing = preview_seed(&dest, &defaults).unwrap();
        assert_eq!(missing, vec![dest.join("extra/late.toml")]);

        let result = seed_operator(&dest, &defaults).unwrap();
        assert!(result.already_seeded);
        assert_eq!(result.seeded, vec![dest.join("extra/late.toml")]);
        assert!(dest.join("extra/late.toml").is_file());
    }

    #[test]
    fn seed_fails_clearly_without_defaults() {
        let root = TempDir::new().unwrap();
        let dest = root.path().join("dest");
        assert!(seed_dest(&dest, &root.path().join("no-such-defaults")).is_err());
        assert!(!dest.exists());
    }
}
