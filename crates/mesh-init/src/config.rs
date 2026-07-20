//! Application configuration for mesh-init services.
//!
//! Supports TOML config files with mesh-init extensions:
//! - Service names are derived from the `.toml` filename.
//! - `Type = "oneshot"` services are not restarted after exit.
//! - `[Socket]` configs define FDs to listen on; accept triggers service start.
//! - Resource limits map to cgroup v2 knobs (memory.low/high/max, cpu.weight).

use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use tracing::{debug, info, warn};

pub use mesh::config::*;

/// Validate a cgroup scope name.
///
/// Cgroup scope names are used directly in filesystem paths under
/// `/sys/fs/cgroup/mesh.slice/`, so they must not contain path separators or
/// `..` components. This is a stricter check than the general service-name
/// check because cgroup names are also used in kernel paths.
pub fn validate_cgroup_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("cgroup name must not be empty".to_string());
    }
    if name.contains('/') || name.contains('\\') {
        return Err("cgroup name must not contain path separators".to_string());
    }
    if name == "." || name == ".." {
        return Err("cgroup name must not be '.' or '..'".to_string());
    }
    if std::path::Path::new(name)
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        return Err("cgroup name must not contain '..' components".to_string());
    }
    if name.contains('\0') {
        return Err("cgroup name must not contain NUL bytes".to_string());
    }
    Ok(())
}

/// Load a single config file from disk.
pub fn load_app_config(path: &Path) -> Result<AppConfig, ConfigError> {
    info!(path = %path.display(), "loading_config");
    let content = std::fs::read_to_string(path)?;
    let service_name = path.file_stem().and_then(|s| s.to_str());
    let mut config = parse_service(&content, service_name)?;
    config.source_path = Some(path.to_string_lossy().into_owned());
    Ok(config)
}

/// Scan directories for `.toml` config files and load all of them.
///
/// Non-existent directories are silently skipped. Individual parse errors
/// are logged as warnings but do not stop loading of other configs.
pub fn load_system_configs(dirs: &[&str]) -> Vec<AppConfig> {
    let mut configs = Vec::new();

    for dir in dirs {
        let dir_path = Path::new(dir);
        if !dir_path.is_dir() {
            debug!(directory = %dir, "config_directory_missing_skipping");
            continue;
        }

        let entries = match std::fs::read_dir(dir_path) {
            Ok(entries) => entries,
            Err(e) => {
                warn!(directory = %dir, error = %e, "read_config_directory_failed");
                continue;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                match load_app_config(&path) {
                    Ok(config) => {
                        info!(service = %config.name, "service_config_loaded");
                        configs.push(config);
                    }
                    Err(e) => {
                        warn!(path = %path.display(), error = %e, "parse_config_failed");
                    }
                }
            }
        }
    }

    configs
}

/// Resolve core config directories in load order.
///
/// Later directories override earlier ones when the same service name appears
/// more than once.
pub fn core_config_dirs() -> Vec<PathBuf> {
    core_config_dirs_with_context(
        |key| std::env::var_os(key),
        || std::env::current_dir().ok(),
        unsafe { libc::getuid() },
    )
}

fn core_config_dirs_with_context<F, C>(mut env: F, current_dir: C, uid: u32) -> Vec<PathBuf>
where
    F: FnMut(&str) -> Option<std::ffi::OsString>,
    C: FnOnce() -> Option<PathBuf>,
{
    if let Some(dir) = env("MESH_INIT_DIR") {
        return vec![PathBuf::from(dir)];
    }
    if uid == 0 {
        let (home_base, opt_base) = home_opt_bases(&mut env);
        vec![
            opt_base.join("system/etc/mesh-init"),
            home_base.join("system/etc/mesh-init"),
        ]
    } else {
        vec![
            current_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("etc/mesh-init"),
        ]
    }
}

/// Resolve on-demand config candidates for a service in precedence order.
pub fn on_demand_config_candidates(service_name: &str) -> Vec<PathBuf> {
    on_demand_config_candidates_with_context(
        service_name,
        |key| std::env::var_os(key),
        || std::env::current_dir().ok(),
        unsafe { libc::getuid() },
    )
}

fn on_demand_config_candidates_with_context<F, C>(
    service_name: &str,
    mut env: F,
    current_dir: C,
    uid: u32,
) -> Vec<PathBuf>
where
    F: FnMut(&str) -> Option<std::ffi::OsString>,
    C: FnOnce() -> Option<PathBuf>,
{
    if let Some(dir) = env("USER_INIT") {
        return vec![PathBuf::from(dir).join(service_name).join("init.toml")];
    }
    if uid == 0 {
        let (home_base, opt_base) = home_opt_bases(&mut env);
        vec![
            opt_base
                .join(service_name)
                .join("etc/mesh-init")
                .join(format!("{service_name}.toml")),
            home_base
                .join(service_name)
                .join("etc/mesh-init")
                .join(format!("{service_name}.toml")),
        ]
    } else {
        vec![
            current_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("etc/mesh-init")
                .join(format!("{service_name}.toml")),
        ]
    }
}

fn home_opt_bases<F>(env: &mut F) -> (PathBuf, PathBuf)
where
    F: FnMut(&str) -> Option<std::ffi::OsString>,
{
    let mesh_root = env("MESH_HOME").map(PathBuf::from);
    let home_base = env("MESH_HOME_BASE")
        .map(PathBuf::from)
        .or_else(|| mesh_root.as_ref().map(|root| root.join("home")))
        .unwrap_or_else(|| PathBuf::from("/home"));
    let opt_base = env("MESH_OPT_BASE")
        .map(PathBuf::from)
        .or_else(|| mesh_root.as_ref().map(|root| root.join("opt")))
        .unwrap_or_else(|| PathBuf::from("/opt"));
    (home_base, opt_base)
}

/// Return the last existing candidate, so mutable `/home` configs override
/// packaged `/opt` configs.
pub fn select_on_demand_config(service_name: &str) -> Option<PathBuf> {
    on_demand_config_candidates(service_name)
        .into_iter()
        .filter(|path| path.exists())
        .last()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppIdentity {
    pub uid: u32,
    pub gid: u32,
}

/// Resolve or create the root-mode identity for an on-demand app.
pub fn resolve_or_create_app_identity(service_name: &str) -> Result<AppIdentity, ConfigError> {
    if unsafe { libc::getuid() } != 0 {
        return Err(ConfigError::Invalid(
            "app identity allocation requires root".to_string(),
        ));
    }
    if let Err(reason) = mesh::config::validate_service_name(service_name) {
        return Err(ConfigError::Invalid(format!(
            "invalid service name: {reason}"
        )));
    }

    let home = mesh::paths::AppPaths::for_app(service_name).home;
    if home.exists() {
        if !home.is_dir() {
            return Err(ConfigError::Invalid(format!(
                "{} exists but is not a directory",
                home.display()
            )));
        }
        let metadata = std::fs::metadata(&home)?;
        let identity = AppIdentity {
            uid: metadata.uid(),
            gid: metadata.gid(),
        };
        ensure_run_user(identity)?;
        return Ok(identity);
    }

    let mut uidmap = load_uidmap()?;
    let identity = if let Some(identity) = uidmap.get(service_name).copied() {
        identity
    } else {
        let identity = allocate_app_identity(&uidmap)?;
        uidmap.insert(service_name.to_string(), identity);
        save_uidmap(&uidmap)?;
        identity
    };

    std::fs::create_dir_all(&home)?;
    chown_path(&home, identity.uid, identity.gid)?;
    let mut perms = std::fs::metadata(&home)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&home, perms)?;
    ensure_run_user(identity)?;
    Ok(identity)
}

fn uidmap_path() -> PathBuf {
    std::env::var_os("MESH_INIT_UIDMAP")
        .map(PathBuf::from)
        .unwrap_or_else(|| mesh::paths::AppPaths::for_app("system").etc.join("uidmap"))
}

fn uid_range() -> Result<(u32, u32), ConfigError> {
    let min = std::env::var("MESH_INIT_UID_MIN")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(2000);
    let max = std::env::var("MESH_INIT_UID_MAX")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(59999);
    if min > max {
        return Err(ConfigError::Invalid(format!(
            "MESH_INIT_UID_MIN ({min}) must be <= MESH_INIT_UID_MAX ({max})"
        )));
    }
    Ok((min, max))
}

fn load_uidmap() -> Result<BTreeMap<String, AppIdentity>, ConfigError> {
    let path = uidmap_path();
    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => return Err(error.into()),
    };
    let mut entries = BTreeMap::new();
    for (line_no, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let name = parts
            .next()
            .ok_or_else(|| ConfigError::Invalid(format!("invalid uidmap line {}", line_no + 1)))?;
        let uid = parts
            .next()
            .ok_or_else(|| {
                ConfigError::Invalid(format!("missing uid on uidmap line {}", line_no + 1))
            })?
            .parse::<u32>()
            .map_err(|e| {
                ConfigError::Invalid(format!("invalid uid on uidmap line {}: {}", line_no + 1, e))
            })?;
        let gid = parts
            .next()
            .ok_or_else(|| {
                ConfigError::Invalid(format!("missing gid on uidmap line {}", line_no + 1))
            })?
            .parse::<u32>()
            .map_err(|e| {
                ConfigError::Invalid(format!("invalid gid on uidmap line {}: {}", line_no + 1, e))
            })?;
        if parts.next().is_some() {
            return Err(ConfigError::Invalid(format!(
                "too many fields on uidmap line {}",
                line_no + 1
            )));
        }
        if let Err(reason) = mesh::config::validate_service_name(name) {
            return Err(ConfigError::Invalid(format!(
                "invalid uidmap service '{}' on line {}: {}",
                name,
                line_no + 1,
                reason
            )));
        }
        entries.insert(name.to_string(), AppIdentity { uid, gid });
    }
    Ok(entries)
}

fn save_uidmap(entries: &BTreeMap<String, AppIdentity>) -> Result<(), ConfigError> {
    let path = uidmap_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    {
        let mut file = std::fs::File::create(&tmp)?;
        writeln!(file, "# service uid gid")?;
        for (service, identity) in entries {
            writeln!(file, "{} {} {}", service, identity.uid, identity.gid)?;
        }
        file.sync_all()?;
    }
    std::fs::rename(tmp, path)?;
    Ok(())
}

fn allocate_app_identity(
    entries: &BTreeMap<String, AppIdentity>,
) -> Result<AppIdentity, ConfigError> {
    let (min, max) = uid_range()?;
    let mut used = HashSet::from([0]);
    if let Some(uid) = mesh::auth::system_uid() {
        used.insert(uid);
    }
    if let Some(uid) = mesh::auth::trusted_sshd_uid() {
        used.insert(uid);
    }
    if let Some(uid) = mesh::auth::ssh_mesh_uid() {
        used.insert(uid);
    }
    for identity in entries.values() {
        used.insert(identity.uid);
        used.insert(identity.gid);
    }
    for id in min..=max {
        if !used.contains(&id) {
            return Ok(AppIdentity { uid: id, gid: id });
        }
    }
    Err(ConfigError::Invalid(format!(
        "no free UID/GID in range {min}..={max}"
    )))
}

fn ensure_run_user(identity: AppIdentity) -> Result<(), ConfigError> {
    let path = run_user_base().join(identity.uid.to_string());
    std::fs::create_dir_all(&path)?;
    chown_path(&path, identity.uid, identity.gid)?;
    let mut perms = std::fs::metadata(&path)?.permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

fn run_user_base() -> PathBuf {
    std::env::var_os("MESH_RUN_USER_BASE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/user"))
}

fn chown_path(path: &Path, uid: u32, gid: u32) -> Result<(), ConfigError> {
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| {
        ConfigError::Invalid(format!("path contains NUL bytes: {}", path.display()))
    })?;
    if unsafe { libc::chown(path.as_ptr(), uid, gid) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::ffi::OsString;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn env_from<'a>(vars: &'a [(&'a str, &'a str)]) -> impl FnMut(&str) -> Option<OsString> + 'a {
        let map: HashMap<&str, &str> = vars.iter().copied().collect();
        move |key| map.get(key).map(OsString::from)
    }

    #[test]
    fn core_config_dirs_layer_root_opt_then_home() {
        let dirs = core_config_dirs_with_context(env_from(&[]), || None, 0);
        assert_eq!(
            dirs,
            vec![
                std::path::PathBuf::from("/opt/system/etc/mesh-init"),
                std::path::PathBuf::from("/home/system/etc/mesh-init"),
            ]
        );
    }

    #[test]
    fn core_config_dirs_non_root_uses_cwd() {
        let dirs = core_config_dirs_with_context(
            env_from(&[]),
            || Some(std::path::PathBuf::from("/workspace/app")),
            1000,
        );
        assert_eq!(
            dirs,
            vec![std::path::PathBuf::from("/workspace/app/etc/mesh-init")]
        );
    }

    #[test]
    fn core_config_dirs_env_replaces_defaults() {
        let dirs = core_config_dirs_with_context(
            env_from(&[("MESH_INIT_DIR", "/custom/etc")]),
            || Some(std::path::PathBuf::from("/workspace/app")),
            0,
        );
        assert_eq!(dirs, vec![std::path::PathBuf::from("/custom/etc")]);
    }

    #[test]
    fn on_demand_candidates_root_opt_then_home() {
        let dirs = on_demand_config_candidates_with_context("demo", env_from(&[]), || None, 0);
        assert_eq!(
            dirs,
            vec![
                std::path::PathBuf::from("/opt/demo/etc/mesh-init/demo.toml"),
                std::path::PathBuf::from("/home/demo/etc/mesh-init/demo.toml"),
            ]
        );
    }

    #[test]
    fn on_demand_candidates_user_init_replaces_defaults() {
        let dirs = on_demand_config_candidates_with_context(
            "demo",
            env_from(&[("USER_INIT", "/data/mesh")]),
            || None,
            0,
        );
        assert_eq!(
            dirs,
            vec![std::path::PathBuf::from("/data/mesh/demo/init.toml")]
        );
    }

    #[test]
    fn on_demand_candidates_non_root_uses_cwd() {
        let dirs = on_demand_config_candidates_with_context(
            "demo",
            env_from(&[]),
            || Some(std::path::PathBuf::from("/workspace/app")),
            1000,
        );
        assert_eq!(
            dirs,
            vec![std::path::PathBuf::from(
                "/workspace/app/etc/mesh-init/demo.toml"
            )]
        );
    }

    #[test]
    fn uidmap_reuses_existing_identity() {
        if unsafe { libc::getuid() } != 0 {
            return;
        }
        let _guard = env_lock().lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let home_base = tmp.path().join("home");
        let run_user_base = tmp.path().join("run/user");
        let uidmap = home_base.join("system/etc/uidmap");
        std::fs::create_dir_all(uidmap.parent().unwrap()).unwrap();
        std::fs::write(&uidmap, "demo 4242 4242\n").unwrap();
        unsafe {
            std::env::set_var("MESH_HOME_BASE", &home_base);
            std::env::set_var("MESH_RUN_USER_BASE", &run_user_base);
            std::env::set_var("MESH_INIT_UIDMAP", &uidmap);
        }

        let identity = resolve_or_create_app_identity("demo").unwrap();

        unsafe {
            std::env::remove_var("MESH_HOME_BASE");
            std::env::remove_var("MESH_RUN_USER_BASE");
            std::env::remove_var("MESH_INIT_UIDMAP");
        }
        assert_eq!(
            identity,
            AppIdentity {
                uid: 4242,
                gid: 4242
            }
        );
        assert!(home_base.join("demo").is_dir());
        assert!(run_user_base.join("4242").is_dir());
    }

    #[test]
    fn test_parse_toml_basic() {
        let toml = r#"
[Service]
ExecStart = "/bin/sleep 60"
"#;
        let config = parse_service(toml, Some("test-svc")).unwrap();
        assert_eq!(config.name, "test-svc");
        assert_eq!(config.command, "/bin/sleep");
        assert_eq!(config.args, vec!["60"]);
        assert_eq!(config.priority, 1000); // default OOMScoreAdjust=0 equivalent
        assert!(!config.oneshot);
    }

    #[test]
    fn test_parse_toml_full() {
        let toml = r#"
[Service]
ExecStart = "/usr/bin/google-chrome-stable --no-sandbox"
User = "1000"
Group = "1000"
OOMScoreAdjust = -800

[Resources]
MemoryMin = "256M"
MemoryHigh = "2G"
MemoryMax = "4G"
CPUWeight = 100

[Environment]
DISPLAY = ":0"
HOME = "/home/user1"
"#;
        let config = parse_service(toml, Some("chrome")).unwrap();
        assert_eq!(config.name, "chrome");
        assert_eq!(config.uid, Some(1000));
        assert_eq!(config.gid, Some(1000));
        assert_eq!(config.user.as_deref(), Some("1000"));
        assert_eq!(config.group.as_deref(), Some("1000"));
        assert_eq!(config.priority, 200);
        assert_eq!(config.oom_score_adjust, Some(-800));
        assert_eq!(config.resources.memory_low, Some(256 * 1024 * 1024));
        assert_eq!(config.resources.memory_high, Some(2 * 1024 * 1024 * 1024));
        assert_eq!(config.resources.memory_max, Some(4 * 1024 * 1024 * 1024));
        assert_eq!(config.resources.cpu_weight, Some(100));
        assert_eq!(config.env.get("DISPLAY").unwrap(), ":0");
        assert!(config.activation.is_empty());
    }

    #[test]
    fn test_parse_toml_lowercase_resource_aliases() {
        let toml = r#"
[Service]
ExecStart = "/bin/true"

[Resources]
memory_min = "64M"
memory_high = "1G"
memory_max = "2G"
cpu_weight = 200
"#;
        let config = parse_service(toml, Some("lowercase-resources")).unwrap();
        assert_eq!(config.resources.memory_low, Some(64 * 1024 * 1024));
        assert_eq!(config.resources.memory_high, Some(1024 * 1024 * 1024));
        assert_eq!(config.resources.memory_max, Some(2 * 1024 * 1024 * 1024));
        assert_eq!(config.resources.cpu_weight, Some(200));
    }

    #[test]
    fn test_parse_toml_resolves_user_and_primary_group() {
        let toml = r#"
[Service]
ExecStart = "/bin/true"
User = "root"
"#;
        let config = parse_service(toml, Some("root-svc")).unwrap();
        assert_eq!(config.uid, Some(0));
        assert_eq!(config.gid, Some(0));
    }

    #[test]
    fn test_parse_toml_rejects_unknown_user() {
        let toml = r#"
[Service]
ExecStart = "/bin/true"
User = "mesh-init-user-that-should-not-exist"
"#;
        assert!(parse_service(toml, Some("bad-user")).is_err());
    }

    #[test]
    fn test_parse_toml_rejects_removed_mesh_uid_gid() {
        let toml = r#"
[Service]
ExecStart = "/bin/true"
MeshUID = 1000
MeshGID = 1000
"#;
        let err = parse_service(toml, Some("old-identity")).unwrap_err();
        assert!(err.to_string().contains("User=/Group="));
    }

    #[test]
    fn test_parse_all_fields_example() {
        let toml = include_str!("../examples/all-fields.toml");
        let config = parse_service(toml, Some("all-fields")).unwrap();
        assert_eq!(config.name, "all-fields");
        assert_eq!(config.uid, Some(1000));
        assert_eq!(config.gid, Some(1000));
        assert_eq!(config.activation_mode, ServiceActivationMode::Hybrid);
        assert_eq!(config.exec_start_pre, vec!["/bin/true"]);
        assert_eq!(config.exec_start_post, vec!["/bin/true"]);
        assert_eq!(config.exec_stop, vec!["/bin/true"]);
        assert_eq!(config.exec_reload, vec!["/bin/true"]);
        assert_eq!(config.working_directory.as_deref(), Some("/tmp"));
        assert_eq!(config.restart, RestartPolicy::OnFailure);
        assert_eq!(config.restart_sec, 5);
        assert_eq!(config.timeout_start_sec, Some(30));
        assert_eq!(config.timeout_stop_sec, Some(10));
        assert_eq!(config.kill_signal, libc::SIGTERM);
        assert_eq!(config.umask, Some(0o022));
        assert_eq!(config.supplementary_groups, vec![0]);
        assert!(config.no_new_privileges);
        assert_eq!(config.resources.memory_max, Some(512 * 1024 * 1024));
        assert_eq!(config.network.backend, NetworkBackend::MeshTun);
        assert_eq!(config.network.egress_redirect_port, Some(15001));
        assert!(config.auth.is_some());
        assert!(config.schedule.is_some());
        assert!(config.constraints.is_some());
        assert_eq!(config.backoff.max_retries, Some(10));
        assert_eq!(config.trace_tag.as_deref(), Some("example.all-fields"));
    }

    #[test]
    fn test_parse_lmesh_radio_examples() {
        let build = parse_service(
            include_str!("../examples/lmesh-radio-build.toml"),
            Some("lmesh-radio-build"),
        )
        .unwrap();
        assert_eq!(build.name, "lmesh-radio-build");
        assert_eq!(build.user.as_deref(), Some("build"));
        assert!(!build.supplementary_groups.is_empty());
        assert_eq!(
            build.env.get("LMESH_CONTROL_SOCKET").unwrap(),
            "/run/mesh/lmesh-radio-build/mesh.sock"
        );
        assert_eq!(
            build.ambient_capabilities,
            vec!["CAP_NET_ADMIN", "CAP_NET_RAW"]
        );

        let wpa = parse_service(
            include_str!("../examples/wpa-supplicant-nan.toml"),
            Some("wpa-supplicant-nan"),
        )
        .unwrap();
        assert_eq!(wpa.name, "wpa-supplicant-nan");
        assert!(wpa.command.ends_with("wpa_supplicant"));
        assert_eq!(wpa.user.as_deref(), Some("build"));
        assert_eq!(wpa.group.as_deref(), Some("plugdev"));
        assert!(wpa.args.contains(&"-g".to_string()));
        assert!(
            wpa.args
                .contains(&"/run/mesh/wpa-supplicant/global".to_string())
        );
        assert_eq!(
            wpa.ambient_capabilities,
            vec!["CAP_NET_ADMIN", "CAP_NET_RAW"]
        );
    }

    #[test]
    fn test_parse_toml_with_peer() {
        let toml = r#"
[Service]
ExecStart = "/bin/true"

[[Peer]]
uid = 1000

[[Peer]]
uid = 1001
delegate = "*.mesh.local"

[[MeshImpersonation]]
from = "root@example.m"
to = "*"
"#;
        let config = parse_service(toml, Some("auth-svc")).unwrap();
        assert_eq!(config.name, "auth-svc");
        let auth = config.auth.expect("auth should be present");
        assert_eq!(auth.peers.len(), 2);
        assert_eq!(auth.peers[0].uid, Some(1000));
        assert_eq!(auth.peers[1].uid, Some(1001));
        assert_eq!(auth.peers[1].delegate.as_deref(), Some("*.mesh.local"));
        assert_eq!(auth.impersonation.len(), 1);
        assert!(auth.can_impersonate("root@example.m", "root@host3-vm.example.m"));
    }

    #[test]
    fn test_parse_toml_with_hybrid_activation_mode() {
        // A11: MeshActivationSocket must be under the service's run_dir.
        // The test resolves run_dir relative to the test working directory.
        let run_dir = mesh::paths::AppPaths::for_app("hybrid-svc").run_dir("hybrid-svc");
        let socket_path = run_dir.join("control.sock");
        let toml = format!(
            r#"
[Service]
ExecStart = "/bin/true"
MeshActivationMode = "hybrid"
MeshActivationSocket = "{}"
"#,
            socket_path.display()
        );
        let config = parse_service(&toml, Some("hybrid-svc")).unwrap();
        assert_eq!(config.activation_mode, ServiceActivationMode::Hybrid);
        assert_eq!(
            config.activation_socket.as_deref(),
            Some(socket_path.to_string_lossy().as_ref())
        );
    }

    #[test]
    fn test_parse_toml_with_ordered_socket_listeners() {
        let toml = r#"
[Service]
ExecStart = "/bin/true"

[Socket]
Accept = false

[[Socket.Listen]]
Type = "stream"
Address = "127.0.0.1:14022"
Name = "ssh"

[[Socket.Listen]]
Type = "stream"
Address = "/run/example/control.sock"
Name = "control"

[[Socket.Listen]]
Type = "datagram"
Address = "127.0.0.1:14023"
Name = "events"

[[Socket.Listen]]
Type = "stream"
Address = "vsock::5000"
Name = "vsock"
"#;
        let config = parse_service(toml, Some("ordered-svc")).unwrap();
        assert_eq!(config.activation.len(), 4);

        assert_eq!(config.activation[0].port, Some(14022));
        assert_eq!(config.activation[0].bind.as_deref(), Some("127.0.0.1"));
        assert!(!config.activation[0].datagram);
        assert_eq!(config.activation[0].fd_name.as_deref(), Some("ssh"));

        assert_eq!(
            config.activation[1].socket.as_deref(),
            Some("/run/example/control.sock")
        );
        assert!(!config.activation[1].datagram);
        assert_eq!(config.activation[1].fd_name.as_deref(), Some("control"));

        assert_eq!(config.activation[2].port, Some(14023));
        assert!(config.activation[2].datagram);
        assert_eq!(config.activation[2].fd_name.as_deref(), Some("events"));

        assert_eq!(config.activation[3].vsock_cid, None);
        assert_eq!(config.activation[3].vsock_port, Some(5000));
        assert!(!config.activation[3].datagram);
        assert_eq!(config.activation[3].fd_name.as_deref(), Some("vsock"));
    }

    #[test]
    fn test_parse_toml_with_pasta_network() {
        let toml = r#"
[Service]
ExecStart = "/bin/sleep 60"

[Network]
backend = "pasta"
command = "pasta"
args = ["--config-net", "{pid}"]
"#;
        let config = parse_service(toml, Some("net-svc")).unwrap();
        assert_eq!(config.network.backend, NetworkBackend::Pasta);
        assert_eq!(config.network.command.as_deref(), Some("pasta"));
        assert_eq!(config.network.args, vec!["--config-net", "{pid}"]);
    }

    #[test]
    fn test_parse_toml_with_mesh_tun_network() {
        let toml = r#"
[Service]
ExecStart = "/bin/sleep 60"

[Network]
backend = "mesh-tun"
control_socket = "/tmp/mesh/control.sock"
if_name = "tap0"
address = "10.5.0.2/24"
gateway = "10.5.0.1"
mtu = 65520
default_route = true
egress_redirect_port = 15001
egress_redirect_uid = 1234
"#;
        let config = parse_service(toml, Some("mesh-tun-svc")).unwrap();
        assert_eq!(config.network.backend, NetworkBackend::MeshTun);
        assert_eq!(
            config.network.control_socket.as_deref(),
            Some("/tmp/mesh/control.sock")
        );
        assert_eq!(config.network.if_name.as_deref(), Some("tap0"));
        assert_eq!(config.network.address.as_deref(), Some("10.5.0.2/24"));
        assert_eq!(config.network.gateway.as_deref(), Some("10.5.0.1"));
        assert_eq!(config.network.mtu, Some(65520));
        assert!(config.network.default_route);
        assert_eq!(config.network.egress_redirect_port, Some(15001));
        assert_eq!(config.network.egress_redirect_uid, Some(1234));
    }

    #[test]
    fn test_parse_memory_size() {
        assert_eq!(parse_memory_size("4096").unwrap(), 4096);
        assert_eq!(parse_memory_size("256K").unwrap(), 256 * 1024);
        assert_eq!(parse_memory_size("256M").unwrap(), 256 * 1024 * 1024);
        assert_eq!(parse_memory_size("2G").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_memory_size("1T").unwrap(), 1024 * 1024 * 1024 * 1024);
        // case insensitive
        assert_eq!(parse_memory_size("256m").unwrap(), 256 * 1024 * 1024);
        // with whitespace
        assert_eq!(parse_memory_size(" 100M ").unwrap(), 100 * 1024 * 1024);
    }

    #[test]
    fn test_parse_memory_size_invalid() {
        assert!(parse_memory_size("").is_err());
        assert!(parse_memory_size("abc").is_err());
        assert!(parse_memory_size("M").is_err());
    }

    #[test]
    fn test_invalid_config_empty_command() {
        let toml = r#"
[Service]
ExecStart = ""
"#;
        assert!(parse_service(toml, Some("bad")).is_err());
    }

    #[test]
    fn test_invalid_oom_score() {
        let toml = r#"
[Service]
ExecStart = "/bin/true"
OOMScoreAdjust = 2000
"#;
        assert!(parse_service(toml, Some("bad")).is_err());
    }

    #[test]
    fn test_load_configs_directory() {
        let dir = tempfile::tempdir().unwrap();

        // Write a valid config
        let config_path = dir.path().join("test.toml");
        std::fs::write(
            &config_path,
            r#"
[Service]
ExecStart = "/bin/true"
"#,
        )
        .unwrap();

        // Write a non-toml file (should be skipped)
        std::fs::write(dir.path().join("readme.txt"), "not a config").unwrap();

        let configs = load_system_configs(&[dir.path().to_str().unwrap()]);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].name, "test");
    }

    #[test]
    fn test_load_configs_nonexistent_dir() {
        let configs = load_system_configs(&["/nonexistent/mesh-init-test"]);
        assert!(configs.is_empty());
    }
}
