//! Application configuration for mesh-init services.
//!
//! Supports TOML config files with mesh-init extensions:
//! - Service names are derived from the `.toml` filename.
//! - `Type = "oneshot"` services are not restarted after exit.
//! - `[Socket]` configs define FDs to listen on; accept triggers service start.
//! - Resource limits map to cgroup v2 knobs (memory.low/high/max, cpu.weight).

use std::path::Path;

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
    info!("Loading config from {}", path.display());
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
            debug!("Config directory {} does not exist, skipping", dir);
            continue;
        }

        let entries = match std::fs::read_dir(dir_path) {
            Ok(entries) => entries,
            Err(e) => {
                warn!("Failed to read config directory {}: {}", dir, e);
                continue;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                match load_app_config(&path) {
                    Ok(config) => {
                        info!("Loaded config for service '{}'", config.name);
                        configs.push(config);
                    }
                    Err(e) => {
                        warn!("Failed to parse config {}: {}", path.display(), e);
                    }
                }
            }
        }
    }

    configs
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
