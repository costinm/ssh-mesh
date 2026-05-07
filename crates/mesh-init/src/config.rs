//! Application configuration for mesh-init services.
//!
//! Supports TOML config files with Android init-like semantics:
//! - Services have a name, command, user/group, priority, and resource limits.
//! - `oneshot` services are not restarted after exit.
//! - Socket configs define FDs to listen on; accept triggers service start.
//! - Resource limits map to cgroup v2 knobs (memory.low/high/max, cpu.weight).

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

pub use mesh::config::*;

/// Load a single config file from disk.
pub fn load_app_config(path: &Path) -> Result<AppConfig, ConfigError> {
    info!("Loading config from {}", path.display());
    let content = std::fs::read_to_string(path)?;
    let mut config = parse_toml(&content)?;
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
[service]
name = "test-svc"
command = "/bin/sleep"
args = ["60"]
"#;
        let config = parse_toml(toml).unwrap();
        assert_eq!(config.name, "test-svc");
        assert_eq!(config.command, "/bin/sleep");
        assert_eq!(config.args, vec!["60"]);
        assert_eq!(config.priority, 500); // default
        assert!(!config.oneshot);
    }

    #[test]
    fn test_parse_toml_full() {
        let toml = r#"
[service]
name = "chrome"
command = "/usr/bin/google-chrome-stable"
args = ["--no-sandbox"]
user = "user1"
group = "user1"
uid = 1000
gid = 1000
priority = 200
oneshot = false
oom_score_adjust = -100

[resources]
memory_low = "256M"
memory_high = "2G"
memory_max = "4G"
cpu_weight = 100

[environment]
DISPLAY = ":0"
HOME = "/home/user1"

[[activation]]
socket = "/run/mesh-init/chrome.sock"
wait = true

[[activation]]
port = 14022
wait = false
"#;
        let config = parse_toml(toml).unwrap();
        assert_eq!(config.name, "chrome");
        assert_eq!(config.uid, Some(1000));
        assert_eq!(config.user.as_deref(), Some("user1"));
        assert_eq!(config.priority, 200);
        assert_eq!(config.oom_score_adjust, Some(-100));
        assert_eq!(config.resources.memory_low, Some(256 * 1024 * 1024));
        assert_eq!(config.resources.memory_high, Some(2 * 1024 * 1024 * 1024));
        assert_eq!(config.resources.memory_max, Some(4 * 1024 * 1024 * 1024));
        assert_eq!(config.resources.cpu_weight, Some(100));
        assert_eq!(config.env.get("DISPLAY").unwrap(), ":0");
        assert_eq!(config.activation.len(), 2);
        assert_eq!(config.activation[0].socket.as_deref(), Some("/run/mesh-init/chrome.sock"));
        assert_eq!(config.activation[0].wait, true);
        assert_eq!(config.activation[1].port, Some(14022));
        assert_eq!(config.activation[1].wait, false);
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
[service]
name = "bad"
command = ""
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn test_invalid_oom_score() {
        let toml = r#"
[service]
name = "bad"
command = "/bin/true"
oom_score_adjust = 2000
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn test_load_configs_directory() {
        let dir = tempfile::tempdir().unwrap();

        // Write a valid config
        let config_path = dir.path().join("test.toml");
        std::fs::write(
            &config_path,
            r#"
[service]
name = "test"
command = "/bin/true"
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
