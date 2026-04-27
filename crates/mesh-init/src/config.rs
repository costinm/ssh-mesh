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

// ============================================================================
// Error Types
// ============================================================================

/// Errors from config parsing and loading.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("I/O error reading config: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("Invalid config: {0}")]
    Invalid(String),
}

// ============================================================================
// Configuration Types
// ============================================================================

/// Top-level TOML structure for a service config file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfigFile {
    pub service: ServiceSection,
    #[serde(default)]
    pub resources: ResourceLimits,
    #[serde(default)]
    pub environment: HashMap<String, String>,
    #[serde(default)]
    pub activation: Vec<ActivationConfig>,
}

/// The `[service]` section of a config file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSection {
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    /// Priority for eviction ordering. Lower = more important. Default 500.
    #[serde(default = "default_priority")]
    pub priority: u32,
    /// If true, do not restart after exit.
    #[serde(default)]
    pub oneshot: bool,
    /// OOM score adjustment (-1000 to 1000).
    pub oom_score_adjust: Option<i32>,
}

/// The `[resources]` section — maps to cgroup v2 knobs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// cgroup memory.low — minimum memory guarantee (bytes or human-readable).
    pub memory_low: Option<String>,
    /// cgroup memory.high — throttle threshold.
    pub memory_high: Option<String>,
    /// cgroup memory.max — hard limit.
    pub memory_max: Option<String>,
    /// cgroup cpu.weight (1-10000, default 100).
    pub cpu_weight: Option<u32>,
}

/// A single `[[activation]]` entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ActivationConfig {
    pub port: Option<u16>,
    pub socket: Option<String>,
    #[serde(default)]
    pub wait: bool,
}

/// Parsed, validated application configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct AppConfig {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub env: HashMap<String, String>,
    pub priority: u32,
    pub oneshot: bool,
    pub oom_score_adjust: Option<i32>,
    pub resources: ResolvedResourceLimits,
    pub activation: Vec<ActivationConfig>,
    /// Path to the config file this was loaded from.
    pub source_path: Option<String>,
}

/// Resource limits with human-readable sizes resolved to bytes.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ResolvedResourceLimits {
    pub memory_low: Option<u64>,
    pub memory_high: Option<u64>,
    pub memory_max: Option<u64>,
    pub cpu_weight: Option<u32>,
}

// ============================================================================
// Defaults
// ============================================================================

fn default_priority() -> u32 {
    500
}

// ============================================================================
// Parsing
// ============================================================================

/// Parse a human-readable memory size string into bytes.
///
/// Supports: plain bytes (`"4096"`), kilobytes (`"256K"`), megabytes (`"256M"`),
/// gigabytes (`"2G"`), terabytes (`"1T"`).
pub fn parse_memory_size(s: &str) -> Result<u64, ConfigError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(ConfigError::Invalid("empty memory size".to_string()));
    }

    let (num_str, multiplier) = match s.as_bytes().last() {
        Some(b'K' | b'k') => (&s[..s.len() - 1], 1024u64),
        Some(b'M' | b'm') => (&s[..s.len() - 1], 1024 * 1024),
        Some(b'G' | b'g') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        Some(b'T' | b't') => (&s[..s.len() - 1], 1024 * 1024 * 1024 * 1024),
        _ => (s, 1u64),
    };

    let value: u64 = num_str
        .trim()
        .parse()
        .map_err(|e| ConfigError::Invalid(format!("invalid memory size '{}': {}", s, e)))?;

    Ok(value * multiplier)
}

/// Resolve a `ResourceLimits` (with string sizes) into `ResolvedResourceLimits` (with byte values).
fn resolve_limits(limits: &ResourceLimits) -> Result<ResolvedResourceLimits, ConfigError> {
    Ok(ResolvedResourceLimits {
        memory_low: limits
            .memory_low
            .as_deref()
            .map(parse_memory_size)
            .transpose()?,
        memory_high: limits
            .memory_high
            .as_deref()
            .map(parse_memory_size)
            .transpose()?,
        memory_max: limits
            .memory_max
            .as_deref()
            .map(parse_memory_size)
            .transpose()?,
        cpu_weight: limits.cpu_weight,
    })
}

/// Parse a TOML config string into an `AppConfig`.
pub fn parse_toml(content: &str) -> Result<AppConfig, ConfigError> {
    let file: AppConfigFile = toml::from_str(content)?;
    let resolved = resolve_limits(&file.resources)?;

    if file.service.command.is_empty() {
        return Err(ConfigError::Invalid(
            "service.command must not be empty".to_string(),
        ));
    }

    if let Some(oom) = file.service.oom_score_adjust
        && !(-1000..=1000).contains(&oom)
    {
        return Err(ConfigError::Invalid(format!(
            "oom_score_adjust must be between -1000 and 1000, got {}",
            oom
        )));
    }

    Ok(AppConfig {
        name: file.service.name,
        command: file.service.command,
        args: file.service.args,
        uid: file.service.uid,
        gid: file.service.gid,
        user: file.service.user,
        group: file.service.group,
        env: file.environment,
        priority: file.service.priority,
        oneshot: file.service.oneshot,
        oom_score_adjust: file.service.oom_score_adjust,
        resources: resolved,
        activation: file.activation,
        source_path: None,
    })
}

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
