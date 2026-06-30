use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::auth::{AuthConfig, ImpersonationRule, PeerConfig};

/// Default IP MTU used by mesh-tun managed TAP namespaces.
///
/// 65520 leaves room for IPv4 and TCP headers under the IPv4 65535-byte
/// packet limit while still allowing Linux to send near-maximum TCP segments.
pub const DEFAULT_MESH_TUN_MTU: u32 = 65_520;

// ============================================================================
// Service / Job Unified Config
// ============================================================================

/// Top-level TOML structure for a config file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AppConfigFile {
    #[serde(rename = "Service")]
    pub service: ServiceSection,
    #[serde(default, rename = "Resources")]
    pub resources: ResourceLimits,
    #[serde(default, rename = "Environment")]
    pub environment: HashMap<String, String>,
    #[serde(default, rename = "Network")]
    pub network: NetworkConfig,
    #[serde(default, rename = "Schedule")]
    pub schedule: Option<ScheduleConfig>,
    #[serde(default, rename = "Constraints")]
    pub constraints: Option<ConstraintConfig>,
    #[serde(default, rename = "Backoff")]
    pub backoff: BackoffConfig,
    /// Authorization peer entries. Same shape as standalone `auth.toml`.
    #[serde(default, rename = "Peer")]
    pub peers: Vec<PeerConfig>,
    /// Identity impersonation entries. Same shape as standalone auth.
    #[serde(default, rename = "MeshImpersonation")]
    pub impersonation: Vec<ImpersonationRule>,

    // Job-specific metadata
    #[serde(default = "default_true", rename = "MeshPersisted")]
    pub persisted: bool,
    #[serde(default, rename = "MeshPrefetch")]
    pub prefetch: bool,
    #[serde(default, rename = "MeshSaveResult")]
    pub save_result: bool,
    #[serde(rename = "MeshTraceTag")]
    pub trace_tag: Option<String>,
    #[serde(default, rename = "MeshUserInitiated")]
    pub user_initiated: bool,
    #[serde(default, rename = "MeshExpedited")]
    pub expedited: bool,
    #[serde(rename = "MeshEstimatedDownloadBytes")]
    pub estimated_download_bytes: Option<u64>,
    #[serde(rename = "MeshEstimatedUploadBytes")]
    pub estimated_upload_bytes: Option<u64>,
    #[serde(rename = "MeshMinimumNetworkChunkBytes")]
    pub minimum_network_chunk_bytes: Option<u64>,
}

/// The `[Service]` section of a config file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServiceSection {
    #[serde(rename = "ExecStart")]
    pub exec_start: String,
    /// How mesh-init handles Accept=true socket-unit activations for this
    /// service. `stdio` is classic inetd. `hybrid` starts the service with a
    /// systemd-style JSONL listener first, then forwards accepted connection
    /// FDs to that JSONL socket.
    #[serde(default, rename = "MeshActivationMode")]
    pub activation_mode: ServiceActivationMode,
    /// JSONL Unix socket used by hybrid activation. Defaults to
    /// `/home/<service>/run/<service>/control.sock` when omitted.
    #[serde(rename = "MeshActivationSocket")]
    pub activation_socket: Option<String>,
    #[serde(rename = "User")]
    pub user: Option<String>,
    #[serde(rename = "Group")]
    pub group: Option<String>,
    #[serde(rename = "MeshUID")]
    pub uid: Option<u32>,
    #[serde(rename = "MeshGID")]
    pub gid: Option<u32>,
    /// `Type=oneshot` marks the service as one-shot and disables restart.
    #[serde(rename = "Type")]
    pub service_type: Option<String>,
    /// OOM score adjustment (-1000 to 1000).
    #[serde(rename = "OOMScoreAdjust")]
    pub oom_score_adjust: Option<i32>,
}

/// The `[resources]` section — maps to cgroup v2 knobs.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ResourceLimits {
    pub memory_low: Option<String>,
    pub memory_high: Option<String>,
    pub memory_max: Option<String>,
    pub cpu_weight: Option<u32>,
}

/// Service-level behavior for Accept=true socket activations.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceActivationMode {
    /// Classic inetd: accepted socket becomes child stdin/stdout/stderr.
    #[default]
    Stdio,
    /// Hybrid: service receives its JSONL listener first, then accepted FDs
    /// are sent to that socket with SCM_RIGHTS.
    Hybrid,
}

/// Legacy inline activation entry.
///
/// New configs should use systemd-style `.socket` files. This type remains
/// because mesh-init merges parsed socket units into the same runtime shape.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ActivationConfig {
    pub port: Option<u16>,
    pub socket: Option<String>,
    #[serde(default)]
    pub wait: bool,
    /// Bind address for TCP activation. Defaults to `127.0.0.1` (loopback) to
    /// avoid exposing unauthenticated activation services. Set to `0.0.0.0`
    /// or `::` to listen on all interfaces — only do this with auth configured.
    #[serde(default)]
    pub bind: Option<String>,
    /// ListenDatagram (true) vs ListenStream (false). Maps to SOCK_DGRAM vs
    /// SOCK_STREAM. Datagram activation with Accept=true is not supported.
    #[serde(default)]
    pub datagram: bool,
    /// Socket file permissions (octal, e.g. 0o660) for UDS activation.
    /// Ignored for TCP and when receiving FDs from systemd activation.
    pub socket_mode: Option<u32>,
    /// Socket file owner for UDS activation. Ignored for TCP.
    pub socket_user: Option<String>,
    /// Socket file group for UDS activation. Ignored for TCP.
    pub socket_group: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkBackend {
    #[default]
    None,
    Pasta,
    MeshTun,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkConfig {
    #[serde(default)]
    pub backend: NetworkBackend,
    /// Backend command for sidecars like pasta.
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Control socket for a shared mesh-tun daemon.
    pub control_socket: Option<String>,
    /// Interface name created in the service network namespace.
    pub if_name: Option<String>,
    /// Address assigned to the service side of the TAP, for example `10.5.0.2/24`.
    pub address: Option<String>,
    /// Gateway used for the service default route.
    pub gateway: Option<String>,
    /// MTU for the service-side TAP interface.
    pub mtu: Option<u32>,
    /// Install a default route through the TAP gateway.
    #[serde(default)]
    pub default_route: bool,
    /// Redirect service TCP egress to this in-namespace listener port.
    ///
    /// mesh-tun uses this for an Istio-style fast path: nftables captures TCP
    /// connections at connect time, while TAP remains available for UDP and
    /// any future TCP traffic intentionally excluded from the redirect policy.
    pub egress_redirect_port: Option<u16>,
    /// Optional uid excluded from egress redirect rules.
    pub egress_redirect_uid: Option<u32>,
}

// ============================================================================
// Job-Specific Configuration Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkType {
    #[default]
    None,
    Any,
    Unmetered,
    NotRoaming,
    Cellular,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BackoffPolicy {
    Linear,
    #[default]
    Exponential,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackoffConfig {
    pub initial_secs: u64,
    #[serde(default)]
    pub policy: BackoffPolicy,
    #[serde(default)]
    pub max_retries: Option<u32>,
    /// Hard cap on the computed backoff delay in seconds. Defaults to 24h to
    /// prevent an exponential backoff from scheduling effectively-never after
    /// many failures. Set to override.
    #[serde(default = "default_max_backoff_secs")]
    pub max_secs: u64,
}

fn default_max_backoff_secs() -> u64 {
    24 * 60 * 60
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            initial_secs: 1,
            policy: BackoffPolicy::Exponential,
            max_retries: None,
            max_secs: default_max_backoff_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ScheduleConfig {
    pub periodic_secs: Option<u64>,
    pub flex_secs: Option<u64>,
    pub minimum_latency_secs: Option<u64>,
    pub override_deadline_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ConstraintConfig {
    pub network_type: Option<NetworkType>,
    #[serde(default)]
    pub requires_charging: bool,
    #[serde(default)]
    pub requires_device_idle: bool,
    #[serde(default)]
    pub requires_battery_not_low: bool,
    #[serde(default)]
    pub requires_storage_not_low: bool,
    #[serde(default)]
    pub triggers: Vec<String>,
    pub trigger_max_delay_secs: Option<u64>,
    #[serde(default)]
    pub custom: HashMap<String, bool>,
}

// ============================================================================
// Resolved Config (Used in runtime)
// ============================================================================

/// Parsed, validated unified configuration.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AppConfig {
    // Service base
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
    pub activation_mode: ServiceActivationMode,
    pub activation_socket: Option<String>,
    pub oom_score_adjust: Option<i32>,
    pub resources: ResolvedResourceLimits,
    pub activation: Vec<ActivationConfig>,
    pub network: NetworkConfig,
    pub source_path: Option<String>,
    /// Resolved authorization config from `[[peer]]` entries.
    pub auth: Option<AuthConfig>,

    // Job optional sections
    pub schedule: Option<ScheduleConfig>,
    pub constraints: Option<ConstraintConfig>,
    pub backoff: BackoffConfig,

    // Job metadata
    pub persisted: bool,
    pub prefetch: bool,
    pub save_result: bool,
    pub trace_tag: Option<String>,
    pub user_initiated: bool,
    pub expedited: bool,
    pub estimated_download_bytes: Option<u64>,
    pub estimated_upload_bytes: Option<u64>,
    pub minimum_network_chunk_bytes: Option<u64>,
}

impl AppConfig {
    /// True if this config has schedule or constraints, i.e. it's a job.
    pub fn is_job(&self) -> bool {
        self.schedule.is_some() || self.constraints.is_some()
    }
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

fn default_true() -> bool {
    true
}

// ============================================================================
// Parsing
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("I/O error reading config: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("Invalid config: {0}")]
    Invalid(String),
}

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

pub fn parse_toml(content: &str) -> Result<AppConfig, ConfigError> {
    parse_service(content, None)
}

pub fn parse_service(content: &str, service_name: Option<&str>) -> Result<AppConfig, ConfigError> {
    let file: AppConfigFile = toml::from_str(content)?;
    let resolved = resolve_limits(&file.resources)?;

    if file.service.exec_start.trim().is_empty() {
        return Err(ConfigError::Invalid(
            "Service.ExecStart must not be empty".to_string(),
        ));
    }

    let (command, args) = parse_exec_start(&file.service.exec_start)?;
    let name = service_name
        .map(str::to_string)
        .unwrap_or_else(|| "service".to_string());

    // Reject names that could escape the jobs/cgroup directory or be used in
    // filesystem paths unsafely.
    if let Err(reason) = validate_service_name(&name) {
        return Err(ConfigError::Invalid(format!(
            "invalid service name: {reason}"
        )));
    }

    if let Some(oom) = file.service.oom_score_adjust {
        if !(-1000..=1000).contains(&oom) {
            return Err(ConfigError::Invalid(format!(
                "OOMScoreAdjust must be between -1000 and 1000, got {}",
                oom
            )));
        }
    }

    Ok(AppConfig {
        name,
        command,
        args,
        activation_mode: file.service.activation_mode,
        activation_socket: file.service.activation_socket,
        uid: file.service.uid,
        gid: file.service.gid,
        user: file.service.user,
        group: file.service.group,
        env: file.environment,
        priority: priority_from_oom_score(file.service.oom_score_adjust),
        oneshot: file
            .service
            .service_type
            .as_deref()
            .is_some_and(|t| t.eq_ignore_ascii_case("oneshot")),
        oom_score_adjust: file.service.oom_score_adjust,
        resources: resolved,
        activation: Vec::new(),
        network: file.network,
        source_path: None,
        auth: if file.peers.is_empty() && file.impersonation.is_empty() {
            None
        } else {
            Some(AuthConfig {
                peers: file.peers,
                impersonation: file.impersonation,
            })
        },

        schedule: file.schedule,
        constraints: file.constraints,
        backoff: file.backoff,
        persisted: file.persisted,
        prefetch: file.prefetch,
        save_result: file.save_result,
        trace_tag: file.trace_tag,
        user_initiated: file.user_initiated,
        expedited: file.expedited,
        estimated_download_bytes: file.estimated_download_bytes,
        estimated_upload_bytes: file.estimated_upload_bytes,
        minimum_network_chunk_bytes: file.minimum_network_chunk_bytes,
    })
}

fn priority_from_oom_score(oom_score_adjust: Option<i32>) -> u32 {
    match oom_score_adjust {
        Some(score) => (score + 1000).clamp(0, 2000) as u32,
        None => 1000,
    }
}

fn parse_exec_start(exec_start: &str) -> Result<(String, Vec<String>), ConfigError> {
    let words = split_exec_words(exec_start)?;
    let Some((command, args)) = words.split_first() else {
        return Err(ConfigError::Invalid(
            "Service.ExecStart must include a command".to_string(),
        ));
    };
    Ok((command.clone(), args.to_vec()))
}

fn split_exec_words(input: &str) -> Result<Vec<String>, ConfigError> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    let mut quote = None;
    let mut in_word = false;

    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), '\\') => {
                if let Some(next) = chars.next() {
                    current.push(next);
                    in_word = true;
                } else {
                    current.push('\\');
                    in_word = true;
                }
            }
            (Some(_), c) => {
                current.push(c);
                in_word = true;
            }
            (None, '\'' | '"') => {
                quote = Some(ch);
                in_word = true;
            }
            (None, '\\') => {
                if let Some(next) = chars.next() {
                    current.push(next);
                    in_word = true;
                } else {
                    current.push('\\');
                    in_word = true;
                }
            }
            (None, c) if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut current));
                    in_word = false;
                }
            }
            (None, c) => {
                current.push(c);
                in_word = true;
            }
        }
    }

    if let Some(q) = quote {
        return Err(ConfigError::Invalid(format!(
            "unterminated quote {} in Service.ExecStart",
            q
        )));
    }

    if in_word {
        words.push(current);
    }

    Ok(words)
}

/// Validate a service/job name for safe use in filesystem paths (cgroup
/// scopes, jobs directory, user config directory).
///
/// A valid name:
/// - is non-empty
/// - is at most 251 characters (leaving room for the `.scope`/`.service`
///   suffixes under NAME_MAX=255)
/// - contains no path separators (`/`, `\`)
/// - is not `.` or `..` and contains no `..` component
/// - contains no NUL bytes
/// - does not start with `-` (could be mistaken for a flag in some contexts)
///
/// Returns `Ok(())` if valid, or `Err(String)` with a reason.
pub fn validate_service_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("name must not be empty".to_string());
    }
    if name.len() > 251 {
        return Err(format!(
            "name must be at most 251 characters, got {}",
            name.len()
        ));
    }
    if name.contains('\0') {
        return Err("name must not contain NUL bytes".to_string());
    }
    if name.contains('/') || name.contains('\\') {
        return Err("name must not contain path separators".to_string());
    }
    if name == "." || name == ".." {
        return Err("name must not be '.' or '..'".to_string());
    }
    // Reject any path component equal to ParentDir, which would let `..`
    // sneak in as part of a joined path.
    if std::path::Path::new(name)
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        return Err("name must not contain '..' components".to_string());
    }
    if name.starts_with('-') {
        return Err("name must not start with '-'".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod name_validation_tests {
    use super::*;

    #[test]
    fn rejects_dotdot() {
        assert!(validate_service_name("../etc").is_err());
        assert!(validate_service_name("..").is_err());
        assert!(validate_service_name("foo/../bar").is_err());
    }

    #[test]
    fn rejects_separators() {
        assert!(validate_service_name("a/b").is_err());
        assert!(validate_service_name("a\\b").is_err());
    }

    #[test]
    fn rejects_empty_and_long() {
        assert!(validate_service_name("").is_err());
        let long = "a".repeat(252);
        assert!(validate_service_name(&long).is_err());
    }

    #[test]
    fn rejects_leading_dash() {
        assert!(validate_service_name("-foo").is_err());
    }

    #[test]
    fn accepts_valid() {
        assert!(validate_service_name("app1").is_ok());
        assert!(validate_service_name("worker-1.mesh").is_ok());
        assert!(validate_service_name("_underscore").is_ok());
    }
}
