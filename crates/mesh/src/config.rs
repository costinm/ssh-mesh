use anyhow::Result;
use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::CString;
use std::fmt;

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
    #[serde(default, rename = "ExecStartPre", deserialize_with = "string_or_vec")]
    pub exec_start_pre: Vec<String>,
    #[serde(default, rename = "ExecStartPost", deserialize_with = "string_or_vec")]
    pub exec_start_post: Vec<String>,
    #[serde(default, rename = "ExecStop", deserialize_with = "string_or_vec")]
    pub exec_stop: Vec<String>,
    #[serde(default, rename = "ExecReload", deserialize_with = "string_or_vec")]
    pub exec_reload: Vec<String>,
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
    #[serde(rename = "WorkingDirectory")]
    pub working_directory: Option<String>,
    #[serde(default, rename = "Restart")]
    pub restart: RestartPolicy,
    #[serde(rename = "RestartSec")]
    pub restart_sec: Option<String>,
    #[serde(rename = "TimeoutStartSec")]
    pub timeout_start_sec: Option<String>,
    #[serde(rename = "TimeoutStopSec")]
    pub timeout_stop_sec: Option<String>,
    #[serde(rename = "KillSignal")]
    pub kill_signal: Option<String>,
    #[serde(default, rename = "KillMode")]
    pub kill_mode: KillMode,
    #[serde(default = "default_true", rename = "SendSIGKILL")]
    pub send_sigkill: bool,
    #[serde(rename = "UMask")]
    pub umask: Option<String>,
    #[serde(
        default,
        rename = "SupplementaryGroups",
        deserialize_with = "string_or_vec"
    )]
    pub supplementary_groups: Vec<String>,
    /// `Type=oneshot` marks the service as one-shot and disables restart.
    #[serde(rename = "Type")]
    pub service_type: Option<String>,
    /// OOM score adjustment (-1000 to 1000).
    #[serde(rename = "OOMScoreAdjust")]
    pub oom_score_adjust: Option<i32>,
    #[serde(default, rename = "NoNewPrivileges")]
    pub no_new_privileges: bool,
    #[serde(default, rename = "PrivateTmp")]
    pub private_tmp: bool,
    #[serde(default, rename = "PrivateDevices")]
    pub private_devices: bool,
    #[serde(default, rename = "PrivateNetwork")]
    pub private_network: bool,
    #[serde(rename = "ProtectSystem")]
    pub protect_system: Option<String>,
    #[serde(rename = "ProtectHome")]
    pub protect_home: Option<String>,
    #[serde(default, rename = "ReadWritePaths", deserialize_with = "string_or_vec")]
    pub read_write_paths: Vec<String>,
    #[serde(default, rename = "ReadOnlyPaths", deserialize_with = "string_or_vec")]
    pub read_only_paths: Vec<String>,
    #[serde(
        default,
        rename = "InaccessiblePaths",
        deserialize_with = "string_or_vec"
    )]
    pub inaccessible_paths: Vec<String>,
    #[serde(
        default,
        rename = "CapabilityBoundingSet",
        deserialize_with = "string_or_vec"
    )]
    pub capability_bounding_set: Vec<String>,
    #[serde(
        default,
        rename = "AmbientCapabilities",
        deserialize_with = "string_or_vec"
    )]
    pub ambient_capabilities: Vec<String>,
}

/// The `[resources]` section — maps to cgroup v2 knobs.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ResourceLimits {
    #[serde(rename = "MemoryMin")]
    pub memory_low: Option<String>,
    #[serde(rename = "MemoryHigh")]
    pub memory_high: Option<String>,
    #[serde(rename = "MemoryMax")]
    pub memory_max: Option<String>,
    #[serde(rename = "CPUWeight")]
    pub cpu_weight: Option<u32>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy {
    #[default]
    No,
    Always,
    OnSuccess,
    OnFailure,
    OnAbnormal,
    OnAbort,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum KillMode {
    #[default]
    ControlGroup,
    Mixed,
    Process,
    None,
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
    /// AF_VSOCK CID for `ListenStream=vsock:CID:PORT`. An omitted CID in the
    /// socket unit is represented as `None` and defaults to VMADDR_CID_ANY at
    /// bind time.
    #[serde(default)]
    pub vsock_cid: Option<u32>,
    /// AF_VSOCK port for `ListenStream=vsock:CID:PORT`.
    #[serde(default)]
    pub vsock_port: Option<u32>,
    #[serde(default)]
    pub wait: bool,
    /// Bind address for TCP activation. For systemd-style socket units, a bare
    /// `ListenStream=PORT` defaults to IPv6-any with dual-stack enabled where
    /// the OS permits it. Inline activation entries without `bind` use the same
    /// default.
    #[serde(default)]
    pub bind: Option<String>,
    /// File descriptor name passed through `LISTEN_FDNAMES` for systemd-style
    /// activation. From `.socket` files this comes from `FileDescriptorName=`,
    /// defaulting to the socket unit file name.
    #[serde(default)]
    pub fd_name: Option<String>,
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
    pub exec_start_pre: Vec<String>,
    pub exec_start_post: Vec<String>,
    pub exec_stop: Vec<String>,
    pub exec_reload: Vec<String>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub working_directory: Option<String>,
    pub restart: RestartPolicy,
    pub restart_sec: u64,
    pub timeout_start_sec: Option<u64>,
    pub timeout_stop_sec: Option<u64>,
    pub kill_signal: i32,
    pub kill_mode: KillMode,
    pub send_sigkill: bool,
    pub umask: Option<u32>,
    pub supplementary_groups: Vec<u32>,
    pub env: HashMap<String, String>,
    pub priority: u32,
    pub oneshot: bool,
    pub activation_mode: ServiceActivationMode,
    pub activation_socket: Option<String>,
    pub oom_score_adjust: Option<i32>,
    pub no_new_privileges: bool,
    pub private_tmp: bool,
    pub private_devices: bool,
    pub private_network: bool,
    pub protect_system: Option<String>,
    pub protect_home: Option<String>,
    pub read_write_paths: Vec<String>,
    pub read_only_paths: Vec<String>,
    pub inaccessible_paths: Vec<String>,
    pub capability_bounding_set: Vec<String>,
    pub ambient_capabilities: Vec<String>,
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

fn string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringOrVec;

    impl<'de> Visitor<'de> for StringOrVec {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a string or list of strings")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(split_systemd_words(value))
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(split_systemd_words(&value))
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut values = Vec::new();
            while let Some(value) = seq.next_element::<String>()? {
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_any(StringOrVec)
}

fn split_systemd_words(value: &str) -> Vec<String> {
    value
        .split_ascii_whitespace()
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
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

fn parse_duration_secs(value: Option<&str>, field: &str) -> Result<Option<u64>, ConfigError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value.eq_ignore_ascii_case("infinity") {
        return Ok(None);
    }
    let (number, multiplier) = if let Some(number) = value.strip_suffix("ms") {
        (number, 1.0 / 1000.0)
    } else if let Some(number) = value.strip_suffix("min") {
        (number, 60.0)
    } else if let Some(number) = value.strip_suffix('h') {
        (number, 60.0 * 60.0)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1.0)
    } else {
        (value, 1.0)
    };
    let parsed = number
        .trim()
        .parse::<f64>()
        .map_err(|_| ConfigError::Invalid(format!("{field} has invalid duration: {value}")))?;
    if !parsed.is_finite() || parsed < 0.0 {
        return Err(ConfigError::Invalid(format!(
            "{field} must be a non-negative duration"
        )));
    }
    Ok(Some((parsed * multiplier).ceil() as u64))
}

fn parse_umask(value: Option<&str>) -> Result<Option<u32>, ConfigError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    u32::from_str_radix(value.trim_start_matches("0o").trim_start_matches('0'), 8)
        .or_else(|_| u32::from_str_radix(value, 8))
        .map(Some)
        .map_err(|_| ConfigError::Invalid(format!("UMask has invalid octal value: {value}")))
}

fn parse_signal(value: Option<&str>) -> Result<i32, ConfigError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(libc::SIGTERM);
    };
    if let Ok(signal) = value.parse::<i32>() {
        return Ok(signal);
    }
    let normalized = value
        .strip_prefix("SIG")
        .unwrap_or(value)
        .to_ascii_uppercase();
    let signal = match normalized.as_str() {
        "TERM" => libc::SIGTERM,
        "KILL" => libc::SIGKILL,
        "INT" => libc::SIGINT,
        "HUP" => libc::SIGHUP,
        "QUIT" => libc::SIGQUIT,
        "ABRT" => libc::SIGABRT,
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        "CONT" => libc::SIGCONT,
        "STOP" => libc::SIGSTOP,
        _ => {
            return Err(ConfigError::Invalid(format!(
                "KillSignal has unsupported signal: {value}"
            )));
        }
    };
    Ok(signal)
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

fn reject_removed_identity_fields(content: &str) -> Result<(), ConfigError> {
    let value: toml::Value = toml::from_str(content)?;
    let Some(service) = value.get("Service").and_then(toml::Value::as_table) else {
        return Ok(());
    };
    let mut removed = Vec::new();
    if service.contains_key("MeshUID") {
        removed.push("MeshUID");
    }
    if service.contains_key("MeshGID") {
        removed.push("MeshGID");
    }
    if removed.is_empty() {
        Ok(())
    } else {
        Err(ConfigError::Invalid(format!(
            "{} removed; use systemd-compatible User=/Group= instead",
            removed.join(" and ")
        )))
    }
}

fn resolve_user(user: Option<&str>) -> Result<(Option<u32>, Option<u32>), ConfigError> {
    let Some(user) = user.map(str::trim).filter(|user| !user.is_empty()) else {
        return Ok((None, None));
    };

    if let Ok(uid) = user.parse::<u32>() {
        return Ok((Some(uid), None));
    }

    let c_user = CString::new(user)
        .map_err(|_| ConfigError::Invalid(format!("User contains NUL byte: {user:?}")))?;
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buffer = vec![0u8; 16 * 1024];
    let rc = unsafe {
        libc::getpwnam_r(
            c_user.as_ptr(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return Err(ConfigError::Invalid(format!("User not found: {user}")));
    }
    Ok((Some(entry.pw_uid), Some(entry.pw_gid)))
}

fn resolve_group(group: Option<&str>) -> Result<Option<u32>, ConfigError> {
    let Some(group) = group.map(str::trim).filter(|group| !group.is_empty()) else {
        return Ok(None);
    };

    if let Ok(gid) = group.parse::<u32>() {
        return Ok(Some(gid));
    }

    let c_group = CString::new(group)
        .map_err(|_| ConfigError::Invalid(format!("Group contains NUL byte: {group:?}")))?;
    let mut entry: libc::group = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::group = std::ptr::null_mut();
    let mut buffer = vec![0u8; 16 * 1024];
    let rc = unsafe {
        libc::getgrnam_r(
            c_group.as_ptr(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return Err(ConfigError::Invalid(format!("Group not found: {group}")));
    }

    Ok(Some(entry.gr_gid))
}

fn resolve_group_required(group: &str, field: &str) -> Result<u32, ConfigError> {
    resolve_group(Some(group))?
        .ok_or_else(|| ConfigError::Invalid(format!("{field} contains an empty group")))
}

pub fn parse_service(content: &str, service_name: Option<&str>) -> Result<AppConfig, ConfigError> {
    reject_removed_identity_fields(content)?;
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

    let (uid, primary_gid) = resolve_user(file.service.user.as_deref())?;
    let gid = resolve_group(file.service.group.as_deref())?.or(primary_gid);
    let restart_sec =
        parse_duration_secs(file.service.restart_sec.as_deref(), "RestartSec")?.unwrap_or(1);
    let timeout_start_sec =
        parse_duration_secs(file.service.timeout_start_sec.as_deref(), "TimeoutStartSec")?;
    let timeout_stop_sec =
        parse_duration_secs(file.service.timeout_stop_sec.as_deref(), "TimeoutStopSec")?;
    let kill_signal = parse_signal(file.service.kill_signal.as_deref())?;
    let umask = parse_umask(file.service.umask.as_deref())?;
    let supplementary_groups = file
        .service
        .supplementary_groups
        .iter()
        .map(|group| resolve_group_required(group, "SupplementaryGroups"))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(AppConfig {
        name,
        command,
        args,
        exec_start_pre: file.service.exec_start_pre,
        exec_start_post: file.service.exec_start_post,
        exec_stop: file.service.exec_stop,
        exec_reload: file.service.exec_reload,
        activation_mode: file.service.activation_mode,
        activation_socket: file.service.activation_socket,
        uid,
        gid,
        user: file.service.user,
        group: file.service.group,
        working_directory: file.service.working_directory,
        restart: file.service.restart,
        restart_sec,
        timeout_start_sec,
        timeout_stop_sec,
        kill_signal,
        kill_mode: file.service.kill_mode,
        send_sigkill: file.service.send_sigkill,
        umask,
        supplementary_groups,
        env: file.environment,
        priority: priority_from_oom_score(file.service.oom_score_adjust),
        oneshot: file
            .service
            .service_type
            .as_deref()
            .is_some_and(|t| t.eq_ignore_ascii_case("oneshot")),
        oom_score_adjust: file.service.oom_score_adjust,
        no_new_privileges: file.service.no_new_privileges,
        private_tmp: file.service.private_tmp,
        private_devices: file.service.private_devices,
        private_network: file.service.private_network,
        protect_system: file.service.protect_system,
        protect_home: file.service.protect_home,
        read_write_paths: file.service.read_write_paths,
        read_only_paths: file.service.read_only_paths,
        inaccessible_paths: file.service.inaccessible_paths,
        capability_bounding_set: file.service.capability_bounding_set,
        ambient_capabilities: file.service.ambient_capabilities,
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
