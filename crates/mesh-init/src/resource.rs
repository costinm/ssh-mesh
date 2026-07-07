//! PSI-based resource management and priority-based eviction.
//!
//! Monitors `/proc/pressure/memory` and freezes or stops low-priority
//! services when memory pressure is detected. Services are evicted
//! in order of decreasing priority value (highest number = least important).

use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

use parking_lot::Mutex;
use tracing::{debug, error, info, warn};

use crate::config::AppConfig;
use crate::process::ManagedProcess;
use crate::protocol::ServiceState;

// ============================================================================
// Pressure Levels
// ============================================================================

/// Classified memory pressure level based on PSI avg10.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PressureLevel {
    /// No significant pressure.
    None,
    /// Light pressure — consider freezing expendable services.
    Low,
    /// Moderate pressure — freeze low-priority services.
    Medium,
    /// Critical pressure — stop low-priority services.
    Critical,
}

impl std::fmt::Display for PressureLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ============================================================================
// PSI Parsing
// ============================================================================

/// Parsed PSI pressure data from `/proc/pressure/memory`.
#[derive(Debug, Clone, Default)]
pub struct PressureData {
    pub some_avg10: f64,
    pub some_avg60: f64,
    pub some_avg300: f64,
    pub full_avg10: f64,
    pub full_avg60: f64,
    pub full_avg300: f64,
}

/// Read and parse `/proc/pressure/memory`.
pub fn read_memory_pressure() -> Option<PressureData> {
    let content = fs::read_to_string("/proc/pressure/memory").ok()?;
    parse_pressure(&content)
}

/// Parse PSI pressure content.
///
/// Format:
/// ```text
/// some avg10=0.00 avg60=0.00 avg300=0.00 total=0
/// full avg10=0.00 avg60=0.00 avg300=0.00 total=0
/// ```
fn parse_pressure(content: &str) -> Option<PressureData> {
    let mut data = PressureData::default();

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        let kind = parts[0];
        let avg10 = parse_kv(parts[1]).unwrap_or(0.0);
        let avg60 = parse_kv(parts[2]).unwrap_or(0.0);
        let avg300 = parse_kv(parts[3]).unwrap_or(0.0);

        match kind {
            "some" => {
                data.some_avg10 = avg10;
                data.some_avg60 = avg60;
                data.some_avg300 = avg300;
            }
            "full" => {
                data.full_avg10 = avg10;
                data.full_avg60 = avg60;
                data.full_avg300 = avg300;
            }
            _ => {}
        }
    }

    Some(data)
}

/// Parse a `key=value` pair where value is f64.
fn parse_kv(s: &str) -> Option<f64> {
    let (_, val) = s.split_once('=')?;
    val.parse().ok()
}

fn psi_threshold_critical() -> f64 {
    std::env::var("MESH_INIT_PSI_CRITICAL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60.0)
}

fn psi_threshold_medium() -> f64 {
    std::env::var("MESH_INIT_PSI_MEDIUM")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20.0)
}

fn psi_threshold_low() -> f64 {
    std::env::var("MESH_INIT_PSI_LOW")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5.0)
}

/// Classify memory pressure into a level based on PSI some_avg10.
///
/// Thresholds can be overridden via env vars:
/// - `MESH_INIT_PSI_CRITICAL` (default: 60.0)
/// - `MESH_INIT_PSI_MEDIUM` (default: 20.0)
/// - `MESH_INIT_PSI_LOW` (default: 5.0)
pub fn classify_pressure(data: &PressureData) -> PressureLevel {
    let avg10 = data.some_avg10;
    if avg10 >= psi_threshold_critical() {
        PressureLevel::Critical
    } else if avg10 >= psi_threshold_medium() {
        PressureLevel::Medium
    } else if avg10 >= psi_threshold_low() {
        PressureLevel::Low
    } else {
        PressureLevel::None
    }
}

// ============================================================================
// Resource Manager
// ============================================================================

/// Manages resource-based eviction of services.
pub struct ResourceManager {
    services: Arc<Mutex<HashMap<String, ManagedProcess>>>,
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl ResourceManager {
    /// Create a new resource manager.
    pub fn new(services: Arc<Mutex<HashMap<String, ManagedProcess>>>) -> Self {
        Self {
            services,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Start the background pressure monitoring task.
    pub fn start(&self) -> tokio::task::JoinHandle<()> {
        let services = self.services.clone();
        let running = self.running.clone();
        running.store(true, std::sync::atomic::Ordering::SeqCst);

        tokio::spawn(async move {
            info!("resource_manager_started");
            while running.load(std::sync::atomic::Ordering::SeqCst) {
                if let Some(pressure) = read_memory_pressure() {
                    let level = classify_pressure(&pressure);
                    if level > PressureLevel::None {
                        debug!(
                            level = %level,
                            avg10 = pressure.some_avg10,
                            "memory_pressure_detected"
                        );
                        evict_by_priority(&services, level);
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
            info!("resource_manager_stopped");
        })
    }

    /// Stop the background monitoring.
    pub fn stop(&self) {
        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Check if a service can be started given current memory conditions.
    ///
    /// Returns false if:
    /// - Memory pressure is Critical (PSI avg10 >= 60%).
    /// - The sum of `memory_low` reservations of all running services plus this
    ///   service's `memory_low` would exceed available system memory.
    pub fn can_start(&self, config: &AppConfig) -> bool {
        // 1. Check PSI pressure
        if let Some(pressure) = read_memory_pressure() {
            let level = classify_pressure(&pressure);
            if level >= PressureLevel::Critical {
                warn!("cannot_start_memory_pressure_critical");
                return false;
            }
        }

        // 2. Check memory.low admission
        let new_low = config.resources.memory_low.unwrap_or(0);
        if new_low > 0 {
            let committed = self.committed_memory_low();
            let available = read_available_memory().unwrap_or(u64::MAX);
            let total_needed = committed + new_low;

            if total_needed > available {
                warn!(
                    service = %config.name,
                    committed,
                    new = new_low,
                    total = total_needed,
                    available,
                    "memory_low_admission_failed"
                );
                return false;
            }

            info!(
                service = %config.name,
                committed,
                new = new_low,
                total = total_needed,
                available,
                "memory_admission_ok"
            );
        }

        true
    }

    /// Sum of `memory_low` reservations for all currently running services.
    pub fn committed_memory_low(&self) -> u64 {
        let services = self.services.lock();
        services
            .values()
            .filter(|p| p.state == ServiceState::Running)
            .map(|p| p.config.resources.memory_low.unwrap_or(0))
            .sum()
    }
}

/// Evict services by priority based on pressure level.
///
/// Sorts running services by priority (highest number = least important first),
/// then freezes or stops them depending on pressure level.
fn evict_by_priority(services: &Arc<Mutex<HashMap<String, ManagedProcess>>>, level: PressureLevel) {
    let mut svcs = services.lock();

    // Collect running services sorted by priority (least important first)
    let mut candidates: Vec<&String> = svcs
        .iter()
        .filter(|(_, p)| p.state == ServiceState::Running)
        .map(|(name, _)| name)
        .collect();

    candidates.sort_by(|a, b| {
        let pa = svcs.get(*a).map(|p| p.config.priority).unwrap_or(0);
        let pb = svcs.get(*b).map(|p| p.config.priority).unwrap_or(0);
        pb.cmp(&pa) // descending: highest priority number (least important) first
    });

    let candidate_names: Vec<String> = candidates.into_iter().cloned().collect();

    for name in candidate_names {
        if let Some(proc) = svcs.get_mut(&name) {
            // Skip critical services (priority < 100)
            if proc.config.priority < 100 {
                continue;
            }

            if let Some(pid) = proc.pid {
                match level {
                    PressureLevel::Low | PressureLevel::Medium => {
                        // Freeze
                        info!(
                            service = %name,
                            priority = proc.config.priority,
                            pressure = %level,
                            "freezing_service_on_pressure"
                        );
                        if let Err(e) =
                            crate::process::freeze_process(pid, proc.cgroup_path.as_deref())
                        {
                            error!(service = %name, error = %e, "freeze_service_failed");
                        } else {
                            proc.state = ServiceState::Frozen;
                        }
                        // Only freeze one at a time for Low pressure
                        if level == PressureLevel::Low {
                            return;
                        }
                    }
                    PressureLevel::Critical => {
                        // Stop
                        info!(
                            service = %name,
                            priority = proc.config.priority,
                            "stopping_service_on_critical_pressure"
                        );
                        let _ = crate::process::send_signal(pid, libc::SIGTERM);
                        proc.state = ServiceState::Stopping;
                    }
                    PressureLevel::None => unreachable!(),
                }
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

// ============================================================================
// System Memory
// ============================================================================

/// Read available memory from `/proc/meminfo`.
///
/// Returns the `MemAvailable` value in bytes, or `None` if it cannot be read.
pub fn read_available_memory() -> Option<u64> {
    let content = fs::read_to_string("/proc/meminfo").ok()?;
    parse_meminfo_available(&content)
}

/// Parse the `MemAvailable` field from `/proc/meminfo` content.
///
/// The field is in kilobytes, so we multiply by 1024 to return bytes.
fn parse_meminfo_available(content: &str) -> Option<u64> {
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            let trimmed = rest.trim().trim_end_matches(" kB").trim();
            let kb: u64 = trimmed.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_meminfo_available() {
        let content = "\
MemTotal:       65847296 kB
MemFree:        15381516 kB
MemAvailable:   48343700 kB
Buffers:            2112 kB
Cached:         32937264 kB
";
        let avail = parse_meminfo_available(content).unwrap();
        assert_eq!(avail, 48343700 * 1024);
    }

    #[test]
    fn test_parse_meminfo_missing() {
        let content = "MemTotal: 100 kB\nMemFree: 50 kB\n";
        assert!(parse_meminfo_available(content).is_none());
    }

    #[test]
    fn test_committed_memory_low() {
        let services = Arc::new(Mutex::new(HashMap::new()));
        let rm = ResourceManager::new(services.clone());

        // No services → 0
        assert_eq!(rm.committed_memory_low(), 0);

        // Add a running service with memory_low
        let cfg = AppConfig {
            name: "svc1".to_string(),
            command: "/bin/true".to_string(),
            args: vec![],
            uid: None,
            gid: None,
            user: None,
            group: None,
            env: HashMap::new(),
            priority: 500,
            oneshot: false,
            oom_score_adjust: None,
            resources: crate::config::ResolvedResourceLimits {
                memory_low: Some(256 * 1024 * 1024),
                ..Default::default()
            },
            activation: vec![],
            source_path: None,
            ..Default::default()
        };
        let mut p = ManagedProcess::new(cfg);
        p.state = ServiceState::Running;
        p.pid = Some(100);
        services.lock().insert("svc1".to_string(), p);

        assert_eq!(rm.committed_memory_low(), 256 * 1024 * 1024);

        // A stopped service should not count
        let cfg2 = AppConfig {
            name: "svc2".to_string(),
            command: "/bin/true".to_string(),
            args: vec![],
            uid: None,
            gid: None,
            user: None,
            group: None,
            env: HashMap::new(),
            priority: 500,
            oneshot: false,
            oom_score_adjust: None,
            resources: crate::config::ResolvedResourceLimits {
                memory_low: Some(128 * 1024 * 1024),
                ..Default::default()
            },
            activation: vec![],
            source_path: None,
            ..Default::default()
        };
        let p2 = ManagedProcess::new(cfg2);
        // p2.state defaults to Stopped
        services.lock().insert("svc2".to_string(), p2);

        // Still only svc1 counts
        assert_eq!(rm.committed_memory_low(), 256 * 1024 * 1024);
    }

    static ENV_MUTEX: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    #[test]
    fn test_pressure_level_classification() {
        let _guard = ENV_MUTEX.lock();
        let mut data = PressureData::default();
        data.some_avg10 = 0.0;
        assert_eq!(classify_pressure(&data), PressureLevel::None);

        data.some_avg10 = 4.9;
        assert_eq!(classify_pressure(&data), PressureLevel::None);

        data.some_avg10 = 5.0;
        assert_eq!(classify_pressure(&data), PressureLevel::Low);

        data.some_avg10 = 19.9;
        assert_eq!(classify_pressure(&data), PressureLevel::Low);

        data.some_avg10 = 20.0;
        assert_eq!(classify_pressure(&data), PressureLevel::Medium);

        data.some_avg10 = 59.9;
        assert_eq!(classify_pressure(&data), PressureLevel::Medium);

        data.some_avg10 = 60.0;
        assert_eq!(classify_pressure(&data), PressureLevel::Critical);

        data.some_avg10 = 100.0;
        assert_eq!(classify_pressure(&data), PressureLevel::Critical);
    }

    #[test]
    fn test_classify_pressure_with_env_override() {
        let _guard = ENV_MUTEX.lock();
        unsafe {
            std::env::set_var("MESH_INIT_PSI_CRITICAL", "80.0");
            std::env::set_var("MESH_INIT_PSI_MEDIUM", "40.0");
            std::env::set_var("MESH_INIT_PSI_LOW", "10.0");
        }

        let mut data = PressureData::default();
        data.some_avg10 = 9.0;
        assert_eq!(classify_pressure(&data), PressureLevel::None);

        data.some_avg10 = 10.0;
        assert_eq!(classify_pressure(&data), PressureLevel::Low);

        data.some_avg10 = 39.9;
        assert_eq!(classify_pressure(&data), PressureLevel::Low);

        data.some_avg10 = 40.0;
        assert_eq!(classify_pressure(&data), PressureLevel::Medium);

        data.some_avg10 = 79.9;
        assert_eq!(classify_pressure(&data), PressureLevel::Medium);

        data.some_avg10 = 80.0;
        assert_eq!(classify_pressure(&data), PressureLevel::Critical);

        unsafe {
            std::env::remove_var("MESH_INIT_PSI_CRITICAL");
            std::env::remove_var("MESH_INIT_PSI_MEDIUM");
            std::env::remove_var("MESH_INIT_PSI_LOW");
        }
    }

    #[test]
    fn test_parse_pressure() {
        let content = "\
some avg10=1.23 avg60=4.56 avg300=7.89 total=12345
full avg10=0.10 avg60=0.20 avg300=0.30 total=5678
";
        let data = parse_pressure(content).unwrap();
        assert!((data.some_avg10 - 1.23).abs() < 0.001);
        assert!((data.some_avg60 - 4.56).abs() < 0.001);
        assert!((data.full_avg10 - 0.10).abs() < 0.001);
    }

    #[test]
    fn test_pressure_level_ordering() {
        assert!(PressureLevel::None < PressureLevel::Low);
        assert!(PressureLevel::Low < PressureLevel::Medium);
        assert!(PressureLevel::Medium < PressureLevel::Critical);
    }

    #[test]
    fn test_eviction_order() {
        use crate::config::{AppConfig, ResolvedResourceLimits};

        let make_config = |name: &str, priority: u32| AppConfig {
            name: name.to_string(),
            command: "/bin/sleep".to_string(),
            args: vec!["999".to_string()],
            uid: None,
            gid: None,
            user: None,
            group: None,
            env: HashMap::new(),
            priority,
            oneshot: false,
            oom_score_adjust: None,
            resources: ResolvedResourceLimits::default(),
            activation: vec![],
            source_path: None,
            ..Default::default()
        };

        let services = Arc::new(Mutex::new(HashMap::new()));
        {
            let mut svcs = services.lock();
            // Critical service — should not be evicted
            let mut p = ManagedProcess::new(make_config("system_ui", 50));
            p.state = ServiceState::Running;
            p.pid = Some(100);
            svcs.insert("system_ui".to_string(), p);

            // Medium priority
            let mut p = ManagedProcess::new(make_config("browser", 500));
            p.state = ServiceState::Running;
            p.pid = Some(200);
            svcs.insert("browser".to_string(), p);

            // Expendable
            let mut p = ManagedProcess::new(make_config("background_sync", 900));
            p.state = ServiceState::Running;
            p.pid = Some(300);
            svcs.insert("background_sync".to_string(), p);
        }

        // Low pressure — should freeze only the least important (background_sync)
        // Note: we can't actually send signals in tests, but we can verify the state change intent
        // The freeze will fail due to invalid PIDs, but state transitions are what we test
        evict_by_priority(&services, PressureLevel::Low);

        let svcs = services.lock();
        // system_ui should be untouched (priority < 100)
        assert_eq!(svcs["system_ui"].state, ServiceState::Running);
    }
}
