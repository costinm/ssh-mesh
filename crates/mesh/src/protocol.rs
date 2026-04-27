//! JSON-lines protocol for the mesh-init UDS control socket.
//!
//! Inspired by MCP/LSP — each message is a single JSON line terminated by `\n`.
//! The daemon reads requests and writes responses on the same connection.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ============================================================================
// Requests
// ============================================================================

/// A request from a client to the mesh-init daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method")]
pub enum Request {
    /// Start a named service. If not already running, loads config and spawns.
    #[serde(rename = "start")]
    Start {
        name: String,
        /// Additional args appended to the service command.
        #[serde(default)]
        args: Vec<String>,
        /// Additional env vars merged with the config's environment.
        #[serde(default)]
        env: HashMap<String, String>,
    },

    /// Stop a running service.
    #[serde(rename = "stop")]
    Stop {
        name: String,
        /// Signal to send (default: SIGTERM).
        signal: Option<i32>,
    },

    /// Freeze (suspend) a running service via SIGSTOP or cgroup.freeze.
    #[serde(rename = "freeze")]
    Freeze { name: String },

    /// Unfreeze (resume) a frozen service.
    #[serde(rename = "unfreeze")]
    Unfreeze { name: String },

    /// Query status of a specific service or all services.
    #[serde(rename = "status")]
    Status { name: Option<String> },

    /// Shutdown the daemon gracefully.
    #[serde(rename = "shutdown")]
    Shutdown,

    /// Reload all configurations from disk and restart changed services.
    #[serde(rename = "reload")]
    Reload,

    /// Schedule a new job.
    #[serde(rename = "schedule_job")]
    ScheduleJob { config: serde_json::Value },

    /// Cancel a scheduled job.
    #[serde(rename = "cancel_job")]
    CancelJob { name: String },

    /// Enqueue a work item to an existing job.
    #[serde(rename = "enqueue_work")]
    EnqueueWork { job_name: String, work: serde_json::Value },

    /// List all scheduled jobs.
    #[serde(rename = "list_jobs")]
    ListJobs,

    /// Mark a job as finished.
    #[serde(rename = "job_finished")]
    JobFinished { name: String, reschedule: bool, result: Option<serde_json::Value> },

    /// Deliver a system event to the job scheduler.
    #[serde(rename = "event")]
    Event { event: serde_json::Value },
}


// ============================================================================
// Responses
// ============================================================================

/// A response from the daemon to a client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl Response {
    /// Create a successful response with no data.
    pub fn ok() -> Self {
        Self {
            success: true,
            error: None,
            data: None,
        }
    }

    /// Create a successful response with data.
    pub fn ok_with_data(data: serde_json::Value) -> Self {
        Self {
            success: true,
            error: None,
            data: Some(data),
        }
    }

    /// Create an error response.
    pub fn err(message: impl Into<String>) -> Self {
        Self {
            success: false,
            error: Some(message.into()),
            data: None,
        }
    }
}

// ============================================================================
// Service Status
// ============================================================================

/// Current state of a managed service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceState {
    Stopped,
    Starting,
    Running,
    Frozen,
    Stopping,
    Failed,
}

impl std::fmt::Display for ServiceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stopped => write!(f, "stopped"),
            Self::Starting => write!(f, "starting"),
            Self::Running => write!(f, "running"),
            Self::Frozen => write!(f, "frozen"),
            Self::Stopping => write!(f, "stopping"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// Status information for a service, returned by the `status` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub name: String,
    pub state: ServiceState,
    pub pid: Option<u32>,
    pub uptime_secs: Option<u64>,
    pub restarts: u32,
    pub consecutive_failures: u32,
    pub next_restart_in_secs: Option<u64>,
    pub cgroup_path: Option<String>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_start_request() {
        let req = Request::Start {
            name: "chrome".to_string(),
            args: vec!["--headless".to_string()],
            env: HashMap::from([("DISPLAY".to_string(), ":0".to_string())]),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"method\":\"start\""));
        assert!(json.contains("\"chrome\""));
    }

    #[test]
    fn test_deserialize_start_request() {
        let json = r#"{"method":"start","name":"chrome","args":[],"env":{}}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        match req {
            Request::Start { name, .. } => assert_eq!(name, "chrome"),
            _ => panic!("expected Start"),
        }
    }

    #[test]
    fn test_serialize_response() {
        let resp = Response::ok_with_data(serde_json::json!({"pid": 1234}));
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: Response = serde_json::from_str(&json).unwrap();
        assert!(parsed.success);
        assert!(parsed.data.is_some());
    }

    #[test]
    fn test_error_response() {
        let resp = Response::err("service not found");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"success\":false"));
        assert!(json.contains("service not found"));
        // data should be omitted
        assert!(!json.contains("\"data\""));
    }

    #[test]
    fn test_deserialize_status_response() {
        let json = r#"{
            "name": "chrome",
            "state": "running",
            "pid": 1234,
            "uptime_secs": 60,
            "restarts": 0,
            "consecutive_failures": 0,
            "cgroup_path": "/sys/fs/cgroup/mesh.slice/chrome.scope"
        }"#;
        let status: ServiceStatus = serde_json::from_str(json).unwrap();
        assert_eq!(status.name, "chrome");
        assert_eq!(status.state, ServiceState::Running);
        assert_eq!(status.pid, Some(1234));
        assert_eq!(status.consecutive_failures, 0);
    }

    #[test]
    fn test_service_state_display() {
        assert_eq!(ServiceState::Running.to_string(), "running");
        assert_eq!(ServiceState::Frozen.to_string(), "frozen");
        assert_eq!(ServiceState::Failed.to_string(), "failed");
    }

    #[test]
    fn test_deserialize_all_methods() {
        let cases = [
            r#"{"method":"stop","name":"x","signal":9}"#,
            r#"{"method":"freeze","name":"x"}"#,
            r#"{"method":"unfreeze","name":"x"}"#,
            r#"{"method":"status","name":null}"#,
            r#"{"method":"shutdown"}"#,
            r#"{"method":"reload"}"#,
        ];
        for json in cases {
            let _req: Request = serde_json::from_str(json).unwrap();
        }
    }
}
