use crate::ProcMon;
use axum::serve;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

/// Configuration for the Pmon server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Refresh interval in seconds for monitoring
    pub refresh_interval: u64,
    /// Optional UDS path for MCP server
    pub mcp_uds_path: Option<String>,
    /// Authorized UID for MCP UDS connections
    pub auth_uid: Option<u32>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            refresh_interval: 10,
            mcp_uds_path: None,
            auth_uid: None,
        }
    }
}

/// Main server struct for running pmond in various modes
pub struct PmonServer {
    config: ServerConfig,
    proc_mon: Arc<ProcMon>,
}

impl PmonServer {
    /// Create a new PmonServer instance
    pub fn new(config: ServerConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let proc_mon = ProcMon::new()?;
        let proc_mon = Arc::new(proc_mon);

        Ok(Self { config, proc_mon })
    }

    /// Run the default HTTP/MCP server mode
    pub async fn run_server(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting PMON process monitor");

        let (tx, _rx) = tokio::sync::mpsc::channel(100);

        // Start monitoring
        self.proc_mon.start(true, true, Some(tx.clone()))?;

        info!("PMON process monitor started successfully");

        // Start UDS servers
        let path_str = if let Some(path) = &self.config.mcp_uds_path {
            path.clone()
        } else {
            // Default to /run/user/<uid>/pmond.sock
            let uid = unsafe { libc::getuid() };
            format!("/run/user/{}/pmond.sock", uid)
        };

        // Ensure parent directory exists
        let path = PathBuf::from(&path_str);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let http_path = format!("{}.http", path_str);
        let mcp_path = format!("{}.mcp", path_str);

        let pm_http = self.proc_mon.clone();
        let auth_uid = self.config.auth_uid;
        tokio::spawn(async move {
            if let Err(e) =
                crate::handlers::run_uds_http_server(pm_http, &http_path, auth_uid).await
            {
                error!("UDS HTTP server error: {}", e);
            }
        });

        let pm_mcp = self.proc_mon.clone();
        let auth_uid = self.config.auth_uid;
        tokio::spawn(async move {
            if let Err(e) = crate::handlers::run_uds_mcp_server(pm_mcp, &mcp_path, auth_uid).await {
                error!("UDS MCP server error: {}", e);
            }
        });

        // Set up HTTP server
        let uid = unsafe { libc::getuid() };
        let port = if uid == 0 {
            8081
        } else {
            8082 + (uid as i32 - 1000)
        };

        let addr = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(&addr).await?;
        info!("Listening on http://{}", addr);

        // Create the Axum app
        let app = crate::handlers::app(self.proc_mon.clone());

        // Run the server
        serve(listener, app.into_make_service()).await?;

        Ok(())
    }

    /// Run MCP server mode via stdio
    pub async fn run_mcp_server(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting PMON MCP server");

        // Start monitoring
        self.proc_mon.start(true, true, None)?;

        crate::handlers::run_stdio_server(self.proc_mon.clone()).await
    }
}
