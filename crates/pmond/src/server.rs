use crate::ProcMon;
use mesh::{MeshApp, MeshConfig};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::error;

/// Configuration for the Pmon server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Refresh interval in seconds for monitoring
    pub refresh_interval: u64,
    /// Optional UDS path for HTTP server
    pub http_uds_path: Option<String>,
    /// Authorized UID for UDS connections
    pub auth_uid: Option<u32>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            refresh_interval: 10,
            http_uds_path: None,
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

    /// Get a reference to the ProcMon instance
    pub fn proc_mon(&self) -> Arc<ProcMon> {
        self.proc_mon.clone()
    }

    fn create_mesh_app(&self) -> MeshApp {
        let mesh_config = MeshConfig {
            http_port: None, // Will use default logic in MeshApp
            http_uds_path: self.config.http_uds_path.clone(),
            auth_uid: self.config.auth_uid,
        };

        MeshApp::new(mesh_config).with_router(crate::handlers::app(self.proc_mon.clone()))
    }

    /// Run the default HTTP server - for debug. In prod - use UDS or
    /// embed the library.
    pub async fn run_server(&self) -> Result<(), Box<dyn std::error::Error>> {
        let (tx, _rx) = tokio::sync::mpsc::channel(100);

        // Start monitoring
        self.proc_mon.start(true, true, Some(tx.clone()))?;

        // Set up HTTP server via MeshApp
        let app = self.create_mesh_app();
        app.run_tcp_server().await?;

        Ok(())
    }

    /// Run the HTTP server on UDS socket
    pub async fn run_uds_server(&self) -> Result<(), Box<dyn std::error::Error>> {
        let (tx, _rx) = tokio::sync::mpsc::channel(100);

        // Start monitoring
        self.proc_mon.start(true, true, Some(tx.clone()))?;

        let app = self.create_mesh_app();

        tokio::spawn(async move {
            if let Err(e) = app.run_uds_server().await {
                error!("UDS HTTP server error: {}", e);
            }
        });

        Ok(())
    }
}
