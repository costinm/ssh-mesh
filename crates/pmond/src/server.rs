use crate::{PmondService, ProcMon};
use mesh::jsonl::McpRegistry;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, error};

/// Configuration for the Pmon server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Refresh interval in seconds for monitoring
    pub refresh_interval: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            refresh_interval: 10,
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

    /// Run the JSON-lines server on an activated UDS socket or stdio.
    pub async fn run_uds_server(&self) -> Result<(), Box<dyn std::error::Error>> {
        debug!(
            refresh_interval = self.config.refresh_interval,
            "starting pmond JSONL server"
        );
        let (tx, _rx) = tokio::sync::mpsc::channel(100);

        // Start monitoring
        self.proc_mon.start(true, true, Some(tx.clone()))?;

        let service = Arc::new(PmondService::new(self.proc_mon.clone()));
        let mcp = Arc::new(pmond_mcp_registry());
        let mut listener = mesh::server::MeshListener::new("pmond", None)?;
        while let Some(stream) = listener.accept().await? {
            let service = service.clone();
            let mcp = mcp.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_jsonl_connection(stream, service, mcp).await {
                    error!("pmond JSONL connection error: {}", e);
                }
            });
        }

        Ok(())
    }
}

fn pmond_mcp_registry() -> McpRegistry {
    let tools =
        serde_json::from_str(include_str!("../resources/tools.json")).unwrap_or_else(|_| json!([]));
    McpRegistry::new("pmond")
        .with_tools_json(tools)
        .with_instructions(
            "Use tools/call with pmond tool names to inspect processes, cgroups, and PSI state.",
        )
}

async fn handle_jsonl_connection(
    stream: mesh::server::MeshStream,
    service: Arc<PmondService>,
    mcp: Arc<McpRegistry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;
        if bytes_read == 0 {
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let service = service.clone();
        let (format, response) = mesh::jsonl::dispatch_request(trimmed, &mcp, move |request| {
            let service = service.clone();
            async move {
                debug!(?request, "pmond JSONL request");
                service.handle_request(request).await
            }
        })
        .await;
        let Some(response) = response else {
            continue;
        };
        let response = mesh::jsonl::format_response(response, &format)?;
        let stream = reader.get_mut();
        stream.write_all(response.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tools_list_uses_recovered_pmond_tools() {
        let registry = pmond_mcp_registry();
        let (_format, response) = mesh::jsonl::dispatch_request::<crate::Request, _, _>(
            r#"{"method":"tools/list"}"#,
            &registry,
            |_| async { mesh::protocol::Response::err("unexpected native call") },
        )
        .await;

        let data = response.unwrap().data.unwrap();
        let tools = data["tools"].as_array().unwrap();
        assert!(tools.iter().any(|tool| {
            tool["name"] == "get_process"
                && tool["description"] == "Get details of a specific process by PID"
                && tool["inputSchema"]["properties"]["pid"]["type"] == "integer"
        }));
        assert!(tools.iter().any(|tool| {
            tool["name"] == "psi_watches"
                && tool["description"] == "Get current PSI (Pressure Stall Information) watches"
        }));
    }

    #[tokio::test]
    async fn tools_call_maps_recovered_name_to_native_request() {
        let registry = pmond_mcp_registry();
        let (_format, response) = mesh::jsonl::dispatch_request::<crate::Request, _, _>(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_process","arguments":{"pid":123}}}"#,
            &registry,
            |request| async move {
                match request {
                    crate::Request::Process { pid } => {
                        mesh::protocol::Response::ok_with_data(json!({ "pid": pid }))
                    }
                    other => mesh::protocol::Response::err(format!("unexpected request: {other:?}")),
                }
            },
        )
        .await;

        let data = response.unwrap().data.unwrap();
        assert_eq!(data["structuredContent"]["pid"], 123);
        assert_eq!(data["isError"], false);
    }
}
