//! MCP server implementations for various transports.
//!
//! This module provides server functions for running MCP over:
//! - HTTP (StreamableHttpService for embedding in Axum)
//! - STDIO (for command-line MCP clients)
//! - Unix Domain Sockets (for local IPC)

use crate::handler::PmonMcpHandler;

use pmond::ProcMon;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use rmcp::ServiceExt;

use std::sync::Arc;
use tracing::{error, info};

/// Creates an MCP StreamableHttpService that can be nested into an Axum router.
///
/// This handles the MCP streamable HTTP protocol - streaming events and JSON-RPC
/// calls. This is backed by a local session manager - will not work well
/// with a load balancer without sticky sessions or some other routing to
/// a specific host, which makes sense since the process is specific to a host.
///
/// It is likely better to use a H2 stream using the stdio protocol - and have the
/// load balancers and some external box handle the strange MCP HTTP/1.1 protocol.
///
/// Even better to use a local stdio server that tunnels over SSH or H2 to
/// the server-stdio server.
pub fn mcp_service(proc_mon: Arc<ProcMon>) -> StreamableHttpService<PmonMcpHandler> {
    let config = StreamableHttpServerConfig::default();
    let session_manager = Arc::new(LocalSessionManager::default());

    StreamableHttpService::new(
        move || Ok(PmonMcpHandler::new(proc_mon.clone())),
        session_manager,
        config,
    )
}
/// Run an MCP server.
/// Supports STDIO (inetd), LISTEN_FD (xinetd), or UDS (standalone) via MeshListener.
pub async fn run_mcp_server(
    proc_mon: Arc<ProcMon>,
    listen_path: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut listener = mesh::server::MeshListener::new("mcp-pmond", listen_path)?;

    while let Some(stream) = listener.accept().await? {
        let proc_mon_clone = proc_mon.clone();
        
        tokio::spawn(async move {
            let handler = PmonMcpHandler::new(proc_mon_clone);
            let (read, write) = tokio::io::split(stream);
            
            // `serve()` takes an `AsyncRead + AsyncWrite` implementation.
            if let Err(e) = handler.serve((read, write)).await {
                error!("MCP session error: {}", e);
            } else {
                info!("MCP session ended");
            }
        });
    }
    
    Ok(())
}
