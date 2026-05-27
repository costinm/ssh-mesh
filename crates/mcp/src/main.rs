//! MCP server binary for pmond.
//!
//! This binary provides standalone MCP server access to the process monitor.
//! It can run in STDIO mode (for integration with MCP clients) or UDS mode.

use clap::Parser;
use mcp::run_mcp_server;
use pmond::ProcMon;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

#[derive(Parser, Debug)]
#[clap(name = "mcp-pmond", version = "0.1.0")]
struct Args {
    /// Run MCP server in STDIO mode (for MCP client integration)
    #[clap(long = "stdio")]
    stdio: bool,

    /// Run MCP server via UDS at the specified path
    #[clap(long = "uds", value_name = "PATH")]
    uds: Option<String>,

    /// Authorized UID for UDS connections (legacy, prefer auth.toml)
    #[clap(long = "auth-uid", value_name = "UID")]
    auth_uid: Option<u32>,
}

fn init_telemetry() {
    let out_layer = tracing_subscriber::fmt::layer().compact();
    Registry::default()
        .with(EnvFilter::from_default_env())
        .with(out_layer)
        .init();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Only initialize telemetry for UDS mode (stdio uses stdin/stdout for protocol)
    if !args.stdio {
        init_telemetry();
    }

    // Create the process monitor
    let proc_mon = ProcMon::new()?;
    let proc_mon = Arc::new(proc_mon);

    // Start monitoring
    proc_mon.start(true, true, None)?;

    if args.stdio {
        run_mcp_server(proc_mon, None).await?;
    } else {
        let path = args.uds.unwrap_or_else(|| "control.sock".to_string());
        info!("Starting MCP UDS server on {}", path);
        run_mcp_server(proc_mon, Some(&path)).await?;
    }

    Ok(())
}
