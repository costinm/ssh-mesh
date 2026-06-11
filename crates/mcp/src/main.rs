//! MCP server binary for pmond.
//!
//! This binary provides standalone MCP server access to the process monitor.
//! It can run in STDIO mode (for integration with MCP clients) or UDS mode.

use clap::Parser;
use mcp::run_mcp_server;
use pmond::ProcMon;
use std::fs::OpenOptions;
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
    let filter = EnvFilter::from_default_env();
    let log_path = std::env::var("MESH_LOG_FILE").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        format!("{}/.run/mcp-pmond/mcp-pmond.log", home)
    });

    if let Some(parent) = std::path::Path::new(&log_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    if let Ok(file) = OpenOptions::new().create(true).append(true).open(&log_path) {
        let out_layer = tracing_subscriber::fmt::layer()
            .compact()
            .with_writer(move || file.try_clone().expect("clone mcp-pmond log file"));
        Registry::default().with(filter).with(out_layer).init();
    } else {
        Registry::default().with(filter).init();
    }
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
