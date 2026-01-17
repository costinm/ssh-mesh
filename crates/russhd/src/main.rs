use std::path::PathBuf;
use std::env;
use log::{info, error};
use tracing_subscriber;
use anyhow::Error;

use russhd::{run_ssh_server, SshServer, get_port_from_env};

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Get SSH port from environment variable or use default
    let ssh_port = get_port_from_env("SSH_PORT", 2222);

    // Get base directory from environment or use home directory as default
    let base_dir = env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"));

    info!("Starting SSH server on port {} with base directory: {:?}", ssh_port, base_dir);

    // Create SSH server instance
    let server = SshServer::new(0, None, base_dir);
    let config = server.get_config();

    // Run the SSH server
    if let Err(e) = run_ssh_server(ssh_port, config, server).await {
        error!("SSH server failed: {}", e);
        return Err(e);
    }

    Ok(())
}