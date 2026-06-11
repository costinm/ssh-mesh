use anyhow::Result;
use axum::{Extension, Json, Router, routing::post};
use clap::Parser;
use lmesh::LocalDiscovery;
use mesh::server::run_axum_server;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::{Duration, sleep};
use tracing::{error, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

#[derive(Parser, Debug)]
#[clap(name = "lmesh", version = "0.1.0")]
struct Args {
    /// Run in client mode to discover nodes
    #[arg(long)]
    client: bool,

    /// UDS path for the server to listen on
    #[arg(long)]
    uds: Option<String>,

    /// Authorized UID for UDS connections (legacy, prefer auth.toml)
    #[arg(long)]
    authorized_uid: Option<u32>,
}

fn init_telemetry() {
    let filter = EnvFilter::from_default_env();
    let log_path = std::env::var("MESH_LOG_FILE").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        format!("{}/.run/lmesh/lmesh.log", home)
    });

    if let Some(parent) = std::path::Path::new(&log_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    if let Ok(file) = OpenOptions::new().create(true).append(true).open(&log_path) {
        let out_layer = tracing_subscriber::fmt::layer()
            .compact()
            .with_writer(move || file.try_clone().expect("clone lmesh log file"));
        Registry::default().with(filter).with(out_layer).init();
    } else {
        Registry::default().with(filter).init();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_telemetry();

    if args.client {
        run_client().await?;
    } else {
        run_server(args).await?;
    }

    Ok(())
}

async fn run_client() -> Result<()> {
    let mut discovery = LocalDiscovery::new(None).await?;
    discovery.start().await?;
    discovery.announce().await?;

    sleep(Duration::from_secs(1)).await;
    let nodes_map = discovery.get_nodes().await;
    if !nodes_map.is_empty() {
        println!("Discovered {} node(s):", nodes_map.len());
        for (_, node) in nodes_map {
            println!("- Public Key: {}", node.public_key);
            println!("  Address:    {}", node.address);
            if let Some(meta) = node.metadata {
                println!("  Metadata:   {:?}", meta);
            }
        }
        return Ok(());
    }
    Ok(())
}

#[derive(Serialize)]
struct NodeInfo {
    public_key: String,
    address: SocketAddr,
    metadata: Option<HashMap<String, String>>,
}

async fn run_server(args: Args) -> Result<()> {
    let mut discovery = LocalDiscovery::new(None).await?;
    discovery.start().await?;

    let discovery_clone = Arc::new(discovery);

    // Periodically announce
    let discovery_periodic = discovery_clone.clone();
    tokio::spawn(async move {
        loop {
            if let Err(e) = discovery_periodic.announce().await {
                warn!("Failed to send announcement: {}", e);
            }
            sleep(Duration::from_secs(60)).await;
        }
    });

    let app = Router::new()
        .route("/nodes", post(handle_get_nodes))
        .route("/announce", post(handle_announce))
        .layer(Extension(discovery_clone));

    run_axum_server("lmesh", args.uds.as_deref(), app)
        .await
        .map_err(|e| anyhow::anyhow!("UDS server error: {}", e))?;

    Ok(())
}

async fn handle_get_nodes(
    Extension(discovery): Extension<Arc<LocalDiscovery>>,
) -> Json<Vec<NodeInfo>> {
    let nodes_map = discovery.get_nodes().await;
    let infos: Vec<NodeInfo> = nodes_map
        .into_values()
        .map(|node| NodeInfo {
            public_key: node.public_key,
            address: node.address,
            metadata: node.metadata,
        })
        .collect();
    Json(infos)
}

async fn handle_announce(Extension(discovery): Extension<Arc<LocalDiscovery>>) -> Json<bool> {
    match discovery.announce().await {
        Ok(_) => Json(true),
        Err(e) => {
            error!("Handle announce error: {}", e);
            Json(false)
        }
    }
}
