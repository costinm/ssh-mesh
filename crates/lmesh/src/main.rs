use anyhow::{bail, Result};
use axum::{routing::post, Extension, Json, Router};
use clap::Parser;
use lmesh::LocalDiscovery;
use mesh::uds::run_uds_server;
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};
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
    #[arg(long, default_value = "/tmp/lmesh.sock")]
    uds: String,

    /// Authorized UID for UDS connections
    #[arg(long)]
    authorized_uid: Option<u32>,
}

fn init_telemetry() {
    let out_layer = tracing_subscriber::fmt::layer().compact();
    Registry::default()
        .with(EnvFilter::from_default_env())
        .with(out_layer)
        .init();
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
    info!("Starting lmesh discovery client...");
    let mut discovery = LocalDiscovery::new(None).await?;
    discovery.start().await?;
    discovery.announce().await?;

    info!("Searching for nodes...");
    for i in 0..30 {
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
        if i % 10 == 0 && i > 0 {
            info!("Searching... ({}s elapsed)", i);
        }
        sleep(Duration::from_secs(1)).await;
    }
    bail!("No other nodes discovered after 30 seconds");
}

#[derive(Serialize)]
struct NodeInfo {
    public_key: String,
    address: SocketAddr,
    metadata: Option<HashMap<String, String>>,
}

async fn run_server(args: Args) -> Result<()> {
    info!("Starting lmesh server on {}...", args.uds);
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

    run_uds_server(app, &args.uds, args.authorized_uid)
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
