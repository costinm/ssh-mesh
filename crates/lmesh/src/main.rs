use anyhow::{Context, Result};
use clap::Parser;
use lmesh::{LmeshService, LocalDiscovery, NodeInfo};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::{Duration, sleep};
use tracing::{debug, error, warn};

#[derive(Parser, Debug)]
#[clap(name = "lmesh", version = "0.1.0")]
struct Args {
    /// Run in client mode to discover nodes
    #[arg(long)]
    client: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let (trace_buffer, _trace_guard) = mesh::local_trace::init("lmesh");
    mesh::local_trace::serve("lmesh", trace_buffer);

    if args.client {
        run_client().await?;
    } else {
        run_server().await?;
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
        for node in nodes_map.into_values().map(NodeInfo::from) {
            println!("- Public Key: {}", node.public_key);
            println!("  Address:    {}", node.address);
            if let Some(meta) = node.metadata {
                println!("  Metadata:   {:?}", meta);
            }
        }
    }
    Ok(())
}

async fn run_server() -> Result<()> {
    let mut discovery = LocalDiscovery::new(None).await?;
    discovery.start().await?;
    discovery.announce().await?;

    let discovery = Arc::new(discovery);
    let service = Arc::new(LmeshService::new(discovery.clone()));
    debug!(
        public_key = %service.public_key_b64(),
        "service_started"
    );

    let discovery_periodic = discovery.clone();
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(60)).await;
            if let Err(e) = discovery_periodic.announce().await {
                warn!("Failed to send announcement: {}", e);
            }
        }
    });

    let mut listener = mesh::server::MeshListener::new("lmesh", None)
        .map_err(|e| anyhow::anyhow!("lmesh listener error: {}", e))?;
    let mcp = Arc::new(mesh::jsonl::McpRegistry::new("lmesh"));
    while let Some(stream) = listener
        .accept()
        .await
        .map_err(|e| anyhow::anyhow!("lmesh accept error: {}", e))?
    {
        let service = service.clone();
        let mcp = mcp.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, service, mcp).await {
                error!("lmesh JSONL connection error: {}", e);
            }
        });
    }

    Ok(())
}

async fn handle_connection(
    stream: mesh::server::MeshStream,
    service: Arc<LmeshService>,
    mcp: Arc<mesh::jsonl::McpRegistry>,
) -> Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader
            .read_line(&mut line)
            .await
            .context("failed to read JSONL request")?;
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
                debug!(?request, "lmesh JSONL request");
                service.handle_request(request).await
            }
        })
        .await;
        let Some(response) = response else {
            continue;
        };

        let response = mesh::jsonl::format_response(response, &format)?;
        writer
            .write_all(response.as_bytes())
            .await
            .context("failed to write JSONL response")?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }

    Ok(())
}
