use anyhow::{Context, Result};
use lmesh::{LmeshService, LocalDiscovery};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::{Duration, sleep};
use tracing::{debug, error, warn};

const DEFAULT_ANNOUNCE_INTERVAL_SECS: u64 = 60;
const DEFAULT_STANDALONE_SOCKET: &str = "lmesh/mesh.sock";
const ANNOUNCE_INTERVAL_ENV: &str = "LMESH_ANNOUNCE_INTERVAL_SECS";
const CONTROL_SOCKET_ENV: &str = "LMESH_CONTROL_SOCKET";

#[tokio::main]
async fn main() -> Result<()> {
    let (trace_buffer, _trace_guard) = mesh::local_trace::init("lmesh");
    mesh::local_trace::serve("lmesh", trace_buffer);

    run_server().await
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
    let announce_interval = announce_interval();
    tokio::spawn(async move {
        loop {
            sleep(announce_interval).await;
            if let Err(e) = discovery_periodic.announce().await {
                warn!("Failed to send announcement: {}", e);
            }
        }
    });

    let listen_path = standalone_listen_path()?;
    let listen_path = listen_path.to_string_lossy().into_owned();
    let mut listener = mesh::server::MeshListener::new("lmesh", Some(&listen_path))
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

fn announce_interval() -> Duration {
    let secs = std::env::var(ANNOUNCE_INTERVAL_ENV)
        .ok()
        .and_then(|value| parse_announce_interval_secs(&value));
    Duration::from_secs(secs.unwrap_or(DEFAULT_ANNOUNCE_INTERVAL_SECS))
}

fn parse_announce_interval_secs(value: &str) -> Option<u64> {
    let secs = value.trim().parse::<u64>().ok()?;
    (secs > 0).then_some(secs)
}

fn standalone_listen_path() -> Result<PathBuf> {
    let path = std::env::var_os(CONTROL_SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STANDALONE_SOCKET));
    resolve_relative_path(path)
}

fn resolve_relative_path(path: PathBuf) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .context("failed to resolve current working directory")?
            .join(path)
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    Ok(path)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_announce_interval_accepts_positive_seconds() {
        assert_eq!(parse_announce_interval_secs("5"), Some(5));
        assert_eq!(parse_announce_interval_secs(" 30 "), Some(30));
    }

    #[test]
    fn parse_announce_interval_rejects_zero_and_invalid_values() {
        assert_eq!(parse_announce_interval_secs("0"), None);
        assert_eq!(parse_announce_interval_secs("nope"), None);
    }

    #[test]
    fn resolve_relative_path_uses_cwd() {
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(
            resolve_relative_path(PathBuf::from("lmesh/mesh.sock")).unwrap(),
            cwd.join("lmesh").join("mesh.sock")
        );
    }
}
