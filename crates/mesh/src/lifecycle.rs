//! Common supervisor lifecycle notifications for mesh services.

use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::broadcast;
use tokio::time::{Duration, timeout};

pub use mesh_api::{LifecycleAction, LifecycleCause, LifecycleEvent};

fn lifecycle_bus() -> &'static broadcast::Sender<LifecycleEvent> {
    static BUS: OnceLock<broadcast::Sender<LifecycleEvent>> = OnceLock::new();
    BUS.get_or_init(|| broadcast::channel(32).0)
}

/// Subscribe to lifecycle events accepted by this process's mesh service.
pub fn subscribe() -> broadcast::Receiver<LifecycleEvent> {
    lifecycle_bus().subscribe()
}

pub(crate) fn publish(event: LifecycleEvent) -> usize {
    lifecycle_bus().send(event).unwrap_or(0)
}

/// Deliver one correlated lifecycle request to a service's mesh Unix socket.
pub async fn notify(socket_path: &Path, event: &LifecycleEvent) -> Result<()> {
    let response = timeout(Duration::from_millis(500), async {
        let stream = tokio::net::UnixStream::connect(socket_path)
            .await
            .with_context(|| format!("connect {}", socket_path.display()))?;
        let (read, mut write) = stream.into_split();
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "mesh-init-lifecycle",
            "method": "mesh.lifecycle",
            "params": event,
        });
        write.write_all(request.to_string().as_bytes()).await?;
        write.write_all(b"\n").await?;
        write.flush().await?;

        let mut response = String::new();
        BufReader::new(read).read_line(&mut response).await?;
        Result::<_, anyhow::Error>::Ok(response)
    })
    .await
    .context("lifecycle notification timed out")??;
    let value: serde_json::Value = serde_json::from_str(response.trim())?;
    if value.get("id")
        != Some(&serde_json::Value::String(
            "mesh-init-lifecycle".to_string(),
        ))
    {
        anyhow::bail!("service returned an uncorrelated lifecycle response");
    }
    if value.get("error").is_some() {
        anyhow::bail!("service rejected lifecycle notification: {value}");
    }
    if value.get("result").is_none() {
        anyhow::bail!("service lifecycle response has no result");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn notify_sends_correlated_json_rpc_to_service_socket() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("mesh.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut line = String::new();
            BufReader::new(read).read_line(&mut line).await.unwrap();
            let request: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
            assert_eq!(request["method"], "mesh.lifecycle");
            assert_eq!(request["params"]["action"], "unfreeze");
            write
                .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":\"mesh-init-lifecycle\",\"result\":{}}\n")
                .await
                .unwrap();
        });

        notify(
            &socket,
            &LifecycleEvent {
                action: LifecycleAction::Unfreeze,
                cause: LifecycleCause::External,
                observed: false,
            },
        )
        .await
        .unwrap();
        server.await.unwrap();
    }
}
