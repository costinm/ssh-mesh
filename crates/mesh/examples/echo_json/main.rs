//! JSON-RPC/Serde variant of the socket-activated echo service.

use std::sync::Arc;

use anyhow::Result;
use mesh::protocol::Response;
use mesh::registry::ServiceRegistry;
use mesh::server::{MeshListener, MeshStream};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Deserialize)]
#[serde(tag = "method")]
enum Request {
    #[serde(rename = "echo.echo")]
    Echo { value: String },
}

async fn serve(stream: MeshStream, registry: Arc<ServiceRegistry>) -> Result<()> {
    let (read, mut write) = tokio::io::split(stream);
    let mut lines = BufReader::new(read).lines();
    while let Some(line) = lines.next_line().await? {
        let (format, response) = mesh::jsonl::dispatch_request(&line, &registry, |request| async {
            match request {
                Request::Echo { value } => {
                    Response::ok_with_data(serde_json::json!({ "value": value }))
                }
            }
        })
        .await;
        if let Some(response) = response {
            write
                .write_all(mesh::jsonl::format_response(response, &format)?.as_bytes())
                .await?;
            write.write_all(b"\n").await?;
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (_log_buffer, _trace_guard) = mesh::local_trace::init("echo-json");
    let registry =
        Arc::new(ServiceRegistry::new("echo-json").with_server_title("JSON-RPC mesh echo example"));
    let mut listener = MeshListener::new("echo-json", None)?;
    while let Some(stream) = listener.accept().await? {
        let registry = Arc::clone(&registry);
        tokio::spawn(async move {
            if let Err(error) = serve(stream, registry).await {
                tracing::warn!(%error, "echo_json_connection_failed");
            }
        });
    }
    Ok(())
}
