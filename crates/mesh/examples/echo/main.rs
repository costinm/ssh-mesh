//! Minimal native-minicbor socket-activated mesh service.

use std::sync::Arc;

use anyhow::{Result, bail};
use mesh::registry::ServiceRegistry;
use mesh::server::MeshListener;
use mesh::tagged::{NameOrTag, TaggedRecord};
use mesh::wire::{
    TaggedRecordHandler, decode_minicbor_request, encode_minicbor_response, serve_cbor_session,
};
use minicbor::{Decode, Encode};

#[derive(Decode)]
#[cbor(map)]
struct EchoRequest {
    #[n(1)]
    value: String,
}

#[derive(Encode)]
#[cbor(map)]
struct EchoResponse {
    #[n(1)]
    value: String,
}

struct Echo {
    registry: ServiceRegistry,
}

#[async_trait::async_trait]
impl TaggedRecordHandler for Echo {
    async fn handle_record(&self, request: TaggedRecord) -> Result<Option<TaggedRecord>> {
        if let Some(response) = self.registry.dispatch_tagged(&request).await? {
            return Ok(Some(response));
        }

        if request.component != NameOrTag::Name("echo".into())
            || request.method != NameOrTag::Name("echo".into())
        {
            bail!("unknown method");
        }

        let EchoRequest { value } = decode_minicbor_request(&request)?;
        Ok(Some(encode_minicbor_response(
            &request,
            EchoResponse { value },
        )?))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (_log_buffer, _trace_guard) = mesh::local_trace::init("echo");
    let service = Arc::new(Echo {
        registry: ServiceRegistry::new("echo").with_server_title("Minimal mesh echo example"),
    });

    let mut listener = MeshListener::new("echo", None)?;
    while let Some(mut stream) = listener.accept().await? {
        let service = Arc::clone(&service);
        tokio::spawn(async move {
            if let Err(error) = serve_cbor_session(&mut stream, service.as_ref()).await {
                tracing::warn!(%error, "echo_connection_failed");
            }
        });
    }
    Ok(())
}
