//! Transport-neutral outgoing mesh streams.
//!
//! A service opens a stream to a mesh node and exchanges its normal tagged-CBOR
//! payloads. It neither knows nor owns the transport association below that
//! stream: QUIC may reuse or create an association and choose a path, while
//! SSH and HTTP/2 can provide the same stream contract without an association.

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    tagged::{RecordKind, TaggedRecord},
    wire::{read_cbor_record, write_cbor_record},
};

pub use mesh_api::MeshTarget;
pub use quic_mux::tokio_mux::{MuxStream, TokioMux, TokioMuxAcceptor, TokioMuxConfig};

/// A reliable bidirectional byte stream selected by a [`MeshClient`].
///
/// The stream deliberately exposes no connection IDs, paths, socket details,
/// handshake state, or transport framing. Those are implementation details of
/// QUIC, SSH, HTTP/2, or a future bearer.
pub trait MeshStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> MeshStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

/// [`MeshClient`] backed by a [`quic_mux::tokio_mux::TokioMux`] session.
///
/// Multiplexes concurrent bidirectional [`MeshStream`]s (`MuxStream`) over one or more
/// underlying byte streams (UDS, TCP, TLS) or packet links attached to the `TokioMux`.
#[derive(Clone)]
pub struct QuicMuxClient {
    mux: TokioMux,
}

impl QuicMuxClient {
    /// Wrap an existing [`TokioMux`] handle as a [`MeshClient`].
    pub fn new(mux: TokioMux) -> Self {
        Self { mux }
    }

    /// Spawn a client [`TokioMux`] session over `stream` (`UnixStream`, `TcpStream`, etc.)
    /// with default [`TokioMuxConfig`].
    pub fn over_stream<S>(stream: S) -> (Self, TokioMuxAcceptor)
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        Self::over_stream_with_config(stream, TokioMuxConfig::default())
    }

    /// Spawn a client [`TokioMux`] session over `stream` with explicit [`TokioMuxConfig`].
    pub fn over_stream_with_config<S>(
        stream: S,
        config: TokioMuxConfig,
    ) -> (Self, TokioMuxAcceptor)
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (mux, acceptor) = TokioMux::client(stream, config);
        (Self { mux }, acceptor)
    }

    /// Connect to a Unix domain stream socket at `path` and initialize a client [`TokioMux`].
    pub async fn connect_uds(
        path: impl AsRef<std::path::Path>,
    ) -> Result<(Self, TokioMuxAcceptor)> {
        let stream = tokio::net::UnixStream::connect(path.as_ref())
            .await
            .with_context(|| format!("connect quic-mux UDS {}", path.as_ref().display()))?;
        Ok(Self::over_stream(stream))
    }

    /// Connect to a TCP address and initialize a client [`TokioMux`].
    pub async fn connect_tcp(addr: &str) -> Result<(Self, TokioMuxAcceptor)> {
        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .with_context(|| format!("connect quic-mux TCP {addr}"))?;
        let _ = stream.set_nodelay(true);
        Ok(Self::over_stream(stream))
    }

    /// Borrow the underlying [`TokioMux`] handle.
    pub fn mux(&self) -> &TokioMux {
        &self.mux
    }

    /// Open a bidirectional [`MuxStream`] directly on the underlying [`TokioMux`].
    pub async fn open_mux_stream(&self) -> Result<MuxStream> {
        self.mux
            .open_bidi()
            .await
            .context("open quic-mux bidirectional stream")
    }
}

#[async_trait::async_trait]
impl MeshClient for QuicMuxClient {
    async fn open_stream(&self, _target: &MeshTarget) -> Result<Box<dyn MeshStream>> {
        let stream = self.open_mux_stream().await?;
        Ok(Box::new(stream))
    }
}

/// Opens ordinary bidirectional streams to named mesh nodes.
///
/// A QUIC implementation may reuse a device association or create one when
/// absent, and may honour [`MeshTarget::path`] for that call. An SSH or HTTP/2
/// implementation opens its corresponding stream. Services such as DMesh
/// `probe` only receive the resulting [`MeshStream`]; they never acquire or
/// reattach an association.
#[async_trait::async_trait]
pub trait MeshClient: Send + Sync {
    async fn open_stream(&self, target: &MeshTarget) -> Result<Box<dyn MeshStream>>;
}

/// Send one correlated tagged-CBOR request over a normal mesh stream.
///
/// This is the compact request/reply convenience for handlers whose response
/// fits one tagged record. Streaming handlers open the same `MeshStream` and
/// use their documented stream framing directly.
pub async fn call_record<C>(client: &C, request: TaggedRecord) -> Result<TaggedRecord>
where
    C: MeshClient + ?Sized,
{
    if request.kind()? != RecordKind::Request {
        bail!("MeshClient call requires a correlated request record");
    }
    let destination = request
        .to
        .as_ref()
        .and_then(serde_json::Value::as_str)
        .context("MeshClient request is missing a string destination")?
        .to_owned();
    let destination = destination.as_str();
    let request_id = request.id.clone().expect("validated request ID");
    let target = MeshTarget::node(destination);
    let started = std::time::Instant::now();
    let allowance = request.timeout.map(std::time::Duration::from_millis);
    let expired = || {
        crate::wire::response_error(
            request_id.clone(),
            serde_json::json!({"error": "timeout", "to": destination}),
        )
    };
    // `to` selected this outgoing stream. Leaving it in the peer-facing
    // envelope would make a remote gateway interpret the request as another
    // forwarding hop instead of invoking its local registered handler.
    let mut request = request;
    request.to = None;
    let exchange = async {
        let mut stream = client.open_stream(&target).await?;
        // The peer gets what remains of the caller's time, so a chain of
        // forwarders never allows more than the original request did.
        if let Some(allowance) = allowance {
            request.timeout = Some(
                u64::try_from(allowance.saturating_sub(started.elapsed()).as_millis())
                    .unwrap_or(u64::MAX),
            );
        }
        write_cbor_record(&mut stream, &request).await?;
        read_cbor_record(&mut stream)
            .await?
            .context("mesh peer closed stream without a response")
    };
    let response = match allowance {
        None => exchange.await?,
        Some(allowance) => match tokio::time::timeout(allowance, exchange).await {
            Ok(response) => response?,
            Err(_) => return Ok(expired()),
        },
    };
    if response.id != Some(request_id)
        || !matches!(response.kind()?, RecordKind::Response | RecordKind::Error)
    {
        bail!("mesh peer returned an uncorrelated response");
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use anyhow::Result;
    use serde_json::json;
    use tokio::io::DuplexStream;

    use super::*;
    use crate::{tagged::NameOrTag, wire::response_ok};

    struct InMemoryClient(Mutex<Option<DuplexStream>>);

    #[async_trait::async_trait]
    impl MeshClient for InMemoryClient {
        async fn open_stream(&self, target: &MeshTarget) -> Result<Box<dyn MeshStream>> {
            if target != &MeshTarget::node("e7") {
                bail!("unexpected target {target:?}");
            }
            let stream = self
                .0
                .lock()
                .expect("test mutex")
                .take()
                .context("test stream already opened")?;
            Ok(Box::new(stream))
        }
    }

    #[tokio::test]
    async fn record_call_uses_a_transport_neutral_stream_and_checks_correlation() {
        let (client_stream, mut peer_stream) = tokio::io::duplex(2048);
        let peer = tokio::spawn(async move {
            let request = read_cbor_record(&mut peer_stream).await?.expect("request");
            assert_eq!(request.to, None, "destination is client routing metadata");
            write_cbor_record(
                &mut peer_stream,
                &response_ok(request.id.expect("request id"), json!({"ok": true})),
            )
            .await
        });
        let client = InMemoryClient(Mutex::new(Some(client_stream)));
        let response = call_record(
            &client,
            TaggedRecord {
                component: NameOrTag::Name("telemetry".to_owned()),
                method: NameOrTag::Name("status".to_owned()),
                id: Some(json!(7)),
                to: Some(json!("e7")),
                ..Default::default()
            },
        )
        .await
        .expect("correlated response");
        peer.await.expect("peer task").expect("peer response");
        assert_eq!(response.result, Some(json!({"ok": true})));
    }

    #[tokio::test]
    async fn the_peer_gets_the_remaining_time_and_a_silent_peer_times_out() {
        let request = |timeout| TaggedRecord {
            component: NameOrTag::Name("telemetry".to_owned()),
            method: NameOrTag::Name("status".to_owned()),
            id: Some(json!(7)),
            to: Some(json!("e7")),
            timeout,
            ..Default::default()
        };
        // The peer sees the allowance, minus the time already used.
        let (client_stream, mut peer_stream) = tokio::io::duplex(2048);
        let peer = tokio::spawn(async move {
            let request = read_cbor_record(&mut peer_stream).await?.expect("request");
            let remaining = request.timeout.expect("timeout is forwarded");
            assert!(remaining <= 5_000 && remaining > 0, "{remaining}");
            write_cbor_record(
                &mut peer_stream,
                &response_ok(request.id.expect("request id"), json!({"ok": true})),
            )
            .await
        });
        let client = InMemoryClient(Mutex::new(Some(client_stream)));
        call_record(&client, request(Some(5_000))).await.expect("response");
        peer.await.expect("peer task").expect("peer response");

        // A peer that never answers is abandoned when the allowance ends.
        let (client_stream, _silent_peer) = tokio::io::duplex(2048);
        let client = InMemoryClient(Mutex::new(Some(client_stream)));
        let response = call_record(&client, request(Some(30))).await.expect("timeout reply");
        assert_eq!(response.error.as_ref().unwrap()["error"], "timeout");
        assert_eq!(response.id, Some(json!(7)));
    }

    #[test]
    fn timeout_is_envelope_key_8_in_cbor_and_a_json_field() {
        let record = TaggedRecord {
            component: NameOrTag::Name("telemetry".to_owned()),
            method: NameOrTag::Name("status".to_owned()),
            id: Some(json!(1)),
            timeout: Some(2500),
            ..Default::default()
        };
        let wire = crate::cbor::encode_record(&record).unwrap();
        // 8 then 2500 (0x19 0x09c4) appears in the map.
        assert!(wire.windows(4).any(|w| w == [8, 0x19, 0x09, 0xc4]));
        assert_eq!(crate::cbor::decode_record(&wire).unwrap().timeout, Some(2500));
        assert_eq!(crate::tagged::to_json(&record, None)["timeout"], 2500);
        let parsed = crate::tagged::record_from_json(
            &json!({"component": "telemetry", "method": "status", "id": 1, "timeout": 2500}),
        )
        .unwrap();
        assert_eq!(parsed.timeout, Some(2500));
    }

    #[test]
    fn target_keeps_the_device_identity_when_a_path_is_forced() {
        let target = MeshTarget::node("e7").with_path("udp://[fe80::1%br-lan]");
        assert_eq!(target.node, "e7");
        assert_eq!(target.path.as_deref(), Some("udp://[fe80::1%br-lan]"));
        assert_eq!(
            serde_json::to_value(&target).expect("target JSON"),
            json!({"node": "e7", "path": "udp://[fe80::1%br-lan]"})
        );
    }

    #[tokio::test]
    async fn quic_mux_client_multiplexes_concurrent_cbor_streams_over_single_uds() {
        use crate::server::MeshListener;
        use crate::wire::{TaggedRecordHandler, serve_cbor_session};

        struct EchoHandler;

        #[async_trait::async_trait]
        impl TaggedRecordHandler for EchoHandler {
            async fn handle_record(&self, record: TaggedRecord) -> Result<Option<TaggedRecord>> {
                let seq = record
                    .env
                    .get(&NameOrTag::Name("seq".to_owned()))
                    .cloned()
                    .unwrap_or(json!(null));
                Ok(Some(response_ok(
                    record.id.expect("request id"),
                    json!({"echo_seq": seq, "method": record.method.text()}),
                )))
            }
        }

        let (client_uds, server_uds) = tokio::net::UnixStream::pair().expect("UnixStream::pair");
        let (client, _client_acceptor) = QuicMuxClient::over_stream(client_uds);
        let (_server_mux, mut server_acceptor) = MeshListener::spawn_quic_mux(server_uds);

        let server_task = tokio::spawn(async move {
            let mut stream_tasks = Vec::new();
            for _ in 0..8 {
                let mut stream = MeshListener::accept_quic_mux_stream(&mut server_acceptor)
                    .await
                    .expect("accept quic-mux stream");
                stream_tasks.push(tokio::spawn(async move {
                    serve_cbor_session(&mut stream, &EchoHandler)
                        .await
                        .expect("serve cbor session on mux stream");
                }));
            }
            for task in stream_tasks {
                task.await.expect("stream task");
            }
        });

        let mut call_tasks = Vec::new();
        for seq in 0..8u64 {
            let client = client.clone();
            call_tasks.push(tokio::spawn(async move {
                let req = TaggedRecord {
                    component: NameOrTag::Name("telemetry".to_owned()),
                    method: NameOrTag::Name("ping".to_owned()),
                    id: Some(json!(100 + seq)),
                    to: Some(json!("local-node")),
                    env: [(NameOrTag::Name("seq".to_owned()), json!(seq))]
                        .into_iter()
                        .collect(),
                    ..Default::default()
                };
                let resp = call_record(&client, req).await.expect("call_record");
                assert_eq!(resp.id, Some(json!(100 + seq)));
                assert_eq!(
                    resp.result,
                    Some(json!({"echo_seq": seq, "method": "ping"}))
                );
            }));
        }

        for task in call_tasks {
            task.await.expect("call task");
        }
        server_task.await.expect("server task");
    }
}
