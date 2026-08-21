//! Tagged-CBOR stream sessions shared by UDS and reliable mesh bearers.
//!
//! The session is deliberately transport-neutral: UDS, a QUIC-lite stream, or
//! an in-memory test connection provide the same `AsyncRead + AsyncWrite`
//! contract. Text/JSON gateways live outside this path.

use std::io::ErrorKind;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::cbor::{
    MAX_RECORD_LEN, decode_record, decode_stream_frame, encode_record, encode_stream_frame,
};
use crate::tagged::{RecordKind, TaggedCatalog, TaggedRecord};

/// Restores bytes consumed only to choose a connection codec.
///
/// A service has to inspect its first byte to choose framed CBOR versus a
/// JSON/text gateway, but neither branch may lose that byte. This wrapper is
/// transport-neutral and works for a UDS, stdio, or a reliable QUIC stream.
pub struct PrefixedStream<S> {
    prefix: Option<u8>,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: u8, inner: S) -> Self {
        Self {
            prefix: Some(prefix),
            inner,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(prefix) = self.prefix.take() {
            buffer.put_slice(&[prefix]);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Common service dispatcher for a tagged-CBOR session.
#[async_trait::async_trait]
pub trait TaggedRecordHandler: Send + Sync {
    /// Return `None` for a one-way message. A request must return a response
    /// whose ID is the request ID; `serve_cbor_session` checks that invariant.
    async fn handle_record(&self, record: TaggedRecord) -> Result<Option<TaggedRecord>>;
}

/// Construct a correlated successful response.
pub fn response_ok(id: serde_json::Value, result: serde_json::Value) -> TaggedRecord {
    TaggedRecord {
        id: Some(id),
        result: Some(result),
        ..Default::default()
    }
}

/// Construct a correlated error response. Error payload shape remains a
/// service API decision, while the envelope stays mechanically recognizable.
pub fn response_error(id: serde_json::Value, error: serde_json::Value) -> TaggedRecord {
    TaggedRecord {
        id: Some(id),
        error: Some(error),
        ..Default::default()
    }
}

/// Deserialize a documented tagged request into an existing serde handler
/// struct. This is a host adapter: numeric IDs are resolved by the generated
/// catalog before serde sees the familiar method/field names. Firmware instead
/// consumes generated bounded CBOR readers from `dmesh-server`.
pub fn decode_typed_request<T>(catalog: &TaggedCatalog, record: &TaggedRecord) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    match record.kind()? {
        RecordKind::Request | RecordKind::Message => {}
        RecordKind::Response | RecordKind::Error => bail!("record is not a request"),
    }
    serde_json::from_value(catalog.to_jsonl(record)).context("deserialize tagged request")
}

/// Serialize a typed handler response into the correlated tagged envelope.
pub fn encode_typed_response<T>(request: &TaggedRecord, result: &T) -> Result<TaggedRecord>
where
    T: serde::Serialize,
{
    let id = request
        .id
        .clone()
        .context("one-way tagged message cannot receive a response")?;
    Ok(response_ok(id, serde_json::to_value(result)?))
}

/// Read one length-framed tagged-CBOR record. A clean EOF before a header is
/// normal; a partial header/body is an error rather than a desynchronization.
pub async fn read_cbor_record<S>(stream: &mut S) -> Result<Option<TaggedRecord>>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0_u8; 4];
    match stream.read_exact(&mut header).await {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let body_len = u32::from_be_bytes(header) as usize;
    if !(4..=MAX_RECORD_LEN).contains(&body_len) {
        bail!("invalid tagged-CBOR stream frame length {body_len}");
    }
    let mut frame = vec![0_u8; body_len + header.len()];
    frame[..4].copy_from_slice(&header);
    stream
        .read_exact(&mut frame[4..])
        .await
        .context("truncated tagged-CBOR stream frame")?;
    decode_record(decode_stream_frame(&frame)?)
        .context("decode tagged-CBOR stream record")
        .map(Some)
}

pub async fn write_cbor_record<S>(stream: &mut S, record: &TaggedRecord) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&encode_stream_frame(&encode_record(record)?)?)
        .await?;
    stream.flush().await?;
    Ok(())
}

/// Serve a CBOR-only control connection. This is the standard UDS and
/// QUIC-lite service loop; it intentionally does not fall back to a line
/// parser, so a programmatic bearer has one unambiguous wire protocol.
pub async fn serve_cbor_session<S, H>(stream: &mut S, handler: &H) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: TaggedRecordHandler,
{
    while let Some(request) = read_cbor_record(stream).await? {
        let request_kind = request.kind()?;
        let request_id = request.id.clone();
        let response = handler.handle_record(request).await?;
        match (request_kind, response) {
            (RecordKind::Request, Some(response)) => {
                if response.id != request_id
                    || !matches!(response.kind()?, RecordKind::Response | RecordKind::Error)
                {
                    bail!("tagged-CBOR handler returned an uncorrelated response");
                }
                write_cbor_record(stream, &response).await?;
            }
            (RecordKind::Request, None) => bail!("tagged-CBOR request did not receive a response"),
            (RecordKind::Message, None) => {}
            (RecordKind::Message, Some(_)) => {
                bail!("tagged-CBOR one-way message unexpectedly returned a response")
            }
            (RecordKind::Response | RecordKind::Error, _) => {
                bail!("tagged-CBOR server received a response envelope")
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use tokio::io::AsyncWriteExt;

    use super::*;
    use crate::tagged::NameOrTag;

    struct Echo;

    #[async_trait::async_trait]
    impl TaggedRecordHandler for Echo {
        async fn handle_record(&self, record: TaggedRecord) -> Result<Option<TaggedRecord>> {
            Ok(Some(response_ok(
                record.id.expect("request id"),
                json!({"echo": true}),
            )))
        }
    }

    #[tokio::test]
    async fn cbor_session_is_transport_neutral_and_correlates_replies() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move { serve_cbor_session(&mut server, &Echo).await });
        let request = TaggedRecord {
            component: NameOrTag::Tag(7),
            method: NameOrTag::Tag(2),
            id: Some(json!(41)),
            ..Default::default()
        };
        write_cbor_record(&mut client, &request).await.unwrap();
        let response = read_cbor_record(&mut client).await.unwrap().unwrap();
        assert_eq!(response.id, Some(json!(41)));
        assert_eq!(response.result, Some(json!({"echo": true})));
        client.shutdown().await.unwrap();
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn prefixed_stream_preserves_codec_selection_byte() {
        let (mut writer, reader) = tokio::io::duplex(64);
        writer.write_all(b"rest").await.unwrap();
        let mut reader = PrefixedStream::new(b'f', reader);
        let mut value = [0_u8; 5];
        reader.read_exact(&mut value).await.unwrap();
        assert_eq!(&value, b"frest");
    }

    #[derive(Debug, Deserialize, PartialEq, Serialize)]
    #[serde(tag = "method")]
    enum DemoRequest {
        #[serde(rename = "radio.check")]
        Check { channel: u8 },
    }

    #[test]
    fn typed_adapter_resolves_numeric_catalog_ids_before_serde() {
        let catalog = TaggedCatalog::from_tools_json(&json!([{
            "name": "radio.check",
            "x-component-index": 7,
            "x-method-index": 2,
            "inputSchema": {"properties": {
                "channel": {"x-protobuf-index": 1}
            }}
        }]))
        .unwrap();
        let request = TaggedRecord {
            component: NameOrTag::Tag(7),
            method: NameOrTag::Tag(2),
            id: Some(json!(4)),
            env: [(NameOrTag::Tag(1), json!(6))].into_iter().collect(),
            ..Default::default()
        };
        assert_eq!(
            decode_typed_request::<DemoRequest>(&catalog, &request).unwrap(),
            DemoRequest::Check { channel: 6 }
        );
        let response = encode_typed_response(&request, &json!({"ok": true})).unwrap();
        assert_eq!(response.id, Some(json!(4)));
        assert_eq!(response.result, Some(json!({"ok": true})));
    }
}
