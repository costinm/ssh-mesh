//! Tagged-CBOR stream sessions shared by UDS and reliable mesh bearers.
//!
//! The session is deliberately transport-neutral: UDS, a QUIC-lite stream, or
//! an in-memory test connection provide the same `AsyncRead + AsyncWrite`
//! contract. Text/JSON gateways live outside this path.

use std::io::{ErrorKind, Read};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::cbor::{MAX_RECORD_LEN, decode_record, decode_stream_frame, encode_record};
use crate::message::{TextRecord, format_text_response, quote_text_value};
use crate::tagged::{
    RecordKind, TaggedCatalog, TaggedRecord, record_from_json, record_from_value_translated,
    to_json, to_text,
};

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

    /// Route a request that names another mesh destination.
    ///
    /// The common session loop calls this instead of [`Self::handle_record`]
    /// whenever envelope key 9 (`to`) is present.  This prevents a local
    /// control service from accidentally applying a request intended for a
    /// device behind it.  A mesh service with a selected bearer overrides this
    /// method and forwards the original tagged record, including its binary
    /// `data` lane.  The default is deliberately a correlated error rather
    /// than a local fallback.
    async fn forward_record(&self, record: TaggedRecord) -> Result<Option<TaggedRecord>> {
        let id = record
            .id
            .context("directed tagged-CBOR request missing id")?;
        Ok(Some(response_error(
            id,
            serde_json::json!({
                "error": "mesh forwarding is unavailable for this service",
                "to": record.to,
            }),
        )))
    }
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

/// Deserialize a tagged request using a small handler-local field-tag table.
///
/// Host services normally keep component and method names on the wire. Only
/// request fields need numeric tags for compact CBOR, so a worker can use this
/// helper without embedding the generated discovery catalog. Gateways may
/// still load `tools.json` to translate other encodings and CLI arguments.
pub fn decode_typed_request_with_tags<T>(
    record: &TaggedRecord,
    field_tags: &[(&str, u32)],
) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    match record.kind()? {
        RecordKind::Request | RecordKind::Message => {}
        RecordKind::Response | RecordKind::Error => bail!("record is not a request"),
    }
    let mut value = crate::tagged::to_json(record, None);
    let fields = value
        .as_object_mut()
        .context("tagged request must decode to an object")?;
    for (name, tag) in field_tags {
        if let Some(value) = fields.remove(&format!("@{tag}")) {
            fields.entry((*name).to_string()).or_insert(value);
        }
    }
    serde_json::from_value(value).context("deserialize tagged request")
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

/// Serialize a typed response and replace selected object field names with
/// their numeric CBOR tags. This is the response-side counterpart to
/// [`decode_typed_request_with_tags`].
pub fn encode_typed_response_with_tags<T>(
    request: &TaggedRecord,
    result: &T,
    field_tags: &[(&str, u32)],
) -> Result<TaggedRecord>
where
    T: serde::Serialize,
{
    let id = request
        .id
        .clone()
        .context("one-way tagged message cannot receive a response")?;
    let mut value = serde_json::to_value(result)?;
    if let Some(fields) = value.as_object_mut() {
        for (name, tag) in field_tags {
            if let Some(value) = fields.remove(*name) {
                fields.insert(tag.to_string(), value);
            }
        }
    }
    Ok(response_ok(id, value))
}

/// Decode a request field map directly with a minicbor-derived type.
pub fn decode_minicbor_request<T>(record: &TaggedRecord) -> Result<T>
where
    T: for<'bytes> minicbor::Decode<'bytes, ()>,
{
    match record.kind()? {
        RecordKind::Request | RecordKind::Message => {}
        RecordKind::Response | RecordKind::Error => bail!("record is not a request"),
    }
    minicbor::decode(&crate::cbor::encode_record_fields(record)?)
        .context("decode native minicbor request")
}

/// Encode a minicbor-derived response into the correlated mesh envelope.
pub fn encode_minicbor_response<T>(request: &TaggedRecord, result: T) -> Result<TaggedRecord>
where
    T: minicbor::Encode<()>,
{
    let id = request
        .id
        .clone()
        .context("one-way tagged message cannot receive a response")?;
    let bytes = minicbor::to_vec(result).context("encode native minicbor response")?;
    Ok(response_ok(id, crate::cbor::decode_value_bytes(&bytes)?))
}

/// One self-delimiting CBOR stream message: the opening envelope (`record` + `raw_header`)
/// and any raw stream body bytes that follow before EOF (`body`).
#[derive(Clone, Debug, PartialEq)]
pub struct CborStreamFrame {
    pub record: TaggedRecord,
    pub raw_header: Vec<u8>,
    pub body: Vec<u8>,
}

/// Inspect a candidate self-delimiting CBOR map buffer: returns `Ok(Some(end))` when a
/// complete map has been buffered, `Ok(None)` when more bytes are needed, or `Err` on
/// invalid CBOR / oversize record.
fn probe_cbor_map_end(buf: &[u8]) -> Result<Option<usize>> {
    let mut dec = minicbor::Decoder::new(buf);
    match dec.skip() {
        Ok(()) => Ok(Some(dec.position())),
        Err(err) if err.is_end_of_input() => {
            if buf.len() >= MAX_RECORD_LEN {
                bail!("self-delimiting tagged-CBOR record exceeds {MAX_RECORD_LEN} bytes");
            }
            Ok(None)
        }
        Err(err) => {
            Err(anyhow::Error::new(err).context("invalid self-delimiting tagged-CBOR stream record"))
        }
    }
}

/// Read the raw CBOR bytes of one self-delimiting (or legacy 4-byte length-framed)
/// CBOR map header from an async byte stream without consuming trailing body bytes.
/// Returns `Ok(None)` on clean EOF before the first byte.
pub async fn read_cbor_header_bytes<S>(stream: &mut S) -> Result<Option<Vec<u8>>>
where
    S: AsyncRead + Unpin,
{
    let mut first = [0_u8; 1];
    match stream.read_exact(&mut first).await {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    if first[0] == 0 {
        let mut rest = [0_u8; 3];
        stream
            .read_exact(&mut rest)
            .await
            .context("truncated tagged-CBOR stream frame header")?;
        let header = [first[0], rest[0], rest[1], rest[2]];
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
        return Ok(Some(decode_stream_frame(&frame)?.to_vec()));
    }
    if (first[0] >> 5) != 5 {
        bail!(
            "invalid self-delimiting tagged-CBOR stream byte 0x{:02x}",
            first[0]
        );
    }
    let mut buf = vec![first[0]];
    loop {
        if let Some(end) = probe_cbor_map_end(&buf)? {
            buf.truncate(end);
            return Ok(Some(buf));
        }
        let mut byte = [0_u8; 1];
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            bail!("truncated self-delimiting tagged-CBOR stream record");
        }
        buf.push(byte[0]);
    }
}

/// Synchronous counterpart to [`read_cbor_header_bytes`] for blocking [`std::io::Read`]
/// transports (such as TCP recovery connections or serial adapters).
pub fn read_cbor_header_bytes_sync<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut first = [0_u8; 1];
    match reader.read_exact(&mut first) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    if first[0] == 0 {
        let mut rest = [0_u8; 3];
        reader
            .read_exact(&mut rest)
            .context("truncated tagged-CBOR stream frame header")?;
        let header = [first[0], rest[0], rest[1], rest[2]];
        let body_len = u32::from_be_bytes(header) as usize;
        if !(4..=MAX_RECORD_LEN).contains(&body_len) {
            bail!("invalid tagged-CBOR stream frame length {body_len}");
        }
        let mut frame = vec![0_u8; body_len + header.len()];
        frame[..4].copy_from_slice(&header);
        reader
            .read_exact(&mut frame[4..])
            .context("truncated tagged-CBOR stream frame")?;
        return Ok(Some(decode_stream_frame(&frame)?.to_vec()));
    }
    if (first[0] >> 5) != 5 {
        bail!(
            "invalid self-delimiting tagged-CBOR stream byte 0x{:02x}",
            first[0]
        );
    }
    let mut buf = vec![first[0]];
    loop {
        if let Some(end) = probe_cbor_map_end(&buf)? {
            buf.truncate(end);
            return Ok(Some(buf));
        }
        let mut byte = [0_u8; 1];
        let n = reader.read(&mut byte)?;
        if n == 0 {
            bail!("truncated self-delimiting tagged-CBOR stream record");
        }
        buf.push(byte[0]);
    }
}

/// Read one self-delimiting (or legacy 4-byte length-framed) tagged-CBOR record.
/// A clean EOF before the first byte is normal; a partial frame/record is an
/// error rather than a desynchronization.
pub async fn read_cbor_record<S>(stream: &mut S) -> Result<Option<TaggedRecord>>
where
    S: AsyncRead + Unpin,
{
    let Some(raw) = read_cbor_header_bytes(stream).await? else {
        return Ok(None);
    };
    decode_record(&raw)
        .context("decode self-delimiting tagged-CBOR stream record")
        .map(Some)
}

pub async fn write_cbor_record<S>(stream: &mut S, record: &TaggedRecord) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(&encode_record(record)?).await?;
    stream.flush().await?;
    Ok(())
}

/// Write one self-delimiting CBOR envelope header followed by an optional raw body
/// (`[CBOR map][raw body]`), then flush. Callers ending their direction follow with `shutdown()`.
pub async fn write_cbor_stream_frame<S>(
    stream: &mut S,
    record: &TaggedRecord,
    body: &[u8],
) -> Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    stream.write_all(&encode_record(record)?).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    stream.flush().await?;
    Ok(())
}

/// Read one self-delimiting CBOR envelope header and any trailing raw body up to EOF.
/// Returns `Ok(None)` on clean EOF before the opening byte.
pub async fn read_cbor_stream_frame<S>(stream: &mut S) -> Result<Option<CborStreamFrame>>
where
    S: AsyncRead + Unpin,
{
    let Some(raw_header) = read_cbor_header_bytes(stream).await? else {
        return Ok(None);
    };
    let record =
        decode_record(&raw_header).context("decode self-delimiting tagged-CBOR stream frame")?;
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await?;
    Ok(Some(CborStreamFrame {
        record,
        raw_header,
        body,
    }))
}

/// Execute one request/reply stream exchange (`[CBOR map][optional body][FIN]`) concurrently
/// so a streaming responder can begin replying while reading the request body.
pub async fn exchange_cbor_stream<S>(
    stream: &mut S,
    request: &TaggedRecord,
    body: &[u8],
) -> Result<CborStreamFrame>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let encoded = encode_record(request)?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let send = async {
        writer.write_all(&encoded).await?;
        if !body.is_empty() {
            writer.write_all(body).await?;
        }
        writer.flush().await?;
        writer.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };
    let recv = async {
        read_cbor_stream_frame(&mut reader)
            .await?
            .context("CBOR stream closed without a response envelope")
    };
    let ((), frame) = tokio::try_join!(send, recv)?;
    Ok(frame)
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
        let response = if request.to.is_some() {
            handler.forward_record(request).await?
        } else {
            handler.handle_record(request).await?
        };
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

#[derive(Clone, Copy, Eq, PartialEq)]
enum LineReplyEncoding {
    JsonRpc,
    Jsonl,
    Text,
}

fn text_scalar_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        _ => value.to_string(),
    }
}

fn parse_text_scalar(value: &str) -> Value {
    if value == "true" {
        return Value::Bool(true);
    }
    if value == "false" {
        return Value::Bool(false);
    }
    if value == "null" {
        return Value::Null;
    }
    if let Ok(int) = value.parse::<i64>() {
        return Value::from(int);
    }
    if let Ok(float) = value.parse::<f64>()
        && float.is_finite()
    {
        return Value::from(float);
    }
    if (value.starts_with('{') || value.starts_with('['))
        && let Ok(parsed) = serde_json::from_str::<Value>(value)
    {
        return parsed;
    }
    Value::String(value.to_owned())
}

/// Format a tagged request into a single structured-text command line
/// (`component.method key=value ...\n`), resolving numeric IDs through
/// `catalog` when available.
pub fn format_text_request_line(record: &TaggedRecord, catalog: Option<&TaggedCatalog>) -> String {
    let projected = to_json(record, catalog);
    let Some(object) = projected.as_object() else {
        return to_text(record);
    };
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        return to_text(record);
    };
    let mut parts = vec![quote_text_value(method)];
    for (key, value) in object {
        if matches!(key.as_str(), "method" | "id" | "result" | "error") {
            continue;
        }
        if key == "params"
            && let Some(items) = value.as_array()
        {
            for item in items {
                parts.push(quote_text_value(&text_scalar_string(item)));
            }
            continue;
        }
        let rendered = text_scalar_string(value);
        parts.push(format!("{key}={}", quote_text_value(&rendered)));
    }
    format!("{}\n", parts.join(" "))
}

/// Parse one structured-text reply line (`response ...` or `error ...`) into
/// a correlated [`TaggedRecord`].
pub fn parse_text_response_line(line: &str, id: Value) -> Result<TaggedRecord> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        bail!("empty structured-text response");
    }
    let text = TextRecord::parse(trimmed).context("parse structured-text response")?;
    let mut map = Map::new();
    for (key, value) in &text.fields {
        map.insert(key.clone(), parse_text_scalar(value));
    }
    if matches!(text.kind.as_str(), "error" | "err") {
        if !map.contains_key("message") && !text.args.is_empty() {
            map.insert("message".to_owned(), Value::String(text.args.join(" ")));
        }
        return Ok(response_error(id, Value::Object(map)));
    }
    if matches!(text.kind.as_str(), "response" | "ok" | "result") {
        if text.fields.get("success").is_some_and(|v| v == "false") {
            return Ok(response_error(id, Value::Object(map)));
        }
        if map.is_empty() && !text.args.is_empty() {
            map.insert("args".to_owned(), json_args_value(&text.args));
        } else if !text.args.is_empty() {
            map.insert("args".to_owned(), json_args_value(&text.args));
        }
        if map.len() > 1 {
            map.remove("success");
        }
        return Ok(response_ok(id, Value::Object(map)));
    }
    bail!("unexpected structured-text reply kind {:?}", text.kind)
}

fn json_args_value(args: &[String]) -> Value {
    Value::Array(args.iter().map(|arg| parse_text_scalar(arg)).collect())
}

fn format_text_reply_line(response: &TaggedRecord, catalog: Option<&TaggedCatalog>) -> String {
    let projected = catalog.map(|cat| cat.to_jsonl(response));
    let projected_result = projected
        .as_ref()
        .and_then(|val| val.get("result"))
        .or(response.result.as_ref());
    let projected_error = projected
        .as_ref()
        .and_then(|val| val.get("error"))
        .or(response.error.as_ref());
    if let Some(error) = projected_error {
        if let Some(message) = error.as_str() {
            return format_text_response(false, Some(message), None);
        }
        if error.is_object() {
            let mut text = TextRecord::from_json_object("error", error);
            if !text.fields.contains_key("message") {
                let fallback = error
                    .get("error")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(|| error.to_string());
                text = text.field("message", fallback);
            }
            return text.format();
        }
        return format_text_response(false, Some(&error.to_string()), None);
    }
    match projected_result {
        Some(value) if value.is_object() => format_text_response(true, None, Some(value)),
        Some(value) => TextRecord::from_json_object("response", value)
            .field("success", "true")
            .format(),
        None => format_text_response(true, None, None),
    }
}

fn parse_line_request(
    trimmed: &str,
    catalog: Option<&TaggedCatalog>,
    seq: &mut u64,
) -> Result<(TaggedRecord, LineReplyEncoding, bool)> {
    if trimmed.starts_with('{') {
        let value: Value = serde_json::from_str(trimmed).context("decode JSON line request")?;
        let object = value
            .as_object()
            .context("JSON line request must be an object")?;
        if let Some(version) = object.get("jsonrpc") {
            if version.as_str() != Some("2.0") {
                bail!("unsupported jsonrpc version {:?}", version);
            }
            let qualified = object
                .get("method")
                .and_then(Value::as_str)
                .context("JSON-RPC request missing string method")?;
            let (component, method) = qualified.split_once('.').unwrap_or(("", qualified));
            let params = match object.get("params") {
                Some(Value::Object(_)) => object["params"].clone(),
                Some(Value::Null) | None => Value::Object(Map::new()),
                Some(_) => bail!("JSON-RPC params must be an object"),
            };
            let mut record = record_from_value_translated(component, method, &params, catalog)?;
            record.id = object.get("id").cloned().filter(|v| !v.is_null());
            if let Some(to) = object.get("to") {
                record.to = Some(to.clone());
            }
            if let Some(timeout) = object.get("timeout").and_then(Value::as_u64) {
                record.timeout = Some(timeout);
            }
            return Ok((record, LineReplyEncoding::JsonRpc, false));
        }

        let mut record = if object.contains_key("component") && object.contains_key("method") {
            record_from_json(&value)?
        } else {
            let qualified = object
                .get("method")
                .and_then(Value::as_str)
                .context("JSONL request missing method")?;
            let (component, method) = qualified.split_once('.').unwrap_or(("", qualified));
            let mut params = Map::new();
            for (k, v) in object {
                if matches!(k.as_str(), "method" | "id" | "to" | "timeout" | "data") {
                    continue;
                }
                params.insert(k.clone(), v.clone());
            }
            let mut record = record_from_value_translated(
                component,
                method,
                &Value::Object(params),
                catalog,
            )?;
            record.id = object.get("id").cloned().filter(|v| !v.is_null());
            if let Some(to) = object.get("to") {
                record.to = Some(to.clone());
            }
            if let Some(timeout) = object.get("timeout").and_then(Value::as_u64) {
                record.timeout = Some(timeout);
            }
            record
        };
        let synthetic_id = if record.id.is_none() {
            *seq += 1;
            record.id = Some(Value::from(*seq));
            true
        } else {
            false
        };
        return Ok((record, LineReplyEncoding::Jsonl, synthetic_id));
    }

    let text = TextRecord::parse(trimmed).context("parse structured-text request")?;
    let mut explicit_id: Option<Value> = None;
    let mut argv = Vec::with_capacity(text.fields.len() + text.args.len());
    let has_schema_id = catalog
        .and_then(|cat| cat.method(&text.kind))
        .is_some_and(|schema| schema.fields.contains_key("id"));
    for (k, v) in &text.fields {
        let key = k.strip_prefix('-').unwrap_or(k);
        if key == "id" && !has_schema_id {
            explicit_id = Some(parse_text_scalar(v));
            continue;
        }
        argv.push(format!("{key}={v}"));
    }
    argv.extend(text.args.iter().cloned());
    let fallback_catalog;
    let effective_catalog = match catalog {
        Some(cat) => cat,
        None => {
            fallback_catalog = TaggedCatalog::default();
            &fallback_catalog
        }
    };
    let mut record = effective_catalog.parse_argv(&text.kind, &argv)?;
    let synthetic_id = if let Some(id) = explicit_id {
        record.id = Some(id);
        false
    } else {
        *seq += 1;
        record.id = Some(Value::from(*seq));
        true
    };
    Ok((record, LineReplyEncoding::Text, synthetic_id))
}

fn format_line_reply(
    response: &TaggedRecord,
    encoding: LineReplyEncoding,
    catalog: Option<&TaggedCatalog>,
) -> Result<String> {
    match encoding {
        LineReplyEncoding::JsonRpc => {
            let id = response.id.clone().unwrap_or(Value::Null);
            let mut map = Map::new();
            map.insert("jsonrpc".to_owned(), Value::String("2.0".to_owned()));
            map.insert("id".to_owned(), id);
            if let Some(result) = &response.result {
                map.insert("result".to_owned(), result.clone());
            } else if let Some(error) = &response.error {
                map.insert("error".to_owned(), error.clone());
            } else {
                bail!("JSON-RPC response missing result or error");
            }
            Ok(serde_json::to_string(&Value::Object(map))?)
        }
        LineReplyEncoding::Jsonl => Ok(serde_json::to_string(&to_json(response, catalog))?),
        LineReplyEncoding::Text => Ok(format_text_reply_line(response, catalog)),
    }
}

/// Serve a newline-delimited JSON-RPC / JSONL / structured-text session on
/// non-CBOR control ports and gateway listeners.
pub async fn serve_line_session<S, H>(
    stream: &mut S,
    handler: &H,
    catalog: Option<&TaggedCatalog>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: TaggedRecordHandler,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    let mut seq = 0_u64;
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (request, encoding, synthetic_id) = parse_line_request(trimmed, catalog, &mut seq)?;
        let request_kind = request.kind()?;
        let request_id = request.id.clone();
        let response = if request.to.is_some() {
            handler.forward_record(request).await?
        } else {
            handler.handle_record(request).await?
        };
        match (request_kind, response, synthetic_id) {
            (RecordKind::Request, Some(response), _) => {
                if response.id != request_id
                    || !matches!(response.kind()?, RecordKind::Response | RecordKind::Error)
                {
                    bail!("line handler returned an uncorrelated response");
                }
                let reply = format_line_reply(&response, encoding, catalog)?;
                write_half.write_all(reply.as_bytes()).await?;
                write_half.write_all(b"\n").await?;
                write_half.flush().await?;
            }
            (RecordKind::Request, None, true) | (RecordKind::Message, None, _) => {}
            (RecordKind::Request, None, false) => {
                bail!("line request did not receive a response")
            }
            (RecordKind::Message, Some(_), _) => {
                bail!("one-way line message unexpectedly returned a response")
            }
            (RecordKind::Response | RecordKind::Error, _, _) => {
                bail!("line server received a response envelope")
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

    struct MustNotExecuteDirected {
        invoked: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait::async_trait]
    impl TaggedRecordHandler for MustNotExecuteDirected {
        async fn handle_record(&self, _record: TaggedRecord) -> Result<Option<TaggedRecord>> {
            self.invoked
                .store(true, std::sync::atomic::Ordering::Release);
            Ok(None)
        }
    }

    #[tokio::test]
    async fn directed_record_never_reaches_the_local_handler() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let invoked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handler = MustNotExecuteDirected {
            invoked: invoked.clone(),
        };
        let server_task =
            tokio::spawn(async move { serve_cbor_session(&mut server, &handler).await });
        write_cbor_record(
            &mut client,
            &TaggedRecord {
                component: NameOrTag::Tag(7),
                method: NameOrTag::Tag(2),
                id: Some(json!(41)),
                to: Some(json!("e7")),
                data: Some(vec![0, 0xff]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let response = read_cbor_record(&mut client).await.unwrap().unwrap();
        assert_eq!(response.id, Some(json!(41)));
        assert!(response.error.is_some());
        assert!(!invoked.load(std::sync::atomic::Ordering::Acquire));
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

    #[test]
    fn named_method_decodes_tagged_fields_without_a_catalog() {
        let request = TaggedRecord {
            component: NameOrTag::Name("radio".to_string()),
            method: NameOrTag::Name("check".to_string()),
            id: Some(json!(4)),
            env: [(NameOrTag::Tag(1), json!(6))].into_iter().collect(),
            ..Default::default()
        };
        assert_eq!(
            decode_typed_request_with_tags::<DemoRequest>(&request, &[("channel", 1)]).unwrap(),
            DemoRequest::Check { channel: 6 }
        );
        let response = encode_typed_response_with_tags(
            &request,
            &serde_json::json!({"accepted": true}),
            &[("accepted", 1)],
        )
        .unwrap();
        assert_eq!(response.result, Some(json!({"1": true})));
    }

    #[derive(Debug, PartialEq, minicbor::Decode)]
    #[cbor(map)]
    struct NativeRequest {
        #[n(1)]
        value: String,
    }

    #[derive(minicbor::Encode)]
    #[cbor(map)]
    struct NativeResponse {
        #[n(1)]
        value: String,
    }

    #[test]
    fn minicbor_adapter_uses_derived_field_tags() {
        let request = TaggedRecord {
            component: NameOrTag::Name("echo".to_string()),
            method: NameOrTag::Name("echo".to_string()),
            id: Some(json!(9)),
            env: [(NameOrTag::Tag(1), json!("hello"))].into_iter().collect(),
            ..Default::default()
        };
        assert_eq!(
            decode_minicbor_request::<NativeRequest>(&request).unwrap(),
            NativeRequest {
                value: "hello".to_string()
            }
        );
        let response = encode_minicbor_response(
            &request,
            NativeResponse {
                value: "hello".to_string(),
            },
        )
        .unwrap();
        assert_eq!(response.id, Some(json!(9)));
        assert_eq!(response.result, Some(json!({"1": "hello"})));
    }

    struct CaptureLineEcho;

    #[async_trait::async_trait]
    impl TaggedRecordHandler for CaptureLineEcho {
        async fn handle_record(&self, record: TaggedRecord) -> Result<Option<TaggedRecord>> {
            let Some(id) = record.id.clone() else {
                return Ok(None);
            };
            Ok(Some(response_ok(
                id,
                json!({
                    "component": record.component.text(),
                    "method": record.method.text(),
                    "channel": record.env.get(&NameOrTag::Name("channel".to_owned())).cloned(),
                }),
            )))
        }
    }

    #[tokio::test]
    async fn line_session_handles_jsonrpc_jsonl_and_structured_text() {
        let (client, mut server) = tokio::io::duplex(8192);
        let server_task =
            tokio::spawn(async move { serve_line_session(&mut server, &CaptureLineEcho, None).await });

        let (read_half, mut write_half) = tokio::io::split(client);
        let mut reader = BufReader::new(read_half);
        let mut reply = String::new();

        // 1. JSON-RPC 2.0 request
        write_half
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"radio.check\",\"params\":{\"channel\":6}}\n")
            .await
            .unwrap();
        write_half.flush().await.unwrap();
        reply.clear();
        reader.read_line(&mut reply).await.unwrap();
        let rpc: Value = serde_json::from_str(reply.trim()).unwrap();
        assert_eq!(rpc["jsonrpc"], "2.0");
        assert_eq!(rpc["id"], 10);
        assert_eq!(rpc["result"]["channel"], 6);

        // 2. Flat JSONL request
        write_half
            .write_all(b"{\"method\":\"radio.check\",\"id\":11,\"channel\":44}\n")
            .await
            .unwrap();
        write_half.flush().await.unwrap();
        reply.clear();
        reader.read_line(&mut reply).await.unwrap();
        let jsonl: Value = serde_json::from_str(reply.trim()).unwrap();
        assert_eq!(jsonl["id"], 11);
        assert_eq!(jsonl["result"]["channel"], 44);

        // 3. Structured text request (and directed forwarding error as text)
        let req = TaggedRecord {
            component: NameOrTag::Name("radio".to_owned()),
            method: NameOrTag::Name("check".to_owned()),
            id: Some(json!(12)),
            env: [(NameOrTag::Name("channel".to_owned()), json!(149))]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let req_line = format_text_request_line(&req, None);
        assert_eq!(req_line, "radio.check channel=149\n");
        write_half.write_all(req_line.as_bytes()).await.unwrap();
        write_half.flush().await.unwrap();
        reply.clear();
        reader.read_line(&mut reply).await.unwrap();
        let parsed = parse_text_response_line(&reply, json!(12)).unwrap();
        assert_eq!(parsed.result.as_ref().unwrap()["channel"], 149);
        assert_eq!(parsed.result.as_ref().unwrap()["component"], "radio");

        write_half
            .write_all(b"radio.check to=e7 channel=6\n")
            .await
            .unwrap();
        write_half.flush().await.unwrap();
        reply.clear();
        reader.read_line(&mut reply).await.unwrap();
        let err_parsed = parse_text_response_line(&reply, json!(13)).unwrap();
        assert!(err_parsed.error.is_some());

        let mut client = reader.into_inner().unsplit(write_half);
        client.shutdown().await.unwrap();
        server_task.await.unwrap().unwrap();
    }

    async fn serve_cbor_echo_stream<S>(mut stream: S) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let frame = read_cbor_stream_frame(&mut stream)
            .await?
            .context("expected CBOR request frame")?;
        let reply = response_ok(
            frame.record.id.clone().context("request id")?,
            json!({
                "component": frame.record.component.text(),
                "method": frame.record.method.text(),
                "body_len": frame.body.len(),
            }),
        );
        let mut echoed_body = b"ack:".to_vec();
        echoed_body.extend_from_slice(&frame.body);
        write_cbor_stream_frame(&mut stream, &reply, &echoed_body).await?;
        stream.shutdown().await?;
        Ok(())
    }

    fn encode_ppp_record(port: u8, payload: &[u8]) -> Vec<u8> {
        let mut wire = Vec::with_capacity(payload.len() + 8);
        wire.push(0x7e);
        for byte in std::iter::once(port).chain(payload.iter().copied()) {
            if byte == 0x7e || byte == 0x7d {
                wire.push(0x7d);
                wire.push(byte ^ 0x20);
            } else {
                wire.push(byte);
            }
        }
        wire.push(0x7e);
        wire
    }

    fn decode_ppp_records(wire: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut records = Vec::new();
        let mut in_frame = false;
        let mut escaped = false;
        let mut current = Vec::new();
        for &byte in wire {
            if byte == 0x7e {
                if in_frame && !current.is_empty() {
                    let port = current.remove(0);
                    records.push((port, std::mem::take(&mut current)));
                }
                current.clear();
                in_frame = true;
                escaped = false;
                continue;
            }
            if !in_frame {
                continue;
            }
            if escaped {
                current.push(byte ^ 0x20);
                escaped = false;
            } else if byte == 0x7d {
                escaped = true;
            } else {
                current.push(byte);
            }
        }
        records
    }

    fn encode_ble_coc_chunks(sdu: &[u8], att_chunk: usize) -> Vec<Vec<u8>> {
        let mut framed = Vec::with_capacity(2 + sdu.len());
        framed.extend_from_slice(&(sdu.len() as u16).to_le_bytes());
        framed.extend_from_slice(sdu);
        framed.chunks(att_chunk).map(|c| c.to_vec()).collect()
    }

    fn decode_ble_coc_chunks(chunks: &[Vec<u8>]) -> Vec<u8> {
        let flat: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
        let len = u16::from_le_bytes([flat[0], flat[1]]) as usize;
        assert_eq!(flat.len(), 2 + len);
        flat[2..2 + len].to_vec()
    }

    #[tokio::test]
    async fn self_delimiting_cbor_stream_interoperates_across_tcp_uds_ppp_and_ble_coc() {
        let request = TaggedRecord {
            component: NameOrTag::Name("flash".to_owned()),
            method: NameOrTag::Name("write".to_owned()),
            id: Some(json!(77)),
            env: [(NameOrTag::Tag(1), json!("mod_quic2"))].into_iter().collect(),
            ..Default::default()
        };
        // Include 0x7e/0x7d bytes inside the body to exercise PPP escaping too.
        let body = b"\x7e\x7d\x00hello-dmesh-stream\xff\x7e".to_vec();

        // 1. Canonical stream bytes produced by `write_cbor_stream_frame`
        let (mut capture_w, mut capture_r) = tokio::io::duplex(4096);
        write_cbor_stream_frame(&mut capture_w, &request, &body)
            .await
            .unwrap();
        capture_w.shutdown().await.unwrap();
        let mut canonical_wire = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut capture_r, &mut canonical_wire)
            .await
            .unwrap();
        assert_eq!(canonical_wire[0] >> 5, 5);
        assert_eq!(
            &canonical_wire[canonical_wire.len() - body.len()..],
            body.as_slice()
        );

        // 2. TCP transport
        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let tcp_srv = tokio::spawn(async move {
            let (stream, _) = tcp_listener.accept().await.unwrap();
            serve_cbor_echo_stream(stream).await.unwrap();
        });
        let mut tcp_client = tokio::net::TcpStream::connect(tcp_addr).await.unwrap();
        let tcp_resp = exchange_cbor_stream(&mut tcp_client, &request, &body)
            .await
            .unwrap();
        tcp_srv.await.unwrap();
        assert_eq!(tcp_resp.record.id, Some(json!(77)));
        assert_eq!(tcp_resp.record.result.as_ref().unwrap()["body_len"], body.len());
        assert_eq!(tcp_resp.body, [b"ack:".as_slice(), body.as_slice()].concat());

        // 3. UDS transport
        let dir = tempfile::tempdir().unwrap();
        let uds_path = dir.path().join("cbor-stream.sock");
        let uds_listener = tokio::net::UnixListener::bind(&uds_path).unwrap();
        let uds_srv = tokio::spawn(async move {
            let (stream, _) = uds_listener.accept().await.unwrap();
            serve_cbor_echo_stream(stream).await.unwrap();
        });
        let mut uds_client = tokio::net::UnixStream::connect(&uds_path).await.unwrap();
        let uds_resp = exchange_cbor_stream(&mut uds_client, &request, &body)
            .await
            .unwrap();
        uds_srv.await.unwrap();
        assert_eq!(uds_resp, tcp_resp);

        // 4. PPP framing over serial (`0x7e port payload 0x7e`, `0x7d` escape)
        let ppp_wire = encode_ppp_record(243, &canonical_wire);
        let decoded_ppp = decode_ppp_records(&ppp_wire);
        assert_eq!(decoded_ppp.len(), 1);
        assert_eq!(decoded_ppp[0].0, 243);
        assert_eq!(decoded_ppp[0].1, canonical_wire);
        let mut ppp_cursor = std::io::Cursor::new(&decoded_ppp[0].1);
        let sync_header = read_cbor_header_bytes_sync(&mut ppp_cursor).unwrap().unwrap();
        let mut remaining_body = Vec::new();
        std::io::Read::read_to_end(&mut ppp_cursor, &mut remaining_body).unwrap();
        assert_eq!(remaining_body, body);
        assert_eq!(
            decode_record(&sync_header).unwrap().method.text(),
            "write"
        );

        // 5. BLE CoC SDU + 23-byte GATT/L2CAP chunking
        let coc_chunks = encode_ble_coc_chunks(&canonical_wire, 23);
        assert!(coc_chunks.len() > 1);
        let reassembled = decode_ble_coc_chunks(&coc_chunks);
        assert_eq!(reassembled, canonical_wire);
        let (mut client_dup, mut server_dup) = tokio::io::duplex(4096);
        let ble_srv = tokio::spawn(async move {
            serve_cbor_echo_stream(&mut server_dup).await.unwrap();
        });
        let ble_resp = {
            let (mut reader, mut writer) = tokio::io::split(&mut client_dup);
            writer.write_all(&reassembled).await.unwrap();
            writer.shutdown().await.unwrap();
            read_cbor_stream_frame(&mut reader).await.unwrap().unwrap()
        };
        ble_srv.await.unwrap();
        assert_eq!(ble_resp, tcp_resp);
    }
}
