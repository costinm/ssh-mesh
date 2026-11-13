//! Asynchronous stream client helpers for the `probe` service over ordinary Tokio byte streams
//! and `quic_mux::TokioMux`.

use alloc::vec;
use alloc::vec::Vec;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::probe::{MAX_BYTES, ProbePayload, ProbePlan, ProbeResult as TransferResult};
use crate::service::{
    DEFAULT_PROBE_MAX_STREAM_PAYLOAD, PROBE_COMPONENT, PROBE_HANDLER, PROBE_REQUEST_MAX,
    ProbeDirection, ProbeResponseReader, ProbeServiceRequest, decode_probe_fields,
    encode_probe_handler_request, encode_probe_handler_upload_response, extract_envelope_id,
};
use mesh_api::envelope::{
    Name, PrefixDecode, decode_envelope_prefix, encode_error_header, encode_numeric_error,
};

/// Completed application probe, with independent directional response/FIN timings.
#[derive(Clone, Copy, Debug)]
pub struct StreamProbeResult {
    /// Underlying transfer counters and elapsed microseconds.
    pub transfer: TransferResult,
    /// Verified uploaded bytes.
    pub upload_bytes: u64,
    /// Verified downloaded bytes.
    pub download_bytes: u64,
    /// Upload duration in microseconds (`0` for download-only).
    pub upload_elapsed_us: u64,
    /// Download duration in microseconds (`0` for upload-only).
    pub download_elapsed_us: u64,
}

impl core::ops::Deref for StreamProbeResult {
    type Target = TransferResult;
    fn deref(&self) -> &Self::Target {
        &self.transfer
    }
}

impl StreamProbeResult {
    /// Measured upload throughput in megabits per second.
    pub fn upload_mbps(&self) -> f64 {
        directional_mbps(self.upload_bytes, self.upload_elapsed_us)
    }

    /// Measured download throughput in megabits per second.
    pub fn download_mbps(&self) -> f64 {
        directional_mbps(self.download_bytes, self.download_elapsed_us)
    }
}

fn directional_mbps(bytes: u64, elapsed_us: u64) -> f64 {
    if elapsed_us == 0 {
        0.0
    } else {
        bytes as f64 * 8.0 / elapsed_us as f64
    }
}

/// Run simultaneous upload/download over two ordinary streams. Each direction
/// has its own terminal response and FIN; neither waits for the other to start.
pub async fn probe_duplex<U, D>(
    upload: &mut U,
    download: &mut D,
    request: ProbeServiceRequest,
    id: u64,
) -> std::io::Result<StreamProbeResult>
where
    U: AsyncRead + AsyncWrite + Unpin,
    D: AsyncRead + AsyncWrite + Unpin,
{
    let mut up = request;
    up.direction = ProbeDirection::Upload;
    up.peer = None;
    let mut down = up;
    down.direction = ProbeDirection::Download;
    let mut up_header = [0; PROBE_REQUEST_MAX];
    let mut down_header = [0; PROBE_REQUEST_MAX];
    let invalid = || std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid probe header");
    let up_len = encode_probe_handler_request(up, id, &mut up_header).ok_or_else(invalid)?;
    let down_len =
        encode_probe_handler_request(down, id.wrapping_add(1), &mut down_header)
            .ok_or_else(invalid)?;
    let started = std::time::Instant::now();
    let (up_result, down_result) = tokio::try_join!(
        probe(upload, &up_header[..up_len], up),
        probe(download, &down_header[..down_len], down),
    )?;
    Ok(StreamProbeResult {
        upload_bytes: up_result.upload_bytes,
        download_bytes: down_result.download_bytes,
        upload_elapsed_us: up_result.upload_elapsed_us,
        download_elapsed_us: down_result.download_elapsed_us,
        transfer: TransferResult {
            bytes: up_result.bytes + down_result.bytes,
            normal_bytes: up_result.bytes + down_result.bytes,
            high_bytes: 0,
            low_bytes: 0,
            elapsed_us: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
            callback_errors: core::array::from_fn(|index| {
                up_result.callback_errors[index].saturating_add(down_result.callback_errors[index])
            }),
        },
    })
}

/// QUIC-mux adapter for the shared stream workload. Both streams use
/// this multiplexer's existing links and common connection flow control.
pub async fn probe_mux(
    mux: &quic_mux::TokioMux,
    payload: &[u8],
    request: ProbeServiceRequest,
) -> std::io::Result<StreamProbeResult> {
    let mut stream = mux.open_bidi().await?;
    if request.direction == ProbeDirection::Both {
        let mut download = mux.open_bidi().await?;
        let id = extract_envelope_id(payload).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid probe request")
        })?;
        probe_duplex(&mut stream, &mut download, request, id).await
    } else {
        probe(&mut stream, payload, request).await
    }
}

/// Write the request parts in order, half-close, and collect the response.
/// Reading concurrently permits a server to respond while receiving a body.
pub async fn exchange<S>(stream: &mut S, parts: &[&[u8]]) -> std::io::Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let send = async {
        for part in parts {
            writer.write_all(part).await?;
        }
        writer.shutdown().await
    };
    let receive = async {
        let mut response = Vec::new();
        reader.read_to_end(&mut response).await?;
        Ok::<_, std::io::Error>(response)
    };
    let (_, response) = tokio::try_join!(send, receive)?;
    Ok(response)
}

/// Request and validate a probe response over any asynchronous byte stream.
/// Consumer delays are workload options, not transport backpressure policy.
pub async fn probe<S>(
    stream: &mut S,
    payload: &[u8],
    request: ProbeServiceRequest,
) -> std::io::Result<StreamProbeResult>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let invalid = |message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message);
    let plan = ProbePlan::from_request(request.workload(), DEFAULT_PROBE_MAX_STREAM_PAYLOAD);
    if request.direction == ProbeDirection::Both {
        return Err(invalid("both requires probe_duplex or probe_mux"));
    }
    if request.bytes == 0 || request.bytes > MAX_BYTES {
        return Err(invalid("probe bytes outside supported range"));
    }
    let expected = request.download_bytes();
    let started = std::time::Instant::now();
    let (mut input, mut output) = tokio::io::split(stream);
    let send = async {
        output.write_all(payload).await?;
        if request.upload_bytes() != 0 {
            let mut source = ProbePayload::new(request.upload_bytes(), plan.packet_size)
                .ok_or_else(|| invalid("invalid probe workload"))?;
            let mut chunk = vec![0; plan.packet_size];
            while !source.is_complete() {
                let count = source.fill(&mut chunk);
                output.write_all(&chunk[..count]).await?;
            }
        }
        output.shutdown().await
    };
    let receive = async {
        let mut reader = ProbeResponseReader::for_request(request);
        if let Some(delay) = request.initial_consume_delay_ms.filter(|delay| *delay != 0) {
            tokio::time::sleep(std::time::Duration::from_millis(u64::from(delay))).await;
        }
        let mut bytes = vec![0; plan.packet_size.max(8)];
        loop {
            let len = input.read(&mut bytes).await?;
            if len == 0 {
                break;
            }
            reader.push(&bytes[..len]).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    alloc::format!("probe response: {error:?}"),
                )
            })?;
            if let Some(delay) = request.consume_delay_ms.filter(|delay| *delay != 0) {
                tokio::time::sleep(std::time::Duration::from_millis(u64::from(delay))).await;
            }
        }
        if !reader.is_complete() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                alloc::format!(
                    "probe response ended after {} of {expected} bytes",
                    reader.bytes()
                ),
            ));
        }
        Ok::<_, std::io::Error>(reader.bytes() + reader.uploaded_bytes())
    };
    let (_, bytes) = tokio::try_join!(send, receive)?;
    let elapsed_us = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
    Ok(StreamProbeResult {
        upload_bytes: request.upload_bytes(),
        download_bytes: request.download_bytes(),
        upload_elapsed_us: if request.upload_bytes() == 0 {
            0
        } else {
            elapsed_us
        },
        download_elapsed_us: if request.download_bytes() == 0 {
            0
        } else {
            elapsed_us
        },
        transfer: TransferResult {
            bytes,
            normal_bytes: bytes,
            high_bytes: 0,
            low_bytes: 0,
            elapsed_us,
            callback_errors: [0; 6],
        },
    })
}

/// Serve a single incoming `probe.handler` stream over any `AsyncRead + AsyncWrite` byte stream.
///
/// Uses single-pass [`decode_envelope_prefix`] to decode the opening request envelope and
/// locate the exact byte offset where the optional upload body begins, validates the upload
/// through `FIN`, and writes the response envelope followed by the optional download payload.
pub async fn serve_probe_stream<S>(stream: &mut S) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut buf = Vec::with_capacity(256);
    let mut chunk = [0u8; 2048];
    let (id, request, body_offset) = loop {
        match decode_envelope_prefix(&buf) {
            PrefixDecode::Invalid => {
                stream
                    .write_all(&encode_error_header(None, b"invalid request header"))
                    .await?;
                return stream.shutdown().await;
            }
            PrefixDecode::Incomplete => {
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    stream
                        .write_all(&encode_error_header(
                            None,
                            b"request ended inside its header",
                        ))
                        .await?;
                    return stream.shutdown().await;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            PrefixDecode::Complete {
                record,
                body_offset,
            } => {
                let id = record.id.unwrap_or(0);
                let comp_ok = matches!(
                    record.component,
                    Some(Name::Tag(PROBE_COMPONENT)) | Some(Name::Text(b"probe"))
                );
                let meth_ok = matches!(
                    record.method,
                    Some(Name::Tag(PROBE_HANDLER)) | Some(Name::Text(b"handler"))
                );
                let parsed = if comp_ok && meth_ok && record.params.is_none() && record.to.is_none()
                {
                    record.fields.and_then(decode_probe_fields)
                } else {
                    None
                };
                let Some(req) = parsed.filter(|r| r.is_accepted_by_handler()) else {
                    let mut err = [0u8; 96];
                    if let Some(len) = encode_numeric_error(
                        PROBE_COMPONENT,
                        PROBE_HANDLER,
                        id,
                        b"invalid probe request",
                        &mut err,
                    ) {
                        stream.write_all(&err[..len]).await?;
                    }
                    return stream.shutdown().await;
                };
                break (id, req, body_offset);
            }
        }
    };

    serve_probe_body(id, request, &buf[body_offset..], stream).await
}

/// Serve a `probe.handler` stream whose opening envelope has already been decoded
/// (for example by `mesh::ComponentDirectory::serve_stream` into a `FramedStream`).
pub async fn serve_framed_probe_stream<S>(
    id: u64,
    fields: Option<&[u8]>,
    stream: &mut S,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let Some(request) = fields
        .and_then(decode_probe_fields)
        .filter(|r| r.is_accepted_by_handler())
    else {
        let mut err = [0u8; 96];
        if let Some(len) = encode_numeric_error(
            PROBE_COMPONENT,
            PROBE_HANDLER,
            id,
            b"invalid probe request",
            &mut err,
        ) {
            stream.write_all(&err[..len]).await?;
        }
        return stream.shutdown().await;
    };
    serve_probe_body(id, request, &[], stream).await
}

async fn serve_probe_body<S>(
    id: u64,
    request: ProbeServiceRequest,
    prefetched_body: &[u8],
    stream: &mut S,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut chunk = [0u8; 2048];
    let plan = ProbePlan::from_request(request.workload(), DEFAULT_PROBE_MAX_STREAM_PAYLOAD);

    if request.upload_bytes() != 0 {
        let mut upload_payload =
            ProbePayload::new(request.upload_bytes(), plan.packet_size).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid probe upload")
            })?;
        let mut rejected = false;
        if !prefetched_body.is_empty()
            && upload_payload
                .consume(prefetched_body, request.verify)
                .is_err()
        {
            rejected = true;
        }
        while !rejected {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                if !upload_payload.is_complete() {
                    rejected = true;
                }
                break;
            }
            if upload_payload.consume(&chunk[..n], request.verify).is_err() {
                rejected = true;
                break;
            }
        }
        if rejected {
            let mut err = [0u8; 96];
            if let Some(len) = encode_numeric_error(
                PROBE_COMPONENT,
                PROBE_HANDLER,
                id,
                b"invalid probe upload",
                &mut err,
            ) {
                stream.write_all(&err[..len]).await?;
            }
            return stream.shutdown().await;
        }
    }

    let mut resp_header = [0u8; 96];
    let header_len = encode_probe_handler_upload_response(
        id,
        request.download_bytes(),
        plan.packet_size,
        request.upload_bytes(),
        &mut resp_header,
    )
    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "encode response"))?;
    stream.write_all(&resp_header[..header_len]).await?;

    if request.download_bytes() != 0 {
        let mut down_payload = ProbePayload::new(request.download_bytes(), plan.packet_size)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid probe download")
            })?;
        let mut out_chunk = vec![0u8; plan.packet_size.max(8)];
        while !down_payload.is_complete() {
            let count = down_payload.fill(&mut out_chunk);
            stream.write_all(&out_chunk[..count]).await?;
        }
    }
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directional_rates_use_independent_timings() {
        assert_eq!(directional_mbps(1_000_000, 1_000_000), 8.0);
        assert_eq!(directional_mbps(1_000_000, 2_000_000), 4.0);
        assert_eq!(directional_mbps(0, 0), 0.0);
    }
}
