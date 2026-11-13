//! Tagged-CBOR wire contract and response reader for the `probe` service (`component = 8`).
//!
//! Specification: `crates/quic-tools/API.md`.

use alloc::vec::Vec;
use mesh_api::cbor::{Decoder, Encoder};
use mesh_api::envelope::{Name, PrefixDecode, decode_envelope_prefix};

use crate::probe::{
    MAX_BYTES as PROBE_MAX_BYTES, ProbePayload, ProbeRequest as ProbeWorkloadRequest,
};
#[cfg(test)]
use crate::probe::{MAX_NORMAL_STREAMS as PROBE_MAX_NORMAL_STREAMS, ProbePlan as ProbeServicePlan};

/// Component ID for the `probe` service (`# \`probe\` API (8)`).
pub const PROBE_COMPONENT: u64 = 8;
/// `probe.start`: ask a node to run a probe against `peer`.
pub const PROBE_START: u64 = 1;
/// `probe.handler`: the probed node's stream handler.
pub const PROBE_HANDLER: u64 = 2;
/// Maximum byte capacity for one canonical `probe.start` or `probe.handler` request header.
pub const PROBE_REQUEST_MAX: usize = 224;
/// Default maximum stream payload size when planning a probe workload.
pub const DEFAULT_PROBE_MAX_STREAM_PAYLOAD: usize = 1168;

/// Maximum duration in milliseconds a `probe.start` job may run: the caller's
/// `timeout` envelope field when given, else a default scaled to the transfer
/// (`30 s` up to `300 s`, assuming at least `8 KiB/s`).
pub fn probe_timeout_ms(requested: Option<u64>, bytes: u64) -> u64 {
    match requested {
        Some(timeout) => timeout,
        None => (bytes / 8_192).clamp(30, 300) * 1000,
    }
}

const FIELD_BYTES: u64 = 1;
const FIELD_PACKET_SIZE: u64 = 2;
const FIELD_ACK_FREQUENCY: u64 = 6;
const FIELD_ACK_DELAY_MS: u64 = 7;
const FIELD_LOW_PRIORITY_BYTES: u64 = 8;
const FIELD_HIGH_PRIORITY_BYTES: u64 = 9;
const FIELD_PARALLEL_STREAMS: u64 = 10;
const FIELD_INITIAL_CONSUME_DELAY_MS: u64 = 11;
const FIELD_CONSUME_DELAY_MS: u64 = 12;
const FIELD_PEER: u64 = 13;

/// Maximum length in bytes of a normalized [`ProbeDestination`] URI.
pub const MAX_PROBE_DESTINATION_URI: usize = 96;

/// Normalized URI destination shared by probe `to` and `peer` selectors.
/// Bare node identifiers are treated as `mesh://` VIPs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeDestination {
    uri: [u8; MAX_PROBE_DESTINATION_URI],
    len: u8,
}

impl ProbeDestination {
    /// Parse and normalize a destination URI or bare mesh VIP.
    pub fn parse(value: &str) -> Option<Self> {
        let (scheme, target) = match value.split_once("://") {
            Some(parts) => parts,
            None => ("mesh", value),
        };
        if scheme.is_empty()
            || !scheme
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || target.is_empty()
            || target
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
            || target.contains(',')
            || target.contains('#')
            || target.contains('?')
            || target.contains('/')
        {
            return None;
        }
        let uri_len = scheme.len().checked_add(3)?.checked_add(target.len())?;
        if uri_len > MAX_PROBE_DESTINATION_URI || uri_len > u8::MAX as usize {
            return None;
        }
        let mut uri = [0; MAX_PROBE_DESTINATION_URI];
        let mut offset = 0;
        uri[offset..offset + scheme.len()].copy_from_slice(scheme.as_bytes());
        offset += scheme.len();
        uri[offset..offset + 3].copy_from_slice(b"://");
        offset += 3;
        uri[offset..offset + target.len()].copy_from_slice(target.as_bytes());
        Some(Self {
            uri,
            len: uri_len as u8,
        })
    }

    /// Borrow the normalized URI string (`<scheme>://<target>`).
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.uri[..usize::from(self.len)])
            .expect("parsed destination URI is valid UTF-8")
    }

    /// Return the URI scheme before `://`.
    pub fn scheme(&self) -> &str {
        self.as_str().split_once("://").expect("normalized URI").0
    }

    /// Return the URI target after `://`.
    pub fn target(&self) -> &str {
        self.as_str().split_once("://").expect("normalized URI").1
    }

    /// Extract an explicit ESP-NOW unicast MAC address when the scheme is `espnow://`.
    pub fn espnow_mac(&self) -> Option<[u8; 6]> {
        let mac = (self.scheme() == "espnow")
            .then(|| parse_mac(self.target().as_bytes()))
            .flatten()?;
        (mac != [0; 6] && mac[0] & 1 == 0).then_some(mac)
    }
}

/// `probe` workload parameters plus optional directional and peer routing options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeServiceRequest {
    /// Opt-in deterministic payload validation; length and FIN are always checked.
    pub verify: bool,
    /// Transfer direction relative to the probe client.
    pub direction: ProbeDirection,
    /// Requested payload bytes per active direction.
    pub bytes: u64,
    /// Nominal chunk/packet payload size in bytes.
    pub packet_size: u16,
    /// Optional ACK-eliciting packet threshold.
    pub ack_frequency: Option<u8>,
    /// Optional maximum receiver ACK delay in milliseconds.
    pub ack_delay_ms: Option<u8>,
    /// Optional low-priority stream byte count.
    pub low_priority_bytes: Option<u32>,
    /// Optional high-priority stream byte count.
    pub high_priority_bytes: Option<u32>,
    /// Optional number of parallel normal streams.
    pub parallel_streams: Option<u8>,
    /// Optional initial receiver delay in milliseconds before consuming payload.
    pub initial_consume_delay_ms: Option<u32>,
    /// Optional per-chunk receiver delay in milliseconds.
    pub consume_delay_ms: Option<u32>,
    /// Responder destination URI or discovery-resolved mesh VIP.
    pub peer: Option<ProbeDestination>,
}

impl ProbeServiceRequest {
    /// Construct a default download [`ProbeServiceRequest`] for `bytes` and `packet_size`.
    pub const fn new(bytes: u64, packet_size: u16) -> Self {
        Self {
            verify: false,
            direction: ProbeDirection::Download,
            bytes,
            packet_size,
            ack_frequency: None,
            ack_delay_ms: None,
            low_priority_bytes: None,
            high_priority_bytes: None,
            parallel_streams: None,
            initial_consume_delay_ms: None,
            consume_delay_ms: None,
            peer: None,
        }
    }

    /// Bytes sent from client to responder (`0` for download-only).
    pub const fn upload_bytes(self) -> u64 {
        match self.direction {
            ProbeDirection::Download => 0,
            _ => self.bytes,
        }
    }

    /// Bytes sent from responder to client (`0` for upload-only).
    pub const fn download_bytes(self) -> u64 {
        match self.direction {
            ProbeDirection::Upload => 0,
            _ => self.bytes,
        }
    }

    /// Total payload bytes across both directions.
    pub const fn total_bytes(self) -> u64 {
        self.upload_bytes().saturating_add(self.download_bytes())
    }

    /// Convert into the underlying [`ProbeWorkloadRequest`].
    pub const fn workload(self) -> ProbeWorkloadRequest {
        ProbeWorkloadRequest {
            bytes: self.bytes,
            packet_size: self.packet_size,
            ack_frequency: self.ack_frequency,
            ack_delay_ms: self.ack_delay_ms,
            low_priority_bytes: self.low_priority_bytes,
            high_priority_bytes: self.high_priority_bytes,
            parallel_streams: self.parallel_streams,
            initial_consume_delay_ms: self.initial_consume_delay_ms,
            consume_delay_ms: self.consume_delay_ms,
        }
    }

    /// Check whether this request satisfies the standard single-stream handler limits.
    pub fn is_accepted_by_handler(&self) -> bool {
        self.direction != ProbeDirection::Both
            && self.bytes != 0
            && self.bytes <= PROBE_MAX_BYTES
            && self.peer.is_none()
            && self.parallel_streams.is_none_or(|streams| streams == 1)
            && self.high_priority_bytes.is_none_or(|bytes| bytes == 0)
            && self.low_priority_bytes.is_none_or(|bytes| bytes == 0)
            && self.ack_frequency.is_none()
            && self.ack_delay_ms.is_none()
    }
}

/// Direction relative to the probe client. `Both` runs two streams concurrently.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeDirection {
    /// Responder sends `bytes` to caller.
    Download,
    /// Caller sends `bytes` to responder.
    Upload,
    /// Concurrent upload and download over two streams.
    Both,
}

impl ProbeDirection {
    /// Wire text representation (`"download"`, `"upload"`, or `"both"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Download => "download",
            Self::Upload => "upload",
            Self::Both => "both",
        }
    }

    /// Parse from wire UTF-8 bytes.
    pub fn parse(value: &[u8]) -> Option<Self> {
        match value {
            b"download" => Some(Self::Download),
            b"upload" => Some(Self::Upload),
            b"both" => Some(Self::Both),
            _ => None,
        }
    }
}

/// Encode the canonical correlated `probe.start` request.
pub fn encode_probe_start_request(
    request: ProbeServiceRequest,
    id: u64,
    output: &mut [u8],
) -> Option<usize> {
    encode_probe_request(PROBE_START, request, id, output)
}

/// Encode the correlated `probe.handler` request sent to the probed node.
pub fn encode_probe_handler_request(
    request: ProbeServiceRequest,
    id: u64,
    output: &mut [u8],
) -> Option<usize> {
    encode_probe_request(PROBE_HANDLER, request, id, output)
}

fn encode_probe_request(
    method: u64,
    request: ProbeServiceRequest,
    id: u64,
    output: &mut [u8],
) -> Option<usize> {
    let optional = usize::from(request.ack_frequency.is_some())
        + usize::from(request.ack_delay_ms.is_some())
        + usize::from(request.low_priority_bytes.is_some())
        + usize::from(request.high_priority_bytes.is_some())
        + usize::from(request.parallel_streams.is_some())
        + usize::from(request.initial_consume_delay_ms.is_some())
        + usize::from(request.consume_delay_ms.is_some())
        + usize::from(request.peer.is_some())
        + usize::from(request.direction != ProbeDirection::Download)
        + usize::from(request.verify);
    let mut e = Encoder::new(output);
    e.map(4)?;
    e.uint(1)?;
    e.uint(PROBE_COMPONENT)?;
    e.uint(2)?;
    e.uint(method)?;
    e.uint(3)?;
    e.uint(id)?;
    e.uint(5)?;
    e.map((2 + optional) as u64)?;
    e.uint(FIELD_BYTES)?;
    e.uint(request.bytes)?;
    e.uint(FIELD_PACKET_SIZE)?;
    e.uint(u64::from(request.packet_size))?;
    for (field, value) in [
        (FIELD_ACK_FREQUENCY, request.ack_frequency.map(u64::from)),
        (FIELD_ACK_DELAY_MS, request.ack_delay_ms.map(u64::from)),
        (
            FIELD_LOW_PRIORITY_BYTES,
            request.low_priority_bytes.map(u64::from),
        ),
        (
            FIELD_HIGH_PRIORITY_BYTES,
            request.high_priority_bytes.map(u64::from),
        ),
        (
            FIELD_PARALLEL_STREAMS,
            request.parallel_streams.map(u64::from),
        ),
        (
            FIELD_INITIAL_CONSUME_DELAY_MS,
            request.initial_consume_delay_ms.map(u64::from),
        ),
        (
            FIELD_CONSUME_DELAY_MS,
            request.consume_delay_ms.map(u64::from),
        ),
    ] {
        if let Some(value) = value {
            e.uint(field)?;
            e.uint(value)?;
        }
    }
    if let Some(peer) = request.peer {
        e.uint(FIELD_PEER)?;
        e.text_value(peer.as_str().as_bytes())?;
    }
    if request.direction != ProbeDirection::Download {
        e.uint(14)?;
        e.text_value(request.direction.as_str().as_bytes())?;
    }
    if request.verify {
        e.uint(16)?;
        e.bool(true)?;
    }
    Some(e.len())
}

/// Decode the CBOR `fields` map (`key 5` or `"fields"`) of a `probe.start` or
/// `probe.handler` request, accepting either compact integer field tags or canonical
/// UTF-8 field names.
pub fn decode_probe_fields(fields: &[u8]) -> Option<ProbeServiceRequest> {
    let mut d = Decoder::new(fields);
    let (major, count) = d.head()?;
    if major != 5 || count == u64::MAX || count > 16 {
        return None;
    }
    let mut seen = 0u16;
    let mut request = ProbeServiceRequest::new(0, 0);
    for _ in 0..count {
        let field = match d.head()? {
            (0, tag) => tag,
            (3, len) => match d.take(usize::try_from(len).ok()?)? {
                b"bytes" => FIELD_BYTES,
                b"packet_size" => FIELD_PACKET_SIZE,
                b"ack_frequency" => FIELD_ACK_FREQUENCY,
                b"ack_delay_ms" => FIELD_ACK_DELAY_MS,
                b"low_priority_bytes" => FIELD_LOW_PRIORITY_BYTES,
                b"high_priority_bytes" => FIELD_HIGH_PRIORITY_BYTES,
                b"parallel_streams" => FIELD_PARALLEL_STREAMS,
                b"initial_consume_delay_ms" => FIELD_INITIAL_CONSUME_DELAY_MS,
                b"consume_delay_ms" => FIELD_CONSUME_DELAY_MS,
                b"peer" => FIELD_PEER,
                b"direction" => 14,
                b"verify" => 16,
                _ => return None,
            },
            _ => return None,
        };
        if !(1..=16).contains(&field) || matches!(field, 3..=5 | 15) {
            return None;
        }
        let bit = 1u16.checked_shl((field - 1) as u32)?;
        if seen & bit != 0 {
            return None;
        }
        seen |= bit;
        match field {
            16 => request.verify = d.boolean()?,
            14 => request.direction = ProbeDirection::parse(d.text_ref()?)?,
            FIELD_PEER => {
                request.peer = Some(ProbeDestination::parse(
                    core::str::from_utf8(d.text_ref()?).ok()?,
                )?)
            }
            FIELD_BYTES => request.bytes = d.uint()?,
            FIELD_PACKET_SIZE => request.packet_size = u16::try_from(d.uint()?).ok()?,
            FIELD_ACK_FREQUENCY => request.ack_frequency = Some(u8::try_from(d.uint()?).ok()?),
            FIELD_ACK_DELAY_MS => request.ack_delay_ms = Some(u8::try_from(d.uint()?).ok()?),
            FIELD_LOW_PRIORITY_BYTES => {
                request.low_priority_bytes = Some(u32::try_from(d.uint()?).ok()?)
            }
            FIELD_HIGH_PRIORITY_BYTES => {
                request.high_priority_bytes = Some(u32::try_from(d.uint()?).ok()?)
            }
            FIELD_PARALLEL_STREAMS => {
                request.parallel_streams = Some(u8::try_from(d.uint()?).ok()?)
            }
            FIELD_INITIAL_CONSUME_DELAY_MS => {
                request.initial_consume_delay_ms = Some(u32::try_from(d.uint()?).ok()?)
            }
            FIELD_CONSUME_DELAY_MS => {
                request.consume_delay_ms = Some(u32::try_from(d.uint()?).ok()?)
            }
            _ => return None,
        }
    }
    if seen & 0b11 != 0b11 || !d.is_finished() || request.bytes == 0 || request.packet_size == 0 {
        return None;
    }
    Some(request)
}

/// Extract the correlation `id` (`key 3`) from a request envelope.
pub fn extract_envelope_id(packet: &[u8]) -> Option<u64> {
    match decode_envelope_prefix(packet) {
        PrefixDecode::Complete { record, .. } => record.id,
        _ => None,
    }
}

fn encode_numeric_response(
    component: u64,
    method: u64,
    id: u64,
    result: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let mut encoder = Encoder::new(out);
    encoder.map(4)?;
    encoder.uint(1)?;
    encoder.uint(component)?;
    encoder.uint(2)?;
    encoder.uint(method)?;
    encoder.uint(3)?;
    encoder.uint(id)?;
    encoder.uint(6)?;
    encoder.encoded_value(result)?;
    Some(encoder.len())
}

/// Encode only the inner `result` CBOR map (`{1: status, 2: peer, 3: requested_bytes,
/// 4: received_bytes, 5: elapsed_us}`) of a `probe.start` response, suitable for
/// returning directly from `ComponentHandler::call_cbor`.
pub fn encode_probe_result_value(
    request: ProbeServiceRequest,
    success: bool,
    received_bytes: u64,
    elapsed_us: u64,
    output: &mut [u8],
) -> Option<usize> {
    let peer = request.peer?;
    let status = if success {
        b"ok".as_slice()
    } else {
        b"error".as_slice()
    };
    let mut e = Encoder::new(output);
    e.map(5)?;
    e.uint(1)?;
    e.text_value(status)?;
    e.uint(2)?;
    e.text_value(peer.as_str().as_bytes())?;
    e.uint(3)?;
    e.uint(request.bytes)?;
    e.uint(4)?;
    e.uint(received_bytes)?;
    e.uint(5)?;
    e.uint(elapsed_us)?;
    Some(e.len())
}

/// Encode the result of a device-directed `probe.start` request using the standard
/// tagged-CBOR response envelope.
pub fn encode_probe_result_response(
    id: u64,
    request: ProbeServiceRequest,
    success: bool,
    received_bytes: u64,
    elapsed_us: u64,
    output: &mut [u8],
) -> Option<usize> {
    let mut value = [0u8; 160];
    let value_len =
        encode_probe_result_value(request, success, received_bytes, elapsed_us, &mut value)?;
    encode_numeric_response(PROBE_COMPONENT, PROBE_START, id, &value[..value_len], output)
}

/// Encode the response header of `probe.handler`: the length of the payload that
/// follows and the packet size it is built from.
pub fn encode_probe_handler_response(
    id: u64,
    bytes: u64,
    packet_size: usize,
    output: &mut [u8],
) -> Option<usize> {
    let mut value = [0u8; 32];
    let mut e = Encoder::new(&mut value);
    e.map(2)?;
    e.uint(1)?;
    e.uint(bytes)?;
    e.uint(2)?;
    e.uint(packet_size as u64)?;
    let value_len = e.len();
    encode_numeric_response(PROBE_COMPONENT, PROBE_HANDLER, id, &value[..value_len], output)
}

/// Encode the response header of `probe.handler` when an upload was also verified.
pub fn encode_probe_handler_upload_response(
    id: u64,
    download_bytes: u64,
    packet_size: usize,
    upload_bytes: u64,
    output: &mut [u8],
) -> Option<usize> {
    if upload_bytes == 0 {
        return encode_probe_handler_response(id, download_bytes, packet_size, output);
    }
    let mut value = [0u8; 48];
    let mut e = Encoder::new(&mut value);
    e.map(3)?;
    e.uint(1)?;
    e.uint(download_bytes)?;
    e.uint(2)?;
    e.uint(packet_size as u64)?;
    e.uint(3)?;
    e.uint(upload_bytes)?;
    let value_len = e.len();
    encode_numeric_response(PROBE_COMPONENT, PROBE_HANDLER, id, &value[..value_len], output)
}

/// Why a probe response was not a valid probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeClientError {
    /// The response header was malformed or not a `probe.handler` result.
    Header,
    /// The peer answered with an error header.
    Rejected,
    /// A payload byte differs from the probe pattern, or there are too many.
    Payload,
}

/// The caller's end of a probe: feeds the bytes of the response stream (header,
/// then payload) and validates the payload, however the transport chunks it.
pub struct ProbeResponseReader {
    verify: bool,
    buffer: Vec<u8>,
    payload: Option<ProbePayload>,
    expected: u64,
    expected_upload: u64,
    uploaded: u64,
    header_done: bool,
}

impl ProbeResponseReader {
    /// `expected` is the download byte count that was requested.
    pub fn new(expected: u64) -> Self {
        Self {
            verify: true,
            buffer: Vec::new(),
            payload: None,
            expected,
            expected_upload: 0,
            uploaded: 0,
            header_done: false,
        }
    }

    /// Validate download bytes and the peer's terminal upload receipt.
    pub fn for_request(request: ProbeServiceRequest) -> Self {
        Self {
            verify: request.verify,
            expected_upload: request.upload_bytes(),
            ..Self::new(request.download_bytes())
        }
    }

    /// Request bytes confirmed by the peer, not merely queued by the sender.
    pub fn uploaded_bytes(&self) -> u64 {
        self.uploaded
    }

    /// Feed the next ordered response bytes.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), ProbeClientError> {
        if !self.header_done {
            self.buffer.extend_from_slice(bytes);
            match decode_envelope_prefix(&self.buffer) {
                PrefixDecode::Incomplete => return Ok(()),
                PrefixDecode::Invalid => return Err(ProbeClientError::Header),
                PrefixDecode::Complete {
                    record,
                    body_offset,
                } => {
                    if record.error.is_some() {
                        return Err(ProbeClientError::Rejected);
                    }
                    let comp_ok = matches!(
                        record.component,
                        Some(Name::Tag(PROBE_COMPONENT)) | Some(Name::Text(b"probe"))
                    );
                    let meth_ok = matches!(
                        record.method,
                        Some(Name::Tag(PROBE_HANDLER)) | Some(Name::Text(b"handler"))
                    );
                    if !comp_ok || !meth_ok {
                        return Err(ProbeClientError::Header);
                    }
                    let mut d = Decoder::new(record.result.ok_or(ProbeClientError::Header)?);
                    let (major, count) = d.head().ok_or(ProbeClientError::Header)?;
                    if major != 5 || !(2..=3).contains(&count) {
                        return Err(ProbeClientError::Header);
                    }
                    let (mut length_field, mut packet_size) = (None, None);
                    let mut uploaded = None;
                    let mut seen = 0u8;
                    for _ in 0..count {
                        let field = d.uint().ok_or(ProbeClientError::Header)?;
                        if !(1..=3).contains(&field) || seen & (1 << field) != 0 {
                            return Err(ProbeClientError::Header);
                        }
                        seen |= 1 << field;
                        match field {
                            1 => length_field = d.uint(),
                            2 => packet_size = d.uint(),
                            3 => uploaded = d.uint(),
                            _ => return Err(ProbeClientError::Header),
                        }
                    }
                    if !d.is_finished() || uploaded.unwrap_or(0) != self.expected_upload {
                        return Err(ProbeClientError::Header);
                    }
                    self.uploaded = uploaded.unwrap_or(0);
                    let announced = length_field.ok_or(ProbeClientError::Header)?;
                    if announced != self.expected {
                        return Err(ProbeClientError::Header);
                    }
                    let packet_size =
                        usize::try_from(packet_size.ok_or(ProbeClientError::Header)?)
                            .map_err(|_| ProbeClientError::Header)?;
                    self.payload = if announced == 0 {
                        None
                    } else {
                        Some(
                            ProbePayload::new(announced, packet_size)
                                .ok_or(ProbeClientError::Header)?,
                        )
                    };
                    if packet_size < 4 {
                        return Err(ProbeClientError::Header);
                    }
                    self.header_done = true;
                    let body = self.buffer.split_off(body_offset);
                    self.buffer.clear();
                    return self.check(&body);
                }
            }
        }
        self.check(bytes)
    }

    fn check(&mut self, bytes: &[u8]) -> Result<(), ProbeClientError> {
        match self.payload.as_mut() {
            Some(payload) => payload
                .consume(bytes, self.verify)
                .map_err(|_| ProbeClientError::Payload),
            None if bytes.is_empty() => Ok(()),
            None => Err(ProbeClientError::Payload),
        }
    }

    /// Payload bytes validated so far.
    pub fn bytes(&self) -> u64 {
        self.payload.as_ref().map_or(0, |payload| payload.offset())
    }

    /// Whether the whole payload arrived and was valid.
    pub fn is_complete(&self) -> bool {
        self.header_done
            && (self.expected == 0
                || self
                    .payload
                    .as_ref()
                    .is_some_and(|payload| payload.is_complete()))
    }
}

fn parse_mac(value: &[u8]) -> Option<[u8; 6]> {
    if value.len() != 17 {
        return None;
    }
    let mut mac = [0; 6];
    for (index, part) in value.split(|byte| *byte == b':').enumerate() {
        if index >= mac.len() || part.len() != 2 {
            return None;
        }
        let high = hex_nibble(part[0])?;
        let low = hex_nibble(part[1])?;
        mac[index] = (high << 4) | low;
    }
    (value.iter().filter(|byte| **byte == b':').count() == 5).then_some(mac)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_uri_is_shared_by_explicit_bearers_and_mesh_vips() {
        let now = ProbeDestination::parse("espnow://02:11:22:33:44:55").unwrap();
        assert_eq!(now.scheme(), "espnow");
        assert_eq!(now.espnow_mac(), Some([2, 0x11, 0x22, 0x33, 0x44, 0x55]));
        let vip = ProbeDestination::parse("fc00::1234").unwrap();
        assert_eq!(vip.as_str(), "mesh://fc00::1234");
        assert_eq!(vip.espnow_mac(), None);
        assert!(ProbeDestination::parse("espnow://02:11:22:33:44:55,udp://host").is_none());
        assert!(ProbeDestination::parse("espnow://02:11:22:33:44:55?channel=6").is_none());
    }

    #[test]
    fn plan_has_one_shared_stream_and_ack_shape() {
        let request = ProbeServiceRequest {
            verify: false,
            direction: ProbeDirection::Download,
            bytes: 10,
            packet_size: 65_535,
            ack_frequency: Some(255),
            ack_delay_ms: Some(0),
            low_priority_bytes: Some(7),
            high_priority_bytes: Some(3),
            parallel_streams: Some(255),
            initial_consume_delay_ms: Some(500),
            consume_delay_ms: Some(11),
            peer: None,
        };
        let plan = ProbeServicePlan::from_request(request.workload(), 1168);
        assert_eq!(plan.packet_size, 1168);
        assert_eq!(plan.normal_streams, PROBE_MAX_NORMAL_STREAMS);
        assert_eq!(plan.normal_bytes, [3, 3, 2, 2]);
        assert_eq!(plan.high_priority_bytes, 3);
        assert_eq!(plan.low_priority_bytes, 7);
        assert_eq!(plan.ack_frequency, 8);
        assert_eq!(plan.ack_delay_ms, 1);
        assert_eq!(plan.total_bytes(), 20);
    }
}
