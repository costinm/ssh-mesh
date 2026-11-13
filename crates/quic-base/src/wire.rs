//! QUIC RFC 9000 variable-length integer and frame wire codec for `quic-mux`.

use core::ops::Range;

/// Maximum value representable in a QUIC 62-bit variable-length integer.
pub const MAX_VARINT: u64 = (1 << 62) - 1;

/// Wire encoding/decoding errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    /// Input buffer ended before a complete varint or frame was decoded.
    UnexpectedEof,
    /// Output or prefix headroom buffer is too small.
    BufferTooSmall,
    /// Value exceeds 62-bit QUIC varint limit.
    VarIntOverflow,
    /// Frame type varint is unknown or unsupported by `quic-mux`.
    UnsupportedFrame(u64),
    /// Frame fields are malformed.
    InvalidFrame,
}

/// QUIC stream identifier (`u64` up to $2^{62}-1$).
///
/// Low 2 bits follow RFC 9000:
/// - Bit 0 (`0x01`): `0` = client-initiated, `1` = server-initiated.
/// - Bit 1 (`0x02`): `0` = bidirectional, `1` = unidirectional.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId(pub u64);

impl StreamId {
    /// Whether this stream was initiated by the client (`bit 0 == 0`).
    #[inline]
    pub const fn is_client_initiated(self) -> bool {
        (self.0 & 0x01) == 0
    }

    /// Whether this stream is bidirectional (`bit 1 == 0`).
    #[inline]
    pub const fn is_bidi(self) -> bool {
        (self.0 & 0x02) == 0
    }

    /// Whether this stream is unidirectional (`bit 1 != 0`).
    #[inline]
    pub const fn is_uni(self) -> bool {
        (self.0 & 0x02) != 0
    }

    /// Sequence index of this stream within its `(initiator, direction)` class.
    #[inline]
    pub const fn index(self) -> u64 {
        self.0 >> 2
    }
}

/// Encoded byte length of a QUIC variable-length integer.
#[inline]
pub const fn varint_len(v: u64) -> Result<usize, WireError> {
    if v <= 63 {
        Ok(1)
    } else if v <= 16_383 {
        Ok(2)
    } else if v <= 1_073_741_823 {
        Ok(4)
    } else if v <= MAX_VARINT {
        Ok(8)
    } else {
        Err(WireError::VarIntOverflow)
    }
}

/// Encode a QUIC varint at the start of `out`, returning the number of bytes written.
pub fn encode_varint(v: u64, out: &mut [u8]) -> Result<usize, WireError> {
    let n = varint_len(v)?;
    if out.len() < n {
        return Err(WireError::BufferTooSmall);
    }
    match n {
        1 => {
            out[0] = v as u8;
        }
        2 => {
            let b = ((v as u16) | 0x4000).to_be_bytes();
            out[..2].copy_from_slice(&b);
        }
        4 => {
            let b = ((v as u32) | 0x8000_0000).to_be_bytes();
            out[..4].copy_from_slice(&b);
        }
        8 => {
            let b = (v | 0xc000_0000_0000_0000).to_be_bytes();
            out[..8].copy_from_slice(&b);
        }
        _ => unreachable!(),
    }
    Ok(n)
}

/// Decode a QUIC varint from the start of `input`, returning `(value, bytes_consumed)`.
pub fn decode_varint(input: &[u8]) -> Result<(u64, usize), WireError> {
    let first = *input.first().ok_or(WireError::UnexpectedEof)?;
    let tag = first >> 6;
    let len = 1usize << tag;
    if input.len() < len {
        return Err(WireError::UnexpectedEof);
    }
    let val = match len {
        1 => u64::from(first & 0x3f),
        2 => {
            let mut b = [0u8; 2];
            b.copy_from_slice(&input[..2]);
            b[0] &= 0x3f;
            u64::from(u16::from_be_bytes(b))
        }
        4 => {
            let mut b = [0u8; 4];
            b.copy_from_slice(&input[..4]);
            b[0] &= 0x3f;
            u64::from(u32::from_be_bytes(b))
        }
        8 => {
            let mut b = [0u8; 8];
            b.copy_from_slice(&input[..8]);
            b[0] &= 0x3f;
            u64::from_be_bytes(b)
        }
        _ => unreachable!(),
    };
    Ok((val, len))
}

/// Decoded `STREAM` frame metadata with the byte range of its payload inside the packet buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamFrameRange {
    /// Target stream identifier.
    pub stream_id: StreamId,
    /// Byte offset in the stream.
    pub offset: u64,
    /// End-of-stream (`FIN`) flag.
    pub fin: bool,
    /// Range of the stream payload within the packet slice passed to `decode_frame`.
    pub payload_range: Range<usize>,
}

/// Decoded `quic-mux` frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// `0x00` PADDING frame.
    Padding,
    /// `0x01` PING frame.
    Ping,
    /// `0x04` RESET_STREAM frame.
    ResetStream {
        /// Stream being reset.
        stream_id: StreamId,
        /// Application error code.
        error_code: u64,
        /// Final byte size of the stream.
        final_size: u64,
    },
    /// `0x05` STOP_SENDING frame.
    StopSending {
        /// Stream being stopped.
        stream_id: StreamId,
        /// Application error code.
        error_code: u64,
    },
    /// `0x08..=0x0f` STREAM frame (payload referenced by range for zero-copy slicing).
    Stream(StreamFrameRange),
    /// `0x10` MAX_DATA frame.
    MaxData(u64),
    /// `0x11` MAX_STREAM_DATA frame.
    MaxStreamData {
        /// Stream receiving additional credit.
        stream_id: StreamId,
        /// New maximum stream data offset.
        max_stream_data: u64,
    },
    /// `0x12` MAX_STREAMS (bidirectional) frame.
    MaxStreamsBidi(u64),
    /// `0x13` MAX_STREAMS (unidirectional) frame.
    MaxStreamsUni(u64),
    /// `0x1c` (transport) or `0x1d` (application) CONNECTION_CLOSE frame.
    ConnectionClose {
        /// `true` for application close (`0x1d`), `false` for transport close (`0x1c`).
        is_application: bool,
        /// Transport or application error code.
        error_code: u64,
        /// Triggering frame type (`0` for application close `0x1d`).
        frame_type: u64,
    },
}

/// Encode only the `STREAM` frame header (`type`, `stream_id`, optional `offset`, optional `len`)
/// into `out`, returning the header length in bytes.
///
/// Used to prepend the `STREAM` header directly in front of an existing payload in pool headroom.
pub fn encode_stream_header(
    stream_id: StreamId,
    offset: u64,
    payload_len: usize,
    fin: bool,
    include_len: bool,
    out: &mut [u8],
) -> Result<usize, WireError> {
    let mut ty = 0x08u8;
    if offset > 0 {
        ty |= 0x04;
    }
    if include_len {
        ty |= 0x02;
    }
    if fin {
        ty |= 0x01;
    }
    if out.is_empty() {
        return Err(WireError::BufferTooSmall);
    }
    out[0] = ty;
    let mut at = 1;
    at += encode_varint(stream_id.0, &mut out[at..])?;
    if offset > 0 {
        at += encode_varint(offset, &mut out[at..])?;
    }
    if include_len {
        at += encode_varint(payload_len as u64, &mut out[at..])?;
    }
    Ok(at)
}

/// Encode a control frame (non-`STREAM` frame) into `out`, returning the number of bytes written.
pub fn encode_control_frame(frame: &Frame, out: &mut [u8]) -> Result<usize, WireError> {
    if out.is_empty() {
        return Err(WireError::BufferTooSmall);
    }
    match *frame {
        Frame::Padding => {
            out[0] = 0x00;
            Ok(1)
        }
        Frame::Ping => {
            out[0] = 0x01;
            Ok(1)
        }
        Frame::ResetStream {
            stream_id,
            error_code,
            final_size,
        } => {
            out[0] = 0x04;
            let mut at = 1;
            at += encode_varint(stream_id.0, &mut out[at..])?;
            at += encode_varint(error_code, &mut out[at..])?;
            at += encode_varint(final_size, &mut out[at..])?;
            Ok(at)
        }
        Frame::StopSending {
            stream_id,
            error_code,
        } => {
            out[0] = 0x05;
            let mut at = 1;
            at += encode_varint(stream_id.0, &mut out[at..])?;
            at += encode_varint(error_code, &mut out[at..])?;
            Ok(at)
        }
        Frame::MaxData(max) => {
            out[0] = 0x10;
            let n = encode_varint(max, &mut out[1..])?;
            Ok(1 + n)
        }
        Frame::MaxStreamData {
            stream_id,
            max_stream_data,
        } => {
            out[0] = 0x11;
            let mut at = 1;
            at += encode_varint(stream_id.0, &mut out[at..])?;
            at += encode_varint(max_stream_data, &mut out[at..])?;
            Ok(at)
        }
        Frame::MaxStreamsBidi(max) => {
            out[0] = 0x12;
            let n = encode_varint(max, &mut out[1..])?;
            Ok(1 + n)
        }
        Frame::MaxStreamsUni(max) => {
            out[0] = 0x13;
            let n = encode_varint(max, &mut out[1..])?;
            Ok(1 + n)
        }
        Frame::ConnectionClose {
            is_application,
            error_code,
            frame_type,
        } => {
            if is_application {
                out[0] = 0x1d; // Application close: type, error_code, reason_len = 0
                let mut at = 1;
                at += encode_varint(error_code, &mut out[at..])?;
                at += encode_varint(0, &mut out[at..])?;
                Ok(at)
            } else {
                out[0] = 0x1c; // Transport close: type, error_code, frame_type, reason_len = 0
                let mut at = 1;
                at += encode_varint(error_code, &mut out[at..])?;
                at += encode_varint(frame_type, &mut out[at..])?;
                at += encode_varint(0, &mut out[at..])?;
                Ok(at)
            }
        }
        Frame::Stream(_) => Err(WireError::InvalidFrame),
    }
}

/// Decode one frame starting at `packet[offset..]`, returning `(Frame, next_offset)`.
///
/// For `Frame::Stream`, `StreamFrameRange::payload_range` is expressed relative to `packet`.
pub fn decode_frame(packet: &[u8], offset: usize) -> Result<(Frame, usize), WireError> {
    let input = packet.get(offset..).ok_or(WireError::UnexpectedEof)?;
    let (ty_u64, ty_len) = decode_varint(input)?;
    let mut at = offset + ty_len;

    match ty_u64 {
        0x00 => Ok((Frame::Padding, at)),
        0x01 => Ok((Frame::Ping, at)),
        0x04 => {
            let (sid, n1) = decode_varint(packet.get(at..).ok_or(WireError::UnexpectedEof)?)?;
            at += n1;
            let (err, n2) = decode_varint(packet.get(at..).ok_or(WireError::UnexpectedEof)?)?;
            at += n2;
            let (fsz, n3) = decode_varint(packet.get(at..).ok_or(WireError::UnexpectedEof)?)?;
            at += n3;
            Ok((
                Frame::ResetStream {
                    stream_id: StreamId(sid),
                    error_code: err,
                    final_size: fsz,
                },
                at,
            ))
        }
        0x05 => {
            let (sid, n1) = decode_varint(packet.get(at..).ok_or(WireError::UnexpectedEof)?)?;
            at += n1;
            let (err, n2) = decode_varint(packet.get(at..).ok_or(WireError::UnexpectedEof)?)?;
            at += n2;
            Ok((
                Frame::StopSending {
                    stream_id: StreamId(sid),
                    error_code: err,
                },
                at,
            ))
        }
        0x08..=0x0f => {
            let ty = ty_u64 as u8;
            let has_off = (ty & 0x04) != 0;
            let has_len = (ty & 0x02) != 0;
            let fin = (ty & 0x01) != 0;

            let (sid, n1) = decode_varint(packet.get(at..).ok_or(WireError::UnexpectedEof)?)?;
            at += n1;
            let stream_offset = if has_off {
                let (off, n2) = decode_varint(packet.get(at..).ok_or(WireError::UnexpectedEof)?)?;
                at += n2;
                off
            } else {
                0
            };
            let payload_len = if has_len {
                let (len, n3) = decode_varint(packet.get(at..).ok_or(WireError::UnexpectedEof)?)?;
                at += n3;
                usize::try_from(len).map_err(|_| WireError::InvalidFrame)?
            } else {
                packet.len().checked_sub(at).ok_or(WireError::UnexpectedEof)?
            };
            let end = at.checked_add(payload_len).ok_or(WireError::InvalidFrame)?;
            if end > packet.len() {
                return Err(WireError::UnexpectedEof);
            }
            Ok((
                Frame::Stream(StreamFrameRange {
                    stream_id: StreamId(sid),
                    offset: stream_offset,
                    fin,
                    payload_range: at..end,
                }),
                end,
            ))
        }
        0x10 => {
            let (max, n) = decode_varint(packet.get(at..).ok_or(WireError::UnexpectedEof)?)?;
            at += n;
            Ok((Frame::MaxData(max), at))
        }
        0x11 => {
            let (sid, n1) = decode_varint(packet.get(at..).ok_or(WireError::UnexpectedEof)?)?;
            at += n1;
            let (max, n2) = decode_varint(packet.get(at..).ok_or(WireError::UnexpectedEof)?)?;
            at += n2;
            Ok((
                Frame::MaxStreamData {
                    stream_id: StreamId(sid),
                    max_stream_data: max,
                },
                at,
            ))
        }
        0x12 => {
            let (max, n) = decode_varint(packet.get(at..).ok_or(WireError::UnexpectedEof)?)?;
            at += n;
            Ok((Frame::MaxStreamsBidi(max), at))
        }
        0x13 => {
            let (max, n) = decode_varint(packet.get(at..).ok_or(WireError::UnexpectedEof)?)?;
            at += n;
            Ok((Frame::MaxStreamsUni(max), at))
        }
        0x1c | 0x1d => {
            let is_application = ty_u64 == 0x1d;
            let (err, n1) = decode_varint(packet.get(at..).ok_or(WireError::UnexpectedEof)?)?;
            at += n1;
            let frame_type = if !is_application {
                let (ft, n_ft) =
                    decode_varint(packet.get(at..).ok_or(WireError::UnexpectedEof)?)?;
                at += n_ft;
                ft
            } else {
                0
            };
            let (reason_len, n2) =
                decode_varint(packet.get(at..).ok_or(WireError::UnexpectedEof)?)?;
            at += n2;
            let rlen = usize::try_from(reason_len).map_err(|_| WireError::InvalidFrame)?;
            at = at.checked_add(rlen).ok_or(WireError::InvalidFrame)?;
            if at > packet.len() {
                return Err(WireError::UnexpectedEof);
            }
            Ok((
                Frame::ConnectionClose {
                    is_application,
                    error_code: err,
                    frame_type,
                },
                at,
            ))
        }
        other => Err(WireError::UnsupportedFrame(other)),
    }
}

/// Maximum byte length of any single `quic-mux` frame header (`1` type byte + up to `3 × 8` varint bytes).
pub const MAX_STREAM_FRAME_HEADER_LEN: usize = 32;

/// Result of inspecting the header prefix of a self-delimiting QUIC frame on a byte stream (TCP/UDS).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamHeaderStep {
    /// Input buffer ends before all header varints of the frame are present.
    NeedMoreHeader,
    /// Frame header varints are complete; total frame length is `header_len + payload_len`.
    Complete {
        /// Encoded frame header length in bytes.
        header_len: usize,
        /// Payload length following the header (`0` for control frames without trailing payload).
        payload_len: usize,
        /// `true` if this frame is a `STREAM` frame (`0x08..=0x0f`).
        is_stream: bool,
    },
}

/// Inspect a frame header prefix on a byte stream (TCP/UDS) where `STREAM` frames carry an explicit
/// `LEN` varint (`0x02` bit set) and control frames are self-delimiting.
pub fn stream_frame_header_step(input: &[u8]) -> Result<StreamHeaderStep, WireError> {
    if input.is_empty() {
        return Ok(StreamHeaderStep::NeedMoreHeader);
    }
    let (ty_u64, ty_len) = match decode_varint(input) {
        Ok(v) => v,
        Err(WireError::UnexpectedEof) => return Ok(StreamHeaderStep::NeedMoreHeader),
        Err(e) => return Err(e),
    };
    let mut at = ty_len;

    macro_rules! step_varint {
        () => {
            match input.get(at..).ok_or(WireError::UnexpectedEof).and_then(decode_varint) {
                Ok((val, n)) => {
                    at += n;
                    val
                }
                Err(WireError::UnexpectedEof) => return Ok(StreamHeaderStep::NeedMoreHeader),
                Err(e) => return Err(e),
            }
        };
    }

    match ty_u64 {
        0x00 | 0x01 => Ok(StreamHeaderStep::Complete {
            header_len: at,
            payload_len: 0,
            is_stream: false,
        }),
        0x04 => {
            let _sid = step_varint!();
            let _err = step_varint!();
            let _fsz = step_varint!();
            Ok(StreamHeaderStep::Complete {
                header_len: at,
                payload_len: 0,
                is_stream: false,
            })
        }
        0x05 | 0x11 => {
            let _a = step_varint!();
            let _b = step_varint!();
            Ok(StreamHeaderStep::Complete {
                header_len: at,
                payload_len: 0,
                is_stream: false,
            })
        }
        0x10 | 0x12 | 0x13 => {
            let _max = step_varint!();
            Ok(StreamHeaderStep::Complete {
                header_len: at,
                payload_len: 0,
                is_stream: false,
            })
        }
        0x08..=0x0f => {
            let ty = ty_u64 as u8;
            let has_off = (ty & 0x04) != 0;
            let has_len = (ty & 0x02) != 0;
            if !has_len {
                // On a byte stream (TCP/UDS), STREAM frames must carry an explicit length varint.
                return Err(WireError::InvalidFrame);
            }
            let _sid = step_varint!();
            if has_off {
                let _off = step_varint!();
            }
            let len = step_varint!();
            let payload_len = usize::try_from(len).map_err(|_| WireError::InvalidFrame)?;
            Ok(StreamHeaderStep::Complete {
                header_len: at,
                payload_len,
                is_stream: true,
            })
        }
        0x1c | 0x1d => {
            let is_application = ty_u64 == 0x1d;
            let _err = step_varint!();
            if !is_application {
                let _ft = step_varint!();
            }
            let rlen_u64 = step_varint!();
            let payload_len = usize::try_from(rlen_u64).map_err(|_| WireError::InvalidFrame)?;
            Ok(StreamHeaderStep::Complete {
                header_len: at,
                payload_len,
                is_stream: false,
            })
        }
        other => Err(WireError::UnsupportedFrame(other)),
    }
}

/// Plan for extracting one self-delimiting `quic-mux` packet from a byte stream's peek window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamPacketPlan {
    /// More header bytes must be read into the peek window before the first frame header is complete.
    NeedMoreHeader,
    /// A packet of `total_len` bytes is ready to be assembled into a pool slot (`take = total_len.min(peek.len())`
    /// bytes from `peek`, followed by `total_len - take` payload bytes read directly from the stream).
    Ready {
        /// Total byte length of the planned packet (`1..=max_packet_len`).
        total_len: usize,
    },
}

/// Plan the next `PoolPacket` from a byte stream's `peek` buffer (`<= 32` bytes), absorbing any
/// complete leading control frames plus at most one `STREAM` frame so single-stream zero-copy
/// ownership handoff is preserved.
pub fn plan_stream_packet(peek: &[u8], max_packet_len: usize) -> Result<StreamPacketPlan, WireError> {
    if peek.is_empty() {
        return Ok(StreamPacketPlan::NeedMoreHeader);
    }
    let mut at = 0usize;
    loop {
        match stream_frame_header_step(&peek[at..])? {
            StreamHeaderStep::NeedMoreHeader => {
                if at == 0 {
                    if peek.len() >= MAX_STREAM_FRAME_HEADER_LEN {
                        return Err(WireError::InvalidFrame);
                    }
                    return Ok(StreamPacketPlan::NeedMoreHeader);
                }
                return Ok(StreamPacketPlan::Ready { total_len: at });
            }
            StreamHeaderStep::Complete {
                header_len,
                payload_len,
                is_stream,
            } => {
                let frame_len = header_len
                    .checked_add(payload_len)
                    .ok_or(WireError::InvalidFrame)?;
                if frame_len == 0 || frame_len > max_packet_len {
                    return Err(WireError::InvalidFrame);
                }
                if at + frame_len > max_packet_len {
                    return Ok(StreamPacketPlan::Ready { total_len: at });
                }
                if is_stream {
                    return Ok(StreamPacketPlan::Ready {
                        total_len: at + frame_len,
                    });
                }
                if at + frame_len <= peek.len() {
                    at += frame_len;
                    if at == peek.len() {
                        return Ok(StreamPacketPlan::Ready { total_len: at });
                    }
                } else if at == 0 {
                    return Ok(StreamPacketPlan::Ready {
                        total_len: frame_len,
                    });
                } else {
                    return Ok(StreamPacketPlan::Ready { total_len: at });
                }
            }
        }
    }
}
