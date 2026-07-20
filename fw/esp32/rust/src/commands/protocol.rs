use anyhow::{anyhow, bail, Result};
use minicbor::{data::Type, Decoder, Encoder};

use super::{CommandRequest, CommandResponse, CommandStatus};

/// Common compact-CBOR field identifiers. These match `mesh::cbor` but are
/// intentionally duplicated: firmware does not link the host crate.
pub const CBOR_METHOD: u16 = 0;
pub const CBOR_PAYLOAD: u16 = 6;
pub const CBOR_STATUS: u16 = 4;
pub const CBOR_ERROR: u16 = 5;
pub const CBOR_MAX_RECORD: usize = 512;

/// Firmware-local command identifiers. These are two-byte CBOR values and are
/// documented in `crates/lmesh/ESP_FIRMWARE_API.md`.
pub fn command_id(name: &str) -> Option<u16> {
    Some(match name {
        "status" => 33,
        "xstatus" => 34,
        "stats" => 35,
        "logs" => 36,
        "messages" => 37,
        "local_messages" => 38,
        "test" => 39,
        "wifi" => 40,
        "nan" => 41,
        "ble" => 42,
        "lora" => 43,
        "lorasend" => 44,
        "loralisten" => 45,
        "loradump" => 46,
        "loraprobe" => 47,
        "sleep" => 48,
        "mode" => 49,
        "power" => 50,
        "battery" => 51,
        "adcprobe" => 52,
        "namespace" => 53,
        "set" => 54,
        "get" => 55,
        "list" => 56,
        "rgbled" => 57,
        "gpio" => 58,
        "i2cconfig" => 59,
        "i2cprobe" => 60,
        "i2cdetect" => 61,
        "i2cget" => 62,
        "i2cset" => 63,
        "i2cdump" => 64,
        "button" => 65,
        "nvs" => 66,
        _ => return None,
    })
}

pub fn command_name(id: u16) -> Option<&'static str> {
    Some(match id {
        33 => "status",
        34 => "xstatus",
        35 => "stats",
        36 => "logs",
        37 => "messages",
        38 => "local_messages",
        39 => "test",
        40 => "wifi",
        41 => "nan",
        42 => "ble",
        43 => "lora",
        44 => "lorasend",
        45 => "loralisten",
        46 => "loradump",
        47 => "loraprobe",
        48 => "sleep",
        49 => "mode",
        50 => "power",
        51 => "battery",
        52 => "adcprobe",
        53 => "namespace",
        54 => "set",
        55 => "get",
        56 => "list",
        57 => "rgbled",
        58 => "gpio",
        59 => "i2cconfig",
        60 => "i2cprobe",
        61 => "i2cdetect",
        62 => "i2cget",
        63 => "i2cset",
        64 => "i2cdump",
        65 => "button",
        66 => "nvs",
        _ => return None,
    })
}

/// Text command format shared by console and line-oriented transports.
///
/// Keep this firmware text protocol in sync with the service-side text stream
/// conventions in `crates/mesh/src/message.rs`: one newline-terminated record,
/// record type as the first token, and structured fields as `key=value`.
///
/// Format:
/// `command key=value flag payload=hex:001122`
pub fn parse_text(line: &str) -> Result<CommandRequest> {
    let mut parts = split_text_tokens(line)?.into_iter();
    let name = parts
        .next()
        .ok_or_else(|| anyhow!("empty command"))?
        .to_string();
    let mut request = CommandRequest::new(name);

    for part in parts {
        if let Some((key, value)) = part.split_once('=') {
            if key == "payload" {
                request.payload = parse_payload(value)?;
            } else {
                request.args.insert(key.to_string(), value.to_string());
            }
        } else {
            request.positionals.push(part.clone());
            request.args.insert(part.to_string(), "true".to_string());
        }
    }

    Ok(request)
}

fn split_text_tokens(line: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' if quoted => quoted = false,
            '"' if current.is_empty() || current.ends_with('=') => quoted = true,
            '\\' if quoted => {
                let Some(escaped) = chars.next() else {
                    return Err(anyhow!("unterminated text escape"));
                };
                current.push(match escaped {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    other => other,
                });
            }
            ch if ch.is_whitespace() && !quoted => {
                if !current.is_empty() {
                    tokens.push(core::mem::take(&mut current));
                }
            }
            ch => current.push(ch),
        }
    }
    if quoted {
        return Err(anyhow!("unterminated quoted text value"));
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

pub fn format_text(response: &CommandResponse) -> String {
    match response.status {
        CommandStatus::Ok => {
            let mut out = response.message.clone();
            if !response.payload.is_empty() {
                if !out.is_empty() {
                    out.push(' ');
                }
                out.push_str("data=");
                out.push_str(&encode_hex(&response.payload));
            }
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out
        }
        CommandStatus::Error => format!("error message={}\n", quote_text_value(&response.message)),
    }
}

/// Encode a flat compact-CBOR command. USB/TTY adds its length/type envelope;
/// BLE, LoRa, NAN, raw Wi-Fi, and UDP carry these bytes directly.
#[allow(dead_code)]
pub fn encode_binary(request: &CommandRequest) -> Vec<u8> {
    let mut out = Vec::new();
    let mut encoder = Encoder::new(&mut out);
    // Compact envelope plus a nested method payload. Command-local fields do
    // not consume envelope IDs.
    let entries = 2
        + usize::from(request.args.contains_key("status"))
        + usize::from(request.args.contains_key("error"));
    encoder.map(entries as u64).expect("Vec CBOR encode");
    encoder.u16(CBOR_METHOD).expect("Vec CBOR encode");
    match command_id(&request.name) {
        Some(id) => encoder.u16(id).expect("Vec CBOR encode"),
        None => encoder.str(&request.name).expect("Vec CBOR encode"),
    };
    for (field, id) in [("status", CBOR_STATUS), ("error", CBOR_ERROR)] {
        if let Some(value) = request.args.get(field) {
            encoder.u16(id).expect("Vec CBOR encode");
            encoder.str(value).expect("Vec CBOR encode");
        }
    }
    encoder.u16(CBOR_PAYLOAD).expect("Vec CBOR encode");
    let payload_fields = request.args.len()
        - usize::from(request.args.contains_key("status"))
        - usize::from(request.args.contains_key("error"))
        + usize::from(!request.payload.is_empty());
    encoder.map(payload_fields as u64).expect("Vec CBOR encode");
    for (key, value) in &request.args {
        if key != "status" && key != "error" {
            encoder.str(key).expect("Vec CBOR encode");
            encoder.str(value).expect("Vec CBOR encode");
        }
    }
    if !request.payload.is_empty() {
        encoder.str("data").expect("Vec CBOR encode");
        encoder.bytes(&request.payload).expect("Vec CBOR encode");
    }
    out
}

#[allow(dead_code)]
pub fn decode_binary(input: &[u8]) -> Result<CommandRequest> {
    if input.len() > CBOR_MAX_RECORD {
        bail!("CBOR command exceeds {CBOR_MAX_RECORD} bytes");
    }
    let mut decoder = Decoder::new(input);
    let Some(count) = decoder.map()? else {
        bail!("indefinite CBOR maps are not supported");
    };
    let mut request = None;
    let mut args = std::collections::BTreeMap::new();
    let mut payload = Vec::new();
    for _ in 0..count {
        let numeric_key = match decoder.datatype()? {
            Type::U8 | Type::U16 | Type::U32 => Some(decoder.u16()?),
            Type::String => {
                let key = decoder.str()?.to_owned();
                let value = decoder.str()?.to_owned();
                args.insert(key, value);
                continue;
            }
            kind => bail!("unsupported CBOR command key {kind:?}"),
        };
        match numeric_key {
            Some(CBOR_METHOD) => {
                request = Some(match decoder.datatype()? {
                    Type::U8 | Type::U16 | Type::U32 => command_name(decoder.u16()?)
                        .ok_or_else(|| anyhow!("unknown CBOR firmware command id"))?
                        .to_owned(),
                    Type::String => decoder.str()?.to_owned(),
                    kind => bail!("unsupported CBOR method value {kind:?}"),
                });
            }
            Some(CBOR_STATUS) => {
                args.insert("status".to_owned(), decoder.str()?.to_owned());
            }
            Some(CBOR_ERROR) => {
                args.insert("error".to_owned(), decoder.str()?.to_owned());
            }
            Some(CBOR_PAYLOAD) => {
                let Some(payload_count) = decoder.map()? else {
                    bail!("indefinite firmware payload maps are not supported");
                };
                for _ in 0..payload_count {
                    let key = decoder.str()?.to_owned();
                    if key == "data" {
                        payload.extend_from_slice(decoder.bytes()?);
                    } else {
                        args.insert(key, decoder.str()?.to_owned());
                    }
                }
            }
            Some(key) => bail!("unsupported reserved CBOR command field {key}"),
            None => unreachable!(),
        }
    }
    if decoder.position() != input.len() {
        bail!("trailing CBOR command data");
    }
    let mut request =
        CommandRequest::new(request.ok_or_else(|| anyhow!("CBOR command has no method"))?);
    request.args = args;
    request.payload = payload;
    Ok(request)
}

fn parse_payload(value: &str) -> Result<Vec<u8>> {
    if let Some(hex) = value.strip_prefix("hex:") {
        decode_hex(hex)
    } else {
        Ok(value.as_bytes().to_vec())
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn escape_value(value: &str) -> String {
    quote_text_value(value)
}

pub fn quote_text_value(value: &str) -> String {
    if is_bare_text_value(value) {
        return value.to_string();
    }
    let mut out = String::new();
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn is_bare_text_value(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\'' | b'\\' | b'='))
}

fn decode_hex(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err(anyhow!("hex payload must have an even length"));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        let high = from_hex(pair[0])?;
        let low = from_hex(pair[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn from_hex(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(anyhow!("invalid hex byte")),
    }
}
