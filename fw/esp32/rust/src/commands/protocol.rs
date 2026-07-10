use anyhow::{anyhow, Result};

use super::{CommandRequest, CommandResponse, CommandStatus};

pub const BINARY_MAGIC: &[u8; 4] = b"DM01";

/// Text command format shared by console and line-oriented transports.
///
/// Format:
/// `command key=value flag payload=hex:001122`
pub fn parse_text(line: &str) -> Result<CommandRequest> {
    let mut parts = line.split_whitespace();
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
            request.args.insert(part.to_string(), "true".to_string());
        }
    }

    Ok(request)
}

pub fn format_text(response: &CommandResponse) -> String {
    let status = match response.status {
        CommandStatus::Ok => "ok",
        CommandStatus::Error => "error",
    };
    if response.payload.is_empty() {
        format!("{status} {}\n", response.message)
    } else {
        format!(
            "{status} {} payload=hex:{}\n",
            response.message,
            encode_hex(&response.payload)
        )
    }
}

/// Minimal binary envelope for future USB/BLE/Wi-Fi use.
///
/// Layout: `DM01 | name_len:u8 | argc:u8 | payload_len:u16-le | name |
/// key_len:u8 value_len:u8 key value ... | payload`.
pub fn encode_binary(request: &CommandRequest) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(BINARY_MAGIC);
    out.push(request.name.len().min(u8::MAX as usize) as u8);
    out.push(request.args.len().min(u8::MAX as usize) as u8);
    out.extend_from_slice(&(request.payload.len().min(u16::MAX as usize) as u16).to_le_bytes());
    out.extend_from_slice(request.name.as_bytes());
    for (key, value) in &request.args {
        out.push(key.len().min(u8::MAX as usize) as u8);
        out.push(value.len().min(u8::MAX as usize) as u8);
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    out.extend_from_slice(&request.payload);
    out
}

pub fn decode_binary(input: &[u8]) -> Result<CommandRequest> {
    if input.len() < 8 || &input[0..4] != BINARY_MAGIC {
        return Err(anyhow!("invalid binary command magic"));
    }
    let name_len = input[4] as usize;
    let argc = input[5] as usize;
    let payload_len = u16::from_le_bytes([input[6], input[7]]) as usize;
    let mut cursor = 8;
    let name_end = cursor + name_len;
    if name_end > input.len() {
        return Err(anyhow!("truncated command name"));
    }
    let mut request = CommandRequest::new(std::str::from_utf8(&input[cursor..name_end])?);
    cursor = name_end;
    for _ in 0..argc {
        if cursor + 2 > input.len() {
            return Err(anyhow!("truncated arg header"));
        }
        let key_len = input[cursor] as usize;
        let value_len = input[cursor + 1] as usize;
        cursor += 2;
        if cursor + key_len + value_len > input.len() {
            return Err(anyhow!("truncated arg body"));
        }
        let key = std::str::from_utf8(&input[cursor..cursor + key_len])?.to_string();
        cursor += key_len;
        let value = std::str::from_utf8(&input[cursor..cursor + value_len])?.to_string();
        cursor += value_len;
        request.args.insert(key, value);
    }
    if cursor + payload_len > input.len() {
        return Err(anyhow!("truncated payload"));
    }
    request
        .payload
        .extend_from_slice(&input[cursor..cursor + payload_len]);
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
