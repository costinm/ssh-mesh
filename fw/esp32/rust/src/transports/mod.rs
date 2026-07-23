use anyhow::Result;

use crate::commands::protocol::{decode_binary, encode_binary, format_text, parse_text};
use crate::commands::{CommandRegistry, CommandRequest, CommandResponse, CommandStatus};

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandFormat {
    Text,
    Binary,
}

#[allow(dead_code)]
pub trait CommandTransport {
    fn name(&self) -> &'static str;
    fn format(&self) -> CommandFormat;
    fn send_response(&mut self, response: &[u8]) -> Result<()>;
}

#[allow(dead_code)]
pub struct LoggingCommandTransport {
    name: &'static str,
    format: CommandFormat,
    responses: u32,
}

impl LoggingCommandTransport {
    #[allow(dead_code)]
    pub fn new(name: &'static str, format: CommandFormat) -> Self {
        Self {
            name,
            format,
            responses: 0,
        }
    }
}

impl CommandTransport for LoggingCommandTransport {
    fn name(&self) -> &'static str {
        self.name
    }

    fn format(&self) -> CommandFormat {
        self.format
    }

    fn send_response(&mut self, response: &[u8]) -> Result<()> {
        self.responses = self.responses.saturating_add(1);
        log::info!(
            "command response: transport={} format={:?} len={} total={}",
            self.name,
            self.format,
            response.len(),
            self.responses
        );
        Ok(())
    }
}

pub fn dispatch_text_line(registry: &mut CommandRegistry, line: &str) -> String {
    crate::components::telemetry::record_command(line);
    match parse_text(line) {
        Ok(request) => format_text(&registry.dispatch(&request)),
        Err(err) => format!("error {err}\n"),
    }
}

pub fn dispatch_binary_packet(registry: &mut CommandRegistry, packet: &[u8]) -> Vec<u8> {
    let is_framed = packet.starts_with(&[0, 0xcb, 0, 0]);
    let cbor_bytes = if is_framed { &packet[4..] } else { packet };
    match decode_binary(cbor_bytes) {
        Ok(request) => {
            let response = registry.dispatch(&request);
            let mut response_bytes = encode_response_as_binary(request.method, &response);
            if is_framed {
                response_bytes = wrap_stream_frame(&response_bytes);
            }
            response_bytes
        }
        Err(err) => {
            let mut request = CommandRequest::new_binary(0);
            request.args.insert(5, err.to_string()); // CBOR_ERROR is 5
            let mut response_bytes = encode_binary(&request);
            if is_framed {
                response_bytes = wrap_stream_frame(&response_bytes);
            }
            response_bytes
        }
    }
}

fn wrap_stream_frame(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 8);
    out.push(0);
    let len = data.len() + 4;
    out.push((len >> 16) as u8);
    out.push((len >> 8) as u8);
    out.push(len as u8);
    out.extend_from_slice(&[0, 0xcb, 0, 0]);
    out.extend_from_slice(data);
    out
}

#[allow(dead_code)]
pub fn send_text_command<T>(
    registry: &mut CommandRegistry,
    transport: &mut T,
    line: &str,
) -> Result<()>
where
    T: CommandTransport,
{
    let response = dispatch_text_line(registry, line);
    log::info!(
        "command dispatch: transport={} format={:?}",
        transport.name(),
        transport.format()
    );
    transport.send_response(response.as_bytes())
}

fn encode_response_as_binary(method: u16, response: &CommandResponse) -> Vec<u8> {
    let mut request = CommandRequest::new_binary(method);
    match response.status {
        CommandStatus::Ok => {
            request.args.insert(4, "ok".to_string()); // CBOR_STATUS is 4
            if !response.message.is_empty() {
                request.args.insert(32, response.message.clone()); // tag 32 for message
            }
        }
        CommandStatus::Error => {
            request.args.insert(5, response.message.clone()); // CBOR_ERROR is 5
        }
    }
    request.payload = response.payload.clone();
    encode_binary(&request)
}
