use anyhow::Result;

use crate::commands::protocol::{decode_binary, encode_binary, format_text, parse_text};
use crate::commands::{CommandRegistry, CommandRequest, CommandResponse};

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

#[allow(dead_code)]
pub fn dispatch_binary_packet(registry: &mut CommandRegistry, packet: &[u8]) -> Vec<u8> {
    match decode_binary(packet) {
        Ok(request) => {
            let response = registry.dispatch(&request);
            encode_response_as_binary(&request.name, &response)
        }
        Err(err) => {
            let request = CommandRequest::new("error").arg_pair("message", err.to_string());
            encode_binary(&request)
        }
    }
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

#[allow(dead_code)]
fn encode_response_as_binary(name: &str, response: &CommandResponse) -> Vec<u8> {
    let mut request = CommandRequest::new(name);
    request.args.insert(
        "status".to_string(),
        format!("{:?}", response.status).to_lowercase(),
    );
    request
        .args
        .insert("message".to_string(), response.message.clone());
    request.payload = response.payload.clone();
    encode_binary(&request)
}
