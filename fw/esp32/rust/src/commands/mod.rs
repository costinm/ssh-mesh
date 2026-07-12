use std::collections::BTreeMap;

use anyhow::{anyhow, Result};

pub mod protocol;

pub type CommandArgs = BTreeMap<String, String>;
const DEFAULT_HELP_MAX_BYTES: usize = 900;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandRequest {
    pub name: String,
    pub args: CommandArgs,
    pub payload: Vec<u8>,
}

impl CommandRequest {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            args: CommandArgs::new(),
            payload: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn arg_pair(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.args.insert(key.into(), value.into());
        self
    }

    pub fn arg(&self, key: &str) -> Option<&str> {
        self.args.get(key).map(String::as_str)
    }

    pub fn arg_i32(&self, key: &str) -> Result<Option<i32>> {
        self.arg(key)
            .map(|value| {
                value
                    .parse::<i32>()
                    .map_err(|err| anyhow!("invalid {key}={value}: {err}"))
            })
            .transpose()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandResponse {
    pub status: CommandStatus,
    pub message: String,
    pub payload: Vec<u8>,
}

impl CommandResponse {
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            status: CommandStatus::Ok,
            message: message.into(),
            payload: Vec::new(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            status: CommandStatus::Error,
            message: message.into(),
            payload: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandStatus {
    Ok,
    Error,
}

pub trait CommandHandler {
    fn name(&self) -> &'static str;
    fn help(&self) -> &'static str;
    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse>;
}

pub struct CommandRegistry {
    handlers: Vec<Box<dyn CommandHandler>>,
}

impl CommandRegistry {
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    pub fn register<H>(&mut self, handler: H)
    where
        H: CommandHandler + 'static,
    {
        self.handlers.push(Box::new(handler));
    }

    pub fn dispatch(&mut self, request: &CommandRequest) -> CommandResponse {
        if request.name == "help" {
            return CommandResponse::ok(self.help_text(request));
        }

        match self
            .handlers
            .iter_mut()
            .find(|handler| handler.name() == request.name)
        {
            Some(handler) => handler
                .handle(request)
                .unwrap_or_else(|err| CommandResponse::error(err.to_string())),
            None => CommandResponse::error(format!("unknown command: {}", request.name)),
        }
    }

    fn help_text(&self, request: &CommandRequest) -> String {
        if let Some(name) = request.arg("command").or_else(|| request.arg("cmd")) {
            return self
                .handlers
                .iter()
                .find(|handler| handler.name() == name)
                .map(|handler| format!("{}: {}", handler.name(), handler.help()))
                .unwrap_or_else(|| format!("unknown command: {name}"));
        }

        let max_bytes = request
            .arg_i32("max_bytes")
            .ok()
            .flatten()
            .unwrap_or(DEFAULT_HELP_MAX_BYTES as i32)
            .clamp(160, 4096) as usize;
        let mut out = String::new();
        let mut count = 0_usize;
        let mut more = false;
        for handler in &self.handlers {
            let line = format!("{}: {}\n", handler.name(), short_help(handler.help()));
            if out.len() + line.len() > max_bytes {
                more = true;
                break;
            }
            out.push_str(&line);
            count += 1;
        }
        if more {
            out.push_str(&format!(
                "help more=true shown={} total={} hint=\"help command=wifi\"\n",
                count,
                self.handlers.len()
            ));
        }
        out
    }
}

fn short_help(help: &'static str) -> &'static str {
    help.split('|')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(help)
}
