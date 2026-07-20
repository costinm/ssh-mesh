use anyhow::{anyhow, Result};
use esp_idf_sys as sys;

use crate::commands::protocol::quote_text_value;
use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::settings::SharedSettings;

struct NvsCommand {
    name: &'static str,
    settings: SharedSettings,
}

impl NvsCommand {
    fn new(name: &'static str, settings: SharedSettings) -> Self {
        Self { name, settings }
    }
}

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    registry.register(NvsCommand::new("nvs", settings.clone()));
    registry.register(NvsCommand::new("namespace", settings.clone()));
    registry.register(NvsCommand::new("set", settings.clone()));
    registry.register(NvsCommand::new("get", settings.clone()));
    registry.register(NvsCommand::new("list", settings));
}

impl CommandHandler for NvsCommand {
    fn name(&self) -> &'static str {
        self.name
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        match self.name {
            "nvs" => self.handle_grouped(request),
            "list" if request.arg("stats").is_some() => nvs_stats(),
            "namespace" => self.namespace(),
            "set" => self.set_values(request, 0),
            "get" => self.get_value(request, 0),
            "list" => self.list_values(),
            _ => Ok(CommandResponse::error("invalid nvs command")),
        }
    }
}

impl NvsCommand {
    fn handle_grouped(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        match request
            .positional(0)
            .or_else(|| request.arg("op"))
            .or_else(|| request.arg("cmd"))
            .unwrap_or("list")
        {
            "ns" | "namespace" => self.namespace(),
            "set" => self.set_values(request, 1),
            "get" => self.get_value(request, 1),
            "list" => {
                if request.arg("stats").is_some() {
                    nvs_stats()
                } else {
                    self.list_values()
                }
            }
            other => Err(anyhow!("unknown nvs subcommand: {other}")),
        }
    }

    fn namespace(&self) -> Result<CommandResponse> {
        let settings = self.settings.borrow();
        Ok(CommandResponse::ok(format!(
            "namespace {}",
            settings.namespace()
        )))
    }

    fn set_values(
        &mut self,
        request: &CommandRequest,
        positional_skip: usize,
    ) -> Result<CommandResponse> {
        let mut pairs = Vec::new();
        if let (Some(key), Some(value)) = (request.arg("key"), request.arg("value")) {
            pairs.push((key, value));
        }
        for (key, value) in &request.args {
            if is_control_arg(key, positional_skip, request) {
                continue;
            }
            if key == "key" || key == "value" {
                continue;
            }
            pairs.push((key.as_str(), value.as_str()));
        }
        if pairs.is_empty() {
            return Err(anyhow!("set requires KEY=VALUE"));
        }

        let mut settings = self.settings.borrow_mut();
        let mut changed = Vec::new();
        for (key, value) in pairs {
            settings.set_str(key, value)?;
            log::info!("setting set: key={} value={}", key, value);
            changed.push(key.to_string());
        }
        Ok(CommandResponse::ok(format!("set {}", changed.join(","))))
    }

    fn get_value(
        &self,
        request: &CommandRequest,
        positional_skip: usize,
    ) -> Result<CommandResponse> {
        let key = request
            .positional(positional_skip)
            .or_else(|| request.arg("key"))
            .or_else(|| first_non_control_arg(request, positional_skip))
            .ok_or_else(|| anyhow!("get requires KEY"))?;
        let value = self.settings.borrow().get_str(key)?.unwrap_or_default();
        Ok(CommandResponse::ok(format!(
            "{key}={}",
            quote_text_value(&value)
        )))
    }

    fn list_values(&self) -> Result<CommandResponse> {
        let settings = self.settings.borrow();
        let mut values = Vec::new();
        for key in settings.known_keys() {
            if let Some(value) = settings.get_str(key)? {
                values.push(format!("{key}={}", quote_text_value(&value)));
            }
        }
        Ok(CommandResponse::ok(values.join(" ")))
    }
}

fn first_non_control_arg(request: &CommandRequest, positional_skip: usize) -> Option<&str> {
    request
        .args
        .keys()
        .find(|key| !is_control_arg(key, positional_skip, request))
        .map(String::as_str)
}

fn is_control_arg(key: &str, positional_skip: usize, request: &CommandRequest) -> bool {
    request
        .positionals
        .iter()
        .take(positional_skip)
        .any(|value| value == key)
        || matches!(key, "cmd" | "op" | "stats")
}

fn nvs_stats() -> Result<CommandResponse> {
    // Current 4 MB ESP32 partition table gives NVS 0x6000 bytes (24 KiB).
    // On the paired TLORA test unit this reports 756 total entries, with
    // 228 used and 402 available after companion/LoRa settings are saved.
    let mut stats = sys::nvs_stats_t {
        used_entries: 0,
        free_entries: 0,
        available_entries: 0,
        total_entries: 0,
        namespace_count: 0,
    };
    let ret = unsafe { sys::nvs_get_stats(core::ptr::null(), &mut stats) };
    if ret != sys::ESP_OK {
        return Err(anyhow!("nvs_get_stats failed ret=0x{ret:x}"));
    }
    Ok(CommandResponse::ok(format!(
        "nvs used_entries={} free_entries={} available_entries={} total_entries={} namespaces={}",
        stats.used_entries,
        stats.free_entries,
        stats.available_entries,
        stats.total_entries,
        stats.namespace_count
    )))
}
