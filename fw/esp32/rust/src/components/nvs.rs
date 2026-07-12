use anyhow::{anyhow, Result};
use esp_idf_sys as sys;

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
    registry.register(NvsCommand::new("namespace", settings.clone()));
    registry.register(NvsCommand::new("set", settings.clone()));
    registry.register(NvsCommand::new("get", settings.clone()));
    registry.register(NvsCommand::new("list", settings));
}

impl CommandHandler for NvsCommand {
    fn name(&self) -> &'static str {
        self.name
    }

    fn help(&self) -> &'static str {
        match self.name {
            "namespace" => "namespace",
            "set" => "set key=KEY value=VALUE",
            "get" => "get key=KEY",
            "list" => "list",
            _ => "nvs",
        }
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        match self.name {
            "list" if request.arg("stats").is_some() => nvs_stats(),
            "namespace" => {
                let settings = self.settings.borrow();
                Ok(CommandResponse::ok(format!(
                    "namespace {}",
                    settings.namespace()
                )))
            }
            "set" => {
                let key = request
                    .arg("key")
                    .ok_or_else(|| anyhow!("set requires key"))?;
                let value = request
                    .arg("value")
                    .ok_or_else(|| anyhow!("set requires value"))?;
                self.settings.borrow_mut().set_str(key, value)?;
                log::info!("setting set: key={} value={}", key, value);
                Ok(CommandResponse::ok(format!("set {key}")))
            }
            "get" => {
                let key = request
                    .arg("key")
                    .ok_or_else(|| anyhow!("get requires key"))?;
                let value = self.settings.borrow().get_str(key)?.unwrap_or_default();
                Ok(CommandResponse::ok(format!("{key}={value}")))
            }
            "list" => {
                let settings = self.settings.borrow();
                let mut values = Vec::new();
                for key in settings.known_keys() {
                    let value = settings.get_str(key)?.unwrap_or_default();
                    values.push(format!("{key}={value}"));
                }
                Ok(CommandResponse::ok(values.join(" ")))
            }
            _ => Ok(CommandResponse::error("invalid nvs command")),
        }
    }
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
