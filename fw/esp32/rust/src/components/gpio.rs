use anyhow::{anyhow, Result};

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

pub fn register_commands(registry: &mut CommandRegistry) {
    registry.register(GpioCommand);
}

struct GpioCommand;

impl CommandHandler for GpioCommand {
    fn name(&self) -> &'static str {
        "gpio"
    }

    fn help(&self) -> &'static str {
        "gpio pin=N mode=input|output level=0|1"
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let pin = request
            .arg_i32("pin")?
            .ok_or_else(|| anyhow!("gpio requires pin=N"))?;
        let mode = request.arg("mode").unwrap_or("output");
        let level = request.arg_i32("level")?.unwrap_or(0);
        log::info!("gpio command: pin={pin} mode={mode} level={level}");
        Ok(CommandResponse::ok(format!(
            "gpio pin={pin} mode={mode} level={level}"
        )))
    }
}
