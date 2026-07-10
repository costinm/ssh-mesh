use anyhow::Result;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

pub fn register_commands(registry: &mut CommandRegistry) {
    registry.register(HelpCommand);
    registry.register(ConsoleCommand);
}

struct HelpCommand;

impl CommandHandler for HelpCommand {
    fn name(&self) -> &'static str {
        "help"
    }

    fn help(&self) -> &'static str {
        "list command help"
    }

    fn handle(&mut self, _request: &CommandRequest) -> Result<CommandResponse> {
        Ok(CommandResponse::ok(
            "help is supplied by the shared command registry",
        ))
    }
}

struct ConsoleCommand;

impl CommandHandler for ConsoleCommand {
    fn name(&self) -> &'static str {
        "console"
    }

    fn help(&self) -> &'static str {
        "console mode=text|binary baud=115200"
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let mode = request.arg("mode").unwrap_or("text");
        let baud = request.arg_i32("baud")?.unwrap_or(115_200);
        log::info!("native ESP console requested: mode={mode} baud={baud}");
        Ok(CommandResponse::ok(format!(
            "console configured mode={mode} baud={baud}"
        )))
    }
}
