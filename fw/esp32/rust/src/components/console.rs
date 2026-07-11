use anyhow::Result;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

pub fn register_commands(registry: &mut CommandRegistry) {
    registry.register(HelpCommand);
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
