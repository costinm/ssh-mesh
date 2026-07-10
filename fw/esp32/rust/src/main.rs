use anyhow::Result;
use esp_idf_svc::log::EspLogger;
use std::io::{self, Write};
use std::time::Duration;

mod commands;
mod components;
mod transports;

use commands::CommandRegistry;
use commands::CommandRequest;
use components::l3dmesh::{Frame, L3Mesh};
use transports::{CommandFormat, LoggingCommandTransport};

fn main() -> Result<()> {
    esp_idf_sys::link_patches();
    EspLogger::initialize_default();

    log::info!("dmesh-rs starting");

    let settings = components::settings::open_shared();
    let mut registry = CommandRegistry::new();
    components::register_commands(&mut registry, settings.clone());
    for (name, help) in registry.help() {
        log::info!("command: {name} - {help}");
    }

    let mut mesh = L3Mesh::new();
    mesh.add_transport(components::ble_bt::ble_transport());
    mesh.add_transport(components::ble_bt::bt_transport());
    mesh.add_transport(components::lora::transport(settings));
    mesh.add_transport(components::nan::transport());

    mesh.on_message(Frame::borrowed(b"hello from rust"), 0)?;

    let response = transports::dispatch_text_line(&mut registry, "wifi");
    log::info!("sample command response: {}", response.trim_end());
    for command in [
        "lora",
        "i2cconfig",
        "i2cprobe sda=21,4 scl=22,15 addr=0x3c save=false",
        "loraprobe sck=5,18 miso=19 mosi=27 cs=18,5 rst=14 dio0=26 save=false",
    ] {
        let response = transports::dispatch_text_line(&mut registry, command);
        log::info!("startup command: {command} => {}", response.trim_end());
    }

    let mut native_console = LoggingCommandTransport::new("native-console", CommandFormat::Text);
    transports::send_text_command(&mut registry, &mut native_console, "gpio pin=2 level=1")?;

    let binary_request =
        commands::protocol::encode_binary(&CommandRequest::new("nan").arg_pair("stats", "true"));
    let binary_response = transports::dispatch_binary_packet(&mut registry, &binary_request);
    let mut usb_binary = LoggingCommandTransport::new("usb-binary", CommandFormat::Binary);
    transports::CommandTransport::send_response(&mut usb_binary, &binary_response)?;

    log::info!("dmesh-rs initialized; messages={}", mesh.in_messages());
    println!("dmesh-rs ready");
    let stdin = io::stdin();
    let mut line = String::new();
    print!("dm-rs> ");
    let _ = io::stdout().flush();
    loop {
        components::ble_bt::poll_text_commands(&mut registry);
        line.clear();
        match stdin.read_line(&mut line) {
            Ok(0) => std::thread::sleep(Duration::from_secs(1)),
            Ok(_) => {
                let command = line.trim();
                if !command.is_empty() {
                    print!("{}", transports::dispatch_text_line(&mut registry, command));
                    let _ = io::stdout().flush();
                }
                print!("dm-rs> ");
                let _ = io::stdout().flush();
            }
            Err(err) => {
                if err.kind() != io::ErrorKind::WouldBlock {
                    log::warn!("console read failed: {err}");
                    print!("dm-rs> ");
                    let _ = io::stdout().flush();
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}
