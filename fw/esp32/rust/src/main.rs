use anyhow::Result;
use esp_idf_svc::log::EspLogger;
use std::ffi::c_char;
use std::io::{self, Write};
use std::time::Duration;

mod commands;
mod components;
mod transports;

use commands::CommandRegistry;
use components::l3dmesh::{Frame, L3Mesh};

fn main() -> Result<()> {
    esp_idf_sys::link_patches();
    EspLogger::initialize_default();
    quiet_runtime_logs();

    if let Err(err) = components::sleep::handle_deep_sleep_wake() {
        components::telemetry::record_log(format!(
            "event type=sleep.error phase=wake message={}",
            commands::protocol::escape_value(&err.to_string())
        ));
    }

    let settings = components::settings::open_shared();
    let mut registry = CommandRegistry::new();
    components::register_commands(&mut registry, settings.clone());

    let ble_start = transports::dispatch_text_line(&mut registry, "ble start=true");
    if ble_start.starts_with("error ") {
        let line = format!(
            "event type=ble.error component=startup response={}",
            commands::protocol::escape_value(ble_start.trim())
        );
        components::telemetry::record_log(line);
    } else {
        let line = format!(
            "event type=ble.mode mode=listen source=startup {}",
            ble_start.trim()
        );
        components::telemetry::record_log(line);
    }
    match settings.borrow().get_bool("nan.enabled", false) {
        Ok(true) => {
            let backend = settings
                .borrow()
                .get_str("nan.backend")
                .ok()
                .flatten()
                .unwrap_or_else(|| "official".to_string());
            let role = settings
                .borrow()
                .get_str("nan.role")
                .ok()
                .flatten()
                .unwrap_or_else(|| "publisher".to_string());
            let service = settings
                .borrow()
                .get_str("nan.service")
                .ok()
                .flatten()
                .unwrap_or_else(|| "dmesh".to_string());
            let channel = settings.borrow().get_i32("nan.channel", 6).unwrap_or(6);
            let command = format!(
                "nan start=true backend={backend} role={role} service={service} channel={channel}"
            );
            let response = transports::dispatch_text_line(&mut registry, &command);
            let event_type = if response.starts_with("error ") {
                "nan.error"
            } else {
                "nan.mode"
            };
            let line = format!(
                "event type={event_type} source=startup response={}",
                commands::protocol::escape_value(response.trim())
            );
            components::telemetry::record_log(line);
        }
        Ok(false) => {}
        Err(err) => {
            let line = format!(
                "event type=nan.error source=startup message={}",
                commands::protocol::escape_value(&err.to_string())
            );
            components::telemetry::record_log(line);
        }
    }

    let mut mesh = L3Mesh::new();
    mesh.add_transport(components::ble_bt::ble_transport());
    mesh.add_transport(components::ble_bt::bt_transport());
    mesh.add_transport(components::lora::transport(settings.clone()));
    mesh.add_transport(components::nan::transport());

    let _lora_rx = match components::lora::start_background_rx(settings.clone()) {
        Ok(handle) => handle,
        Err(err) => {
            let line = format!(
                "event type=lora.error component=startup message={}",
                commands::protocol::escape_value(&err.to_string())
            );
            components::telemetry::record_log(line);
            None
        }
    };

    mesh.on_message(Frame::borrowed(b"hello from rust"), 0)?;

    let ready = "event type=system.ready app=dmesh-rs";
    components::telemetry::record_log(ready);
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

fn quiet_runtime_logs() {
    log::set_max_level(log::LevelFilter::Warn);
    unsafe {
        set_esp_log_level(b"*\0", esp_idf_sys::esp_log_level_t_ESP_LOG_WARN);
        set_esp_log_level(b"BT_APPL\0", esp_idf_sys::esp_log_level_t_ESP_LOG_NONE);
        set_esp_log_level(b"BT_BTM\0", esp_idf_sys::esp_log_level_t_ESP_LOG_NONE);
        set_esp_log_level(b"BT_HCI\0", esp_idf_sys::esp_log_level_t_ESP_LOG_NONE);
        set_esp_log_level(b"gpio\0", esp_idf_sys::esp_log_level_t_ESP_LOG_NONE);
        set_esp_log_level(b"nan_app\0", esp_idf_sys::esp_log_level_t_ESP_LOG_NONE);
    }
}

unsafe fn set_esp_log_level(tag: &'static [u8], level: esp_idf_sys::esp_log_level_t) {
    unsafe {
        esp_idf_sys::esp_log_level_set(tag.as_ptr() as *const c_char, level);
    }
}
