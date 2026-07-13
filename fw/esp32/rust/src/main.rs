use anyhow::Result;
use esp_idf_svc::log::EspLogger;
use std::ffi::c_char;
use std::time::{Duration, Instant};

mod commands;
mod components;
mod transports;

use commands::CommandRegistry;
use components::l3dmesh::L3Mesh;

const BOOT_ACTIVE_WINDOW_MS: u32 = 10_000;
const BOOT_PAIRING_HOLD_MS: u32 = 3_000;
const BOOT_POLL_MS: u64 = 100;

fn main() {
    if let Err(err) = run() {
        let _ = err;
        rom_print(b"event type=system.error phase=main\n\0");
    }
}

#[no_mangle]
pub extern "C" fn app_main() {
    rom_print(b"dm-rs boot step=app_main\n\0");
    if let Err(err) = run() {
        let _ = err;
        rom_print(b"dm-rs boot step=app_error\n\0");
    }
}

fn run() -> Result<()> {
    rom_print(b"dm-rs boot step=link_patches\n\0");
    esp_idf_sys::link_patches();
    init_console_uart();
    rom_print(b"dm-rs boot step=logger\n\0");
    EspLogger::initialize_default();
    quiet_runtime_logs();

    let wake_cause = unsafe { esp_idf_sys::esp_sleep_get_wakeup_cause() };
    rom_print(b"dm-rs boot step=wake\n\0");
    if let Err(err) = components::sleep::handle_deep_sleep_wake() {
        components::telemetry::record_log(format!(
            "event type=sleep.error phase=wake message={}",
            commands::protocol::escape_value(&err.to_string())
        ));
    }

    rom_print(b"dm-rs boot step=settings\n\0");
    let settings = components::settings::open_shared();
    rom_print(b"dm-rs boot step=registry\n\0");
    let mut registry = CommandRegistry::new();
    components::register_commands(&mut registry, settings.clone());

    rom_print(b"dm-rs boot step=ble_config\n\0");
    let companion_setting = settings.borrow().get_bool("ble.comp", true);
    if let Err(err) = &companion_setting {
        let line = format!(
            "event type=ble.companion_error source=startup message={}",
            commands::protocol::escape_value(&err.to_string())
        );
        components::telemetry::record_log(line);
    }
    let companion_active_ms = settings
        .borrow()
        .get_i32("cm.active_ms", 60_000)
        .unwrap_or(60_000)
        .max(0) as u32;
    components::ble_bt::configure_companion_advertising(2_000, 1_000);
    components::ble_bt::configure_companion_active_window(companion_active_ms);
    rom_print(b"dm-rs boot step=boot_window\n\0");
    let pairing_recovery = run_boot_active_window(wake_cause, &mut registry);
    rom_print(b"dm-rs boot step=mode\n\0");
    if pairing_recovery {
        match components::ble_bt::start_pairing_recovery(&settings) {
            Ok(removed) => {
                components::telemetry::record_log(format!(
                    "event type=boot_window pairing_recovery=true bonds_removed={}",
                    removed
                ));
            }
            Err(err) => {
                components::telemetry::record_log(format!(
                    "event type=boot_window pairing_recovery=false msg={}",
                    commands::protocol::escape_value(&err.to_string())
                ));
            }
        }
        components::mode::enter_pairing_recovery(
            &settings,
            components::ble_bt::PAIRING_RECOVERY_WINDOW_MS,
        );
    } else if is_real_boot(wake_cause) || is_button_wake(wake_cause) {
        components::mode::init_after_boot_window(&settings, is_button_wake(wake_cause));
    } else {
        components::mode::init(&settings);
    }

    if pairing_recovery {
        rom_print(b"dm-rs boot step=mesh_skip_pairing\n\0");
        components::telemetry::record_log(
            "event type=mesh.start skipped=true reason=pairing_recovery",
        );
    } else {
        rom_print(b"dm-rs boot step=mesh\n\0");
        let mut mesh = L3Mesh::new();
        rom_print(b"dm-rs boot step=mesh_ble_local_only\n\0");
        rom_print(b"dm-rs boot step=mesh_lora\n\0");
        mesh.add_transport(components::lora::transport(settings.clone()));
        rom_print(b"dm-rs boot step=mesh_nan\n\0");
        mesh.add_transport(components::nan::transport());
    }

    let mut serial_enabled = true;
    let ready = "event type=system.ready app=dmesh-rs";
    components::telemetry::record_log(ready);
    rom_print(b"dm-rs boot step=console\n\0");
    let mut line = Vec::new();
    if serial_enabled {
        uart_write("dm-rs> ");
    }
    loop {
        components::mode::poll(&settings);
        components::ble_bt::poll_text_commands(&mut registry);
        poll_raw_wifi_commands(&mut registry);
        components::button::poll_level_press();
        if components::button::take_long_presses() > 0 {
            serial_enabled = true;
            components::mode::mark_companion_active(&settings, companion_active_ms);
            uart_write("dm-rs> ");
        }
        for _ in 0..components::button::take_cycle_presses() {
            components::mode::handle_button_short(&settings);
            serial_enabled = true;
            if serial_enabled {
                uart_write("dm-rs> ");
            }
        }
        let mut buf = [0_u8; 128];
        match uart_read(&mut buf) {
            read if read > 0 => {
                if !serial_enabled {
                    serial_enabled = true;
                    uart_write("dm-rs> ");
                }
                components::mode::mark_companion_active(&settings, companion_active_ms);
                let read = read as usize;
                for byte in &buf[..read] {
                    if *byte == b'\n' || *byte == b'\r' {
                        let command = core::str::from_utf8(&line).unwrap_or("").trim();
                        if !command.is_empty() {
                            let response = transports::dispatch_text_line(&mut registry, command);
                            uart_write(&response);
                        }
                        line.clear();
                        uart_write("dm-rs> ");
                    } else {
                        line.push(*byte);
                    }
                }
            }
            -1 => {
                log::warn!("console read failed");
                std::thread::sleep(Duration::from_millis(250));
            }
            _ => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

fn run_boot_active_window(
    wake_cause: esp_idf_sys::esp_sleep_source_t,
    registry: &mut CommandRegistry,
) -> bool {
    if !is_real_boot(wake_cause) {
        return false;
    }

    let boot_pressed = components::button::is_pressed();
    let probe_long_press = true;
    components::telemetry::record_log(
        "event type=boot_window barrier=true action=watch_prg_and_console",
    );
    uart_write("event type=boot_window barrier=true action=watch_prg_and_console\n");
    components::telemetry::record_log(format!(
        "event type=boot_window start=true cause={} probe_long_press={} window_ms={}",
        wake_cause_name(wake_cause),
        probe_long_press,
        BOOT_ACTIVE_WINDOW_MS
    ));
    uart_write(&format!(
        "event type=boot_window start=true cause={} probe_long_press={} gpio={} pressed={}\n",
        wake_cause_name(wake_cause),
        probe_long_press,
        components::button::configured_gpio()
            .map(|pin| pin.to_string())
            .unwrap_or_else(|| "none".to_string()),
        boot_pressed
    ));

    let deadline = Instant::now() + Duration::from_millis(BOOT_ACTIVE_WINDOW_MS as u64);
    let mut pressed_since: Option<Instant> = None;
    let mut pairing_recovery_requested = false;
    let mut line = Vec::new();
    uart_write("dm-rs> ");
    while Instant::now() < deadline {
        poll_boot_console(registry, &mut line);
        if probe_long_press {
            if components::button::is_pressed() {
                let start = match pressed_since {
                    Some(start) => start,
                    None => {
                        let start = Instant::now();
                        pressed_since = Some(start);
                        uart_write("event type=boot_window button_down=true\n");
                        start
                    }
                };
                if !pairing_recovery_requested
                    && start.elapsed() >= Duration::from_millis(BOOT_PAIRING_HOLD_MS as u64)
                {
                    pairing_recovery_requested = true;
                    uart_write("event type=boot_window long_press=true action=pairing_recovery\n");
                    components::button::suppress_until_release();
                    components::telemetry::record_log(
                        "event type=boot_window long_press=true pending=pairing_recovery",
                    );
                }
            } else {
                if let Some(start) = pressed_since.take() {
                    uart_write(&format!(
                        "event type=boot_window button_up=true held_ms={}\n",
                        start.elapsed().as_millis()
                    ));
                }
                pressed_since = None;
            }
        }
        std::thread::sleep(Duration::from_millis(BOOT_POLL_MS));
    }
    components::telemetry::record_log(format!(
        "event type=boot_window done=true pairing_recovery={}",
        pairing_recovery_requested
    ));
    pairing_recovery_requested
}

fn poll_boot_console(registry: &mut CommandRegistry, line: &mut Vec<u8>) {
    let mut buf = [0_u8; 128];
    match uart_read(&mut buf) {
        read if read > 0 => {
            let read = read as usize;
            for byte in &buf[..read] {
                if *byte == b'\n' || *byte == b'\r' {
                    let command = core::str::from_utf8(line).unwrap_or("").trim();
                    if !command.is_empty() {
                        let response = transports::dispatch_text_line(registry, command);
                        uart_write(&response);
                    }
                    line.clear();
                    uart_write("dm-rs> ");
                } else {
                    line.push(*byte);
                }
            }
        }
        -1 => {
            log::warn!("boot console read failed");
            std::thread::sleep(Duration::from_millis(20));
        }
        _ => {}
    }
}

fn is_real_boot(cause: esp_idf_sys::esp_sleep_source_t) -> bool {
    cause == esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_UNDEFINED
}

fn is_button_wake(cause: esp_idf_sys::esp_sleep_source_t) -> bool {
    cause == esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_EXT0
}

fn wake_cause_name(cause: esp_idf_sys::esp_sleep_source_t) -> &'static str {
    match cause {
        x if x == esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_UNDEFINED => "undefined",
        x if x == esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_EXT0 => "ext0",
        x if x == esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_EXT1 => "ext1",
        x if x == esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_TIMER => "timer",
        x if x == esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_GPIO => "gpio",
        x if x == esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_UART => "uart",
        _ => "other",
    }
}

fn poll_raw_wifi_commands(registry: &mut CommandRegistry) {
    while let Some(command) = components::wifi::take_raw_command() {
        components::telemetry::record_log(format!(
            "event type=wifi.raw_command source={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} len={} rssi={}",
            command.source[0],
            command.source[1],
            command.source[2],
            command.source[3],
            command.source[4],
            command.source[5],
            command.text.len(),
            command.rssi
        ));
        let response = transports::dispatch_text_line(registry, &command.text);
        if let Err(err) =
            components::wifi::send_vendor_payload_to(command.source, response.as_bytes())
        {
            components::telemetry::record_log(format!(
                "event type=wifi.raw_response ok=false msg={}",
                commands::protocol::escape_value(&err.to_string())
            ));
        }
    }
}

fn rom_print(message: &'static [u8]) {
    unsafe {
        esp_idf_sys::esp_rom_printf(message.as_ptr() as *const c_char);
    }
}

fn init_console_uart() {
    const UART0: esp_idf_sys::uart_port_t = esp_idf_sys::uart_port_t_UART_NUM_0;
    const UART0_VFS: core::ffi::c_int = esp_idf_sys::uart_port_t_UART_NUM_0 as core::ffi::c_int;

    unsafe {
        let mut config = esp_idf_sys::uart_config_t::default();
        config.baud_rate = 115_200;
        config.data_bits = esp_idf_sys::uart_word_length_t_UART_DATA_8_BITS;
        config.parity = esp_idf_sys::uart_parity_t_UART_PARITY_DISABLE;
        config.stop_bits = esp_idf_sys::uart_stop_bits_t_UART_STOP_BITS_1;
        config.flow_ctrl = esp_idf_sys::uart_hw_flowcontrol_t_UART_HW_FLOWCTRL_DISABLE;
        config.__bindgen_anon_1.source_clk =
            esp_idf_sys::soc_periph_uart_clk_src_legacy_t_UART_SCLK_DEFAULT;

        let _ = esp_idf_sys::uart_param_config(UART0, &config);
        let install =
            esp_idf_sys::uart_driver_install(UART0, 1024, 1024, 0, core::ptr::null_mut(), 0);
        if install == esp_idf_sys::ESP_OK || install == esp_idf_sys::ESP_ERR_INVALID_STATE {
            esp_idf_sys::esp_vfs_dev_uart_use_driver(UART0_VFS);
            esp_idf_sys::esp_vfs_dev_uart_port_set_rx_line_endings(
                UART0_VFS,
                esp_idf_sys::esp_line_endings_t_ESP_LINE_ENDINGS_LF,
            );
            esp_idf_sys::esp_vfs_dev_uart_port_set_tx_line_endings(
                UART0_VFS,
                esp_idf_sys::esp_line_endings_t_ESP_LINE_ENDINGS_CRLF,
            );
        }
    }
}

fn uart_read(buf: &mut [u8]) -> i32 {
    unsafe {
        esp_idf_sys::uart_read_bytes(
            esp_idf_sys::uart_port_t_UART_NUM_0,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            buf.len() as u32,
            2,
        )
    }
}

fn uart_write(text: &str) {
    unsafe {
        let bytes = text.as_bytes();
        let _ = esp_idf_sys::uart_write_bytes(
            esp_idf_sys::uart_port_t_UART_NUM_0,
            bytes.as_ptr() as *const core::ffi::c_void,
            bytes.len(),
        );
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
