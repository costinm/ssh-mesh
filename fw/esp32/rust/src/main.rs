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
const MAIN_HOUSEKEEPING_POLL_MS: u64 = 1_000;

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
    components::wake::register_main_task();
    init_console_uart();
    rom_print(b"dm-rs boot step=logger\n\0");
    EspLogger::initialize_default();
    quiet_runtime_logs();

    let wake_cause = unsafe { esp_idf_sys::esp_sleep_get_wakeup_cause() };
    rom_print(b"dm-rs boot step=settings\n\0");
    let settings = components::settings::open_shared();
    components::serial::configure_active_window(&settings);
    rom_print(b"dm-rs boot step=power\n\0");
    if let Err(err) = components::power::apply_default(&settings) {
        components::telemetry::record_log(format!(
            "event type=power.default ok=false msg={}",
            commands::protocol::escape_value(&err.to_string())
        ));
    }
    rom_print(b"dm-rs boot step=wake\n\0");
    if let Err(err) = components::sleep::handle_deep_sleep_wake() {
        components::telemetry::record_log(format!(
            "event type=sleep.error phase=wake message={}",
            commands::protocol::escape_value(&err.to_string())
        ));
    }

    rom_print(b"dm-rs boot step=button\n\0");
    if let Err(err) = components::button::initialize(&settings) {
        components::telemetry::record_log(format!(
            "ev=button.err op=init err={}",
            commands::protocol::escape_value(&err.to_string())
        ));
    }

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
        .get_i32("cm.active_ms", 5_000)
        .unwrap_or(5_000)
        .max(0) as u32;
    components::ble_bt::configure_companion_advertising(30_000, 5_000);
    components::ble_bt::configure_companion_active_window(companion_active_ms);
    rom_print(b"dm-rs boot step=boot_window\n\0");
    let boot_window = run_boot_active_window(wake_cause, &mut registry);
    apply_post_boot_uart_policy(&boot_window);
    rom_print(b"dm-rs boot step=mode\n\0");
    if boot_window.pairing_recovery {
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

    if boot_window.pairing_recovery {
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

    let ready = "event type=system.ready app=dmesh-rs";
    components::telemetry::record_log(ready);
    components::serial::activate_window();
    rom_print(b"dm-rs boot step=console\n\0");
    uart_write("dm-rs> ");
    // Install the edge handler only after the UART manager and boot probe are
    // live. DTR/PRG then opens a 20-second console-active window without
    // racing early startup or the boot long-press pairing recovery path.
    match components::button::start_runtime_interrupts() {
        Ok(()) => components::telemetry::record_log("event type=button.runtime_interrupt ok=true"),
        Err(err) => components::telemetry::record_log(format!(
            "event type=button.runtime_interrupt ok=false msg={}",
            commands::protocol::escape_value(&err.to_string())
        )),
    }
    loop {
        components::telemetry::record_main_loop();
        components::mode::poll(&settings);
        components::ble_bt::poll_text_commands(&mut registry);
        poll_raw_wifi_commands(&mut registry, &settings);
        poll_nan_commands(&mut registry, &settings);
        components::test::poll_main();
        if components::button::take_console_wakes() > 0 {
            components::serial::rearm_after_wake();
            components::telemetry::record_log("event type=uart.wake source=button");
            uart_write("event type=uart.wake source=button\ndm-rs> ");
        }
        if components::button::take_long_presses() > 0 {
            components::serial::set_debug_enabled(true);
            components::serial::activate_window();
            components::mode::mark_companion_active(&settings, companion_active_ms);
            uart_write("dm-rs> ");
        }
        for _ in 0..components::button::take_sync_requests() {
            components::mode::send_button_sync(&settings);
        }
        drain_uart_console(&mut registry, &settings, companion_active_ms);
        match wait_for_firmware_activity(Duration::from_millis(MAIN_HOUSEKEEPING_POLL_MS)) {
            UartWait::Data => {}
            UartWait::Timeout => {
                components::telemetry::record_uart_timeout();
            }
        }
        components::serial::poll_active_window();
    }
}

fn drain_uart_console(
    registry: &mut CommandRegistry,
    settings: &components::settings::SharedSettings,
    companion_active_ms: u32,
) {
    while let Some(frame) = components::serial::take_frame() {
        components::mode::mark_companion_active(settings, companion_active_ms);
        match frame.kind {
            components::serial::UartFrameKind::Text => {
                let command = core::str::from_utf8(&frame.data).unwrap_or("").trim();
                if !command.is_empty() {
                    uart_write(&transports::dispatch_text_line(registry, command));
                }
                uart_write("dm-rs> ");
            }
            components::serial::UartFrameKind::Binary => {
                let response = transports::dispatch_binary_packet(registry, &frame.data);
                components::serial::write_bytes(&response);
            }
        }
        // The manager owns driver deletion. It observes this notification only
        // after the acknowledgement above has been accepted by UART TX.
        let _ = components::serial::finish_pending_uninstall();
        let _ = components::serial::finish_pending_suspend();
    }
}

enum UartWait {
    Data,
    Timeout,
}

struct BootWindowResult {
    probed: bool,
    pairing_recovery: bool,
    uart_input: bool,
}

fn run_boot_active_window(
    wake_cause: esp_idf_sys::esp_sleep_source_t,
    registry: &mut CommandRegistry,
) -> BootWindowResult {
    if !is_real_boot(wake_cause) {
        return BootWindowResult {
            probed: false,
            pairing_recovery: false,
            uart_input: false,
        };
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
        boot_active_window_ms()
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

    let deadline = Instant::now() + Duration::from_millis(boot_active_window_ms() as u64);
    let mut uart_input = false;
    uart_write("dm-rs> ");
    if boot_pressed {
        let hold = Duration::from_millis(BOOT_PAIRING_HOLD_MS as u64);
        let _ = wait_for_firmware_activity(hold);
        uart_input |= poll_boot_console(registry);
        if components::button::is_pressed() {
            uart_write("event type=boot_window long_press=true action=pairing_recovery\n");
            components::button::suppress_until_release();
            components::telemetry::record_log(
                "event type=boot_window long_press=true pending=pairing_recovery",
            );
            components::telemetry::record_log(
                "event type=boot_window done=true pairing_recovery=true immediate=true",
            );
            return BootWindowResult {
                probed: true,
                pairing_recovery: true,
                uart_input,
            };
        }
    }
    while Instant::now() < deadline {
        uart_input |= poll_boot_console(registry);
        if probe_long_press && components::button::take_long_presses() > 0 {
            uart_write("event type=boot_window long_press=true action=pairing_recovery\n");
            components::button::suppress_until_release();
            components::telemetry::record_log(
                "event type=boot_window long_press=true pending=pairing_recovery",
            );
            components::telemetry::record_log(
                "event type=boot_window done=true pairing_recovery=true immediate=true",
            );
            return BootWindowResult {
                probed: true,
                pairing_recovery: true,
                uart_input,
            };
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let wait = remaining.min(Duration::from_millis(500));
        let _ = wait_for_firmware_activity(wait);
    }
    components::telemetry::record_log(format!(
        "event type=boot_window done=true pairing_recovery={}",
        false
    ));
    BootWindowResult {
        probed: true,
        pairing_recovery: false,
        uart_input,
    }
}

fn boot_active_window_ms() -> u32 {
    BOOT_ACTIVE_WINDOW_MS
}

fn apply_post_boot_uart_policy(boot_window: &BootWindowResult) {
    if !boot_window.probed {
        return;
    }
    if boot_window.uart_input {
        components::telemetry::record_log("event type=uart.boot_policy input=true debug=true");
        components::serial::set_debug_enabled(true);
        return;
    }

    components::telemetry::record_log("event type=uart.boot_policy input=false debug=false");
    components::serial::set_debug_enabled(false);
}

fn poll_boot_console(registry: &mut CommandRegistry) -> bool {
    let mut received = false;
    while let Some(frame) = components::serial::take_frame() {
        received = true;
        match frame.kind {
            components::serial::UartFrameKind::Text => {
                let command = core::str::from_utf8(&frame.data).unwrap_or("").trim();
                if !command.is_empty() {
                    uart_write(&transports::dispatch_text_line(registry, command));
                }
                uart_write("dm-rs> ");
            }
            components::serial::UartFrameKind::Binary => {
                components::serial::write_bytes(&transports::dispatch_binary_packet(
                    registry,
                    &frame.data,
                ));
            }
        }
        let _ = components::serial::finish_pending_suspend();
        let _ = components::serial::finish_pending_uninstall();
    }
    received
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

fn poll_raw_wifi_commands(
    registry: &mut CommandRegistry,
    settings: &components::settings::SharedSettings,
) {
    components::telemetry::record_raw_poll();
    while let Some(command) = components::wifi::take_raw_command() {
        components::telemetry::record_raw_command();
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
        let response = if command.text.starts_with("dmesh.ping") {
            let source = match command.response {
                components::wifi::WifiResponsePath::Action => "wifi_raw",
                components::wifi::WifiResponsePath::Data => "wifi_data",
            };
            components::mode::status_pong_text(settings, source)
        } else {
            transports::dispatch_text_line(registry, &command.text)
        };
        let response = format!("resp {response}");
        if let Err(err) = components::wifi::send_response_payload_to(
            command.response,
            command.source,
            response.as_bytes(),
        ) {
            components::telemetry::record_log(format!(
                "event type=wifi.raw_response ok=false msg={}",
                commands::protocol::escape_value(&err.to_string())
            ));
        }
    }
}

fn poll_nan_commands(
    registry: &mut CommandRegistry,
    settings: &components::settings::SharedSettings,
) {
    while let Some(command) = components::nan::take_command() {
        components::telemetry::record_log(format!(
            "event type=nan.command len={}",
            command.text.len()
        ));
        let response = if command.text.starts_with("dmesh.ping") {
            components::mode::status_pong_text(settings, "nan")
        } else {
            transports::dispatch_text_line(registry, &command.text)
        };
        let response = format!("resp {response}");
        if let Err(err) = components::nan::send_response_payload_to(&command, response.as_bytes()) {
            components::telemetry::record_log(format!(
                "event type=nan.response ok=false msg={}",
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
        config.baud_rate = 460_800;
        config.data_bits = esp_idf_sys::uart_word_length_t_UART_DATA_8_BITS;
        config.parity = esp_idf_sys::uart_parity_t_UART_PARITY_DISABLE;
        config.stop_bits = esp_idf_sys::uart_stop_bits_t_UART_STOP_BITS_1;
        config.flow_ctrl = esp_idf_sys::uart_hw_flowcontrol_t_UART_HW_FLOWCTRL_DISABLE;
        config.__bindgen_anon_1.source_clk = uart_source_clk();

        let _ = esp_idf_sys::uart_param_config(UART0, &config);
        let mut queue: esp_idf_sys::QueueHandle_t = core::ptr::null_mut();
        let mut install = esp_idf_sys::uart_driver_install(UART0, 2048, 1024, 16, &mut queue, 0);
        if install == esp_idf_sys::ESP_ERR_INVALID_STATE {
            // ESP-IDF may have installed its stdio UART0 driver before app_main.
            // It has no event queue we can own, so replace it rather than silently
            // accepting a console that can write but never receive commands.
            let _ = esp_idf_sys::uart_driver_delete(UART0);
            queue = core::ptr::null_mut();
            install = esp_idf_sys::uart_driver_install(UART0, 2048, 1024, 16, &mut queue, 0);
        }
        if install == esp_idf_sys::ESP_OK {
            if !queue.is_null() {
                let _ = components::serial::start_ingress_task(queue);
            }
            esp_idf_sys::esp_vfs_dev_uart_use_driver(UART0_VFS);
            esp_idf_sys::esp_vfs_dev_uart_port_set_rx_line_endings(
                UART0_VFS,
                esp_idf_sys::esp_line_endings_t_ESP_LINE_ENDINGS_LF,
            );
            esp_idf_sys::esp_vfs_dev_uart_port_set_tx_line_endings(
                UART0_VFS,
                esp_idf_sys::esp_line_endings_t_ESP_LINE_ENDINGS_CRLF,
            );
            components::serial::activate_window();
        }
    }
}

#[cfg(target_feature = "esp32s3ops")]
fn uart_source_clk() -> esp_idf_sys::uart_sclk_t {
    esp_idf_sys::soc_periph_uart_clk_src_legacy_t_UART_SCLK_XTAL
}

#[cfg(not(target_feature = "esp32s3ops"))]
fn uart_source_clk() -> esp_idf_sys::uart_sclk_t {
    // REF_TICK is only 1 MHz and cannot represent 460800 baud accurately on
    // classic ESP32; it silently corrupts RX. Classic ESP-IDF exposes APB as
    // the accurate source. The active UART PM lock keeps that clock stable.
    esp_idf_sys::soc_periph_uart_clk_src_legacy_t_UART_SCLK_APB
}

fn wait_for_firmware_activity(timeout: Duration) -> UartWait {
    if components::wake::wait(timeout) {
        UartWait::Data
    } else {
        UartWait::Timeout
    }
}

fn uart_write(text: &str) {
    components::serial::write(text);
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
        set_esp_log_level(b"wifi\0", esp_idf_sys::esp_log_level_t_ESP_LOG_NONE);
    }
}

unsafe fn set_esp_log_level(tag: &'static [u8], level: esp_idf_sys::esp_log_level_t) {
    unsafe {
        esp_idf_sys::esp_log_level_set(tag.as_ptr() as *const c_char, level);
    }
}
