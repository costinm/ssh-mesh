use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

use anyhow::{bail, Result};
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::settings::{parse_bool, SharedSettings};
use super::telemetry;

const MODE_COMPANION: u8 = 0;
const MODE_INFRA: u8 = 1;
const DEFAULT_ADV_MS: u32 = 1_000;
const DEFAULT_WINDOW_MS: u32 = 60_000;
const DEFAULT_BOOT_WINDOW_MS: u32 = 10_000;
const DEFAULT_ACTIVE_MS: u32 = 60_000;
const PING_PREFIX: &[u8] = b"dmesh.ping";

static PRODUCT_MODE: AtomicU8 = AtomicU8::new(MODE_INFRA);
static COMPANION_ADVERTISING: AtomicBool = AtomicBool::new(false);
static COMPANION_DEADLINE_MS: AtomicU32 = AtomicU32::new(0);
static PING_RESPONSE_PENDING: AtomicBool = AtomicBool::new(false);
static PING_RX: AtomicU32 = AtomicU32::new(0);
static PING_TX: AtomicU32 = AtomicU32::new(0);

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    registry.register(ModeCommand { settings });
}

pub fn init(settings: &SharedSettings) {
    let mode = configured_mode(settings);
    PRODUCT_MODE.store(mode, Ordering::Relaxed);
    if mode == MODE_COMPANION {
        let _ = enter_companion_advertising(
            settings,
            get_u32(settings, "cm.boot_ms", DEFAULT_BOOT_WINDOW_MS),
            get_u32(settings, "cm.adv_ms", DEFAULT_ADV_MS),
            "boot",
        );
    } else {
        if let Err(err) = start_infra_radios(settings, "boot") {
            telemetry::record_log(format!(
                "event type=mode.infra_start ok=false reason=boot msg={}",
                crate::commands::protocol::escape_value(&err.to_string())
            ));
        }
        telemetry::record_log("event type=mode active=infra".to_string());
    }
}

pub fn configured_companion(settings: &SharedSettings) -> bool {
    configured_mode(settings) == MODE_COMPANION
}

pub fn init_after_boot_window(settings: &SharedSettings, button_wake: bool) {
    let mode = configured_mode(settings);
    PRODUCT_MODE.store(mode, Ordering::Relaxed);
    if mode == MODE_COMPANION {
        if button_wake {
            let _ = enter_companion_advertising(
                settings,
                get_u32(settings, "cm.win_ms", DEFAULT_WINDOW_MS),
                get_u32(settings, "cm.adv_ms", DEFAULT_ADV_MS),
                "button_wake",
            );
        } else if super::ble_bt::gatt_connected() {
            let _ = enter_companion_advertising(
                settings,
                get_u32(settings, "cm.active_ms", DEFAULT_ACTIVE_MS),
                get_u32(settings, "cm.adv_ms", DEFAULT_ADV_MS),
                "boot_connected",
            );
        } else if let Err(err) = enter_companion_sleep(settings) {
            telemetry::record_log(format!(
                "event type=mode.sleep ok=false reason=boot_window_done msg={}",
                crate::commands::protocol::escape_value(&err.to_string())
            ));
        }
    } else {
        COMPANION_ADVERTISING.store(false, Ordering::Relaxed);
        COMPANION_DEADLINE_MS.store(0, Ordering::Relaxed);
        if let Err(err) = start_infra_radios(settings, "boot_window_done") {
            telemetry::record_log(format!(
                "event type=mode.infra_start ok=false reason=boot_window_done msg={}",
                crate::commands::protocol::escape_value(&err.to_string())
            ));
        }
        telemetry::record_log("event type=mode active=infra reason=boot_window_done".to_string());
    }
}

pub fn set_infra(settings: &SharedSettings, save: bool, reason: &'static str) -> Result<()> {
    PRODUCT_MODE.store(MODE_INFRA, Ordering::Relaxed);
    COMPANION_ADVERTISING.store(false, Ordering::Relaxed);
    COMPANION_DEADLINE_MS.store(0, Ordering::Relaxed);
    if save {
        settings.borrow_mut().set_str("mode", "infra")?;
    }
    start_infra_radios(settings, reason)?;
    telemetry::record_log(format!("event type=mode active=infra reason={}", reason));
    Ok(())
}

pub fn enter_pairing_recovery(settings: &SharedSettings, window_ms: u32) {
    PRODUCT_MODE.store(MODE_COMPANION, Ordering::Relaxed);
    COMPANION_ADVERTISING.store(true, Ordering::Relaxed);
    COMPANION_DEADLINE_MS.store(now_ms().wrapping_add(window_ms), Ordering::Relaxed);
    super::nan::stop_nan().ok();
    super::wifi::stop_raw_monitor().ok();
    super::lora::sleep_radio(settings).ok();
    telemetry::record_log(format!(
        "event type=mode active=companion state=pairing_recovery window_ms={}",
        window_ms
    ));
}

pub fn poll(settings: &SharedSettings) {
    if PING_RESPONSE_PENDING.swap(false, Ordering::Relaxed) {
        if let Err(err) = send_status_ping(settings, "rx") {
            telemetry::record_log(format!(
                "event type=mode.ping_response ok=false msg={}",
                crate::commands::protocol::escape_value(&err.to_string())
            ));
        }
    }

    if PRODUCT_MODE.load(Ordering::Relaxed) != MODE_COMPANION {
        return;
    }
    if !COMPANION_ADVERTISING.load(Ordering::Relaxed) {
        return;
    }
    if super::ble_bt::gatt_connected() {
        COMPANION_DEADLINE_MS.store(
            now_ms().wrapping_add(get_u32(settings, "cm.active_ms", DEFAULT_ACTIVE_MS)),
            Ordering::Relaxed,
        );
        return;
    }
    let deadline = COMPANION_DEADLINE_MS.load(Ordering::Relaxed);
    if deadline != 0 && now_ms().wrapping_sub(deadline) < u32::MAX / 2 {
        if let Err(err) = enter_companion_sleep(settings) {
            telemetry::record_log(format!(
                "event type=mode.sleep ok=false msg={}",
                crate::commands::protocol::escape_value(&err.to_string())
            ));
            COMPANION_DEADLINE_MS
                .store(now_ms().wrapping_add(DEFAULT_WINDOW_MS), Ordering::Relaxed);
        }
    }
}

pub fn handle_button_short(settings: &SharedSettings) {
    if PRODUCT_MODE.load(Ordering::Relaxed) == MODE_INFRA {
        if let Err(err) = send_status_ping(settings, "button") {
            telemetry::record_log(format!(
                "event type=mode.button action=ping ok=false msg={}",
                crate::commands::protocol::escape_value(&err.to_string())
            ));
        }
        return;
    }
    if COMPANION_ADVERTISING.load(Ordering::Relaxed) && !super::ble_bt::gatt_connected() {
        if let Err(err) = enter_companion_sleep(settings) {
            telemetry::record_log(format!(
                "event type=mode.button action=sleep ok=false msg={}",
                crate::commands::protocol::escape_value(&err.to_string())
            ));
        }
    } else {
        let _ = enter_companion_advertising(
            settings,
            get_u32(settings, "cm.win_ms", DEFAULT_WINDOW_MS),
            get_u32(settings, "cm.adv_ms", DEFAULT_ADV_MS),
            "button",
        );
    }
}

pub fn mark_companion_active(settings: &SharedSettings, window_ms: u32) {
    if PRODUCT_MODE.load(Ordering::Relaxed) == MODE_COMPANION {
        let _ = enter_companion_advertising(
            settings,
            window_ms.max(1_000),
            get_u32(settings, "cm.adv_ms", DEFAULT_ADV_MS),
            "active",
        );
    }
}

pub fn observe_ping(transport: &'static str, payload: &[u8]) {
    if !payload.starts_with(PING_PREFIX) {
        return;
    }
    PING_RX.fetch_add(1, Ordering::Relaxed);
    telemetry::record_log(format!(
        "event type=mode.ping_rx transport={} len={}",
        transport,
        payload.len()
    ));
    if PRODUCT_MODE.load(Ordering::Relaxed) == MODE_INFRA
        && !payload
            .windows(b"reply=true".len())
            .any(|w| w == b"reply=true")
    {
        PING_RESPONSE_PENDING.store(true, Ordering::Relaxed);
    }
}

fn enter_companion_advertising(
    settings: &SharedSettings,
    window_ms: u32,
    adv_ms: u32,
    reason: &'static str,
) -> Result<()> {
    PRODUCT_MODE.store(MODE_COMPANION, Ordering::Relaxed);
    super::nan::stop_nan().ok();
    super::wifi::stop_raw_monitor().ok();
    super::lora::sleep_radio(settings).ok();
    super::ble_bt::set_advertising_interval_ms(adv_ms, adv_ms);
    super::ble_bt::start_connectable_advertising()?;
    super::ble_bt::open_companion_active_window(window_ms);
    COMPANION_ADVERTISING.store(true, Ordering::Relaxed);
    COMPANION_DEADLINE_MS.store(now_ms().wrapping_add(window_ms), Ordering::Relaxed);
    telemetry::record_log(format!(
        "event type=mode active=companion state=ble_advertising reason={} window_ms={} adv_ms={}",
        reason, window_ms, adv_ms
    ));
    Ok(())
}

fn enter_companion_sleep(settings: &SharedSettings) -> Result<()> {
    PRODUCT_MODE.store(MODE_COMPANION, Ordering::Relaxed);
    let lora_listen = get_bool(settings, "cm.lora", false);
    super::nan::stop_nan().ok();
    super::wifi::stop_raw_monitor().ok();
    super::ble_bt::stop_radio_activity();
    COMPANION_ADVERTISING.store(false, Ordering::Relaxed);
    COMPANION_DEADLINE_MS.store(0, Ordering::Relaxed);
    telemetry::record_log(format!(
        "event type=mode active=companion state=deep_sleep lora_listen={}",
        lora_listen
    ));
    super::sleep::enter_companion_deep_sleep(settings, lora_listen, 0, DEFAULT_ACTIVE_MS)
}

fn start_infra_radios(settings: &SharedSettings, reason: &'static str) -> Result<()> {
    let channel = get_u32(settings, "raw.ch", 6).clamp(1, 13) as u8;
    super::wifi::start_raw_monitor_mode(channel, "action")?;
    // TODO(raw-security): raw Wi-Fi commands are intentionally unauthenticated
    // during bring-up. Add mesh-owner public-key authentication and payload
    // encryption before this is used outside local testing.
    telemetry::record_log(format!(
        "event type=mode.infra_start raw_wifi=true channel={} reason={}",
        channel, reason
    ));
    Ok(())
}

fn send_status_ping(settings: &SharedSettings, source: &'static str) -> Result<()> {
    if PRODUCT_MODE.load(Ordering::Relaxed) == MODE_COMPANION {
        bail!("companion firmware does not send ping");
    }
    let mut payload = format!(
        "dmesh.ping type=status reply={} source={} uptime_ms={} {}",
        if source == "rx" { "true" } else { "false" },
        source,
        now_ms(),
        telemetry::stats_text(settings)
    );
    if payload.len() > 180 {
        payload.truncate(180);
    }
    let bytes = payload.as_bytes();
    let lora = super::lora::send_raw_text(settings, &payload).is_ok();
    let wifi = super::wifi::forward_management_packet(bytes).is_ok();
    let nan = super::nan::forward_packet(bytes).is_ok();
    PING_TX.fetch_add(1, Ordering::Relaxed);
    telemetry::record_log(format!(
        "event type=mode.ping_tx source={} len={} lora={} wifi_raw={} nan={}",
        source,
        bytes.len(),
        lora,
        wifi,
        nan
    ));
    Ok(())
}

fn configured_mode(settings: &SharedSettings) -> u8 {
    let from_mode = settings.borrow().get_str("mode").ok().flatten();
    if matches!(from_mode.as_deref(), Some("infra")) {
        return MODE_INFRA;
    }
    if matches!(from_mode.as_deref(), Some("companion")) {
        return MODE_COMPANION;
    }
    MODE_INFRA
}

fn get_u32(settings: &SharedSettings, key: &str, default: u32) -> u32 {
    settings
        .borrow()
        .get_i32(key, default as i32)
        .unwrap_or(default as i32)
        .max(0) as u32
}

fn get_bool(settings: &SharedSettings, key: &str, default: bool) -> bool {
    settings.borrow().get_bool(key, default).unwrap_or(default)
}

fn now_ms() -> u32 {
    (unsafe { sys::esp_timer_get_time() } / 1000) as u32
}

fn mode_name() -> &'static str {
    match PRODUCT_MODE.load(Ordering::Relaxed) {
        MODE_INFRA => "infra",
        _ => "companion",
    }
}

struct ModeCommand {
    settings: SharedSettings,
}

impl CommandHandler for ModeCommand {
    fn name(&self) -> &'static str {
        "mode"
    }

    fn help(&self) -> &'static str {
        "mode status=true | mode companion=true|infra=true save=true | mode advertise=true window_ms=60000 adv_ms=1000 | mode active=true ms=60000 | mode sleep=true | mode lora_sleep_listen=true save=true | mode raw_wifi=true channel=6 | mode ping=true"
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if request
            .arg("infra")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            if save_requested(request) {
                let mut settings = self.settings.borrow_mut();
                settings.set_str("mode", "infra")?;
                settings.set_bool("ble.comp", false)?;
                drop(settings);
                set_infra(&self.settings, false, "command")?;
            } else {
                set_infra(&self.settings, false, "command")?;
            }
            return Ok(CommandResponse::ok(status_text()));
        }
        if request
            .arg("companion")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            PRODUCT_MODE.store(MODE_COMPANION, Ordering::Relaxed);
            if save_requested(request) {
                self.settings.borrow_mut().set_str("mode", "companion")?;
            }
            enter_companion_advertising(
                &self.settings,
                get_u32(&self.settings, "cm.win_ms", DEFAULT_WINDOW_MS),
                get_u32(&self.settings, "cm.adv_ms", DEFAULT_ADV_MS),
                "command",
            )?;
            return Ok(CommandResponse::ok(status_text()));
        }
        if let Some(enabled) = request
            .arg("lora_sleep_listen")
            .or_else(|| request.arg("lora_listen"))
        {
            let enabled = parse_bool(enabled)?;
            if save_requested(request) {
                self.settings.borrow_mut().set_bool("cm.lora", enabled)?;
            }
            return Ok(CommandResponse::ok(status_text()));
        }
        if request
            .arg("raw_wifi")
            .or_else(|| request.arg("raw"))
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            let channel = request.arg_i32("channel")?.unwrap_or(6).clamp(1, 13) as u8;
            super::wifi::start_raw_monitor_mode(channel, "action")?;
            return Ok(CommandResponse::ok(format!(
                "mode raw_wifi=true channel={} {}",
                channel,
                status_text()
            )));
        }
        if request
            .arg("raw_wifi")
            .or_else(|| request.arg("raw"))
            .map(parse_bool)
            .transpose()?
            .is_some_and(|enabled| !enabled)
        {
            super::wifi::stop_raw_monitor()?;
            return Ok(CommandResponse::ok(format!(
                "mode raw_wifi=false {}",
                status_text()
            )));
        }
        if request
            .arg("ping")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            send_status_ping(&self.settings, "command")?;
            return Ok(CommandResponse::ok(status_text()));
        }
        if request
            .arg("active")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            let ms = request
                .arg_i32("ms")?
                .or(request.arg_i32("window_ms")?)
                .unwrap_or(DEFAULT_ACTIVE_MS as i32)
                .max(1_000) as u32;
            enter_companion_advertising(
                &self.settings,
                ms,
                get_u32(&self.settings, "cm.adv_ms", DEFAULT_ADV_MS),
                "command",
            )?;
            return Ok(CommandResponse::ok(status_text()));
        }
        if request
            .arg("advertise")
            .or_else(|| request.arg("adv"))
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            let window_ms = request
                .arg_i32("window_ms")?
                .or(request.arg_i32("ms")?)
                .unwrap_or(DEFAULT_WINDOW_MS as i32)
                .max(1_000) as u32;
            let adv_ms = request
                .arg_i32("adv_ms")?
                .unwrap_or(DEFAULT_ADV_MS as i32)
                .clamp(100, 10_000) as u32;
            enter_companion_advertising(&self.settings, window_ms, adv_ms, "command")?;
            return Ok(CommandResponse::ok(status_text()));
        }
        if request
            .arg("sleep")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            enter_companion_sleep(&self.settings)?;
            return Ok(CommandResponse::ok("mode sleep rejected"));
        }
        Ok(CommandResponse::ok(status_text()))
    }
}

fn save_requested(request: &CommandRequest) -> bool {
    request
        .arg("save")
        .map(parse_bool)
        .transpose()
        .unwrap_or(None)
        .unwrap_or(false)
}

fn status_text() -> String {
    format!(
        "mode active={} companion_advertising={} deadline_ms={} ping_rx={} ping_tx={}",
        mode_name(),
        COMPANION_ADVERTISING.load(Ordering::Relaxed),
        COMPANION_DEADLINE_MS.load(Ordering::Relaxed),
        PING_RX.load(Ordering::Relaxed),
        PING_TX.load(Ordering::Relaxed)
    )
}
