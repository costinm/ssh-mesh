use std::ffi::{c_char, CString};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

use anyhow::{bail, Result};
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::settings::{parse_bool, SharedSettings};
use super::telemetry;

const MODE_COMPANION: u8 = 0;
const MODE_INFRA: u8 = 1;
const DEFAULT_ADV_MS: u32 = 1_000;
const DEFAULT_PENDING_ADV_MS: u32 = 1_500;
const DEFAULT_WINDOW_MS: u32 = 10_000;
const DEFAULT_BOOT_WINDOW_MS: u32 = 10_000;
const DEFAULT_ACTIVE_MS: u32 = 5_000;
const DEFAULT_PENDING_WINDOW_MS: u32 = 30_000;
const DEFAULT_WAKE_MS: u32 = 30_000;
const DEFAULT_NAN_DUTY_MS: u32 = 2_000;
const DEFAULT_NAN_ACTIVE_MS: u32 = 500;
const PING_PREFIX: &[u8] = b"dmesh.ping";

static PRODUCT_MODE: AtomicU8 = AtomicU8::new(MODE_INFRA);
static COMPANION_ADVERTISING: AtomicBool = AtomicBool::new(false);
static COMPANION_DEADLINE_MS: AtomicU32 = AtomicU32::new(0);
static COMPANION_PENDING_ADVERTISING: AtomicBool = AtomicBool::new(false);
static RAW_NAN_DUTY_ENABLED: AtomicBool = AtomicBool::new(false);
static RAW_NAN_DUTY_ACTIVE: AtomicBool = AtomicBool::new(false);
static RAW_NAN_DUTY_NEXT_MS: AtomicU32 = AtomicU32::new(0);
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

#[allow(dead_code)]
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
        COMPANION_PENDING_ADVERTISING.store(false, Ordering::Relaxed);
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
    COMPANION_PENDING_ADVERTISING.store(false, Ordering::Relaxed);
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
    COMPANION_PENDING_ADVERTISING.store(false, Ordering::Relaxed);
    COMPANION_DEADLINE_MS.store(now_ms().wrapping_add(window_ms), Ordering::Relaxed);
    stop_raw_nan_duty();
    super::nan::stop_nan().ok();
    super::wifi::stop_raw_monitor().ok();
    super::lora::sleep_radio(settings).ok();
    telemetry::record_log(format!(
        "event type=mode active=companion state=pairing_recovery window_ms={}",
        window_ms
    ));
}

pub fn poll(settings: &SharedSettings) {
    poll_raw_nan_duty(settings);

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
        COMPANION_PENDING_ADVERTISING.store(false, Ordering::Relaxed);
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
    observe_ping_inner(transport, payload, true);
}

pub fn observe_ping_no_auto_response(transport: &'static str, payload: &[u8]) {
    observe_ping_inner(transport, payload, false);
}

fn observe_ping_inner(transport: &'static str, payload: &[u8], auto_response: bool) {
    if !payload.starts_with(PING_PREFIX) {
        return;
    }
    PING_RX.fetch_add(1, Ordering::Relaxed);
    telemetry::record_log(format!(
        "event type=mode.ping_rx transport={} len={}",
        transport,
        payload.len()
    ));
    if auto_response
        && PRODUCT_MODE.load(Ordering::Relaxed) == MODE_INFRA
        && !payload
            .windows(b"reply=true".len())
            .any(|w| w == b"reply=true")
    {
        PING_RESPONSE_PENDING.store(true, Ordering::Relaxed);
    }
}

pub fn status_pong_text(settings: &SharedSettings, source: &'static str) -> String {
    let mut payload = format!(
        "dmesh.pong type=status reply=true source={} uptime_ms={} {}",
        source,
        now_ms(),
        telemetry::stats_text(settings)
    );
    if payload.len() > 220 {
        payload.truncate(220);
    }
    payload
}

fn enter_companion_advertising(
    settings: &SharedSettings,
    window_ms: u32,
    adv_ms: u32,
    reason: &'static str,
) -> Result<()> {
    PRODUCT_MODE.store(MODE_COMPANION, Ordering::Relaxed);
    if reason != "pending" {
        COMPANION_PENDING_ADVERTISING.store(false, Ordering::Relaxed);
    }
    stop_raw_nan_duty();
    super::nan::stop_nan().ok();
    super::wifi::stop_raw_monitor().ok();
    super::lora::sleep_radio(settings).ok();
    super::ble_bt::set_advertising_interval_ms(adv_ms, adv_ms);
    if let Err(err) = super::sleep::enable_companion_idle_pm(settings) {
        telemetry::record_log(format!(
            "event type=mode.companion_pm ok=false msg={}",
            crate::commands::protocol::escape_value(&err.to_string())
        ));
    }
    if let Err(err) = super::ble_bt::enable_controller_sleep() {
        telemetry::record_log(format!(
            "event type=mode.companion_ble_sleep ok=false msg={}",
            crate::commands::protocol::escape_value(&err.to_string())
        ));
    }
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
    let pending = telemetry::pending_message_count();
    if pending > 0 && !COMPANION_PENDING_ADVERTISING.swap(true, Ordering::Relaxed) {
        let window_ms = get_u32(settings, "cm.pending_ms", DEFAULT_PENDING_WINDOW_MS);
        let adv_ms = get_u32(settings, "cm.pending_adv_ms", DEFAULT_PENDING_ADV_MS);
        telemetry::record_log(format!(
            "event type=mode active=companion state=pending_advertising pending={} window_ms={} adv_ms={}",
            pending, window_ms, adv_ms
        ));
        return enter_companion_advertising(settings, window_ms, adv_ms, "pending");
    }

    stop_raw_nan_duty();
    super::nan::stop_nan().ok();
    super::wifi::stop_raw_monitor().ok();
    super::ble_bt::stop_radio_activity();
    COMPANION_ADVERTISING.store(false, Ordering::Relaxed);
    COMPANION_PENDING_ADVERTISING.store(false, Ordering::Relaxed);
    COMPANION_DEADLINE_MS.store(0, Ordering::Relaxed);
    let wake_ms = get_u32(settings, "cm.wake_ms", DEFAULT_WAKE_MS);
    let active_ms = if lora_listen {
        get_u32(settings, "cm.active_ms", DEFAULT_ACTIVE_MS)
    } else {
        0
    };
    telemetry::record_log(format!(
        "event type=mode active=companion state=deep_sleep lora_listen={} wake_ms={} active_ms={} pending={}",
        lora_listen, wake_ms, active_ms, pending
    ));
    super::sleep::enter_companion_deep_sleep(settings, lora_listen, wake_ms, active_ms)
}

fn start_infra_radios(settings: &SharedSettings, reason: &'static str) -> Result<()> {
    boot_print("dm-rs mode step=infra_start");
    let channel = get_u32(settings, "raw.ch", 6).clamp(1, 13) as u8;
    let wifi_mode = settings
        .borrow()
        .get_str("wifi.mode")
        .ok()
        .flatten()
        .unwrap_or_else(|| "nan".to_string());
    match wifi_mode.as_str() {
        "off" | "false" | "none" => {
            stop_raw_nan_duty();
            super::wifi::stop_raw_monitor().ok();
            super::nan::stop_nan().ok();
            telemetry::record_log(format!(
                "event type=mode.infra_radio medium=wifi status=off channel={} reason={}",
                channel, reason
            ));
        }
        "nan" | "aware" | "true" | "" => {
            boot_print("dm-rs mode step=wifi_raw_nan");
            start_raw_nan_duty(settings, reason, channel)?;
        }
        "official_nan" | "nan_official" | "idf_nan" => {
            boot_print("dm-rs mode step=wifi_official_nan");
            stop_raw_nan_duty();
            super::wifi::stop_raw_monitor().ok();
            match super::nan::start_infra_default(settings.clone()) {
                Ok(status) => telemetry::record_log(format!(
                    "event type=mode.infra_radio medium=nan status=started channel={} reason={} {}",
                    channel,
                    reason,
                    status
                )),
                Err(err) => telemetry::record_log(format!(
                    "event type=mode.infra_radio medium=nan status=error channel={} reason={} msg={}",
                    channel,
                    reason,
                    crate::commands::protocol::escape_value(&err.to_string())
                )),
            }
        }
        "nan_sleep" | "raw_nan_sleep" | "sleepy_nan" => {
            boot_print("dm-rs mode step=wifi_nan_sleep");
            stop_raw_nan_duty();
            super::nan::stop_nan().ok();
            super::wifi::stop_raw_monitor().ok();
            super::ble_bt::stop_radio_activity();
            let nan_channel = get_u32(settings, "nan.channel", channel as u32).clamp(1, 13) as u8;
            let wake_ms = get_u32(
                settings,
                "nan.wake_ms",
                get_u32(settings, "cm.wake_ms", 2_000),
            );
            let active_ms = get_u32(
                settings,
                "nan.active_ms",
                get_u32(settings, "cm.active_ms", 500),
            );
            let lora_listen = get_bool(settings, "lora.enabled", true);
            telemetry::record_log(format!(
                "event type=mode.infra_radio medium=nan status=sleepy_raw channel={} reason={} wake_ms={} active_ms={} lora_listen={}",
                nan_channel, reason, wake_ms, active_ms, lora_listen
            ));
            return super::sleep::enter_raw_nan_deep_sleep(
                settings,
                lora_listen,
                wake_ms,
                active_ms,
                nan_channel,
            );
        }
        "sta_idle" | "idle_sta" | "sta_only" => {
            boot_print("dm-rs mode step=wifi_sta_idle");
            stop_raw_nan_duty();
            super::nan::stop_nan().ok();
            let ssid = settings
                .borrow()
                .get_str("wifi.ssid")
                .ok()
                .flatten()
                .unwrap_or_else(|| "DMesh-Idle".to_string());
            super::wifi::start_sta_idle_mode(channel, &ssid)?;
            telemetry::record_log(format!(
                "event type=mode.infra_radio medium=wifi status=sta_idle ssid={} channel={} reason={}",
                crate::commands::protocol::escape_value(&ssid),
                channel,
                reason
            ));
        }
        "raw" | "dmesh" => {
            boot_print("dm-rs mode step=wifi_raw");
            stop_raw_nan_duty();
            super::nan::stop_nan().ok();
            super::wifi::start_raw_monitor_mode(channel, "dmesh")?;
            // TODO(raw-security): raw Wi-Fi commands are intentionally
            // unauthenticated during bring-up. Add mesh-owner public-key
            // authentication and payload encryption before this is used
            // outside local testing.
            telemetry::record_log(format!(
                "event type=mode.infra_radio medium=wifi status=raw channel={} filter=dmesh reason={}",
                channel, reason
            ));
        }
        other => {
            boot_print("dm-rs mode step=wifi_invalid_fallback");
            telemetry::record_log(format!(
                "event type=mode.infra_radio medium=wifi status=invalid mode={} action=raw_nan_duty reason={}",
                crate::commands::protocol::escape_value(other),
                reason
            ));
            start_raw_nan_duty(settings, reason, channel)?;
        }
    }
    boot_print("dm-rs mode step=wifi_done");
    start_infra_lora(settings, reason)
}

fn start_infra_lora(settings: &SharedSettings, reason: &'static str) -> Result<()> {
    boot_print("dm-rs mode step=lora_start");
    if !lora_boot_enabled(settings) {
        telemetry::record_log(format!(
            "event type=mode.infra_radio medium=lora rx=false reason={} status=not_configured",
            reason
        ));
        boot_print("dm-rs mode step=lora_skipped");
        return Ok(());
    }
    boot_print("dm-rs mode step=lora_status");
    telemetry::record_log(format!(
        "event type=mode.infra_radio medium=lora reason={} {}",
        reason,
        super::lora::status_text(settings)
    ));
    if !get_bool(settings, "lora.enabled", true) {
        let _ = super::lora::sleep_radio(settings);
        telemetry::record_log(format!(
            "event type=mode.infra_radio medium=lora rx=false reason={} status=disabled",
            reason
        ));
        boot_print("dm-rs mode step=lora_disabled");
        return Ok(());
    }
    boot_print("dm-rs mode step=lora_rx");
    match super::lora::start_background_rx(settings.clone()) {
        Ok(Some(_)) => telemetry::record_log(format!(
            "event type=mode.infra_radio medium=lora rx=true reason={}",
            reason
        )),
        Ok(None) => telemetry::record_log(format!(
            "event type=mode.infra_radio medium=lora rx=false reason={} status=unavailable_or_running",
            reason
        )),
        Err(err) => telemetry::record_log(format!(
            "event type=mode.infra_radio medium=lora rx=false reason={} msg={}",
            reason,
            crate::commands::protocol::escape_value(&err.to_string())
        )),
    }
    boot_print("dm-rs mode step=lora_done");
    Ok(())
}

fn lora_boot_enabled(settings: &SharedSettings) -> bool {
    let settings = settings.borrow();
    let configured = [
        "lora.spi_host",
        "lora.sck",
        "lora.miso",
        "lora.mosi",
        "lora.cs",
        "lora.rst",
        "lora.dio0",
        "lora.busy",
    ]
    .iter()
    .any(|key| matches!(settings.get_str(key), Ok(Some(_))));
    if !configured {
        return false;
    }
    match settings.get_str("lora.enabled") {
        Ok(Some(value)) => parse_bool(&value).unwrap_or(false),
        _ => true,
    }
}

fn start_raw_nan_duty(
    settings: &SharedSettings,
    reason: &'static str,
    default_channel: u8,
) -> Result<()> {
    #[cfg(target_feature = "esp32s3ops")]
    {
        if matches!(reason, "boot" | "boot_window_done") && !get_bool(settings, "nan.boot", false) {
            stop_raw_nan_duty();
            telemetry::record_log(format!(
                "event type=mode.infra_radio medium=nan status=deferred target=s3 reason={} set=nan.boot=true",
                reason
            ));
            return Ok(());
        }
    }
    super::wifi::stop_raw_monitor().ok();
    let channel = get_u32(settings, "nan.channel", default_channel as u32).clamp(1, 13) as u8;
    let active_ms = get_u32(settings, "nan.active_ms", DEFAULT_NAN_ACTIVE_MS).clamp(50, 60_000);
    let duty_ms = get_u32(settings, "nan.wake_ms", DEFAULT_NAN_DUTY_MS)
        .max(active_ms)
        .clamp(100, 60_000);
    super::nan::start_raw_window(channel, "sdf")?;
    RAW_NAN_DUTY_ENABLED.store(true, Ordering::Relaxed);
    RAW_NAN_DUTY_ACTIVE.store(true, Ordering::Relaxed);
    RAW_NAN_DUTY_NEXT_MS.store(now_ms().wrapping_add(active_ms), Ordering::Relaxed);
    if matches!(reason, "boot" | "boot_window_done") {
        let _ = queue_boot_discovery(settings, reason);
    }
    let queued_sent = super::nan::drain_raw_queue();
    telemetry::record_log(format!(
        "event type=mode.infra_radio medium=nan status=raw_duty channel={} reason={} duty_ms={} active_ms={} queued_sent={}",
        channel, reason, duty_ms, active_ms, queued_sent
    ));
    Ok(())
}

fn stop_raw_nan_duty() {
    RAW_NAN_DUTY_ENABLED.store(false, Ordering::Relaxed);
    RAW_NAN_DUTY_ACTIVE.store(false, Ordering::Relaxed);
    RAW_NAN_DUTY_NEXT_MS.store(0, Ordering::Relaxed);
}

fn poll_raw_nan_duty(settings: &SharedSettings) {
    if !RAW_NAN_DUTY_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let now = now_ms();
    let deadline = RAW_NAN_DUTY_NEXT_MS.load(Ordering::Relaxed);
    if deadline != 0 && now.wrapping_sub(deadline) >= u32::MAX / 2 {
        return;
    }
    let channel = get_u32(settings, "nan.channel", 6).clamp(1, 13) as u8;
    let active_ms = get_u32(settings, "nan.active_ms", DEFAULT_NAN_ACTIVE_MS).clamp(50, 60_000);
    let duty_ms = get_u32(settings, "nan.wake_ms", DEFAULT_NAN_DUTY_MS)
        .max(active_ms)
        .clamp(100, 60_000);

    if RAW_NAN_DUTY_ACTIVE.load(Ordering::Relaxed) {
        let queued_sent = super::nan::drain_raw_queue();
        super::nan::stop_nan().ok();
        super::wifi::stop_raw_monitor().ok();
        RAW_NAN_DUTY_ACTIVE.store(false, Ordering::Relaxed);
        RAW_NAN_DUTY_NEXT_MS.store(
            now.wrapping_add(duty_ms.saturating_sub(active_ms)),
            Ordering::Relaxed,
        );
        telemetry::record_log(format!(
            "event type=nan.duty phase=idle channel={} idle_ms={} queued_sent={}",
            channel,
            duty_ms.saturating_sub(active_ms),
            queued_sent
        ));
        return;
    }

    match super::nan::start_raw_window(channel, "sdf") {
        Ok(()) => {
            let queued_sent = super::nan::drain_raw_queue();
            RAW_NAN_DUTY_ACTIVE.store(true, Ordering::Relaxed);
            RAW_NAN_DUTY_NEXT_MS.store(now.wrapping_add(active_ms), Ordering::Relaxed);
            telemetry::record_log(format!(
                "event type=nan.duty phase=active channel={} active_ms={} queued_sent={}",
                channel, active_ms, queued_sent
            ));
        }
        Err(err) => {
            RAW_NAN_DUTY_NEXT_MS.store(now.wrapping_add(1_000), Ordering::Relaxed);
            telemetry::record_log(format!(
                "event type=nan.duty phase=active ok=false msg={}",
                crate::commands::protocol::escape_value(&err.to_string())
            ));
        }
    }
}

fn queue_boot_discovery(settings: &SharedSettings, source: &'static str) -> Result<()> {
    let from = local_suffix4_hex()?;
    let mut payload = format!(
        "dmesh.ping type=discover source={} reboot=true reply=false to=ffffffff from={} uptime_ms={} {}",
        source,
        from,
        now_ms(),
        telemetry::stats_text(settings)
    );
    if payload.len() > 220 {
        payload.truncate(220);
    }
    super::nan::queue_raw_broadcast(payload.as_bytes())?;
    telemetry::record_log(format!(
        "event type=mode.discovery queued=true medium=nan from={} len={}",
        from,
        payload.len()
    ));
    Ok(())
}

fn local_suffix4_hex() -> Result<String> {
    let mut mac = [0_u8; 6];
    unsafe {
        let ret = sys::esp_read_mac(mac.as_mut_ptr(), sys::esp_mac_type_t_ESP_MAC_WIFI_STA);
        if ret != sys::ESP_OK {
            bail!("esp_read_mac failed err=0x{ret:x}");
        }
    }
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}",
        mac[2], mac[3], mac[4], mac[5]
    ))
}

fn send_status_ping(settings: &SharedSettings, source: &'static str) -> Result<()> {
    if PRODUCT_MODE.load(Ordering::Relaxed) == MODE_COMPANION {
        bail!("companion firmware does not send ping");
    }
    let mut payload = if source == "rx" {
        status_pong_text(settings, source)
    } else {
        format!(
            "dmesh.ping type=status reply=false source={} uptime_ms={} {}",
            source,
            now_ms(),
            telemetry::stats_text(settings)
        )
    };
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
    if matches!(from_mode.as_deref(), Some("companion")) {
        telemetry::record_log("event type=mode.startup saved=companion action=ignore start=infra");
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

fn boot_print(line: &str) {
    if let Ok(message) = CString::new(format!("{line}\n")) {
        unsafe {
            sys::esp_rom_printf(message.as_ptr() as *const c_char);
        }
    }
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
        "mode status=true | mode companion=true|infra=true save=true | mode advertise=true window_ms=10000 adv_ms=1000 | mode active=true ms=5000 | mode sleep=true | mode lora_sleep_listen=true save=true | mode raw_wifi=true channel=6 | mode ping=true"
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
            super::wifi::start_raw_monitor_mode(channel, "dmesh")?;
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
        "mode active={} companion_advertising={} companion_pending_advertising={} pending={} deadline_ms={} ping_rx={} ping_tx={}",
        mode_name(),
        COMPANION_ADVERTISING.load(Ordering::Relaxed),
        COMPANION_PENDING_ADVERTISING.load(Ordering::Relaxed),
        telemetry::pending_message_count(),
        COMPANION_DEADLINE_MS.load(Ordering::Relaxed),
        PING_RX.load(Ordering::Relaxed),
        PING_TX.load(Ordering::Relaxed)
    )
}
