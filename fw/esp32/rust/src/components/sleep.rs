use std::mem::size_of;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::lora::{self, LoraChip, LoraConfig};
use super::settings::{parse_bool, SharedSettings};
use super::telemetry;

const RTC_MAGIC: u32 = 0x4453_4c50;
const RTC_VERSION: u16 = 2;
const FLAG_WIFI: u32 = 1 << 0;
const FLAG_SERIAL: u32 = 1 << 1;
const FLAG_BLE: u32 = 1 << 2;
const FLAG_LORA: u32 = 1 << 3;
const DEFAULT_WAKE_MS: u32 = 5_000;
const DEFAULT_FORWARD_MS: u32 = 1_000;
const LIGHT_PS_NONE: u8 = 0;
const LIGHT_PS_MIN: u8 = 1;
const LIGHT_PS_MAX: u8 = 2;

static LIGHT_SLEEP_ENABLED: AtomicBool = AtomicBool::new(false);
static LIGHT_WIFI: AtomicBool = AtomicBool::new(false);
static LIGHT_BLE: AtomicBool = AtomicBool::new(false);
static LIGHT_BLE_SCAN: AtomicBool = AtomicBool::new(false);
static LIGHT_RAW: AtomicBool = AtomicBool::new(false);
static LIGHT_NAN: AtomicBool = AtomicBool::new(false);
static LIGHT_SERIAL: AtomicBool = AtomicBool::new(false);
static LIGHT_CHANNEL: AtomicU8 = AtomicU8::new(6);
static LIGHT_WAKE_MS: AtomicU32 = AtomicU32::new(0);
static LIGHT_PS: AtomicU8 = AtomicU8::new(LIGHT_PS_MIN);

unsafe extern "C" {
    fn esp_clk_cpu_freq() -> u32;
    fn esp_clk_xtal_freq() -> u32;
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RtcLoraConfig {
    chip: i32,
    frequency_hz: u32,
    bandwidth_hz: u32,
    spi_host: i32,
    sck: i32,
    miso: i32,
    mosi: i32,
    cs: i32,
    rst: i32,
    dio0: i32,
    busy: i32,
    sf: i32,
    cr: i32,
    sync_word: i32,
    crc: u8,
    beacon: u8,
    _pad0: [u8; 2],
    preamble: i32,
    tx_power: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RtcSleepState {
    magic: u32,
    version: u16,
    len: u16,
    checksum: u32,
    flags: u32,
    wake_ms: u32,
    forward_ms: u32,
    boot_count: u32,
    wake_count: u32,
    last_cause: u32,
    last_ext1_mask: u64,
    last_packet_len: u16,
    _pad0: u16,
    last_packet_hash: u32,
    lora: RtcLoraConfig,
}

impl RtcSleepState {
    const fn empty() -> Self {
        Self {
            magic: 0,
            version: 0,
            len: 0,
            checksum: 0,
            flags: 0,
            wake_ms: 0,
            forward_ms: 0,
            boot_count: 0,
            wake_count: 0,
            last_cause: 0,
            last_ext1_mask: 0,
            last_packet_len: 0,
            _pad0: 0,
            last_packet_hash: 0,
            lora: RtcLoraConfig {
                chip: 0,
                frequency_hz: 0,
                bandwidth_hz: 0,
                spi_host: 0,
                sck: 0,
                miso: 0,
                mosi: 0,
                cs: 0,
                rst: 0,
                dio0: 0,
                busy: -1,
                sf: 0,
                cr: 0,
                sync_word: 0,
                crc: 0,
                beacon: 0,
                _pad0: [0; 2],
                preamble: 0,
                tx_power: 0,
            },
        }
    }
}

#[link_section = ".rtc_noinit"]
static mut RTC_SLEEP_STATE: RtcSleepState = RtcSleepState::empty();

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    registry.register(SleepCommand { settings });
}

pub fn handle_deep_sleep_wake() -> Result<()> {
    let cause = unsafe { sys::esp_sleep_get_wakeup_cause() };
    let ext1_mask = unsafe { sys::esp_sleep_get_ext1_wakeup_status() };
    let mut state = read_state();
    if valid_state(&state) {
        state.boot_count = state.boot_count.saturating_add(1);
        state.last_cause = cause;
        state.last_ext1_mask = ext1_mask;
        write_state(state);
    }

    telemetry::record_log(format!(
        "event type=sleep.wakeup cause={} ext1_mask=0x{:x} rtc_valid={}",
        wake_cause_name(cause),
        ext1_mask,
        valid_state(&state)
    ));

    if !valid_state(&state) {
        return Ok(());
    }

    let lora_wake = state.flags & FLAG_LORA != 0
        && cause == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_EXT1
        && ext1_mask & (1_u64 << state.lora.dio0) != 0;
    let timer_wake = cause == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_TIMER;
    if !lora_wake && !timer_wake {
        return Ok(());
    }

    if lora_wake {
        let config = state.lora.to_config();
        match lora::read_wake_packet_no_reset(&config) {
            Ok(Some(packet)) => {
                state.wake_count = state.wake_count.saturating_add(1);
                state.last_packet_len = packet.data.len().min(u16::MAX as usize) as u16;
                state.last_packet_hash = fnv1a32(&packet.data);
                write_state(update_checksum(state));
                if state.flags & FLAG_SERIAL != 0 {
                    telemetry::record_log(format!(
                        "event type=lora.wake_rx len={} rssi={} snr={}",
                        packet.data.len(),
                        packet.rssi,
                        packet.snr
                    ));
                } else {
                    telemetry::record_log(format!(
                        "event type=lora.wake_rx len={} rssi={} snr={}",
                        packet.data.len(),
                        packet.rssi,
                        packet.snr
                    ));
                }
                forward_packet(&state, &packet.data, Some((packet.rssi, packet.snr)));
            }
            Ok(None) => {
                telemetry::record_log("event type=lora.wake_rx len=0 message=no-pending-packet");
            }
            Err(err) => {
                telemetry::record_log(format!(
                    "event type=lora.wake_rx error={}",
                    crate::commands::protocol::escape_value(&err.to_string())
                ));
            }
        }
    }

    if active_window(&state)? {
        return Ok(());
    }
    enter_deep_sleep_with_state(state)
}

struct SleepCommand {
    settings: SharedSettings,
}

impl CommandHandler for SleepCommand {
    fn name(&self) -> &'static str {
        "sleep"
    }

    fn help(&self) -> &'static str {
        "sleep status=true | sleep profile=ble_adv|active | sleep mode=deep wake_ms=5000 active_ms=1000 ble=true wifi=true serial=true start=true | sleep mode=light start=true stop=true wifi=true ble=true ble_scan=false raw=true nan=false ps=min|max|none channel=6 wake_ms=0 serial=true"
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if let Some(profile) = request.arg("profile") {
            return apply_profile(&self.settings, request, profile);
        }
        if request.arg("status").is_some()
            || (request.arg("start").is_none() && request.arg("stop").is_none())
        {
            return Ok(CommandResponse::ok(status_text()));
        }

        let mode = request.arg("mode").unwrap_or("deep");
        if mode == "light" {
            if request
                .arg("stop")
                .map(parse_bool)
                .transpose()?
                .unwrap_or(false)
            {
                stop_light_sleep()?;
                return Ok(CommandResponse::ok(status_text()));
            }
            start_light_sleep(&self.settings, request)?;
            return Ok(CommandResponse::ok(status_text()));
        }
        if mode != "deep" {
            bail!("only mode=deep is implemented for RTC LoRa wake loop");
        }
        let config = lora::load_config(&self.settings)?;
        let wake_ms = parse_u32_arg(request, "wake_ms", DEFAULT_WAKE_MS)?
            .or(parse_u32_arg(request, "ms", DEFAULT_WAKE_MS)?)
            .unwrap_or(DEFAULT_WAKE_MS);
        let forward_ms = parse_u32_arg(request, "active_ms", DEFAULT_FORWARD_MS)?
            .or(parse_u32_arg(request, "forward_ms", DEFAULT_FORWARD_MS)?)
            .unwrap_or(DEFAULT_FORWARD_MS);
        let mut flags = 0_u32;
        if request
            .arg("lora")
            .or_else(|| request.arg("lora_listen"))
            .map(parse_bool)
            .transpose()?
            .unwrap_or(true)
        {
            flags |= FLAG_LORA;
        }
        if request
            .arg("wifi")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(true)
        {
            flags |= FLAG_WIFI;
        }
        if request
            .arg("ble")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(true)
        {
            flags |= FLAG_BLE;
        }
        if request
            .arg("serial")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(true)
        {
            flags |= FLAG_SERIAL;
        }
        let mut state = new_state(config, wake_ms, forward_ms, flags);
        if flags & FLAG_LORA != 0 {
            lora::prepare_deep_sleep_rx(&config)?;
        }
        state = update_checksum(state);
        write_state(state);
        enter_deep_sleep_with_state(state)?;
        Ok(CommandResponse::ok("sleep rejected"))
    }
}

fn apply_profile(
    settings: &SharedSettings,
    request: &CommandRequest,
    profile: &str,
) -> Result<CommandResponse> {
    match profile {
        "ble_adv" | "ble-advertise" | "ble_connectable" => {
            if request
                .arg("lora_sleep")
                .map(parse_bool)
                .transpose()?
                .unwrap_or(true)
            {
                lora::sleep_radio(settings)?;
            }
            start_light_sleep_profile(
                settings,
                LightSleepProfile {
                    ble: true,
                    ble_scan: false,
                    wifi: false,
                    raw: false,
                    nan: false,
                    serial: false,
                    channel: 6,
                    wake_ms: 0,
                    ps: "max",
                },
            )?;
            super::ble_bt::set_advertising_interval_ms(1000, 1200);
            super::ble_bt::start_connectable_advertising()?;
            Ok(CommandResponse::ok(format!(
                "{} {}",
                "sleep profile=ble_adv lora_sleep=true",
                status_text()
            )))
        }
        "active" | "awake" | "play" => {
            stop_light_sleep()?;
            super::ble_bt::disable_controller_sleep()?;
            super::ble_bt::start_listen_mode()?;
            Ok(CommandResponse::ok(format!(
                "sleep profile=active {}",
                status_text()
            )))
        }
        _ => bail!("unsupported sleep profile {profile}"),
    }
}

pub fn enter_companion_deep_sleep(
    settings: &SharedSettings,
    lora_listen: bool,
    wake_ms: u32,
    active_ms: u32,
) -> Result<()> {
    let mut flags = 0;
    if lora_listen {
        flags |= FLAG_LORA | FLAG_BLE;
    }
    let config = lora::load_config(settings)?;
    let mut state = new_state(config, wake_ms, active_ms, flags);
    if lora_listen {
        lora::prepare_deep_sleep_rx(&state.lora.to_config())?;
    } else {
        let _ = lora::sleep_radio(settings);
    }
    state = update_checksum(state);
    write_state(state);
    enter_deep_sleep_with_state(state)
}

struct LightSleepProfile {
    ble: bool,
    ble_scan: bool,
    wifi: bool,
    raw: bool,
    nan: bool,
    serial: bool,
    channel: u8,
    wake_ms: u32,
    ps: &'static str,
}

fn start_light_sleep_profile(settings: &SharedSettings, profile: LightSleepProfile) -> Result<()> {
    let ps_code = parse_ps(profile.ps)?;

    configure_pm(true)?;
    configure_light_wake_sources(settings, profile.wake_ms, profile.serial)?;
    if profile.ble {
        if profile.ble_scan {
            super::ble_bt::start_listen_mode()?;
        } else {
            super::ble_bt::start_connectable_advertising()?;
        }
        if let Err(err) = super::ble_bt::enable_controller_sleep() {
            telemetry::record_log(format!(
                "ev=sleep.err mode=light target=ble_sleep err={}",
                crate::commands::protocol::escape_value(&err.to_string())
            ));
        }
    } else {
        super::ble_bt::stop_radio_activity();
    }
    if profile.wifi || profile.raw {
        if profile.raw {
            super::wifi::start_raw_monitor_mode(profile.channel, "action")?;
        } else {
            super::wifi::ensure_raw_wifi_started(profile.channel)?;
        }
        super::wifi::set_power_save(profile.ps)?;
    } else {
        let _ = super::wifi::stop_raw_monitor();
    }
    if profile.nan {
        telemetry::record_log("ev=sleep.light nan=requested action=skip reason=no_helper");
    }

    LIGHT_SLEEP_ENABLED.store(true, Ordering::Relaxed);
    LIGHT_WIFI.store(profile.wifi, Ordering::Relaxed);
    LIGHT_BLE.store(profile.ble, Ordering::Relaxed);
    LIGHT_BLE_SCAN.store(profile.ble_scan, Ordering::Relaxed);
    LIGHT_RAW.store(profile.raw, Ordering::Relaxed);
    LIGHT_NAN.store(profile.nan, Ordering::Relaxed);
    LIGHT_SERIAL.store(profile.serial, Ordering::Relaxed);
    LIGHT_CHANNEL.store(profile.channel, Ordering::Relaxed);
    LIGHT_WAKE_MS.store(profile.wake_ms, Ordering::Relaxed);
    LIGHT_PS.store(ps_code, Ordering::Relaxed);
    telemetry::record_log(format!(
        "ev=sleep.light on=true wifi={} ble={} ble_scan={} raw={} nan={} ps={} ch={} wake_ms={} serial={}",
        profile.wifi,
        profile.ble,
        profile.ble_scan,
        profile.raw,
        profile.nan,
        profile.ps,
        profile.channel,
        profile.wake_ms,
        profile.serial
    ));
    Ok(())
}

fn start_light_sleep(settings: &SharedSettings, request: &CommandRequest) -> Result<()> {
    let channel = request
        .arg("channel")
        .map(|value| {
            value
                .parse::<u8>()
                .map_err(|err| anyhow!("invalid channel={value}: {err}"))
        })
        .transpose()?
        .unwrap_or(6)
        .clamp(1, 13);
    let wake_ms = parse_u32_arg(request, "wake_ms", 0)?
        .or(parse_u32_arg(request, "ms", 0)?)
        .unwrap_or(0);
    let wifi = request
        .arg("wifi")
        .map(parse_bool)
        .transpose()?
        .unwrap_or(true);
    let ble = request
        .arg("ble")
        .map(parse_bool)
        .transpose()?
        .unwrap_or(true);
    let ble_scan = request
        .arg("ble_scan")
        .map(parse_bool)
        .transpose()?
        .unwrap_or(false);
    let raw = request
        .arg("raw")
        .map(parse_bool)
        .transpose()?
        .unwrap_or(true);
    let nan = request
        .arg("nan")
        .map(parse_bool)
        .transpose()?
        .unwrap_or(false);
    let serial = request
        .arg("serial")
        .map(parse_bool)
        .transpose()?
        .unwrap_or(true);
    let ps = request.arg("ps").unwrap_or("min");
    let ps_code = parse_ps(ps)?;

    configure_pm(true)?;
    configure_light_wake_sources(settings, wake_ms, serial)?;
    if ble {
        if ble_scan {
            super::ble_bt::start_listen_mode()?;
        } else {
            super::ble_bt::start_connectable_advertising()?;
        }
        if let Err(err) = super::ble_bt::enable_controller_sleep() {
            telemetry::record_log(format!(
                "ev=sleep.err mode=light target=ble_sleep err={}",
                crate::commands::protocol::escape_value(&err.to_string())
            ));
        }
    } else {
        super::ble_bt::stop_radio_activity();
    }
    if wifi || raw {
        if raw {
            super::wifi::start_raw_monitor_mode(channel, "action")?;
        } else {
            super::wifi::ensure_raw_wifi_started(channel)?;
        }
        super::wifi::set_power_save(ps)?;
    } else {
        let _ = super::wifi::stop_raw_monitor();
    }
    if nan {
        telemetry::record_log("ev=sleep.light nan=requested action=skip reason=no_helper");
    }

    LIGHT_SLEEP_ENABLED.store(true, Ordering::Relaxed);
    LIGHT_WIFI.store(wifi, Ordering::Relaxed);
    LIGHT_BLE.store(ble, Ordering::Relaxed);
    LIGHT_BLE_SCAN.store(ble_scan, Ordering::Relaxed);
    LIGHT_RAW.store(raw, Ordering::Relaxed);
    LIGHT_NAN.store(nan, Ordering::Relaxed);
    LIGHT_SERIAL.store(serial, Ordering::Relaxed);
    LIGHT_CHANNEL.store(channel, Ordering::Relaxed);
    LIGHT_WAKE_MS.store(wake_ms, Ordering::Relaxed);
    LIGHT_PS.store(ps_code, Ordering::Relaxed);
    telemetry::record_log(format!(
        "ev=sleep.light on=true wifi={} ble={} ble_scan={} raw={} nan={} ps={} ch={} wake_ms={} serial={}",
        wifi, ble, ble_scan, raw, nan, ps, channel, wake_ms, serial
    ));
    Ok(())
}

fn stop_light_sleep() -> Result<()> {
    configure_pm(false)?;
    unsafe {
        let _ = sys::esp_sleep_disable_wakeup_source(sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_ALL);
        let _ = sys::esp_wifi_set_ps(sys::wifi_ps_type_t_WIFI_PS_NONE);
    }
    let _ = super::ble_bt::disable_controller_sleep();
    LIGHT_SLEEP_ENABLED.store(false, Ordering::Relaxed);
    LIGHT_WIFI.store(false, Ordering::Relaxed);
    LIGHT_BLE.store(false, Ordering::Relaxed);
    LIGHT_BLE_SCAN.store(false, Ordering::Relaxed);
    LIGHT_RAW.store(false, Ordering::Relaxed);
    LIGHT_NAN.store(false, Ordering::Relaxed);
    LIGHT_SERIAL.store(false, Ordering::Relaxed);
    LIGHT_WAKE_MS.store(0, Ordering::Relaxed);
    telemetry::record_log("ev=sleep.light on=false");
    Ok(())
}

fn configure_pm(light_sleep_enable: bool) -> Result<()> {
    let max_freq_mhz = cpu_freq_mhz().max(80);
    let min_freq_mhz = if light_sleep_enable {
        xtal_freq_mhz().clamp(1, max_freq_mhz)
    } else {
        max_freq_mhz
    };
    let config = sys::esp_pm_config_t {
        max_freq_mhz: max_freq_mhz as i32,
        min_freq_mhz: min_freq_mhz as i32,
        light_sleep_enable,
    };
    unsafe {
        esp_ok(sys::esp_pm_configure(
            (&config as *const sys::esp_pm_config_t).cast(),
        ))
    }
}

fn configure_light_wake_sources(
    settings: &SharedSettings,
    wake_ms: u32,
    serial: bool,
) -> Result<()> {
    unsafe {
        let _ = sys::esp_sleep_disable_wakeup_source(sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_ALL);
        if wake_ms > 0 {
            esp_ok(sys::esp_sleep_enable_timer_wakeup(wake_ms as u64 * 1000))?;
        }
        if serial {
            esp_ok_allow_invalid_state(sys::uart_set_wakeup_threshold(
                sys::uart_port_t_UART_NUM_0,
                3,
            ))?;
            esp_ok_allow_invalid_state(sys::esp_sleep_enable_uart_wakeup(
                sys::uart_port_t_UART_NUM_0 as i32,
            ))?;
        }
        let _ = sys::esp_sleep_enable_wifi_wakeup();
        let _ = sys::esp_sleep_enable_wifi_beacon_wakeup();
        let _ = sys::esp_sleep_enable_bt_wakeup();
    }

    let mut button_gpio = None;
    if let Ok(Some(pin)) = super::button::configure_light_wake(settings) {
        button_gpio = Some(pin);
    }

    if let Ok(config) = lora::load_config(settings) {
        if config.dio0 >= 0 {
            unsafe {
                let ret = sys::gpio_wakeup_enable(
                    config.dio0 as sys::gpio_num_t,
                    sys::gpio_int_type_t_GPIO_INTR_HIGH_LEVEL,
                );
                if ret == sys::ESP_OK {
                    esp_ok(sys::esp_sleep_enable_gpio_wakeup())?;
                } else {
                    telemetry::record_log(format!(
                        "ev=sleep.err mode=light target=lora_gpio gpio={} err=0x{:x}",
                        config.dio0, ret
                    ));
                }
            }
        }
    }
    if let Some(pin) = button_gpio {
        telemetry::record_log(format!("ev=sleep.light_wake source=button gpio={}", pin));
    }
    Ok(())
}

fn status_text() -> String {
    let state = read_state();
    let valid = valid_state(&state);
    let cause = unsafe { sys::esp_sleep_get_wakeup_cause() };
    let ext1_mask = unsafe { sys::esp_sleep_get_ext1_wakeup_status() };
    let mut pm = sys::esp_pm_config_t::default();
    let pm_ok =
        unsafe { sys::esp_pm_get_configuration((&mut pm as *mut sys::esp_pm_config_t).cast()) }
            == sys::ESP_OK;
    format!(
        "sleep rtc_valid={} cause={} ext1_mask=0x{:x} rtc_bytes={} flags=0x{:x} wake_ms={} forward_ms={} wake_count={} last_len={} last_hash=0x{:08x} light={} pm={} max={} min={} wifi={} ble={} ble_scan={} raw={} nan={} serial={} ch={} ps={} wifi_ps={} light_wake_ms={}",
        valid,
        wake_cause_name(cause),
        ext1_mask,
        size_of::<RtcSleepState>(),
        if valid { state.flags } else { 0 },
        if valid { state.wake_ms } else { 0 },
        if valid { state.forward_ms } else { 0 },
        if valid { state.wake_count } else { 0 },
        if valid { state.last_packet_len } else { 0 },
        if valid { state.last_packet_hash } else { 0 },
        LIGHT_SLEEP_ENABLED.load(Ordering::Relaxed),
        pm_ok && pm.light_sleep_enable,
        if pm_ok { pm.max_freq_mhz } else { 0 },
        if pm_ok { pm.min_freq_mhz } else { 0 },
        LIGHT_WIFI.load(Ordering::Relaxed),
        LIGHT_BLE.load(Ordering::Relaxed),
        LIGHT_BLE_SCAN.load(Ordering::Relaxed),
        LIGHT_RAW.load(Ordering::Relaxed),
        LIGHT_NAN.load(Ordering::Relaxed),
        LIGHT_SERIAL.load(Ordering::Relaxed),
        LIGHT_CHANNEL.load(Ordering::Relaxed),
        ps_name(LIGHT_PS.load(Ordering::Relaxed)),
        super::wifi::power_save_name(),
        LIGHT_WAKE_MS.load(Ordering::Relaxed)
    )
}

fn enter_deep_sleep_with_state(state: RtcSleepState) -> Result<()> {
    let config = state.lora.to_config();
    if state.flags & FLAG_LORA != 0 {
        lora::prepare_deep_sleep_rx(&config)?;
    }
    configure_wake_sources(&state)?;
    telemetry::record_log(format!(
        "event type=sleep.enter mode=deep wake_ms={} active_ms={} flags=0x{:x} dio0={}",
        state.wake_ms, state.forward_ms, state.flags, state.lora.dio0
    ));
    unsafe {
        sys::esp_deep_sleep_start();
    }
}

fn configure_wake_sources(state: &RtcSleepState) -> Result<()> {
    unsafe {
        let _ = sys::esp_sleep_disable_wakeup_source(sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_ALL);
        if state.wake_ms > 0 {
            esp_ok(sys::esp_sleep_enable_timer_wakeup(
                state.wake_ms as u64 * 1000,
            ))?;
        }
        if let Some(pin) = super::button::configured_gpio() {
            if sys::rtc_gpio_is_valid_gpio(pin) {
                esp_ok(sys::esp_sleep_enable_ext0_wakeup(pin as sys::gpio_num_t, 0))?;
            } else {
                telemetry::record_log(format!(
                    "event type=sleep.wake_source source=button gpio={} status=invalid_rtc",
                    pin
                ));
            }
        }
        esp_ok(sys::esp_sleep_pd_config(
            sys::esp_sleep_pd_domain_t_ESP_PD_DOMAIN_RTC_PERIPH,
            sys::esp_sleep_pd_option_t_ESP_PD_OPTION_ON,
        ))?;
        if state.flags & FLAG_LORA != 0 {
            if !sys::rtc_gpio_is_valid_gpio(state.lora.dio0) {
                bail!("lora.dio0={} is not RTC-capable", state.lora.dio0);
            }
            esp_ok(sys::esp_sleep_enable_ext1_wakeup(
                1_u64 << state.lora.dio0,
                sys::esp_sleep_ext1_wakeup_mode_t_ESP_EXT1_WAKEUP_ANY_HIGH,
            ))?;
        }
        let _ = sys::rtc_gpio_isolate(sys::gpio_num_t_GPIO_NUM_12);
    }
    Ok(())
}

fn forward_packet(state: &RtcSleepState, packet: &[u8], metrics: Option<(i32, f32)>) {
    let start = Instant::now();
    let ble_sent = if state.flags & FLAG_BLE != 0 {
        match metrics {
            Some((rssi, snr)) => super::ble_bt::announce_lora_packet(packet, rssi, snr).is_ok(),
            None => super::ble_bt::forward_packet_for_window(packet, 0).unwrap_or(false),
        }
    } else {
        false
    };
    let wifi_sent = if state.flags & FLAG_WIFI != 0 {
        super::wifi::forward_management_packet(packet).is_ok()
    } else {
        false
    };
    if state.flags & FLAG_SERIAL != 0 {
        telemetry::record_log(format!(
            "event type=sleep.forward ble_sent={} wifi_sent={} elapsed_ms={}",
            ble_sent,
            wifi_sent,
            start.elapsed().as_millis()
        ));
    }
    let elapsed = start.elapsed();
    let target = Duration::from_millis(state.forward_ms as u64);
    if elapsed < target {
        std::thread::sleep(target - elapsed);
    }
}

fn active_window(state: &RtcSleepState) -> Result<bool> {
    let deadline = Instant::now() + Duration::from_millis(state.forward_ms as u64);
    if state.flags & FLAG_BLE != 0 {
        let marker = state.wake_count.to_le_bytes();
        if let Err(err) =
            super::ble_bt::announce_packet(super::ble_bt::DmeshBleEvent::Generic, &marker, None)
        {
            telemetry::record_log(format!(
                "event type=sleep.active transport=ble status=error message={}",
                crate::commands::protocol::escape_value(&err.to_string())
            ));
        }
    }
    while Instant::now() < deadline {
        if state.flags & FLAG_SERIAL != 0 && uart0_has_input() {
            telemetry::record_log("event type=sleep.active source=serial action=promote");
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    telemetry::record_log(format!(
        "event type=sleep.active source=timer action=sleep active_ms={}",
        state.forward_ms
    ));
    Ok(false)
}

fn uart0_has_input() -> bool {
    let mut byte = [0_u8; 1];
    let read = unsafe {
        sys::uart_read_bytes(sys::uart_port_t_UART_NUM_0, byte.as_mut_ptr().cast(), 1, 0)
    };
    read > 0
}

fn new_state(config: LoraConfig, wake_ms: u32, forward_ms: u32, flags: u32) -> RtcSleepState {
    let old = read_state();
    let mut state = RtcSleepState {
        magic: RTC_MAGIC,
        version: RTC_VERSION,
        len: size_of::<RtcSleepState>() as u16,
        checksum: 0,
        flags,
        wake_ms,
        forward_ms,
        boot_count: old.boot_count,
        wake_count: old.wake_count,
        last_cause: old.last_cause,
        last_ext1_mask: old.last_ext1_mask,
        last_packet_len: old.last_packet_len,
        _pad0: 0,
        last_packet_hash: old.last_packet_hash,
        lora: RtcLoraConfig::from_config(config),
    };
    state = update_checksum(state);
    state
}

impl RtcLoraConfig {
    fn from_config(config: LoraConfig) -> Self {
        Self {
            frequency_hz: config.frequency_hz,
            chip: match config.chip {
                LoraChip::Sx127x => 0,
                LoraChip::Sx1262 => 1,
            },
            bandwidth_hz: config.bandwidth_hz,
            spi_host: config.spi_host,
            sck: config.sck,
            miso: config.miso,
            mosi: config.mosi,
            cs: config.cs,
            rst: config.rst,
            dio0: config.dio0,
            busy: config.busy,
            sf: config.sf,
            cr: config.cr,
            sync_word: config.sync_word,
            crc: if config.crc { 1 } else { 0 },
            beacon: if config.beacon { 1 } else { 0 },
            _pad0: [0; 2],
            preamble: config.preamble,
            tx_power: config.tx_power,
        }
    }

    fn to_config(self) -> LoraConfig {
        LoraConfig {
            chip: if self.chip == 1 {
                LoraChip::Sx1262
            } else {
                LoraChip::Sx127x
            },
            frequency_hz: self.frequency_hz,
            bandwidth_hz: self.bandwidth_hz,
            beacon: self.beacon != 0,
            spi_host: self.spi_host,
            sck: self.sck,
            miso: self.miso,
            mosi: self.mosi,
            cs: self.cs,
            rst: self.rst,
            dio0: self.dio0,
            busy: self.busy,
            sf: self.sf,
            cr: self.cr,
            sync_word: self.sync_word,
            crc: self.crc != 0,
            preamble: self.preamble,
            tx_power: self.tx_power,
        }
    }
}

fn read_state() -> RtcSleepState {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RTC_SLEEP_STATE)) }
}

fn write_state(state: RtcSleepState) {
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(RTC_SLEEP_STATE), state);
    }
}

fn valid_state(state: &RtcSleepState) -> bool {
    state.magic == RTC_MAGIC
        && state.version == RTC_VERSION
        && state.len as usize == size_of::<RtcSleepState>()
        && checksum_for_validation(*state) == state.checksum
}

fn update_checksum(mut state: RtcSleepState) -> RtcSleepState {
    state.checksum = 0;
    state.checksum = checksum(state);
    state
}

fn checksum(state: RtcSleepState) -> u32 {
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&state as *const RtcSleepState).cast::<u8>(),
            size_of::<RtcSleepState>(),
        )
    };
    bytes.iter().fold(0x811c_9dc5_u32, |acc, byte| {
        acc.wrapping_mul(16777619) ^ *byte as u32
    })
}

fn checksum_for_validation(mut state: RtcSleepState) -> u32 {
    state.checksum = 0;
    checksum(state)
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c_9dc5_u32, |acc, byte| {
        acc.wrapping_mul(16777619) ^ *byte as u32
    })
}

fn parse_u32_arg(request: &CommandRequest, key: &str, _default: u32) -> Result<Option<u32>> {
    request
        .arg(key)
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|err| anyhow!("invalid {key}={value}: {err}"))
        })
        .transpose()
}

fn parse_ps(value: &str) -> Result<u8> {
    match value {
        "none" | "off" => Ok(LIGHT_PS_NONE),
        "min" | "min_modem" => Ok(LIGHT_PS_MIN),
        "max" | "max_modem" => Ok(LIGHT_PS_MAX),
        _ => bail!("unsupported ps={value}"),
    }
}

fn ps_name(value: u8) -> &'static str {
    match value {
        LIGHT_PS_NONE => "none",
        LIGHT_PS_MIN => "min",
        LIGHT_PS_MAX => "max",
        _ => "unknown",
    }
}

fn cpu_freq_mhz() -> u32 {
    unsafe { esp_clk_cpu_freq() / 1_000_000 }
}

fn xtal_freq_mhz() -> u32 {
    unsafe { esp_clk_xtal_freq() / 1_000_000 }
}

fn wake_cause_name(cause: sys::esp_sleep_wakeup_cause_t) -> &'static str {
    match cause {
        x if x == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_UNDEFINED => "undefined",
        x if x == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_EXT0 => "ext0",
        x if x == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_EXT1 => "ext1",
        x if x == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_TIMER => "timer",
        x if x == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_TOUCHPAD => "touchpad",
        x if x == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_ULP => "ulp",
        x if x == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_GPIO => "gpio",
        x if x == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_UART => "uart",
        x if x == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_WIFI => "wifi",
        _ => "other",
    }
}

fn esp_ok_allow_invalid_state(ret: sys::esp_err_t) -> Result<()> {
    if ret == sys::ESP_OK || ret == sys::ESP_ERR_INVALID_STATE {
        Ok(())
    } else {
        bail!("esp_err=0x{ret:x}")
    }
}

fn esp_ok(ret: sys::esp_err_t) -> Result<()> {
    if ret == sys::ESP_OK {
        Ok(())
    } else {
        bail!("esp_err=0x{ret:x}")
    }
}
