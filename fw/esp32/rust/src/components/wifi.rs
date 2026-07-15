use std::collections::VecDeque;
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::frames::{hex_bytes, parse_bytes};
use super::settings::{parse_bool, parse_i32};
use super::telemetry::{self, Direction};

const FRAME_ADDR1: usize = 4;
const FRAME_ADDR2: usize = 10;
const FRAME_ADDR3: usize = 16;
const RAW_FILTER_ALL: u32 = 0;
const RAW_FILTER_MGMT: u32 = 1;
const RAW_FILTER_ACTION: u32 = 2;
const RAW_FILTER_BEACON: u32 = 3;
const RAW_FILTER_PROBE_REQ: u32 = 4;
const RAW_FILTER_PROBE_RESP: u32 = 5;
const RAW_FILTER_DATA: u32 = 6;
const RAW_FILTER_DMESH: u32 = 7;
const RAW_FILTER_DMESH_DATA: u32 = 8;
const RAW_COMMAND_QUEUE_MAX: usize = 8;
const RAW_COMMAND_MAX_LEN: usize = 512;
const RAW_BROADCAST: [u8; 6] = [0xff; 6];
// lmesh discovery uses ff02::5227, whose Ethernet/Wi-Fi multicast mapping is
// 33:33:00:00:52:27. Directed device traffic uses the peer MAC with the
// multicast bit set.
const LMESH_IPV6_DISCOVERY_MULTICAST: [u8; 6] = [0x33, 0x33, 0x00, 0x00, 0x52, 0x27];
const DMESH_ESPNOW_PREFIX: [u8; 4] = [0x7f, 0x18, 0xfe, 0x34];
const DMESH_ESPNOW_TYPE: u8 = 0x04;
const DMESH_VENDOR_MARKER_LEN: usize = 9;
const DMESH_FIXED_MESH_DST4: [u8; 4] = [0xff; 4];

static RAW_MONITOR_RUNNING: AtomicBool = AtomicBool::new(false);
static RAW_FILTER_MODE: AtomicU32 = AtomicU32::new(RAW_FILTER_MGMT);
static RAW_FILTER_BSSID_ENABLED: AtomicBool = AtomicBool::new(false);
static RAW_FILTER_BSSID: [AtomicU8; 6] = [
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
];
static RAW_RX_TOTAL: AtomicU32 = AtomicU32::new(0);
static RAW_RX_MATCHED: AtomicU32 = AtomicU32::new(0);
static RAW_RX_DROPPED: AtomicU32 = AtomicU32::new(0);
static RAW_RX_LAST_LEN: AtomicU32 = AtomicU32::new(0);
static RAW_RX_LAST_RSSI: AtomicI32 = AtomicI32::new(0);
static RAW_TX_TOTAL: AtomicU32 = AtomicU32::new(0);
static RAW_CMD_RX_TOTAL: AtomicU32 = AtomicU32::new(0);
static RAW_CMD_DROPPED: AtomicU32 = AtomicU32::new(0);
static RAW_WIFI_INIT: AtomicBool = AtomicBool::new(false);
static WIFI_NETIF_PROBE_RUNNING: AtomicBool = AtomicBool::new(false);
static WIFI_NETIF_RX_TOTAL: AtomicU32 = AtomicU32::new(0);
static WIFI_NETIF_RX_LAST_LEN: AtomicU32 = AtomicU32::new(0);
static RAW_LAST_COMMAND_PEER: [AtomicU8; 6] = [
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
];
static RAW_LAST_COMMAND_PEER_VALID: AtomicBool = AtomicBool::new(false);
static mut RAW_RX_LAST: [u8; 256] = [0; 256];
static mut WIFI_NETIF_RX_LAST: [u8; 256] = [0; 256];
static mut WIFI_STA_NETIF: *mut sys::esp_netif_t = std::ptr::null_mut();
static mut WIFI_AP_NETIF: *mut sys::esp_netif_t = std::ptr::null_mut();

#[derive(Clone, Debug)]
pub struct RawWifiCommand {
    pub source: [u8; 6],
    pub text: String,
    pub rssi: i32,
}

static RAW_COMMAND_QUEUE: OnceLock<Mutex<VecDeque<RawWifiCommand>>> = OnceLock::new();

pub fn register_commands(registry: &mut CommandRegistry) {
    registry.register(WifiCommand::default());
}

pub fn forward_management_packet(packet: &[u8]) -> Result<()> {
    ensure_raw_wifi_started(6)?;
    let frame = vendor_action_frame(RAW_BROADCAST, packet)?;
    raw_tx_frame(&frame, true)?;
    RAW_TX_TOTAL.fetch_add(1, Ordering::Relaxed);
    telemetry::record_packet("wifi", Direction::Tx, packet, "source=lora_forward");
    Ok(())
}

pub fn send_vendor_payload_to(destination: [u8; 6], payload: &[u8]) -> Result<()> {
    ensure_raw_wifi_started(6)?;
    let frame = vendor_action_frame(destination, payload)?;
    raw_tx_frame(&frame, true)?;
    RAW_TX_TOTAL.fetch_add(1, Ordering::Relaxed);
    telemetry::record_packet(
        "wifi",
        Direction::Tx,
        payload,
        format!(
            "source=raw_command_response dst={}",
            format_mac(destination)
        ),
    );
    Ok(())
}

#[allow(dead_code)]
pub fn send_to_last_command_peer(payload: &[u8]) -> Result<()> {
    let peer = last_command_peer().context("no raw wifi command peer known")?;
    send_vendor_payload_to(peer, payload)
}

pub fn take_raw_command() -> Option<RawWifiCommand> {
    raw_command_queue().lock().ok()?.pop_front()
}

pub fn start_raw_monitor_mode(channel: u8, filter: &str) -> Result<()> {
    start_raw_only(channel, filter)
}

pub fn start_light_sleep_test_mode(mode: &str, channel: u8) -> Result<()> {
    let channel = channel.clamp(1, 13);
    match mode {
        "raw" | "mgmt" | "prom" | "prom_mgmt" => start_raw_only(channel, "dmesh"),
        "raw_data" | "data" | "prom_data" => start_raw_only(channel, "dmesh_data"),
        "sta" | "unconnected_sta" | "idle_sta" => {
            ensure_raw_wifi_started(channel)?;
            unsafe {
                esp_ok(sys::esp_wifi_set_promiscuous(false))?;
            }
            Ok(())
        }
        "ap" | "softap" | "open_ap" => start_light_sleep_test_ap(channel, 2_000),
        _ => bail!("unsupported wifi light sleep test mode={mode}"),
    }
}

pub fn start_light_sleep_test_ap(channel: u8, beacon_ms: u32) -> Result<()> {
    let ssid = default_direct_ssid()?;
    let beacon_tu = beacon_ms_to_tu(beacon_ms);
    low_level_start_ap_with_beacon_tu(&ssid, "", channel, beacon_tu)
}

fn start_raw_only(channel: u8, filter: &str) -> Result<()> {
    let filter_mode = parse_raw_filter(filter)?;
    RAW_FILTER_MODE.store(filter_mode, Ordering::Relaxed);
    ensure_raw_wifi_started(channel.clamp(1, 13))?;
    start_raw_after_wifi(channel, filter)
}

fn start_raw_after_wifi(channel: u8, filter: &str) -> Result<()> {
    let filter_mode = parse_raw_filter(filter)?;
    RAW_FILTER_MODE.store(filter_mode, Ordering::Relaxed);
    unsafe {
        let mut promisc_filter = sys::wifi_promiscuous_filter_t {
            filter_mask: promiscuous_filter_mask(filter_mode),
        };
        let _ = sys::esp_wifi_set_channel(
            channel.clamp(1, 13),
            sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE,
        );
        esp_ok(sys::esp_wifi_set_promiscuous(false))?;
        esp_ok(sys::esp_wifi_set_promiscuous_rx_cb(Some(raw_wifi_cb)))?;
        esp_ok(sys::esp_wifi_set_promiscuous_filter(&mut promisc_filter))?;
        // ESP-IDF's control filter only selects 802.11 control subtypes; it
        // cannot match the DMesh body key. Keep control frames disabled and
        // apply the DMesh mesh-dst4 filter in the RX parser below.
        let ctrl_filter = sys::wifi_promiscuous_filter_t { filter_mask: 0 };
        esp_ok(sys::esp_wifi_set_promiscuous_ctrl_filter(&ctrl_filter))?;
        esp_ok(sys::esp_wifi_set_promiscuous(true))?;
    }
    RAW_MONITOR_RUNNING.store(true, Ordering::Relaxed);
    Ok(())
}

pub fn set_power_save(mode: &str) -> Result<()> {
    let ps = match mode {
        "none" | "off" => sys::wifi_ps_type_t_WIFI_PS_NONE,
        "min" | "min_modem" => sys::wifi_ps_type_t_WIFI_PS_MIN_MODEM,
        "max" | "max_modem" => sys::wifi_ps_type_t_WIFI_PS_MAX_MODEM,
        _ => bail!("unsupported wifi ps={mode}"),
    };
    unsafe { esp_ok(sys::esp_wifi_set_ps(ps)) }
}

pub fn power_save_name() -> &'static str {
    let mut ps = sys::wifi_ps_type_t_WIFI_PS_NONE;
    let ret = unsafe { sys::esp_wifi_get_ps(&mut ps) };
    if ret != sys::ESP_OK {
        return "unknown";
    }
    match ps {
        x if x == sys::wifi_ps_type_t_WIFI_PS_NONE => "none",
        x if x == sys::wifi_ps_type_t_WIFI_PS_MIN_MODEM => "min",
        x if x == sys::wifi_ps_type_t_WIFI_PS_MAX_MODEM => "max",
        _ => "unknown",
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum WifiMode {
    Off,
    StaIdle,
    Raw,
    RawData,
    RawSta,
    RawStaData,
    RawAp,
    RawApData,
    RawApSta,
    RawApStaData,
}

impl Default for WifiMode {
    fn default() -> Self {
        Self::Off
    }
}

#[derive(Default)]
struct WifiCommand {
    mode: WifiMode,
    ssid: Option<String>,
    psk: Option<String>,
    timeout_ms: u32,
}

impl CommandHandler for WifiCommand {
    fn name(&self) -> &'static str {
        "wifi"
    }

    fn help(&self) -> &'static str {
        "wifi mode=off|sta_idle|raw|raw_data|raw_sta|raw_sta_data|raw_ap|raw_ap_data|raw_ap_sta|raw_ap_sta_data channel=6 filter=dmesh ssid=SSID psk=PSK timeout=MS | wifi scan=true | wifi raw=hex:... | wifi raw_action=TEXT | wifi raw_data=TEXT | wifi raw_stats=true"
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        self.configure_raw_filter(request)?;
        if request.arg("raw_stop").is_some() {
            stop_raw_monitor()?;
            return Ok(CommandResponse::ok("wifi raw monitor stopped"));
        }
        if request.arg("raw_stats").is_some() {
            return Ok(CommandResponse::ok(raw_stats()));
        }
        if request.arg("netif_stats").is_some() {
            return Ok(CommandResponse::ok(netif_probe_stats()));
        }
        if request
            .arg("netif_probe")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            let iface = request
                .arg("iface")
                .or_else(|| request.arg("if"))
                .unwrap_or("sta");
            start_netif_probe(iface)?;
            return Ok(CommandResponse::ok(format!(
                "wifi netif_probe started {}",
                netif_probe_stats()
            )));
        }
        if request
            .arg("raw_monitor")
            .or_else(|| request.arg("monitor"))
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            self.start_raw_monitor(request)?;
            return Ok(CommandResponse::ok(format!(
                "wifi raw monitor started {}",
                raw_stats()
            )));
        }
        if let Some(raw) = request.arg("raw").or_else(|| request.arg("raw_tx")) {
            let channel = request
                .arg("channel")
                .map(parse_i32)
                .transpose()?
                .unwrap_or(6)
                .clamp(1, 13) as u8;
            prepare_raw_tx(channel)?;
            let bytes = parse_bytes(raw)?;
            raw_tx(&bytes, request)?;
            return Ok(CommandResponse::ok(format!(
                "wifi raw sent bytes={} {}",
                bytes.len(),
                raw_stats()
            )));
        }
        if let Some(payload) = request.arg("raw_data") {
            let channel = request
                .arg("channel")
                .map(parse_i32)
                .transpose()?
                .unwrap_or(6)
                .clamp(1, 13) as u8;
            let destination = request
                .arg("dst")
                .or_else(|| request.arg("destination"))
                .map(parse_mac)
                .transpose()?
                .unwrap_or(LMESH_IPV6_DISCOVERY_MULTICAST);
            let source = request
                .arg("src")
                .or_else(|| request.arg("source_mac"))
                .map(parse_mac)
                .transpose()?;
            let bssid = request
                .arg("bssid")
                .or_else(|| request.arg("ap_bssid"))
                .map(parse_mac)
                .transpose()?;
            let to_ap = request
                .arg("to_ap")
                .or_else(|| request.arg("tods"))
                .map(parse_bool)
                .transpose()?
                .unwrap_or(false);
            prepare_raw_tx(channel)?;
            let frame = match (bssid, to_ap) {
                (Some(bssid), true) => {
                    dmesh_sta_to_ap_data_frame(destination, source, bssid, payload.as_bytes())?
                }
                (Some(bssid), false) => {
                    dmesh_ap_to_sta_data_frame(destination, bssid, payload.as_bytes())?
                }
                (None, _) => dmesh_data_frame(destination, source, payload.as_bytes())?,
            };
            raw_tx_frame(&frame, true)?;
            RAW_TX_TOTAL.fetch_add(1, Ordering::Relaxed);
            telemetry::record_packet("wifi", Direction::Tx, payload.as_bytes(), "raw_data=true");
            return Ok(CommandResponse::ok(format!(
                "wifi raw_data sent bytes={} {}",
                frame.len(),
                raw_stats()
            )));
        }
        if let Some(payload) = request
            .arg("raw_action")
            .or_else(|| request.arg("raw_payload"))
        {
            let channel = request
                .arg("channel")
                .map(parse_i32)
                .transpose()?
                .unwrap_or(6)
                .clamp(1, 13) as u8;
            let destination = request
                .arg("dst")
                .or_else(|| request.arg("destination"))
                .map(parse_mac)
                .transpose()?
                .unwrap_or(RAW_BROADCAST);
            prepare_raw_tx(channel)?;
            let frame = vendor_action_frame(destination, payload.as_bytes())?;
            raw_tx_frame(&frame, true)?;
            RAW_TX_TOTAL.fetch_add(1, Ordering::Relaxed);
            telemetry::record_packet("wifi", Direction::Tx, payload.as_bytes(), "raw_action=true");
            return Ok(CommandResponse::ok(format!(
                "wifi raw_action sent bytes={} {}",
                frame.len(),
                raw_stats()
            )));
        }
        if request.arg("stop").is_some() {
            self.stop()?;
            return Ok(CommandResponse::ok("wifi stopped"));
        }
        if request.arg("time").is_some() {
            start_sntp(request.arg("time").unwrap_or("pool.ntp.org"))?;
            return Ok(CommandResponse::ok("wifi sntp started"));
        }
        if request.arg("scan").is_some() {
            return self.scan();
        }
        if let Some(mode) = request.arg("mode") {
            return self.start_mode(request, mode);
        }

        if let Some(timeout) = request.arg_i32("timeout")? {
            self.timeout_ms = timeout.max(0) as u32;
        }
        if request
            .arg("ap")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            self.start_ap(request)
        } else if request.arg("ssid").is_some() {
            self.start_sta(request)
        } else {
            Ok(CommandResponse::ok(format!(
                "wifi mode={:?} ssid={} timeout_ms={} {}",
                self.mode,
                self.ssid.as_deref().unwrap_or(""),
                self.timeout_ms,
                wifi_net_status()
            )))
        }
    }
}

impl WifiCommand {
    fn start_mode(&mut self, request: &CommandRequest, mode: &str) -> Result<CommandResponse> {
        let channel = command_channel(request, 6)?;
        match mode {
            "off" | "stop" | "stopped" => {
                self.stop()?;
                Ok(CommandResponse::ok("wifi mode=Off"))
            }
            "raw" => {
                start_raw_only(channel, mode_filter_name(request, "dmesh"))?;
                self.mode = WifiMode::Raw;
                Ok(CommandResponse::ok(format!(
                    "wifi mode=Raw channel={} {} {}",
                    channel,
                    wifi_net_status(),
                    raw_stats()
                )))
            }
            "raw_data" | "data_raw" => {
                start_raw_only(channel, mode_filter_name(request, "dmesh_data"))?;
                self.mode = WifiMode::RawData;
                Ok(CommandResponse::ok(format!(
                    "wifi mode=RawData sta=unassociated channel={} {} {}",
                    channel,
                    wifi_net_status(),
                    raw_stats()
                )))
            }
            "sta_idle" | "idle_sta" | "sta_only" | "station_idle" => {
                let ssid = request.arg("ssid").unwrap_or("DMesh-Idle");
                validate_wifi_string("ssid", ssid, 32)?;
                low_level_start_sta_idle(ssid, channel)?;
                self.mode = WifiMode::StaIdle;
                self.ssid = Some(ssid.to_string());
                self.psk = None;
                Ok(CommandResponse::ok(format!(
                    "wifi mode=StaIdle ssid={} channel={} connect=false {} {}",
                    ssid,
                    channel,
                    wifi_net_status(),
                    raw_stats()
                )))
            }
            "raw_sta" | "sta_raw" => {
                let ssid = request
                    .arg("ssid")
                    .context("wifi raw_sta requires ssid=...")?;
                let psk = request.arg("psk").unwrap_or("");
                let timeout_ms = self.command_timeout(request)?;
                validate_wifi_string("ssid", ssid, 32)?;
                validate_wifi_string("psk", psk, 64)?;
                low_level_start_sta(ssid, psk, channel)?;
                start_raw_after_wifi(channel, mode_filter_name(request, "dmesh"))?;
                if timeout_ms > 0 {
                    task_delay(Duration::from_millis(timeout_ms as u64));
                }
                self.mode = WifiMode::RawSta;
                self.ssid = Some(ssid.to_string());
                self.psk = Some(psk.to_string());
                Ok(CommandResponse::ok(format!(
                    "wifi mode=RawSta ssid={} channel={} timeout_ms={} {} {}",
                    ssid,
                    channel,
                    timeout_ms,
                    wifi_net_status(),
                    raw_stats()
                )))
            }
            "raw_sta_data" | "sta_raw_data" | "raw_data_sta" | "data_raw_sta" => {
                if let Some(ssid) = request.arg("ssid") {
                    let psk = request.arg("psk").unwrap_or("");
                    let timeout_ms = self.command_timeout(request)?;
                    validate_wifi_string("ssid", ssid, 32)?;
                    validate_wifi_string("psk", psk, 64)?;
                    low_level_start_sta(ssid, psk, channel)?;
                    start_raw_after_wifi(channel, mode_filter_name(request, "dmesh_data"))?;
                    if timeout_ms > 0 {
                        task_delay(Duration::from_millis(timeout_ms as u64));
                    }
                    self.mode = WifiMode::RawStaData;
                    self.ssid = Some(ssid.to_string());
                    self.psk = Some(psk.to_string());
                    Ok(CommandResponse::ok(format!(
                        "wifi mode=RawStaData ssid={} channel={} timeout_ms={} {} {}",
                        ssid,
                        channel,
                        timeout_ms,
                        wifi_net_status(),
                        raw_stats()
                    )))
                } else {
                    start_raw_only(channel, mode_filter_name(request, "dmesh_data"))?;
                    self.mode = WifiMode::RawStaData;
                    Ok(CommandResponse::ok(format!(
                        "wifi mode=RawStaData sta=unassociated channel={} {} {}",
                        channel,
                        wifi_net_status(),
                        raw_stats()
                    )))
                }
            }
            "fake_sta" | "sta_fake" | "raw_fake_sta" | "fake_sta_raw" => {
                let bssid = request
                    .arg("bssid")
                    .or_else(|| request.arg("ap_bssid"))
                    .map(parse_mac)
                    .transpose()?
                    .context("wifi fake_sta requires bssid=xx:xx:xx:xx:xx:xx")?;
                let ssid = request.arg("ssid").unwrap_or("DMesh-Fake");
                let psk = request.arg("psk").unwrap_or("");
                validate_wifi_string("ssid", ssid, 32)?;
                validate_wifi_string("psk", psk, 64)?;
                low_level_start_fake_sta(ssid, psk, bssid, channel)?;
                start_raw_after_wifi(channel, mode_filter_name(request, "dmesh"))?;
                self.mode = WifiMode::RawSta;
                self.ssid = Some(ssid.to_string());
                self.psk = Some(psk.to_string());
                Ok(CommandResponse::ok(format!(
                    "wifi mode=FakeSta ssid={} bssid={} channel={} connect=false {} {}",
                    ssid,
                    format_mac(bssid),
                    channel,
                    wifi_net_status(),
                    raw_stats()
                )))
            }
            "raw_ap" | "ap_raw" => {
                let (ssid, psk) = self.ap_identity(request)?;
                let beacon_tu = command_beacon_tu(request)?;
                low_level_start_ap_with_beacon_tu(&ssid, &psk, channel, beacon_tu)?;
                start_raw_after_wifi(channel, mode_filter_name(request, "dmesh"))?;
                self.mode = WifiMode::RawAp;
                self.ssid = Some(ssid.clone());
                self.psk = Some(psk.clone());
                Ok(CommandResponse::ok(format!(
                    "wifi mode=RawAp ssid={} channel={} beacon_tu={} auth={} {} {}",
                    ssid,
                    channel,
                    beacon_tu,
                    if psk.is_empty() { "open" } else { "wpa2" },
                    wifi_net_status(),
                    raw_stats()
                )))
            }
            "raw_ap_data" | "ap_raw_data" | "raw_data_ap" | "data_raw_ap" => {
                let (ssid, psk) = self.ap_identity(request)?;
                let beacon_tu = command_beacon_tu(request)?;
                low_level_start_ap_with_beacon_tu(&ssid, &psk, channel, beacon_tu)?;
                start_raw_after_wifi(channel, mode_filter_name(request, "dmesh_data"))?;
                self.mode = WifiMode::RawApData;
                self.ssid = Some(ssid.clone());
                self.psk = Some(psk.clone());
                Ok(CommandResponse::ok(format!(
                    "wifi mode=RawApData ssid={} channel={} beacon_tu={} auth={} {} {}",
                    ssid,
                    channel,
                    beacon_tu,
                    if psk.is_empty() { "open" } else { "wpa2" },
                    wifi_net_status(),
                    raw_stats()
                )))
            }
            "raw_ap_sta" | "raw_sta_ap" | "ap_sta_raw" | "sta_ap_raw" => {
                let (ap_ssid, ap_psk) = self.ap_identity(request)?;
                let sta_ssid = request
                    .arg("sta_ssid")
                    .or_else(|| request.arg("join_ssid"))
                    .or_else(|| request.arg("ssid"))
                    .context("wifi raw_ap_sta requires ssid=... or sta_ssid=...")?;
                let sta_psk = request
                    .arg("sta_psk")
                    .or_else(|| request.arg("join_psk"))
                    .or_else(|| request.arg("psk"))
                    .unwrap_or("");
                let timeout_ms = self.command_timeout(request)?;
                validate_wifi_string("ssid", sta_ssid, 32)?;
                validate_wifi_string("psk", sta_psk, 64)?;
                low_level_start_ap_sta(&ap_ssid, &ap_psk, sta_ssid, sta_psk, channel)?;
                start_raw_after_wifi(channel, mode_filter_name(request, "dmesh"))?;
                if timeout_ms > 0 {
                    task_delay(Duration::from_millis(timeout_ms as u64));
                }
                self.mode = WifiMode::RawApSta;
                self.ssid = Some(ap_ssid.clone());
                self.psk = Some(ap_psk.clone());
                Ok(CommandResponse::ok(format!(
                    "wifi mode=RawApSta ap_ssid={} sta_ssid={} channel={} timeout_ms={} {} {}",
                    ap_ssid,
                    sta_ssid,
                    channel,
                    timeout_ms,
                    wifi_net_status(),
                    raw_stats()
                )))
            }
            "raw_ap_sta_data" | "raw_sta_ap_data" | "ap_sta_raw_data" | "sta_ap_raw_data" => {
                let (ap_ssid, ap_psk) = self.ap_identity(request)?;
                let sta_ssid = request
                    .arg("sta_ssid")
                    .or_else(|| request.arg("join_ssid"))
                    .or_else(|| request.arg("ssid"))
                    .context("wifi raw_ap_sta_data requires ssid=... or sta_ssid=...")?;
                let sta_psk = request
                    .arg("sta_psk")
                    .or_else(|| request.arg("join_psk"))
                    .or_else(|| request.arg("psk"))
                    .unwrap_or("");
                let timeout_ms = self.command_timeout(request)?;
                validate_wifi_string("ssid", sta_ssid, 32)?;
                validate_wifi_string("psk", sta_psk, 64)?;
                low_level_start_ap_sta(&ap_ssid, &ap_psk, sta_ssid, sta_psk, channel)?;
                start_raw_after_wifi(channel, mode_filter_name(request, "dmesh_data"))?;
                if timeout_ms > 0 {
                    task_delay(Duration::from_millis(timeout_ms as u64));
                }
                self.mode = WifiMode::RawApStaData;
                self.ssid = Some(ap_ssid.clone());
                self.psk = Some(ap_psk.clone());
                Ok(CommandResponse::ok(format!(
                    "wifi mode=RawApStaData ap_ssid={} sta_ssid={} channel={} timeout_ms={} {} {}",
                    ap_ssid,
                    sta_ssid,
                    channel,
                    timeout_ms,
                    wifi_net_status(),
                    raw_stats()
                )))
            }
            "sta" => self.start_sta(request),
            "ap" => self.start_ap(request),
            _ => bail!("unsupported wifi mode={mode}"),
        }
    }

    fn start_sta(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let ssid = request.arg("ssid").context("wifi sta requires ssid=...")?;
        let psk = request.arg("psk").unwrap_or("");
        let channel = command_channel(request, 6)?;
        validate_wifi_string("ssid", ssid, 32)?;
        validate_wifi_string("psk", psk, 64)?;
        self.ssid = Some(ssid.to_string());
        self.psk = Some(psk.to_string());

        let timeout_ms = self.command_timeout(request)?;
        low_level_start_sta(ssid, psk, channel)?;
        start_raw_after_wifi(channel, raw_filter_name())?;
        if timeout_ms > 0 {
            task_delay(Duration::from_millis(timeout_ms as u64));
        }
        self.mode = WifiMode::RawSta;
        Ok(CommandResponse::ok(format!(
            "wifi mode=RawSta ssid={} channel={} timeout_ms={} {}",
            self.ssid.as_deref().unwrap_or(""),
            channel,
            timeout_ms,
            wifi_net_status()
        )))
    }

    fn start_ap(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let (ssid, psk) = self.ap_identity(request)?;
        let channel = command_channel(request, 6)?;
        self.ssid = Some(ssid.clone());
        self.psk = Some(psk.clone());

        let beacon_tu = command_beacon_tu(request)?;
        low_level_start_ap_with_beacon_tu(&ssid, &psk, channel, beacon_tu)?;
        start_raw_after_wifi(channel, raw_filter_name())?;
        self.mode = WifiMode::RawAp;
        Ok(CommandResponse::ok(format!(
            "wifi mode=RawAp ssid={} channel={} beacon_tu={} auth={} {}",
            self.ssid.as_deref().unwrap_or(""),
            channel,
            beacon_tu,
            if psk.is_empty() { "open" } else { "wpa2" },
            wifi_net_status()
        )))
    }

    fn scan(&mut self) -> Result<CommandResponse> {
        let aps = low_level_scan()?;
        let summary = aps
            .iter()
            .take(16)
            .map(|ap| format!("{}:{}:ch{}:auth{}", ap.ssid, ap.rssi, ap.channel, ap.auth))
            .collect::<Vec<_>>()
            .join(",");
        Ok(CommandResponse::ok(format!(
            "wifi scan count={} {}",
            aps.len(),
            summary
        )))
    }

    fn start_raw_monitor(&mut self, request: &CommandRequest) -> Result<()> {
        let channel = command_channel(request, 6)?;
        start_raw_only(channel, mode_filter_name(request, "dmesh"))?;
        self.mode = WifiMode::Raw;
        Ok(())
    }

    fn configure_raw_filter(&mut self, request: &CommandRequest) -> Result<()> {
        if let Some(filter) = request.arg("filter").or_else(|| request.arg("raw_filter")) {
            RAW_FILTER_MODE.store(parse_raw_filter(filter)?, Ordering::Relaxed);
        }
        if let Some(bssid) = request
            .arg("raw_bssid")
            .or_else(|| request.arg("bssid_filter"))
        {
            if bssid == "none" || bssid == "false" {
                RAW_FILTER_BSSID_ENABLED.store(false, Ordering::Relaxed);
            } else {
                let bssid = parse_mac(bssid)?;
                for (idx, byte) in bssid.iter().enumerate() {
                    RAW_FILTER_BSSID[idx].store(*byte, Ordering::Relaxed);
                }
                RAW_FILTER_BSSID_ENABLED.store(true, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        low_level_stop_wifi()?;
        self.mode = WifiMode::Off;
        Ok(())
    }

    fn command_timeout(&mut self, request: &CommandRequest) -> Result<u32> {
        if let Some(timeout) = request.arg_i32("timeout")? {
            self.timeout_ms = timeout.max(0) as u32;
        }
        Ok(self.timeout_ms)
    }

    fn ap_identity(&self, request: &CommandRequest) -> Result<(String, String)> {
        let ssid = if let Some(ssid) = request.arg("ap_ssid").or_else(|| request.arg("ssid")) {
            ssid.to_string()
        } else {
            default_direct_ssid()?
        };
        let psk = request
            .arg("ap_psk")
            .or_else(|| request.arg("psk"))
            .unwrap_or("")
            .to_string();
        validate_wifi_string("ssid", &ssid, 32)?;
        validate_wifi_string("psk", &psk, 64)?;
        if !psk.is_empty() && psk.len() < 8 {
            bail!("AP psk must be empty or at least 8 bytes");
        }
        Ok((ssid, psk))
    }
}

fn command_channel(request: &CommandRequest, default: u8) -> Result<u8> {
    Ok(request
        .arg("channel")
        .map(parse_i32)
        .transpose()?
        .unwrap_or(default as i32)
        .clamp(1, 13) as u8)
}

fn mode_filter_name<'a>(request: &'a CommandRequest, default: &'a str) -> &'a str {
    request
        .arg("filter")
        .or_else(|| request.arg("raw_filter"))
        .unwrap_or(default)
}

#[derive(Debug)]
struct ScanAp {
    ssid: String,
    rssi: i8,
    channel: u8,
    auth: &'static str,
}

pub fn ensure_raw_wifi_started(channel: u8) -> Result<()> {
    ensure_low_level_wifi()?;
    unsafe {
        esp_ok_allow_invalid_state(sys::esp_wifi_set_mode(sys::wifi_mode_t_WIFI_MODE_STA))?;
        esp_ok_allow_invalid_state(sys::esp_wifi_start())?;
        esp_ok(sys::esp_wifi_set_channel(
            channel.max(1),
            sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE,
        ))?;
    }
    Ok(())
}

fn ensure_low_level_wifi() -> Result<()> {
    unsafe {
        esp_ok_allow_invalid_state(sys::esp_netif_init())?;
        esp_ok_allow_invalid_state(sys::esp_event_loop_create_default())?;
        if WIFI_STA_NETIF.is_null() {
            WIFI_STA_NETIF = sys::esp_netif_create_default_wifi_sta();
        }
        if WIFI_AP_NETIF.is_null() {
            WIFI_AP_NETIF = sys::esp_netif_create_default_wifi_ap();
        }
        if !RAW_WIFI_INIT.swap(true, Ordering::SeqCst) {
            let mut cfg = wifi_init_config_default();
            let ret = sys::esp_wifi_init(&mut cfg);
            if ret != sys::ESP_OK && ret != sys::ESP_ERR_INVALID_STATE {
                RAW_WIFI_INIT.store(false, Ordering::SeqCst);
                esp_ok(ret)?;
            }
            let _ = sys::esp_wifi_set_storage(sys::wifi_storage_t_WIFI_STORAGE_RAM);
        }
    }
    Ok(())
}

fn low_level_start_ap(ssid: &str, psk: &str, channel: u8) -> Result<()> {
    low_level_start_ap_with_beacon_tu(ssid, psk, channel, 100)
}

fn low_level_start_ap_with_beacon_tu(
    ssid: &str,
    psk: &str,
    channel: u8,
    beacon_tu: u16,
) -> Result<()> {
    ensure_low_level_wifi()?;
    unsafe {
        let _ = sys::esp_wifi_stop();
        esp_ok(sys::esp_wifi_set_mode(sys::wifi_mode_t_WIFI_MODE_AP))?;
        let mut ap = sys::wifi_ap_config_t::default();
        copy_cstr_bytes(&mut ap.ssid, ssid.as_bytes());
        copy_cstr_bytes(&mut ap.password, psk.as_bytes());
        ap.ssid_len = ssid.len().min(ap.ssid.len()) as u8;
        ap.channel = channel;
        ap.authmode = if psk.is_empty() {
            sys::wifi_auth_mode_t_WIFI_AUTH_OPEN
        } else {
            sys::wifi_auth_mode_t_WIFI_AUTH_WPA2_PSK
        };
        ap.max_connection = 4;
        ap.beacon_interval = beacon_tu;
        let mut conf = sys::wifi_config_t { ap };
        esp_ok(sys::esp_wifi_set_config(
            sys::wifi_interface_t_WIFI_IF_AP,
            &mut conf,
        ))?;
        esp_ok(sys::esp_wifi_start())?;
        if !WIFI_AP_NETIF.is_null() {
            let _ = sys::esp_netif_create_ip6_linklocal(WIFI_AP_NETIF);
        }
    }
    Ok(())
}

fn beacon_ms_to_tu(beacon_ms: u32) -> u16 {
    // ESP-IDF stores SoftAP beacon_interval in 1024 us time units. Keep the
    // test helper in the common documented range while allowing a 2 s beacon.
    let tu = ((beacon_ms as u64 * 1000) / 1024).clamp(100, 60_000);
    tu as u16
}

fn command_beacon_tu(request: &CommandRequest) -> Result<u16> {
    let beacon_ms = request
        .arg("beacon_ms")
        .or_else(|| request.arg("beacon"))
        .map(parse_i32)
        .transpose()?
        .unwrap_or(102);
    Ok(beacon_ms_to_tu(beacon_ms.max(1) as u32))
}

fn low_level_start_sta(ssid: &str, psk: &str, channel: u8) -> Result<()> {
    ensure_low_level_wifi()?;
    unsafe {
        let _ = sys::esp_wifi_disconnect();
        let _ = sys::esp_wifi_stop();
        esp_ok(sys::esp_wifi_set_mode(sys::wifi_mode_t_WIFI_MODE_STA))?;
        let mut sta = sys::wifi_sta_config_t::default();
        copy_cstr_bytes(&mut sta.ssid, ssid.as_bytes());
        copy_cstr_bytes(&mut sta.password, psk.as_bytes());
        sta.channel = channel;
        sta.threshold.authmode = if psk.is_empty() {
            sys::wifi_auth_mode_t_WIFI_AUTH_OPEN
        } else {
            sys::wifi_auth_mode_t_WIFI_AUTH_WPA2_PSK
        };
        let mut conf = sys::wifi_config_t { sta };
        esp_ok(sys::esp_wifi_set_config(
            sys::wifi_interface_t_WIFI_IF_STA,
            &mut conf,
        ))?;
        esp_ok(sys::esp_wifi_start())?;
        esp_ok(sys::esp_wifi_connect())?;
        if !WIFI_STA_NETIF.is_null() {
            let _ = sys::esp_netif_create_ip6_linklocal(WIFI_STA_NETIF);
        }
    }
    Ok(())
}

fn low_level_start_sta_idle(ssid: &str, channel: u8) -> Result<()> {
    ensure_low_level_wifi()?;
    unsafe {
        let _ = sys::esp_wifi_disconnect();
        let _ = sys::esp_wifi_set_promiscuous(false);
        let _ = sys::esp_wifi_stop();
        esp_ok(sys::esp_wifi_set_mode(sys::wifi_mode_t_WIFI_MODE_STA))?;
        let mut sta = sys::wifi_sta_config_t::default();
        copy_cstr_bytes(&mut sta.ssid, ssid.as_bytes());
        sta.channel = channel;
        sta.threshold.authmode = sys::wifi_auth_mode_t_WIFI_AUTH_OPEN;
        let mut conf = sys::wifi_config_t { sta };
        esp_ok(sys::esp_wifi_set_config(
            sys::wifi_interface_t_WIFI_IF_STA,
            &mut conf,
        ))?;
        esp_ok(sys::esp_wifi_start())?;
        esp_ok_allow_invalid_state(sys::esp_wifi_set_channel(
            channel.clamp(1, 13),
            sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE,
        ))?;
        if !WIFI_STA_NETIF.is_null() {
            let _ = sys::esp_netif_create_ip6_linklocal(WIFI_STA_NETIF);
        }
    }
    RAW_MONITOR_RUNNING.store(false, Ordering::Relaxed);
    WIFI_NETIF_PROBE_RUNNING.store(false, Ordering::Relaxed);
    Ok(())
}

fn low_level_start_fake_sta(ssid: &str, psk: &str, bssid: [u8; 6], channel: u8) -> Result<()> {
    ensure_low_level_wifi()?;
    unsafe {
        let _ = sys::esp_wifi_disconnect();
        let _ = sys::esp_wifi_stop();
        esp_ok(sys::esp_wifi_set_mode(sys::wifi_mode_t_WIFI_MODE_STA))?;
        let mut sta = sys::wifi_sta_config_t::default();
        copy_cstr_bytes(&mut sta.ssid, ssid.as_bytes());
        copy_cstr_bytes(&mut sta.password, psk.as_bytes());
        sta.bssid_set = true;
        sta.bssid.copy_from_slice(&bssid);
        sta.channel = channel;
        sta.threshold.authmode = if psk.is_empty() {
            sys::wifi_auth_mode_t_WIFI_AUTH_OPEN
        } else {
            sys::wifi_auth_mode_t_WIFI_AUTH_WPA2_PSK
        };
        let mut conf = sys::wifi_config_t { sta };
        esp_ok(sys::esp_wifi_set_config(
            sys::wifi_interface_t_WIFI_IF_STA,
            &mut conf,
        ))?;
        esp_ok(sys::esp_wifi_start())?;
        esp_ok_allow_invalid_state(sys::esp_wifi_set_channel(
            channel.clamp(1, 13),
            sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE,
        ))?;
        if !WIFI_STA_NETIF.is_null() {
            let _ = sys::esp_netif_create_ip6_linklocal(WIFI_STA_NETIF);
        }
    }
    Ok(())
}

fn low_level_start_ap_sta(
    ap_ssid: &str,
    ap_psk: &str,
    sta_ssid: &str,
    sta_psk: &str,
    channel: u8,
) -> Result<()> {
    ensure_low_level_wifi()?;
    unsafe {
        let _ = sys::esp_wifi_disconnect();
        let _ = sys::esp_wifi_stop();
        esp_ok(sys::esp_wifi_set_mode(sys::wifi_mode_t_WIFI_MODE_APSTA))?;

        let mut ap = sys::wifi_ap_config_t::default();
        copy_cstr_bytes(&mut ap.ssid, ap_ssid.as_bytes());
        copy_cstr_bytes(&mut ap.password, ap_psk.as_bytes());
        ap.ssid_len = ap_ssid.len().min(ap.ssid.len()) as u8;
        ap.channel = channel;
        ap.authmode = if ap_psk.is_empty() {
            sys::wifi_auth_mode_t_WIFI_AUTH_OPEN
        } else {
            sys::wifi_auth_mode_t_WIFI_AUTH_WPA2_PSK
        };
        ap.max_connection = 4;
        ap.beacon_interval = 100;
        let mut ap_conf = sys::wifi_config_t { ap };
        esp_ok(sys::esp_wifi_set_config(
            sys::wifi_interface_t_WIFI_IF_AP,
            &mut ap_conf,
        ))?;

        let mut sta = sys::wifi_sta_config_t::default();
        copy_cstr_bytes(&mut sta.ssid, sta_ssid.as_bytes());
        copy_cstr_bytes(&mut sta.password, sta_psk.as_bytes());
        sta.channel = channel;
        sta.threshold.authmode = if sta_psk.is_empty() {
            sys::wifi_auth_mode_t_WIFI_AUTH_OPEN
        } else {
            sys::wifi_auth_mode_t_WIFI_AUTH_WPA2_PSK
        };
        let mut sta_conf = sys::wifi_config_t { sta };
        esp_ok(sys::esp_wifi_set_config(
            sys::wifi_interface_t_WIFI_IF_STA,
            &mut sta_conf,
        ))?;

        esp_ok(sys::esp_wifi_start())?;
        esp_ok(sys::esp_wifi_connect())?;
        if !WIFI_AP_NETIF.is_null() {
            let _ = sys::esp_netif_create_ip6_linklocal(WIFI_AP_NETIF);
        }
        if !WIFI_STA_NETIF.is_null() {
            let _ = sys::esp_netif_create_ip6_linklocal(WIFI_STA_NETIF);
        }
    }
    Ok(())
}

fn low_level_scan() -> Result<Vec<ScanAp>> {
    ensure_low_level_wifi()?;
    unsafe {
        let _ = sys::esp_wifi_stop();
        esp_ok(sys::esp_wifi_set_mode(sys::wifi_mode_t_WIFI_MODE_STA))?;
        esp_ok(sys::esp_wifi_start())?;
        esp_ok(sys::esp_wifi_scan_start(std::ptr::null(), true))?;
        let mut total = 0_u16;
        esp_ok(sys::esp_wifi_scan_get_ap_num(&mut total))?;
        let mut records = vec![sys::wifi_ap_record_t::default(); total.min(32) as usize];
        let mut count = records.len() as u16;
        if count > 0 {
            esp_ok(sys::esp_wifi_scan_get_ap_records(
                &mut count,
                records.as_mut_ptr(),
            ))?;
        }
        records.truncate(count as usize);
        Ok(records
            .iter()
            .map(|record| ScanAp {
                ssid: ssid_from_bytes(&record.ssid),
                rssi: record.rssi,
                channel: record.primary,
                auth: auth_name(record.authmode),
            })
            .collect())
    }
}

fn low_level_stop_wifi() -> Result<()> {
    unsafe {
        let _ = sys::esp_wifi_disconnect();
        let _ = sys::esp_wifi_stop();
        let _ = sys::esp_wifi_set_promiscuous(false);
        let _ = sys::esp_wifi_internal_reg_rxcb(sys::wifi_interface_t_WIFI_IF_STA, None);
    }
    RAW_MONITOR_RUNNING.store(false, Ordering::Relaxed);
    WIFI_NETIF_PROBE_RUNNING.store(false, Ordering::Relaxed);
    Ok(())
}

fn prepare_raw_tx(channel: u8) -> Result<()> {
    let mut mode = sys::wifi_mode_t_WIFI_MODE_NULL;
    let ret = unsafe { sys::esp_wifi_get_mode(&mut mode) };
    if ret != sys::ESP_OK || mode == sys::wifi_mode_t_WIFI_MODE_NULL {
        ensure_raw_wifi_started(channel)?;
    }
    Ok(())
}

fn wifi_init_config_default() -> sys::wifi_init_config_t {
    sys::wifi_init_config_t {
        osi_funcs: std::ptr::addr_of_mut!(sys::g_wifi_osi_funcs),
        wpa_crypto_funcs: unsafe { sys::g_wifi_default_wpa_crypto_funcs },
        static_rx_buf_num: sys::CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM as i32,
        dynamic_rx_buf_num: sys::CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM as i32,
        tx_buf_type: sys::CONFIG_ESP_WIFI_TX_BUFFER_TYPE as i32,
        static_tx_buf_num: sys::WIFI_STATIC_TX_BUFFER_NUM as i32,
        dynamic_tx_buf_num: sys::WIFI_DYNAMIC_TX_BUFFER_NUM as i32,
        rx_mgmt_buf_type: sys::CONFIG_ESP_WIFI_DYNAMIC_RX_MGMT_BUF as i32,
        rx_mgmt_buf_num: sys::WIFI_RX_MGMT_BUF_NUM_DEF as i32,
        cache_tx_buf_num: sys::WIFI_CACHE_TX_BUFFER_NUM as i32,
        csi_enable: sys::WIFI_CSI_ENABLED as i32,
        ampdu_rx_enable: sys::WIFI_AMPDU_RX_ENABLED as i32,
        ampdu_tx_enable: sys::WIFI_AMPDU_TX_ENABLED as i32,
        amsdu_tx_enable: sys::WIFI_AMSDU_TX_ENABLED as i32,
        nvs_enable: sys::WIFI_NVS_ENABLED as i32,
        nano_enable: sys::WIFI_NANO_FORMAT_ENABLED as i32,
        rx_ba_win: sys::WIFI_DEFAULT_RX_BA_WIN as i32,
        wifi_task_core_id: sys::WIFI_TASK_CORE_ID as i32,
        beacon_max_len: sys::WIFI_SOFTAP_BEACON_MAX_LEN as i32,
        mgmt_sbuf_num: sys::WIFI_MGMT_SBUF_NUM as i32,
        feature_caps: sys::WIFI_FEATURE_CAPS as u64,
        sta_disconnected_pm: sys::WIFI_STA_DISCONNECTED_PM_ENABLED != 0,
        espnow_max_encrypt_num: sys::CONFIG_ESP_WIFI_ESPNOW_MAX_ENCRYPT_NUM as i32,
        tx_hetb_queue_num: sys::WIFI_TX_HETB_QUEUE_NUM as i32,
        dump_hesigb_enable: sys::WIFI_DUMP_HESIGB_ENABLED != 0,
        magic: sys::WIFI_INIT_CONFIG_MAGIC as i32,
    }
}

pub fn stop_raw_monitor() -> Result<()> {
    unsafe {
        let _ = sys::esp_wifi_set_promiscuous(false);
        esp_ok_allow_invalid_state(sys::esp_wifi_stop())?;
    }
    RAW_MONITOR_RUNNING.store(false, Ordering::Relaxed);
    Ok(())
}

fn raw_tx(bytes: &[u8], request: &CommandRequest) -> Result<()> {
    if bytes.len() < 24 || bytes.len() > 1500 {
        bail!(
            "raw 802.11 frame length must be 24..=1500, got {}",
            bytes.len()
        );
    }
    let en_sys_seq = request
        .arg("sys_seq")
        .map(parse_bool)
        .transpose()?
        .unwrap_or(true);
    raw_tx_frame(bytes, en_sys_seq)?;
    RAW_TX_TOTAL.fetch_add(1, Ordering::Relaxed);
    telemetry::record_packet(
        "wifi",
        Direction::Tx,
        bytes,
        format!(
            "raw=true sys_seq={} subtype={}",
            en_sys_seq,
            frame_subtype(bytes)
        ),
    );
    Ok(())
}

fn raw_tx_frame(bytes: &[u8], en_sys_seq: bool) -> Result<()> {
    let iface = raw_tx_interface();
    unsafe {
        esp_ok(sys::esp_wifi_80211_tx(
            iface,
            bytes.as_ptr() as *const _,
            bytes.len() as i32,
            en_sys_seq,
        ))
    }
}

fn raw_tx_interface() -> sys::wifi_interface_t {
    let mut mode = sys::wifi_mode_t_WIFI_MODE_NULL;
    let ret = unsafe { sys::esp_wifi_get_mode(&mut mode) };
    if ret == sys::ESP_OK && mode == sys::wifi_mode_t_WIFI_MODE_AP {
        sys::wifi_interface_t_WIFI_IF_AP
    } else {
        sys::wifi_interface_t_WIFI_IF_STA
    }
}

fn start_netif_probe(iface: &str) -> Result<()> {
    ensure_low_level_wifi()?;
    let (netif, wifi_if) = match iface {
        "ap" | "softap" => (unsafe { WIFI_AP_NETIF }, sys::wifi_interface_t_WIFI_IF_AP),
        "sta" | "station" => (unsafe { WIFI_STA_NETIF }, sys::wifi_interface_t_WIFI_IF_STA),
        _ => bail!("unsupported netif_probe iface={iface}"),
    };
    if netif.is_null() {
        bail!("{iface} netif is not initialized");
    }
    unsafe {
        let driver = sys::esp_netif_get_io_driver(netif) as sys::wifi_netif_driver_t;
        if driver.is_null() {
            bail!("{iface} netif has no wifi io driver");
        }
        esp_ok(sys::esp_wifi_register_if_rxcb(
            driver,
            Some(wifi_netif_probe_cb),
            netif as *mut core::ffi::c_void,
        ))?;
    }
    WIFI_NETIF_PROBE_RUNNING.store(true, Ordering::Relaxed);
    let line = format!("event type=wifi.netif_probe iface={iface} wifi_if={wifi_if}");
    telemetry::emit_console(&line);
    telemetry::record_log(line);
    Ok(())
}

unsafe extern "C" fn wifi_netif_probe_cb(
    _esp_netif: *mut sys::esp_netif_t,
    buffer: *mut core::ffi::c_void,
    len: usize,
    eb: *mut core::ffi::c_void,
) -> sys::esp_err_t {
    WIFI_NETIF_RX_TOTAL.fetch_add(1, Ordering::Relaxed);
    if !buffer.is_null() && len > 0 {
        let copy_len = len.min(256);
        unsafe {
            core::ptr::copy_nonoverlapping(
                buffer as *const u8,
                core::ptr::addr_of_mut!(WIFI_NETIF_RX_LAST) as *mut u8,
                copy_len,
            );
        }
        WIFI_NETIF_RX_LAST_LEN.store(copy_len as u32, Ordering::Relaxed);
        let frame = unsafe { core::slice::from_raw_parts(buffer as *const u8, copy_len) };
        let line = format!(
            "event type=wifi.netif_rx len={} sample_len={} sample={}",
            len,
            copy_len,
            hex_bytes(frame)
        );
        telemetry::emit_console(&line);
        telemetry::record_log(line);
    }
    unsafe {
        let free_ptr = if !eb.is_null() { eb } else { buffer };
        if !free_ptr.is_null() {
            sys::esp_wifi_internal_free_rx_buffer(free_ptr);
        }
    }
    sys::ESP_OK
}

fn vendor_action_frame(destination: [u8; 6], payload: &[u8]) -> Result<Vec<u8>> {
    let mac = station_mac()?;
    let body_len = payload.len().min(1400);
    let mut frame = Vec::with_capacity(24 + DMESH_VENDOR_MARKER_LEN + body_len);
    frame.extend_from_slice(&[0xd0, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&mac);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&dmesh_vendor_marker(destination));
    frame.extend_from_slice(&payload[..body_len]);
    Ok(frame)
}

fn dmesh_data_frame(
    destination: [u8; 6],
    source: Option<[u8; 6]>,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mac = source.map(Ok).unwrap_or_else(station_mac)?;
    let body_len = payload.len().min(1400);
    let mut frame = Vec::with_capacity(24 + DMESH_VENDOR_MARKER_LEN + body_len);
    frame.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&mac);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&dmesh_vendor_marker(destination));
    frame.extend_from_slice(&payload[..body_len]);
    Ok(frame)
}

fn dmesh_sta_to_ap_data_frame(
    destination: [u8; 6],
    source: Option<[u8; 6]>,
    bssid: [u8; 6],
    payload: &[u8],
) -> Result<Vec<u8>> {
    let source = source.map(Ok).unwrap_or_else(station_mac)?;
    let body_len = payload.len().min(1400);
    let mut frame = Vec::with_capacity(24 + DMESH_VENDOR_MARKER_LEN + body_len);
    frame.extend_from_slice(&[0x08, 0x01, 0x00, 0x00]);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&dmesh_vendor_marker(destination));
    frame.extend_from_slice(&payload[..body_len]);
    Ok(frame)
}

fn dmesh_ap_to_sta_data_frame(
    destination: [u8; 6],
    bssid: [u8; 6],
    payload: &[u8],
) -> Result<Vec<u8>> {
    let body_len = payload.len().min(1400);
    let mut frame = Vec::with_capacity(24 + DMESH_VENDOR_MARKER_LEN + body_len);
    frame.extend_from_slice(&[0x08, 0x02, 0x00, 0x00]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&dmesh_vendor_marker(destination));
    frame.extend_from_slice(&payload[..body_len]);
    Ok(frame)
}

fn dmesh_vendor_marker(destination: [u8; 6]) -> [u8; DMESH_VENDOR_MARKER_LEN] {
    let mut marker = [0_u8; DMESH_VENDOR_MARKER_LEN];
    marker[..DMESH_ESPNOW_PREFIX.len()].copy_from_slice(&DMESH_ESPNOW_PREFIX);
    marker[4..8].copy_from_slice(&destination[2..6]);
    marker[8] = DMESH_ESPNOW_TYPE;
    marker
}

fn device_multicast_mac() -> Result<[u8; 6]> {
    let mut mac = station_mac()?;
    mac[0] |= 0x01;
    mac[0] &= !0x02;
    Ok(mac)
}

fn station_mac() -> Result<[u8; 6]> {
    let mut mac = [0_u8; 6];
    unsafe {
        esp_ok(sys::esp_read_mac(
            mac.as_mut_ptr(),
            sys::esp_mac_type_t_ESP_MAC_WIFI_STA,
        ))?;
    }
    Ok(mac)
}

fn ap_mac() -> Result<[u8; 6]> {
    let mut mac = [0_u8; 6];
    unsafe {
        esp_ok(sys::esp_read_mac(
            mac.as_mut_ptr(),
            sys::esp_mac_type_t_ESP_MAC_WIFI_SOFTAP,
        ))?;
    }
    Ok(mac)
}

unsafe extern "C" fn raw_wifi_cb(
    buf: *mut core::ffi::c_void,
    type_: sys::wifi_promiscuous_pkt_type_t,
) {
    if buf.is_null()
        || (type_ != sys::wifi_promiscuous_pkt_type_t_WIFI_PKT_MGMT
            && type_ != sys::wifi_promiscuous_pkt_type_t_WIFI_PKT_DATA)
    {
        RAW_RX_DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let pkt = unsafe { &*(buf as *const sys::wifi_promiscuous_pkt_t) };
    let len = pkt.rx_ctrl.sig_len().min(1500) as usize;
    let payload = pkt.payload.as_ptr();
    if payload.is_null() || len < 24 {
        RAW_RX_DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let frame = unsafe { core::slice::from_raw_parts(payload, len) };
    super::nan::observe_promiscuous_frame(frame, pkt.rx_ctrl.rssi() as i32);
    observe_promiscuous_frame(frame, pkt.rx_ctrl.rssi() as i32);
}

pub fn observe_promiscuous_frame(frame: &[u8], rssi: i32) {
    if !RAW_MONITOR_RUNNING.load(Ordering::Relaxed) {
        return;
    }
    RAW_RX_TOTAL.fetch_add(1, Ordering::Relaxed);
    if !matches_raw_filter(frame) {
        return;
    }
    let dmesh_payload = dmesh_vendor_payload(frame);
    if matches!(
        RAW_FILTER_MODE.load(Ordering::Relaxed),
        RAW_FILTER_ALL
            | RAW_FILTER_ACTION
            | RAW_FILTER_DATA
            | RAW_FILTER_DMESH
            | RAW_FILTER_DMESH_DATA
    ) && dmesh_payload.is_none()
    {
        RAW_RX_DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    RAW_RX_MATCHED.fetch_add(1, Ordering::Relaxed);
    telemetry::record_packet(
        "wifi",
        Direction::Rx,
        frame,
        format!("raw=true subtype={} rssi={}", frame_subtype(frame), rssi),
    );
    RAW_RX_LAST_RSSI.store(rssi, Ordering::Relaxed);
    let copy_len = frame.len().min(256);
    unsafe {
        core::ptr::copy_nonoverlapping(
            frame.as_ptr(),
            core::ptr::addr_of_mut!(RAW_RX_LAST) as *mut u8,
            copy_len,
        );
    }
    RAW_RX_LAST_LEN.store(copy_len as u32, Ordering::Relaxed);
    if let Some(payload) = dmesh_payload {
        telemetry::record_companion_packet("wifi", payload);
        super::mode::observe_ping("wifi_raw", payload);
        enqueue_raw_command(frame, payload, rssi);
        let dst = frame_address(frame, FRAME_ADDR1)
            .map(format_mac)
            .unwrap_or_else(|| "none".to_string());
        let src = frame_address(frame, FRAME_ADDR2)
            .map(format_mac)
            .unwrap_or_else(|| "none".to_string());
        let destination = raw_destination_name(frame);
        let payload_b64 = base64_standard(payload);
        let line = format!(
            "event type=wifi.raw_frame source=dmesh_vendor destination={} src={} dst={} len={} rssi={} payload_b64={}",
            destination,
            src,
            dst,
            payload.len(),
            rssi,
            payload_b64
        );
        telemetry::emit_console(&line);
        telemetry::record_log(line);
    }
}

fn matches_raw_filter(frame: &[u8]) -> bool {
    if RAW_FILTER_BSSID_ENABLED.load(Ordering::Relaxed) && !frame_has_bssid(frame) {
        return false;
    }
    match RAW_FILTER_MODE.load(Ordering::Relaxed) {
        RAW_FILTER_ALL => true,
        RAW_FILTER_MGMT => frame_type(frame) == 0,
        RAW_FILTER_ACTION => frame_subtype(frame) == 13,
        RAW_FILTER_BEACON => frame_subtype(frame) == 8,
        RAW_FILTER_PROBE_REQ => frame_subtype(frame) == 4,
        RAW_FILTER_PROBE_RESP => frame_subtype(frame) == 5,
        RAW_FILTER_DATA => frame_type(frame) == 2,
        RAW_FILTER_DMESH => frame_type(frame) == 0 && frame_subtype(frame) == 13,
        RAW_FILTER_DMESH_DATA => {
            frame_type(frame) == 2 || (frame_type(frame) == 0 && frame_subtype(frame) == 13)
        }
        _ => true,
    }
}

fn frame_type(frame: &[u8]) -> u8 {
    (frame.first().copied().unwrap_or(0) & 0x0c) >> 2
}

fn frame_subtype(frame: &[u8]) -> u8 {
    frame.first().copied().unwrap_or(0) >> 4
}

fn frame_has_bssid(frame: &[u8]) -> bool {
    if frame.len() < FRAME_ADDR3 + 6 {
        return false;
    }
    for base in [FRAME_ADDR1, FRAME_ADDR2, FRAME_ADDR3] {
        let mut matched = true;
        for idx in 0..6 {
            if frame[base + idx] != RAW_FILTER_BSSID[idx].load(Ordering::Relaxed) {
                matched = false;
                break;
            }
        }
        if matched {
            return true;
        }
    }
    false
}

fn dmesh_vendor_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() <= 24 + DMESH_VENDOR_MARKER_LEN {
        return None;
    }
    if frame_type(frame) == 2 {
        if !frame_matches_dmesh_data_destination(frame) {
            return None;
        }
        let header = dmesh_vendor_header(&frame[24..])?;
        if !mesh_dst4_allowed(header.mesh_dst4) {
            return None;
        }
        let payload_start = 24 + header.len;
        let payload_end = frame.len().saturating_sub(4).max(payload_start);
        return Some(&frame[payload_start..payload_end]);
    } else if frame_subtype(frame) != 13 {
        return None;
    }
    let header = dmesh_vendor_header(&frame[24..])?;
    if !mesh_dst4_allowed(header.mesh_dst4) {
        return None;
    }
    let payload_start = 24 + header.len;
    Some(&frame[payload_start..])
}

#[derive(Clone, Copy)]
struct DmeshVendorHeader {
    len: usize,
    mesh_dst4: [u8; 4],
}

fn dmesh_vendor_header(body: &[u8]) -> Option<DmeshVendorHeader> {
    if body.len() >= DMESH_VENDOR_MARKER_LEN
        && body[..DMESH_ESPNOW_PREFIX.len()] == DMESH_ESPNOW_PREFIX
        && body[8] == DMESH_ESPNOW_TYPE
    {
        return Some(DmeshVendorHeader {
            len: DMESH_VENDOR_MARKER_LEN,
            mesh_dst4: [body[4], body[5], body[6], body[7]],
        });
    }
    None
}

fn mesh_dst4_allowed(key: [u8; 4]) -> bool {
    if key == DMESH_FIXED_MESH_DST4 || key == mesh_dst4(LMESH_IPV6_DISCOVERY_MULTICAST) {
        return true;
    }
    if station_mac()
        .map(|mac| key == mesh_dst4(mac))
        .unwrap_or(false)
    {
        return true;
    }
    ap_mac().map(|mac| key == mesh_dst4(mac)).unwrap_or(false)
}

fn mesh_dst4(destination: [u8; 6]) -> [u8; 4] {
    [
        destination[2],
        destination[3],
        destination[4],
        destination[5],
    ]
}

fn frame_matches_dmesh_data_destination(frame: &[u8]) -> bool {
    let Some(destination) = frame_address(frame, FRAME_ADDR1) else {
        return false;
    };
    if destination == LMESH_IPV6_DISCOVERY_MULTICAST {
        return true;
    }
    if station_mac().map(|mac| destination == mac).unwrap_or(false) {
        return true;
    }
    if ap_mac().map(|mac| destination == mac).unwrap_or(false) {
        return true;
    }
    device_multicast_mac()
        .map(|mac| destination == mac)
        .unwrap_or(false)
}

fn raw_destination_name(frame: &[u8]) -> &'static str {
    let Some(destination) = frame_address(frame, FRAME_ADDR1) else {
        return "unknown";
    };
    if destination == LMESH_IPV6_DISCOVERY_MULTICAST {
        return "ff02_5227";
    }
    if station_mac().map(|mac| destination == mac).unwrap_or(false) {
        return "device_unicast";
    }
    if ap_mac().map(|mac| destination == mac).unwrap_or(false) {
        return "ap_unicast";
    }
    if device_multicast_mac()
        .map(|mac| destination == mac)
        .unwrap_or(false)
    {
        return "device_multicast";
    }
    "other"
}

fn base64_standard(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut chunks = data.chunks_exact(3);
    for chunk in &mut chunks {
        let word = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | chunk[2] as u32;
        out.push(TABLE[((word >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((word >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((word >> 6) & 0x3f) as usize] as char);
        out.push(TABLE[(word & 0x3f) as usize] as char);
    }
    let rem = chunks.remainder();
    if rem.len() == 1 {
        let word = (rem[0] as u32) << 16;
        out.push(TABLE[((word >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((word >> 12) & 0x3f) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem.len() == 2 {
        let word = ((rem[0] as u32) << 16) | ((rem[1] as u32) << 8);
        out.push(TABLE[((word >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((word >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((word >> 6) & 0x3f) as usize] as char);
        out.push('=');
    }
    out
}

fn enqueue_raw_command(frame: &[u8], payload: &[u8], rssi: i32) {
    if payload.len() > RAW_COMMAND_MAX_LEN {
        RAW_CMD_DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let Ok(text) = core::str::from_utf8(payload) else {
        return;
    };
    let text = text.trim();
    if text.is_empty() {
        return;
    }
    let Some(source) = frame_address(frame, FRAME_ADDR2) else {
        RAW_CMD_DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    };
    set_last_command_peer(source);
    let Ok(mut queue) = raw_command_queue().lock() else {
        RAW_CMD_DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    };
    if queue.len() >= RAW_COMMAND_QUEUE_MAX {
        queue.pop_front();
        RAW_CMD_DROPPED.fetch_add(1, Ordering::Relaxed);
    }
    queue.push_back(RawWifiCommand {
        source,
        text: text.to_string(),
        rssi,
    });
    RAW_CMD_RX_TOTAL.fetch_add(1, Ordering::Relaxed);
    super::wake::notify();
}

fn raw_command_queue() -> &'static Mutex<VecDeque<RawWifiCommand>> {
    RAW_COMMAND_QUEUE.get_or_init(|| Mutex::new(VecDeque::with_capacity(RAW_COMMAND_QUEUE_MAX)))
}

fn frame_address(frame: &[u8], offset: usize) -> Option<[u8; 6]> {
    frame.get(offset..offset + 6)?.try_into().ok()
}

fn set_last_command_peer(peer: [u8; 6]) {
    for (idx, byte) in peer.iter().enumerate() {
        RAW_LAST_COMMAND_PEER[idx].store(*byte, Ordering::Relaxed);
    }
    RAW_LAST_COMMAND_PEER_VALID.store(true, Ordering::Release);
}

fn last_command_peer() -> Option<[u8; 6]> {
    if !RAW_LAST_COMMAND_PEER_VALID.load(Ordering::Acquire) {
        return None;
    }
    let mut peer = [0_u8; 6];
    for (idx, byte) in peer.iter_mut().enumerate() {
        *byte = RAW_LAST_COMMAND_PEER[idx].load(Ordering::Relaxed);
    }
    Some(peer)
}

fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn raw_stats() -> String {
    let last_len = RAW_RX_LAST_LEN.load(Ordering::Relaxed) as usize;
    let last = unsafe { &RAW_RX_LAST[..last_len.min(256)] };
    let peer = last_command_peer()
        .map(format_mac)
        .unwrap_or_else(|| "none".to_string());
    format!(
        "raw_monitor={} filter={} bssid_filter={} rx={} matched={} dropped={} tx={} cmd_rx={} cmd_dropped={} last_peer={} last_len={} last_rssi={} last={}",
        RAW_MONITOR_RUNNING.load(Ordering::Relaxed),
        raw_filter_name(),
        RAW_FILTER_BSSID_ENABLED.load(Ordering::Relaxed),
        RAW_RX_TOTAL.load(Ordering::Relaxed),
        RAW_RX_MATCHED.load(Ordering::Relaxed),
        RAW_RX_DROPPED.load(Ordering::Relaxed),
        RAW_TX_TOTAL.load(Ordering::Relaxed),
        RAW_CMD_RX_TOTAL.load(Ordering::Relaxed),
        RAW_CMD_DROPPED.load(Ordering::Relaxed),
        peer,
        last_len,
        RAW_RX_LAST_RSSI.load(Ordering::Relaxed),
        hex_bytes(last)
    )
}

fn netif_probe_stats() -> String {
    let last_len = WIFI_NETIF_RX_LAST_LEN.load(Ordering::Relaxed) as usize;
    let last = unsafe { &WIFI_NETIF_RX_LAST[..last_len.min(256)] };
    format!(
        "netif_probe={} netif_rx={} netif_last_len={} netif_last={}",
        WIFI_NETIF_PROBE_RUNNING.load(Ordering::Relaxed),
        WIFI_NETIF_RX_TOTAL.load(Ordering::Relaxed),
        last_len,
        hex_bytes(last)
    )
}

fn parse_raw_filter(value: &str) -> Result<u32> {
    match value {
        "all" => Ok(RAW_FILTER_ALL),
        "mgmt" | "management" => Ok(RAW_FILTER_MGMT),
        "action" => Ok(RAW_FILTER_ACTION),
        "data" => Ok(RAW_FILTER_DATA),
        "dmesh" | "mesh" => Ok(RAW_FILTER_DMESH),
        "dmesh_data" | "mesh_data" | "dmesh+data" | "mesh+data" => Ok(RAW_FILTER_DMESH_DATA),
        "beacon" => Ok(RAW_FILTER_BEACON),
        "probe_req" | "probe-request" => Ok(RAW_FILTER_PROBE_REQ),
        "probe_resp" | "probe-response" => Ok(RAW_FILTER_PROBE_RESP),
        _ => bail!("unsupported raw wifi filter {value}"),
    }
}

fn raw_filter_name() -> &'static str {
    match RAW_FILTER_MODE.load(Ordering::Relaxed) {
        RAW_FILTER_ALL => "all",
        RAW_FILTER_MGMT => "mgmt",
        RAW_FILTER_ACTION => "action",
        RAW_FILTER_DATA => "data",
        RAW_FILTER_DMESH => "dmesh",
        RAW_FILTER_DMESH_DATA => "dmesh_data",
        RAW_FILTER_BEACON => "beacon",
        RAW_FILTER_PROBE_REQ => "probe_req",
        RAW_FILTER_PROBE_RESP => "probe_resp",
        _ => "unknown",
    }
}

fn promiscuous_filter_mask(filter_mode: u32) -> u32 {
    match filter_mode {
        RAW_FILTER_ALL | RAW_FILTER_DMESH_DATA => {
            sys::WIFI_PROMIS_FILTER_MASK_MGMT | sys::WIFI_PROMIS_FILTER_MASK_DATA
        }
        RAW_FILTER_DMESH => sys::WIFI_PROMIS_FILTER_MASK_MGMT,
        RAW_FILTER_DATA => sys::WIFI_PROMIS_FILTER_MASK_DATA,
        _ => sys::WIFI_PROMIS_FILTER_MASK_MGMT,
    }
}

fn parse_mac(value: &str) -> Result<[u8; 6]> {
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != 6 {
        bail!("MAC must have 6 colon-separated bytes");
    }
    let mut mac = [0_u8; 6];
    for (idx, part) in parts.iter().enumerate() {
        mac[idx] = u8::from_str_radix(part, 16).map_err(|err| anyhow!("invalid MAC: {err}"))?;
    }
    Ok(mac)
}

fn default_direct_ssid() -> Result<String> {
    let mac = station_mac()?;
    Ok(format!("Direct-{:02x}-Dmesh-Local", mac[5]))
}

fn copy_cstr_bytes<const N: usize>(dst: &mut [u8; N], src: &[u8]) {
    dst.fill(0);
    let len = src.len().min(N);
    dst[..len].copy_from_slice(&src[..len]);
}

fn ssid_from_bytes(bytes: &[u8]) -> String {
    let len = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

fn auth_name(auth: sys::wifi_auth_mode_t) -> &'static str {
    match auth {
        x if x == sys::wifi_auth_mode_t_WIFI_AUTH_OPEN => "open",
        x if x == sys::wifi_auth_mode_t_WIFI_AUTH_WPA2_PSK => "wpa2",
        x if x == sys::wifi_auth_mode_t_WIFI_AUTH_WPA_WPA2_PSK => "wpa_wpa2",
        x if x == sys::wifi_auth_mode_t_WIFI_AUTH_WPA3_PSK => "wpa3",
        x if x == sys::wifi_auth_mode_t_WIFI_AUTH_WPA2_WPA3_PSK => "wpa2_wpa3",
        _ => "other",
    }
}

fn wifi_net_status() -> String {
    let sta = unsafe { WIFI_STA_NETIF };
    let ap = unsafe { WIFI_AP_NETIF };
    format!(
        "sta_ip={} ap_ip={} ap_stations={} sta_ll={} ap_ll={}",
        ip4_info(sta).unwrap_or_else(|| "none".to_string()),
        ip4_info(ap).unwrap_or_else(|| "none".to_string()),
        ap_station_count(),
        ip6_linklocal(sta).unwrap_or_else(|| "none".to_string()),
        ip6_linklocal(ap).unwrap_or_else(|| "none".to_string())
    )
}

fn ap_station_count() -> i32 {
    let mut list = sys::wifi_sta_list_t::default();
    let ret = unsafe { sys::esp_wifi_ap_get_sta_list(&mut list) };
    if ret == sys::ESP_OK {
        list.num
    } else {
        -1
    }
}

fn ip4_info(netif: *mut sys::esp_netif_t) -> Option<String> {
    if netif.is_null() {
        return None;
    }
    let mut info = sys::esp_netif_ip_info_t::default();
    let ret = unsafe { sys::esp_netif_get_ip_info(netif, &mut info) };
    if ret != sys::ESP_OK || info.ip.addr == 0 {
        return None;
    }
    Some(format_ip4(info.ip.addr))
}

fn format_ip4(addr: u32) -> String {
    let bytes = addr.to_le_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

fn ip6_linklocal(netif: *mut sys::esp_netif_t) -> Option<String> {
    if netif.is_null() {
        return None;
    }
    let mut ip = sys::esp_ip6_addr_t::default();
    let ret = unsafe { sys::esp_netif_get_ip6_linklocal(netif, &mut ip) };
    if ret != sys::ESP_OK {
        return None;
    }
    Some(format_ip6(ip))
}

fn format_ip6(ip: sys::esp_ip6_addr_t) -> String {
    let mut words = [0_u16; 8];
    for (idx, part) in ip.addr.iter().enumerate() {
        let bytes = part.to_be_bytes();
        words[idx * 2] = u16::from_be_bytes([bytes[0], bytes[1]]);
        words[idx * 2 + 1] = u16::from_be_bytes([bytes[2], bytes[3]]);
    }
    format!(
        "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}%{}",
        words[0], words[1], words[2], words[3], words[4], words[5], words[6], words[7], ip.zone
    )
}

fn start_sntp(server: &str) -> Result<()> {
    let server = if server == "true" || server.is_empty() {
        "pool.ntp.org"
    } else {
        server
    };
    let server = CString::new(server)?;
    unsafe {
        if sys::esp_sntp_enabled() {
            sys::esp_sntp_stop();
        }
        sys::esp_sntp_setoperatingmode(sys::esp_sntp_operatingmode_t_ESP_SNTP_OPMODE_POLL);
        sys::esp_sntp_setservername(0, server.as_ptr());
        sys::esp_sntp_init();
    }
    Ok(())
}

fn validate_wifi_string(name: &str, value: &str, max: usize) -> Result<()> {
    if value.len() > max {
        bail!("{name} must be at most {max} bytes");
    }
    Ok(())
}

fn task_delay(timeout: Duration) {
    unsafe {
        sys::vTaskDelay(duration_to_ticks(timeout).max(1));
    }
}

fn duration_to_ticks(timeout: Duration) -> sys::TickType_t {
    let hz = sys::configTICK_RATE_HZ as u128;
    let ticks = timeout.as_millis().saturating_mul(hz).div_ceil(1000);
    ticks.min(sys::TickType_t::MAX as u128) as sys::TickType_t
}

fn esp_ok(ret: sys::esp_err_t) -> Result<()> {
    if ret == sys::ESP_OK {
        Ok(())
    } else {
        bail!("esp_err=0x{ret:x}")
    }
}

fn esp_ok_allow_invalid_state(ret: sys::esp_err_t) -> Result<()> {
    if ret == sys::ESP_OK || ret == sys::ESP_ERR_INVALID_STATE {
        Ok(())
    } else {
        bail!("esp_err=0x{ret:x}")
    }
}
