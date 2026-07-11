use std::convert::TryInto;
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU8, Ordering};

use anyhow::{anyhow, bail, Context, Result};
use embedded_svc::wifi::{
    AccessPointConfiguration, AuthMethod, ClientConfiguration, Configuration,
};
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::wifi::{BlockingWifi, EspWifi};
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
static RAW_WIFI_INIT: AtomicBool = AtomicBool::new(false);
static mut RAW_RX_LAST: [u8; 256] = [0; 256];

pub fn register_commands(registry: &mut CommandRegistry) {
    registry.register(WifiCommand::default());
}

pub fn forward_management_packet(packet: &[u8]) -> Result<()> {
    ensure_raw_wifi_started(6)?;
    let frame = vendor_action_frame(packet)?;
    raw_tx_frame(&frame, true)?;
    RAW_TX_TOTAL.fetch_add(1, Ordering::Relaxed);
    telemetry::record_packet("wifi", Direction::Tx, packet, "source=lora_forward");
    Ok(())
}

pub fn start_raw_monitor_mode(channel: u8, filter: &str) -> Result<()> {
    RAW_FILTER_MODE.store(parse_raw_filter(filter)?, Ordering::Relaxed);
    ensure_raw_wifi_started(channel.clamp(1, 13))?;
    unsafe {
        let mut promisc_filter = sys::wifi_promiscuous_filter_t {
            filter_mask: sys::WIFI_PROMIS_FILTER_MASK_MGMT,
        };
        esp_ok(sys::esp_wifi_set_promiscuous(false))?;
        esp_ok(sys::esp_wifi_set_promiscuous_rx_cb(Some(raw_wifi_cb)))?;
        esp_ok(sys::esp_wifi_set_promiscuous_filter(&mut promisc_filter))?;
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
    Stopped,
    Sta,
    Ap,
}

impl Default for WifiMode {
    fn default() -> Self {
        Self::Stopped
    }
}

type WifiDriver = BlockingWifi<EspWifi<'static>>;

#[derive(Default)]
struct WifiCommand {
    mode: WifiMode,
    ssid: Option<String>,
    psk: Option<String>,
    timeout_ms: u32,
    wifi: Option<WifiDriver>,
}

impl CommandHandler for WifiCommand {
    fn name(&self) -> &'static str {
        "wifi"
    }

    fn help(&self) -> &'static str {
        "wifi ssid=SSID psk=PSK timeout=MS | wifi ap=true ssid=SSID psk=PSK channel=6 | wifi scan=true | wifi raw_monitor=true filter=mgmt|action|beacon|probe_req|probe_resp bssid=aa:bb:... | wifi raw=hex:... | wifi raw_stats=true"
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
            ensure_raw_wifi_started(channel)?;
            let bytes = parse_bytes(raw)?;
            raw_tx(&bytes, request)?;
            return Ok(CommandResponse::ok(format!(
                "wifi raw sent bytes={} {}",
                bytes.len(),
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
                "wifi mode={:?} ssid={} timeout_ms={}",
                self.mode,
                self.ssid.as_deref().unwrap_or(""),
                self.timeout_ms
            )))
        }
    }
}

impl WifiCommand {
    fn driver(&mut self) -> Result<&mut WifiDriver> {
        if self.wifi.is_none() {
            let peripherals = Peripherals::take()?;
            let sys_loop = EspSystemEventLoop::take()?;
            let wifi = EspWifi::new(peripherals.modem, sys_loop.clone(), None)?;
            self.wifi = Some(BlockingWifi::wrap(wifi, sys_loop)?);
        }
        Ok(self.wifi.as_mut().expect("wifi initialized"))
    }

    fn start_sta(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let ssid = request.arg("ssid").context("wifi sta requires ssid=...")?;
        let psk = request.arg("psk").unwrap_or("");
        validate_wifi_string("ssid", ssid, 32)?;
        validate_wifi_string("psk", psk, 64)?;
        self.ssid = Some(ssid.to_string());
        self.psk = Some(psk.to_string());

        let timeout_ms = self.timeout_ms;
        let wifi = self.driver()?;
        wifi.set_configuration(&Configuration::Client(ClientConfiguration {
            ssid: ssid.try_into().map_err(|_| anyhow!("ssid too long"))?,
            password: psk.try_into().map_err(|_| anyhow!("psk too long"))?,
            auth_method: if psk.is_empty() {
                AuthMethod::None
            } else {
                AuthMethod::WPA2Personal
            },
            ..Default::default()
        }))?;
        wifi.start()?;
        wifi.connect()?;
        if timeout_ms > 0 {
            let _ = wifi.wait_netif_up();
        }
        self.mode = WifiMode::Sta;
        Ok(CommandResponse::ok(format!(
            "wifi mode=Sta ssid={} timeout_ms={}",
            self.ssid.as_deref().unwrap_or(""),
            timeout_ms
        )))
    }

    fn start_ap(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let ssid = request.arg("ssid").unwrap_or("dmesh");
        let psk = request.arg("psk").unwrap_or("");
        let channel = request
            .arg("channel")
            .map(parse_i32)
            .transpose()?
            .unwrap_or(6)
            .clamp(1, 13) as u8;
        validate_wifi_string("ssid", ssid, 32)?;
        validate_wifi_string("psk", psk, 64)?;
        if !psk.is_empty() && psk.len() < 8 {
            bail!("AP psk must be empty or at least 8 bytes");
        }
        self.ssid = Some(ssid.to_string());
        self.psk = Some(psk.to_string());

        let wifi = self.driver()?;
        wifi.set_configuration(&Configuration::AccessPoint(AccessPointConfiguration {
            ssid: ssid.try_into().map_err(|_| anyhow!("ssid too long"))?,
            password: psk.try_into().map_err(|_| anyhow!("psk too long"))?,
            channel,
            auth_method: if psk.is_empty() {
                AuthMethod::None
            } else {
                AuthMethod::WPA2Personal
            },
            ..Default::default()
        }))?;
        wifi.start()?;
        self.mode = WifiMode::Ap;
        Ok(CommandResponse::ok(format!(
            "wifi mode=Ap ssid={} channel={}",
            self.ssid.as_deref().unwrap_or(""),
            channel
        )))
    }

    fn scan(&mut self) -> Result<CommandResponse> {
        let wifi = self.driver()?;
        wifi.set_configuration(&Configuration::Client(ClientConfiguration::default()))?;
        wifi.start()?;
        let aps = wifi.scan()?;
        let summary = aps
            .iter()
            .take(16)
            .map(|ap| format!("{}:{}:ch{}", ap.ssid, ap.signal_strength, ap.channel))
            .collect::<Vec<_>>()
            .join(",");
        Ok(CommandResponse::ok(format!(
            "wifi scan count={} {}",
            aps.len(),
            summary
        )))
    }

    fn start_raw_monitor(&mut self, request: &CommandRequest) -> Result<()> {
        let channel = request
            .arg("channel")
            .map(parse_i32)
            .transpose()?
            .unwrap_or(6)
            .clamp(1, 13) as u8;
        start_raw_monitor_mode(channel, raw_filter_name())
    }

    fn configure_raw_filter(&mut self, request: &CommandRequest) -> Result<()> {
        if let Some(filter) = request.arg("filter").or_else(|| request.arg("raw_filter")) {
            RAW_FILTER_MODE.store(parse_raw_filter(filter)?, Ordering::Relaxed);
        }
        if let Some(bssid) = request.arg("bssid").or_else(|| request.arg("raw_bssid")) {
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
        if let Some(wifi) = self.wifi.as_mut() {
            let _ = wifi.disconnect();
            let _ = wifi.stop();
        }
        self.mode = WifiMode::Stopped;
        Ok(())
    }
}

pub fn ensure_raw_wifi_started(channel: u8) -> Result<()> {
    unsafe {
        esp_ok_allow_invalid_state(sys::esp_netif_init())?;
        esp_ok_allow_invalid_state(sys::esp_event_loop_create_default())?;
        if !RAW_WIFI_INIT.swap(true, Ordering::SeqCst) {
            let mut cfg = wifi_init_config_default();
            let ret = sys::esp_wifi_init(&mut cfg);
            if ret != sys::ESP_OK && ret != sys::ESP_ERR_INVALID_STATE {
                RAW_WIFI_INIT.store(false, Ordering::SeqCst);
                esp_ok(ret)?;
            }
            let _ = sys::esp_wifi_set_storage(sys::wifi_storage_t_WIFI_STORAGE_RAM);
        }
        esp_ok_allow_invalid_state(sys::esp_wifi_set_mode(sys::wifi_mode_t_WIFI_MODE_STA))?;
        esp_ok_allow_invalid_state(sys::esp_wifi_start())?;
        esp_ok(sys::esp_wifi_set_channel(
            channel.max(1),
            sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE,
        ))?;
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

fn stop_raw_monitor() -> Result<()> {
    unsafe {
        let _ = sys::esp_wifi_set_promiscuous(false);
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
    unsafe {
        esp_ok(sys::esp_wifi_80211_tx(
            sys::wifi_interface_t_WIFI_IF_STA,
            bytes.as_ptr() as *const _,
            bytes.len() as i32,
            en_sys_seq,
        ))
    }
}

fn vendor_action_frame(payload: &[u8]) -> Result<Vec<u8>> {
    let mac = station_mac()?;
    let body_len = payload.len().min(1400);
    let mut frame = Vec::with_capacity(24 + 5 + body_len);
    frame.extend_from_slice(&[0xd0, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&mac);
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&[0x7f, 0x50, 0x6f, 0x9a, 0x42]);
    frame.extend_from_slice(&payload[..body_len]);
    Ok(frame)
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

unsafe extern "C" fn raw_wifi_cb(
    buf: *mut core::ffi::c_void,
    type_: sys::wifi_promiscuous_pkt_type_t,
) {
    if type_ != sys::wifi_promiscuous_pkt_type_t_WIFI_PKT_MGMT || buf.is_null() {
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
    if let Some(payload) = dmesh_vendor_payload(frame) {
        let line = format!(
            "event type=wifi.raw_rx source=dmesh_vendor len={} rssi={}",
            payload.len(),
            rssi
        );
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
    const VENDOR_ACTION: [u8; 5] = [0x7f, 0x50, 0x6f, 0x9a, 0x42];
    if frame.len() <= 29 || frame_subtype(frame) != 13 {
        return None;
    }
    if frame[24..29] == VENDOR_ACTION {
        Some(&frame[29..])
    } else {
        None
    }
}

fn raw_stats() -> String {
    let last_len = RAW_RX_LAST_LEN.load(Ordering::Relaxed) as usize;
    let last = unsafe { &RAW_RX_LAST[..last_len.min(256)] };
    format!(
        "raw_monitor={} filter={} bssid_filter={} rx={} matched={} dropped={} tx={} last_len={} last_rssi={} last={}",
        RAW_MONITOR_RUNNING.load(Ordering::Relaxed),
        raw_filter_name(),
        RAW_FILTER_BSSID_ENABLED.load(Ordering::Relaxed),
        RAW_RX_TOTAL.load(Ordering::Relaxed),
        RAW_RX_MATCHED.load(Ordering::Relaxed),
        RAW_RX_DROPPED.load(Ordering::Relaxed),
        RAW_TX_TOTAL.load(Ordering::Relaxed),
        last_len,
        RAW_RX_LAST_RSSI.load(Ordering::Relaxed),
        hex_bytes(last)
    )
}

fn parse_raw_filter(value: &str) -> Result<u32> {
    match value {
        "all" => Ok(RAW_FILTER_ALL),
        "mgmt" | "management" => Ok(RAW_FILTER_MGMT),
        "action" => Ok(RAW_FILTER_ACTION),
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
        RAW_FILTER_BEACON => "beacon",
        RAW_FILTER_PROBE_REQ => "probe_req",
        RAW_FILTER_PROBE_RESP => "probe_resp",
        _ => "unknown",
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
