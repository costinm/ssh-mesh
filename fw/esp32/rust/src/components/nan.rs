use std::convert::TryInto;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

use anyhow::{anyhow, bail, Result};
use embedded_svc::wifi::{AuthMethod, ClientConfiguration, Configuration};
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::wifi::{BlockingWifi, EspWifi};
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::l3dmesh::{Frame, Transport};
use super::settings::{parse_bool, parse_i32};

const NAN_ID: u8 = 1;
const FRAME_DST: usize = 4;
const FRAME_SRC: usize = 10;
const FRAME_BSSID: usize = 16;
const FRAME_DATA: usize = 24;
const NAN_ACTION_START: usize = 30;
const SVC_ID: [u8; 6] = [0x75, 0x94, 0x31, 0x93, 0xea, 0xc9];
const NAN_BSSID: [u8; 6] = [0x50, 0x6f, 0x9a, 0x01, 0x05, 0x01];

static NAN_RUNNING: AtomicBool = AtomicBool::new(false);
static NAN_RX_MGMT: AtomicU32 = AtomicU32::new(0);
static NAN_RX_ACTION: AtomicU32 = AtomicU32::new(0);
static NAN_RX_BEACON: AtomicU32 = AtomicU32::new(0);
static NAN_RX_SDF: AtomicU32 = AtomicU32::new(0);
static NAN_RX_OTHER: AtomicU32 = AtomicU32::new(0);
static NAN_RX_BYTES: AtomicU32 = AtomicU32::new(0);
static NAN_RX_MATCHED: AtomicU32 = AtomicU32::new(0);
static NAN_FILTER_MODE: AtomicU32 = AtomicU32::new(FILTER_NAN);
static NAN_FILTER_BSSID_ENABLED: AtomicBool = AtomicBool::new(false);
static NAN_FILTER_BSSID: [AtomicU8; 6] = [
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
];

const FILTER_ALL_MGMT: u32 = 0;
const FILTER_NAN: u32 = 1;
const FILTER_ACTION: u32 = 2;
const FILTER_BEACON: u32 = 3;
const FILTER_SDF: u32 = 4;

static NAN_HEADER: [u8; 30] = [
    0xd0, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x50, 0x6f, 0x9a, 0x01, 0x05, 0x01, 0x00, 0x00, 0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13,
];

static NAN_DEVICE_CAPABILITIES: [u8; 12] = [
    0x0f, 0x09, 0x00, 0x00, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x14, 0x00,
];

static NAN_AVAILABILITY: [u8; 30] = [
    0x12, 0x1b, 0x00, 0x0b, 0x01, 0x00, 0x16, 0x00, 0x1a, 0x10, 0x18, 0x00, 0x04, 0xfe, 0xff, 0xff,
    0x3f, 0x31, 0x51, 0xff, 0x07, 0x00, 0x80, 0x20, 0x00, 0x0f, 0x80, 0x01, 0x00, 0x0f,
];

static NAN_SERVICE_EXTENSION: [u8; 7] = [0x0e, 0x04, 0x00, NAN_ID, 0x00, 0x02, 0x02];

static NAN_SERVICE_DESCRIPTOR: [u8; 29] = [
    0x03, 0x1a, 0x00, 0x75, 0x94, 0x31, 0x93, 0xea, 0xc9, NAN_ID, 0x00, 0x10, 0x10, 0x31, 0x32,
    0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x30, 0x30, 0x30, 0x30, 0x57, 0x78, 0x68, 0x37,
];

pub fn register_commands(registry: &mut CommandRegistry) {
    registry.register(NanCommand::default());
}

pub fn transport() -> NanTransport {
    NanTransport::default()
}

struct NanCommand {
    dump: bool,
    channel: u8,
    wifi: Option<BlockingWifi<EspWifi<'static>>>,
}

impl Default for NanCommand {
    fn default() -> Self {
        Self {
            dump: false,
            channel: 6,
            wifi: None,
        }
    }
}

impl CommandHandler for NanCommand {
    fn name(&self) -> &'static str {
        "nan"
    }

    fn help(&self) -> &'static str {
        "nan start=true|stop=true|stats=true filter=nan|mgmt|action|beacon|sdf bssid=50:6f:9a:01:05:01 | publish=true|send=TEXT dst=...|raw=hex:..."
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if let Some(dump) = request.arg("dump") {
            self.dump = parse_bool(dump)?;
        }
        if let Some(channel) = request.arg("channel").map(parse_i32).transpose()? {
            self.channel = channel.clamp(1, 13) as u8;
        }
        if let Some(filter) = request.arg("filter") {
            NAN_FILTER_MODE.store(parse_filter_mode(filter)?, Ordering::Relaxed);
        }
        if let Some(bssid) = request.arg("bssid") {
            if bssid == "none" || bssid == "false" {
                NAN_FILTER_BSSID_ENABLED.store(false, Ordering::Relaxed);
            } else {
                let bssid = parse_mac(bssid)?;
                for (idx, byte) in bssid.iter().enumerate() {
                    NAN_FILTER_BSSID[idx].store(*byte, Ordering::Relaxed);
                }
                NAN_FILTER_BSSID_ENABLED.store(true, Ordering::Relaxed);
            }
        }
        if request.arg("stop").is_some() {
            stop_nan()?;
            return Ok(CommandResponse::ok("nan stopped"));
        }
        if request.arg("stats").is_some() {
            return Ok(CommandResponse::ok(stats()));
        }
        if request.arg("start").is_some()
            || request
                .arg("enable")
                .map(parse_bool)
                .transpose()?
                .unwrap_or(false)
        {
            self.start_nan()?;
            return Ok(CommandResponse::ok(format!(
                "nan started channel={} dump={} filter={}",
                self.channel.max(1),
                self.dump,
                filter_name()
            )));
        }
        if let Some(raw) = request.arg("raw") {
            let bytes = parse_bytes(raw)?;
            self.ensure_started()?;
            raw_tx(&bytes, true)?;
            return Ok(CommandResponse::ok(format!(
                "nan raw sent bytes={}",
                bytes.len()
            )));
        }
        if request.arg("publish").is_some() {
            self.ensure_started()?;
            let frame = nan_publish_frame()?;
            raw_tx(&frame, true)?;
            return Ok(CommandResponse::ok(format!(
                "nan publish sent bytes={}",
                frame.len()
            )));
        }
        if let Some(data) = request.arg("send") {
            self.ensure_started()?;
            let dst = parse_mac(request.arg("dst").unwrap_or("ff:ff:ff:ff:ff:ff"))?;
            let instance = request
                .arg("instance")
                .map(parse_i32)
                .transpose()?
                .unwrap_or(NAN_ID as i32)
                .clamp(0, 255) as u8;
            let frame = nan_followup_frame(&dst, instance, data.as_bytes())?;
            raw_tx(&frame, true)?;
            return Ok(CommandResponse::ok(format!(
                "nan followup sent bytes={} dst={}",
                frame.len(),
                format_mac(&dst)
            )));
        }
        Ok(CommandResponse::ok(stats()))
    }
}

impl NanCommand {
    fn driver(&mut self) -> Result<&mut BlockingWifi<EspWifi<'static>>> {
        if self.wifi.is_none() {
            let peripherals = Peripherals::take()?;
            let sys_loop = EspSystemEventLoop::take()?;
            let wifi = EspWifi::new(peripherals.modem, sys_loop.clone(), None)?;
            self.wifi = Some(BlockingWifi::wrap(wifi, sys_loop)?);
        }
        Ok(self.wifi.as_mut().expect("nan wifi initialized"))
    }

    fn start_nan(&mut self) -> Result<()> {
        let channel = self.channel.max(1);
        let wifi = self.driver()?;
        wifi.set_configuration(&Configuration::Client(ClientConfiguration {
            ssid: "".try_into().map_err(|_| anyhow!("empty ssid failed"))?,
            auth_method: AuthMethod::None,
            ..Default::default()
        }))?;
        wifi.start()?;
        unsafe {
            let mut filter = sys::wifi_promiscuous_filter_t {
                filter_mask: sys::WIFI_PROMIS_FILTER_MASK_MGMT,
            };
            esp_ok(sys::esp_wifi_set_promiscuous(false))?;
            esp_ok(sys::esp_wifi_set_promiscuous_rx_cb(Some(sniffer_cb)))?;
            esp_ok(sys::esp_wifi_set_promiscuous_filter(&mut filter))?;
            esp_ok(sys::esp_wifi_set_channel(
                channel,
                sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE,
            ))?;
            esp_ok(sys::esp_wifi_set_promiscuous(true))?;
        }
        NAN_RUNNING.store(true, Ordering::Relaxed);
        if self.dump {
            log::info!(
                "nan raw monitor started channel={channel} filter={}",
                filter_name()
            );
        }
        Ok(())
    }

    fn ensure_started(&mut self) -> Result<()> {
        if !NAN_RUNNING.load(Ordering::Relaxed) {
            self.start_nan()?;
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct NanTransport {
    sent_frames: u32,
}

impl Transport for NanTransport {
    fn name(&self) -> &'static str {
        "nan"
    }

    fn send(&mut self, frame: &Frame<'_>, from_interface: i32) -> Result<()> {
        self.sent_frames = self.sent_frames.saturating_add(1);
        log::info!(
            "nan send: from={} len={} total={}",
            from_interface,
            frame.payload().len(),
            self.sent_frames
        );
        Ok(())
    }
}

fn stop_nan() -> Result<()> {
    unsafe {
        let _ = sys::esp_wifi_set_promiscuous(false);
    }
    NAN_RUNNING.store(false, Ordering::Relaxed);
    Ok(())
}

fn raw_tx(bytes: &[u8], en_sys_seq: bool) -> Result<()> {
    if bytes.len() < 24 || bytes.len() > 1500 {
        bail!(
            "raw 802.11 frame length must be 24..=1500, got {}",
            bytes.len()
        );
    }
    unsafe {
        esp_ok(sys::esp_wifi_80211_tx(
            sys::wifi_interface_t_WIFI_IF_STA,
            bytes.as_ptr() as *const _,
            bytes.len() as i32,
            en_sys_seq,
        ))
    }
}

fn nan_publish_frame() -> Result<Vec<u8>> {
    let mut frame = NAN_HEADER.to_vec();
    let mac = station_mac()?;
    frame[FRAME_SRC..FRAME_SRC + 6].copy_from_slice(&mac);
    frame[FRAME_BSSID..FRAME_BSSID + 6].copy_from_slice(&NAN_BSSID);
    frame.extend_from_slice(&NAN_DEVICE_CAPABILITIES);
    frame.extend_from_slice(&NAN_AVAILABILITY);
    frame.extend_from_slice(&NAN_SERVICE_EXTENSION);
    frame.extend_from_slice(&NAN_SERVICE_DESCRIPTOR);
    Ok(frame)
}

fn nan_followup_frame(dst: &[u8; 6], instance: u8, data: &[u8]) -> Result<Vec<u8>> {
    let len = data.len().min(255);
    let mut frame = NAN_HEADER.to_vec();
    let mac = station_mac()?;
    frame[FRAME_DST..FRAME_DST + 6].copy_from_slice(dst);
    frame[FRAME_SRC..FRAME_SRC + 6].copy_from_slice(&mac);
    frame[FRAME_BSSID..FRAME_BSSID + 6].copy_from_slice(&NAN_BSSID);
    let sz = len + 6 + 4;
    frame.push(0x03);
    frame.push((sz & 0xff) as u8);
    frame.push((sz >> 8) as u8);
    frame.extend_from_slice(&SVC_ID);
    frame.push(NAN_ID);
    frame.push(instance);
    frame.push(0x12);
    frame.push(len as u8);
    frame.extend_from_slice(&data[..len]);
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

unsafe extern "C" fn sniffer_cb(
    buf: *mut core::ffi::c_void,
    type_: sys::wifi_promiscuous_pkt_type_t,
) {
    if type_ != sys::wifi_promiscuous_pkt_type_t_WIFI_PKT_MGMT || buf.is_null() {
        NAN_RX_OTHER.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let pkt = unsafe { &*(buf as *const sys::wifi_promiscuous_pkt_t) };
    let len = pkt.rx_ctrl.sig_len().min(1500) as usize;
    let payload = pkt.payload.as_ptr();
    if payload.is_null() || len < FRAME_DATA {
        NAN_RX_OTHER.fetch_add(1, Ordering::Relaxed);
        return;
    }
    NAN_RX_MGMT.fetch_add(1, Ordering::Relaxed);
    NAN_RX_BYTES.fetch_add(len as u32, Ordering::Relaxed);
    let frame = unsafe { core::slice::from_raw_parts(payload, len) };
    if !matches_filter(frame) {
        return;
    }
    NAN_RX_MATCHED.fetch_add(1, Ordering::Relaxed);
    match frame[0] {
        0x80 => {
            if is_nan_bssid(frame) {
                NAN_RX_BEACON.fetch_add(1, Ordering::Relaxed);
            }
        }
        0xd0 => {
            NAN_RX_ACTION.fetch_add(1, Ordering::Relaxed);
            if is_nan_sdf(frame) {
                NAN_RX_SDF.fetch_add(1, Ordering::Relaxed);
            }
        }
        _ => {
            NAN_RX_OTHER.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn is_nan_bssid(frame: &[u8]) -> bool {
    frame.len() > FRAME_BSSID + 3
        && frame[FRAME_BSSID] == 0x50
        && frame[FRAME_BSSID + 1] == 0x6f
        && frame[FRAME_BSSID + 2] == 0x9a
}

fn is_nan_sdf(frame: &[u8]) -> bool {
    frame.len() > NAN_ACTION_START
        && is_nan_bssid(frame)
        && frame[FRAME_DATA] == 0x04
        && frame[FRAME_DATA + 1] == 0x09
        && frame[FRAME_DATA + 2] == 0x50
        && frame[FRAME_DATA + 3] == 0x6f
        && frame[FRAME_DATA + 4] == 0x9a
        && frame[FRAME_DATA + 5] == 0x13
}

fn matches_filter(frame: &[u8]) -> bool {
    if NAN_FILTER_BSSID_ENABLED.load(Ordering::Relaxed) {
        if frame.len() < FRAME_BSSID + 6 {
            return false;
        }
        for idx in 0..6 {
            if frame[FRAME_BSSID + idx] != NAN_FILTER_BSSID[idx].load(Ordering::Relaxed) {
                return false;
            }
        }
    }
    match NAN_FILTER_MODE.load(Ordering::Relaxed) {
        FILTER_ALL_MGMT => true,
        FILTER_NAN => is_nan_bssid(frame),
        FILTER_ACTION => frame.first() == Some(&0xd0),
        FILTER_BEACON => frame.first() == Some(&0x80),
        FILTER_SDF => is_nan_sdf(frame),
        _ => is_nan_bssid(frame),
    }
}

fn stats() -> String {
    format!(
        "nan running={} filter={} bssid_filter={} mgmt={} matched={} action={} beacon={} sdf={} other={} bytes={}",
        NAN_RUNNING.load(Ordering::Relaxed),
        filter_name(),
        NAN_FILTER_BSSID_ENABLED.load(Ordering::Relaxed),
        NAN_RX_MGMT.load(Ordering::Relaxed),
        NAN_RX_MATCHED.load(Ordering::Relaxed),
        NAN_RX_ACTION.load(Ordering::Relaxed),
        NAN_RX_BEACON.load(Ordering::Relaxed),
        NAN_RX_SDF.load(Ordering::Relaxed),
        NAN_RX_OTHER.load(Ordering::Relaxed),
        NAN_RX_BYTES.load(Ordering::Relaxed)
    )
}

fn parse_filter_mode(value: &str) -> Result<u32> {
    match value {
        "mgmt" | "all" | "all_mgmt" => Ok(FILTER_ALL_MGMT),
        "nan" => Ok(FILTER_NAN),
        "action" => Ok(FILTER_ACTION),
        "beacon" => Ok(FILTER_BEACON),
        "sdf" => Ok(FILTER_SDF),
        _ => bail!("unknown nan filter {value}"),
    }
}

fn filter_name() -> &'static str {
    match NAN_FILTER_MODE.load(Ordering::Relaxed) {
        FILTER_ALL_MGMT => "mgmt",
        FILTER_NAN => "nan",
        FILTER_ACTION => "action",
        FILTER_BEACON => "beacon",
        FILTER_SDF => "sdf",
        _ => "nan",
    }
}

fn parse_bytes(value: &str) -> Result<Vec<u8>> {
    let value = value.strip_prefix("hex:").unwrap_or(value);
    if value.contains(',') {
        return value
            .split(',')
            .map(|v| Ok(parse_i32(v.trim())? as u8))
            .collect();
    }
    if value.len() % 2 != 0 {
        bail!("hex byte string must have even length");
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(Into::into))
        .collect()
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

fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn esp_ok(ret: sys::esp_err_t) -> Result<()> {
    if ret == sys::ESP_OK {
        Ok(())
    } else {
        bail!("esp_err=0x{ret:x}")
    }
}
