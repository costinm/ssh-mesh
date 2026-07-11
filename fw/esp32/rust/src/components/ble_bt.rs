use std::collections::VecDeque;
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use esp_idf_svc::bt::{Ble, BtDriver};
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};
use crate::transports::dispatch_text_line;

use super::frames::hex_bytes;
use super::l3dmesh::{Frame, Transport};
use super::settings::{parse_bool, parse_i32};
use super::telemetry::{self, Direction};

static BLE_STARTED: AtomicBool = AtomicBool::new(false);
static BLE_ADV_STARTED: AtomicBool = AtomicBool::new(false);
static BLE_SCAN_STARTED: AtomicBool = AtomicBool::new(false);
static BLE_SCAN_STOPPING: AtomicBool = AtomicBool::new(false);
static BLE_MODE: AtomicU8 = AtomicU8::new(BLE_MODE_OFF);
static BLE_SCAN_REPORTS: AtomicU32 = AtomicU32::new(0);
static BLE_SCAN_MATCHED: AtomicU32 = AtomicU32::new(0);
static BLE_SCAN_LAST_RSSI: AtomicI32 = AtomicI32::new(0);
static BLE_FILTER_DMESH: AtomicBool = AtomicBool::new(true);
static BLE_FILTER_UUID16: AtomicU32 = AtomicU32::new(0);
static BLE_FILTER_ADDR_ENABLED: AtomicBool = AtomicBool::new(false);
static BLE_FILTER_ADDR: [AtomicU8; 6] = [
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
];
static BLE_ANNOUNCE_TX: AtomicU32 = AtomicU32::new(0);
static BLE_ANNOUNCE_RX: AtomicU32 = AtomicU32::new(0);
static BLE_LAST_ANNOUNCE_HASH: AtomicU32 = AtomicU32::new(0);
static BLE_WAKE_REQUEST_RX: AtomicU32 = AtomicU32::new(0);
static BLE_PENDING_SWITCHES: AtomicU32 = AtomicU32::new(0);
static BLE_GATT_STARTED: AtomicBool = AtomicBool::new(false);
static BLE_GATT_CONNECTED: AtomicBool = AtomicBool::new(false);
static BLE_GATT_NOTIFY_ENABLED: AtomicBool = AtomicBool::new(false);
static BLE_GATT_RX_TEXT: AtomicU32 = AtomicU32::new(0);
static BLE_GATT_RX_BINARY: AtomicU32 = AtomicU32::new(0);
static BLE_GATT_TX: AtomicU32 = AtomicU32::new(0);
static BLE_GATT_IF: AtomicU8 = AtomicU8::new(0xff);
static BLE_GATT_CONN_ID: AtomicU32 = AtomicU32::new(0xffff);
static BLE_GATT_TX_HANDLE: AtomicU32 = AtomicU32::new(0);
static BLE_GATT_RX_HANDLE: AtomicU32 = AtomicU32::new(0);
static BLE_GATT_CCC_HANDLE: AtomicU32 = AtomicU32::new(0);
static BLE_GATT_DB_READY: AtomicBool = AtomicBool::new(false);
static BLE_TEXT_QUEUE: OnceLock<Mutex<VecDeque<Vec<u8>>>> = OnceLock::new();
static BLE_ADV_PENDING: AtomicBool = AtomicBool::new(false);

static mut RAW_ADV_DATA: [u8; 31] = [0; 31];
static mut RAW_ADV_LEN: usize = 0;
static mut PENDING_ADV_DATA: [u8; 31] = [0; 31];
static mut PENDING_ADV_LEN: usize = 0;
static mut GATT_HANDLES: [u16; GATT_IDX_NB] = [0; GATT_IDX_NB];
static mut GATT_DB: MaybeUninit<[sys::esp_gatts_attr_db_t; GATT_IDX_NB]> = MaybeUninit::uninit();

pub const DMESH_BLE_SERVICE_UUID16: u16 = 0xfd5d;
const DMESH_ADV_MAGIC: [u8; 2] = *b"DM";
const DMESH_ADV_VERSION: u8 = 1;
const DMESH_EVENT_GENERIC: u8 = 0;
const DMESH_EVENT_LORA_RX: u8 = 1;
const DMESH_EVENT_IDLE_HELLO: u8 = 2;
const DMESH_EVENT_WAKE_REQUEST: u8 = 3;
const DMESH_EVENT_PAYLOAD_PENDING: u8 = 4;
const DMESH_MAX_PREFIX: usize = 5;
const BLE_MODE_OFF: u8 = 0;
const BLE_MODE_LISTEN: u8 = 1;
const BLE_MODE_ANNOUNCE: u8 = 2;
const BLE_MODE_CONNECTABLE: u8 = 3;
const GATT_APP_ID: u16 = 0x6e40;
const GATT_IDX_SVC: usize = 0;
const GATT_IDX_RX_VAL: usize = 2;
const GATT_IDX_TX_VAL: usize = 4;
const GATT_IDX_TX_CCC: usize = 5;
const GATT_IDX_NB: usize = 6;

const UUID_PRI_SERVICE: u16 = sys::ESP_GATT_UUID_PRI_SERVICE as u16;
const UUID_CHAR_DECLARE: u16 = sys::ESP_GATT_UUID_CHAR_DECLARE as u16;
const UUID_CLIENT_CONFIG: u16 = sys::ESP_GATT_UUID_CHAR_CLIENT_CONFIG as u16;
const NORDIC_SERVICE_UUID: [u8; 16] = [
    0x9e, 0xca, 0xdc, 0x24, 0x0e, 0xe5, 0xa9, 0xe0, 0x93, 0xf3, 0xa3, 0xb5, 0x01, 0x00, 0x40, 0x6e,
];
const NORDIC_RX_UUID: [u8; 16] = [
    0x9e, 0xca, 0xdc, 0x24, 0x0e, 0xe5, 0xa9, 0xe0, 0x93, 0xf3, 0xa3, 0xb5, 0x02, 0x00, 0x40, 0x6e,
];
const NORDIC_TX_UUID: [u8; 16] = [
    0x9e, 0xca, 0xdc, 0x24, 0x0e, 0xe5, 0xa9, 0xe0, 0x93, 0xf3, 0xa3, 0xb5, 0x03, 0x00, 0x40, 0x6e,
];
static mut RX_VALUE: [u8; 512] = [0; 512];
static mut TX_VALUE: [u8; 512] = [0; 512];
static mut CCC_VALUE: [u8; 2] = [0; 2];
static mut CHAR_PROP_WRITE: u8 =
    sys::ESP_GATT_CHAR_PROP_BIT_WRITE_NR as u8 | sys::ESP_GATT_CHAR_PROP_BIT_WRITE as u8;
static mut CHAR_PROP_NOTIFY: u8 = sys::ESP_GATT_CHAR_PROP_BIT_NOTIFY as u8;

pub fn register_commands(registry: &mut CommandRegistry) {
    registry.register(RadioCommand::new("ble"));
}

pub fn ble_transport() -> RadioTransport {
    RadioTransport::new("ble")
}

pub fn bt_transport() -> RadioTransport {
    RadioTransport::new("bt")
}

pub fn forward_packet_for_window(packet: &[u8], window_ms: u32) -> Result<bool> {
    let mut radio = RadioCommand::new("ble");
    radio.ensure_ble()?;
    start_gatt()?;
    announce_packet(DmeshBleEvent::PayloadPending, packet, None)?;
    send_gatt(packet);
    let deadline = Instant::now() + Duration::from_millis(window_ms as u64);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(true)
}

pub fn start_listen_mode() -> Result<()> {
    let mut radio = RadioCommand::new("ble");
    radio.ensure_ble()?;
    start_gatt()?;
    start_scan_params(0, true)?;
    BLE_MODE.store(BLE_MODE_LISTEN, Ordering::Relaxed);
    Ok(())
}

pub fn enable_controller_sleep() -> Result<()> {
    unsafe { esp_ok(sys::esp_bt_sleep_enable()) }
}

pub fn disable_controller_sleep() -> Result<()> {
    unsafe { esp_ok(sys::esp_bt_sleep_disable()) }
}

pub fn poll_text_commands(registry: &mut CommandRegistry) {
    for _ in 0..4 {
        let command = {
            let mut queue = ble_text_queue().lock().unwrap();
            queue.pop_front()
        };
        let Some(command) = command else {
            return;
        };
        let line = core::str::from_utf8(&command).unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let response = dispatch_text_line(registry, line);
        send_gatt(response.as_bytes());
    }
}

pub fn announce_lora_packet(packet: &[u8], rssi: i32, snr: f32) -> Result<()> {
    announce_packet(DmeshBleEvent::LoraRx, packet, Some((rssi, snr)))
}

pub fn announce_packet(
    event: DmeshBleEvent,
    packet: &[u8],
    metrics: Option<(i32, f32)>,
) -> Result<()> {
    let mut radio = RadioCommand::new("ble");
    radio.ensure_ble()?;
    start_gatt()?;
    let adv = dmesh_adv_data(event, packet, metrics)?;
    start_raw_adv(&adv)?;
    send_gatt(packet);
    BLE_ANNOUNCE_TX.fetch_add(1, Ordering::Relaxed);
    BLE_MODE.store(BLE_MODE_CONNECTABLE, Ordering::Relaxed);
    telemetry::record_packet("ble", Direction::Tx, &adv, "announce=true");
    Ok(())
}

#[derive(Clone, Copy)]
pub enum DmeshBleEvent {
    Generic,
    LoraRx,
    IdleHello,
    WakeRequest,
    PayloadPending,
}

impl DmeshBleEvent {
    fn code(self) -> u8 {
        match self {
            Self::Generic => DMESH_EVENT_GENERIC,
            Self::LoraRx => DMESH_EVENT_LORA_RX,
            Self::IdleHello => DMESH_EVENT_IDLE_HELLO,
            Self::WakeRequest => DMESH_EVENT_WAKE_REQUEST,
            Self::PayloadPending => DMESH_EVENT_PAYLOAD_PENDING,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::LoraRx => "lora_rx",
            Self::IdleHello => "idle_hello",
            Self::WakeRequest => "wake_request",
            Self::PayloadPending => "payload_pending",
        }
    }

    fn from_code(code: u8) -> Self {
        match code {
            DMESH_EVENT_LORA_RX => Self::LoraRx,
            DMESH_EVENT_IDLE_HELLO => Self::IdleHello,
            DMESH_EVENT_WAKE_REQUEST => Self::WakeRequest,
            DMESH_EVENT_PAYLOAD_PENDING => Self::PayloadPending,
            _ => Self::Generic,
        }
    }
}

struct RadioCommand {
    name: &'static str,
    enabled: bool,
    mtu: usize,
    bt: Option<BtDriver<'static, Ble>>,
}

impl RadioCommand {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            enabled: true,
            mtu: 512,
            bt: None,
        }
    }
}

impl CommandHandler for RadioCommand {
    fn name(&self) -> &'static str {
        self.name
    }

    fn help(&self) -> &'static str {
        "ble start=true|mode=listen|gatt|announce|connectable|advertise=true payload=hex:... event=generic|lora_rx|wake_request|payload_pending|announce=hex:...|send=hex:...|raw_adv=hex:...|scan=true filter=dmesh|all scan_stop=true filter_uuid16=0xfd5d filter_addr=aa:bb:...|stats=true"
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if self.name == "bt" {
            return self.handle_bt_placeholder(request);
        }
        if let Some(enable) = request.arg("enable") {
            self.enabled = parse_bool(enable)?;
        }
        if let Some(mtu) = request.arg_i32("mtu")? {
            self.mtu = mtu.max(1) as usize;
        }
        if let Some(uuid16) = request.arg("filter_uuid16") {
            let uuid16 = parse_i32(uuid16)? as u32;
            BLE_FILTER_UUID16.store(uuid16 & 0xffff, Ordering::Relaxed);
        }
        if let Some(filter) = request.arg("filter") {
            match filter {
                "dmesh" => BLE_FILTER_DMESH.store(true, Ordering::Relaxed),
                "all" | "none" => BLE_FILTER_DMESH.store(false, Ordering::Relaxed),
                _ => bail!("unsupported BLE filter {filter}"),
            }
        }
        if let Some(addr) = request.arg("filter_addr") {
            if addr == "none" || addr == "false" {
                BLE_FILTER_ADDR_ENABLED.store(false, Ordering::Relaxed);
            } else {
                let addr = parse_mac(addr)?;
                for (idx, byte) in addr.iter().enumerate() {
                    BLE_FILTER_ADDR[idx].store(*byte, Ordering::Relaxed);
                }
                BLE_FILTER_ADDR_ENABLED.store(true, Ordering::Relaxed);
            }
        }
        if request.arg("start").is_some() {
            self.ensure_ble()?;
            start_gatt()?;
            start_scan_params(0, true)?;
            BLE_MODE.store(BLE_MODE_LISTEN, Ordering::Relaxed);
            return Ok(CommandResponse::ok("ble started"));
        }
        if request.arg("stats").is_some() {
            return Ok(CommandResponse::ok(ble_stats()));
        }
        if request.arg("scan_stop").is_some() {
            unsafe {
                let _ = sys::esp_ble_gap_stop_scanning();
            }
            BLE_SCAN_STARTED.store(false, Ordering::Relaxed);
            return Ok(CommandResponse::ok("ble scan stopped"));
        }
        if request
            .arg("scan")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            self.ensure_ble()?;
            start_gatt()?;
            start_scan(request)?;
            return Ok(CommandResponse::ok(format!(
                "ble scan started {}",
                ble_stats()
            )));
        }
        if let Some(raw) = request.arg("raw_adv") {
            self.ensure_ble()?;
            let data = parse_bytes(raw)?;
            start_raw_adv(&data)?;
            telemetry::record_packet("ble", Direction::Tx, &data, "raw_adv=true");
            return Ok(CommandResponse::ok(format!(
                "ble raw_adv started bytes={}",
                data.len()
            )));
        }
        if request
            .arg("advertise")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
            || request.arg("announce").is_some()
        {
            self.ensure_ble()?;
            let payload = request
                .arg("payload")
                .or_else(|| request.arg("data"))
                .or_else(|| request.arg("announce"))
                .map(parse_bytes)
                .transpose()?
                .unwrap_or_default();
            let event = parse_event(request.arg("event").unwrap_or("payload_pending"))?;
            let rssi = request.arg_i32("rssi")?.unwrap_or(0);
            let snr = request
                .arg("snr")
                .and_then(|value| value.parse::<f32>().ok());
            let metrics = snr.map(|snr| (rssi, snr));
            announce_packet(event, &payload, metrics)?;
            return Ok(CommandResponse::ok(format!(
                "ble announce event={} bytes={} {}",
                event.name(),
                payload.len(),
                ble_stats()
            )));
        }
        if let Some(data) = request.arg("send").or_else(|| request.arg("gatt")) {
            self.ensure_ble()?;
            start_gatt()?;
            let payload = parse_bytes(data)?;
            send_gatt(&payload);
            telemetry::record_packet("ble", Direction::Tx, &payload, "source=gatt_command");
            return Ok(CommandResponse::ok(format!(
                "ble gatt sent bytes={} {}",
                payload.len(),
                ble_stats()
            )));
        }
        if let Some(mode) = request.arg("mode") {
            if mode == "listen" || mode == "scan" {
                self.ensure_ble()?;
                start_gatt()?;
                start_scan_params(0, true)?;
                BLE_MODE.store(BLE_MODE_LISTEN, Ordering::Relaxed);
                return Ok(CommandResponse::ok(format!(
                    "ble listen started {}",
                    ble_stats()
                )));
            }
            if mode == "announce" || mode == "connectable" {
                self.ensure_ble()?;
                start_gatt()?;
                let payload = request
                    .arg("payload")
                    .or_else(|| request.arg("data"))
                    .map(parse_bytes)
                    .transpose()?
                    .unwrap_or_default();
                let event = request
                    .arg("event")
                    .map(parse_event)
                    .transpose()?
                    .unwrap_or(DmeshBleEvent::PayloadPending);
                announce_packet(event, &payload, None)?;
                return Ok(CommandResponse::ok(format!(
                    "ble connectable started {}",
                    ble_stats()
                )));
            }
            if mode == "gatt" || mode == "nus" || mode == "meshcore" {
                self.ensure_ble()?;
                start_gatt()?;
                return Ok(CommandResponse::ok(format!(
                    "ble gatt started {}",
                    ble_stats()
                )));
            }
        }
        Ok(CommandResponse::ok(ble_stats()))
    }
}

fn parse_event(value: &str) -> Result<DmeshBleEvent> {
    match value {
        "generic" => Ok(DmeshBleEvent::Generic),
        "lora" | "lora_rx" => Ok(DmeshBleEvent::LoraRx),
        "idle" | "idle_hello" => Ok(DmeshBleEvent::IdleHello),
        "wake" | "wake_request" => Ok(DmeshBleEvent::WakeRequest),
        "pending" | "payload_pending" => Ok(DmeshBleEvent::PayloadPending),
        other => bail!("unsupported BLE advertise event {other}"),
    }
}

impl RadioCommand {
    fn ensure_ble(&mut self) -> Result<()> {
        if BLE_STARTED.load(Ordering::Relaxed) {
            return Ok(());
        }
        if self.bt.is_none() {
            let peripherals = Peripherals::take()?;
            self.bt = Some(BtDriver::<Ble>::new(peripherals.modem, None)?);
            let name = CString::new("MeshCore")?;
            unsafe {
                esp_ok(sys::esp_ble_gap_register_callback(Some(gap_cb)))?;
                esp_ok(sys::esp_ble_gatts_register_callback(Some(gatts_cb)))?;
                esp_ok(sys::esp_ble_gap_set_device_name(name.as_ptr()))?;
            }
            BLE_STARTED.store(true, Ordering::Relaxed);
        }
        Ok(())
    }

    fn handle_bt_placeholder(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if let Some(enable) = request.arg("enable") {
            self.enabled = parse_bool(enable)?;
        }
        Ok(CommandResponse::ok(format!(
            "bt classic placeholder enabled={} mtu={}",
            self.enabled, self.mtu
        )))
    }
}

fn start_gatt() -> Result<()> {
    if BLE_GATT_STARTED.load(Ordering::Relaxed) {
        return Ok(());
    }
    unsafe {
        if !BLE_GATT_DB_READY.load(Ordering::Acquire) {
            core::ptr::addr_of_mut!(GATT_DB).write(MaybeUninit::new(gatt_db()));
            BLE_GATT_DB_READY.store(true, Ordering::Release);
        }
        esp_ok(sys::esp_ble_gatt_set_local_mtu(200))?;
        esp_ok(sys::esp_ble_gatts_app_register(GATT_APP_ID))?;
    }
    BLE_GATT_STARTED.store(true, Ordering::Relaxed);
    Ok(())
}

pub struct RadioTransport {
    name: &'static str,
    sent_frames: u32,
}

impl RadioTransport {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            sent_frames: 0,
        }
    }
}

impl Transport for RadioTransport {
    fn name(&self) -> &'static str {
        self.name
    }

    fn send(&mut self, frame: &Frame<'_>, from_interface: i32) -> Result<()> {
        self.sent_frames = self.sent_frames.saturating_add(1);
        telemetry::record_packet(
            self.name,
            Direction::Tx,
            frame.payload(),
            format!("source=l3mesh from={from_interface}"),
        );
        log::info!(
            "{} send: from={} len={} total={}",
            self.name,
            from_interface,
            frame.payload().len(),
            self.sent_frames
        );
        Ok(())
    }
}

fn start_raw_adv(data: &[u8]) -> Result<()> {
    if data.len() > 31 {
        bail!("BLE legacy advertising data is limited to 31 bytes");
    }
    unsafe {
        let ptr = core::ptr::addr_of_mut!(PENDING_ADV_DATA) as *mut u8;
        core::ptr::write_bytes(ptr, 0, 31);
        core::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
        PENDING_ADV_LEN = data.len();
        BLE_ADV_PENDING.store(true, Ordering::Relaxed);
        BLE_SCAN_STOPPING.store(true, Ordering::Relaxed);
        let stop_ret = sys::esp_ble_gap_stop_scanning();
        if stop_ret == sys::ESP_OK {
            sys::vTaskDelay(duration_to_ticks(Duration::from_millis(120)));
            if BLE_ADV_PENDING.swap(false, Ordering::Relaxed) {
                BLE_SCAN_STOPPING.store(false, Ordering::Relaxed);
                return configure_raw_adv(data);
            }
            return Ok(());
        }
        BLE_SCAN_STARTED.store(false, Ordering::Relaxed);
        BLE_SCAN_STOPPING.store(false, Ordering::Relaxed);
        BLE_ADV_PENDING.store(false, Ordering::Relaxed);
    }
    configure_raw_adv(data)
}

fn configure_raw_adv(data: &[u8]) -> Result<()> {
    unsafe {
        let _ = sys::esp_ble_gap_stop_advertising();
        BLE_SCAN_STARTED.store(false, Ordering::Relaxed);
        BLE_ADV_STARTED.store(false, Ordering::Relaxed);
        let ptr = core::ptr::addr_of_mut!(RAW_ADV_DATA) as *mut u8;
        core::ptr::write_bytes(ptr, 0, 31);
        core::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
        RAW_ADV_LEN = data.len();
        esp_ok(sys::esp_ble_gap_config_adv_data_raw(
            ptr,
            RAW_ADV_LEN as u32,
        ))?;
        sys::vTaskDelay(duration_to_ticks(Duration::from_millis(30)));
    }
    start_ble_advertising()?;
    Ok(())
}

fn start_ble_advertising() -> Result<()> {
    let mut params = sys::esp_ble_adv_params_t {
        adv_int_min: 0x20,
        adv_int_max: 0x40,
        adv_type: sys::esp_ble_adv_type_t_ADV_TYPE_IND,
        own_addr_type: sys::esp_ble_addr_type_t_BLE_ADDR_TYPE_PUBLIC,
        peer_addr: [0; 6],
        peer_addr_type: sys::esp_ble_addr_type_t_BLE_ADDR_TYPE_PUBLIC,
        channel_map: sys::esp_ble_adv_channel_t_ADV_CHNL_ALL,
        adv_filter_policy: sys::esp_ble_adv_filter_t_ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
    };
    unsafe {
        esp_ok(sys::esp_ble_gap_start_advertising(&mut params))?;
    }
    BLE_ADV_STARTED.store(true, Ordering::Relaxed);
    Ok(())
}

fn duration_to_ticks(timeout: Duration) -> sys::TickType_t {
    let hz = sys::configTICK_RATE_HZ as u128;
    let ticks = timeout.as_millis().saturating_mul(hz).div_ceil(1000);
    ticks.min(sys::TickType_t::MAX as u128) as sys::TickType_t
}

fn start_scan(request: &CommandRequest) -> Result<()> {
    let duration = request
        .arg("duration")
        .map(parse_i32)
        .transpose()?
        .unwrap_or(0)
        .max(0) as u32;
    let active = request
        .arg("active")
        .map(parse_bool)
        .transpose()?
        .unwrap_or(true);
    start_scan_params(duration, active)
}

fn start_scan_params(duration: u32, active: bool) -> Result<()> {
    if BLE_SCAN_STARTED.load(Ordering::Relaxed) && duration == 0 && active {
        BLE_MODE.store(BLE_MODE_LISTEN, Ordering::Relaxed);
        return Ok(());
    }
    let mut params = sys::esp_ble_scan_params_t {
        scan_type: if active {
            sys::esp_ble_scan_type_t_BLE_SCAN_TYPE_ACTIVE
        } else {
            sys::esp_ble_scan_type_t_BLE_SCAN_TYPE_PASSIVE
        },
        own_addr_type: sys::esp_ble_addr_type_t_BLE_ADDR_TYPE_PUBLIC,
        scan_filter_policy: sys::esp_ble_scan_filter_t_BLE_SCAN_FILTER_ALLOW_ALL,
        scan_interval: 0x50,
        scan_window: 0x30,
        scan_duplicate: sys::esp_ble_scan_duplicate_t_BLE_SCAN_DUPLICATE_DISABLE,
    };
    unsafe {
        let _ = sys::esp_ble_gap_stop_advertising();
        BLE_ADV_STARTED.store(false, Ordering::Relaxed);
        esp_ok(sys::esp_ble_gap_set_scan_params(&mut params))?;
        esp_ok(sys::esp_ble_gap_start_scanning(duration))?;
    }
    BLE_SCAN_STARTED.store(true, Ordering::Relaxed);
    BLE_ADV_STARTED.store(false, Ordering::Relaxed);
    Ok(())
}

fn dmesh_adv_data(
    event: DmeshBleEvent,
    packet: &[u8],
    metrics: Option<(i32, f32)>,
) -> Result<Vec<u8>> {
    let mac = ble_mac()?;
    let hash = fnv1a32(packet);
    let (rssi, snr) = metrics.unwrap_or((0, 0.0));
    let prefix_len = packet.len().min(DMESH_MAX_PREFIX);
    let mut service = Vec::with_capacity(2 + 19 + prefix_len);
    service.extend_from_slice(&DMESH_BLE_SERVICE_UUID16.to_le_bytes());
    service.extend_from_slice(&DMESH_ADV_MAGIC);
    service.push(DMESH_ADV_VERSION);
    service.push(0);
    service.push(event.code());
    service.extend_from_slice(&mac);
    service.extend_from_slice(&(packet.len().min(u16::MAX as usize) as u16).to_le_bytes());
    service.extend_from_slice(&hash.to_le_bytes());
    service.push(rssi.clamp(i8::MIN as i32, i8::MAX as i32) as i8 as u8);
    service.push((snr * 4.0).round().clamp(i8::MIN as f32, i8::MAX as f32) as i8 as u8);
    service.extend_from_slice(&packet[..prefix_len]);

    let mut adv = Vec::with_capacity(31);
    adv.extend_from_slice(&[0x02, 0x01, 0x06]);
    adv.push((service.len() + 1).min(0xff) as u8);
    adv.push(0x16);
    adv.extend_from_slice(&service);
    if adv.len() > 31 {
        bail!("DMesh BLE announcement exceeded legacy advertising limit");
    }
    Ok(adv)
}

#[derive(Debug)]
struct DmeshAnnouncement {
    event: u8,
    mac: [u8; 6],
    payload_len: u16,
    payload_hash: u32,
    rssi: i8,
    snr: f32,
    prefix: Vec<u8>,
}

impl DmeshAnnouncement {
    fn event_name(&self) -> &'static str {
        DmeshBleEvent::from_code(self.event).name()
    }

    fn needs_connectable_response(&self) -> bool {
        matches!(
            DmeshBleEvent::from_code(self.event),
            DmeshBleEvent::WakeRequest | DmeshBleEvent::PayloadPending
        )
    }
}

fn parse_dmesh_adv(adv: &[u8]) -> Option<DmeshAnnouncement> {
    let mut i = 0;
    while i < adv.len() {
        let len = *adv.get(i)? as usize;
        if len == 0 {
            break;
        }
        let typ = *adv.get(i + 1)?;
        let data_start = i + 2;
        let data_end = (i + 1 + len).min(adv.len());
        let data = adv.get(data_start..data_end)?;
        if typ == 0x16 && data.len() >= 21 {
            let uuid = u16::from_le_bytes([data[0], data[1]]);
            if uuid == DMESH_BLE_SERVICE_UUID16
                && data[2..4] == DMESH_ADV_MAGIC
                && data[4] == DMESH_ADV_VERSION
            {
                let mut mac = [0_u8; 6];
                mac.copy_from_slice(&data[7..13]);
                let payload_len = u16::from_le_bytes([data[13], data[14]]);
                let payload_hash = u32::from_le_bytes([data[15], data[16], data[17], data[18]]);
                let rssi = data[19] as i8;
                let snr = data[20] as i8 as f32 / 4.0;
                return Some(DmeshAnnouncement {
                    event: data[6],
                    mac,
                    payload_len,
                    payload_hash,
                    rssi,
                    snr,
                    prefix: data[21..].to_vec(),
                });
            }
        }
        i += len + 1;
    }
    None
}

fn ble_mac() -> Result<[u8; 6]> {
    let mut mac = [0_u8; 6];
    unsafe {
        esp_ok(sys::esp_read_mac(
            mac.as_mut_ptr(),
            sys::esp_mac_type_t_ESP_MAC_BT,
        ))?;
    }
    Ok(mac)
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c_9dc5_u32, |acc, byte| {
        acc.wrapping_mul(16777619) ^ *byte as u32
    })
}

unsafe extern "C" fn gap_cb(
    event: sys::esp_gap_ble_cb_event_t,
    param: *mut sys::esp_ble_gap_cb_param_t,
) {
    if event == sys::esp_gap_ble_cb_event_t_ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT {
        let _ = start_ble_advertising();
        return;
    }
    if event == sys::esp_gap_ble_cb_event_t_ESP_GAP_BLE_SCAN_RESULT_EVT && !param.is_null() {
        let result = unsafe { (*param).scan_rst };
        if result.search_evt == sys::esp_gap_search_evt_t_ESP_GAP_SEARCH_INQ_CMPL_EVT {
            BLE_SCAN_STOPPING.store(false, Ordering::Relaxed);
            BLE_SCAN_STARTED.store(false, Ordering::Relaxed);
            if BLE_ADV_PENDING.swap(false, Ordering::Relaxed) {
                unsafe {
                    let ptr = core::ptr::addr_of!(PENDING_ADV_DATA) as *const u8;
                    let data = core::slice::from_raw_parts(ptr, PENDING_ADV_LEN);
                    if let Err(err) = configure_raw_adv(data) {
                        let line = format!(
                            "event type=ble.error component=advertise message={}",
                            crate::commands::protocol::escape_value(&err.to_string())
                        );
                        telemetry::record_log(line);
                    }
                }
            }
            return;
        }
        if result.search_evt != sys::esp_gap_search_evt_t_ESP_GAP_SEARCH_INQ_RES_EVT {
            return;
        }
        BLE_SCAN_REPORTS.fetch_add(1, Ordering::Relaxed);
        BLE_SCAN_LAST_RSSI.store(result.rssi, Ordering::Relaxed);
        let len =
            (result.adv_data_len as usize + result.scan_rsp_len as usize).min(result.ble_adv.len());
        let adv = &result.ble_adv[..len];
        if matches_ble_filter(&result.bda, adv) {
            BLE_SCAN_MATCHED.fetch_add(1, Ordering::Relaxed);
            if let Some(announce) = parse_dmesh_adv(adv) {
                BLE_ANNOUNCE_RX.fetch_add(1, Ordering::Relaxed);
                telemetry::count_packet("ble", Direction::Rx, adv.len());
                if matches!(
                    DmeshBleEvent::from_code(announce.event),
                    DmeshBleEvent::WakeRequest
                ) {
                    BLE_WAKE_REQUEST_RX.fetch_add(1, Ordering::Relaxed);
                }
                let first_seen = BLE_LAST_ANNOUNCE_HASH
                    .swap(announce.payload_hash, Ordering::Relaxed)
                    != announce.payload_hash;
                if first_seen {
                    let line = format!(
                        "event type=ble.announce_rx event={} addr={} mac={} len={} hash=0x{:08x} rssi={} snr={} prefix={}",
                        announce.event_name(),
                        format_mac(&result.bda),
                        format_mac(&announce.mac),
                        announce.payload_len,
                        announce.payload_hash,
                        announce.rssi,
                        announce.snr,
                        hex_bytes(&announce.prefix)
                    );
                    telemetry::record_log(line);
                    telemetry::record_packet_sample(
                        "ble",
                        Direction::Rx,
                        adv,
                        format!(
                            "source=scan rssi={} addr={}",
                            result.rssi,
                            format_mac(&result.bda)
                        ),
                    );
                }
                if announce.needs_connectable_response() {
                    let response = dmesh_adv_data(DmeshBleEvent::IdleHello, &[], None);
                    if let Ok(response) = response {
                        if start_raw_adv(&response).is_ok() {
                            BLE_MODE.store(BLE_MODE_CONNECTABLE, Ordering::Relaxed);
                            BLE_PENDING_SWITCHES.fetch_add(1, Ordering::Relaxed);
                            let line = format!(
                                "event type=ble.mode mode=connectable source=announce_rx event={}",
                                announce.event_name()
                            );
                            telemetry::record_log(line);
                        }
                    }
                }
            } else {
                telemetry::record_packet(
                    "ble",
                    Direction::Rx,
                    adv,
                    format!(
                        "source=scan rssi={} addr={}",
                        result.rssi,
                        format_mac(&result.bda)
                    ),
                );
            }
        }
    }
}

fn matches_ble_filter(addr: &[u8; 6], adv: &[u8]) -> bool {
    if BLE_FILTER_ADDR_ENABLED.load(Ordering::Relaxed) {
        for idx in 0..6 {
            if addr[idx] != BLE_FILTER_ADDR[idx].load(Ordering::Relaxed) {
                return false;
            }
        }
    }
    let uuid16 = BLE_FILTER_UUID16.load(Ordering::Relaxed);
    if uuid16 != 0 && !adv_contains_uuid16(adv, uuid16 as u16) {
        return false;
    }
    if BLE_FILTER_DMESH.load(Ordering::Relaxed) && parse_dmesh_adv(adv).is_none() {
        return false;
    }
    true
}

fn adv_contains_uuid16(adv: &[u8], uuid: u16) -> bool {
    let le = uuid.to_le_bytes();
    let mut i = 0;
    while i < adv.len() {
        let len = adv[i] as usize;
        if len == 0 || i + len >= adv.len() + 1 {
            break;
        }
        let typ = adv[i + 1];
        let data_start = i + 2;
        let data_end = (i + 1 + len).min(adv.len());
        if matches!(typ, 0x02 | 0x03 | 0x16)
            && adv[data_start..data_end].windows(2).any(|w| w == le)
        {
            return true;
        }
        i += len + 1;
    }
    false
}

fn ble_stats() -> String {
    format!(
        "ble started={} mode={} adv={} scan={} reports={} matched={} last_rssi={} filter=dmesh:{} filter_uuid16=0x{:04x} filter_addr={} announce_tx={} announce_rx={} wake_rx={} pending_switches={} gatt_started={} gatt_connected={} notify={} gatt_rx_text={} gatt_rx_binary={} gatt_tx={}",
        BLE_STARTED.load(Ordering::Relaxed),
        ble_mode_name(),
        BLE_ADV_STARTED.load(Ordering::Relaxed),
        BLE_SCAN_STARTED.load(Ordering::Relaxed),
        BLE_SCAN_REPORTS.load(Ordering::Relaxed),
        BLE_SCAN_MATCHED.load(Ordering::Relaxed),
        BLE_SCAN_LAST_RSSI.load(Ordering::Relaxed),
        BLE_FILTER_DMESH.load(Ordering::Relaxed),
        BLE_FILTER_UUID16.load(Ordering::Relaxed),
        BLE_FILTER_ADDR_ENABLED.load(Ordering::Relaxed),
        BLE_ANNOUNCE_TX.load(Ordering::Relaxed),
        BLE_ANNOUNCE_RX.load(Ordering::Relaxed),
        BLE_WAKE_REQUEST_RX.load(Ordering::Relaxed),
        BLE_PENDING_SWITCHES.load(Ordering::Relaxed),
        BLE_GATT_STARTED.load(Ordering::Relaxed),
        BLE_GATT_CONNECTED.load(Ordering::Relaxed),
        BLE_GATT_NOTIFY_ENABLED.load(Ordering::Relaxed),
        BLE_GATT_RX_TEXT.load(Ordering::Relaxed),
        BLE_GATT_RX_BINARY.load(Ordering::Relaxed),
        BLE_GATT_TX.load(Ordering::Relaxed)
    )
}

fn ble_mode_name() -> &'static str {
    match BLE_MODE.load(Ordering::Relaxed) {
        BLE_MODE_LISTEN => "listen",
        BLE_MODE_ANNOUNCE => "announce",
        BLE_MODE_CONNECTABLE => "connectable",
        BLE_MODE_OFF => "off",
        _ => "unknown",
    }
}

unsafe extern "C" fn gatts_cb(
    event: sys::esp_gatts_cb_event_t,
    gatts_if: sys::esp_gatt_if_t,
    param: *mut sys::esp_ble_gatts_cb_param_t,
) {
    if param.is_null() {
        return;
    }
    match event {
        x if x == sys::esp_gatts_cb_event_t_ESP_GATTS_REG_EVT => {
            let reg = unsafe { (*param).reg };
            if reg.app_id == GATT_APP_ID && reg.status == sys::esp_gatt_status_t_ESP_GATT_OK {
                BLE_GATT_IF.store(gatts_if, Ordering::Relaxed);
                unsafe {
                    if BLE_GATT_DB_READY.load(Ordering::Acquire) {
                        let db = core::ptr::addr_of!(GATT_DB) as *const sys::esp_gatts_attr_db_t;
                        let _ =
                            sys::esp_ble_gatts_create_attr_tab(db, gatts_if, GATT_IDX_NB as u16, 0);
                    }
                }
            }
        }
        x if x == sys::esp_gatts_cb_event_t_ESP_GATTS_CREAT_ATTR_TAB_EVT => {
            let add = unsafe { (*param).add_attr_tab };
            if add.status == sys::esp_gatt_status_t_ESP_GATT_OK
                && add.num_handle as usize == GATT_IDX_NB
                && !add.handles.is_null()
            {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        add.handles,
                        core::ptr::addr_of_mut!(GATT_HANDLES) as *mut u16,
                        GATT_IDX_NB,
                    );
                    BLE_GATT_RX_HANDLE
                        .store(GATT_HANDLES[GATT_IDX_RX_VAL] as u32, Ordering::Relaxed);
                    BLE_GATT_TX_HANDLE
                        .store(GATT_HANDLES[GATT_IDX_TX_VAL] as u32, Ordering::Relaxed);
                    BLE_GATT_CCC_HANDLE
                        .store(GATT_HANDLES[GATT_IDX_TX_CCC] as u32, Ordering::Relaxed);
                    let _ = sys::esp_ble_gatts_start_service(GATT_HANDLES[GATT_IDX_SVC]);
                }
            }
        }
        x if x == sys::esp_gatts_cb_event_t_ESP_GATTS_CONNECT_EVT => {
            let connect = unsafe { (*param).connect };
            BLE_GATT_CONN_ID.store(connect.conn_id as u32, Ordering::Relaxed);
            BLE_GATT_IF.store(gatts_if, Ordering::Relaxed);
            BLE_GATT_CONNECTED.store(true, Ordering::Relaxed);
            let line = "event type=ble.gatt state=connected".to_string();
            telemetry::record_log(line);
        }
        x if x == sys::esp_gatts_cb_event_t_ESP_GATTS_DISCONNECT_EVT => {
            BLE_GATT_CONNECTED.store(false, Ordering::Relaxed);
            BLE_GATT_NOTIFY_ENABLED.store(false, Ordering::Relaxed);
            let line = "event type=ble.gatt state=disconnected".to_string();
            telemetry::record_log(line);
            unsafe {
                let mut params = default_adv_params();
                let _ = sys::esp_ble_gap_start_advertising(&mut params);
            }
        }
        x if x == sys::esp_gatts_cb_event_t_ESP_GATTS_WRITE_EVT => {
            let write = unsafe { (*param).write };
            if write.value.is_null() || write.len == 0 {
                return;
            }
            let data = unsafe { core::slice::from_raw_parts(write.value, write.len as usize) };
            if write.handle as u32 == BLE_GATT_CCC_HANDLE.load(Ordering::Relaxed) && data.len() >= 2
            {
                BLE_GATT_NOTIFY_ENABLED.store(data[0] & 0x01 != 0, Ordering::Relaxed);
            } else if write.handle as u32 == BLE_GATT_RX_HANDLE.load(Ordering::Relaxed) {
                let response = handle_gatt_rx(data);
                if !response.is_empty() {
                    send_gatt(&response);
                }
            }
            if write.need_rsp {
                unsafe {
                    let _ = sys::esp_ble_gatts_send_response(
                        gatts_if,
                        write.conn_id,
                        write.trans_id,
                        sys::esp_gatt_status_t_ESP_GATT_OK,
                        core::ptr::null_mut(),
                    );
                }
            }
        }
        _ => {}
    }
}

fn handle_gatt_rx(data: &[u8]) -> Vec<u8> {
    telemetry::record_packet("ble", Direction::Rx, data, "source=gatt_rx");
    if data
        .first()
        .map(|byte| is_meshcore_binary_tag(*byte))
        .unwrap_or(false)
    {
        BLE_GATT_RX_BINARY.fetch_add(1, Ordering::Relaxed);
        return meshcore_response(data);
    }
    if data.first().map(|byte| byte.is_ascii()).unwrap_or(false) {
        BLE_GATT_RX_TEXT.fetch_add(1, Ordering::Relaxed);
        queue_ble_text(data);
        return Vec::new();
    }
    BLE_GATT_RX_BINARY.fetch_add(1, Ordering::Relaxed);
    Vec::new()
}

fn is_meshcore_binary_tag(byte: u8) -> bool {
    (0x01..=0x1b).contains(&byte) || byte >= 0x80
}

fn meshcore_response(data: &[u8]) -> Vec<u8> {
    match data[0] {
        0x01 => meshcore_self_info(),
        0x16 => meshcore_device_info(),
        _ => Vec::new(),
    }
}

fn meshcore_self_info() -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.push(0x05);
    out.push(0);
    out.push(13);
    out.push(20);
    out.extend_from_slice(&[0x44; 32]);
    out.extend_from_slice(&0_i32.to_le_bytes());
    out.extend_from_slice(&0_i32.to_le_bytes());
    out.push(0);
    out.push(0);
    out.push(0);
    out.push(0);
    out.extend_from_slice(&915_000_u32.to_le_bytes());
    out.extend_from_slice(&250_000_u32.to_le_bytes());
    out.push(9);
    out.push(5);
    out.extend_from_slice(b"dmesh-rs");
    out
}

fn meshcore_device_info() -> Vec<u8> {
    let mut out = Vec::with_capacity(76);
    out.push(0x0d);
    out.push(3);
    out.push(32);
    out.push(8);
    out.extend_from_slice(&0_u32.to_le_bytes());
    push_fixed_ascii(&mut out, b"dmesh-rs", 12);
    push_fixed_ascii(&mut out, b"ESP32 Rust GATT", 40);
    push_fixed_ascii(&mut out, b"meshcore-uuid", 20);
    out
}

fn push_fixed_ascii(out: &mut Vec<u8>, value: &[u8], width: usize) {
    let used = value.len().min(width);
    out.extend_from_slice(&value[..used]);
    out.resize(out.len() + width - used, 0);
}

fn queue_ble_text(data: &[u8]) {
    let mut queue = ble_text_queue().lock().unwrap();
    if queue.len() >= 8 {
        let _ = queue.pop_front();
    }
    queue.push_back(data.to_vec());
}

fn ble_text_queue() -> &'static Mutex<VecDeque<Vec<u8>>> {
    BLE_TEXT_QUEUE.get_or_init(|| Mutex::new(VecDeque::new()))
}

fn send_gatt(data: &[u8]) {
    if !BLE_GATT_CONNECTED.load(Ordering::Relaxed)
        || !BLE_GATT_NOTIFY_ENABLED.load(Ordering::Relaxed)
    {
        return;
    }
    let gatts_if = BLE_GATT_IF.load(Ordering::Relaxed);
    let conn_id = BLE_GATT_CONN_ID.load(Ordering::Relaxed) as u16;
    let handle = BLE_GATT_TX_HANDLE.load(Ordering::Relaxed) as u16;
    if gatts_if == 0xff || handle == 0 {
        return;
    }
    for chunk in data.chunks(180) {
        let mut buf = [0_u8; 180];
        buf[..chunk.len()].copy_from_slice(chunk);
        unsafe {
            let _ = sys::esp_ble_gatts_send_indicate(
                gatts_if,
                conn_id,
                handle,
                chunk.len() as u16,
                buf.as_mut_ptr(),
                false,
            );
        }
        BLE_GATT_TX.fetch_add(1, Ordering::Relaxed);
        telemetry::record_packet("ble", Direction::Tx, chunk, "source=gatt_notify");
    }
}

fn default_adv_params() -> sys::esp_ble_adv_params_t {
    sys::esp_ble_adv_params_t {
        adv_int_min: 0x20,
        adv_int_max: 0x40,
        adv_type: sys::esp_ble_adv_type_t_ADV_TYPE_IND,
        own_addr_type: sys::esp_ble_addr_type_t_BLE_ADDR_TYPE_PUBLIC,
        peer_addr: [0; 6],
        peer_addr_type: sys::esp_ble_addr_type_t_BLE_ADDR_TYPE_PUBLIC,
        channel_map: sys::esp_ble_adv_channel_t_ADV_CHNL_ALL,
        adv_filter_policy: sys::esp_ble_adv_filter_t_ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
    }
}

fn gatt_db() -> [sys::esp_gatts_attr_db_t; GATT_IDX_NB] {
    [
        attr(
            sys::ESP_GATT_AUTO_RSP as u8,
            sys::ESP_UUID_LEN_16 as u16,
            ptr16(&UUID_PRI_SERVICE),
            sys::ESP_GATT_PERM_READ as u16,
            16,
            16,
            ptr128(&NORDIC_SERVICE_UUID),
        ),
        attr(
            sys::ESP_GATT_AUTO_RSP as u8,
            sys::ESP_UUID_LEN_16 as u16,
            ptr16(&UUID_CHAR_DECLARE),
            sys::ESP_GATT_PERM_READ as u16,
            1,
            1,
            core::ptr::addr_of_mut!(CHAR_PROP_WRITE),
        ),
        attr(
            sys::ESP_GATT_AUTO_RSP as u8,
            sys::ESP_UUID_LEN_128 as u16,
            ptr128(&NORDIC_RX_UUID),
            sys::ESP_GATT_PERM_WRITE as u16,
            512,
            0,
            core::ptr::addr_of_mut!(RX_VALUE) as *mut u8,
        ),
        attr(
            sys::ESP_GATT_AUTO_RSP as u8,
            sys::ESP_UUID_LEN_16 as u16,
            ptr16(&UUID_CHAR_DECLARE),
            sys::ESP_GATT_PERM_READ as u16,
            1,
            1,
            core::ptr::addr_of_mut!(CHAR_PROP_NOTIFY),
        ),
        attr(
            sys::ESP_GATT_AUTO_RSP as u8,
            sys::ESP_UUID_LEN_128 as u16,
            ptr128(&NORDIC_TX_UUID),
            sys::ESP_GATT_PERM_READ as u16,
            512,
            0,
            core::ptr::addr_of_mut!(TX_VALUE) as *mut u8,
        ),
        attr(
            sys::ESP_GATT_AUTO_RSP as u8,
            sys::ESP_UUID_LEN_16 as u16,
            ptr16(&UUID_CLIENT_CONFIG),
            (sys::ESP_GATT_PERM_READ | sys::ESP_GATT_PERM_WRITE) as u16,
            2,
            2,
            core::ptr::addr_of_mut!(CCC_VALUE) as *mut u8,
        ),
    ]
}

fn attr(
    auto_rsp: u8,
    uuid_length: u16,
    uuid_p: *mut u8,
    perm: u16,
    max_length: u16,
    length: u16,
    value: *mut u8,
) -> sys::esp_gatts_attr_db_t {
    sys::esp_gatts_attr_db_t {
        attr_control: sys::esp_attr_control_t { auto_rsp },
        att_desc: sys::esp_attr_desc_t {
            uuid_length,
            uuid_p,
            perm,
            max_length,
            length,
            value,
        },
    }
}

fn ptr16(value: &'static u16) -> *mut u8 {
    value as *const u16 as *mut u8
}

fn ptr128(value: &'static [u8; 16]) -> *mut u8 {
    value.as_ptr() as *mut u8
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
