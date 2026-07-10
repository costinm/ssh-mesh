use std::collections::VecDeque;
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, bail, Result};
use esp_idf_svc::bt::{Ble, BtDriver};
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};
use crate::transports::dispatch_text_line;

use super::l3dmesh::{Frame, Transport};
use super::settings::{parse_bool, parse_i32};

static BLE_STARTED: AtomicBool = AtomicBool::new(false);
static BLE_ADV_STARTED: AtomicBool = AtomicBool::new(false);
static BLE_SCAN_STARTED: AtomicBool = AtomicBool::new(false);
static BLE_SCAN_REPORTS: AtomicU32 = AtomicU32::new(0);
static BLE_SCAN_MATCHED: AtomicU32 = AtomicU32::new(0);
static BLE_SCAN_LAST_RSSI: AtomicI32 = AtomicI32::new(0);
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
static BLE_NUS_STARTED: AtomicBool = AtomicBool::new(false);
static BLE_NUS_CONNECTED: AtomicBool = AtomicBool::new(false);
static BLE_NUS_NOTIFY_ENABLED: AtomicBool = AtomicBool::new(false);
static BLE_NUS_RX_TEXT: AtomicU32 = AtomicU32::new(0);
static BLE_NUS_RX_BINARY: AtomicU32 = AtomicU32::new(0);
static BLE_NUS_TX: AtomicU32 = AtomicU32::new(0);
static BLE_NUS_GATTS_IF: AtomicU8 = AtomicU8::new(0xff);
static BLE_NUS_CONN_ID: AtomicU32 = AtomicU32::new(0xffff);
static BLE_NUS_TX_HANDLE: AtomicU32 = AtomicU32::new(0);
static BLE_NUS_RX_HANDLE: AtomicU32 = AtomicU32::new(0);
static BLE_NUS_CCC_HANDLE: AtomicU32 = AtomicU32::new(0);
static BLE_NUS_DB_READY: AtomicBool = AtomicBool::new(false);
static BLE_NUS_TEXT_QUEUE: OnceLock<Mutex<VecDeque<Vec<u8>>>> = OnceLock::new();

static mut RAW_ADV_DATA: [u8; 31] = [0; 31];
static mut RAW_ADV_LEN: usize = 0;
static mut NUS_HANDLES: [u16; NUS_IDX_NB] = [0; NUS_IDX_NB];
static mut NUS_DB: MaybeUninit<[sys::esp_gatts_attr_db_t; NUS_IDX_NB]> = MaybeUninit::uninit();

const NUS_APP_ID: u16 = 0x6e40;
const NUS_IDX_SVC: usize = 0;
const NUS_IDX_RX_VAL: usize = 2;
const NUS_IDX_TX_VAL: usize = 4;
const NUS_IDX_TX_CCC: usize = 5;
const NUS_IDX_NB: usize = 6;

const UUID_PRI_SERVICE: u16 = sys::ESP_GATT_UUID_PRI_SERVICE as u16;
const UUID_CHAR_DECLARE: u16 = sys::ESP_GATT_UUID_CHAR_DECLARE as u16;
const UUID_CLIENT_CONFIG: u16 = sys::ESP_GATT_UUID_CHAR_CLIENT_CONFIG as u16;
const NUS_SERVICE_UUID: [u8; 16] = [
    0x9e, 0xca, 0xdc, 0x24, 0x0e, 0xe5, 0xa9, 0xe0, 0x93, 0xf3, 0xa3, 0xb5, 0x01, 0x00, 0x40, 0x6e,
];
const NUS_RX_UUID: [u8; 16] = [
    0x9e, 0xca, 0xdc, 0x24, 0x0e, 0xe5, 0xa9, 0xe0, 0x93, 0xf3, 0xa3, 0xb5, 0x02, 0x00, 0x40, 0x6e,
];
const NUS_TX_UUID: [u8; 16] = [
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
    registry.register(RadioCommand::new("bt"));
}

pub fn ble_transport() -> RadioTransport {
    RadioTransport::new("ble")
}

pub fn bt_transport() -> RadioTransport {
    RadioTransport::new("bt")
}

pub fn poll_text_commands(registry: &mut CommandRegistry) {
    for _ in 0..4 {
        let command = {
            let mut queue = nus_text_queue().lock().unwrap();
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
        send_nus(response.as_bytes());
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
        "ble start=true|raw_adv=hex:...|scan=true|scan_stop=true filter_uuid16=0xfeaa filter_addr=aa:bb:...|stats=true|mode=nus"
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
            return Ok(CommandResponse::ok(format!(
                "ble raw_adv started bytes={}",
                data.len()
            )));
        }
        if let Some(mode) = request.arg("mode") {
            if mode == "nus" || mode == "meshcore" {
                self.ensure_ble()?;
                start_nus()?;
                return Ok(CommandResponse::ok(format!(
                    "ble nus started {}",
                    ble_stats()
                )));
            }
        }
        Ok(CommandResponse::ok(ble_stats()))
    }
}

impl RadioCommand {
    fn ensure_ble(&mut self) -> Result<()> {
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

fn start_nus() -> Result<()> {
    unsafe {
        if !BLE_NUS_DB_READY.load(Ordering::Acquire) {
            core::ptr::addr_of_mut!(NUS_DB).write(MaybeUninit::new(nus_db()));
            BLE_NUS_DB_READY.store(true, Ordering::Release);
        }
        esp_ok(sys::esp_ble_gatt_set_local_mtu(200))?;
        esp_ok(sys::esp_ble_gatts_app_register(NUS_APP_ID))?;
    }
    BLE_NUS_STARTED.store(true, Ordering::Relaxed);
    let adv = nus_adv_data();
    start_raw_adv(&adv)?;
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
        let ptr = core::ptr::addr_of_mut!(RAW_ADV_DATA) as *mut u8;
        core::ptr::write_bytes(ptr, 0, 31);
        core::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
        RAW_ADV_LEN = data.len();
        esp_ok(sys::esp_ble_gap_config_adv_data_raw(
            ptr,
            RAW_ADV_LEN as u32,
        ))?;
    }
    Ok(())
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
        esp_ok(sys::esp_ble_gap_set_scan_params(&mut params))?;
        esp_ok(sys::esp_ble_gap_start_scanning(duration))?;
    }
    BLE_SCAN_STARTED.store(true, Ordering::Relaxed);
    Ok(())
}

unsafe extern "C" fn gap_cb(
    event: sys::esp_gap_ble_cb_event_t,
    param: *mut sys::esp_ble_gap_cb_param_t,
) {
    if event == sys::esp_gap_ble_cb_event_t_ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT {
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
            let _ = sys::esp_ble_gap_start_advertising(&mut params);
        }
        BLE_ADV_STARTED.store(true, Ordering::Relaxed);
        return;
    }
    if event == sys::esp_gap_ble_cb_event_t_ESP_GAP_BLE_SCAN_RESULT_EVT && !param.is_null() {
        let result = unsafe { (*param).scan_rst };
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
        "ble started={} adv={} scan={} reports={} matched={} last_rssi={} filter_uuid16=0x{:04x} filter_addr={} nus_started={} nus_connected={} notify={} nus_rx_text={} nus_rx_binary={} nus_tx={}",
        BLE_STARTED.load(Ordering::Relaxed),
        BLE_ADV_STARTED.load(Ordering::Relaxed),
        BLE_SCAN_STARTED.load(Ordering::Relaxed),
        BLE_SCAN_REPORTS.load(Ordering::Relaxed),
        BLE_SCAN_MATCHED.load(Ordering::Relaxed),
        BLE_SCAN_LAST_RSSI.load(Ordering::Relaxed),
        BLE_FILTER_UUID16.load(Ordering::Relaxed),
        BLE_FILTER_ADDR_ENABLED.load(Ordering::Relaxed),
        BLE_NUS_STARTED.load(Ordering::Relaxed),
        BLE_NUS_CONNECTED.load(Ordering::Relaxed),
        BLE_NUS_NOTIFY_ENABLED.load(Ordering::Relaxed),
        BLE_NUS_RX_TEXT.load(Ordering::Relaxed),
        BLE_NUS_RX_BINARY.load(Ordering::Relaxed),
        BLE_NUS_TX.load(Ordering::Relaxed)
    )
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
            if reg.app_id == NUS_APP_ID && reg.status == sys::esp_gatt_status_t_ESP_GATT_OK {
                BLE_NUS_GATTS_IF.store(gatts_if, Ordering::Relaxed);
                unsafe {
                    if BLE_NUS_DB_READY.load(Ordering::Acquire) {
                        let db = core::ptr::addr_of!(NUS_DB) as *const sys::esp_gatts_attr_db_t;
                        let _ =
                            sys::esp_ble_gatts_create_attr_tab(db, gatts_if, NUS_IDX_NB as u16, 0);
                    }
                }
            }
        }
        x if x == sys::esp_gatts_cb_event_t_ESP_GATTS_CREAT_ATTR_TAB_EVT => {
            let add = unsafe { (*param).add_attr_tab };
            if add.status == sys::esp_gatt_status_t_ESP_GATT_OK
                && add.num_handle as usize == NUS_IDX_NB
                && !add.handles.is_null()
            {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        add.handles,
                        core::ptr::addr_of_mut!(NUS_HANDLES) as *mut u16,
                        NUS_IDX_NB,
                    );
                    BLE_NUS_RX_HANDLE.store(NUS_HANDLES[NUS_IDX_RX_VAL] as u32, Ordering::Relaxed);
                    BLE_NUS_TX_HANDLE.store(NUS_HANDLES[NUS_IDX_TX_VAL] as u32, Ordering::Relaxed);
                    BLE_NUS_CCC_HANDLE.store(NUS_HANDLES[NUS_IDX_TX_CCC] as u32, Ordering::Relaxed);
                    let _ = sys::esp_ble_gatts_start_service(NUS_HANDLES[NUS_IDX_SVC]);
                }
            }
        }
        x if x == sys::esp_gatts_cb_event_t_ESP_GATTS_CONNECT_EVT => {
            let connect = unsafe { (*param).connect };
            BLE_NUS_CONN_ID.store(connect.conn_id as u32, Ordering::Relaxed);
            BLE_NUS_GATTS_IF.store(gatts_if, Ordering::Relaxed);
            BLE_NUS_CONNECTED.store(true, Ordering::Relaxed);
        }
        x if x == sys::esp_gatts_cb_event_t_ESP_GATTS_DISCONNECT_EVT => {
            BLE_NUS_CONNECTED.store(false, Ordering::Relaxed);
            BLE_NUS_NOTIFY_ENABLED.store(false, Ordering::Relaxed);
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
            if write.handle as u32 == BLE_NUS_CCC_HANDLE.load(Ordering::Relaxed) && data.len() >= 2
            {
                BLE_NUS_NOTIFY_ENABLED.store(data[0] & 0x01 != 0, Ordering::Relaxed);
            } else if write.handle as u32 == BLE_NUS_RX_HANDLE.load(Ordering::Relaxed) {
                let response = handle_nus_rx(data);
                send_nus(&response);
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

fn handle_nus_rx(data: &[u8]) -> Vec<u8> {
    if data
        .first()
        .map(|b| is_meshcore_binary_tag(*b))
        .unwrap_or(false)
    {
        BLE_NUS_RX_BINARY.fetch_add(1, Ordering::Relaxed);
        return meshcore_response(data);
    }
    if data.first().map(|b| b.is_ascii()).unwrap_or(false) {
        BLE_NUS_RX_TEXT.fetch_add(1, Ordering::Relaxed);
        queue_nus_text(data);
        return Vec::new();
    }
    BLE_NUS_RX_BINARY.fetch_add(1, Ordering::Relaxed);
    vec![0x01, 0x01]
}

fn is_meshcore_binary_tag(byte: u8) -> bool {
    (0x01..=0x1b).contains(&byte) || byte >= 0x80
}

fn meshcore_response(data: &[u8]) -> Vec<u8> {
    match data[0] {
        0x01 => meshcore_self_info(),
        0x16 => meshcore_device_info(),
        _ => vec![0x01, 0x02],
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
    out.push(11);
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
    push_fixed_ascii(&mut out, b"ESP32 Rust NUS", 40);
    push_fixed_ascii(&mut out, b"meshcore-compat", 20);
    out
}

fn push_fixed_ascii(out: &mut Vec<u8>, value: &[u8], width: usize) {
    let used = value.len().min(width);
    out.extend_from_slice(&value[..used]);
    out.resize(out.len() + width - used, 0);
}

fn queue_nus_text(data: &[u8]) {
    let mut queue = nus_text_queue().lock().unwrap();
    if queue.len() >= 8 {
        let _ = queue.pop_front();
    }
    queue.push_back(data.to_vec());
}

fn nus_text_queue() -> &'static Mutex<VecDeque<Vec<u8>>> {
    BLE_NUS_TEXT_QUEUE.get_or_init(|| Mutex::new(VecDeque::new()))
}

fn send_nus(data: &[u8]) {
    if !BLE_NUS_CONNECTED.load(Ordering::Relaxed) || !BLE_NUS_NOTIFY_ENABLED.load(Ordering::Relaxed)
    {
        return;
    }
    let gatts_if = BLE_NUS_GATTS_IF.load(Ordering::Relaxed);
    let conn_id = BLE_NUS_CONN_ID.load(Ordering::Relaxed) as u16;
    let handle = BLE_NUS_TX_HANDLE.load(Ordering::Relaxed) as u16;
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
        BLE_NUS_TX.fetch_add(1, Ordering::Relaxed);
    }
}

fn nus_adv_data() -> Vec<u8> {
    vec![
        0x02, 0x01, 0x06, 0x11, 0x07, 0x9e, 0xca, 0xdc, 0x24, 0x0e, 0xe5, 0xa9, 0xe0, 0x93, 0xf3,
        0xa3, 0xb5, 0x01, 0x00, 0x40, 0x6e, 0x09, 0x09, b'M', b'e', b's', b'h', b'C', b'o', b'r',
        b'e',
    ]
}

fn nus_db() -> [sys::esp_gatts_attr_db_t; NUS_IDX_NB] {
    [
        attr(
            sys::ESP_GATT_AUTO_RSP as u8,
            sys::ESP_UUID_LEN_16 as u16,
            ptr16(&UUID_PRI_SERVICE),
            sys::ESP_GATT_PERM_READ as u16,
            16,
            16,
            ptr128(&NUS_SERVICE_UUID),
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
            ptr128(&NUS_RX_UUID),
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
            ptr128(&NUS_TX_UUID),
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

fn esp_ok(ret: sys::esp_err_t) -> Result<()> {
    if ret == sys::ESP_OK {
        Ok(())
    } else {
        bail!("esp_err=0x{ret:x}")
    }
}
