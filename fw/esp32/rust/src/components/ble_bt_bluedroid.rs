use std::collections::VecDeque;
use std::ffi::CString;
use std::mem::size_of;
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

use super::frames::{decode_frame, hex_bytes};
use super::settings::{parse_bool, parse_i32, SharedSettings};
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
static BLE_GATT_AUTHENTICATED: AtomicBool = AtomicBool::new(false);
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
static BLE_ADV_START_DONE: AtomicBool = AtomicBool::new(false);
static BLE_ADV_START_STATUS: AtomicU32 = AtomicU32::new(0xffff);
static BLE_SECURITY_CONFIGURED: AtomicBool = AtomicBool::new(false);
static BLE_COMPANION_ENABLED: AtomicBool = AtomicBool::new(false);
static BLE_COMPANION_SAVE_PENDING: AtomicBool = AtomicBool::new(false);
static BLE_PAIRING_DEADLINE_MS: AtomicU32 = AtomicU32::new(0);
static BLE_PAIRING_ACCEPTED: AtomicBool = AtomicBool::new(false);
static BLE_PAIRING_REQUEST_DEADLINE_MS: AtomicU32 = AtomicU32::new(0);
static BLE_PAIRING_CONFIRM_TIMEOUT_MS: AtomicU32 = AtomicU32::new(60_000);
static BLE_FIXED_PIN: AtomicU32 = AtomicU32::new(0);
static BLE_PENDING_NOTIFY: AtomicBool = AtomicBool::new(false);
static BLE_COMPANION_ADV_PERIOD_MS: AtomicU32 = AtomicU32::new(0);
static BLE_COMPANION_ADV_WINDOW_MS: AtomicU32 = AtomicU32::new(0);
static BLE_COMPANION_ADV_STATE: AtomicBool = AtomicBool::new(false);
static BLE_COMPANION_ADV_NEXT_MS: AtomicU32 = AtomicU32::new(0);
static BLE_COMPANION_ACTIVE_MS: AtomicU32 = AtomicU32::new(10_000);
static BLE_COMPANION_ACTIVE_DEADLINE_MS: AtomicU32 = AtomicU32::new(0);
static BLE_COMPANION_ACTIVE_CHANGED: AtomicBool = AtomicBool::new(false);
static BLE_ADV_INT_MIN: AtomicU32 = AtomicU32::new(0x20);
static BLE_ADV_INT_MAX: AtomicU32 = AtomicU32::new(0x40);
#[cfg(target_feature = "esp32s3ops")]
const BLE_EXT_ADV_INSTANCE: u8 = 0;
#[cfg(target_feature = "esp32s3ops")]
static BLE_EXT_ADV_ADDR_DONE: AtomicBool = AtomicBool::new(false);
#[cfg(target_feature = "esp32s3ops")]
static BLE_EXT_ADV_ADDR_STATUS: AtomicU32 = AtomicU32::new(0xffff);
#[cfg(target_feature = "esp32s3ops")]
static BLE_EXT_ADV_PARAMS_DONE: AtomicBool = AtomicBool::new(false);
#[cfg(target_feature = "esp32s3ops")]
static BLE_EXT_ADV_PARAMS_STATUS: AtomicU32 = AtomicU32::new(0xffff);
#[cfg(target_feature = "esp32s3ops")]
static BLE_EXT_ADV_DATA_DONE: AtomicBool = AtomicBool::new(false);
#[cfg(target_feature = "esp32s3ops")]
static BLE_EXT_ADV_DATA_STATUS: AtomicU32 = AtomicU32::new(0xffff);
#[cfg(target_feature = "esp32s3ops")]
static BLE_EXT_ADV_START_DONE: AtomicBool = AtomicBool::new(false);
#[cfg(target_feature = "esp32s3ops")]
static BLE_EXT_ADV_START_STATUS: AtomicU32 = AtomicU32::new(0xffff);
static BLE_CONNECTED_ADDR: [AtomicU8; 6] = [
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
];
static BLE_PAIRED_ADDR: [AtomicU8; 6] = [
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
];
static BLE_PAIRING_REQUEST_ADDR: [AtomicU8; 6] = [
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
];

static mut RAW_ADV_DATA: [u8; 31] = [0; 31];
static mut RAW_ADV_LEN: usize = 0;
static mut PENDING_ADV_DATA: [u8; 31] = [0; 31];
static mut PENDING_ADV_LEN: usize = 0;
static mut GATT_HANDLES: [u16; GATT_IDX_NB] = [0; GATT_IDX_NB];
static mut GATT_DB: MaybeUninit<[sys::esp_gatts_attr_db_t; GATT_IDX_NB]> = MaybeUninit::uninit();

pub const DMESH_BLE_SERVICE_UUID16: u16 = 0xfd5d;
pub const DMESH_BLE_PAIRING_UUID: [u8; 16] = [
    0x01, 0x00, 0x68, 0x73, 0x65, 0x4d, 0x42, 0x8c, 0x6f, 0x4a, 0x2a, 0x4f, 0x80, 0x6f, 0x6b, 0x5f,
];
pub const DMESH_BLE_OPERATIONAL_UUID: [u8; 16] = [
    0x02, 0x00, 0x68, 0x73, 0x65, 0x4d, 0x42, 0x8c, 0x6f, 0x4a, 0x2a, 0x4f, 0x80, 0x6f, 0x6b, 0x5f,
];
const BLE_MODE_OFF: u8 = 0;
const BLE_MODE_LISTEN: u8 = 1;
const BLE_MODE_ANNOUNCE: u8 = 2;
const BLE_MODE_CONNECTABLE: u8 = 3;
pub const PAIRING_RECOVERY_WINDOW_MS: u32 = 300_000;
const GATT_APP_ID: u16 = 0x6e40;
const GATT_IDX_SVC: usize = 0;
const GATT_IDX_RX_VAL: usize = 2;
const GATT_IDX_TX_VAL: usize = 4;
const GATT_IDX_TX_CCC: usize = 5;
const GATT_IDX_NB: usize = 6;

const UUID_PRI_SERVICE: u16 = sys::ESP_GATT_UUID_PRI_SERVICE as u16;
const UUID_CHAR_DECLARE: u16 = sys::ESP_GATT_UUID_CHAR_DECLARE as u16;
const UUID_CLIENT_CONFIG: u16 = sys::ESP_GATT_UUID_CHAR_CLIENT_CONFIG as u16;
pub const DMESH_GATT_SERVICE_UUID: [u8; 16] = [
    0x03, 0x00, 0x68, 0x73, 0x65, 0x4d, 0x42, 0x8c, 0x6f, 0x4a, 0x2a, 0x4f, 0x80, 0x6f, 0x6b, 0x5f,
];
pub const DMESH_GATT_RX_UUID: [u8; 16] = [
    0x04, 0x00, 0x68, 0x73, 0x65, 0x4d, 0x42, 0x8c, 0x6f, 0x4a, 0x2a, 0x4f, 0x80, 0x6f, 0x6b, 0x5f,
];
pub const DMESH_GATT_TX_UUID: [u8; 16] = [
    0x05, 0x00, 0x68, 0x73, 0x65, 0x4d, 0x42, 0x8c, 0x6f, 0x4a, 0x2a, 0x4f, 0x80, 0x6f, 0x6b, 0x5f,
];
static mut RX_VALUE: [u8; 512] = [0; 512];
static mut TX_VALUE: [u8; 512] = [0; 512];
static mut CCC_VALUE: [u8; 2] = [0; 2];
static mut CHAR_PROP_WRITE: u8 =
    sys::ESP_GATT_CHAR_PROP_BIT_WRITE_NR as u8 | sys::ESP_GATT_CHAR_PROP_BIT_WRITE as u8;
static mut CHAR_PROP_NOTIFY: u8 = sys::ESP_GATT_CHAR_PROP_BIT_NOTIFY as u8;

unsafe fn ble_gap_stop_scanning() -> sys::esp_err_t {
    #[cfg(target_feature = "esp32s3ops")]
    {
        sys::esp_ble_gap_stop_ext_scan()
    }
    #[cfg(not(target_feature = "esp32s3ops"))]
    {
        sys::esp_ble_gap_stop_scanning()
    }
}

unsafe fn ble_gap_stop_advertising() -> sys::esp_err_t {
    sys::esp_ble_gap_stop_advertising()
}

unsafe fn ble_gap_config_adv_data_raw(raw_data: *mut u8, raw_data_len: u32) -> sys::esp_err_t {
    sys::esp_ble_gap_config_adv_data_raw(raw_data, raw_data_len)
}

unsafe fn ble_gap_set_scan_params(params: *mut sys::esp_ble_scan_params_t) -> sys::esp_err_t {
    #[cfg(target_feature = "esp32s3ops")]
    {
        let params = &*params;
        let ext = sys::esp_ble_ext_scan_params_t {
            own_addr_type: params.own_addr_type,
            filter_policy: params.scan_filter_policy,
            scan_duplicate: params.scan_duplicate,
            cfg_mask: sys::ESP_BLE_GAP_PHY_1M_PREF_MASK as u8,
            uncoded_cfg: sys::esp_ble_ext_scan_cfg_t {
                scan_type: params.scan_type,
                scan_interval: params.scan_interval,
                scan_window: params.scan_window,
            },
            coded_cfg: sys::esp_ble_ext_scan_cfg_t::default(),
        };
        sys::esp_ble_gap_set_ext_scan_params(&ext)
    }
    #[cfg(not(target_feature = "esp32s3ops"))]
    {
        sys::esp_ble_gap_set_scan_params(params)
    }
}

unsafe fn ble_gap_start_scanning(duration: u32) -> sys::esp_err_t {
    #[cfg(target_feature = "esp32s3ops")]
    {
        sys::esp_ble_gap_start_ext_scan(duration, 0)
    }
    #[cfg(not(target_feature = "esp32s3ops"))]
    {
        sys::esp_ble_gap_start_scanning(duration)
    }
}

unsafe fn ble_gap_start_advertising(params: *mut sys::esp_ble_adv_params_t) -> sys::esp_err_t {
    sys::esp_ble_gap_start_advertising(params)
}

#[cfg(target_feature = "esp32s3ops")]
fn ext_adv_params() -> sys::esp_ble_gap_ext_adv_params_t {
    sys::esp_ble_gap_ext_adv_params_t {
        type_: sys::ESP_BLE_GAP_SET_EXT_ADV_PROP_CONNECTABLE as u16,
        interval_min: BLE_ADV_INT_MIN.load(Ordering::Relaxed),
        interval_max: BLE_ADV_INT_MAX.load(Ordering::Relaxed),
        channel_map: sys::esp_ble_adv_channel_t_ADV_CHNL_ALL,
        own_addr_type: sys::esp_ble_addr_type_t_BLE_ADDR_TYPE_PUBLIC,
        peer_addr_type: sys::esp_ble_addr_type_t_BLE_ADDR_TYPE_PUBLIC,
        peer_addr: [0; 6],
        filter_policy: sys::esp_ble_adv_filter_t_ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
        tx_power: sys::EXT_ADV_TX_PWR_NO_PREFERENCE as i8,
        primary_phy: sys::ESP_BLE_GAP_PHY_1M as u8,
        max_skip: 0,
        secondary_phy: sys::ESP_BLE_GAP_PHY_1M as u8,
        sid: 0,
        scan_req_notif: false,
    }
}

#[cfg(target_feature = "esp32s3ops")]
fn ext_adv_random_addr() -> [u8; 6] {
    let mut addr = [0_u8; 6];
    let ret = unsafe { sys::esp_ble_gap_addr_create_static(addr.as_mut_ptr()) };
    if ret == sys::ESP_OK {
        return addr;
    }
    [0xc0, 0xde, 0x5d, 0x00, 0x00, 0x01]
}

#[cfg(target_feature = "esp32s3ops")]
fn wait_ext_adv_stage(
    label: &'static str,
    done: &AtomicBool,
    status: &AtomicU32,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if done.load(Ordering::Relaxed) {
            let status = status.load(Ordering::Relaxed);
            if status == 0 {
                return Ok(());
            }
            bail!("{label} status=0x{status:x}");
        }
        unsafe {
            sys::vTaskDelay(duration_to_ticks(Duration::from_millis(10)));
        }
    }
    bail!("{label} timeout")
}

#[cfg(target_feature = "esp32s3ops")]
unsafe fn request_ext_adv_params() -> sys::esp_err_t {
    BLE_EXT_ADV_PARAMS_DONE.store(false, Ordering::Relaxed);
    BLE_EXT_ADV_PARAMS_STATUS.store(0xffff, Ordering::Relaxed);
    let params = ext_adv_params();
    sys::esp_ble_gap_ext_adv_set_params(BLE_EXT_ADV_INSTANCE, &params)
}

fn wait_legacy_adv_started(timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if BLE_ADV_START_DONE.load(Ordering::Relaxed) {
            let status = BLE_ADV_START_STATUS.load(Ordering::Relaxed);
            if status == 0 {
                return Ok(());
            }
            bail!("legacy_adv_start status=0x{status:x}");
        }
        unsafe {
            sys::vTaskDelay(duration_to_ticks(Duration::from_millis(10)));
        }
    }
    bail!("legacy_adv_start timeout")
}

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    {
        let settings_ref = settings.borrow();
        BLE_COMPANION_ENABLED.store(
            settings_ref.get_bool("ble.comp", false).unwrap_or(false),
            Ordering::Relaxed,
        );
        BLE_FIXED_PIN.store(
            settings_ref
                .get_i32("ble.fixed_pin", 0)
                .unwrap_or(0)
                .clamp(0, 999_999) as u32,
            Ordering::Relaxed,
        );
    }
    registry.register(RadioCommand::with_settings("ble", settings));
}

pub fn advertised_identity() -> String {
    format!(
        "mac={} adv_uuid={} pair_uuid={} gatt_service={} gatt_rx={} gatt_tx={}",
        public_bt_address_string(),
        uuid128_string(&DMESH_BLE_OPERATIONAL_UUID),
        uuid128_string(&DMESH_BLE_PAIRING_UUID),
        uuid128_string(&DMESH_GATT_SERVICE_UUID),
        uuid128_string(&DMESH_GATT_RX_UUID),
        uuid128_string(&DMESH_GATT_TX_UUID)
    )
}

pub fn uuid128_string(uuid: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        uuid[15],
        uuid[14],
        uuid[13],
        uuid[12],
        uuid[11],
        uuid[10],
        uuid[9],
        uuid[8],
        uuid[7],
        uuid[6],
        uuid[5],
        uuid[4],
        uuid[3],
        uuid[2],
        uuid[1],
        uuid[0]
    )
}

fn public_bt_address_string() -> String {
    let mut mac = [0_u8; 6];
    let ret = unsafe { sys::esp_read_mac(mac.as_mut_ptr(), sys::esp_mac_type_t_ESP_MAC_BT) };
    if ret == sys::ESP_OK {
        format_mac(&mac)
    } else {
        format!("unavailable err={ret}")
    }
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

pub fn stop_radio_activity() {
    unsafe {
        if BLE_SCAN_STARTED.load(Ordering::Relaxed) {
            let _ = ble_gap_stop_scanning();
        }
        if BLE_ADV_STARTED.load(Ordering::Relaxed) {
            let _ = ble_gap_stop_advertising();
        }
    }
    BLE_SCAN_STARTED.store(false, Ordering::Relaxed);
    BLE_ADV_STARTED.store(false, Ordering::Relaxed);
    BLE_ADV_PENDING.store(false, Ordering::Relaxed);
    BLE_SCAN_STOPPING.store(false, Ordering::Relaxed);
    BLE_MODE.store(BLE_MODE_OFF, Ordering::Relaxed);
}

fn restart_advertising_after_disconnect() -> bool {
    matches!(
        BLE_MODE.load(Ordering::Relaxed),
        BLE_MODE_CONNECTABLE | BLE_MODE_ANNOUNCE
    ) || pairing_open()
        || BLE_PENDING_NOTIFY.load(Ordering::Relaxed)
        || companion_active()
}

pub fn configure_companion_advertising(period_ms: u32, window_ms: u32) {
    let window_ms = window_ms.min(period_ms);
    BLE_COMPANION_ADV_PERIOD_MS.store(period_ms, Ordering::Relaxed);
    BLE_COMPANION_ADV_WINDOW_MS.store(window_ms, Ordering::Relaxed);
    BLE_COMPANION_ADV_STATE.store(false, Ordering::Relaxed);
    BLE_COMPANION_ADV_NEXT_MS.store(now_ms().wrapping_add(200), Ordering::Relaxed);
}

pub fn configure_companion_active_window(timeout_ms: u32) {
    BLE_COMPANION_ACTIVE_MS.store(timeout_ms.max(1_000), Ordering::Relaxed);
}

pub fn open_companion_active_window(timeout_ms: u32) {
    if timeout_ms == 0 {
        BLE_COMPANION_ACTIVE_DEADLINE_MS.store(0, Ordering::Relaxed);
        BLE_COMPANION_ACTIVE_CHANGED.store(true, Ordering::Relaxed);
        stop_radio_activity();
        return;
    }
    BLE_COMPANION_ACTIVE_DEADLINE_MS.store(now_ms().wrapping_add(timeout_ms), Ordering::Relaxed);
    BLE_COMPANION_ACTIVE_CHANGED.store(true, Ordering::Relaxed);
    if BLE_COMPANION_ENABLED.load(Ordering::Relaxed) {
        let _ = start_connectable_idle();
    }
    telemetry::record_log(format!(
        "event type=ble.companion active=true timeout_ms={}",
        timeout_ms
    ));
}

pub fn companion_active() -> bool {
    let deadline = BLE_COMPANION_ACTIVE_DEADLINE_MS.load(Ordering::Relaxed);
    deadline != 0 && deadline.wrapping_sub(now_ms()) < i32::MAX as u32
}

pub fn take_companion_active_changed() -> bool {
    BLE_COMPANION_ACTIVE_CHANGED.swap(false, Ordering::Relaxed)
}

pub fn poll_text_commands(registry: &mut CommandRegistry) {
    poll_companion_advertising();
    if BLE_COMPANION_SAVE_PENDING.swap(false, Ordering::Relaxed) {
        let peer = paired_addr_string();
        let command = format!("ble companion=true save=true peer={peer}");
        let response = dispatch_text_line(registry, &command);
        let line = format!(
            "event type=ble.companion save=true response={}",
            crate::commands::protocol::escape_value(response.trim())
        );
        telemetry::record_log(line.clone());
        telemetry::emit_console(&line);
        let response = dispatch_text_line(registry, "mode companion=true save=true");
        let line = format!(
            "event type=ble.companion mode=companion response={}",
            crate::commands::protocol::escape_value(response.trim())
        );
        telemetry::record_log(line.clone());
        telemetry::emit_console(&line);
    }
    if BLE_PENDING_NOTIFY.load(Ordering::Relaxed) && companion_link_ready() {
        notify_companion_pending();
    }
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
        let mut response = response.into_bytes();
        if !response.ends_with(b"\n") {
            response.push(b'\n');
        }
        send_gatt(&response);
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
    wait_gatt_service_ready(Duration::from_millis(1_000))?;
    let adv = dmesh_adv_data(event, packet, metrics)?;
    start_raw_adv(&adv)?;
    send_gatt(packet);
    BLE_ANNOUNCE_TX.fetch_add(1, Ordering::Relaxed);
    BLE_MODE.store(BLE_MODE_CONNECTABLE, Ordering::Relaxed);
    telemetry::record_packet("ble", Direction::Tx, &adv, "announce=true");
    Ok(())
}

pub fn open_pairing_window(timeout_ms: u32) {
    if timeout_ms == 0 {
        BLE_PAIRING_DEADLINE_MS.store(0, Ordering::Relaxed);
        BLE_PAIRING_ACCEPTED.store(false, Ordering::Relaxed);
        BLE_PAIRING_REQUEST_DEADLINE_MS.store(0, Ordering::Relaxed);
        telemetry::record_log("event type=ble.pairing state=closed");
        return;
    }
    let deadline = now_ms().wrapping_add(timeout_ms);
    BLE_PAIRING_DEADLINE_MS.store(deadline, Ordering::Relaxed);
    BLE_PAIRING_ACCEPTED.store(false, Ordering::Relaxed);
    telemetry::record_log(format!(
        "event type=ble.pairing state=open timeout_ms={}",
        timeout_ms
    ));
    if let Err(err) = start_pairable_advertising() {
        telemetry::record_log(format!(
            "event type=ble.pairing advertise=false msg={}",
            crate::commands::protocol::escape_value(&err.to_string())
        ));
        let _ = start_connectable_idle();
    }
}

pub fn request_pairing(request_timeout_ms: u32, confirm_timeout_ms: u32) {
    let request_timeout_ms = request_timeout_ms.clamp(1_000, 300_000);
    let confirm_timeout_ms = confirm_timeout_ms.clamp(1_000, 300_000);
    let addr = connected_addr();
    set_pairing_request_addr(&addr);
    BLE_PAIRING_CONFIRM_TIMEOUT_MS.store(confirm_timeout_ms, Ordering::Relaxed);
    BLE_PAIRING_REQUEST_DEADLINE_MS
        .store(now_ms().wrapping_add(request_timeout_ms), Ordering::Relaxed);
    BLE_PAIRING_DEADLINE_MS.store(0, Ordering::Relaxed);
    BLE_PAIRING_ACCEPTED.store(false, Ordering::Relaxed);
    telemetry::record_log(format!(
        "event type=ble.pairing state=requested request_timeout_ms={} confirm_timeout_ms={} peer={}",
        request_timeout_ms,
        confirm_timeout_ms,
        format_mac(&addr)
    ));
    let _ = start_connectable_idle();
}

pub fn start_pairing_recovery(settings: &SharedSettings) -> Result<usize> {
    super::nan::stop_nan().ok();
    super::wifi::stop_raw_monitor().ok();
    super::lora::sleep_radio(settings).ok();
    let mut radio = RadioCommand::with_settings("ble", settings.clone());
    radio.ensure_ble()?;
    start_gatt()?;
    wait_gatt_service_ready(Duration::from_millis(1_000))?;
    let removed = reset_pairing_state();
    {
        let mut settings = settings.borrow_mut();
        settings.set_str("mode", "infra")?;
        settings.set_bool("ble.comp", false)?;
        settings.set_str("ble.peer", "")?;
    }
    open_pairing_window(PAIRING_RECOVERY_WINDOW_MS);
    if !BLE_ADV_STARTED.load(Ordering::Relaxed) {
        bail!("pairing recovery advertising did not start");
    }
    telemetry::emit_console(&format!(
        "event type=ble.pairing_recovery advertise=true bonds_removed={} {}",
        removed,
        advertised_identity()
    ));
    telemetry::record_log(format!(
        "event type=ble.pairing_recovery active=true bonds_removed={}",
        removed
    ));
    Ok(removed)
}

pub fn confirm_pairing_request() -> bool {
    if !pairing_requested() {
        telemetry::record_log("event type=ble.pairing state=ignored reason=no_request");
        return false;
    }
    let timeout_ms = BLE_PAIRING_CONFIRM_TIMEOUT_MS.load(Ordering::Relaxed);
    let requested = pairing_request_addr();
    let connected = connected_addr();
    BLE_PAIRING_REQUEST_DEADLINE_MS.store(0, Ordering::Relaxed);
    open_pairing_window(timeout_ms);
    if BLE_GATT_CONNECTED.load(Ordering::Relaxed) && requested == connected {
        unsafe {
            let _ = sys::esp_ble_set_encryption(
                connected.as_ptr() as *mut u8,
                sys::esp_ble_sec_act_t_ESP_BLE_SEC_ENCRYPT_NO_MITM,
            );
        }
    }
    telemetry::record_log(format!(
        "event type=ble.pairing state=confirmed timeout_ms={} peer={}",
        timeout_ms,
        format_mac(&requested)
    ));
    true
}

pub fn companion_message_ready(packet: &[u8]) {
    if !BLE_COMPANION_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    if companion_link_ready() {
        notify_companion_pending();
    } else if let Err(err) = announce_packet(DmeshBleEvent::PayloadPending, packet, None) {
        telemetry::record_log(format!(
            "event type=ble.companion action=advertise ok=false err={}",
            crate::commands::protocol::escape_value(&err.to_string())
        ));
    } else {
        BLE_PENDING_NOTIFY.store(true, Ordering::Relaxed);
    }
}

pub fn companion_queue_empty() {
    BLE_PENDING_NOTIFY.store(false, Ordering::Relaxed);
    if BLE_COMPANION_ENABLED.load(Ordering::Relaxed) {
        if BLE_COMPANION_ADV_WINDOW_MS.load(Ordering::Relaxed) == 0 {
            stop_radio_activity();
        }
    }
}

pub fn start_connectable_advertising() -> Result<()> {
    start_connectable_idle()
}

pub fn gatt_connected() -> bool {
    BLE_GATT_CONNECTED.load(Ordering::Relaxed)
}

pub fn set_advertising_interval_ms(min_ms: u32, max_ms: u32) {
    let min = adv_ms_to_units(min_ms);
    let max = adv_ms_to_units(max_ms).max(min);
    BLE_ADV_INT_MIN.store(min, Ordering::Relaxed);
    BLE_ADV_INT_MAX.store(max, Ordering::Relaxed);
    telemetry::record_log(format!(
        "event type=ble.adv_interval min_ms={} max_ms={} min_units={} max_units={}",
        min_ms, max_ms, min, max
    ));
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
    fn name(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::LoraRx => "lora_rx",
            Self::IdleHello => "idle_hello",
            Self::WakeRequest => "wake_request",
            Self::PayloadPending => "payload_pending",
        }
    }
}

struct RadioCommand {
    name: &'static str,
    enabled: bool,
    mtu: usize,
    bt: Option<BtDriver<'static, Ble>>,
    settings: Option<SharedSettings>,
}

impl RadioCommand {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            enabled: true,
            mtu: 512,
            bt: None,
            settings: None,
        }
    }

    fn with_settings(name: &'static str, settings: SharedSettings) -> Self {
        let mut command = Self::new(name);
        command.settings = Some(settings);
        command
    }
}

impl CommandHandler for RadioCommand {
    fn name(&self) -> &'static str {
        self.name
    }

    fn help(&self) -> &'static str {
        "ble start=true|stop=true|mode=listen|gatt|announce|connectable|pairable=true|advertise=true payload=hex:... event=generic|lora_rx|wake_request|payload_pending|announce=hex:...|send=hex:...|raw_adv=hex:...|scan=true filter=dmesh|all scan_stop=true filter_uuid16=0xfd5d(legacy) filter_addr=aa:bb:...|companion=true save=true pairing=true|request|confirm timeout_ms=60000 confirm_ms=60000 fixed_pin=1234 pairing_recovery=true reset_pairing=true stats=true bonds=true"
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
        if let Some(pin) = request
            .arg_i32("fixed_pin")?
            .or(request.arg_i32("pin")?)
            .or(request.arg_i32("passkey")?)
        {
            let pin = pin.clamp(0, 999_999) as u32;
            BLE_FIXED_PIN.store(pin, Ordering::Relaxed);
            BLE_SECURITY_CONFIGURED.store(false, Ordering::Relaxed);
            if request
                .arg("save")
                .map(parse_bool)
                .transpose()?
                .unwrap_or(false)
            {
                if let Some(settings) = &self.settings {
                    settings.borrow_mut().set_i32("ble.fixed_pin", pin as i32)?;
                }
            }
        }
        if request.arg("adv_ms").is_some()
            || request.arg("adv_min_ms").is_some()
            || request.arg("adv_max_ms").is_some()
        {
            let min_ms = request
                .arg_i32("adv_min_ms")?
                .or(request.arg_i32("adv_ms")?)
                .unwrap_or(1000)
                .max(20) as u32;
            let max_ms = request
                .arg_i32("adv_max_ms")?
                .or(request.arg_i32("adv_ms")?)
                .unwrap_or(min_ms as i32)
                .max(min_ms as i32) as u32;
            set_advertising_interval_ms(min_ms, max_ms);
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
        if request
            .arg("pairing_recovery")
            .or_else(|| request.arg("recovery"))
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            let Some(settings) = &self.settings else {
                bail!("pairing_recovery requires settings");
            };
            let removed = start_pairing_recovery(settings)?;
            return Ok(CommandResponse::ok(format!(
                "ble pairing_recovery=true bonds_removed={} {}",
                removed,
                ble_stats()
            )));
        }
        if let Some(companion) = request.arg("companion") {
            let enabled = parse_bool(companion)?;
            BLE_COMPANION_ENABLED.store(enabled, Ordering::Relaxed);
            if request
                .arg("save")
                .map(parse_bool)
                .transpose()?
                .unwrap_or(false)
            {
                if let Some(settings) = &self.settings {
                    let mut settings = settings.borrow_mut();
                    settings.set_bool("ble.comp", enabled)?;
                    if let Some(peer) = request.arg("peer") {
                        settings.set_str("ble.peer", peer)?;
                    }
                }
            }
            if enabled
                && matches!(
                    request.arg("pairing"),
                    Some("request" | "true" | "1" | "yes" | "on")
                )
            {
                let request_timeout_ms = request
                    .arg_i32("timeout_ms")?
                    .or(request.arg_i32("request_ms")?)
                    .or(request.arg_i32("ms")?)
                    .unwrap_or(120_000)
                    .clamp(1_000, 300_000) as u32;
                let confirm_timeout_ms = request
                    .arg_i32("confirm_timeout_ms")?
                    .or(request.arg_i32("confirm_ms")?)
                    .unwrap_or(60_000)
                    .clamp(1_000, 300_000) as u32;
                self.ensure_ble()?;
                start_gatt()?;
                request_pairing(request_timeout_ms, confirm_timeout_ms);
                open_pairing_window(request_timeout_ms);
                return Ok(CommandResponse::ok(format!(
                    "ble companion=true pairing=open {}",
                    ble_stats()
                )));
            }
            if enabled {
                start_companion_runtime()?;
            }
            return Ok(CommandResponse::ok(ble_stats()));
        }
        if request
            .arg("reset_pairing")
            .or_else(|| request.arg("clear_pairing"))
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            self.ensure_ble()?;
            let removed = reset_pairing_state();
            if request
                .arg("save")
                .map(parse_bool)
                .transpose()?
                .unwrap_or(true)
            {
                if let Some(settings) = &self.settings {
                    let mut settings = settings.borrow_mut();
                    settings.set_bool("ble.comp", false)?;
                    settings.set_str("ble.peer", "")?;
                }
            }
            return Ok(CommandResponse::ok(format!(
                "ble reset_pairing=true bonds_removed={} {}",
                removed,
                ble_stats()
            )));
        }
        if let Some(pairing) = request.arg("pairing") {
            match pairing {
                "request" | "true" | "1" | "yes" | "on" => {
                    let request_timeout_ms = request
                        .arg_i32("timeout_ms")?
                        .or(request.arg_i32("request_ms")?)
                        .or(request.arg_i32("ms")?)
                        .unwrap_or(120_000)
                        .clamp(1_000, 300_000) as u32;
                    let confirm_timeout_ms = request
                        .arg_i32("confirm_timeout_ms")?
                        .or(request.arg_i32("confirm_ms")?)
                        .unwrap_or(60_000)
                        .clamp(1_000, 300_000) as u32;
                    self.ensure_ble()?;
                    start_gatt()?;
                    request_pairing(request_timeout_ms, confirm_timeout_ms);
                    open_pairing_window(request_timeout_ms);
                    return Ok(CommandResponse::ok(ble_stats()));
                }
                "confirm" | "accept" => {
                    self.ensure_ble()?;
                    start_gatt()?;
                    let ok = confirm_pairing_request();
                    return Ok(CommandResponse::ok(format!(
                        "ble pairing_confirmed={} {}",
                        ok,
                        ble_stats()
                    )));
                }
                "false" | "0" | "no" | "off" => {
                    BLE_PAIRING_DEADLINE_MS.store(0, Ordering::Relaxed);
                    BLE_PAIRING_ACCEPTED.store(false, Ordering::Relaxed);
                    BLE_PAIRING_REQUEST_DEADLINE_MS.store(0, Ordering::Relaxed);
                    return Ok(CommandResponse::ok(ble_stats()));
                }
                _ => bail!("unsupported BLE pairing action {pairing}"),
            }
        }
        if request.arg("cancel").is_some() {
            BLE_PAIRING_DEADLINE_MS.store(0, Ordering::Relaxed);
            BLE_PAIRING_ACCEPTED.store(false, Ordering::Relaxed);
            BLE_PAIRING_REQUEST_DEADLINE_MS.store(0, Ordering::Relaxed);
            return Ok(CommandResponse::ok(ble_stats()));
        }
        if request.arg("start").is_some() {
            self.ensure_ble()?;
            start_gatt()?;
            start_scan_params(0, true)?;
            BLE_MODE.store(BLE_MODE_LISTEN, Ordering::Relaxed);
            return Ok(CommandResponse::ok("ble started"));
        }
        if request
            .arg("stop")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
            || request
                .arg("advertise")
                .map(parse_bool)
                .transpose()?
                .is_some_and(|advertise| !advertise)
        {
            stop_radio_activity();
            return Ok(CommandResponse::ok("ble stopped"));
        }
        if request.arg("stats").is_some() {
            return Ok(CommandResponse::ok(ble_stats()));
        }
        if request.arg("bonds").is_some() || request.arg("paired").is_some() {
            return Ok(CommandResponse::ok(ble_bond_status(self.settings.as_ref())));
        }
        if request.arg("scan_stop").is_some() {
            unsafe {
                let _ = ble_gap_stop_scanning();
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
        if request
            .arg("pairable")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            self.ensure_ble()?;
            start_gatt()?;
            start_pairable_advertising()?;
            return Ok(CommandResponse::ok(format!(
                "ble pairable started {}",
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
            unsafe {
                sys::esp_log_level_set(
                    b"*\0".as_ptr().cast(),
                    sys::esp_log_level_t_ESP_LOG_VERBOSE,
                );
            }
            self.bt = Some(BtDriver::<Ble>::new(peripherals.modem, None)?);
            let name = CString::new("DMesh")?;
            unsafe {
                esp_ok(sys::esp_ble_gap_register_callback(Some(gap_cb)))?;
                esp_ok(sys::esp_ble_gatts_register_callback(Some(gatts_cb)))?;
                esp_ok(sys::esp_ble_gap_set_device_name(name.as_ptr()))?;
            }
            configure_security()?;
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

pub fn start_companion_runtime() -> Result<()> {
    let mut radio = RadioCommand::new("ble");
    radio.ensure_ble()?;
    start_gatt()?;
    start_scan_params(0, true)?;
    Ok(())
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

fn wait_gatt_service_ready(timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if BLE_GATT_TX_HANDLE.load(Ordering::Relaxed) != 0
            && BLE_GATT_RX_HANDLE.load(Ordering::Relaxed) != 0
            && BLE_GATT_CCC_HANDLE.load(Ordering::Relaxed) != 0
        {
            return Ok(());
        }
        unsafe {
            sys::vTaskDelay(duration_to_ticks(Duration::from_millis(20)));
        }
    }
    bail!("BLE GATT service not ready")
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
        if BLE_SCAN_STARTED.load(Ordering::Relaxed) {
            BLE_SCAN_STOPPING.store(true, Ordering::Relaxed);
            let stop_ret = ble_gap_stop_scanning();
            if stop_ret == sys::ESP_OK || stop_ret == sys::ESP_ERR_INVALID_STATE {
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
    }
    BLE_ADV_PENDING.store(false, Ordering::Relaxed);
    configure_raw_adv(data)
}

fn configure_raw_adv(data: &[u8]) -> Result<()> {
    unsafe {
        // Bluedroid on ESP32-S3 can report the controller as actively advertising
        // before our local state sees an ADV_START event. Force the controller to
        // a known stopped state before changing advertising data/parameters.
        esp_ok_allow_invalid_state(ble_gap_stop_advertising())?;
        sys::vTaskDelay(duration_to_ticks(Duration::from_millis(250)));
        BLE_SCAN_STARTED.store(false, Ordering::Relaxed);
        BLE_ADV_STARTED.store(false, Ordering::Relaxed);
        let ptr = core::ptr::addr_of_mut!(RAW_ADV_DATA) as *mut u8;
        core::ptr::write_bytes(ptr, 0, 31);
        core::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
        RAW_ADV_LEN = data.len();
        esp_ok(ble_gap_config_adv_data_raw(ptr, RAW_ADV_LEN as u32))?;
        sys::vTaskDelay(duration_to_ticks(Duration::from_millis(30)));
    }
    wait_legacy_adv_started(Duration::from_millis(1_000))?;
    Ok(())
}

fn start_ble_advertising() -> Result<()> {
    let mut params = sys::esp_ble_adv_params_t {
        adv_int_min: BLE_ADV_INT_MIN.load(Ordering::Relaxed) as u16,
        adv_int_max: BLE_ADV_INT_MAX.load(Ordering::Relaxed) as u16,
        adv_type: sys::esp_ble_adv_type_t_ADV_TYPE_IND,
        own_addr_type: sys::esp_ble_addr_type_t_BLE_ADDR_TYPE_PUBLIC,
        peer_addr: [0; 6],
        peer_addr_type: sys::esp_ble_addr_type_t_BLE_ADDR_TYPE_PUBLIC,
        channel_map: sys::esp_ble_adv_channel_t_ADV_CHNL_ALL,
        adv_filter_policy: sys::esp_ble_adv_filter_t_ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
    };
    unsafe {
        BLE_ADV_START_DONE.store(false, Ordering::Relaxed);
        BLE_ADV_START_STATUS.store(0xffff, Ordering::Relaxed);
        esp_ok(ble_gap_start_advertising(&mut params))?;
    }
    BLE_ADV_STARTED.store(true, Ordering::Relaxed);
    Ok(())
}

fn start_connectable_idle() -> Result<()> {
    announce_packet(DmeshBleEvent::IdleHello, &[], None)
}

fn start_pairable_advertising() -> Result<()> {
    start_gatt()?;
    wait_gatt_service_ready(Duration::from_millis(1_000))?;
    let mut adv = Vec::with_capacity(28);
    adv.extend_from_slice(&[0x02, 0x01, 0x06]);
    adv.push((DMESH_BLE_PAIRING_UUID.len() + 1) as u8);
    adv.push(0x07);
    adv.extend_from_slice(&DMESH_BLE_PAIRING_UUID);
    adv.extend_from_slice(&[0x06, 0x08, b'D', b'M', b'e', b's', b'h']);
    start_raw_adv(&adv)?;
    BLE_MODE.store(BLE_MODE_CONNECTABLE, Ordering::Relaxed);
    let line = format!(
        "event type=ble.pairing state=advertising uuid={} name=DMesh adv_raw={} {}",
        uuid128_string(&DMESH_BLE_PAIRING_UUID),
        hex_bytes(&adv),
        advertised_identity()
    );
    telemetry::record_log(line.clone());
    telemetry::emit_console(&line);
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
        esp_ok_allow_invalid_state(ble_gap_stop_advertising())?;
        BLE_ADV_STARTED.store(false, Ordering::Relaxed);
        esp_ok(ble_gap_set_scan_params(&mut params))?;
        esp_ok(ble_gap_start_scanning(duration))?;
    }
    BLE_SCAN_STARTED.store(true, Ordering::Relaxed);
    BLE_ADV_STARTED.store(false, Ordering::Relaxed);
    Ok(())
}

fn dmesh_adv_data(
    _event: DmeshBleEvent,
    packet: &[u8],
    _metrics: Option<(i32, f32)>,
) -> Result<Vec<u8>> {
    let (source, packet_id) = dmesh_adv_ids(packet);
    let pending = telemetry::pending_message_count();
    let battery = battery_level();
    let prefix_len = 0usize;
    let mut service = Vec::with_capacity(16 + 10 + prefix_len);
    service.extend_from_slice(&DMESH_BLE_OPERATIONAL_UUID);
    service.extend_from_slice(&source.to_le_bytes());
    service.extend_from_slice(&packet_id.to_le_bytes());
    service.push(pending);
    service.push(battery);
    service.extend_from_slice(&packet[..prefix_len]);

    let mut adv = Vec::with_capacity(31);
    adv.extend_from_slice(&[0x02, 0x01, 0x06]);
    adv.push((service.len() + 1).min(0xff) as u8);
    adv.push(0x21);
    adv.extend_from_slice(&service);
    if adv.len() > 31 {
        bail!("DMesh BLE announcement exceeded legacy advertising limit");
    }
    Ok(adv)
}

fn dmesh_adv_ids(packet: &[u8]) -> (u32, u32) {
    decode_frame(packet)
        .ok()
        .and_then(|decoded| decoded.meshtastic)
        .map(|header| (header.from, header.id))
        .unwrap_or((0, 0))
}

fn battery_level() -> u8 {
    super::battery::battery_level_default()
}

fn configure_security() -> Result<()> {
    if BLE_SECURITY_CONFIGURED.swap(true, Ordering::Relaxed) {
        return Ok(());
    }
    let fixed_pin = BLE_FIXED_PIN.load(Ordering::Relaxed);
    let mut auth_req = if fixed_pin == 0 {
        sys::ESP_LE_AUTH_BOND as u8
    } else {
        sys::ESP_LE_AUTH_REQ_BOND_MITM as u8
    };
    let mut iocap = if fixed_pin == 0 {
        sys::ESP_IO_CAP_NONE as u8
    } else {
        sys::ESP_IO_CAP_OUT as u8
    };
    let mut key_size = 16_u8;
    let mut init_key = (sys::ESP_BLE_ENC_KEY_MASK | sys::ESP_BLE_ID_KEY_MASK) as u8;
    let mut rsp_key = init_key;
    unsafe {
        esp_ok(sys::esp_ble_gap_set_security_param(
            sys::esp_ble_sm_param_t_ESP_BLE_SM_AUTHEN_REQ_MODE,
            (&mut auth_req as *mut u8).cast(),
            size_of::<u8>() as u8,
        ))?;
        esp_ok(sys::esp_ble_gap_set_security_param(
            sys::esp_ble_sm_param_t_ESP_BLE_SM_IOCAP_MODE,
            (&mut iocap as *mut u8).cast(),
            size_of::<u8>() as u8,
        ))?;
        esp_ok(sys::esp_ble_gap_set_security_param(
            sys::esp_ble_sm_param_t_ESP_BLE_SM_MAX_KEY_SIZE,
            (&mut key_size as *mut u8).cast(),
            size_of::<u8>() as u8,
        ))?;
        esp_ok(sys::esp_ble_gap_set_security_param(
            sys::esp_ble_sm_param_t_ESP_BLE_SM_SET_INIT_KEY,
            (&mut init_key as *mut u8).cast(),
            size_of::<u8>() as u8,
        ))?;
        esp_ok(sys::esp_ble_gap_set_security_param(
            sys::esp_ble_sm_param_t_ESP_BLE_SM_SET_RSP_KEY,
            (&mut rsp_key as *mut u8).cast(),
            size_of::<u8>() as u8,
        ))?;
        if fixed_pin != 0 {
            let mut passkey = fixed_pin;
            esp_ok(sys::esp_ble_gap_set_security_param(
                sys::esp_ble_sm_param_t_ESP_BLE_SM_SET_STATIC_PASSKEY,
                (&mut passkey as *mut u32).cast(),
                size_of::<u32>() as u8,
            ))?;
        }
    }
    Ok(())
}

fn pairing_open() -> bool {
    let deadline = BLE_PAIRING_DEADLINE_MS.load(Ordering::Relaxed);
    deadline != 0
        && deadline.wrapping_sub(now_ms()) < i32::MAX as u32
        && !BLE_PAIRING_ACCEPTED.load(Ordering::Relaxed)
}

fn pairing_requested() -> bool {
    let deadline = BLE_PAIRING_REQUEST_DEADLINE_MS.load(Ordering::Relaxed);
    deadline != 0 && deadline.wrapping_sub(now_ms()) < i32::MAX as u32
}

fn companion_link_ready() -> bool {
    BLE_COMPANION_ENABLED.load(Ordering::Relaxed)
        && BLE_GATT_CONNECTED.load(Ordering::Relaxed)
        && BLE_GATT_NOTIFY_ENABLED.load(Ordering::Relaxed)
        && BLE_GATT_AUTHENTICATED.load(Ordering::Relaxed)
}

fn poll_companion_advertising() {
    if !BLE_COMPANION_ENABLED.load(Ordering::Relaxed)
        || companion_active()
        || BLE_GATT_CONNECTED.load(Ordering::Relaxed)
        || BLE_PENDING_NOTIFY.load(Ordering::Relaxed)
    {
        return;
    }
    let period_ms = BLE_COMPANION_ADV_PERIOD_MS.load(Ordering::Relaxed);
    let window_ms = BLE_COMPANION_ADV_WINDOW_MS.load(Ordering::Relaxed);
    if period_ms == 0 || window_ms == 0 {
        return;
    }
    let now = now_ms();
    let next = BLE_COMPANION_ADV_NEXT_MS.load(Ordering::Relaxed);
    if next.wrapping_sub(now) < i32::MAX as u32 {
        return;
    }
    if BLE_COMPANION_ADV_STATE.load(Ordering::Relaxed) {
        unsafe {
            let _ = ble_gap_stop_scanning();
        }
        BLE_SCAN_STARTED.store(false, Ordering::Relaxed);
        BLE_SCAN_STOPPING.store(false, Ordering::Relaxed);
        BLE_COMPANION_ADV_STATE.store(false, Ordering::Relaxed);
        BLE_COMPANION_ADV_NEXT_MS.store(now.wrapping_add(period_ms - window_ms), Ordering::Relaxed);
        if BLE_MODE.load(Ordering::Relaxed) == BLE_MODE_LISTEN {
            BLE_MODE.store(BLE_MODE_OFF, Ordering::Relaxed);
        }
    } else if start_companion_wake_scan().is_ok() {
        BLE_COMPANION_ADV_STATE.store(true, Ordering::Relaxed);
        BLE_COMPANION_ADV_NEXT_MS.store(now.wrapping_add(window_ms), Ordering::Relaxed);
    } else {
        BLE_COMPANION_ADV_NEXT_MS.store(now.wrapping_add(period_ms), Ordering::Relaxed);
    }
}

fn start_companion_wake_scan() -> Result<()> {
    let mut radio = RadioCommand::new("ble");
    radio.ensure_ble()?;
    start_gatt()?;
    BLE_FILTER_DMESH.store(true, Ordering::Relaxed);
    BLE_FILTER_UUID16.store(0, Ordering::Relaxed);
    BLE_FILTER_ADDR_ENABLED.store(false, Ordering::Relaxed);
    start_scan_params(0, true)?;
    BLE_MODE.store(BLE_MODE_LISTEN, Ordering::Relaxed);
    telemetry::record_log("event type=ble.companion wake_scan=true");
    Ok(())
}

fn notify_companion_pending() {
    if !companion_link_ready() {
        return;
    }
    let text = telemetry::companion_notify_text(1200);
    if text.contains("count=0") {
        BLE_PENDING_NOTIFY.store(false, Ordering::Relaxed);
        return;
    }
    send_gatt(text.as_bytes());
    BLE_PENDING_NOTIFY.store(false, Ordering::Relaxed);
}

fn set_connected_addr(addr: &[u8; 6]) {
    for (idx, byte) in addr.iter().enumerate() {
        BLE_CONNECTED_ADDR[idx].store(*byte, Ordering::Relaxed);
    }
}

fn connected_addr() -> [u8; 6] {
    let mut mac = [0_u8; 6];
    for (idx, byte) in mac.iter_mut().enumerate() {
        *byte = BLE_CONNECTED_ADDR[idx].load(Ordering::Relaxed);
    }
    mac
}

fn set_paired_addr(addr: &[u8; 6]) {
    for (idx, byte) in addr.iter().enumerate() {
        BLE_PAIRED_ADDR[idx].store(*byte, Ordering::Relaxed);
    }
}

fn set_pairing_request_addr(addr: &[u8; 6]) {
    for (idx, byte) in addr.iter().enumerate() {
        BLE_PAIRING_REQUEST_ADDR[idx].store(*byte, Ordering::Relaxed);
    }
}

fn pairing_request_addr() -> [u8; 6] {
    let mut mac = [0_u8; 6];
    for (idx, byte) in mac.iter_mut().enumerate() {
        *byte = BLE_PAIRING_REQUEST_ADDR[idx].load(Ordering::Relaxed);
    }
    mac
}

fn paired_addr_string() -> String {
    let mut mac = [0_u8; 6];
    for (idx, byte) in mac.iter_mut().enumerate() {
        *byte = BLE_PAIRED_ADDR[idx].load(Ordering::Relaxed);
    }
    format_mac(&mac)
}

fn is_bonded_addr(addr: &[u8; 6]) -> bool {
    let count = unsafe { sys::esp_ble_get_bond_device_num() };
    if count <= 0 {
        return false;
    }
    let mut devices = vec![sys::esp_ble_bond_dev_t::default(); count.min(8) as usize];
    let mut dev_num = devices.len() as i32;
    let ok = unsafe { sys::esp_ble_get_bond_device_list(&mut dev_num, devices.as_mut_ptr()) }
        == sys::ESP_OK;
    ok && devices
        .iter()
        .take(dev_num.max(0) as usize)
        .any(|device| &device.bd_addr == addr)
}

fn reset_pairing_state() -> usize {
    BLE_COMPANION_ENABLED.store(false, Ordering::Relaxed);
    BLE_COMPANION_SAVE_PENDING.store(false, Ordering::Relaxed);
    BLE_PAIRING_DEADLINE_MS.store(0, Ordering::Relaxed);
    BLE_PAIRING_ACCEPTED.store(false, Ordering::Relaxed);
    BLE_PAIRING_REQUEST_DEADLINE_MS.store(0, Ordering::Relaxed);
    BLE_GATT_AUTHENTICATED.store(false, Ordering::Relaxed);
    set_paired_addr(&[0; 6]);
    set_pairing_request_addr(&[0; 6]);

    let count = unsafe { sys::esp_ble_get_bond_device_num() };
    if count <= 0 {
        telemetry::record_log("event type=ble.pairing reset=true bonds_removed=0");
        return 0;
    }
    let mut devices = vec![sys::esp_ble_bond_dev_t::default(); count.min(16) as usize];
    let mut dev_num = devices.len() as i32;
    let ok = unsafe { sys::esp_ble_get_bond_device_list(&mut dev_num, devices.as_mut_ptr()) }
        == sys::ESP_OK;
    if !ok {
        telemetry::record_log("event type=ble.pairing reset=true bonds_removed=0 bond_list=false");
        return 0;
    }
    let mut removed = 0;
    for device in devices.iter().take(dev_num.max(0) as usize) {
        let ret = unsafe { sys::esp_ble_remove_bond_device(device.bd_addr.as_ptr() as *mut u8) };
        if ret == sys::ESP_OK {
            removed += 1;
        }
    }
    telemetry::record_log(format!(
        "event type=ble.pairing reset=true bonds_removed={}",
        removed
    ));
    removed
}

fn now_ms() -> u32 {
    unsafe { (sys::esp_timer_get_time() / 1000) as u32 }
}

#[derive(Debug)]
struct DmeshAnnouncement {
    source: u32,
    packet_id: u32,
    pending: u8,
    battery: u8,
    prefix: Vec<u8>,
}

impl DmeshAnnouncement {
    fn dedupe_key(&self) -> u32 {
        self.source.rotate_left(13) ^ self.packet_id
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
        if typ == 0x16 && data.len() >= 12 {
            let uuid = u16::from_le_bytes([data[0], data[1]]);
            if uuid == DMESH_BLE_SERVICE_UUID16 {
                let source = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
                let packet_id = u32::from_le_bytes([data[6], data[7], data[8], data[9]]);
                return Some(DmeshAnnouncement {
                    source,
                    packet_id,
                    pending: data[10],
                    battery: data[11],
                    prefix: data[12..].to_vec(),
                });
            }
        } else if typ == 0x21 && data.len() >= 26 && data[..16] == DMESH_BLE_OPERATIONAL_UUID[..] {
            let source = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
            let packet_id = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
            return Some(DmeshAnnouncement {
                source,
                packet_id,
                pending: data[24],
                battery: data[25],
                prefix: data[26..].to_vec(),
            });
        }
        i += len + 1;
    }
    None
}

unsafe extern "C" fn gap_cb(
    event: sys::esp_gap_ble_cb_event_t,
    param: *mut sys::esp_ble_gap_cb_param_t,
) {
    if event == sys::esp_gap_ble_cb_event_t_ESP_GAP_BLE_SEC_REQ_EVT && !param.is_null() {
        let req = unsafe { (*param).ble_security.ble_req };
        let accept = pairing_open()
            || (BLE_COMPANION_ENABLED.load(Ordering::Relaxed) && is_bonded_addr(&req.bd_addr));
        if accept {
            BLE_PAIRING_ACCEPTED.store(true, Ordering::Relaxed);
        }
        unsafe {
            let _ = sys::esp_ble_gap_security_rsp(req.bd_addr.as_ptr() as *mut u8, accept);
        }
        let line = format!(
            "event type=ble.security request=true accept={} pairing_open={}",
            accept,
            pairing_open()
        );
        telemetry::record_log(line.clone());
        telemetry::emit_console(&line);
        return;
    }
    if event == sys::esp_gap_ble_cb_event_t_ESP_GAP_BLE_NC_REQ_EVT && !param.is_null() {
        let notif = unsafe { (*param).ble_security.key_notif };
        let accept = pairing_open();
        unsafe {
            let _ = sys::esp_ble_confirm_reply(notif.bd_addr.as_ptr() as *mut u8, accept);
        }
        let line = format!(
            "event type=ble.security numeric_compare accept={}",
            accept
        );
        telemetry::record_log(line.clone());
        telemetry::emit_console(&line);
        return;
    }
    if event == sys::esp_gap_ble_cb_event_t_ESP_GAP_BLE_AUTH_CMPL_EVT && !param.is_null() {
        let auth = unsafe { (*param).ble_security.auth_cmpl };
        if auth.success {
            let pairing_accepted = BLE_PAIRING_ACCEPTED.load(Ordering::Relaxed);
            set_paired_addr(&auth.bd_addr);
            BLE_GATT_AUTHENTICATED.store(true, Ordering::Relaxed);
            if pairing_accepted {
                BLE_COMPANION_ENABLED.store(true, Ordering::Relaxed);
                BLE_COMPANION_SAVE_PENDING.store(true, Ordering::Relaxed);
            }
            BLE_PAIRING_DEADLINE_MS.store(0, Ordering::Relaxed);
            BLE_PAIRING_ACCEPTED.store(false, Ordering::Relaxed);
            let line = format!(
                "event type=ble.security auth=ok pairing={} peer={}",
                pairing_accepted,
                format_mac(&auth.bd_addr),
            );
            telemetry::record_log(line.clone());
            telemetry::emit_console(&line);
        } else {
            BLE_GATT_AUTHENTICATED.store(false, Ordering::Relaxed);
            let line = format!(
                "event type=ble.security auth=fail reason={}",
                auth.fail_reason
            );
            telemetry::record_log(line.clone());
            telemetry::emit_console(&line);
        }
        return;
    }
    #[cfg(target_feature = "esp32s3ops")]
    if event == sys::esp_gap_ble_cb_event_t_ESP_GAP_BLE_EXT_ADV_SET_RAND_ADDR_COMPLETE_EVT
        && !param.is_null()
    {
        let addr = unsafe { (*param).ext_adv_set_rand_addr };
        BLE_EXT_ADV_ADDR_STATUS.store(addr.status as u32, Ordering::Relaxed);
        BLE_EXT_ADV_ADDR_DONE.store(true, Ordering::Relaxed);
        telemetry::emit_console(&format!(
            "event type=ble.ext_adv_rand_addr status={} instance={}",
            addr.status, addr.instance
        ));
        return;
    }
    #[cfg(target_feature = "esp32s3ops")]
    if event == sys::esp_gap_ble_cb_event_t_ESP_GAP_BLE_EXT_ADV_DATA_SET_COMPLETE_EVT
        && !param.is_null()
    {
        let data = unsafe { (*param).ext_adv_data_set };
        BLE_EXT_ADV_DATA_STATUS.store(data.status as u32, Ordering::Relaxed);
        BLE_EXT_ADV_DATA_DONE.store(true, Ordering::Relaxed);
        telemetry::emit_console(&format!(
            "event type=ble.ext_adv_data status={} instance={}",
            data.status, data.instance
        ));
        return;
    }
    if event == sys::esp_gap_ble_cb_event_t_ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT {
        if let Err(err) = start_ble_advertising() {
            BLE_ADV_STARTED.store(false, Ordering::Relaxed);
            BLE_ADV_START_DONE.store(true, Ordering::Relaxed);
            BLE_ADV_START_STATUS.store(0xffff, Ordering::Relaxed);
            telemetry::record_log(format!(
                "event type=ble.error component=legacy_adv_start message={}",
                crate::commands::protocol::escape_value(&err.to_string())
            ));
        }
        return;
    }
    if event == sys::esp_gap_ble_cb_event_t_ESP_GAP_BLE_ADV_START_COMPLETE_EVT && !param.is_null()
    {
        let start = unsafe { (*param).adv_start_cmpl };
        BLE_ADV_START_STATUS.store(start.status as u32, Ordering::Relaxed);
        BLE_ADV_START_DONE.store(true, Ordering::Relaxed);
        BLE_ADV_STARTED.store(start.status == 0, Ordering::Relaxed);
        telemetry::record_log(format!(
            "event type=ble.legacy_adv_start status={}",
            start.status
        ));
        return;
    }
    #[cfg(target_feature = "esp32s3ops")]
    if event == sys::esp_gap_ble_cb_event_t_ESP_GAP_BLE_EXT_ADV_SET_PARAMS_COMPLETE_EVT
        && !param.is_null()
    {
        let params = unsafe { (*param).ext_adv_set_params };
        BLE_EXT_ADV_PARAMS_STATUS.store(params.status as u32, Ordering::Relaxed);
        BLE_EXT_ADV_PARAMS_DONE.store(true, Ordering::Relaxed);
        telemetry::emit_console(&format!(
            "event type=ble.ext_adv_params status={} instance={}",
            params.status, params.instance
        ));
        return;
    }
    #[cfg(target_feature = "esp32s3ops")]
    if event == sys::esp_gap_ble_cb_event_t_ESP_GAP_BLE_EXT_ADV_START_COMPLETE_EVT
        && !param.is_null()
    {
        let start = unsafe { (*param).ext_adv_start };
        BLE_EXT_ADV_START_STATUS.store(start.status as u32, Ordering::Relaxed);
        BLE_EXT_ADV_START_DONE.store(true, Ordering::Relaxed);
        telemetry::emit_console(&format!(
            "event type=ble.ext_adv_start status={} instance_num={}",
            start.status, start.instance_num
        ));
        return;
    }
    #[cfg(target_feature = "esp32s3ops")]
    if event == sys::esp_gap_ble_cb_event_t_ESP_GAP_BLE_EXT_ADV_REPORT_EVT && !param.is_null() {
        let report = unsafe { (*param).ext_adv_report.params };
        let len = (report.adv_data_len as usize).min(report.adv_data.len());
        handle_ble_scan_report(&report.addr, report.rssi as i32, &report.adv_data[..len]);
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
        handle_ble_scan_report(&result.bda, result.rssi, adv);
    }
}

fn handle_ble_scan_report(addr: &[u8; 6], rssi: i32, adv: &[u8]) {
    BLE_SCAN_REPORTS.fetch_add(1, Ordering::Relaxed);
    BLE_SCAN_LAST_RSSI.store(rssi, Ordering::Relaxed);
    let companion_wake_match = BLE_COMPANION_ENABLED.load(Ordering::Relaxed)
        && BLE_COMPANION_ADV_STATE.load(Ordering::Relaxed)
        && !BLE_GATT_CONNECTED.load(Ordering::Relaxed);
    if companion_wake_match {
        BLE_SCAN_MATCHED.fetch_add(1, Ordering::Relaxed);
        BLE_WAKE_REQUEST_RX.fetch_add(1, Ordering::Relaxed);
        BLE_PENDING_SWITCHES.fetch_add(1, Ordering::Relaxed);
        open_companion_active_window(BLE_COMPANION_ACTIVE_MS.load(Ordering::Relaxed).max(1_000));
        telemetry::record_log(format!(
            "event type=ble.companion wake_request=true addr={} rssi={} parser=any",
            format_mac(addr),
            rssi
        ));
    }
    if matches_ble_filter(addr, adv) {
        BLE_SCAN_MATCHED.fetch_add(1, Ordering::Relaxed);
        if let Some(announce) = parse_dmesh_adv(adv) {
            BLE_ANNOUNCE_RX.fetch_add(1, Ordering::Relaxed);
            telemetry::count_packet("ble", Direction::Rx, adv.len());
            if BLE_MODE.load(Ordering::Relaxed) == BLE_MODE_LISTEN
                && !BLE_GATT_CONNECTED.load(Ordering::Relaxed)
            {
                BLE_WAKE_REQUEST_RX.fetch_add(1, Ordering::Relaxed);
                BLE_PENDING_SWITCHES.fetch_add(1, Ordering::Relaxed);
                let _ = start_connectable_idle();
                telemetry::record_log(format!(
                    "event type=ble.wake_request action=connectable addr={} src=0x{:08x}",
                    format_mac(addr),
                    announce.source
                ));
            }
            if BLE_COMPANION_ENABLED.load(Ordering::Relaxed)
                && BLE_COMPANION_ADV_STATE.load(Ordering::Relaxed)
                && !BLE_GATT_CONNECTED.load(Ordering::Relaxed)
            {
                BLE_WAKE_REQUEST_RX.fetch_add(1, Ordering::Relaxed);
                BLE_PENDING_SWITCHES.fetch_add(1, Ordering::Relaxed);
                open_companion_active_window(
                    BLE_COMPANION_ACTIVE_MS.load(Ordering::Relaxed).max(1_000),
                );
                telemetry::record_log(format!(
                    "event type=ble.companion wake_request=true addr={} src=0x{:08x}",
                    format_mac(addr),
                    announce.source
                ));
            }
            let first_seen = BLE_LAST_ANNOUNCE_HASH
                .swap(announce.dedupe_key(), Ordering::Relaxed)
                != announce.dedupe_key();
            if first_seen {
                let line = format!(
                    "event type=ble.announce_rx addr={} src=0x{:08x} n={} pending={} battery={} prefix={}",
                    format_mac(addr),
                    announce.source,
                    announce.packet_id,
                    announce.pending,
                    announce.battery,
                    hex_bytes(&announce.prefix)
                );
                telemetry::record_log(line);
                telemetry::record_packet_sample(
                    "ble",
                    Direction::Rx,
                    adv,
                    format!("source=scan rssi={} addr={}", rssi, format_mac(addr)),
                );
            }
        } else {
            telemetry::record_packet(
                "ble",
                Direction::Rx,
                adv,
                format!("source=scan rssi={} addr={}", rssi, format_mac(addr)),
            );
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
        "ble started={} mode={} adv={} scan={} reports={} matched={} last_rssi={} filter=dmesh:{} filter_uuid16=0x{:04x} filter_addr={} announce_tx={} announce_rx={} wake_rx={} pending_switches={} gatt_started={} gatt_connected={} notify={} pairing_requested={} pairing_open={} fixed_pin={} gatt_rx_text={} gatt_rx_binary={} gatt_tx={}",
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
        pairing_requested(),
        pairing_open(),
        BLE_FIXED_PIN.load(Ordering::Relaxed),
        BLE_GATT_RX_TEXT.load(Ordering::Relaxed),
        BLE_GATT_RX_BINARY.load(Ordering::Relaxed),
        BLE_GATT_TX.load(Ordering::Relaxed)
    )
}

fn ble_bond_status(settings: Option<&SharedSettings>) -> String {
    let count = unsafe { sys::esp_ble_get_bond_device_num() }.max(0) as usize;
    let mut bonds = Vec::new();
    if count > 0 {
        let mut devices = vec![sys::esp_ble_bond_dev_t::default(); count.min(16)];
        let mut dev_num = devices.len() as i32;
        let ok = unsafe { sys::esp_ble_get_bond_device_list(&mut dev_num, devices.as_mut_ptr()) }
            == sys::ESP_OK;
        if ok {
            for device in devices.iter().take(dev_num.max(0) as usize) {
                bonds.push(format_mac(&device.bd_addr));
            }
        }
    }
    let (saved_mode, saved_companion, saved_peer) = settings
        .map(|settings| {
            let settings = settings.borrow();
            (
                settings.get_str("mode").ok().flatten().unwrap_or_default(),
                settings
                    .get_bool("ble.comp", false)
                    .map(|value| value.to_string())
                    .unwrap_or_else(|_| "err".to_string()),
                settings.get_str("ble.peer").ok().flatten().unwrap_or_default(),
            )
        })
        .unwrap_or_else(|| ("".to_string(), "".to_string(), "".to_string()));
    format!(
        "ble bonds={} bonded={} connected={} connected_peer={} paired_peer={} auth={} companion={} save_pending={} saved_mode={} saved_ble_comp={} saved_peer={}",
        count,
        if bonds.is_empty() { "none".to_string() } else { bonds.join(",") },
        BLE_GATT_CONNECTED.load(Ordering::Relaxed),
        format_mac(&connected_addr()),
        paired_addr_string(),
        BLE_GATT_AUTHENTICATED.load(Ordering::Relaxed),
        BLE_COMPANION_ENABLED.load(Ordering::Relaxed),
        BLE_COMPANION_SAVE_PENDING.load(Ordering::Relaxed),
        crate::commands::protocol::quote_text_value(&saved_mode),
        saved_companion,
        crate::commands::protocol::quote_text_value(&saved_peer)
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
            BLE_GATT_AUTHENTICATED.store(false, Ordering::Relaxed);
            set_connected_addr(&connect.remote_bda);
            if BLE_COMPANION_ENABLED.load(Ordering::Relaxed) || pairing_open() {
                unsafe {
                    let _ = sys::esp_ble_set_encryption(
                        connect.remote_bda.as_ptr() as *mut u8,
                        sys::esp_ble_sec_act_t_ESP_BLE_SEC_ENCRYPT_NO_MITM,
                    );
                }
            }
            let line = format!(
                "event type=ble.gatt state=connected peer={} pairing_open={} companion={}",
                format_mac(&connect.remote_bda),
                pairing_open(),
                BLE_COMPANION_ENABLED.load(Ordering::Relaxed)
            );
            telemetry::record_log(line.clone());
            telemetry::emit_console(&line);
        }
        x if x == sys::esp_gatts_cb_event_t_ESP_GATTS_DISCONNECT_EVT => {
            let disconnect = unsafe { (*param).disconnect };
            BLE_GATT_CONNECTED.store(false, Ordering::Relaxed);
            BLE_GATT_NOTIFY_ENABLED.store(false, Ordering::Relaxed);
            BLE_GATT_AUTHENTICATED.store(false, Ordering::Relaxed);
            let line = format!(
                "event type=ble.gatt state=disconnected reason={}",
                disconnect.reason as u32
            );
            telemetry::record_log(line.clone());
            telemetry::emit_console(&line);
            if restart_advertising_after_disconnect() {
                unsafe {
                    let mut params = default_adv_params();
                    let _ = ble_gap_start_advertising(&mut params);
                }
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
                let line = format!(
                    "event type=ble.gatt_write target=ccc handle={} len={} need_rsp={} prep={} value={:02x}{:02x}",
                    write.handle,
                    write.len,
                    write.need_rsp,
                    write.is_prep,
                    data[0],
                    data[1]
                );
                telemetry::record_log(line.clone());
                telemetry::emit_console(&line);
                BLE_GATT_NOTIFY_ENABLED.store(data[0] & 0x01 != 0, Ordering::Relaxed);
                if data[0] & 0x01 != 0 {
                    notify_companion_pending();
                }
            } else if write.handle as u32 == BLE_GATT_RX_HANDLE.load(Ordering::Relaxed) {
                let line = format!(
                    "event type=ble.gatt_write target=rx handle={} len={} need_rsp={} prep={}",
                    write.handle, write.len, write.need_rsp, write.is_prep
                );
                telemetry::record_log(line.clone());
                telemetry::emit_console(&line);
                let response = handle_gatt_rx(data);
                if !response.is_empty() {
                    send_gatt(&response);
                }
            } else {
                let line = format!(
                    "event type=ble.gatt_write target=unknown handle={} len={} need_rsp={} prep={} rx_handle={} ccc_handle={}",
                    write.handle,
                    write.len,
                    write.need_rsp,
                    write.is_prep,
                    BLE_GATT_RX_HANDLE.load(Ordering::Relaxed),
                    BLE_GATT_CCC_HANDLE.load(Ordering::Relaxed)
                );
                telemetry::record_log(line.clone());
                telemetry::emit_console(&line);
            }
            if write.need_rsp {
                unsafe {
                    let ret = sys::esp_ble_gatts_send_response(
                        gatts_if,
                        write.conn_id,
                        write.trans_id,
                        sys::esp_gatt_status_t_ESP_GATT_OK,
                        core::ptr::null_mut(),
                    );
                    telemetry::record_log(format!(
                        "event type=ble.gatt_write_rsp target_handle={} ret={}",
                        write.handle, ret
                    ));
                }
            }
        }
        _ => {}
    }
}

fn handle_gatt_rx(data: &[u8]) -> Vec<u8> {
    telemetry::record_packet("ble", Direction::Rx, data, "source=gatt_rx");
    if BLE_COMPANION_ENABLED.load(Ordering::Relaxed)
        && !BLE_GATT_AUTHENTICATED.load(Ordering::Relaxed)
    {
        return b"error message=companion_requires_encryption\n".to_vec();
    }
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
        queue_ble_text(&normalize_ble_text(data));
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

fn normalize_ble_text(data: &[u8]) -> Vec<u8> {
    let line = core::str::from_utf8(data).unwrap_or("").trim();
    if matches!(
        line,
        "pair" | "pairing" | "pair request" | "pairing request"
    ) {
        return b"ble pairing=request".to_vec();
    }
    if matches!(line, "pair cancel" | "pairing cancel") {
        return b"ble pairing=false".to_vec();
    }
    if line == "ready" || line.starts_with("ready ") {
        return format!(
            "messages pull {}",
            line.strip_prefix("ready").unwrap_or("").trim()
        )
        .trim()
        .as_bytes()
        .to_vec();
    }
    if line == "ack" || line.starts_with("ack ") {
        return format!(
            "messages ack {}",
            line.strip_prefix("ack").unwrap_or("").trim()
        )
        .trim()
        .as_bytes()
        .to_vec();
    }
    data.to_vec()
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
        adv_int_min: BLE_ADV_INT_MIN.load(Ordering::Relaxed) as u16,
        adv_int_max: BLE_ADV_INT_MAX.load(Ordering::Relaxed) as u16,
        adv_type: sys::esp_ble_adv_type_t_ADV_TYPE_IND,
        own_addr_type: sys::esp_ble_addr_type_t_BLE_ADDR_TYPE_PUBLIC,
        peer_addr: [0; 6],
        peer_addr_type: sys::esp_ble_addr_type_t_BLE_ADDR_TYPE_PUBLIC,
        channel_map: sys::esp_ble_adv_channel_t_ADV_CHNL_ALL,
        adv_filter_policy: sys::esp_ble_adv_filter_t_ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
    }
}

fn adv_ms_to_units(ms: u32) -> u32 {
    // BLE advertising intervals use 0.625 ms units. Legacy advertising accepts
    // 0x20..0x4000, roughly 20 ms through 10.24 s.
    ms.saturating_mul(1600).div_ceil(1000).clamp(0x20, 0x4000)
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
            ptr128(&DMESH_GATT_SERVICE_UUID),
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
            sys::ESP_GATT_RSP_BY_APP as u8,
            sys::ESP_UUID_LEN_128 as u16,
            ptr128(&DMESH_GATT_RX_UUID),
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
            ptr128(&DMESH_GATT_TX_UUID),
            sys::ESP_GATT_PERM_READ as u16,
            512,
            0,
            core::ptr::addr_of_mut!(TX_VALUE) as *mut u8,
        ),
        attr(
            sys::ESP_GATT_RSP_BY_APP as u8,
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

fn esp_ok_allow_invalid_state(ret: sys::esp_err_t) -> Result<()> {
    if ret == sys::ESP_OK || ret == sys::ESP_ERR_INVALID_STATE {
        Ok(())
    } else {
        bail!("esp_err=0x{ret:x}")
    }
}
