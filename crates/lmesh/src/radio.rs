use anyhow::{Context, Result, bail};
use mesh::message::{
    FIELD_CTRL_DIR, FIELD_IFACE, FIELD_MEDIUM, FIELD_NETWORK, FIELD_NODE, FIELD_PAYLOAD,
    FIELD_RADIO_ID, FIELD_RSSI, FIELD_SNR, FIELD_STATUS, MeshMessage, MeshMessageCodec, TextRecord,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::radio_protocol;

const DEFAULT_WIFI_IFACE: &str = "wlan1";
const DEFAULT_WPA_CTRL_DIR: &str = "/run/ssh-mesh-wpa";
const DEFAULT_WPA_SERVICE_NAME: &str = "dmesh";
const DEFAULT_HCI_DEV: u16 = 0;
const MAX_HISTORY: usize = 128;
const AF_BLUETOOTH: libc::c_int = 31;
const BTPROTO_HCI: libc::c_int = 1;
const HCI_CHANNEL_RAW: u16 = 0;
const HCI_COMMAND_PKT: u8 = 0x01;
const OGF_LE_CTL: u16 = 0x08;
const OCF_LE_SET_ADV_PARAMETERS: u16 = 0x0006;
const OCF_LE_SET_ADV_DATA: u16 = 0x0008;
const OCF_LE_SET_ADV_ENABLE: u16 = 0x000a;
const OCF_LE_SET_SCAN_PARAMETERS: u16 = 0x000b;
const OCF_LE_SET_SCAN_ENABLE: u16 = 0x000c;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const IFF_UP: u32 = 0x1;

/// Linux radio backend used by the lmesh JSONL methods.
#[derive(Clone, Default)]
pub struct RadioService {
    history: Arc<Mutex<VecDeque<RadioEvent>>>,
    radios: Arc<Vec<RadioAdapter>>,
}

impl RadioService {
    /// Create a radio service from environment and optional MESH_HOME/lmesh.toml config.
    pub fn from_environment() -> Self {
        Self {
            history: Arc::new(Mutex::new(VecDeque::new())),
            radios: Arc::new(load_radio_adapters()),
        }
    }

    /// Return interface, capability, process-capability, and control status.
    pub fn status(&self) -> Value {
        let iface = wifi_iface(None);
        let ctrl_dir = wpa_ctrl_dir(None);
        let wpa_status = wpa_command(&iface, &ctrl_dir, "STATUS");
        let wpa_driver_flags2 = wpa_command(&iface, &ctrl_dir, "DRIVER_FLAGS2");

        json!({
            "wifi_iface": iface,
            "wpa_ctrl_dir": ctrl_dir,
            "radios": self.radios.as_ref(),
            "capabilities": process_caps(),
            "hci": hci_probe(DEFAULT_HCI_DEV),
            "wpa": {
                "backend": "ctrl_uds",
                "status": command_result_json(wpa_status),
                "driver_flags2": command_result_json(wpa_driver_flags2),
            }
        })
    }

    /// Return recent radio method results and observed notifications.
    pub fn history(&self, keys: Option<String>, limit: Option<usize>) -> Value {
        let keys = keys
            .unwrap_or_else(|| "messages,net,wifi,BLE,N".to_string())
            .split(',')
            .map(|key| key.trim().to_string())
            .filter(|key| !key.is_empty())
            .collect::<Vec<_>>();
        let limit = limit.unwrap_or(40).max(1);
        let events = self
            .history
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .rev()
            .filter(|event| keys.is_empty() || keys.iter().any(|key| event.key.starts_with(key)))
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        json!({ "events": events })
    }

    /// Return the configured local, remote, and future adapter inventory.
    pub fn list_radios(&self) -> Value {
        json!({ "radios": self.radios.as_ref() })
    }

    /// Return recently observed neighbors from normalized radio messages.
    pub fn neighbors(&self, seen_within_sec: Option<u64>) -> Value {
        let window_ms = seen_within_sec.unwrap_or(21_600).saturating_mul(1000);
        let cutoff = now_millis_u64().saturating_sub(window_ms);
        let mut neighbors: BTreeMap<String, NeighborInfo> = BTreeMap::new();
        for event in self
            .history
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
        {
            let Some(message) = &event.message else {
                continue;
            };
            if message.timestamp_ms < cutoff {
                continue;
            }
            let Some(node) = message
                .field_value(FIELD_NODE)
                .or_else(|| message.field_value(mesh::message::FIELD_PEER))
            else {
                continue;
            };
            let entry = neighbors
                .entry(node.to_string())
                .or_insert_with(|| NeighborInfo::new(node));
            if message.timestamp_ms >= entry.last_seen_ms {
                entry.last_seen_ms = message.timestamp_ms;
                entry.medium = message.field_value(FIELD_MEDIUM).map(str::to_string);
                entry.network = message.field_value(FIELD_NETWORK).map(str::to_string);
                entry.radio_id = message.field_value(FIELD_RADIO_ID).map(str::to_string);
                entry.rssi = message
                    .field_value(FIELD_RSSI)
                    .and_then(|value| value.parse().ok());
                entry.snr = message
                    .field_value(FIELD_SNR)
                    .and_then(|value| value.parse().ok());
                entry.source = Some(event.source.clone());
                entry.last_event = Some(event.key.clone());
            }
        }
        json!({
            "seen_within_sec": seen_within_sec.unwrap_or(21_600),
            "neighbors": neighbors.into_values().collect::<Vec<_>>(),
        })
    }

    /// Fan out a discovery ping request to the selected media and record the intent.
    pub fn discovery_ping(&self, medium: Option<String>) -> Value {
        let medium = medium.unwrap_or_else(|| "all".to_string());
        let selected = self
            .radios
            .iter()
            .filter(|radio| medium == "all" || radio.medium == medium)
            .cloned()
            .collect::<Vec<_>>();
        let mut serial_results = Vec::new();
        for radio in &selected {
            let message = MeshMessage::new(mesh::message::KIND_DM_PING, MeshMessageCodec::Text)
                .field(FIELD_MEDIUM, &radio.medium)
                .field(FIELD_RADIO_ID, &radio.id)
                .field(FIELD_STATUS, "queued");
            self.record_message("discovery.ping", "local", message);
            if radio.kind == "esp-serial" {
                serial_results.push(self.ping_serial_radio(radio));
            }
        }
        json!({
            "ok": true,
            "medium": medium,
            "sent": selected.len(),
            "radios": selected,
            "serial": serial_results,
        })
    }

    fn ping_serial_radio(&self, radio: &RadioAdapter) -> Value {
        let Some(path) = radio.path.as_deref() else {
            return json!({ "radio_id": radio.id, "ok": false, "error": "missing serial path" });
        };
        let command = TextRecord::new("dm.ping")
            .field("medium", "serial")
            .field("radio_id", &radio.id)
            .field("network", radio.network.as_deref().unwrap_or("default"))
            .format();
        match serial_exchange(path, radio.baud.unwrap_or(115_200), &command) {
            Ok(messages) => {
                for message in &messages {
                    self.record_message("esp-serial.rx", &radio.id, message.clone());
                }
                json!({
                    "radio_id": radio.id,
                    "path": path,
                    "ok": true,
                    "replies": messages,
                })
            }
            Err(error) => json!({
                "radio_id": radio.id,
                "path": path,
                "ok": false,
                "error": error.to_string(),
            }),
        }
    }

    /// Start a raw Linux HCI BLE scan for DMesh service advertisements.
    pub fn ble_scan(&self, dev_id: Option<u16>, reason: Option<String>) -> Result<Value> {
        let dev_id = dev_id.unwrap_or(DEFAULT_HCI_DEV);
        let socket = HciSocket::open(dev_id)?;
        socket.send_le_command(
            OCF_LE_SET_SCAN_PARAMETERS,
            &[0x00, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00],
        )?;
        socket.send_le_command(OCF_LE_SET_SCAN_ENABLE, &[0x01, 0x00])?;
        let result = json!({
            "ok": true,
            "backend": "linux_hci_raw",
            "dev_id": dev_id,
            "service_uuid16": format!("0x{:04x}", radio_protocol::DMESH_BLE_SERVICE_UUID16),
            "reason": reason.unwrap_or_else(|| "jsonl".to_string()),
            "note": "scan enabled; advertising reports are kernel/HCI events and are not yet streamed on this JSONL reply",
        });
        self.record_message(
            "BLE.scan",
            "host-ble",
            MeshMessage::new(mesh::message::KIND_BLE_SCAN, MeshMessageCodec::Text)
                .field(FIELD_MEDIUM, "ble")
                .field(FIELD_RADIO_ID, format!("hci{dev_id}"))
                .field(FIELD_STATUS, "enabled"),
        );
        self.record("BLE.scan", result.clone());
        Ok(result)
    }

    /// Enable or disable raw Linux HCI BLE advertising with DMesh service data.
    pub fn ble_adv(
        &self,
        dev_id: Option<u16>,
        on: Option<bool>,
        payload: Option<String>,
    ) -> Result<Value> {
        let dev_id = dev_id.unwrap_or(DEFAULT_HCI_DEV);
        let on = on.unwrap_or(true);
        let socket = HciSocket::open(dev_id)?;
        let payload_text = payload.unwrap_or_else(|| "lmesh".to_string());
        if on {
            let device_id = local_device_id()?;
            let service_data = radio_protocol::build_ble_service_data(
                radio_protocol::BleEvent::IdleHello,
                &device_id,
                payload_text.as_bytes(),
                0,
                0,
            )?;
            socket.send_le_command(
                OCF_LE_SET_ADV_PARAMETERS,
                &[
                    0xa0, 0x00, 0xa0, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00,
                    0x00, 0x00,
                ],
            )?;
            socket.send_le_command(OCF_LE_SET_ADV_DATA, &adv_data(&service_data)?)?;
            socket.send_le_command(OCF_LE_SET_ADV_ENABLE, &[0x01])?;
        } else {
            socket.send_le_command(OCF_LE_SET_ADV_ENABLE, &[0x00])?;
        }
        let result = json!({
            "ok": true,
            "backend": "linux_hci_raw",
            "dev_id": dev_id,
            "on": on,
        });
        self.record_message(
            "BLE.adv",
            "host-ble",
            MeshMessage::new(mesh::message::KIND_BLE_ADV, MeshMessageCodec::Text)
                .field(FIELD_MEDIUM, "ble")
                .field(FIELD_RADIO_ID, format!("hci{dev_id}"))
                .field(FIELD_STATUS, if on { "enabled" } else { "disabled" })
                .field(FIELD_PAYLOAD, payload_text),
        );
        self.record("BLE.adv", result.clone());
        Ok(result)
    }

    /// Attach to NAN through the repo-built wpa_supplicant control socket.
    pub fn nan_start(&self, iface: Option<String>, ctrl_dir: Option<String>) -> Value {
        let iface = wifi_iface(iface);
        let ctrl_dir = wpa_ctrl_dir(ctrl_dir);
        let link_up = set_link_up(&iface);
        let status = wpa_command(&iface, &ctrl_dir, "STATUS");
        let driver_flags2 = wpa_command(&iface, &ctrl_dir, "DRIVER_FLAGS2");
        let result = json!({
            "link_up": command_result_json(link_up),
            "status": command_result_json(status),
            "driver_flags2": command_result_json(driver_flags2),
        });
        self.record_message(
            "N.start",
            "host-nan",
            MeshMessage::new(mesh::message::KIND_NAN_START, MeshMessageCodec::WpaText)
                .field(FIELD_MEDIUM, "nan")
                .field(FIELD_IFACE, &iface)
                .field(FIELD_CTRL_DIR, &ctrl_dir),
        );
        self.record("N.start", result.clone());
        result
    }

    /// Stop NAN sessions through wpa_supplicant.
    pub fn nan_stop(&self, iface: Option<String>, ctrl_dir: Option<String>) -> Value {
        let iface = wifi_iface(iface);
        let ctrl_dir = wpa_ctrl_dir(ctrl_dir);
        let publish = wpa_raw_command(&iface, &ctrl_dir, "NAN_CANCEL_PUBLISH publish_id=1");
        let subscribe = wpa_raw_command(&iface, &ctrl_dir, "NAN_CANCEL_SUBSCRIBE subscribe_id=1");
        let result = json!({
            "publish": command_result_json(publish),
            "subscribe": command_result_json(subscribe),
        });
        self.record("N.stop", result.clone());
        result
    }

    /// Start a NAN publish using DMesh service info.
    pub fn nan_adv(&self, iface: Option<String>, ctrl_dir: Option<String>) -> Result<Value> {
        let iface = wifi_iface(iface);
        let ctrl_dir = wpa_ctrl_dir(ctrl_dir);
        let _ = set_link_up(&iface);
        let service_info =
            radio_protocol::build_nan_service_info("android", &local_device_id()?, 0)?;
        let cmd = format!(
            "NAN_PUBLISH service_name={} ttl=30 freq=0 srv_proto_type=0 ssi={}",
            DEFAULT_WPA_SERVICE_NAME,
            hex_bytes(&service_info)
        );
        let result = command_result_json(wpa_raw_command(&iface, &ctrl_dir, &cmd));
        self.record_message(
            "N.publish",
            "host-nan",
            MeshMessage::new(mesh::message::KIND_NAN_PUBLISH, MeshMessageCodec::WpaText)
                .field(FIELD_MEDIUM, "nan")
                .field(FIELD_IFACE, &iface)
                .field(FIELD_CTRL_DIR, &ctrl_dir),
        );
        self.record("N.publish", result.clone());
        Ok(result)
    }

    /// Start a NAN subscribe using the DMesh service name.
    pub fn nan_sub(&self, iface: Option<String>, ctrl_dir: Option<String>) -> Value {
        let iface = wifi_iface(iface);
        let ctrl_dir = wpa_ctrl_dir(ctrl_dir);
        let _ = set_link_up(&iface);
        let cmd = format!(
            "NAN_SUBSCRIBE service_name={} active=1 ttl=30 freq=0 srv_proto_type=0",
            DEFAULT_WPA_SERVICE_NAME
        );
        let result = command_result_json(wpa_raw_command(&iface, &ctrl_dir, &cmd));
        self.record_message(
            "N.subscribe",
            "host-nan",
            MeshMessage::new(mesh::message::KIND_NAN_SUBSCRIBE, MeshMessageCodec::WpaText)
                .field(FIELD_MEDIUM, "nan")
                .field(FIELD_IFACE, &iface)
                .field(FIELD_CTRL_DIR, &ctrl_dir),
        );
        self.record("N.subscribe", result.clone());
        result
    }

    /// Send a NAN follow-up ping/probe.
    pub fn nan_ping(
        &self,
        iface: Option<String>,
        ctrl_dir: Option<String>,
        peer: Option<String>,
        payload: Option<String>,
    ) -> Result<Value> {
        let iface = wifi_iface(iface);
        let ctrl_dir = wpa_ctrl_dir(ctrl_dir);
        let _ = set_link_up(&iface);
        let target = parse_device_id(peer.as_deref()).unwrap_or([0xff; 6]);
        let payload_text = payload.unwrap_or_else(|| "ping".to_string());
        let followup = radio_protocol::build_nan_followup(
            "hello",
            &local_device_id()?,
            &target,
            payload_text.as_bytes(),
        )?;
        let cmd = format!(
            "NAN_TRANSMIT handle=1 address={} ssi={}",
            colon_mac(&target),
            hex_bytes(&followup)
        );
        let result = command_result_json(wpa_raw_command(&iface, &ctrl_dir, &cmd));
        self.record_message(
            "N.transmit",
            "host-nan",
            MeshMessage::new(mesh::message::KIND_NAN_FOLLOWUP, MeshMessageCodec::WpaText)
                .field(FIELD_MEDIUM, "nan")
                .field(FIELD_IFACE, &iface)
                .field(FIELD_CTRL_DIR, &ctrl_dir)
                .field(FIELD_PAYLOAD, payload_text),
        );
        self.record("N.transmit", result.clone());
        Ok(result)
    }

    fn record(&self, key: &str, value: Value) {
        self.push_event(RadioEvent {
            ts_millis: now_millis(),
            key: key.to_string(),
            source: "local".to_string(),
            value,
            message: None,
        });
    }

    fn record_message(&self, key: &str, source: &str, message: MeshMessage) {
        self.push_event(RadioEvent {
            ts_millis: message.timestamp_ms as u128,
            key: key.to_string(),
            source: source.to_string(),
            value: json!({ "message": message }),
            message: Some(message),
        });
    }

    fn push_event(&self, event: RadioEvent) {
        let mut history = self
            .history
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        history.push_back(event);
        while history.len() > MAX_HISTORY {
            history.pop_front();
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RadioEvent {
    ts_millis: u128,
    key: String,
    source: String,
    value: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<MeshMessage>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RadioAdapter {
    id: String,
    kind: String,
    medium: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    baud: Option<u32>,
    enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NeighborInfo {
    node: String,
    last_seen_ms: u64,
    medium: Option<String>,
    network: Option<String>,
    radio_id: Option<String>,
    rssi: Option<i32>,
    snr: Option<f32>,
    source: Option<String>,
    last_event: Option<String>,
}

impl NeighborInfo {
    fn new(node: &str) -> Self {
        Self {
            node: node.to_string(),
            last_seen_ms: 0,
            medium: None,
            network: None,
            radio_id: None,
            rssi: None,
            snr: None,
            source: None,
            last_event: None,
        }
    }
}

fn serial_exchange(path: &str, baud: u32, command: &str) -> Result<Vec<MeshMessage>> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("failed to open serial radio {path}"))?;
    configure_serial(file.as_raw_fd(), baud)
        .with_context(|| format!("failed to configure serial radio {path}"))?;
    file.write_all(command.as_bytes())
        .with_context(|| format!("failed to write serial command to {path}"))?;
    file.write_all(b"\n")
        .with_context(|| format!("failed to write serial newline to {path}"))?;
    file.flush()
        .with_context(|| format!("failed to flush serial command to {path}"))?;

    let deadline = std::time::Instant::now() + Duration::from_millis(250);
    let mut bytes = Vec::new();
    let mut buf = [0_u8; 512];
    while std::time::Instant::now() < deadline {
        match file.read(&mut buf) {
            Ok(0) => std::thread::sleep(Duration::from_millis(10)),
            Ok(n) => {
                bytes.extend_from_slice(&buf[..n]);
                if bytes.contains(&b'\n') {
                    break;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error).with_context(|| format!("failed to read from {path}")),
        }
    }

    let text = String::from_utf8_lossy(&bytes);
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| mesh::message::parse_firmware_message_line(line).ok())
        .collect())
}

fn configure_serial(fd: RawFd, baud: u32) -> Result<()> {
    let mut termios = unsafe {
        let mut termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut termios) != 0 {
            return Err(std::io::Error::last_os_error()).context("tcgetattr failed");
        }
        termios
    };
    unsafe {
        libc::cfmakeraw(&mut termios);
    }
    let speed = baud_to_speed(baud)?;
    let rc = unsafe { libc::cfsetspeed(&mut termios, speed) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("cfsetspeed failed");
    }
    termios.c_cflag |= libc::CLOCAL | libc::CREAD;
    let rc = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("tcsetattr failed");
    }
    Ok(())
}

fn baud_to_speed(baud: u32) -> Result<libc::speed_t> {
    match baud {
        9_600 => Ok(libc::B9600),
        19_200 => Ok(libc::B19200),
        38_400 => Ok(libc::B38400),
        57_600 => Ok(libc::B57600),
        115_200 => Ok(libc::B115200),
        230_400 => Ok(libc::B230400),
        _ => bail!("unsupported serial baud {baud}"),
    }
}

#[derive(Debug, Deserialize)]
struct LmeshToml {
    #[serde(default)]
    radios: Vec<RadioConfig>,
}

#[derive(Debug, Deserialize)]
struct RadioConfig {
    id: Option<String>,
    kind: String,
    medium: Option<String>,
    path: Option<String>,
    network: Option<String>,
    baud: Option<u32>,
    enabled: Option<bool>,
}

fn load_radio_adapters() -> Vec<RadioAdapter> {
    let mut radios = vec![
        RadioAdapter {
            id: "host-mcast".to_string(),
            kind: "host-mcast".to_string(),
            medium: "mcast".to_string(),
            path: None,
            network: None,
            baud: None,
            enabled: true,
        },
        RadioAdapter {
            id: "host-ble".to_string(),
            kind: "host-ble".to_string(),
            medium: "ble".to_string(),
            path: Some(format!("hci{DEFAULT_HCI_DEV}")),
            network: None,
            baud: None,
            enabled: true,
        },
        RadioAdapter {
            id: "host-nan".to_string(),
            kind: "host-nan".to_string(),
            medium: "nan".to_string(),
            path: Some(format!("{}/{}", wpa_ctrl_dir(None), wifi_iface(None))),
            network: None,
            baud: None,
            enabled: true,
        },
    ];

    if let Ok(devices) = std::env::var("LMESH_SERIAL_DEVICES") {
        for (idx, path) in devices
            .split(',')
            .map(str::trim)
            .filter(|path| !path.is_empty())
            .enumerate()
        {
            radios.push(RadioAdapter {
                id: format!("esp-serial-{idx}"),
                kind: "esp-serial".to_string(),
                medium: "serial".to_string(),
                path: Some(path.to_string()),
                network: None,
                baud: Some(115_200),
                enabled: true,
            });
        }
    }

    if let Some(config) = read_lmesh_config() {
        for radio in config.radios {
            let default_baud = (radio.kind == "esp-serial").then_some(115_200);
            let id = radio.id.unwrap_or_else(|| {
                radio
                    .path
                    .as_deref()
                    .map(sanitize_radio_id)
                    .unwrap_or_else(|| radio.kind.clone())
            });
            radios.push(RadioAdapter {
                id,
                medium: radio
                    .medium
                    .unwrap_or_else(|| default_medium_for_kind(&radio.kind).to_string()),
                kind: radio.kind,
                path: radio.path,
                network: radio.network,
                baud: radio.baud.or(default_baud),
                enabled: radio.enabled.unwrap_or(true),
            });
        }
    }

    radios
}

fn read_lmesh_config() -> Option<LmeshToml> {
    let mesh_home = std::env::var_os("MESH_HOME").map(PathBuf::from)?;
    let path = mesh_home.join("lmesh.toml");
    let data = std::fs::read_to_string(path).ok()?;
    toml::from_str(&data).ok()
}

fn default_medium_for_kind(kind: &str) -> &'static str {
    match kind {
        "host-mcast" => "mcast",
        "host-ble" | "android-ble" => "ble",
        "host-nan" | "android-nan" => "nan",
        "esp-serial" => "serial",
        "remote-uds" => "remote",
        _ => "unknown",
    }
}

fn sanitize_radio_id(path: &str) -> String {
    path.chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

#[repr(C)]
struct SockaddrHci {
    hci_family: libc::sa_family_t,
    hci_dev: u16,
    hci_channel: u16,
}

struct HciSocket {
    fd: RawFd,
}

impl HciSocket {
    fn open(dev_id: u16) -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                AF_BLUETOOTH,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                BTPROTO_HCI,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context(
                "failed to open AF_BLUETOOTH raw HCI socket; CAP_NET_RAW is usually required",
            );
        }
        let addr = SockaddrHci {
            hci_family: AF_BLUETOOTH as libc::sa_family_t,
            hci_dev: dev_id,
            hci_channel: HCI_CHANNEL_RAW,
        };
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const SockaddrHci as *const libc::sockaddr,
                std::mem::size_of::<SockaddrHci>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(error).with_context(|| format!("failed to bind HCI device {dev_id}"));
        }
        Ok(Self { fd })
    }

    fn send_le_command(&self, ocf: u16, params: &[u8]) -> Result<()> {
        if params.len() > u8::MAX as usize {
            bail!("HCI command parameters too large: {}", params.len());
        }
        let opcode = (OGF_LE_CTL << 10) | ocf;
        let mut packet = Vec::with_capacity(4 + params.len());
        packet.push(HCI_COMMAND_PKT);
        packet.extend_from_slice(&opcode.to_le_bytes());
        packet.push(params.len() as u8);
        packet.extend_from_slice(params);
        let written = unsafe {
            libc::send(
                self.fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
            )
        };
        if written < 0 {
            return Err(std::io::Error::last_os_error()).context("failed to send HCI command");
        }
        Ok(())
    }
}

impl Drop for HciSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

fn adv_data(service_data: &[u8]) -> Result<Vec<u8>> {
    let field_len = 1 + service_data.len();
    if field_len > 0x1f {
        bail!("BLE advertisement service data too large: {}", field_len);
    }
    let mut adv = Vec::with_capacity(32);
    adv.push(field_len as u8);
    adv.push(0x16);
    adv.extend_from_slice(service_data);
    let mut out = Vec::with_capacity(32);
    out.push(adv.len() as u8);
    out.extend_from_slice(&adv);
    out.resize(32, 0);
    Ok(out)
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NlMsgErr {
    error: i32,
    msg: NlMsgHdr,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IfInfoMsg {
    ifi_family: u8,
    ifi_pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

fn set_link_up(iface: &str) -> std::result::Result<CommandOutput, String> {
    let iface_c = std::ffi::CString::new(iface.as_bytes())
        .map_err(|_| format!("interface name contains NUL byte: {iface:?}"))?;
    let ifindex = unsafe { libc::if_nametoindex(iface_c.as_ptr()) };
    if ifindex == 0 {
        return Err(format!(
            "if_nametoindex({iface}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(format!(
            "failed to open rtnetlink socket: {}",
            std::io::Error::last_os_error()
        ));
    }

    let result = unsafe { send_setlink_up(fd, ifindex as i32) };
    unsafe {
        libc::close(fd);
    }
    result.map(|()| CommandOutput {
        status: Some(0),
        stdout: format!("set {iface} up via rtnetlink"),
        stderr: String::new(),
    })
}

unsafe fn send_setlink_up(fd: RawFd, ifindex: i32) -> std::result::Result<(), String> {
    let header_len = std::mem::size_of::<NlMsgHdr>();
    let info_len = std::mem::size_of::<IfInfoMsg>();
    let msg_len = header_len + info_len;
    let header = NlMsgHdr {
        nlmsg_len: msg_len as u32,
        nlmsg_type: libc::RTM_NEWLINK,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };
    let mut info: IfInfoMsg = unsafe { std::mem::zeroed() };
    info.ifi_family = libc::AF_UNSPEC as u8;
    info.ifi_index = ifindex;
    info.ifi_flags = IFF_UP;
    info.ifi_change = IFF_UP;
    let mut request = Vec::with_capacity(msg_len);
    append_struct(&mut request, &header);
    append_struct(&mut request, &info);

    let written = unsafe {
        libc::send(
            fd,
            request.as_ptr() as *const libc::c_void,
            request.len(),
            0,
        )
    };
    if written < 0 {
        return Err(format!(
            "failed to send RTM_NEWLINK: {}",
            std::io::Error::last_os_error()
        ));
    }
    if written as usize != request.len() {
        return Err(format!(
            "short RTM_NEWLINK write: wrote {written}, expected {}",
            request.len()
        ));
    }

    let mut response = [0u8; 4096];
    let read = unsafe {
        libc::recv(
            fd,
            response.as_mut_ptr() as *mut libc::c_void,
            response.len(),
            0,
        )
    };
    if read < 0 {
        return Err(format!(
            "failed to read RTM_NEWLINK ACK: {}",
            std::io::Error::last_os_error()
        ));
    }
    parse_netlink_ack(&response[..read as usize])
}

fn append_struct<T>(out: &mut Vec<u8>, value: &T) {
    let bytes = unsafe {
        std::slice::from_raw_parts(value as *const T as *const u8, std::mem::size_of::<T>())
    };
    out.extend_from_slice(bytes);
}

fn parse_netlink_ack(response: &[u8]) -> std::result::Result<(), String> {
    if response.len() < std::mem::size_of::<NlMsgHdr>() {
        return Err("short netlink ACK".to_string());
    }
    let header = unsafe { std::ptr::read_unaligned(response.as_ptr() as *const NlMsgHdr) };
    if header.nlmsg_type != NLMSG_ERROR {
        return Ok(());
    }
    if response.len() < std::mem::size_of::<NlMsgHdr>() + std::mem::size_of::<NlMsgErr>() {
        return Err("short netlink error ACK".to_string());
    }
    let err_offset = std::mem::size_of::<NlMsgHdr>();
    let error = unsafe { std::ptr::read_unaligned(response[err_offset..].as_ptr() as *const i32) };
    if error == 0 {
        Ok(())
    } else {
        let errno = -error;
        Err(format!(
            "RTM_NEWLINK failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ))
    }
}

fn wpa_command(
    iface: &str,
    ctrl_dir: &str,
    command: &str,
) -> std::result::Result<CommandOutput, String> {
    wpa_ctrl_command(iface, ctrl_dir, command)
}

fn wpa_raw_command(
    iface: &str,
    ctrl_dir: &str,
    command: &str,
) -> std::result::Result<CommandOutput, String> {
    wpa_ctrl_command(iface, ctrl_dir, command)
}

fn wpa_ctrl_command(
    iface: &str,
    ctrl_dir: &str,
    command: &str,
) -> std::result::Result<CommandOutput, String> {
    let server_path = format!("{ctrl_dir}/{iface}");
    let client_path = format!(
        "/tmp/lmesh-wpa-{}-{}-{}.sock",
        unsafe { libc::getuid() },
        std::process::id(),
        now_millis()
    );
    let socket = UnixDatagram::bind(&client_path)
        .map_err(|error| format!("failed to bind WPA client socket {client_path}: {error}"))?;
    let _unlink_client = UnlinkOnDrop(client_path.clone());
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("failed to set WPA read timeout: {error}"))?;
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("failed to set WPA write timeout: {error}"))?;
    socket
        .connect(&server_path)
        .map_err(|error| format!("failed to connect WPA control socket {server_path}: {error}"))?;
    socket
        .send(command.as_bytes())
        .map_err(|error| format!("failed to send WPA command {command:?}: {error}"))?;
    let mut response = vec![0_u8; 8192];
    let len = socket
        .recv(&mut response)
        .map_err(|error| format!("failed to receive WPA response for {command:?}: {error}"))?;
    response.truncate(len);
    let stdout = String::from_utf8_lossy(&response).trim().to_string();
    let ok = !(stdout.starts_with("FAIL") || stdout.starts_with("UNKNOWN COMMAND"));
    Ok(CommandOutput {
        status: Some(if ok { 0 } else { 1 }),
        stdout,
        stderr: String::new(),
    })
}

struct UnlinkOnDrop(String);

impl Drop for UnlinkOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[derive(Debug)]
struct CommandOutput {
    status: Option<i32>,
    stdout: String,
    stderr: String,
}

fn command_result_json(output: std::result::Result<CommandOutput, String>) -> Value {
    match output {
        Ok(output) => json!({
            "ok": output.status == Some(0),
            "status": output.status,
            "stdout": output.stdout,
            "stderr": output.stderr,
        }),
        Err(error) => json!({ "ok": false, "error": error }),
    }
}

fn wifi_iface(value: Option<String>) -> String {
    value
        .or_else(|| std::env::var("LMESH_WIFI_IFACE").ok())
        .unwrap_or_else(|| DEFAULT_WIFI_IFACE.to_string())
}

fn wpa_ctrl_dir(value: Option<String>) -> String {
    value
        .or_else(|| std::env::var("LMESH_WPA_CTRL_DIR").ok())
        .unwrap_or_else(|| DEFAULT_WPA_CTRL_DIR.to_string())
}

fn process_caps() -> Value {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let caps = status
        .lines()
        .filter(|line| {
            line.starts_with("CapInh:")
                || line.starts_with("CapPrm:")
                || line.starts_with("CapEff:")
                || line.starts_with("CapBnd:")
                || line.starts_with("CapAmb:")
        })
        .map(|line| {
            let mut parts = line.split_whitespace();
            let name = parts.next().unwrap_or("").trim_end_matches(':').to_string();
            let value = parts.next().unwrap_or("").to_string();
            (name, Value::String(value))
        })
        .collect::<serde_json::Map<_, _>>();
    Value::Object(caps)
}

fn hci_probe(dev_id: u16) -> Value {
    match HciSocket::open(dev_id) {
        Ok(_) => json!({ "ok": true, "dev_id": dev_id, "backend": "linux_hci_raw" }),
        Err(error) => json!({ "ok": false, "dev_id": dev_id, "error": error.to_string() }),
    }
}

fn local_device_id() -> Result<[u8; 6]> {
    if let Some(value) = std::env::var("LMESH_DEVICE_ID").ok() {
        if let Some(id) = parse_device_id(Some(&value)) {
            return Ok(id);
        }
        bail!("LMESH_DEVICE_ID must be 12 hex chars or colon-separated 6-byte hex");
    }
    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "lmesh".to_string());
    let digest = crate::public_key_sha(&hostname);
    parse_device_id(Some(&digest[..12])).context("failed to derive local DMesh device id")
}

fn parse_device_id(value: Option<&str>) -> Option<[u8; 6]> {
    let value = value?;
    let compact = value.replace(':', "");
    if compact.len() != 12 {
        return None;
    }
    let mut out = [0_u8; 6];
    for (idx, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&compact[idx * 2..idx * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn colon_mac(bytes: &[u8; 6]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn now_millis_u64() -> u64 {
    now_millis().min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_device_ids() {
        assert_eq!(
            parse_device_id(Some("001122334455")).unwrap(),
            [0, 17, 34, 51, 68, 85]
        );
        assert_eq!(
            parse_device_id(Some("00:11:22:33:44:55")).unwrap(),
            [0, 17, 34, 51, 68, 85]
        );
        assert!(parse_device_id(Some("0011")).is_none());
    }
}
