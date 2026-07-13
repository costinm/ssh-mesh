use anyhow::{Context, Result, bail};
use mesh::message::{
    FIELD_CTRL_DIR, FIELD_IFACE, FIELD_LEN, FIELD_MEDIUM, FIELD_NETWORK, FIELD_NODE, FIELD_PAYLOAD,
    FIELD_RADIO_ID, FIELD_RSSI, FIELD_SNR, FIELD_STATUS, MeshMessage, MeshMessageCodec, TextRecord,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::radio_protocol;

const DEFAULT_WIFI_IFACE: &str = "wlan1";
const DEFAULT_WPA_CTRL_DIR: &str = "/run/ssh-mesh-wpa";
const DEFAULT_WPA_SERVICE_NAME: &str = "dmesh";
const DEFAULT_HCI_DEV: u16 = 0;
const DEFAULT_RAW_WIFI_CHANNEL: u8 = 6;
const DEFAULT_RAW_WIFI_LISTEN_SECS: u64 = 60;
const MAX_HISTORY: usize = 128;
const ETH_P_ALL: u16 = 0x0003;
const NETLINK_GENERIC: libc::c_int = 16;
const NETLINK_EXT_ACK: libc::c_int = 11;
const GENL_ID_CTRL: u16 = 16;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const NLMSGERR_ATTR_MSG: u16 = 1;
const NLMSGERR_ATTR_OFFS: u16 = 2;
const NLMSGERR_ATTR_MISS_TYPE: u16 = 5;
const NL80211_GENL_VERSION: u8 = 1;
const NL80211_CMD_REMAIN_ON_CHANNEL: u8 = 55;
const NL80211_CMD_REGISTER_FRAME: u8 = 58;
const NL80211_CMD_FRAME: u8 = 59;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
const NL80211_ATTR_FRAME: u16 = 51;
const NL80211_ATTR_DURATION: u16 = 87;
const NL80211_ATTR_FRAME_MATCH: u16 = 91;
const NL80211_ATTR_FRAME_TYPE: u16 = 101;
const NL80211_ATTR_OFFCHANNEL_TX_OK: u16 = 108;
const NL80211_ATTR_TX_NO_CCK_RATE: u16 = 135;
const NL80211_ATTR_DONT_WAIT_FOR_ACK: u16 = 142;
const DMESH_VENDOR_ACTION: [u8; 5] = [0x7f, 0x50, 0x6f, 0x9a, 0x42];
const IEEE80211_ADDR1: usize = 4;
const IEEE80211_ADDR2: usize = 10;
const IEEE80211_ADDR3: usize = 16;
const IEEE80211_BODY: usize = 24;
const IEEE80211_ACTION_FRAME_TYPE: u16 = 0x00d0;
const RAW_WIFI_BROADCAST: [u8; 6] = [0xff; 6];
const RAW_WIFI_MULTICAST: [u8; 6] = [0x01, 0x00, 0x5e, 0x44, 0x4d, 0x01];
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
    raw_wifi_listeners: Arc<Mutex<HashSet<String>>>,
}

impl RadioService {
    /// Create a radio service from environment and optional MESH_HOME/lmesh.toml config.
    pub fn from_environment() -> Self {
        Self {
            history: Arc::new(Mutex::new(VecDeque::new())),
            radios: Arc::new(load_radio_adapters()),
            raw_wifi_listeners: Arc::new(Mutex::new(HashSet::new())),
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

    /// Start a direct nl80211 listener for ESP32 DMesh vendor action frames.
    pub fn wifi_raw_listen(
        &self,
        iface: Option<String>,
        ctrl_dir: Option<String>,
        channel: Option<u8>,
        listen_sec: Option<u64>,
        rx_variant: Option<String>,
    ) -> Value {
        let iface = wifi_iface(iface);
        let ctrl_dir = wpa_ctrl_dir(ctrl_dir);
        let channel = raw_wifi_channel(channel);
        let listen_sec = listen_sec.unwrap_or(DEFAULT_RAW_WIFI_LISTEN_SECS).max(1);
        let wpa_channel = prepare_raw_wifi_channel(&iface, &ctrl_dir, channel, listen_sec);
        let rx_variant = rx_variant.unwrap_or_else(|| "nl80211".to_string());
        let listener_key = format!("{iface}:{rx_variant}");
        {
            let mut listeners = self
                .raw_wifi_listeners
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !listeners.insert(listener_key.clone()) {
                return json!({
                    "ok": true,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "ctrl_dir": ctrl_dir,
                    "channel": channel,
                    "listen_sec": listen_sec,
                    "rx_variant": rx_variant,
                    "wpa_channel": wpa_channel,
                    "already_running": true,
                });
            }
        }

        let listen_result = if rx_variant == "monitor" {
            let monitor_iface = format!("{iface}mon");
            ensure_monitor_iface(&iface, &monitor_iface, channel).and_then(|setup| {
                let socket = MonitorRxSocket::open(&monitor_iface)?;
                let history = self.history.clone();
                let listeners = self.raw_wifi_listeners.clone();
                let iface_for_thread = iface.clone();
                let monitor_for_thread = monitor_iface.clone();
                let listener_key_for_thread = listener_key.clone();
                std::thread::spawn(move || {
                    monitor_receive_loop(socket, &iface_for_thread, &monitor_for_thread, history);
                    listeners
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .remove(&listener_key_for_thread);
                });
                Ok(json!({
                    "ok": true,
                    "backend": "linux_af_packet_monitor",
                    "iface": iface,
                    "monitor_iface": monitor_iface,
                    "ctrl_dir": ctrl_dir,
                    "channel": channel,
                    "listen_sec": listen_sec,
                    "rx_variant": rx_variant,
                    "monitor": setup,
                    "wpa_channel": wpa_channel,
                    "note": "monitor listener records DMesh action and multicast data frames visible on this interface",
                }))
            })
        } else if rx_variant == "nl80211" {
            Nl80211Socket::open()
                .and_then(|socket| {
                    socket.register_dmesh_action(ifindex(&iface)?)?;
                    Ok(socket)
                })
                .map(|socket| {
                    let history = self.history.clone();
                    let listeners = self.raw_wifi_listeners.clone();
                    let iface_for_thread = iface.clone();
                    let listener_key_for_thread = listener_key.clone();
                    std::thread::spawn(move || {
                        nl80211_receive_loop(socket, &iface_for_thread, history);
                        listeners
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .remove(&listener_key_for_thread);
                    });
                    json!({
                        "ok": true,
                        "backend": "linux_nl80211",
                        "iface": iface,
                        "ctrl_dir": ctrl_dir,
                        "channel": channel,
                        "listen_sec": listen_sec,
                        "rx_variant": rx_variant,
                        "wpa_channel": wpa_channel,
                        "note": "listener records ESP32 DMesh vendor action frames visible on this interface",
                    })
                })
        } else {
            Err(anyhow::anyhow!(
                "unknown rx_variant {rx_variant:?}; expected nl80211 or monitor"
            ))
        };

        match listen_result {
            Ok(result) => {
                self.record_message(
                    "wifi.raw.listen",
                    "host-wifi",
                    MeshMessage::new(mesh::message::KIND_EVENT, MeshMessageCodec::Text)
                        .field(FIELD_MEDIUM, "wifi")
                        .field(FIELD_IFACE, &iface)
                        .field(FIELD_STATUS, "listening"),
                );
                self.record("wifi.raw.listen", result.clone());
                result
            }
            Err(error) => {
                self.raw_wifi_listeners
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .remove(&listener_key);
                json!({
                    "ok": false,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "error": format!("{error:#}"),
                })
            }
        }
    }

    /// Send an ESP32-compatible DMesh vendor action frame.
    pub fn wifi_raw_send(
        &self,
        iface: Option<String>,
        ctrl_dir: Option<String>,
        channel: Option<u8>,
        listen_sec: Option<u64>,
        destination: Option<String>,
        tx_variant: Option<String>,
        tx_duration_ms: Option<u32>,
        payload: String,
    ) -> Value {
        let iface = wifi_iface(iface);
        let ctrl_dir = wpa_ctrl_dir(ctrl_dir);
        let channel = raw_wifi_channel(channel);
        let listen_sec = listen_sec.unwrap_or(DEFAULT_RAW_WIFI_LISTEN_SECS).max(1);
        let tx_options =
            match RawWifiTxOptions::from_variant(tx_variant.as_deref(), listen_sec, tx_duration_ms)
            {
                Ok(options) => options,
                Err(error) => {
                    return json!({
                        "ok": false,
                        "backend": "linux_nl80211",
                        "iface": iface,
                        "error": error.to_string(),
                    });
                }
            };
        let wpa_channel = if tx_options.variant == "roc" {
            json!({
                "skipped": true,
                "reason": "tx_variant=roc owns nl80211 remain-on-channel directly",
            })
        } else {
            prepare_raw_wifi_channel(&iface, &ctrl_dir, channel, listen_sec)
        };
        let destination = parse_mac(destination.as_deref()).unwrap_or_else(|| {
            if tx_options.variant == "multicast_data" {
                RAW_WIFI_MULTICAST
            } else {
                RAW_WIFI_BROADCAST
            }
        });
        let source = match iface_mac(&iface) {
            Ok(source) => source,
            Err(error) => {
                return json!({
                    "ok": false,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "error": format!("{error:#}"),
                });
            }
        };
        let frame = if tx_options.variant == "multicast_data" {
            build_dmesh_multicast_data_frame(destination, source, payload.as_bytes())
        } else {
            build_dmesh_vendor_action_frame(destination, source, payload.as_bytes())
        };
        let result = if tx_options.variant == "monitor" || tx_options.variant == "multicast_data" {
            match send_monitor_frame(&iface, channel, &frame) {
                Ok(monitor) => json!({
                    "ok": true,
                    "backend": "linux_af_packet_monitor",
                    "tx_variant": tx_options.variant,
                    "tx_options": tx_options.as_json(),
                    "monitor": monitor,
                    "iface": iface,
                    "ctrl_dir": ctrl_dir,
                    "channel": channel,
                "listen_sec": listen_sec,
                "tx_duration_ms": tx_duration_ms,
                "wpa_channel": wpa_channel,
                    "destination": colon_mac(&destination),
                    "source": colon_mac(&source),
                    "payload_len": payload.len(),
                    "frame_len": frame.len(),
                }),
                Err(error) => json!({
                    "ok": false,
                    "backend": "linux_af_packet_monitor",
                    "tx_variant": tx_options.variant,
                    "tx_options": tx_options.as_json(),
                    "iface": iface,
                    "error": format!("{error:#}"),
                }),
            }
        } else {
            match Nl80211Socket::open().and_then(|socket| {
                if tx_options.variant == "roc" {
                    socket.remain_on_channel(
                        ifindex(&iface)?,
                        channel_to_freq(channel),
                        tx_options.duration_ms.unwrap_or(10),
                    )?;
                }
                socket.send_frame(
                    ifindex(&iface)?,
                    channel_to_freq(channel),
                    &tx_options,
                    &frame,
                )
            }) {
                Ok(()) => json!({
                    "ok": true,
                    "backend": "linux_nl80211",
                    "tx_variant": tx_options.variant,
                    "tx_options": tx_options.as_json(),
                    "iface": iface,
                    "ctrl_dir": ctrl_dir,
                    "channel": channel,
                    "listen_sec": listen_sec,
                    "tx_duration_ms": tx_duration_ms,
                    "wpa_channel": wpa_channel,
                    "destination": colon_mac(&destination),
                    "source": colon_mac(&source),
                    "payload_len": payload.len(),
                    "frame_len": frame.len(),
                }),
                Err(error) => json!({
                    "ok": false,
                    "backend": "linux_nl80211",
                    "tx_variant": tx_options.variant,
                    "tx_options": tx_options.as_json(),
                    "iface": iface,
                    "error": format!("{error:#}"),
                }),
            }
        };
        self.record_message(
            "wifi.raw.tx",
            "host-wifi",
            MeshMessage::new(mesh::message::KIND_EVENT, MeshMessageCodec::Text)
                .field(FIELD_MEDIUM, "wifi")
                .field(FIELD_IFACE, &iface)
                .field(mesh::message::FIELD_PEER, colon_mac(&destination))
                .field(FIELD_LEN, payload.len())
                .field(FIELD_PAYLOAD, payload),
        );
        self.record("wifi.raw.tx", result.clone());
        result
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

#[repr(C)]
#[derive(Clone, Copy)]
struct GenlMsgHdr {
    cmd: u8,
    version: u8,
    reserved: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NlAttrHdr {
    nla_len: u16,
    nla_type: u16,
}

struct Nl80211Socket {
    fd: RawFd,
    family_id: u16,
}

#[derive(Clone)]
struct RawWifiTxOptions {
    variant: String,
    include_freq: bool,
    duration_ms: Option<u32>,
    offchannel_tx_ok: bool,
    dont_wait_for_ack: bool,
    tx_no_cck_rate: bool,
}

impl RawWifiTxOptions {
    fn from_variant(
        variant: Option<&str>,
        listen_sec: u64,
        tx_duration_ms: Option<u32>,
    ) -> Result<Self> {
        let variant = variant.unwrap_or("standard").trim();
        let duration_ms = tx_duration_ms
            .unwrap_or_else(|| listen_sec.saturating_mul(1000).min(u32::MAX as u64) as u32);
        let options = match variant {
            "" | "standard" => Self {
                variant: "standard".to_string(),
                include_freq: true,
                duration_ms: Some(duration_ms),
                offchannel_tx_ok: true,
                dont_wait_for_ack: false,
                tx_no_cck_rate: false,
            },
            "zero_duration" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: Some(0),
                offchannel_tx_ok: true,
                dont_wait_for_ack: false,
                tx_no_cck_rate: false,
            },
            "no_duration" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: None,
                offchannel_tx_ok: true,
                dont_wait_for_ack: false,
                tx_no_cck_rate: false,
            },
            "no_offchannel" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: Some(duration_ms),
                offchannel_tx_ok: false,
                dont_wait_for_ack: false,
                tx_no_cck_rate: false,
            },
            "minimal" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: false,
                tx_no_cck_rate: false,
            },
            "dont_wait_ack" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: Some(duration_ms),
                offchannel_tx_ok: true,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "dont_wait_no_duration" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: None,
                offchannel_tx_ok: true,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "dont_wait_minimal" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "dont_wait_no_cck" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: None,
                offchannel_tx_ok: true,
                dont_wait_for_ack: true,
                tx_no_cck_rate: true,
            },
            "no_cck" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: Some(duration_ms),
                offchannel_tx_ok: true,
                dont_wait_for_ack: false,
                tx_no_cck_rate: true,
            },
            "no_freq" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: Some(duration_ms),
                offchannel_tx_ok: true,
                dont_wait_for_ack: false,
                tx_no_cck_rate: false,
            },
            "monitor" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "multicast_data" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "roc" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: Some(tx_duration_ms.unwrap_or(10)),
                offchannel_tx_ok: true,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "pyroute2" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: Some(duration_ms),
                offchannel_tx_ok: false,
                dont_wait_for_ack: false,
                tx_no_cck_rate: false,
            },
            other => bail!(
                "unknown tx_variant {other:?}; expected standard, zero_duration, no_duration, no_offchannel, minimal, dont_wait_ack, dont_wait_no_duration, dont_wait_minimal, dont_wait_no_cck, no_cck, no_freq, monitor, multicast_data, roc, or pyroute2"
            ),
        };
        Ok(options)
    }

    fn as_json(&self) -> Value {
        json!({
            "include_freq": self.include_freq,
            "duration_ms": self.duration_ms,
            "offchannel_tx_ok": self.offchannel_tx_ok,
            "dont_wait_for_ack": self.dont_wait_for_ack,
            "tx_no_cck_rate": self.tx_no_cck_rate,
        })
    }
}

impl Nl80211Socket {
    fn open() -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_GENERIC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to open NETLINK_GENERIC socket");
        }
        let enable: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_NETLINK,
                NETLINK_EXT_ACK,
                &enable as *const libc::c_int as *const libc::c_void,
                std::mem::size_of_val(&enable) as libc::socklen_t,
            );
        }
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_pid = 0;
        addr.nl_groups = 0;
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(error).context("failed to bind NETLINK_GENERIC socket");
        }
        let mut socket = Self { fd, family_id: 0 };
        let family_id = socket.resolve_family("nl80211")?;
        socket.family_id = family_id;
        Ok(socket)
    }

    fn resolve_family(&self, name: &str) -> Result<u16> {
        let mut payload = genl_payload(CTRL_CMD_GETFAMILY, 2);
        let mut name_bytes = name.as_bytes().to_vec();
        name_bytes.push(0);
        append_attr(&mut payload, CTRL_ATTR_FAMILY_NAME, &name_bytes);
        self.send_genl(GENL_ID_CTRL, libc::NLM_F_REQUEST as u16, 1, &payload)?;
        let response = self.recv_netlink()?;
        let attrs = genl_attrs(&response)?;
        for (kind, value) in attrs {
            if kind == CTRL_ATTR_FAMILY_ID && value.len() >= 2 {
                return Ok(u16::from_ne_bytes([value[0], value[1]]));
            }
        }
        bail!("nl80211 generic netlink family id not found")
    }

    fn register_dmesh_action(&self, ifindex: u32) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_REGISTER_FRAME, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        append_attr(
            &mut payload,
            NL80211_ATTR_FRAME_TYPE,
            &IEEE80211_ACTION_FRAME_TYPE.to_ne_bytes(),
        );
        append_attr(&mut payload, NL80211_ATTR_FRAME_MATCH, &DMESH_VENDOR_ACTION);
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            2,
            &payload,
        )?;
        self.recv_ack()
            .context("failed to register DMesh action frame match")
    }

    fn remain_on_channel(&self, ifindex: u32, freq: u32, duration_ms: u32) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_REMAIN_ON_CHANNEL, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_WIPHY_FREQ, &freq.to_ne_bytes());
        append_attr(
            &mut payload,
            NL80211_ATTR_DURATION,
            &duration_ms.to_ne_bytes(),
        );
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            4,
            &payload,
        )?;
        self.recv_ack()
            .context("nl80211 remain-on-channel failed")?;
        let settle_ms = duration_ms.saturating_div(2).clamp(1, 20);
        std::thread::sleep(Duration::from_millis(settle_ms as u64));
        Ok(())
    }

    fn send_frame(
        &self,
        ifindex: u32,
        freq: u32,
        options: &RawWifiTxOptions,
        frame: &[u8],
    ) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_FRAME, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        if options.include_freq {
            append_attr(&mut payload, NL80211_ATTR_WIPHY_FREQ, &freq.to_ne_bytes());
        }
        if let Some(duration_ms) = options.duration_ms {
            append_attr(
                &mut payload,
                NL80211_ATTR_DURATION,
                &duration_ms.to_ne_bytes(),
            );
        }
        append_attr(&mut payload, NL80211_ATTR_FRAME, frame);
        if options.offchannel_tx_ok {
            append_attr(&mut payload, NL80211_ATTR_OFFCHANNEL_TX_OK, &[]);
        }
        if options.dont_wait_for_ack {
            append_attr(&mut payload, NL80211_ATTR_DONT_WAIT_FOR_ACK, &[]);
        }
        if options.tx_no_cck_rate {
            append_attr(&mut payload, NL80211_ATTR_TX_NO_CCK_RATE, &[]);
        }
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            3,
            &payload,
        )?;
        self.recv_ack().context("nl80211 frame TX failed")
    }

    fn recv_frame(&self) -> Result<Vec<u8>> {
        loop {
            let response = self.recv_netlink()?;
            let Some(header) = genl_header(&response) else {
                continue;
            };
            if header.cmd != NL80211_CMD_FRAME {
                continue;
            }
            for (kind, value) in genl_attrs(&response)? {
                if kind == NL80211_ATTR_FRAME {
                    return Ok(value.to_vec());
                }
            }
        }
    }

    fn send_genl(&self, nlmsg_type: u16, flags: u16, seq: u32, payload: &[u8]) -> Result<()> {
        let header = libc::nlmsghdr {
            nlmsg_len: (std::mem::size_of::<libc::nlmsghdr>() + payload.len()) as u32,
            nlmsg_type,
            nlmsg_flags: flags,
            nlmsg_seq: seq,
            nlmsg_pid: 0,
        };
        let mut request = Vec::with_capacity(header.nlmsg_len as usize);
        append_struct(&mut request, &header);
        request.extend_from_slice(payload);
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        kernel.nl_pid = 0;
        kernel.nl_groups = 0;
        let written = unsafe {
            libc::sendto(
                self.fd,
                request.as_ptr() as *const libc::c_void,
                request.len(),
                0,
                &kernel as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if written < 0 {
            let os_error = std::io::Error::last_os_error();
            bail!(
                "failed to send netlink request type={} len={} flags=0x{:x}: {}",
                nlmsg_type,
                request.len(),
                flags,
                os_error
            );
        }
        Ok(())
    }

    fn recv_netlink(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0_u8; 65536];
        let read =
            unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if read < 0 {
            return Err(std::io::Error::last_os_error()).context("failed to receive netlink reply");
        }
        buf.truncate(read as usize);
        if let Some(error) = netlink_error(&buf) {
            bail!(
                "netlink error: {}{}",
                std::io::Error::from_raw_os_error(error),
                netlink_extack_message(&buf)
            );
        }
        Ok(buf)
    }

    fn recv_ack(&self) -> Result<()> {
        let response = self.recv_netlink()?;
        if netlink_is_ack(&response) {
            Ok(())
        } else {
            Ok(())
        }
    }
}

impl Drop for Nl80211Socket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

struct MonitorTxSocket {
    fd: RawFd,
}

struct MonitorRxSocket {
    fd: RawFd,
}

impl MonitorTxSocket {
    fn open(iface: &str) -> Result<Self> {
        let ifindex = ifindex(iface)?;
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                (ETH_P_ALL as i32).to_be(),
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to open AF_PACKET raw socket for monitor TX");
        }
        let addr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as libc::sa_family_t,
            sll_protocol: ETH_P_ALL.to_be(),
            sll_ifindex: ifindex as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(error).with_context(|| format!("failed to bind AF_PACKET to {iface}"));
        }
        Ok(Self { fd })
    }

    fn send(&self, packet: &[u8]) -> Result<usize> {
        let written = unsafe {
            libc::send(
                self.fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
            )
        };
        if written < 0 {
            Err(std::io::Error::last_os_error()).context("failed to send monitor frame")
        } else {
            Ok(written as usize)
        }
    }
}

impl MonitorRxSocket {
    fn open(iface: &str) -> Result<Self> {
        let ifindex = ifindex(iface)?;
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                (ETH_P_ALL as i32).to_be(),
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to open AF_PACKET raw socket for monitor RX");
        }
        let addr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as libc::sa_family_t,
            sll_protocol: ETH_P_ALL.to_be(),
            sll_ifindex: ifindex as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(error).with_context(|| format!("failed to bind AF_PACKET to {iface}"));
        }
        Ok(Self { fd })
    }

    fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read =
            unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if read < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(read as usize)
        }
    }
}

impl Drop for MonitorTxSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

impl Drop for MonitorRxSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

fn send_monitor_frame(iface: &str, channel: u8, frame: &[u8]) -> Result<Value> {
    let monitor_iface = format!("{iface}mon");
    let setup = ensure_monitor_iface(iface, &monitor_iface, channel)?;
    let packet = build_radiotap_packet(frame);
    let socket = MonitorTxSocket::open(&monitor_iface)?;
    let written = socket.send(&packet)?;
    if written != packet.len() {
        bail!(
            "short monitor frame write: wrote {written}, expected {}",
            packet.len()
        );
    }
    Ok(json!({
        "iface": monitor_iface,
        "packet_len": packet.len(),
        "setup": setup,
    }))
}

fn ensure_monitor_iface(base_iface: &str, monitor_iface: &str, channel: u8) -> Result<Value> {
    let mut steps = Vec::new();
    if ifindex(monitor_iface).is_err() {
        steps.push(run_command(
            "iw",
            &[
                "dev",
                base_iface,
                "interface",
                "add",
                monitor_iface,
                "type",
                "monitor",
            ],
        ));
    }
    steps.push(run_command("ip", &["link", "set", monitor_iface, "up"]));
    steps.push(run_command(
        "iw",
        &["dev", monitor_iface, "set", "channel", &channel.to_string()],
    ));
    let failed = steps
        .iter()
        .filter(|step| {
            if step.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                return false;
            }
            let is_channel_busy = step
                .get("args")
                .and_then(Value::as_array)
                .map(|args| args.iter().any(|arg| arg.as_str() == Some("channel")))
                .unwrap_or(false)
                && step
                    .get("stderr")
                    .and_then(Value::as_str)
                    .map(|stderr| stderr.contains("Device or resource busy"))
                    .unwrap_or(false);
            !is_channel_busy
        })
        .cloned()
        .collect::<Vec<_>>();
    if !failed.is_empty() {
        bail!(
            "failed to prepare monitor interface {monitor_iface}: {}",
            json!(failed)
        );
    }
    Ok(json!(steps))
}

fn run_command(program: &str, args: &[&str]) -> Value {
    match Command::new(program).args(args).output() {
        Ok(output) => json!({
            "program": program,
            "args": args,
            "ok": output.status.success(),
            "status": output.status.code(),
            "stdout": String::from_utf8_lossy(&output.stdout).trim(),
            "stderr": String::from_utf8_lossy(&output.stderr).trim(),
        }),
        Err(error) => json!({
            "program": program,
            "args": args,
            "ok": false,
            "error": error.to_string(),
        }),
    }
}

fn build_radiotap_packet(frame: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(8 + frame.len());
    packet.extend_from_slice(&[0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(frame);
    packet
}

fn genl_payload(cmd: u8, version: u8) -> Vec<u8> {
    let mut payload = Vec::new();
    append_struct(
        &mut payload,
        &GenlMsgHdr {
            cmd,
            version,
            reserved: 0,
        },
    );
    payload
}

fn append_attr(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let len = std::mem::size_of::<NlAttrHdr>() + value.len();
    append_struct(
        out,
        &NlAttrHdr {
            nla_len: len as u16,
            nla_type: kind,
        },
    );
    out.extend_from_slice(value);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

fn netlink_payload(response: &[u8]) -> Result<&[u8]> {
    if response.len() < std::mem::size_of::<libc::nlmsghdr>() {
        bail!("short netlink message");
    }
    let header = unsafe { std::ptr::read_unaligned(response.as_ptr() as *const libc::nlmsghdr) };
    let len = header.nlmsg_len as usize;
    if len < std::mem::size_of::<libc::nlmsghdr>() || len > response.len() {
        bail!("invalid netlink message length {len}");
    }
    Ok(&response[std::mem::size_of::<libc::nlmsghdr>()..len])
}

fn genl_header(response: &[u8]) -> Option<GenlMsgHdr> {
    let payload = netlink_payload(response).ok()?;
    if payload.len() < std::mem::size_of::<GenlMsgHdr>() {
        return None;
    }
    Some(unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const GenlMsgHdr) })
}

fn genl_attrs(response: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let payload = netlink_payload(response)?;
    if payload.len() < std::mem::size_of::<GenlMsgHdr>() {
        bail!("short generic netlink message");
    }
    parse_attrs(&payload[std::mem::size_of::<GenlMsgHdr>()..])
}

fn parse_attrs(mut bytes: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut attrs = Vec::new();
    while bytes.len() >= std::mem::size_of::<NlAttrHdr>() {
        let header = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const NlAttrHdr) };
        let len = header.nla_len as usize;
        if len < std::mem::size_of::<NlAttrHdr>() || len > bytes.len() {
            break;
        }
        attrs.push((
            header.nla_type,
            &bytes[std::mem::size_of::<NlAttrHdr>()..len],
        ));
        let aligned = (len + 3) & !3;
        if aligned > bytes.len() {
            break;
        }
        bytes = &bytes[aligned..];
    }
    Ok(attrs)
}

fn netlink_error(response: &[u8]) -> Option<i32> {
    if response.len() < std::mem::size_of::<libc::nlmsghdr>() + 4 {
        return None;
    }
    let header = unsafe { std::ptr::read_unaligned(response.as_ptr() as *const libc::nlmsghdr) };
    if header.nlmsg_type != NLMSG_ERROR {
        return None;
    }
    let offset = std::mem::size_of::<libc::nlmsghdr>();
    let error = unsafe { std::ptr::read_unaligned(response[offset..].as_ptr() as *const i32) };
    (error < 0).then_some(-error)
}

fn netlink_extack_message(response: &[u8]) -> String {
    let Some(attrs) = netlink_extack_attrs(response) else {
        return String::new();
    };
    let mut details = Vec::new();
    for (kind, value) in attrs {
        match kind {
            NLMSGERR_ATTR_MSG => {
                let text = String::from_utf8_lossy(trim_nul(value)).trim().to_string();
                if !text.is_empty() {
                    details.push(format!("msg={text:?}"));
                }
            }
            NLMSGERR_ATTR_OFFS if value.len() >= 4 => {
                let offset = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
                details.push(format!("offset={offset}"));
            }
            NLMSGERR_ATTR_MISS_TYPE if value.len() >= 4 => {
                let attr = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
                details.push(format!("missing_attr={attr}"));
            }
            _ => {}
        }
    }
    if details.is_empty() {
        String::new()
    } else {
        format!(" ({})", details.join(", "))
    }
}

fn netlink_extack_attrs(response: &[u8]) -> Option<Vec<(u16, &[u8])>> {
    let header_len = std::mem::size_of::<libc::nlmsghdr>();
    let error_len = std::mem::size_of::<i32>();
    if response.len() < header_len + error_len + header_len {
        return None;
    }
    let header = unsafe { std::ptr::read_unaligned(response.as_ptr() as *const libc::nlmsghdr) };
    if header.nlmsg_type != NLMSG_ERROR {
        return None;
    }
    let original_offset = header_len + error_len;
    let original = unsafe {
        std::ptr::read_unaligned(response[original_offset..].as_ptr() as *const libc::nlmsghdr)
    };
    let full_original_error_len = nlmsg_align(error_len + original.nlmsg_len as usize);
    let compact_error_len = nlmsg_align(error_len + header_len);
    for ext_offset in [
        header_len + full_original_error_len,
        header_len + compact_error_len,
    ] {
        if ext_offset < response.len()
            && let Ok(attrs) = parse_attrs(&response[ext_offset..])
            && !attrs.is_empty()
        {
            return Some(attrs);
        }
    }
    None
}

fn trim_nul(value: &[u8]) -> &[u8] {
    match value.iter().position(|byte| *byte == 0) {
        Some(pos) => &value[..pos],
        None => value,
    }
}

fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

fn netlink_is_ack(response: &[u8]) -> bool {
    if response.len() < std::mem::size_of::<libc::nlmsghdr>() + 4 {
        return false;
    }
    let header = unsafe { std::ptr::read_unaligned(response.as_ptr() as *const libc::nlmsghdr) };
    if header.nlmsg_type != NLMSG_ERROR {
        return false;
    }
    let offset = std::mem::size_of::<libc::nlmsghdr>();
    let error = unsafe { std::ptr::read_unaligned(response[offset..].as_ptr() as *const i32) };
    error == 0
}

fn nl80211_receive_loop(
    socket: Nl80211Socket,
    iface: &str,
    history: Arc<Mutex<VecDeque<RadioEvent>>>,
) {
    loop {
        match socket.recv_frame() {
            Ok(frame) => {
                if let Some(value) = parse_dmesh_vendor_action(&frame, iface) {
                    let message = mesh_message_from_raw_wifi(&value, iface);
                    push_radio_event(
                        &history,
                        RadioEvent {
                            ts_millis: now_millis(),
                            key: "wifi.raw.rx".to_string(),
                            source: iface.to_string(),
                            value,
                            message: Some(message),
                        },
                    );
                }
            }
            Err(error) => {
                push_radio_event(
                    &history,
                    RadioEvent {
                        ts_millis: now_millis(),
                        key: "wifi.raw.listen.error".to_string(),
                        source: iface.to_string(),
                        value: json!({ "ok": false, "iface": iface, "error": error.to_string() }),
                        message: None,
                    },
                );
                break;
            }
        }
    }
}

fn monitor_receive_loop(
    socket: MonitorRxSocket,
    iface: &str,
    monitor_iface: &str,
    history: Arc<Mutex<VecDeque<RadioEvent>>>,
) {
    let mut buf = [0_u8; 4096];
    loop {
        match socket.recv(&mut buf) {
            Ok(0) => continue,
            Ok(len) => {
                let packet = &buf[..len];
                if let Some(frame) = ieee80211_frame(packet)
                    && let Some(value) = parse_dmesh_wifi_frame(frame, iface, "linux_af_packet_monitor")
                {
                    let message = mesh_message_from_raw_wifi(&value, iface);
                    push_radio_event(
                        &history,
                        RadioEvent {
                            ts_millis: now_millis(),
                            key: "wifi.raw.rx".to_string(),
                            source: monitor_iface.to_string(),
                            value,
                            message: Some(message),
                        },
                    );
                }
            }
            Err(error) => {
                push_radio_event(
                    &history,
                    RadioEvent {
                        ts_millis: now_millis(),
                        key: "wifi.raw.listen.error".to_string(),
                        source: monitor_iface.to_string(),
                        value: json!({
                            "ok": false,
                            "iface": iface,
                            "monitor_iface": monitor_iface,
                            "error": error.to_string()
                        }),
                        message: None,
                    },
                );
                break;
            }
        }
    }
}

fn ieee80211_frame(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < IEEE80211_BODY {
        return None;
    }
    if is_dmesh_candidate_frame(packet) {
        return Some(packet);
    }
    let radiotap_len = radiotap_len(packet)?;
    let frame = packet.get(radiotap_len..)?;
    is_dmesh_candidate_frame(frame).then_some(frame)
}

fn radiotap_len(packet: &[u8]) -> Option<usize> {
    if packet.len() < 8 || packet[0] != 0 {
        return None;
    }
    let len = u16::from_le_bytes([packet[2], packet[3]]) as usize;
    (len >= 8 && len < packet.len()).then_some(len)
}

fn is_dmesh_candidate_frame(frame: &[u8]) -> bool {
    frame.len() >= IEEE80211_BODY
        && ((frame_type(frame) == 0 && frame_subtype(frame) == 13) || frame_type(frame) == 2)
}

fn parse_dmesh_vendor_action(frame: &[u8], iface: &str) -> Option<Value> {
    parse_dmesh_wifi_frame(frame, iface, "linux_nl80211")
}

fn parse_dmesh_wifi_frame(frame: &[u8], iface: &str, backend: &str) -> Option<Value> {
    if frame.len() <= IEEE80211_BODY + DMESH_VENDOR_ACTION.len() {
        return None;
    }
    let body = &frame[IEEE80211_BODY..];
    if !body.starts_with(&DMESH_VENDOR_ACTION) {
        return None;
    }
    let payload = &body[DMESH_VENDOR_ACTION.len()..];
    let source = mac_at(frame, IEEE80211_ADDR2)?;
    let destination = mac_at(frame, IEEE80211_ADDR1)?;
    let bssid = mac_at(frame, IEEE80211_ADDR3)?;
    let layout = if frame_type(frame) == 2 {
        "multicast_data"
    } else {
        "vendor_action"
    };
    Some(json!({
        "protocol": "dmesh_wifi_raw",
        "layout": layout,
        "backend": backend,
        "iface": iface,
        "frame_type": frame_type(frame),
        "frame_subtype": frame_subtype(frame),
        "source": colon_mac(&source),
        "destination": colon_mac(&destination),
        "bssid": colon_mac(&bssid),
        "payload_len": payload.len(),
        "payload": hex_bytes(payload),
        "payload_text": String::from_utf8_lossy(payload).trim(),
    }))
}

fn build_dmesh_vendor_action_frame(
    destination: [u8; 6],
    source: [u8; 6],
    payload: &[u8],
) -> Vec<u8> {
    let body_len = payload.len().min(1400);
    let mut frame = Vec::with_capacity(IEEE80211_BODY + DMESH_VENDOR_ACTION.len() + body_len);
    frame.extend_from_slice(&[0xd0, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&DMESH_VENDOR_ACTION);
    frame.extend_from_slice(&payload[..body_len]);
    frame
}

fn build_dmesh_multicast_data_frame(
    destination: [u8; 6],
    source: [u8; 6],
    payload: &[u8],
) -> Vec<u8> {
    let body_len = payload.len().min(1400);
    let mut frame = Vec::with_capacity(IEEE80211_BODY + DMESH_VENDOR_ACTION.len() + body_len);
    frame.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&DMESH_VENDOR_ACTION);
    frame.extend_from_slice(&payload[..body_len]);
    frame
}

fn mesh_message_from_raw_wifi(value: &Value, iface: &str) -> MeshMessage {
    let mut message = MeshMessage::new(mesh::message::KIND_EVENT, MeshMessageCodec::Text)
        .field(FIELD_MEDIUM, "wifi")
        .field(FIELD_IFACE, iface);
    for (field, key) in [
        (FIELD_NODE, "source"),
        (mesh::message::FIELD_PEER, "destination"),
        (FIELD_LEN, "payload_len"),
        (FIELD_PAYLOAD, "payload_text"),
    ] {
        if let Some(value) = value.get(key) {
            message = message.field(field, json_scalar_string(value));
        }
    }
    message
}

fn push_radio_event(history: &Arc<Mutex<VecDeque<RadioEvent>>>, event: RadioEvent) {
    let mut history = history
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    history.push_back(event);
    while history.len() > MAX_HISTORY {
        history.pop_front();
    }
}

fn mac_at(frame: &[u8], offset: usize) -> Option<[u8; 6]> {
    let mut out = [0_u8; 6];
    out.copy_from_slice(frame.get(offset..offset + 6)?);
    Some(out)
}

fn ifindex(iface: &str) -> Result<u32> {
    let iface_c = std::ffi::CString::new(iface.as_bytes())
        .map_err(|_| anyhow::anyhow!("interface name contains NUL byte: {iface:?}"))?;
    let ifindex = unsafe { libc::if_nametoindex(iface_c.as_ptr()) };
    if ifindex == 0 {
        bail!(
            "if_nametoindex({iface}) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(ifindex)
}

fn channel_to_freq(channel: u8) -> u32 {
    if channel == 14 {
        2484
    } else {
        2407 + (channel as u32 * 5)
    }
}

fn iface_mac(iface: &str) -> Result<[u8; 6]> {
    let iface_c = std::ffi::CString::new(iface.as_bytes())
        .map_err(|_| anyhow::anyhow!("interface name contains NUL byte: {iface:?}"))?;
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to open ioctl socket");
    }
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = iface_c.as_bytes_with_nul();
    if name_bytes.len() > request.ifr_name.len() {
        unsafe {
            libc::close(fd);
        }
        bail!("interface name too long: {iface}");
    }
    for (idx, byte) in name_bytes.iter().enumerate() {
        request.ifr_name[idx] = *byte as libc::c_char;
    }
    let rc = unsafe { libc::ioctl(fd, libc::SIOCGIFHWADDR as libc::c_int, &mut request) };
    let error = std::io::Error::last_os_error();
    unsafe {
        libc::close(fd);
    }
    if rc < 0 {
        return Err(error).with_context(|| format!("failed to read hardware address for {iface}"));
    }
    let mut out = [0_u8; 6];
    unsafe {
        let data = request.ifr_ifru.ifru_hwaddr.sa_data;
        for (idx, slot) in out.iter_mut().enumerate() {
            *slot = data[idx] as u8;
        }
    }
    Ok(out)
}

fn parse_mac(value: Option<&str>) -> Option<[u8; 6]> {
    let value = value?;
    let compact = value.replace([':', '-'], "");
    if compact.len() != 12 {
        return None;
    }
    let mut out = [0_u8; 6];
    for (idx, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&compact[idx * 2..idx * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
fn frame_type(frame: &[u8]) -> u8 {
    (frame.first().copied().unwrap_or(0) & 0x0c) >> 2
}

#[cfg(test)]
fn frame_subtype(frame: &[u8]) -> u8 {
    frame.first().copied().unwrap_or(0) >> 4
}

fn json_scalar_string(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| value.to_string())
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

fn raw_wifi_channel(value: Option<u8>) -> u8 {
    value.unwrap_or(DEFAULT_RAW_WIFI_CHANNEL).clamp(1, 13)
}

fn prepare_raw_wifi_channel(iface: &str, ctrl_dir: &str, channel: u8, listen_sec: u64) -> Value {
    let set_channel = wpa_raw_command(
        iface,
        ctrl_dir,
        &format!("P2P_SET listen_channel {channel}"),
    );
    let disallow_freq = wpa_raw_command(iface, ctrl_dir, "P2P_SET disallow_freq ");
    let listen = wpa_raw_command(iface, ctrl_dir, &format!("P2P_LISTEN {listen_sec}"));
    json!({
        "set_channel": command_result_json(set_channel),
        "disallow_freq": command_result_json(disallow_freq),
        "listen": command_result_json(listen),
    })
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

    #[test]
    fn raw_wifi_vendor_action_round_trips() {
        let dst = [0xff; 6];
        let src = [0x02, 0x00, 0x00, 0xaa, 0xbb, 0xcc];
        let frame = build_dmesh_vendor_action_frame(dst, src, b"stats");

        assert_eq!(&frame[..4], &[0xd0, 0x00, 0x00, 0x00]);
        assert_eq!(
            &frame[IEEE80211_BODY..IEEE80211_BODY + 5],
            &DMESH_VENDOR_ACTION
        );

        let parsed = parse_dmesh_vendor_action(&frame, "wlan-test").unwrap();
        assert_eq!(parsed["protocol"], "dmesh_wifi_raw");
        assert_eq!(parsed["source"], "02:00:00:aa:bb:cc");
        assert_eq!(parsed["destination"], "ff:ff:ff:ff:ff:ff");
        assert_eq!(parsed["payload_text"], "stats");
    }

    #[test]
    fn raw_wifi_accepts_radiotap_prefix() {
        let frame = build_dmesh_vendor_action_frame([0xff; 6], [1, 2, 3, 4, 5, 6], b"ping");
        let mut packet = vec![0, 0, 8, 0, 0, 0, 0, 0];
        packet.extend_from_slice(&frame);

        assert_eq!(ieee80211_frame(&packet).unwrap(), frame.as_slice());
    }

    #[test]
    fn raw_wifi_multicast_data_frame_has_dmesh_body() {
        let src = [0x02, 0x00, 0x00, 0xaa, 0xbb, 0xcc];
        let frame = build_dmesh_multicast_data_frame(RAW_WIFI_MULTICAST, src, b"stats");

        assert_eq!(&frame[..4], &[0x08, 0x00, 0x00, 0x00]);
        assert_eq!(
            &frame[IEEE80211_ADDR1..IEEE80211_ADDR1 + 6],
            &RAW_WIFI_MULTICAST
        );
        assert_eq!(&frame[IEEE80211_ADDR2..IEEE80211_ADDR2 + 6], &src);
        assert_eq!(
            &frame[IEEE80211_BODY..IEEE80211_BODY + DMESH_VENDOR_ACTION.len()],
            &DMESH_VENDOR_ACTION
        );
        assert_eq!(
            &frame[IEEE80211_BODY + DMESH_VENDOR_ACTION.len()..],
            b"stats"
        );
    }
}
