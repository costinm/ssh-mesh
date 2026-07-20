use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::l3dmesh::{Frame, Transport};
use super::settings::{parse_bool, parse_i32, SharedSettings};
use super::telemetry::{self, Direction};

const NAN_ID: u8 = 1;
const FRAME_DST: usize = 4;
const FRAME_SRC: usize = 10;
const FRAME_BSSID: usize = 16;
const FRAME_DATA: usize = 24;
const NAN_ACTION_START: usize = 30;
const SVC_ID: [u8; 6] = [0x75, 0x94, 0x31, 0x93, 0xea, 0xc9];
const NAN_BSSID: [u8; 6] = [0x50, 0x6f, 0x9a, 0x01, 0x05, 0x01];
const DEFAULT_SERVICE: &str = "dmesh";
const DEFAULT_CHANNEL: u8 = 6;
const NAN_COMMAND_QUEUE_MAX: usize = 8;
const NAN_OUTGOING_QUEUE_MAX: usize = 8;
const NAN_COMMAND_MAX_LEN: usize = 231;

static NAN_RUNNING: AtomicBool = AtomicBool::new(false);
static NAN_RX_MGMT: AtomicU32 = AtomicU32::new(0);
static NAN_RX_ACTION: AtomicU32 = AtomicU32::new(0);
static NAN_RX_BEACON: AtomicU32 = AtomicU32::new(0);
static NAN_RX_SDF: AtomicU32 = AtomicU32::new(0);
static NAN_RX_OTHER: AtomicU32 = AtomicU32::new(0);
static NAN_RX_BYTES: AtomicU32 = AtomicU32::new(0);
static NAN_RX_MATCHED: AtomicU32 = AtomicU32::new(0);
static NAN_RAW_COMMAND_RX: AtomicU32 = AtomicU32::new(0);
static NAN_RAW_RESPONSE_RX: AtomicU32 = AtomicU32::new(0);
static NAN_RAW_RESPONSE_TX: AtomicU32 = AtomicU32::new(0);
static NAN_LAST_BEACON_LOCAL_LO: AtomicU32 = AtomicU32::new(0);
static NAN_LAST_BEACON_LOCAL_HI: AtomicU32 = AtomicU32::new(0);
static NAN_LAST_BEACON_TSF_LO: AtomicU32 = AtomicU32::new(0);
static NAN_LAST_BEACON_TSF_HI: AtomicU32 = AtomicU32::new(0);
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NanBackend {
    Raw,
}

impl NanBackend {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "raw" | "frame" | "promisc" => Ok(Self::Raw),
            _ => bail!("unsupported NAN backend; firmware supports raw only"),
        }
    }

    fn name(self) -> &'static str {
        "raw"
    }
}

static NAN_COMMAND_QUEUE: OnceLock<Mutex<VecDeque<NanTextCommand>>> = OnceLock::new();
static NAN_OUTGOING_QUEUE: OnceLock<Mutex<VecDeque<RawNanOutgoing>>> = OnceLock::new();

#[derive(Clone, Debug)]
enum NanCommandPeer {
    Raw { mac: [u8; 6], instance: u8 },
}

pub struct NanTextCommand {
    peer: NanCommandPeer,
    pub text: String,
}

struct RawNanOutgoing {
    dst: [u8; 6],
    instance: u8,
    payload: Vec<u8>,
}

fn nan_command_queue() -> &'static Mutex<VecDeque<NanTextCommand>> {
    NAN_COMMAND_QUEUE.get_or_init(|| Mutex::new(VecDeque::with_capacity(NAN_COMMAND_QUEUE_MAX)))
}

fn nan_outgoing_queue() -> &'static Mutex<VecDeque<RawNanOutgoing>> {
    NAN_OUTGOING_QUEUE.get_or_init(|| Mutex::new(VecDeque::with_capacity(NAN_OUTGOING_QUEUE_MAX)))
}

pub fn take_command() -> Option<NanTextCommand> {
    nan_command_queue().lock().ok()?.pop_front()
}

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    registry.register(NanCommand::new(settings));
}

pub fn transport() -> NanTransport {
    NanTransport::default()
}

pub fn forward_packet(packet: &[u8]) -> Result<()> {
    if NAN_RUNNING.load(Ordering::Relaxed) {
        let frame = nan_followup_frame(&[0xff; 6], NAN_ID, packet)?;
        raw_tx(&frame, true)?;
        telemetry::record_log(format!(
            "event type=nan.forward backend=raw dst=ff:ff:ff:ff:ff:ff bytes={}",
            packet.len()
        ));
        return Ok(());
    }
    bail!("NAN is not running")
}

pub fn raw_followup_frame(dst: &[u8; 6], data: &[u8]) -> Result<Vec<u8>> {
    nan_followup_frame(dst, NAN_ID, data)
}

pub fn start_raw_window(channel: u8, filter: &str) -> Result<()> {
    NAN_FILTER_MODE.store(parse_filter_mode(filter)?, Ordering::Relaxed);
    start_raw_sniffer(channel.max(1))
}

pub fn raw_payload(frame: &[u8]) -> Option<&[u8]> {
    raw_command_info(frame).map(|info| info.payload)
}

struct RawNanCommandInfo<'a> {
    source: [u8; 6],
    instance: u8,
    payload: &'a [u8],
}

fn raw_command_info(frame: &[u8]) -> Option<RawNanCommandInfo<'_>> {
    if !is_nan_sdf(frame) || frame.len() <= NAN_ACTION_START {
        return None;
    }
    let source = frame.get(FRAME_SRC..FRAME_SRC + 6)?.try_into().ok()?;
    let mut offset = NAN_ACTION_START;
    while offset + 3 <= frame.len() {
        let attr_id = frame[offset];
        let attr_len = u16::from_le_bytes([frame[offset + 1], frame[offset + 2]]) as usize;
        let body_start = offset + 3;
        let body_end = body_start.checked_add(attr_len)?;
        if body_end > frame.len() {
            return None;
        }
        let body = &frame[body_start..body_end];
        if attr_id == 0x03 {
            if let Some((instance, payload)) = raw_service_descriptor_payload(body) {
                return Some(RawNanCommandInfo {
                    source,
                    instance,
                    payload,
                });
            }
        }
        offset = body_end;
    }
    None
}

fn raw_service_descriptor_payload(body: &[u8]) -> Option<(u8, &[u8])> {
    if body.len() < 10 || body[..SVC_ID.len()] != SVC_ID {
        return None;
    }
    // Service descriptor body:
    //   service_id[6], instance_id, requestor_instance_id,
    //   service_control, ssi_len, service_specific_info...
    if body[8] != 0x12 {
        return None;
    }
    let instance = body[6];
    let len = body[9] as usize;
    let payload_start = 10_usize;
    let payload_end = payload_start.checked_add(len)?;
    if payload_end > body.len() {
        return None;
    }
    Some((instance, &body[payload_start..payload_end]))
}

pub fn send_response_payload_to(command: &NanTextCommand, payload: &[u8]) -> Result<()> {
    match &command.peer {
        NanCommandPeer::Raw { mac, instance } => {
            let frame = nan_followup_frame(mac, *instance, payload)?;
            raw_tx(&frame, true)?;
            NAN_RAW_RESPONSE_TX.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }
}

pub fn queue_raw_broadcast(payload: &[u8]) -> Result<usize> {
    enqueue_outgoing_raw([0xff; 6], NAN_ID, payload)
}

pub fn drain_raw_queue() -> usize {
    drain_outgoing_raw()
}

pub fn raw_response_rx_count() -> u32 {
    NAN_RAW_RESPONSE_RX.load(Ordering::Relaxed)
}

pub fn raw_tx_active() -> bool {
    NAN_RUNNING.load(Ordering::Relaxed)
}

pub fn sync_to_next_discovery_window(timeout_ms: u64, dw_tu: u64, offset_tu: u64) -> u64 {
    let start_us = now_us();
    let before_beacon = NAN_RX_BEACON.load(Ordering::Relaxed);
    wait_for_beacon_or_timeout(before_beacon, timeout_ms);
    let wait_us =
        wait_us_until_tsf_phase(dw_tu.saturating_mul(1024), offset_tu.saturating_mul(1024));
    if wait_us > 0 {
        task_delay(Duration::from_micros(wait_us));
    }
    now_us().saturating_sub(start_us)
}

struct NanCommand {
    settings: SharedSettings,
    dump: bool,
    channel: u8,
    backend: NanBackend,
    service: String,
}

impl NanCommand {
    fn new(settings: SharedSettings) -> Self {
        Self {
            settings,
            dump: false,
            channel: DEFAULT_CHANNEL,
            backend: NanBackend::Raw,
            service: DEFAULT_SERVICE.to_string(),
        }
    }

    fn apply_settings(&mut self, request: &CommandRequest) -> Result<()> {
        if let Some(backend) = request.arg("backend") {
            self.backend = NanBackend::parse(backend)?;
        } else if let Some(backend) = self.settings.borrow().get_str("nan.backend")? {
            self.backend = NanBackend::parse(&backend)?;
        }
        if let Some(service) = request.arg("service") {
            self.service = checked_service_name(service)?;
        } else if let Some(service) = self.settings.borrow().get_str("nan.service")? {
            self.service = checked_service_name(&service)?;
        }
        if let Some(channel) = request.arg("channel").map(parse_i32).transpose()? {
            self.channel = channel.clamp(1, 13) as u8;
        } else {
            self.channel = self
                .settings
                .borrow()
                .get_i32("nan.channel", DEFAULT_CHANNEL as i32)?
                .clamp(1, 13) as u8;
        }
        Ok(())
    }

    fn maybe_save_settings(&self, request: &CommandRequest, enabled: bool) -> Result<()> {
        if request
            .arg("save")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            let mut settings = self.settings.borrow_mut();
            settings.set_bool("nan.enabled", enabled)?;
            settings.set_str("nan.backend", self.backend.name())?;
            settings.set_str("nan.service", &self.service)?;
            settings.set_i32("nan.channel", self.channel as i32)?;
        }
        Ok(())
    }
}

impl CommandHandler for NanCommand {
    fn name(&self) -> &'static str {
        "nan"
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if let Some(dump) = request.arg("dump") {
            self.dump = parse_bool(dump)?;
        }
        self.apply_settings(request)?;
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
        if request.arg("cycle").is_some() {
            return self.raw_cycle_test(request);
        }
        if request.arg("stop").is_some() {
            super::mode::stop_raw_nan_duty();
            stop_nan()?;
            super::wifi::stop_raw_monitor()?;
            self.maybe_save_settings(request, false)?;
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
            self.start_selected()?;
            self.maybe_save_settings(request, true)?;
            return Ok(CommandResponse::ok(format!(
                "nan started backend={} service={} channel={} dump={} filter={}",
                self.backend.name(),
                self.service,
                self.channel.max(1),
                self.dump,
                filter_name()
            )));
        }
        if let Some(raw) = request.arg("raw") {
            let bytes = parse_bytes(raw)?;
            self.ensure_raw_started()?;
            raw_tx(&bytes, true)?;
            return Ok(CommandResponse::ok(format!(
                "nan raw sent bytes={}",
                bytes.len()
            )));
        }
        if request.arg("publish").is_some() {
            self.ensure_raw_started()?;
            let frame = nan_publish_frame()?;
            raw_tx(&frame, true)?;
            return Ok(CommandResponse::ok(format!(
                "nan publish backend={} service={}",
                self.backend.name(),
                self.service
            )));
        }
        if let Some(data) = request.arg("queue").or_else(|| request.arg("enqueue")) {
            let dst = parse_mac(request.arg("dst").unwrap_or("ff:ff:ff:ff:ff:ff"))?;
            let instance = request
                .arg("instance")
                .map(parse_i32)
                .transpose()?
                .unwrap_or(NAN_ID as i32)
                .clamp(0, 255) as u8;
            let queued = enqueue_outgoing_raw(dst, instance, data.as_bytes())?;
            return Ok(CommandResponse::ok(format!(
                "nan queued backend=raw len={} queue={}",
                data.len().min(255),
                queued
            )));
        }
        if let Some(data) = request.arg("send") {
            self.ensure_raw_started()?;
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
                "nan followup sent backend={} bytes={}",
                self.backend.name(),
                data.len().min(255)
            )));
        }
        Ok(CommandResponse::ok(stats()))
    }
}

impl NanCommand {
    fn raw_cycle_test(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        self.backend = NanBackend::Raw;
        let channel = self.channel.max(1);
        let period_ms = request
            .arg_i32("wake_ms")?
            .unwrap_or(2_000)
            .clamp(100, 60_000) as u64;
        let active_ms = request
            .arg_i32("active_ms")?
            .unwrap_or(500)
            .clamp(50, 60_000) as u64;
        let count = request.arg_i32("count")?.unwrap_or(10).clamp(1, 100) as u32;
        let filter = request.arg("filter").unwrap_or("sdf");
        let sync = request
            .arg("sync")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false);
        let dw_tu = request.arg_i32("dw_tu")?.unwrap_or(512).clamp(1, 65_535) as u64;
        let offset_tu = request.arg_i32("offset_tu")?.unwrap_or(0).max(0) as u64;
        let sync_timeout_ms = request
            .arg_i32("sync_ms")?
            .unwrap_or(1_000)
            .clamp(10, 10_000) as u64;
        let extend_on_rx = request
            .arg("extend_on_rx")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(true);
        let extend_ms = request
            .arg_i32("extend_ms")?
            .unwrap_or(500)
            .clamp(0, 60_000) as u64;
        let idle_ms = period_ms.saturating_sub(active_ms);

        telemetry::record_log(format!(
            "event type=nan.cycle start=true channel={} period_ms={} active_ms={} idle_ms={} count={} filter={} sync={} dw_tu={} offset_tu={} sync_ms={} extend_on_rx={} extend_ms={}",
            channel, period_ms, active_ms, idle_ms, count, filter, sync, dw_tu, offset_tu, sync_timeout_ms, extend_on_rx, extend_ms
        ));
        for idx in 0..count {
            stop_nan()?;
            let _ = super::wifi::stop_raw_monitor();
            let idle_start_us = now_us();
            telemetry::record_log(format!(
                "event type=nan.cycle phase=idle index={} local_us={} idle_ms={}",
                idx, idle_start_us, idle_ms
            ));
            if idle_ms > 0 {
                task_delay(Duration::from_millis(idle_ms));
            }

            let start_beacons = NAN_RX_BEACON.load(Ordering::Relaxed);
            let start_sdf = NAN_RX_SDF.load(Ordering::Relaxed);
            let start_action = NAN_RX_ACTION.load(Ordering::Relaxed);
            let radio_start_begin_us = now_us();
            start_raw_window(channel, filter)?;
            let radio_start_end_us = now_us();
            let radio_start_us = radio_start_end_us.saturating_sub(radio_start_begin_us);
            if sync {
                let sync_start_us = now_us();
                let before_beacon = NAN_RX_BEACON.load(Ordering::Relaxed);
                wait_for_beacon_or_timeout(before_beacon, sync_timeout_ms);
                let wait_us = wait_us_until_tsf_phase(dw_tu * 1024, offset_tu * 1024);
                telemetry::record_log(format!(
                    "event type=nan.cycle phase=sync index={} local_us={} sync_wait_ms={} phase_wait_us={} last_beacon_local_us={} last_beacon_tsf_us={} beacon_delta={}",
                    idx,
                    now_us(),
                    now_us().saturating_sub(sync_start_us) / 1000,
                    wait_us,
                    last_beacon_local_us(),
                    last_beacon_tsf_us(),
                    NAN_RX_BEACON.load(Ordering::Relaxed).saturating_sub(before_beacon)
                ));
                if wait_us > 0 {
                    task_delay(Duration::from_micros(wait_us));
                }
            }
            let start_local_us = now_us();
            telemetry::record_log(format!(
                "event type=nan.cycle phase=active_start index={} local_us={} radio_start_us={} est_tsf_us={} est_tsf_phase_us={} last_beacon_local_us={} last_beacon_tsf_us={} raw_beacon={} raw_sdf={} raw_action={}",
                idx,
                start_local_us,
                radio_start_us,
                estimated_tsf_us(start_local_us),
                estimated_tsf_us(start_local_us) % (dw_tu * 1024),
                last_beacon_local_us(),
                last_beacon_tsf_us(),
                start_beacons,
                start_sdf,
                start_action
            ));
            let queued_sent = drain_outgoing_raw();
            if queued_sent > 0 {
                telemetry::record_log(format!(
                    "event type=nan.cycle phase=active_tx index={} queued_sent={}",
                    idx, queued_sent
                ));
            }
            let mut deadline_us = start_local_us.saturating_add(active_ms.saturating_mul(1000));
            let mut last_sdf = NAN_RX_SDF.load(Ordering::Relaxed);
            let mut extended = 0_u32;
            while now_us() < deadline_us {
                task_delay(Duration::from_millis(20));
                let current_sdf = NAN_RX_SDF.load(Ordering::Relaxed);
                if extend_on_rx && extend_ms > 0 && current_sdf != last_sdf {
                    let extended_deadline = now_us().saturating_add(extend_ms.saturating_mul(1000));
                    if extended_deadline > deadline_us {
                        deadline_us = extended_deadline;
                        extended = extended.saturating_add(1);
                        telemetry::record_log(format!(
                            "event type=nan.cycle phase=extend index={} local_us={} sdf_delta={} new_deadline_us={}",
                            idx,
                            now_us(),
                            current_sdf.saturating_sub(start_sdf),
                            deadline_us
                        ));
                    }
                    last_sdf = current_sdf;
                }
            }

            let end_local_us = now_us();
            telemetry::record_log(format!(
                "event type=nan.cycle phase=active_stop index={} local_us={} elapsed_ms={} extended={} est_tsf_us={} est_tsf_phase_us={} beacon_delta={} sdf_delta={} action_delta={} last_beacon_local_us={} last_beacon_tsf_us={}",
                idx,
                end_local_us,
                end_local_us.saturating_sub(start_local_us) / 1000,
                extended,
                estimated_tsf_us(end_local_us),
                estimated_tsf_us(end_local_us) % (dw_tu * 1024),
                NAN_RX_BEACON.load(Ordering::Relaxed).saturating_sub(start_beacons),
                NAN_RX_SDF.load(Ordering::Relaxed).saturating_sub(start_sdf),
                NAN_RX_ACTION.load(Ordering::Relaxed).saturating_sub(start_action),
                last_beacon_local_us(),
                last_beacon_tsf_us()
            ));
        }
        stop_nan()?;
        let _ = super::wifi::stop_raw_monitor();
        Ok(CommandResponse::ok(format!(
            "nan cycle done channel={} period_ms={} active_ms={} count={} {}",
            channel,
            period_ms,
            active_ms,
            count,
            stats()
        )))
    }

    fn start_selected(&mut self) -> Result<()> {
        if NAN_RUNNING.load(Ordering::Relaxed) {
            stop_nan()?;
        }
        self.start_raw()
    }

    fn start_raw(&mut self) -> Result<()> {
        start_raw_sniffer(self.channel.max(1))?;
        if self.dump {
            log::info!(
                "nan raw monitor started channel={} filter={}",
                self.channel.max(1),
                filter_name()
            );
        }
        Ok(())
    }

    fn ensure_raw_started(&mut self) -> Result<()> {
        if !NAN_RUNNING.load(Ordering::Relaxed) {
            self.start_raw()?;
        }
        Ok(())
    }
}

fn wait_for_beacon_or_timeout(start_count: u32, timeout_ms: u64) {
    let deadline_us = now_us().saturating_add(timeout_ms.saturating_mul(1000));
    while now_us() < deadline_us {
        if NAN_RX_BEACON.load(Ordering::Relaxed) != start_count {
            return;
        }
        task_delay(Duration::from_millis(10));
    }
}

fn wait_us_until_tsf_phase(period_us: u64, offset_us: u64) -> u64 {
    if period_us == 0 {
        return 0;
    }
    let now = now_us();
    let tsf = estimated_tsf_us(now);
    if tsf == 0 {
        return 0;
    }
    let phase = tsf % period_us;
    let target = offset_us % period_us;
    if phase <= target {
        target - phase
    } else {
        period_us - (phase - target)
    }
}

fn estimated_tsf_us(local_us: u64) -> u64 {
    let beacon_local = last_beacon_local_us();
    let beacon_tsf = last_beacon_tsf_us();
    if beacon_local == 0 || beacon_tsf == 0 {
        return 0;
    }
    beacon_tsf.saturating_add(local_us.saturating_sub(beacon_local))
}

fn start_raw_sniffer(channel: u8) -> Result<()> {
    super::wifi::ensure_raw_wifi_started(channel)?;
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
    Ok(())
}

#[derive(Default)]
pub struct NanTransport {
    #[allow(dead_code)]
    sent_frames: u32,
}

impl Transport for NanTransport {
    fn name(&self) -> &'static str {
        "nan"
    }

    fn send(&mut self, frame: &Frame<'_>, from_interface: i32) -> Result<()> {
        self.sent_frames = self.sent_frames.saturating_add(1);
        telemetry::record_packet(
            "wifi",
            Direction::Tx,
            frame.payload(),
            format!("source=nan_l3mesh from={from_interface}"),
        );
        log::info!(
            "nan send: from={} len={} total={}",
            from_interface,
            frame.payload().len(),
            self.sent_frames
        );
        Ok(())
    }
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

fn now_us() -> u64 {
    unsafe { sys::esp_timer_get_time().max(0) as u64 }
}

fn store_last_beacon_local_us(value: u64) {
    NAN_LAST_BEACON_LOCAL_LO.store(value as u32, Ordering::Relaxed);
    NAN_LAST_BEACON_LOCAL_HI.store((value >> 32) as u32, Ordering::Relaxed);
}

fn store_last_beacon_tsf_us(value: u64) {
    NAN_LAST_BEACON_TSF_LO.store(value as u32, Ordering::Relaxed);
    NAN_LAST_BEACON_TSF_HI.store((value >> 32) as u32, Ordering::Relaxed);
}

fn last_beacon_local_us() -> u64 {
    ((NAN_LAST_BEACON_LOCAL_HI.load(Ordering::Relaxed) as u64) << 32)
        | NAN_LAST_BEACON_LOCAL_LO.load(Ordering::Relaxed) as u64
}

fn last_beacon_tsf_us() -> u64 {
    ((NAN_LAST_BEACON_TSF_HI.load(Ordering::Relaxed) as u64) << 32)
        | NAN_LAST_BEACON_TSF_LO.load(Ordering::Relaxed) as u64
}

fn enqueue_raw_command(source: [u8; 6], instance: u8, payload: &[u8]) -> bool {
    if payload.starts_with(b"resp ") || payload.starts_with(b"notify ") {
        return false;
    }
    if payload.len() > NAN_COMMAND_MAX_LEN {
        return false;
    }
    let Ok(text) = core::str::from_utf8(payload) else {
        return false;
    };
    let text = text.trim();
    if text.is_empty() {
        return false;
    }
    if !command_targets_this_device(text) {
        return false;
    }
    if station_mac().map(|mac| mac == source).unwrap_or(false) {
        return false;
    }
    let Ok(mut queue) = nan_command_queue().lock() else {
        return false;
    };
    if queue.len() >= NAN_COMMAND_QUEUE_MAX {
        queue.pop_front();
    }
    queue.push_back(NanTextCommand {
        peer: NanCommandPeer::Raw {
            mac: source,
            instance,
        },
        text: text.to_string(),
    });
    NAN_RAW_COMMAND_RX.fetch_add(1, Ordering::Relaxed);
    super::wake::notify();
    true
}

fn enqueue_outgoing_raw(dst: [u8; 6], instance: u8, payload: &[u8]) -> Result<usize> {
    let len = payload.len().min(255);
    let Ok(mut queue) = nan_outgoing_queue().lock() else {
        bail!("nan outgoing queue lock failed")
    };
    if queue.len() >= NAN_OUTGOING_QUEUE_MAX {
        queue.pop_front();
    }
    queue.push_back(RawNanOutgoing {
        dst,
        instance,
        payload: payload[..len].to_vec(),
    });
    Ok(queue.len())
}

fn drain_outgoing_raw() -> usize {
    let mut sent = 0_usize;
    loop {
        let item = {
            let Ok(mut queue) = nan_outgoing_queue().lock() else {
                return sent;
            };
            queue.pop_front()
        };
        let Some(item) = item else {
            return sent;
        };
        match nan_followup_frame(&item.dst, item.instance, &item.payload)
            .and_then(|frame| raw_tx(&frame, true))
        {
            Ok(()) => {
                sent += 1;
                telemetry::record_log(format!(
                    "event type=nan.queue_tx ok=true dst={} len={} sent={}",
                    format_mac(&item.dst),
                    item.payload.len(),
                    sent
                ));
            }
            Err(err) => {
                telemetry::record_log(format!(
                    "event type=nan.queue_tx ok=false dst={} len={} message={}",
                    format_mac(&item.dst),
                    item.payload.len(),
                    crate::commands::protocol::escape_value(&err.to_string())
                ));
                let _ = enqueue_outgoing_raw(item.dst, item.instance, &item.payload);
                return sent;
            }
        }
    }
}

fn checked_service_name(value: &str) -> Result<String> {
    if value.is_empty() || value.len() >= 256 || value.as_bytes().contains(&0) {
        bail!("NAN service name must be 1..255 non-NUL bytes");
    }
    Ok(value.to_string())
}

pub fn stop_nan() -> Result<()> {
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
        ))?;
    }
    telemetry::record_packet("wifi", Direction::Tx, bytes, "source=nan_raw");
    Ok(())
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

fn command_targets_this_device(text: &str) -> bool {
    let Some(to) = command_token_value(text, "to") else {
        return true;
    };
    if is_broadcast_target(to) {
        return true;
    }
    let Ok(mac) = station_mac() else {
        return false;
    };
    to.eq_ignore_ascii_case(&mac_suffix4_hex(&mac))
}

fn is_broadcast_target(value: &str) -> bool {
    let value = value.strip_prefix("0x").unwrap_or(value);
    value.eq_ignore_ascii_case("ffffffff")
        || value.eq_ignore_ascii_case("ff:ff:ff:ff")
        || value.eq_ignore_ascii_case("broadcast")
        || value.eq_ignore_ascii_case("all")
}

fn command_token_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.split_ascii_whitespace().find_map(|token| {
        let (name, value) = token.split_once('=')?;
        if name == key && !value.is_empty() {
            Some(value)
        } else {
            None
        }
    })
}

fn mac_suffix4_hex(mac: &[u8; 6]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}", mac[2], mac[3], mac[4], mac[5])
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
    let frame = unsafe { core::slice::from_raw_parts(payload, len) };
    super::wifi::observe_promiscuous_frame(frame, pkt.rx_ctrl.rssi() as i32);
    observe_promiscuous_frame(frame, pkt.rx_ctrl.rssi() as i32);
}

pub fn observe_promiscuous_frame(frame: &[u8], _rssi: i32) {
    if !NAN_RUNNING.load(Ordering::Relaxed) {
        return;
    }
    NAN_RX_MGMT.fetch_add(1, Ordering::Relaxed);
    NAN_RX_BYTES.fetch_add(frame.len() as u32, Ordering::Relaxed);
    let custom_raw_action = super::wifi::custom_raw_action_payload(frame);
    if custom_raw_action.is_none() && !matches_filter(frame) {
        return;
    }
    NAN_RX_MATCHED.fetch_add(1, Ordering::Relaxed);
    telemetry::record_packet(
        "wifi",
        Direction::Rx,
        frame,
        format!("source=nan subtype=0x{:02x}", frame[0]),
    );
    match frame[0] {
        0x80 => {
            if is_nan_bssid(frame) {
                NAN_RX_BEACON.fetch_add(1, Ordering::Relaxed);
                if let Some(tsf) = beacon_tsf_us(frame) {
                    store_last_beacon_local_us(now_us());
                    store_last_beacon_tsf_us(tsf);
                }
            }
        }
        0xd0 => {
            NAN_RX_ACTION.fetch_add(1, Ordering::Relaxed);
            if let Some((source, payload)) = custom_raw_action {
                telemetry::record_log(format!(
                    "event type=wifi.raw_action_rx peer={} len={}",
                    format_mac(&source),
                    payload.len()
                ));
                telemetry::record_packet("wifi", Direction::Rx, payload, "source=raw_action");
            } else if is_nan_sdf(frame) {
                NAN_RX_SDF.fetch_add(1, Ordering::Relaxed);
                if let Some(info) = raw_command_info(frame) {
                    telemetry::record_log(format!(
                        "event type=nan.raw_followup_rx peer={} instance={} len={}",
                        format_mac(&info.source),
                        info.instance,
                        info.payload.len()
                    ));
                    if !station_mac().map(|mac| mac == info.source).unwrap_or(false)
                        && (info.payload.starts_with(b"resp ")
                            || info.payload.starts_with(b"notify "))
                    {
                        NAN_RAW_RESPONSE_RX.fetch_add(1, Ordering::Relaxed);
                    } else {
                        enqueue_raw_command(info.source, info.instance, info.payload);
                    }
                }
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

fn beacon_tsf_us(frame: &[u8]) -> Option<u64> {
    let tsf = frame.get(FRAME_DATA..FRAME_DATA + 8)?;
    Some(u64::from_le_bytes(tsf.try_into().ok()?))
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
    let last_beacon_local_us = last_beacon_local_us();
    let last_beacon_tsf_us = last_beacon_tsf_us();
    let beacon_age_ms = if last_beacon_local_us == 0 {
        u64::MAX
    } else {
        now_us().saturating_sub(last_beacon_local_us) / 1000
    };
    let queue_len = nan_outgoing_queue()
        .lock()
        .map(|queue| queue.len())
        .unwrap_or(0);
    format!(
        "nan support=raw running={} filter={} bssid_filter={} raw_mgmt={} raw_matched={} raw_action={} raw_beacon={} raw_sdf={} raw_other={} raw_bytes={} raw_cmd_rx={} raw_resp_rx={} raw_resp_tx={} last_beacon_local_us={} last_beacon_tsf_us={} beacon_age_ms={} queue_len={}",
        NAN_RUNNING.load(Ordering::Relaxed),
        filter_name(),
        NAN_FILTER_BSSID_ENABLED.load(Ordering::Relaxed),
        NAN_RX_MGMT.load(Ordering::Relaxed),
        NAN_RX_MATCHED.load(Ordering::Relaxed),
        NAN_RX_ACTION.load(Ordering::Relaxed),
        NAN_RX_BEACON.load(Ordering::Relaxed),
        NAN_RX_SDF.load(Ordering::Relaxed),
        NAN_RX_OTHER.load(Ordering::Relaxed),
        NAN_RX_BYTES.load(Ordering::Relaxed),
        NAN_RAW_COMMAND_RX.load(Ordering::Relaxed),
        NAN_RAW_RESPONSE_RX.load(Ordering::Relaxed),
        NAN_RAW_RESPONSE_TX.load(Ordering::Relaxed),
        last_beacon_local_us,
        last_beacon_tsf_us,
        beacon_age_ms,
        queue_len
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
