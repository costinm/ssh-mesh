use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};

use anyhow::Result;

use crate::commands::protocol::quote_text_value;
use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::settings::{parse_bool, SharedSettings};

const DEFAULT_DEPTH: usize = 10;
const DEFAULT_RESPONSE_MAX_BYTES: usize = 2048;
const MIN_RESPONSE_MAX_BYTES: usize = 256;
const MAX_RESPONSE_MAX_BYTES: usize = 8192;
const MAX_DEPTH: usize = 64;
const MAX_COMPANION_DEPTH: usize = 64;
const PREVIEW_BYTES: usize = 96;

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    registry.register(TelemetryCommand::new("stats", settings.clone()));
    registry.register(TelemetryCommand::new("logs", settings.clone()));
    registry.register(TelemetryCommand::new("messages", settings.clone()));
    registry.register(TelemetryCommand::new("local_messages", settings));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Rx,
    Tx,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Rx => "rx",
            Self::Tx => "tx",
        }
    }
}

#[derive(Clone)]
struct MessageRecord {
    seq: u64,
    ts_ms: i64,
    transport: &'static str,
    direction: Direction,
    len: usize,
    detail: String,
    data: String,
}

#[derive(Clone)]
struct CompanionRecord {
    seq: u64,
    ts_ms: i64,
    transport: &'static str,
    len: usize,
    hash: u32,
    data: Vec<u8>,
}

#[derive(Default)]
struct TelemetryState {
    seq: u64,
    companion_seq: u64,
    messages: VecDeque<MessageRecord>,
    local_messages: VecDeque<MessageRecord>,
    companion_messages: VecDeque<CompanionRecord>,
    logs: VecDeque<String>,
}

struct AtomicCounter {
    rx_packets: AtomicU32,
    rx_bytes: AtomicU32,
    tx_packets: AtomicU32,
    tx_bytes: AtomicU32,
}

impl AtomicCounter {
    const fn new() -> Self {
        Self {
            rx_packets: AtomicU32::new(0),
            rx_bytes: AtomicU32::new(0),
            tx_packets: AtomicU32::new(0),
            tx_bytes: AtomicU32::new(0),
        }
    }

    fn record(&self, direction: Direction, len: usize) {
        match direction {
            Direction::Rx => {
                self.rx_packets.fetch_add(1, Ordering::Relaxed);
                self.rx_bytes.fetch_add(len as u32, Ordering::Relaxed);
            }
            Direction::Tx => {
                self.tx_packets.fetch_add(1, Ordering::Relaxed);
                self.tx_bytes.fetch_add(len as u32, Ordering::Relaxed);
            }
        }
    }

    fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
        }
    }

    fn reset(&self) {
        self.rx_packets.store(0, Ordering::Relaxed);
        self.rx_bytes.store(0, Ordering::Relaxed);
        self.tx_packets.store(0, Ordering::Relaxed);
        self.tx_bytes.store(0, Ordering::Relaxed);
    }
}

struct CounterSnapshot {
    rx_packets: u32,
    rx_bytes: u32,
    tx_packets: u32,
    tx_bytes: u32,
}

static LORA_COUNTER: AtomicCounter = AtomicCounter::new();
static BLE_COUNTER: AtomicCounter = AtomicCounter::new();
static WIFI_COUNTER: AtomicCounter = AtomicCounter::new();

struct TelemetryCommand {
    name: &'static str,
    settings: SharedSettings,
}

impl TelemetryCommand {
    fn new(name: &'static str, settings: SharedSettings) -> Self {
        Self { name, settings }
    }
}

impl CommandHandler for TelemetryCommand {
    fn name(&self) -> &'static str {
        self.name
    }

    fn help(&self) -> &'static str {
        match self.name {
            "stats" => "stats reset=true",
            "logs" => "logs count=10 depth=10 max_bytes=2048 clear=true",
            "messages" => {
                "messages count=10 depth=10 max_bytes=2048 transport=lora|ble|wifi direction=rx pull=true after_seq=0 ack=true seq=N hash=0x... clear=true"
            }
            "local_messages" => {
                "local_messages count=10 depth=10 max_bytes=2048 transport=lora|ble|wifi clear=true"
            }
            _ => "telemetry",
        }
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        match self.name {
            "stats" => self.stats(request),
            "logs" => self.logs(request),
            "messages" => self.messages(request),
            "local_messages" => self.local_messages(request),
            _ => Ok(CommandResponse::error("invalid telemetry command")),
        }
    }
}

impl TelemetryCommand {
    fn stats(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if request
            .arg("reset")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            reset();
        }
        Ok(CommandResponse::ok(stats_text(&self.settings)))
    }

    fn logs(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if request
            .arg("clear")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            clear_logs();
        }
        let count = self.depth(request, "log.depth")?;
        let max_bytes = response_max_bytes(request)?;
        Ok(CommandResponse::ok(logs_text(count, max_bytes)))
    }

    fn messages(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if request.arg("pull").is_some() {
            let max_bytes = response_max_bytes(request)?;
            let after_seq = request
                .arg("after_seq")
                .map(parse_u64)
                .transpose()?
                .unwrap_or(0);
            let transport = request.arg("transport");
            return Ok(CommandResponse::ok(companion_pull_text(
                after_seq, max_bytes, transport,
            )));
        }
        if request.arg("ack").is_some() {
            let seq = request.arg("seq").map(parse_u64).transpose()?.unwrap_or(0);
            let hash = request.arg("hash").map(parse_u32).transpose()?.unwrap_or(0);
            return Ok(CommandResponse::ok(companion_ack_text(seq, hash)));
        }
        if request
            .arg("clear")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            clear_messages();
        }
        let count = self.depth(request, "msg.depth")?;
        let max_bytes = response_max_bytes(request)?;
        let transport = request.arg("transport");
        let direction = request.arg("direction");
        Ok(CommandResponse::ok(messages_text(
            count,
            max_bytes,
            transport,
            direction,
            MessageQueue::General,
        )))
    }

    fn local_messages(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if request
            .arg("clear")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            clear_local_messages();
        }
        let count = self.depth(request, "local_msg.depth")?;
        let max_bytes = response_max_bytes(request)?;
        Ok(CommandResponse::ok(messages_text(
            count,
            max_bytes,
            request.arg("transport"),
            request.arg("direction"),
            MessageQueue::Local,
        )))
    }

    fn depth(&mut self, request: &CommandRequest, key: &str) -> Result<usize> {
        if let Some(depth) = request.arg_i32("depth")? {
            self.settings
                .borrow_mut()
                .set_i32(key, depth.clamp(1, MAX_DEPTH as i32))?;
        }
        if let Some(count) = request.arg_i32("count")? {
            return Ok(count.clamp(1, MAX_DEPTH as i32) as usize);
        }
        Ok(self
            .settings
            .borrow()
            .get_i32(key, DEFAULT_DEPTH as i32)?
            .clamp(1, MAX_DEPTH as i32) as usize)
    }
}

pub fn record_command(line: &str) {
    let command = line.split_whitespace().next().unwrap_or("");
    if matches!(command, "stats" | "logs" | "messages" | "local_messages") {
        return;
    }
    record_log(format!("ev=cmd.rx text={}", quote_text_value(line)));
}

pub fn record_log(line: impl Into<String>) {
    if let Ok(mut state) = telemetry().try_lock() {
        push_bounded(
            &mut state.logs,
            format!("log ts={} {}", format_ts(now_ms()), line.into()),
            MAX_DEPTH,
        );
    }
}

pub fn record_packet(
    transport: &'static str,
    direction: Direction,
    data: &[u8],
    detail: impl Into<String>,
) {
    count_packet(transport, direction, data.len());
    if direction == Direction::Rx {
        record_packet_sample(transport, direction, data, detail);
    }
}

pub fn record_packet_sample(
    transport: &'static str,
    direction: Direction,
    data: &[u8],
    detail: impl Into<String>,
) {
    if let Ok(mut state) = telemetry().try_lock() {
        state.seq = state.seq.saturating_add(1);
        let record = MessageRecord {
            seq: state.seq,
            ts_ms: now_ms(),
            transport,
            direction,
            len: data.len(),
            detail: detail.into(),
            data: hex_preview(data),
        };
        push_bounded(&mut state.messages, record, MAX_DEPTH);
    }
    if transport == "lora" && direction == Direction::Rx {
        record_companion_packet(transport, data);
    }
}

pub fn count_packet(transport: &'static str, direction: Direction, len: usize) {
    counter_for(transport).record(direction, len);
}

pub fn record_local_packet(
    transport: &'static str,
    direction: Direction,
    data: &[u8],
    detail: impl Into<String>,
) {
    if let Ok(mut state) = telemetry().try_lock() {
        state.seq = state.seq.saturating_add(1);
        let record = MessageRecord {
            seq: state.seq,
            ts_ms: now_ms(),
            transport,
            direction,
            len: data.len(),
            detail: detail.into(),
            data: hex_preview(data),
        };
        push_bounded(&mut state.local_messages, record, MAX_DEPTH);
    }
}

pub fn stats_text(settings: &SharedSettings) -> String {
    let state = telemetry().lock().unwrap();
    let lora = LORA_COUNTER.snapshot();
    let ble = BLE_COUNTER.snapshot();
    let wifi = WIFI_COUNTER.snapshot();
    format!(
        "stats lora_rx={} lora_rx_bytes={} lora_tx={} lora_tx_bytes={} ble_rx={} ble_rx_bytes={} ble_tx={} ble_tx_bytes={} wifi_rx={} wifi_rx_bytes={} wifi_tx={} wifi_tx_bytes={} logs={} messages={} local_messages={} companion={} {}",
        lora.rx_packets,
        lora.rx_bytes,
        lora.tx_packets,
        lora.tx_bytes,
        ble.rx_packets,
        ble.rx_bytes,
        ble.tx_packets,
        ble.tx_bytes,
        wifi.rx_packets,
        wifi.rx_bytes,
        wifi.tx_packets,
        wifi.tx_bytes,
        state.logs.len(),
        state.messages.len(),
        state.local_messages.len(),
        state.companion_messages.len(),
        super::battery::stats_fields(settings)
    )
}

pub fn pending_message_count() -> u8 {
    let state = telemetry().lock().unwrap();
    state.companion_messages.len().min(u8::MAX as usize) as u8
}

pub fn record_companion_packet(transport: &'static str, data: &[u8]) {
    if let Ok(mut state) = telemetry().try_lock() {
        state.companion_seq = state.companion_seq.saturating_add(1);
        let record = CompanionRecord {
            seq: state.companion_seq,
            ts_ms: now_ms(),
            transport,
            len: data.len(),
            hash: fnv1a32(data),
            data: data.to_vec(),
        };
        push_bounded(&mut state.companion_messages, record, MAX_COMPANION_DEPTH);
    }
    super::ble_bt::companion_message_ready(data);
}

pub fn companion_notify_text(max_bytes: usize) -> String {
    companion_pull_text(0, max_bytes, None)
}

fn logs_text(count: usize, max_bytes: usize) -> String {
    let state = telemetry().lock().unwrap();
    let skip = state.logs.len().saturating_sub(count);
    let selected = state.logs.iter().skip(skip).collect::<Vec<_>>();
    if selected.is_empty() {
        "logs count=0".to_string()
    } else {
        let mut out = String::new();
        let mut rendered = 0;
        for line in &selected {
            if !append_bounded_line(&mut out, line, max_bytes) {
                break;
            }
            rendered += 1;
        }
        let more = rendered < selected.len();
        if more {
            let marker = format!(
                "logs partial=true count={} total={} more=true max_bytes={}",
                rendered,
                selected.len(),
                max_bytes
            );
            let _ = append_bounded_line(&mut out, &marker, max_bytes);
        }
        if out.is_empty() {
            format!(
                "logs partial=true count=0 total={} more=true max_bytes={}",
                selected.len(),
                max_bytes
            )
        } else {
            out
        }
    }
}

#[derive(Clone, Copy)]
enum MessageQueue {
    General,
    Local,
}

fn messages_text(
    count: usize,
    max_bytes: usize,
    transport: Option<&str>,
    direction: Option<&str>,
    queue: MessageQueue,
) -> String {
    let state = telemetry().lock().unwrap();
    let source = match queue {
        MessageQueue::General => &state.messages,
        MessageQueue::Local => &state.local_messages,
    };
    let mut records = source
        .iter()
        .filter(|record| {
            transport
                .map(|value| value == record.transport)
                .unwrap_or(true)
        })
        .filter(|record| {
            direction
                .map(|value| value == record.direction.as_str())
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();
    let skip = records.len().saturating_sub(count);
    records.drain(0..skip);
    if records.is_empty() {
        return match queue {
            MessageQueue::General => "messages count=0".to_string(),
            MessageQueue::Local => "local_messages count=0".to_string(),
        };
    }
    let mut out = String::new();
    let mut rendered = 0;
    for record in &records {
        let line = format_message_record(record);
        if !append_bounded_line(&mut out, &line, max_bytes) {
            break;
        }
        rendered += 1;
    }
    let more = rendered < records.len();
    if more {
        let name = match queue {
            MessageQueue::General => "messages",
            MessageQueue::Local => "local_messages",
        };
        let next_seq = records.get(rendered).map(|record| record.seq).unwrap_or(0);
        let marker = format!(
            "{} partial=true count={} total={} more=true next_seq={} max_bytes={}",
            name,
            rendered,
            records.len(),
            next_seq,
            max_bytes
        );
        let _ = append_bounded_line(&mut out, &marker, max_bytes);
    }
    if out.is_empty() {
        let name = match queue {
            MessageQueue::General => "messages",
            MessageQueue::Local => "local_messages",
        };
        format!(
            "{} partial=true count=0 total={} more=true next_seq={} max_bytes={}",
            name,
            records.len(),
            records.first().map(|record| record.seq).unwrap_or(0),
            max_bytes
        )
    } else {
        out
    }
}

fn companion_pull_text(after_seq: u64, max_bytes: usize, transport: Option<&str>) -> String {
    let state = telemetry().lock().unwrap();
    let records = state
        .companion_messages
        .iter()
        .filter(|record| record.seq > after_seq)
        .filter(|record| {
            transport
                .map(|value| value == record.transport)
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();
    if records.is_empty() {
        return format!(
            "messages pull=true count=0 pending={} more=false",
            state.companion_messages.len()
        );
    }
    let mut out = String::new();
    let mut rendered = 0;
    for record in &records {
        let line = format_companion_record(record);
        if !append_bounded_line(&mut out, &line, max_bytes) {
            break;
        }
        rendered += 1;
    }
    let more = rendered < records.len();
    let marker = format!(
        "messages pull=true count={} pending={} more={} next_seq={} max_bytes={}",
        rendered,
        state.companion_messages.len(),
        more,
        records.get(rendered).map(|record| record.seq).unwrap_or(0),
        max_bytes
    );
    let _ = append_bounded_line(&mut out, &marker, max_bytes);
    if out.is_empty() {
        marker
    } else {
        out
    }
}

fn companion_ack_text(seq: u64, hash: u32) -> String {
    let mut state = telemetry().lock().unwrap();
    let Some(pos) = state
        .companion_messages
        .iter()
        .position(|record| record.seq == seq)
    else {
        return format!(
            "messages ack=true seq={} hash=0x{:08x} deleted=false duplicate=true pending={}",
            seq,
            hash,
            state.companion_messages.len()
        );
    };
    if state
        .companion_messages
        .get(pos)
        .map(|record| record.hash != hash)
        .unwrap_or(true)
    {
        return format!(
            "messages ack=false seq={} hash=0x{:08x} error=hash_mismatch pending={}",
            seq,
            hash,
            state.companion_messages.len()
        );
    }
    let _ = state.companion_messages.remove(pos);
    let pending = state.companion_messages.len();
    drop(state);
    if pending == 0 {
        super::ble_bt::companion_queue_empty();
    }
    format!(
        "messages ack=true seq={} hash=0x{:08x} deleted=true pending={}",
        seq, hash, pending
    )
}

pub fn emit_console(line: &str) {
    uart_write("\n");
    uart_write(line);
    uart_write("\ndm-rs> ");
}

fn uart_write(text: &str) {
    unsafe {
        let bytes = text.as_bytes();
        let _ = esp_idf_sys::uart_write_bytes(
            esp_idf_sys::uart_port_t_UART_NUM_0,
            bytes.as_ptr() as *const core::ffi::c_void,
            bytes.len(),
        );
    }
}

fn reset() {
    LORA_COUNTER.reset();
    BLE_COUNTER.reset();
    WIFI_COUNTER.reset();
    let mut state = telemetry().lock().unwrap();
    state.messages.clear();
    state.local_messages.clear();
    state.logs.clear();
}

fn clear_logs() {
    telemetry().lock().unwrap().logs.clear();
}

fn clear_messages() {
    telemetry().lock().unwrap().messages.clear();
}

fn clear_local_messages() {
    telemetry().lock().unwrap().local_messages.clear();
}

fn counter_for(transport: &str) -> &'static AtomicCounter {
    match transport {
        "lora" => &LORA_COUNTER,
        "ble" | "bt" => &BLE_COUNTER,
        "wifi" | "nan" => &WIFI_COUNTER,
        _ => &WIFI_COUNTER,
    }
}

fn telemetry() -> &'static Mutex<TelemetryState> {
    static TELEMETRY: OnceLock<Mutex<TelemetryState>> = OnceLock::new();
    TELEMETRY.get_or_init(|| Mutex::new(TelemetryState::default()))
}

fn push_bounded<T>(queue: &mut VecDeque<T>, item: T, max: usize) {
    while queue.len() >= max {
        let _ = queue.pop_front();
    }
    queue.push_back(item);
}

fn response_max_bytes(request: &CommandRequest) -> Result<usize> {
    Ok(request
        .arg_i32("max_bytes")?
        .unwrap_or(DEFAULT_RESPONSE_MAX_BYTES as i32)
        .clamp(MIN_RESPONSE_MAX_BYTES as i32, MAX_RESPONSE_MAX_BYTES as i32) as usize)
}

fn parse_u64(value: &str) -> Result<u64> {
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|err| anyhow::anyhow!("invalid u64 {value}: {err}"))
    } else {
        value
            .parse::<u64>()
            .map_err(|err| anyhow::anyhow!("invalid u64 {value}: {err}"))
    }
}

fn parse_u32(value: &str) -> Result<u32> {
    if let Some(hex) = value.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).map_err(|err| anyhow::anyhow!("invalid u32 {value}: {err}"))
    } else {
        value.parse::<u32>().or_else(|_| {
            u32::from_str_radix(value, 16)
                .map_err(|err| anyhow::anyhow!("invalid u32 {value}: {err}"))
        })
    }
}

fn append_bounded_line(out: &mut String, line: &str, max_bytes: usize) -> bool {
    let extra = line.len() + usize::from(!out.is_empty());
    if out.len().saturating_add(extra) > max_bytes {
        return false;
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(line);
    true
}

fn format_message_record(record: &MessageRecord) -> String {
    format!(
        "msg ts={} seq={} t={} dir={} len={} {} data={}",
        format_ts(record.ts_ms),
        record.seq,
        record.transport,
        record.direction.as_str(),
        record.len,
        record.detail,
        quote_text_value(&record.data)
    )
}

fn format_companion_record(record: &CompanionRecord) -> String {
    format!(
        "msg ts={} seq={} t={} dir=rx len={} hash=0x{:08x} data=hex:{}",
        format_ts(record.ts_ms),
        record.seq,
        record.transport,
        record.len,
        record.hash,
        encode_hex(&record.data)
    )
}

fn encode_hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push(hex_char(byte >> 4));
        out.push(hex_char(byte & 0x0f));
    }
    out
}

fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5_u32;
    for byte in data {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

fn hex_preview(data: &[u8]) -> String {
    let mut out = String::new();
    for byte in data.iter().take(PREVIEW_BYTES) {
        out.push(hex_char(byte >> 4));
        out.push(hex_char(byte & 0x0f));
    }
    if data.len() > PREVIEW_BYTES {
        out.push_str("...");
    }
    out
}

fn hex_char(nibble: u8) -> char {
    b"0123456789abcdef"[(nibble & 0x0f) as usize] as char
}

fn now_ms() -> i64 {
    unsafe { esp_idf_sys::esp_timer_get_time() / 1000 }
}

fn format_ts(ms: i64) -> String {
    format!("{}.{:03}s", ms / 1000, ms.rem_euclid(1000))
}
