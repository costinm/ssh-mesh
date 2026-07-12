use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::frames::{
    address_metadata, decode_frame, encode_meshtastic_data, encode_meshtastic_frame,
    format_meshtastic_node, hex_bytes, parse_bytes, FrameKind, MESHTASTIC_DEFAULT_CHANNEL_HASH,
    MESHTASTIC_DEFAULT_HOP_LIMIT, MESHTASTIC_DEFAULT_PORTNUM,
};
use super::l3dmesh::{Frame, Transport};
use super::settings::{parse_bool, parse_i32, SharedSettings};
use super::telemetry::{self, Direction};

const DEFAULT_FREQUENCY_HZ: u32 = 913_125_000;
const DEFAULT_BANDWIDTH_HZ: u32 = 250_000;
const SX127X_VERSION: u8 = 0x12;

const REG_FIFO: u8 = 0x00;
const REG_OP_MODE: u8 = 0x01;
const REG_FRF_MSB: u8 = 0x06;
const REG_FRF_MID: u8 = 0x07;
const REG_FRF_LSB: u8 = 0x08;
const REG_PA_CONFIG: u8 = 0x09;
const REG_LNA: u8 = 0x0c;
const REG_FIFO_ADDR_PTR: u8 = 0x0d;
const REG_FIFO_TX_BASE_ADDR: u8 = 0x0e;
const REG_FIFO_RX_BASE_ADDR: u8 = 0x0f;
const REG_FIFO_RX_CURRENT_ADDR: u8 = 0x10;
const REG_IRQ_FLAGS: u8 = 0x12;
const REG_RX_NB_BYTES: u8 = 0x13;
const REG_PKT_SNR_VALUE: u8 = 0x19;
const REG_PKT_RSSI_VALUE: u8 = 0x1a;
const REG_MODEM_CONFIG_1: u8 = 0x1d;
const REG_MODEM_CONFIG_2: u8 = 0x1e;
const REG_PREAMBLE_MSB: u8 = 0x20;
const REG_PREAMBLE_LSB: u8 = 0x21;
const REG_PAYLOAD_LENGTH: u8 = 0x22;
const REG_MODEM_CONFIG_3: u8 = 0x26;
const REG_SYNC_WORD: u8 = 0x39;
const REG_DIO_MAPPING_1: u8 = 0x40;
const REG_VERSION: u8 = 0x42;

const MODE_LONG_RANGE: u8 = 0x80;
const MODE_SLEEP: u8 = 0x00;
const MODE_STDBY: u8 = 0x01;
const MODE_TX: u8 = 0x03;
const MODE_RX_CONTINUOUS: u8 = 0x05;

const IRQ_TX_DONE: u8 = 0x08;
const IRQ_PAYLOAD_CRC_ERROR: u8 = 0x20;
const IRQ_RX_DONE: u8 = 0x40;

static BACKGROUND_RX_RUNNING: AtomicBool = AtomicBool::new(false);
static GPIO_ISR_SERVICE_READY: AtomicBool = AtomicBool::new(false);
static LORA_PACKET_COUNTER: AtomicU32 = AtomicU32::new(1);
static LORA_RX_TASK: AtomicPtr<sys::tskTaskControlBlock> = AtomicPtr::new(std::ptr::null_mut());
static LORA_SPI_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    registry.register(LoraCommand::new("lora", settings.clone()));
    registry.register(LoraCommand::new("loraprobe", settings.clone()));
    registry.register(LoraCommand::new("lorasend", settings.clone()));
    registry.register(LoraCommand::new("loralisten", settings.clone()));
    registry.register(LoraCommand::new("loradump", settings));
}

pub fn sleep_radio(settings: &SharedSettings) -> Result<()> {
    BACKGROUND_RX_RUNNING.store(false, Ordering::Relaxed);
    notify_lora_rx_task();
    let state = LoraState::load(settings)?;
    let _guard = lora_spi_lock().lock().unwrap();
    let mut radio = Radio::open(&state.config)?;
    radio.sleep()
}

pub fn send_text(settings: &SharedSettings, text: &str, hop_limit: u8) -> Result<String> {
    send_payload(
        settings,
        text.as_bytes(),
        FrameKind::Meshtastic,
        Some(hop_limit),
        None,
        2000,
    )
}

pub fn send_raw_text(settings: &SharedSettings, text: &str) -> Result<String> {
    send_payload(
        settings,
        text.as_bytes(),
        FrameKind::Raw,
        Some(0),
        None,
        2000,
    )
}

pub fn transport(settings: SharedSettings) -> LoraTransport {
    LoraTransport::new(settings)
}

pub fn start_background_rx(settings: SharedSettings) -> Result<Option<thread::JoinHandle<()>>> {
    let state = LoraState::load(&settings)?;
    let mut config = state.config;
    if BACKGROUND_RX_RUNNING.swap(true, Ordering::Relaxed) {
        return Ok(None);
    }
    if let Err(err) = probe_lora_ready(&config) {
        BACKGROUND_RX_RUNNING.store(false, Ordering::Relaxed);
        let line = format!(
            "ev=lora.probe ok=false sck={} miso={} mosi={} cs={} rst={} dio0={} msg={}",
            config.sck,
            config.miso,
            config.mosi,
            config.cs,
            config.rst,
            config.dio0,
            crate::commands::protocol::escape_value(&err.to_string())
        );
        telemetry::record_log(line);
        return Ok(None);
    }

    apply_medium_fast(&mut config);
    let line = format!(
        "ev=lora.probe ok=true preset=medium_fast rf={} sync=0x{:02x} sck={} miso={} mosi={} cs={} rst={} dio0={}",
        compact_rf(&config),
        config.sync_word,
        config.sck,
        config.miso,
        config.mosi,
        config.cs,
        config.rst,
        config.dio0
    );
    telemetry::record_log(line);

    let local_node = meshtastic_sender_node().ok();
    let handle = thread::Builder::new()
        .name("lora-rx".to_string())
        .stack_size(12 * 1024)
        .spawn(move || {
            if let Err(err) = run_background_rx(config, local_node) {
                BACKGROUND_RX_RUNNING.store(false, Ordering::Relaxed);
                let line = format!(
                    "ev=lora.err c=rx msg={}",
                    crate::commands::protocol::escape_value(&err.to_string())
                );
                telemetry::record_log(line);
            }
        })
        .map_err(|err| anyhow!("failed to start LoRa RX thread: {err}"))?;
    Ok(Some(handle))
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum LoraChip {
    Sx127x,
    Sx1262,
}

impl LoraChip {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "sx127x" | "sx1276" | "sx1278" | "rf95" => Ok(Self::Sx127x),
            "sx1262" | "sx126x" => Ok(Self::Sx1262),
            _ => bail!("unsupported LoRa chip {value}"),
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Sx127x => "sx127x",
            Self::Sx1262 => "sx1262",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LoraConfig {
    pub(crate) chip: LoraChip,
    pub frequency_hz: u32,
    pub bandwidth_hz: u32,
    pub beacon: bool,
    pub spi_host: i32,
    pub sck: i32,
    pub miso: i32,
    pub mosi: i32,
    pub cs: i32,
    pub rst: i32,
    pub dio0: i32,
    pub busy: i32,
    pub sf: i32,
    pub cr: i32,
    pub sync_word: i32,
    pub crc: bool,
    pub preamble: i32,
    pub tx_power: i32,
}

impl Default for LoraConfig {
    fn default() -> Self {
        Self {
            chip: LoraChip::Sx127x,
            frequency_hz: DEFAULT_FREQUENCY_HZ,
            bandwidth_hz: DEFAULT_BANDWIDTH_HZ,
            beacon: true,
            spi_host: sys::spi_host_device_t_SPI3_HOST as i32,
            sck: 5,
            miso: 19,
            mosi: 27,
            cs: 18,
            rst: 14,
            dio0: 26,
            busy: -1,
            sf: 10,
            cr: 5,
            sync_word: 0x2b,
            crc: true,
            preamble: 16,
            tx_power: 17,
        }
    }
}

struct LoraCommand {
    name: &'static str,
    settings: SharedSettings,
}

impl LoraCommand {
    fn new(name: &'static str, settings: SharedSettings) -> Self {
        Self { name, settings }
    }
}

#[derive(Clone, Debug)]
struct LoraState {
    config: LoraConfig,
}

impl LoraState {
    fn load(settings: &SharedSettings) -> Result<Self> {
        let defaults = LoraConfig::default();
        let settings = settings.borrow();
        Ok(Self {
            config: LoraConfig {
                chip: settings
                    .get_str("lora.chip")?
                    .as_deref()
                    .map(LoraChip::parse)
                    .transpose()?
                    .unwrap_or(defaults.chip),
                frequency_hz: settings.get_i32("lora.freq", defaults.frequency_hz as i32)? as u32,
                bandwidth_hz: settings.get_i32("lora.bw", defaults.bandwidth_hz as i32)? as u32,
                beacon: settings.get_bool("lora.beacon", defaults.beacon)?,
                spi_host: settings.get_i32("lora.spi_host", defaults.spi_host)?,
                sck: settings.get_i32("lora.sck", defaults.sck)?,
                miso: settings.get_i32("lora.miso", defaults.miso)?,
                mosi: settings.get_i32("lora.mosi", defaults.mosi)?,
                cs: settings.get_i32("lora.cs", defaults.cs)?,
                rst: settings.get_i32("lora.rst", defaults.rst)?,
                dio0: settings.get_i32("lora.dio0", defaults.dio0)?,
                busy: settings.get_i32("lora.busy", defaults.busy)?,
                sf: settings.get_i32("lora.sf", defaults.sf)?,
                cr: settings.get_i32("lora.cr", defaults.cr)?,
                sync_word: settings.get_i32("lora.sync_word", defaults.sync_word)?,
                crc: settings.get_bool("lora.crc", defaults.crc)?,
                preamble: settings.get_i32("lora.preamble", defaults.preamble)?,
                tx_power: settings.get_i32("lora.tx_power", defaults.tx_power)?,
            },
        })
    }
}

pub fn load_config(settings: &SharedSettings) -> Result<LoraConfig> {
    Ok(LoraState::load(settings)?.config)
}

impl CommandHandler for LoraCommand {
    fn name(&self) -> &'static str {
        self.name
    }

    fn help(&self) -> &'static str {
        match self.name {
            "lora" => "lora board=heltec_v3 | chip=sx127x|sx1262 preset=medium_fast|medium_slow freq=913125000 bw=250000 sf=9 cr=5 sync_word=0x2b rx=true|false sleep=true|false apply=true",
            "loraprobe" => "loraprobe chip=sx127x|sx1262 sck=5,18,9 miso=19,11 mosi=27,10 cs=18,5,8 rst=14,23,12 dio0=26,14 busy=-1,13 save=true",
            "lorasend" => "lorasend text=hello | data=hex:0102 | format=raw",
            "loralisten" => "loralisten ms=5000 count=4 local_only=true",
            "loradump" => "loradump",
            _ => "lora",
        }
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        match self.name {
            "lora" => self.configure(request),
            "loraprobe" => self.probe(request),
            "lorasend" => self.send_raw(request),
            "loralisten" => self.listen(request),
            "loradump" => self.dump(request),
            _ => Ok(CommandResponse::error("invalid lora command")),
        }
    }
}

impl LoraCommand {
    fn configure(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if request
            .arg("sleep")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            sleep_radio(&self.settings)?;
            return Ok(CommandResponse::ok("lora sleep=true"));
        }
        let rx_request = request.arg("rx").map(parse_bool).transpose()?;
        if let Some(false) = rx_request {
            BACKGROUND_RX_RUNNING.store(false, Ordering::Relaxed);
            notify_lora_rx_task();
            return Ok(CommandResponse::ok("lora rx=false"));
        }
        if let Some(preset) = request.arg("preset") {
            let preset = LoraPreset::parse(preset)?;
            let mut settings = self.settings.borrow_mut();
            settings.set_i32("lora.bw", preset.bandwidth_hz as i32)?;
            settings.set_i32("lora.sf", preset.sf)?;
            settings.set_i32("lora.cr", preset.cr)?;
            settings.set_bool("lora.crc", true)?;
            settings.set_i32("lora.preamble", 16)?;
        }
        if let Some(board) = request.arg("board") {
            match board.to_ascii_lowercase().as_str() {
                "heltec_v3" | "heltec-v3" | "wb32laf" => {
                    let mut settings = self.settings.borrow_mut();
                    settings.set_str("lora.chip", LoraChip::Sx1262.as_str())?;
                    settings.set_i32("lora.spi_host", sys::spi_host_device_t_SPI2_HOST as i32)?;
                    settings.set_i32("lora.sck", 9)?;
                    settings.set_i32("lora.miso", 11)?;
                    settings.set_i32("lora.mosi", 10)?;
                    settings.set_i32("lora.cs", 8)?;
                    settings.set_i32("lora.rst", 12)?;
                    settings.set_i32("lora.dio0", 14)?;
                    settings.set_i32("lora.busy", 13)?;
                    settings.set_i32("lora.tx_power", 17)?;
                }
                _ => bail!("unsupported LoRa board {board}"),
            }
        }
        if let Some(chip) = request.arg("chip") {
            self.settings
                .borrow_mut()
                .set_str("lora.chip", LoraChip::parse(chip)?.as_str())?;
        }
        if let Some(freq) = request.arg_i32("freq")? {
            self.settings
                .borrow_mut()
                .set_i32("lora.freq", freq.max(0))?;
        }
        if let Some(bw) = request.arg_i32("bw")? {
            validate_bandwidth(bw as u32)?;
            self.settings.borrow_mut().set_i32("lora.bw", bw)?;
        }
        if let Some(beacon) = request.arg("beacon") {
            self.settings
                .borrow_mut()
                .set_bool("lora.beacon", parse_bool(beacon)?)?;
        }
        if let Some(crc) = request.arg("crc") {
            self.settings
                .borrow_mut()
                .set_bool("lora.crc", parse_bool(crc)?)?;
        }
        for (arg, key) in [
            ("spi_host", "lora.spi_host"),
            ("sck", "lora.sck"),
            ("miso", "lora.miso"),
            ("mosi", "lora.mosi"),
            ("cs", "lora.cs"),
            ("rst", "lora.rst"),
            ("dio0", "lora.dio0"),
            ("busy", "lora.busy"),
            ("sf", "lora.sf"),
            ("cr", "lora.cr"),
            ("sync_word", "lora.sync_word"),
            ("preamble", "lora.preamble"),
            ("tx_power", "lora.tx_power"),
        ] {
            if let Some(value) = request.arg(arg) {
                let value = parse_i32(value)?;
                match arg {
                    "sck" | "miso" | "mosi" | "cs" | "rst" | "dio0" => validate_pin(value)?,
                    "busy" => validate_optional_pin(value)?,
                    "sf" => validate_sf(value)?,
                    "cr" => validate_cr(value)?,
                    "sync_word" => validate_u8(value)?,
                    "preamble" => validate_range("preamble", value, 6, 65535)?,
                    "tx_power" => validate_range("tx_power", value, 2, 20)?,
                    _ => {}
                }
                self.settings.borrow_mut().set_i32(key, value)?;
            }
        }

        let state = LoraState::load(&self.settings)?;
        if request
            .arg("apply")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            let _guard = lora_spi_lock().lock().unwrap();
            let mut radio = Radio::open(&state.config)?;
            radio.configure_radio()?;
        }
        if let Some(true) = rx_request {
            let started = start_background_rx(self.settings.clone())?.is_some();
            return Ok(CommandResponse::ok(format!(
                "lora rx=true started={} freq={} bw={} sf={} cr={} sync_word=0x{:02x}",
                started,
                state.config.frequency_hz,
                state.config.bandwidth_hz,
                state.config.sf,
                state.config.cr,
                state.config.sync_word
            )));
        }
        Ok(CommandResponse::ok(format!(
            "lora chip={} freq={} bw={} sf={} cr={} sync_word=0x{:02x} crc={} preamble={} tx_power={} spi_host={} sck={} miso={} mosi={} cs={} rst={} dio0={} busy={}",
            state.config.chip.as_str(),
            state.config.frequency_hz,
            state.config.bandwidth_hz,
            state.config.sf,
            state.config.cr,
            state.config.sync_word,
            state.config.crc,
            state.config.preamble,
            state.config.tx_power,
            state.config.spi_host,
            state.config.sck,
            state.config.miso,
            state.config.mosi,
            state.config.cs,
            state.config.rst,
            state.config.dio0,
            state.config.busy
        )))
    }

    fn probe(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let state = LoraState::load(&self.settings)?;
        let host_candidates = parse_i32_list(request.arg("spi_host"), state.config.spi_host)?;
        let chip_candidates = parse_chip_list(request.arg("chip"), state.config.chip)?;
        let sck_candidates = parse_pin_list(request.arg("sck"), state.config.sck)?;
        let miso_candidates = parse_pin_list(request.arg("miso"), state.config.miso)?;
        let mosi_candidates = parse_pin_list(request.arg("mosi"), state.config.mosi)?;
        let cs_candidates = parse_pin_list(request.arg("cs"), state.config.cs)?;
        let rst_candidates = parse_pin_list(request.arg("rst"), state.config.rst)?;
        let dio0_candidates = parse_pin_list(request.arg("dio0"), state.config.dio0)?;
        let busy_candidates = parse_optional_pin_list(request.arg("busy"), state.config.busy)?;

        let save = request
            .arg("save")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false);
        let mut attempts = Vec::new();

        for chip in &chip_candidates {
            for host in &host_candidates {
                for sck in &sck_candidates {
                    for miso in &miso_candidates {
                        for mosi in &mosi_candidates {
                            for cs in &cs_candidates {
                                for rst in &rst_candidates {
                                    for dio0 in &dio0_candidates {
                                        for busy in &busy_candidates {
                                            if has_duplicate_pins(&[
                                                *sck, *miso, *mosi, *cs, *rst, *dio0, *busy,
                                            ]) {
                                                continue;
                                            }
                                            let mut config = state.config.clone();
                                            config.chip = *chip;
                                            config.spi_host = *host;
                                            config.sck = *sck;
                                            config.miso = *miso;
                                            config.mosi = *mosi;
                                            config.cs = *cs;
                                            config.rst = *rst;
                                            config.dio0 = *dio0;
                                            config.busy = *busy;
                                            let result = probe_lora(&config);
                                            attempts.push(format!(
                                        "chip={},host={host},sck={sck},miso={miso},mosi={mosi},cs={cs},rst={rst},dio0={dio0},busy={busy}:{result}",
                                        chip.as_str()
                                    ));
                                            if result.starts_with("ready") && save {
                                                let mut settings = self.settings.borrow_mut();
                                                settings.set_str("lora.chip", chip.as_str())?;
                                                settings.set_i32("lora.spi_host", *host)?;
                                                settings.set_i32("lora.sck", *sck)?;
                                                settings.set_i32("lora.miso", *miso)?;
                                                settings.set_i32("lora.mosi", *mosi)?;
                                                settings.set_i32("lora.cs", *cs)?;
                                                settings.set_i32("lora.rst", *rst)?;
                                                settings.set_i32("lora.dio0", *dio0)?;
                                                settings.set_i32("lora.busy", *busy)?;
                                                return Ok(CommandResponse::ok(format!(
                                            "loraprobe matched chip={} host={host} sck={sck} miso={miso} mosi={mosi} cs={cs} rst={rst} dio0={dio0} busy={busy} saved=true",
                                            chip.as_str()
                                        )));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(CommandResponse::ok(format!(
            "loraprobe {}",
            attempts.join(" ")
        )))
    }

    fn send_raw(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let payload = parse_payload(request)?;
        let kind = request
            .arg("format")
            .or_else(|| request.arg("kind"))
            .map(FrameKind::parse)
            .transpose()?
            .unwrap_or(FrameKind::Meshtastic);
        let portnum = request
            .arg_i32("portnum")?
            .or_else(|| {
                self.settings
                    .borrow()
                    .get_i32("lora.portnum", MESHTASTIC_DEFAULT_PORTNUM as i32)
                    .ok()
            })
            .unwrap_or(MESHTASTIC_DEFAULT_PORTNUM as i32);
        if !(0..=511).contains(&portnum) {
            bail!("Meshtastic portnum out of private/reserved range: {portnum}");
        }
        let timeout_ms = parse_arg_or(request, "timeout", 2000)? as u32;
        let hop_limit = request
            .arg_i32("hop_limit")?
            .or(request.arg_i32("hop")?)
            .or_else(|| {
                if request
                    .arg("forward")
                    .map(parse_bool)
                    .transpose()
                    .ok()
                    .flatten()
                    .unwrap_or(false)
                {
                    Some(1)
                } else {
                    None
                }
            })
            .map(|hop| hop.clamp(0, 7) as u8);
        let response = send_payload(
            &self.settings,
            &payload,
            kind,
            hop_limit,
            Some(portnum as u32),
            timeout_ms,
        )?;
        Ok(CommandResponse::ok(response))
    }

    fn listen(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let ms = parse_arg_or(request, "ms", 5000)?.max(1) as u32;
        let max_packets = parse_arg_or(request, "count", 4)?.clamp(1, 16) as usize;
        let local_only = request
            .arg("local_only")
            .or_else(|| request.arg("wake_only"))
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false);
        let state = LoraState::load(&self.settings)?;
        let local_node = meshtastic_sender_node().ok();
        let _guard = lora_spi_lock().lock().unwrap();
        let mut radio = Radio::open(&state.config)?;
        radio.configure_radio()?;
        radio.start_rx()?;

        let deadline = Instant::now() + Duration::from_millis(ms as u64);
        let mut packets = Vec::new();
        while Instant::now() < deadline && packets.len() < max_packets {
            if let Some(packet) = radio.poll_packet()? {
                let decoded = decode_frame(&packet.data)?;
                let address = address_metadata(&packet.data, &self.settings)?;
                let mac_local_match = decoded
                    .meshtastic
                    .zip(local_node)
                    .map(|(header, node)| header.is_for(node))
                    .unwrap_or(false);
                let local_match = address.local_match || mac_local_match;
                if local_match {
                    telemetry::record_local_packet(
                        "lora",
                        Direction::Rx,
                        &packet.data,
                        compact_lora_detail(
                            decoded.meshtastic,
                            address.destination.as_deref(),
                            packet.rssi,
                            packet.snr,
                        ),
                    );
                }
                if local_only && !local_match && !address.broadcast {
                    continue;
                }
                telemetry::record_packet(
                    "lora",
                    Direction::Rx,
                    &packet.data,
                    compact_lora_detail(
                        decoded.meshtastic,
                        address.destination.as_deref(),
                        packet.rssi,
                        packet.snr,
                    ),
                );
                packets.push(format!(
                    "src={} dst={} n={} local={} bc={} hl={} hs={} len={} wire={} rssi={} snr={} data={}",
                    decoded
                        .meshtastic
                        .map(|h| format_meshtastic_node(h.from))
                        .unwrap_or_else(|| "-".to_string()),
                    address.destination.as_deref().unwrap_or(""),
                    decoded
                        .meshtastic
                        .map(|h| h.id.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    local_match,
                    address.broadcast,
                    decoded.meshtastic.map(|h| h.hop_limit()).unwrap_or(0),
                    decoded.meshtastic.map(|h| h.hop_start()).unwrap_or(0),
                    decoded.payload.len(),
                    packet.data.len(),
                    packet.rssi,
                    packet.snr,
                    hex_bytes(decoded.payload)
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(CommandResponse::ok(format!(
            "loralisten n={} {}",
            packets.len(),
            packets.join(" | ")
        )))
    }

    fn dump(&mut self, _request: &CommandRequest) -> Result<CommandResponse> {
        let state = LoraState::load(&self.settings)?;
        let _guard = lora_spi_lock().lock().unwrap();
        let mut radio = Radio::open(&state.config)?;
        Ok(CommandResponse::ok(format!("loradump {}", radio.dump()?)))
    }
}

pub struct LoraTransport {
    sent_frames: u32,
    settings: SharedSettings,
}

impl LoraTransport {
    fn new(settings: SharedSettings) -> Self {
        Self {
            sent_frames: 0,
            settings,
        }
    }
}

impl Transport for LoraTransport {
    fn name(&self) -> &'static str {
        "lora"
    }

    fn send(&mut self, frame: &Frame<'_>, from_interface: i32) -> Result<()> {
        self.sent_frames = self.sent_frames.saturating_add(1);
        let state = LoraState::load(&self.settings)?;
        telemetry::count_packet("lora", Direction::Tx, frame.payload().len());
        telemetry::record_log(format!(
            "ev=lora.tx t=lora src=l3 from={} n={} len={} rf={}",
            from_interface,
            self.sent_frames,
            frame.payload().len(),
            compact_rf(&state.config)
        ));
        log::info!(
            "lora transport queued: from={} len={} total={} freq={} cs={}",
            from_interface,
            frame.payload().len(),
            self.sent_frames,
            state.config.frequency_hz,
            state.config.cs
        );
        Ok(())
    }
}

fn run_background_rx(config: LoraConfig, local_node: Option<u32>) -> Result<()> {
    LORA_RX_TASK.store(
        unsafe { sys::xTaskGetCurrentTaskHandle() },
        Ordering::SeqCst,
    );
    {
        let _guard = lora_spi_lock().lock().unwrap();
        let mut radio = Radio::open(&config)?;
        radio.configure_radio()?;
        radio.start_rx()?;
    }
    configure_dio0_interrupt(config.dio0)?;
    let started = format!(
        "ev=lora.rx_start rf={} sync=0x{:02x} cs={} rst={} dio0={}",
        compact_rf(&config),
        config.sync_word,
        config.cs,
        config.rst,
        config.dio0
    );
    telemetry::record_log(started);

    while BACKGROUND_RX_RUNNING.load(Ordering::Relaxed) {
        let notified = wait_for_lora_irq(Duration::from_secs(30));
        if !BACKGROUND_RX_RUNNING.load(Ordering::Relaxed) {
            break;
        }
        match notified {
            true => match poll_background_packet(&config) {
                Ok(Some(packet)) => {
                    record_background_packet(&packet, "background", local_node);
                    forward_rx_packet(&packet);
                }
                Ok(None) => {}
                Err(err) => {
                    let line = format!(
                        "ev=lora.err c=rx msg={}",
                        crate::commands::protocol::escape_value(&err.to_string())
                    );
                    telemetry::record_log(line);
                    thread::sleep(Duration::from_millis(1000));
                }
            },
            false => {
                // A long timeout is a missed-IRQ recovery path, not the normal RX mechanism.
                if let Ok(Some(packet)) = poll_background_packet(&config) {
                    record_background_packet(&packet, "background-timeout", local_node);
                    forward_rx_packet(&packet);
                }
            }
        }
    }
    unsafe {
        let _ = sys::gpio_isr_handler_remove(config.dio0);
        let _ = set_lora_irq_enabled(config.dio0, false);
    }
    LORA_RX_TASK.store(std::ptr::null_mut(), Ordering::SeqCst);
    Ok(())
}

fn poll_background_packet(config: &LoraConfig) -> Result<Option<Packet>> {
    let _guard = lora_spi_lock().lock().unwrap();
    let mut radio = Radio::open_no_reset(config)?;
    let packet = radio.poll_packet()?;
    radio.start_rx()?;
    Ok(packet)
}

fn record_background_packet(packet: &Packet, source: &str, local_node: Option<u32>) {
    let decoded = decode_frame(&packet.data).ok();
    let (src, dst, packet_id, local_match, broadcast, hop_limit, hop_start) =
        if let Some(decoded) = decoded {
            if let Some(header) = decoded.meshtastic {
                (
                    format_meshtastic_node(header.from),
                    format_meshtastic_node(header.to),
                    header.id.to_string(),
                    local_node.map(|node| header.is_for(node)).unwrap_or(false),
                    header.is_broadcast(),
                    header.hop_limit(),
                    header.hop_start(),
                )
            } else {
                (
                    "-".to_string(),
                    "-".to_string(),
                    "-".to_string(),
                    false,
                    false,
                    0,
                    0,
                )
            }
        } else {
            (
                "-".to_string(),
                "-".to_string(),
                "-".to_string(),
                false,
                false,
                0,
                0,
            )
        };
    let detail = format!(
        "src={} dst={} n={} rssi={} snr={} hl={} hs={} source={}",
        src, dst, packet_id, packet.rssi, packet.snr, hop_limit, hop_start, source
    );
    telemetry::record_packet("lora", Direction::Rx, &packet.data, detail.clone());
    if local_match {
        telemetry::record_local_packet("lora", Direction::Rx, &packet.data, detail.clone());
    }
    let line = format!(
        "ev={} t=lora src={} dst={} n={} local={} bc={} hl={} hs={} len={} rssi={} snr={}",
        if local_match {
            "lora.rx_local"
        } else {
            "lora.rx"
        },
        src,
        dst,
        packet_id,
        local_match,
        broadcast,
        hop_limit,
        hop_start,
        packet.data.len(),
        packet.rssi,
        packet.snr
    );
    telemetry::record_log(line.clone());
    telemetry::emit_console(&line);
}

fn lora_spi_lock() -> &'static Mutex<()> {
    LORA_SPI_LOCK.get_or_init(|| Mutex::new(()))
}

fn configure_dio0_interrupt(pin: i32) -> Result<()> {
    unsafe {
        if !GPIO_ISR_SERVICE_READY.load(Ordering::Relaxed) {
            let install = sys::gpio_install_isr_service(0);
            if install != sys::ESP_OK && install != sys::ESP_ERR_INVALID_STATE {
                esp_ok(install)?;
            }
            GPIO_ISR_SERVICE_READY.store(true, Ordering::Relaxed);
        }
        let _ = sys::gpio_isr_handler_remove(pin);
        esp_ok(sys::gpio_set_intr_type(
            pin,
            sys::gpio_int_type_t_GPIO_INTR_POSEDGE,
        ))?;
        esp_ok(sys::gpio_isr_handler_add(
            pin,
            Some(lora_dio0_isr),
            std::ptr::null_mut(),
        ))?;
    }
    Ok(())
}

fn set_lora_irq_enabled(pin: i32, enabled: bool) -> Result<()> {
    let intr_type = if enabled {
        sys::gpio_int_type_t_GPIO_INTR_POSEDGE
    } else {
        sys::gpio_int_type_t_GPIO_INTR_DISABLE
    };
    unsafe {
        esp_ok(sys::gpio_set_intr_type(pin, intr_type))?;
    }
    Ok(())
}

fn wait_for_lora_irq(timeout: Duration) -> bool {
    let ticks = duration_to_ticks(timeout);
    unsafe { sys::ulTaskGenericNotifyTake(0, 1, ticks) != 0 }
}

fn notify_lora_rx_task() {
    let task = LORA_RX_TASK.load(Ordering::SeqCst);
    if !task.is_null() {
        unsafe {
            sys::xTaskGenericNotify(
                task,
                0,
                1,
                sys::eNotifyAction_eIncrement,
                std::ptr::null_mut(),
            );
        }
    }
}

fn duration_to_ticks(timeout: Duration) -> sys::TickType_t {
    let hz = sys::configTICK_RATE_HZ as u128;
    let ticks = timeout.as_millis().saturating_mul(hz).div_ceil(1000);
    ticks.min(sys::TickType_t::MAX as u128) as sys::TickType_t
}

unsafe extern "C" fn lora_dio0_isr(_arg: *mut core::ffi::c_void) {
    let task = LORA_RX_TASK.load(Ordering::SeqCst);
    if !task.is_null() {
        let mut higher_priority_task_woken: sys::BaseType_t = 0;
        unsafe {
            sys::vTaskGenericNotifyGiveFromISR(task, 0, &mut higher_priority_task_woken);
        }
    }
}

fn forward_rx_packet(packet: &Packet) {
    super::mode::observe_ping("lora", &packet.data);
    match super::ble_bt::announce_lora_packet(&packet.data, packet.rssi, packet.snr) {
        Ok(()) => {
            let line = format!("ev=lora.fwd t=ble len={} ok=true", packet.data.len());
            telemetry::record_log(line);
        }
        Err(err) => {
            let line = format!(
                "ev=lora.fwd t=ble len={} ok=false msg={}",
                packet.data.len(),
                crate::commands::protocol::escape_value(&err.to_string())
            );
            telemetry::record_log(line);
        }
    }
    match super::wifi::forward_management_packet(&packet.data) {
        Ok(()) => {
            let line = format!("ev=lora.fwd t=wifi_raw len={} ok=true", packet.data.len());
            telemetry::record_log(line);
        }
        Err(err) => {
            let line = format!(
                "ev=lora.fwd t=wifi_raw len={} ok=false msg={}",
                packet.data.len(),
                crate::commands::protocol::escape_value(&err.to_string())
            );
            telemetry::record_log(line);
        }
    }
    match super::nan::forward_packet(&packet.data) {
        Ok(()) => {
            let line = format!("ev=lora.fwd t=nan len={} ok=true", packet.data.len());
            telemetry::record_log(line);
        }
        Err(err) => {
            let line = format!(
                "ev=lora.fwd t=nan len={} ok=false msg={}",
                packet.data.len(),
                crate::commands::protocol::escape_value(&err.to_string())
            );
            telemetry::record_log(line);
        }
    }
}

struct Packet {
    data: Vec<u8>,
    rssi: i32,
    snr: f32,
}

struct LoraPreset {
    bandwidth_hz: u32,
    sf: i32,
    cr: i32,
}

impl LoraPreset {
    fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "medium_fast" | "mediumfast" | "mf" => Ok(Self {
                bandwidth_hz: 250_000,
                sf: 9,
                cr: 5,
            }),
            "medium_slow" | "mediumslow" | "ms" => Ok(Self {
                bandwidth_hz: 250_000,
                sf: 10,
                cr: 5,
            }),
            _ => bail!("unsupported LoRa preset {value}"),
        }
    }
}

fn apply_medium_fast(config: &mut LoraConfig) {
    config.bandwidth_hz = 250_000;
    config.sf = 9;
    config.cr = 5;
    config.sync_word = 0x2b;
    config.crc = true;
    config.preamble = 16;
}

struct Sx127x {
    config: LoraConfig,
    host: sys::spi_host_device_t,
    handle: sys::spi_device_handle_t,
}

enum Radio {
    Sx127x(Sx127x),
    Sx1262(Sx1262),
}

impl Radio {
    fn open(config: &LoraConfig) -> Result<Self> {
        match config.chip {
            LoraChip::Sx127x => Ok(Self::Sx127x(Sx127x::open(config)?)),
            LoraChip::Sx1262 => Ok(Self::Sx1262(Sx1262::open(config)?)),
        }
    }

    fn open_no_reset(config: &LoraConfig) -> Result<Self> {
        match config.chip {
            LoraChip::Sx127x => Ok(Self::Sx127x(Sx127x::open_no_reset(config)?)),
            LoraChip::Sx1262 => Ok(Self::Sx1262(Sx1262::open_no_reset(config)?)),
        }
    }

    fn configure_radio(&mut self) -> Result<()> {
        match self {
            Self::Sx127x(radio) => radio.configure_radio(),
            Self::Sx1262(radio) => radio.configure_radio(),
        }
    }

    fn send_packet(&mut self, payload: &[u8], timeout_ms: u32) -> Result<()> {
        match self {
            Self::Sx127x(radio) => radio.send_packet(payload, timeout_ms),
            Self::Sx1262(radio) => radio.send_packet(payload, timeout_ms),
        }
    }

    fn start_rx(&mut self) -> Result<()> {
        match self {
            Self::Sx127x(radio) => radio.start_rx(),
            Self::Sx1262(radio) => radio.start_rx(),
        }
    }

    fn sleep(&mut self) -> Result<()> {
        match self {
            Self::Sx127x(radio) => radio.sleep(),
            Self::Sx1262(radio) => radio.sleep(),
        }
    }

    fn poll_packet(&mut self) -> Result<Option<Packet>> {
        match self {
            Self::Sx127x(radio) => radio.poll_packet(),
            Self::Sx1262(radio) => radio.poll_packet(),
        }
    }

    fn dump(&mut self) -> Result<String> {
        match self {
            Self::Sx127x(radio) => radio.dump(),
            Self::Sx1262(radio) => radio.dump(),
        }
    }
}

impl Sx127x {
    fn open(config: &LoraConfig) -> Result<Self> {
        Self::open_inner(config, true)
    }

    fn open_no_reset(config: &LoraConfig) -> Result<Self> {
        Self::open_inner(config, false)
    }

    fn open_inner(config: &LoraConfig, reset: bool) -> Result<Self> {
        validate_config(config)?;
        let host = spi_host(config.spi_host)?;
        unsafe {
            let _ = sys::spi_bus_free(host);
        }

        let mut bus = sys::spi_bus_config_t::default();
        bus.sclk_io_num = config.sck;
        bus.max_transfer_sz = 256;
        unsafe {
            bus.__bindgen_anon_1.mosi_io_num = config.mosi;
            bus.__bindgen_anon_2.miso_io_num = config.miso;
            bus.__bindgen_anon_3.quadwp_io_num = sys::gpio_num_t_GPIO_NUM_NC;
            bus.__bindgen_anon_4.quadhd_io_num = sys::gpio_num_t_GPIO_NUM_NC;
            esp_ok(sys::spi_bus_initialize(
                host,
                &bus,
                sys::spi_common_dma_t_SPI_DMA_DISABLED,
            ))?;
        }

        let mut dev = sys::spi_device_interface_config_t::default();
        dev.clock_speed_hz = 1_000_000;
        dev.mode = 0;
        dev.spics_io_num = sys::gpio_num_t_GPIO_NUM_NC;
        dev.queue_size = 1;

        let mut handle = std::ptr::null_mut();
        unsafe {
            esp_ok(sys::spi_bus_add_device(host, &dev, &mut handle))?;
            esp_ok(sys::gpio_set_direction(
                config.cs,
                sys::gpio_mode_t_GPIO_MODE_OUTPUT,
            ))?;
            esp_ok(sys::gpio_set_level(config.cs, 1))?;
            esp_ok(sys::gpio_set_direction(
                config.rst,
                sys::gpio_mode_t_GPIO_MODE_OUTPUT,
            ))?;
            esp_ok(sys::gpio_set_direction(
                config.dio0,
                sys::gpio_mode_t_GPIO_MODE_INPUT,
            ))?;
        }

        let mut radio = Self {
            config: config.clone(),
            host,
            handle,
        };
        if reset {
            radio.reset()?;
        }
        let version = radio.read_reg(REG_VERSION)?;
        if version != SX127X_VERSION {
            bail!("unexpected SX127x version 0x{version:02x}");
        }
        Ok(radio)
    }

    fn reset(&mut self) -> Result<()> {
        unsafe {
            esp_ok(sys::gpio_set_level(self.config.rst, 0))?;
        }
        std::thread::sleep(Duration::from_millis(10));
        unsafe {
            esp_ok(sys::gpio_set_level(self.config.rst, 1))?;
        }
        std::thread::sleep(Duration::from_millis(10));
        Ok(())
    }

    fn configure_radio(&mut self) -> Result<()> {
        self.write_reg(REG_OP_MODE, MODE_LONG_RANGE | MODE_SLEEP)?;
        self.set_frequency(self.config.frequency_hz)?;
        self.write_reg(REG_FIFO_TX_BASE_ADDR, 0)?;
        self.write_reg(REG_FIFO_RX_BASE_ADDR, 0)?;
        let lna = self.read_reg(REG_LNA)? | 0x03;
        self.write_reg(REG_LNA, lna)?;
        self.set_bandwidth(self.config.bandwidth_hz)?;
        self.set_spreading_factor(self.config.sf)?;
        self.set_coding_rate(self.config.cr)?;
        self.set_crc(self.config.crc)?;
        self.set_preamble(self.config.preamble as u16)?;
        self.write_reg(REG_SYNC_WORD, self.config.sync_word as u8)?;
        self.set_tx_power(self.config.tx_power)?;
        self.write_reg(REG_MODEM_CONFIG_3, 0x04)?;
        self.write_reg(REG_IRQ_FLAGS, 0xff)?;
        self.write_reg(REG_OP_MODE, MODE_LONG_RANGE | MODE_STDBY)?;
        Ok(())
    }

    fn set_frequency(&mut self, hz: u32) -> Result<()> {
        let frf = ((hz as u64) << 19) / 32_000_000_u64;
        self.write_reg(REG_FRF_MSB, (frf >> 16) as u8)?;
        self.write_reg(REG_FRF_MID, (frf >> 8) as u8)?;
        self.write_reg(REG_FRF_LSB, frf as u8)
    }

    fn set_bandwidth(&mut self, hz: u32) -> Result<()> {
        let bw = match hz {
            7_800 => 0,
            10_400 => 1,
            15_600 => 2,
            20_800 => 3,
            31_250 => 4,
            41_700 => 5,
            62_500 => 6,
            125_000 => 7,
            250_000 => 8,
            500_000 => 9,
            _ => bail!("unsupported LoRa bandwidth {hz}"),
        };
        let current = self.read_reg(REG_MODEM_CONFIG_1)? & 0x0f;
        self.write_reg(REG_MODEM_CONFIG_1, (bw << 4) | current)
    }

    fn set_spreading_factor(&mut self, sf: i32) -> Result<()> {
        validate_sf(sf)?;
        if sf == 6 {
            self.write_reg(0x31, 0xc5)?;
            self.write_reg(0x37, 0x0c)?;
        } else {
            self.write_reg(0x31, 0xc3)?;
            self.write_reg(0x37, 0x0a)?;
        }
        let current = self.read_reg(REG_MODEM_CONFIG_2)? & 0x0f;
        self.write_reg(REG_MODEM_CONFIG_2, ((sf as u8) << 4) | current)
    }

    fn set_coding_rate(&mut self, cr: i32) -> Result<()> {
        validate_cr(cr)?;
        let current = self.read_reg(REG_MODEM_CONFIG_1)? & 0xf1;
        self.write_reg(REG_MODEM_CONFIG_1, current | (((cr - 4) as u8) << 1))
    }

    fn set_crc(&mut self, enable: bool) -> Result<()> {
        let current = self.read_reg(REG_MODEM_CONFIG_2)?;
        let value = if enable {
            current | 0x04
        } else {
            current & !0x04
        };
        self.write_reg(REG_MODEM_CONFIG_2, value)
    }

    fn set_preamble(&mut self, preamble: u16) -> Result<()> {
        self.write_reg(REG_PREAMBLE_MSB, (preamble >> 8) as u8)?;
        self.write_reg(REG_PREAMBLE_LSB, preamble as u8)
    }

    fn set_tx_power(&mut self, dbm: i32) -> Result<()> {
        validate_range("tx_power", dbm, 2, 20)?;
        let output = dbm.clamp(2, 17);
        self.write_reg(REG_PA_CONFIG, 0x80 | ((output - 2) as u8))
    }

    fn send_packet(&mut self, payload: &[u8], timeout_ms: u32) -> Result<()> {
        self.write_reg(REG_OP_MODE, MODE_LONG_RANGE | MODE_STDBY)?;
        self.write_reg(REG_FIFO_ADDR_PTR, 0)?;
        for byte in payload {
            self.write_reg(REG_FIFO, *byte)?;
        }
        self.write_reg(REG_PAYLOAD_LENGTH, payload.len() as u8)?;
        self.write_reg(REG_IRQ_FLAGS, 0xff)?;
        self.write_reg(REG_DIO_MAPPING_1, 0x40)?;
        self.write_reg(REG_OP_MODE, MODE_LONG_RANGE | MODE_TX)?;

        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        while Instant::now() < deadline {
            let irq = self.read_reg(REG_IRQ_FLAGS)?;
            if irq & IRQ_TX_DONE != 0 {
                self.write_reg(REG_IRQ_FLAGS, IRQ_TX_DONE)?;
                self.write_reg(REG_OP_MODE, MODE_LONG_RANGE | MODE_STDBY)?;
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        bail!("LoRa TX timeout");
    }

    fn start_rx(&mut self) -> Result<()> {
        self.write_reg(REG_FIFO_ADDR_PTR, 0)?;
        self.write_reg(REG_IRQ_FLAGS, 0xff)?;
        self.write_reg(REG_DIO_MAPPING_1, 0x00)?;
        self.write_reg(REG_OP_MODE, MODE_LONG_RANGE | MODE_RX_CONTINUOUS)
    }

    fn sleep(&mut self) -> Result<()> {
        self.write_reg(REG_OP_MODE, MODE_LONG_RANGE | MODE_SLEEP)
    }

    fn poll_packet(&mut self) -> Result<Option<Packet>> {
        let irq = self.read_reg(REG_IRQ_FLAGS)?;
        if irq & IRQ_RX_DONE == 0 {
            return Ok(None);
        }
        self.write_reg(REG_IRQ_FLAGS, irq)?;
        if irq & IRQ_PAYLOAD_CRC_ERROR != 0 {
            return Ok(None);
        }
        let len = self.read_reg(REG_RX_NB_BYTES)? as usize;
        let current = self.read_reg(REG_FIFO_RX_CURRENT_ADDR)?;
        self.write_reg(REG_FIFO_ADDR_PTR, current)?;
        let mut data = Vec::with_capacity(len);
        for _ in 0..len {
            data.push(self.read_reg(REG_FIFO)?);
        }
        let snr = (self.read_reg(REG_PKT_SNR_VALUE)? as i8) as f32 / 4.0;
        let rssi = self.read_reg(REG_PKT_RSSI_VALUE)? as i32 - 164;
        Ok(Some(Packet { data, rssi, snr }))
    }

    fn dump(&mut self) -> Result<String> {
        let mut regs = Vec::new();
        let mut values = [0_u8; 0x50];
        for reg in 0x00_u8..=0x4f {
            let value = self.read_reg(reg)?;
            values[reg as usize] = value;
            regs.push(format!("{reg:02x}:{value:02x}"));
        }
        Ok(format!(
            "chip=sx127x {} regs={}",
            decode_registers(&values),
            regs.join(" ")
        ))
    }

    fn read_reg(&mut self, reg: u8) -> Result<u8> {
        let mut rx = [0_u8; 2];
        self.spi(&[reg & 0x7f, 0], &mut rx)?;
        Ok(rx[1])
    }

    fn write_reg(&mut self, reg: u8, value: u8) -> Result<()> {
        let mut rx = [0_u8; 2];
        self.spi(&[reg | 0x80, value], &mut rx)
    }

    fn spi(&mut self, tx: &[u8], rx: &mut [u8]) -> Result<()> {
        if tx.len() != rx.len() {
            bail!("spi tx/rx length mismatch");
        }
        let mut transaction = sys::spi_transaction_t::default();
        transaction.length = tx.len() * 8;
        unsafe {
            transaction.__bindgen_anon_1.tx_buffer = tx.as_ptr() as *const _;
            transaction.__bindgen_anon_2.rx_buffer = rx.as_mut_ptr() as *mut _;
            esp_ok(sys::gpio_set_level(self.config.cs, 0))?;
            let ret = sys::spi_device_transmit(self.handle, &mut transaction);
            let cs_ret = sys::gpio_set_level(self.config.cs, 1);
            esp_ok(ret)?;
            esp_ok(cs_ret)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct WakePacket {
    pub data: Vec<u8>,
    pub rssi: i32,
    pub snr: f32,
}

pub fn prepare_deep_sleep_rx(config: &LoraConfig) -> Result<()> {
    let mut radio = Radio::open(config)?;
    radio.configure_radio()?;
    radio.start_rx()
}

pub fn read_wake_packet_no_reset(config: &LoraConfig) -> Result<Option<WakePacket>> {
    let mut radio = Radio::open_no_reset(config)?;
    Ok(radio.poll_packet()?.map(|packet| WakePacket {
        data: packet.data,
        rssi: packet.rssi,
        snr: packet.snr,
    }))
}

impl Drop for Sx127x {
    fn drop(&mut self) {
        unsafe {
            if !self.handle.is_null() {
                let _ = sys::spi_bus_remove_device(self.handle);
            }
            let _ = sys::spi_bus_free(self.host);
        }
    }
}

const SX126X_CMD_SET_SLEEP: u8 = 0x84;
const SX126X_CMD_SET_STANDBY: u8 = 0x80;
const SX126X_CMD_SET_TX: u8 = 0x83;
const SX126X_CMD_SET_RX: u8 = 0x82;
const SX126X_CMD_SET_PACKET_TYPE: u8 = 0x8a;
const SX126X_CMD_GET_PACKET_TYPE: u8 = 0x11;
const SX126X_CMD_SET_RF_FREQUENCY: u8 = 0x86;
const SX126X_CMD_SET_PA_CONFIG: u8 = 0x95;
const SX126X_CMD_SET_TX_PARAMS: u8 = 0x8e;
const SX126X_CMD_SET_BUFFER_BASE_ADDRESS: u8 = 0x8f;
const SX126X_CMD_SET_MODULATION_PARAMS: u8 = 0x8b;
const SX126X_CMD_SET_PACKET_PARAMS: u8 = 0x8c;
const SX126X_CMD_SET_DIO_IRQ_PARAMS: u8 = 0x08;
const SX126X_CMD_GET_IRQ_STATUS: u8 = 0x12;
const SX126X_CMD_CLEAR_IRQ_STATUS: u8 = 0x02;
const SX126X_CMD_SET_DIO2_AS_RF_SWITCH: u8 = 0x9d;
const SX126X_CMD_SET_DIO3_AS_TCXO_CTRL: u8 = 0x97;
const SX126X_CMD_GET_STATUS: u8 = 0xc0;
const SX126X_CMD_GET_RX_BUFFER_STATUS: u8 = 0x13;
const SX126X_CMD_GET_PACKET_STATUS: u8 = 0x14;
const SX126X_CMD_WRITE_BUFFER: u8 = 0x0e;
const SX126X_CMD_READ_BUFFER: u8 = 0x1e;

const SX126X_PACKET_TYPE_LORA: u8 = 0x01;
const SX126X_STANDBY_RC: u8 = 0x00;
const SX126X_RAMP_200_US: u8 = 0x04;
const SX126X_IRQ_TX_DONE: u16 = 0x0001;
const SX126X_IRQ_RX_DONE: u16 = 0x0002;
const SX126X_IRQ_CRC_ERR: u16 = 0x0040;
const SX126X_IRQ_TIMEOUT: u16 = 0x0200;

struct Sx1262 {
    config: LoraConfig,
    host: sys::spi_host_device_t,
    handle: sys::spi_device_handle_t,
}

impl Sx1262 {
    fn open(config: &LoraConfig) -> Result<Self> {
        Self::open_inner(config, true)
    }

    fn open_no_reset(config: &LoraConfig) -> Result<Self> {
        Self::open_inner(config, false)
    }

    fn open_inner(config: &LoraConfig, reset: bool) -> Result<Self> {
        validate_config(config)?;
        let host = spi_host(config.spi_host)?;
        unsafe {
            let _ = sys::spi_bus_free(host);
        }

        let mut bus = sys::spi_bus_config_t::default();
        bus.sclk_io_num = config.sck;
        bus.max_transfer_sz = 512;
        unsafe {
            bus.__bindgen_anon_1.mosi_io_num = config.mosi;
            bus.__bindgen_anon_2.miso_io_num = config.miso;
            bus.__bindgen_anon_3.quadwp_io_num = sys::gpio_num_t_GPIO_NUM_NC;
            bus.__bindgen_anon_4.quadhd_io_num = sys::gpio_num_t_GPIO_NUM_NC;
            esp_ok(sys::spi_bus_initialize(
                host,
                &bus,
                sys::spi_common_dma_t_SPI_DMA_DISABLED,
            ))?;
        }

        let mut dev = sys::spi_device_interface_config_t::default();
        dev.clock_speed_hz = 1_000_000;
        dev.mode = 0;
        dev.spics_io_num = sys::gpio_num_t_GPIO_NUM_NC;
        dev.queue_size = 1;

        let mut handle = std::ptr::null_mut();
        unsafe {
            esp_ok(sys::spi_bus_add_device(host, &dev, &mut handle))?;
            esp_ok(sys::gpio_set_direction(
                config.cs,
                sys::gpio_mode_t_GPIO_MODE_OUTPUT,
            ))?;
            esp_ok(sys::gpio_set_level(config.cs, 1))?;
            esp_ok(sys::gpio_set_direction(
                config.rst,
                sys::gpio_mode_t_GPIO_MODE_OUTPUT,
            ))?;
            esp_ok(sys::gpio_set_direction(
                config.dio0,
                sys::gpio_mode_t_GPIO_MODE_INPUT,
            ))?;
            esp_ok(sys::gpio_set_direction(
                config.busy,
                sys::gpio_mode_t_GPIO_MODE_INPUT,
            ))?;
        }

        let mut radio = Self {
            config: *config,
            host,
            handle,
        };
        if reset {
            radio.reset()?;
        }
        radio.set_standby()?;
        let status = radio.status()?;
        if status == 0x00 || status == 0xff {
            bail!("unexpected SX1262 status 0x{status:02x}");
        }
        Ok(radio)
    }

    fn reset(&mut self) -> Result<()> {
        unsafe {
            esp_ok(sys::gpio_set_level(self.config.rst, 0))?;
        }
        thread::sleep(Duration::from_millis(10));
        unsafe {
            esp_ok(sys::gpio_set_level(self.config.rst, 1))?;
        }
        thread::sleep(Duration::from_millis(20));
        self.wait_while_busy(Duration::from_millis(500))
    }

    fn configure_radio(&mut self) -> Result<()> {
        self.set_standby()?;
        self.command(SX126X_CMD_SET_DIO2_AS_RF_SWITCH, &[0x01])?;
        self.command(SX126X_CMD_SET_DIO3_AS_TCXO_CTRL, &[0x02, 0x00, 0x03, 0x20])?;
        thread::sleep(Duration::from_millis(5));
        self.command(SX126X_CMD_SET_PACKET_TYPE, &[SX126X_PACKET_TYPE_LORA])?;
        self.set_frequency(self.config.frequency_hz)?;
        self.command(SX126X_CMD_SET_PA_CONFIG, &[0x04, 0x07, 0x00, 0x01])?;
        self.command(
            SX126X_CMD_SET_TX_PARAMS,
            &[
                self.config.tx_power.clamp(-9, 22) as i8 as u8,
                SX126X_RAMP_200_US,
            ],
        )?;
        self.command(SX126X_CMD_SET_BUFFER_BASE_ADDRESS, &[0x00, 0x80])?;
        self.set_modulation_params()?;
        self.set_packet_params(255)?;
        self.set_irq_mask(
            SX126X_IRQ_TX_DONE | SX126X_IRQ_RX_DONE | SX126X_IRQ_CRC_ERR | SX126X_IRQ_TIMEOUT,
        )?;
        self.clear_irq(0xffff)?;
        Ok(())
    }

    fn set_standby(&mut self) -> Result<()> {
        self.command(SX126X_CMD_SET_STANDBY, &[SX126X_STANDBY_RC])
    }

    fn set_frequency(&mut self, hz: u32) -> Result<()> {
        let rf = ((hz as u64) << 25) / 32_000_000_u64;
        self.command(
            SX126X_CMD_SET_RF_FREQUENCY,
            &[
                (rf >> 24) as u8,
                (rf >> 16) as u8,
                (rf >> 8) as u8,
                rf as u8,
            ],
        )
    }

    fn set_modulation_params(&mut self) -> Result<()> {
        let bw = match self.config.bandwidth_hz {
            7_800 => 0x00,
            10_400 => 0x08,
            15_600 => 0x01,
            20_800 => 0x09,
            31_250 => 0x02,
            41_700 => 0x0a,
            62_500 => 0x03,
            125_000 => 0x04,
            250_000 => 0x05,
            500_000 => 0x06,
            hz => bail!("unsupported SX1262 LoRa bandwidth {hz}"),
        };
        let cr = (self.config.cr - 4).clamp(1, 4) as u8;
        let ldro = if symbol_time_ms(self.config.bandwidth_hz, self.config.sf) >= 16 {
            1
        } else {
            0
        };
        self.command(
            SX126X_CMD_SET_MODULATION_PARAMS,
            &[self.config.sf as u8, bw, cr, ldro],
        )
    }

    fn set_packet_params(&mut self, payload_len: u8) -> Result<()> {
        self.command(
            SX126X_CMD_SET_PACKET_PARAMS,
            &[
                (self.config.preamble >> 8) as u8,
                self.config.preamble as u8,
                0x00,
                payload_len,
                if self.config.crc { 0x01 } else { 0x00 },
                0x00,
            ],
        )
    }

    fn set_irq_mask(&mut self, mask: u16) -> Result<()> {
        let dio1 = mask;
        self.command(
            SX126X_CMD_SET_DIO_IRQ_PARAMS,
            &[
                (mask >> 8) as u8,
                mask as u8,
                (dio1 >> 8) as u8,
                dio1 as u8,
                0,
                0,
                0,
                0,
            ],
        )
    }

    fn send_packet(&mut self, payload: &[u8], timeout_ms: u32) -> Result<()> {
        if payload.len() > 255 {
            bail!("SX1262 payload too large: {}", payload.len());
        }
        self.set_standby()?;
        self.set_packet_params(payload.len() as u8)?;
        self.write_buffer(0, payload)?;
        self.clear_irq(0xffff)?;
        let timeout = sx126x_timeout(timeout_ms);
        self.command(
            SX126X_CMD_SET_TX,
            &[(timeout >> 16) as u8, (timeout >> 8) as u8, timeout as u8],
        )?;

        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        while Instant::now() < deadline {
            let irq = self.irq_status()?;
            if irq & SX126X_IRQ_TX_DONE != 0 {
                self.clear_irq(irq)?;
                self.set_standby()?;
                return Ok(());
            }
            if irq & SX126X_IRQ_TIMEOUT != 0 {
                self.clear_irq(irq)?;
                bail!("SX1262 TX timeout");
            }
            thread::sleep(Duration::from_millis(5));
        }
        bail!("SX1262 TX timeout");
    }

    fn start_rx(&mut self) -> Result<()> {
        self.set_standby()?;
        self.set_packet_params(255)?;
        self.clear_irq(0xffff)?;
        self.command(SX126X_CMD_SET_RX, &[0xff, 0xff, 0xff])
    }

    fn sleep(&mut self) -> Result<()> {
        self.command(SX126X_CMD_SET_SLEEP, &[0x00])
    }

    fn poll_packet(&mut self) -> Result<Option<Packet>> {
        let irq = self.irq_status()?;
        if irq & SX126X_IRQ_RX_DONE == 0 {
            return Ok(None);
        }
        self.clear_irq(irq)?;
        if irq & SX126X_IRQ_CRC_ERR != 0 {
            return Ok(None);
        }
        let (len, offset) = self.rx_buffer_status()?;
        let data = self.read_buffer(offset, len)?;
        let (rssi, snr) = self.packet_status()?;
        Ok(Some(Packet { data, rssi, snr }))
    }

    fn dump(&mut self) -> Result<String> {
        let status = self.status()?;
        let packet_type = self.read_u8(SX126X_CMD_GET_PACKET_TYPE)?;
        let irq = self.irq_status()?;
        Ok(format!(
            "chip=sx1262 status=0x{status:02x} packet_type=0x{packet_type:02x} irq=0x{irq:04x} busy={} dio1={}",
            self.config.busy, self.config.dio0
        ))
    }

    fn status(&mut self) -> Result<u8> {
        self.read_u8(SX126X_CMD_GET_STATUS)
    }

    fn irq_status(&mut self) -> Result<u16> {
        let data = self.read(SX126X_CMD_GET_IRQ_STATUS, &[], 2)?;
        Ok(((data[0] as u16) << 8) | data[1] as u16)
    }

    fn clear_irq(&mut self, mask: u16) -> Result<()> {
        self.command(
            SX126X_CMD_CLEAR_IRQ_STATUS,
            &[(mask >> 8) as u8, mask as u8],
        )
    }

    fn rx_buffer_status(&mut self) -> Result<(usize, u8)> {
        let data = self.read(SX126X_CMD_GET_RX_BUFFER_STATUS, &[], 2)?;
        Ok((data[0] as usize, data[1]))
    }

    fn packet_status(&mut self) -> Result<(i32, f32)> {
        let data = self.read(SX126X_CMD_GET_PACKET_STATUS, &[], 3)?;
        let rssi = -(data[0] as i32) / 2;
        let snr = (data[1] as i8) as f32 / 4.0;
        Ok((rssi, snr))
    }

    fn write_buffer(&mut self, offset: u8, payload: &[u8]) -> Result<()> {
        let mut data = Vec::with_capacity(payload.len() + 1);
        data.push(offset);
        data.extend_from_slice(payload);
        self.command(SX126X_CMD_WRITE_BUFFER, &data)
    }

    fn read_buffer(&mut self, offset: u8, len: usize) -> Result<Vec<u8>> {
        self.read(SX126X_CMD_READ_BUFFER, &[offset], len)
    }

    fn read_u8(&mut self, opcode: u8) -> Result<u8> {
        Ok(self.read(opcode, &[], 1)?[0])
    }

    fn command(&mut self, opcode: u8, data: &[u8]) -> Result<()> {
        self.wait_while_busy(Duration::from_millis(500))?;
        let mut tx = Vec::with_capacity(data.len() + 1);
        tx.push(opcode);
        tx.extend_from_slice(data);
        let mut rx = vec![0_u8; tx.len()];
        self.spi(&tx, &mut rx)?;
        self.wait_while_busy(Duration::from_millis(500))
    }

    fn read(&mut self, opcode: u8, args: &[u8], len: usize) -> Result<Vec<u8>> {
        self.wait_while_busy(Duration::from_millis(500))?;
        let mut tx = Vec::with_capacity(args.len() + len + 2);
        tx.push(opcode);
        tx.extend_from_slice(args);
        tx.push(0);
        tx.resize(args.len() + len + 2, 0);
        let mut rx = vec![0_u8; tx.len()];
        self.spi(&tx, &mut rx)?;
        self.wait_while_busy(Duration::from_millis(500))?;
        Ok(rx[(args.len() + 2)..].to_vec())
    }

    fn wait_while_busy(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let level = unsafe { sys::gpio_get_level(self.config.busy) };
            if level == 0 {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(1));
        }
        bail!("SX1262 busy timeout gpio={}", self.config.busy)
    }

    fn spi(&mut self, tx: &[u8], rx: &mut [u8]) -> Result<()> {
        if tx.len() != rx.len() {
            bail!("spi tx/rx length mismatch");
        }
        let mut transaction = sys::spi_transaction_t::default();
        transaction.length = tx.len() * 8;
        unsafe {
            transaction.__bindgen_anon_1.tx_buffer = tx.as_ptr() as *const _;
            transaction.__bindgen_anon_2.rx_buffer = rx.as_mut_ptr() as *mut _;
            esp_ok(sys::gpio_set_level(self.config.cs, 0))?;
            let ret = sys::spi_device_transmit(self.handle, &mut transaction);
            let cs_ret = sys::gpio_set_level(self.config.cs, 1);
            esp_ok(ret)?;
            esp_ok(cs_ret)?;
        }
        Ok(())
    }
}

impl Drop for Sx1262 {
    fn drop(&mut self) {
        unsafe {
            if !self.handle.is_null() {
                let _ = sys::spi_bus_remove_device(self.handle);
            }
            let _ = sys::spi_bus_free(self.host);
        }
    }
}

fn sx126x_timeout(timeout_ms: u32) -> u32 {
    let units = ((timeout_ms as u64) * 1000 / 15).clamp(1, 0x00ff_ffff);
    units as u32
}

fn symbol_time_ms(bw: u32, sf: i32) -> u32 {
    (((1_u32 << sf.clamp(6, 12)) as u64) * 1000 / bw.max(1) as u64) as u32
}

fn probe_lora(config: &LoraConfig) -> String {
    match probe_lora_ready(config) {
        Ok(value) => match config.chip {
            LoraChip::Sx127x => format!("ready(chip=sx127x,version=0x{value:02x})"),
            LoraChip::Sx1262 => format!("ready(chip=sx1262,status=0x{value:02x})"),
        },
        Err(err) => format!("err:{err}"),
    }
}

fn probe_lora_ready(config: &LoraConfig) -> Result<u8> {
    let _guard = lora_spi_lock().lock().unwrap();
    match Radio::open(config)? {
        Radio::Sx127x(mut radio) => {
            let version = radio.read_reg(REG_VERSION)?;
            if version == SX127X_VERSION {
                Ok(version)
            } else {
                bail!("unexpected SX127x version 0x{version:02x}")
            }
        }
        Radio::Sx1262(mut radio) => radio.status(),
    }
}

fn decode_registers(regs: &[u8; 0x50]) -> String {
    let op_mode = regs[REG_OP_MODE as usize];
    let frf = ((regs[REG_FRF_MSB as usize] as u32) << 16)
        | ((regs[REG_FRF_MID as usize] as u32) << 8)
        | regs[REG_FRF_LSB as usize] as u32;
    let freq_hz = ((frf as u64) * 32_000_000_u64 / (1_u64 << 19)) as u32;
    let modem_config_1 = regs[REG_MODEM_CONFIG_1 as usize];
    let modem_config_2 = regs[REG_MODEM_CONFIG_2 as usize];
    let modem_config_3 = regs[REG_MODEM_CONFIG_3 as usize];
    let bw = decode_bandwidth((modem_config_1 >> 4) & 0x0f);
    let cr = 4 + ((modem_config_1 >> 1) & 0x07);
    let implicit_header = modem_config_1 & 0x01 != 0;
    let sf = modem_config_2 >> 4;
    let crc = modem_config_2 & 0x04 != 0;
    let preamble =
        ((regs[REG_PREAMBLE_MSB as usize] as u16) << 8) | regs[REG_PREAMBLE_LSB as usize] as u16;
    let mode = match op_mode & 0x07 {
        MODE_SLEEP => "sleep",
        MODE_STDBY => "standby",
        MODE_TX => "tx",
        MODE_RX_CONTINUOUS => "rx_continuous",
        _ => "other",
    };
    format!(
        "version=0x{:02x} mode={} lora={} freq={} bw={} sf={} cr={} header={} crc={} preamble={} sync_word=0x{:02x} irq=0x{:02x} dio=0x{:02x} lna=0x{:02x} modem3=0x{:02x}",
        regs[REG_VERSION as usize],
        mode,
        op_mode & MODE_LONG_RANGE != 0,
        freq_hz,
        bw.map(|value| value.to_string()).unwrap_or_else(|| "unknown".to_string()),
        sf,
        cr,
        if implicit_header { "implicit" } else { "explicit" },
        crc,
        preamble,
        regs[REG_SYNC_WORD as usize],
        regs[REG_IRQ_FLAGS as usize],
        regs[REG_DIO_MAPPING_1 as usize],
        regs[REG_LNA as usize],
        modem_config_3
    )
}

fn decode_bandwidth(code: u8) -> Option<u32> {
    match code {
        0 => Some(7_800),
        1 => Some(10_400),
        2 => Some(15_600),
        3 => Some(20_800),
        4 => Some(31_250),
        5 => Some(41_700),
        6 => Some(62_500),
        7 => Some(125_000),
        8 => Some(250_000),
        9 => Some(500_000),
        _ => None,
    }
}

fn parse_payload(request: &CommandRequest) -> Result<Vec<u8>> {
    if let Some(data) = request.arg("data").or_else(|| request.arg("payload")) {
        return parse_bytes(data);
    }
    if let Some(text) = request.arg("text") {
        return Ok(text.as_bytes().to_vec());
    }
    if !request.payload.is_empty() {
        return Ok(request.payload.clone());
    }
    bail!("lorasend requires data=hex:... or text=...");
}

fn send_payload(
    settings: &SharedSettings,
    payload: &[u8],
    kind: FrameKind,
    hop_limit: Option<u8>,
    portnum: Option<u32>,
    timeout_ms: u32,
) -> Result<String> {
    let sender = meshtastic_sender_node()?;
    let packet_id = LORA_PACKET_COUNTER.fetch_add(1, Ordering::Relaxed);
    let channel = settings
        .borrow()
        .get_i32("lora.channel_hash", MESHTASTIC_DEFAULT_CHANNEL_HASH as i32)?
        .clamp(0, u8::MAX as i32) as u8;
    let portnum = match portnum {
        Some(portnum) => portnum,
        None => settings
            .borrow()
            .get_i32("lora.portnum", MESHTASTIC_DEFAULT_PORTNUM as i32)?
            .clamp(0, 511) as u32,
    };
    let hop_limit = match hop_limit {
        Some(hop_limit) => hop_limit.clamp(0, 7),
        None => settings
            .borrow()
            .get_i32("lora.hop_limit", MESHTASTIC_DEFAULT_HOP_LIMIT as i32)?
            .clamp(0, 7) as u8,
    };
    let packet = match kind {
        FrameKind::Meshtastic => encode_meshtastic_frame(
            &encode_meshtastic_data(portnum, payload)?,
            sender,
            packet_id,
            channel,
            hop_limit,
        )?,
        FrameKind::Raw => payload.to_vec(),
    };
    if packet.len() > 255 {
        bail!("LoRa payload too large: {}", packet.len());
    }
    let state = LoraState::load(settings)?;
    let _guard = lora_spi_lock().lock().unwrap();
    let mut radio = Radio::open(&state.config)?;
    radio.configure_radio()?;
    let background_rx = BACKGROUND_RX_RUNNING.load(Ordering::Relaxed);
    if background_rx {
        set_lora_irq_enabled(state.config.dio0, false)?;
    }
    let send_result = radio.send_packet(&packet, timeout_ms);
    if background_rx {
        let rx_result = radio.start_rx();
        let irq_result = set_lora_irq_enabled(state.config.dio0, true);
        send_result?;
        rx_result?;
        irq_result?;
    } else {
        send_result?;
    }
    telemetry::count_packet("lora", Direction::Tx, packet.len());
    telemetry::record_log(format!(
        "ev=lora.tx t=lora src={} dst={} n={} hop={} len={} data_len={} rf={}",
        format_meshtastic_node(sender),
        if kind == FrameKind::Meshtastic {
            format_meshtastic_node(super::frames::MESHTASTIC_BROADCAST)
        } else {
            "-".to_string()
        },
        packet_id,
        hop_limit,
        packet.len(),
        payload.len(),
        compact_rf(&state.config)
    ));
    Ok(format!(
        "lorasend src={} dst={} n={} hop={} len={} data_len={} rf={}{}",
        format_meshtastic_node(sender),
        if kind == FrameKind::Meshtastic {
            format_meshtastic_node(super::frames::MESHTASTIC_BROADCAST)
        } else {
            "-".to_string()
        },
        packet_id,
        hop_limit,
        packet.len(),
        payload.len(),
        compact_rf(&state.config),
        if kind == FrameKind::Raw { " f=raw" } else { "" }
    ))
}

fn compact_rf(config: &LoraConfig) -> String {
    format!(
        "{}/{}/{}/{}",
        compact_hz(config.frequency_hz, "M"),
        compact_hz(config.bandwidth_hz, "k"),
        config.sf,
        config.cr
    )
}

fn compact_hz(value: u32, suffix: &str) -> String {
    let divisor = if suffix == "M" { 1_000_000 } else { 1_000 };
    if value % divisor == 0 {
        format!("{}{}", value / divisor, suffix)
    } else {
        let scaled = value as f32 / divisor as f32;
        format!("{scaled:.3}{suffix}")
    }
}

fn compact_lora_detail(
    header: Option<super::frames::MeshtasticHeader>,
    dst: Option<&str>,
    rssi: i32,
    snr: f32,
) -> String {
    let (src, packet_id, hop_limit, hop_start) = header
        .map(|h| {
            (
                format_meshtastic_node(h.from),
                h.id.to_string(),
                h.hop_limit(),
                h.hop_start(),
            )
        })
        .unwrap_or_else(|| ("-".to_string(), "-".to_string(), 0, 0));
    format!(
        "src={} dst={} n={} rssi={} snr={} hl={} hs={}",
        src,
        dst.unwrap_or("-"),
        packet_id,
        rssi,
        snr,
        hop_limit,
        hop_start
    )
}

fn meshtastic_sender_node() -> Result<u32> {
    let mac = station_mac()?;
    Ok(u32::from_le_bytes([mac[2], mac[3], mac[4], mac[5]]))
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

fn parse_pin_list(value: Option<&str>, default: i32) -> Result<Vec<i32>> {
    let values = parse_i32_list(value, default)?;
    for pin in &values {
        validate_pin(*pin)?;
    }
    Ok(values)
}

fn parse_optional_pin_list(value: Option<&str>, default: i32) -> Result<Vec<i32>> {
    let values = parse_i32_list(value, default)?;
    for pin in &values {
        validate_optional_pin(*pin)?;
    }
    Ok(values)
}

fn parse_chip_list(value: Option<&str>, default: LoraChip) -> Result<Vec<LoraChip>> {
    match value {
        Some(value) => value
            .split(',')
            .map(|item| LoraChip::parse(item.trim()))
            .collect(),
        None => Ok(vec![default]),
    }
}

fn parse_i32_list(value: Option<&str>, default: i32) -> Result<Vec<i32>> {
    match value {
        Some(value) => value
            .split(',')
            .map(|item| parse_i32(item.trim()))
            .collect(),
        None => Ok(vec![default]),
    }
}

fn parse_arg_or(request: &CommandRequest, key: &str, default: i32) -> Result<i32> {
    request
        .arg(key)
        .map(parse_i32)
        .transpose()
        .map(|v| v.unwrap_or(default))
}

fn has_duplicate_pins(pins: &[i32]) -> bool {
    for (idx, pin) in pins.iter().enumerate() {
        if *pin < 0 {
            continue;
        }
        if pins[idx + 1..].contains(pin) {
            return true;
        }
    }
    false
}

fn spi_host(host: i32) -> Result<sys::spi_host_device_t> {
    match host {
        1 => Ok(sys::spi_host_device_t_SPI2_HOST),
        2 => Ok(sys::spi_host_device_t_SPI3_HOST),
        _ => bail!("invalid SPI host {host}; use 1=SPI2/HSPI or 2=SPI3/VSPI"),
    }
}

fn validate_config(config: &LoraConfig) -> Result<()> {
    spi_host(config.spi_host)?;
    for pin in [
        config.sck,
        config.miso,
        config.mosi,
        config.cs,
        config.rst,
        config.dio0,
    ] {
        validate_pin(pin)?;
    }
    validate_optional_pin(config.busy)?;
    if matches!(config.chip, LoraChip::Sx1262) && config.busy < 0 {
        bail!("SX1262 requires busy GPIO");
    }
    validate_sf(config.sf)?;
    validate_cr(config.cr)?;
    validate_bandwidth(config.bandwidth_hz)?;
    validate_u8(config.sync_word)?;
    validate_range("preamble", config.preamble, 6, 65535)?;
    validate_range("tx_power", config.tx_power, 2, 20)?;
    Ok(())
}

fn validate_pin(pin: i32) -> Result<()> {
    if !(0..=39).contains(&pin) {
        return Err(anyhow!("invalid ESP32 GPIO pin {pin}"));
    }
    Ok(())
}

fn validate_optional_pin(pin: i32) -> Result<()> {
    if pin == -1 {
        Ok(())
    } else {
        validate_pin(pin)
    }
}

fn validate_sf(sf: i32) -> Result<()> {
    validate_range("sf", sf, 6, 12)
}

fn validate_cr(cr: i32) -> Result<()> {
    validate_range("cr", cr, 5, 8)
}

fn validate_u8(value: i32) -> Result<()> {
    validate_range("u8", value, 0, 255)
}

fn validate_bandwidth(bw: u32) -> Result<()> {
    match bw {
        7_800 | 10_400 | 15_600 | 20_800 | 31_250 | 41_700 | 62_500 | 125_000 | 250_000
        | 500_000 => Ok(()),
        _ => bail!("unsupported LoRa bandwidth {bw}"),
    }
}

fn validate_range(name: &str, value: i32, min: i32, max: i32) -> Result<()> {
    if value < min || value > max {
        bail!("{name} must be in {min}..={max}, got {value}");
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
