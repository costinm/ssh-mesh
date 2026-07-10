use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::l3dmesh::{Frame, Transport};
use super::settings::{parse_bool, parse_i32, SharedSettings};

const DEFAULT_FREQUENCY_HZ: u32 = 915_000_000;
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

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    registry.register(LoraCommand::new("lora", settings.clone()));
    registry.register(LoraCommand::new("loraprobe", settings.clone()));
    registry.register(LoraCommand::new("lorasend", settings.clone()));
    registry.register(LoraCommand::new("loralisten", settings.clone()));
    registry.register(LoraCommand::new("loradump", settings));
}

pub fn transport(settings: SharedSettings) -> LoraTransport {
    LoraTransport::new(settings)
}

#[derive(Clone, Debug)]
struct LoraConfig {
    frequency_hz: u32,
    bandwidth_hz: u32,
    beacon: bool,
    spi_host: i32,
    sck: i32,
    miso: i32,
    mosi: i32,
    cs: i32,
    rst: i32,
    dio0: i32,
    sf: i32,
    cr: i32,
    sync_word: i32,
    crc: bool,
    preamble: i32,
    tx_power: i32,
}

impl Default for LoraConfig {
    fn default() -> Self {
        Self {
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
            sf: 10,
            cr: 5,
            sync_word: 0x34,
            crc: true,
            preamble: 8,
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

impl CommandHandler for LoraCommand {
    fn name(&self) -> &'static str {
        self.name
    }

    fn help(&self) -> &'static str {
        "lora preset=medium_fast|medium_slow freq=915000000 bw=250000 sf=7 cr=5 sync_word=0x34 | loraprobe | lorasend data=hex:... | loralisten ms=5000"
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
        if let Some(preset) = request.arg("preset") {
            let preset = LoraPreset::parse(preset)?;
            let mut settings = self.settings.borrow_mut();
            settings.set_i32("lora.bw", preset.bandwidth_hz as i32)?;
            settings.set_i32("lora.sf", preset.sf)?;
            settings.set_i32("lora.cr", preset.cr)?;
            settings.set_bool("lora.crc", true)?;
            settings.set_i32("lora.preamble", 8)?;
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
            let mut radio = Sx127x::open(&state.config)?;
            radio.configure_radio()?;
        }
        Ok(CommandResponse::ok(format!(
            "lora freq={} bw={} sf={} cr={} sync_word=0x{:02x} crc={} preamble={} tx_power={} spi_host={} sck={} miso={} mosi={} cs={} rst={} dio0={}",
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
            state.config.dio0
        )))
    }

    fn probe(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let state = LoraState::load(&self.settings)?;
        let host_candidates = parse_i32_list(request.arg("spi_host"), state.config.spi_host)?;
        let sck_candidates = parse_pin_list(request.arg("sck"), state.config.sck)?;
        let miso_candidates = parse_pin_list(request.arg("miso"), state.config.miso)?;
        let mosi_candidates = parse_pin_list(request.arg("mosi"), state.config.mosi)?;
        let cs_candidates = parse_pin_list(request.arg("cs"), state.config.cs)?;
        let rst_candidates = parse_pin_list(request.arg("rst"), state.config.rst)?;
        let dio0_candidates = parse_pin_list(request.arg("dio0"), state.config.dio0)?;

        let save = request
            .arg("save")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false);
        let mut attempts = Vec::new();

        for host in &host_candidates {
            for sck in &sck_candidates {
                for miso in &miso_candidates {
                    for mosi in &mosi_candidates {
                        for cs in &cs_candidates {
                            for rst in &rst_candidates {
                                for dio0 in &dio0_candidates {
                                    if has_duplicate_pins(&[*sck, *miso, *mosi, *cs, *rst, *dio0]) {
                                        continue;
                                    }
                                    let mut config = state.config.clone();
                                    config.spi_host = *host;
                                    config.sck = *sck;
                                    config.miso = *miso;
                                    config.mosi = *mosi;
                                    config.cs = *cs;
                                    config.rst = *rst;
                                    config.dio0 = *dio0;
                                    let result = probe_lora(&config);
                                    attempts.push(format!(
                                        "host={host},sck={sck},miso={miso},mosi={mosi},cs={cs},rst={rst},dio0={dio0}:{result}"
                                    ));
                                    if result.starts_with("ready") && save {
                                        let mut settings = self.settings.borrow_mut();
                                        settings.set_i32("lora.spi_host", *host)?;
                                        settings.set_i32("lora.sck", *sck)?;
                                        settings.set_i32("lora.miso", *miso)?;
                                        settings.set_i32("lora.mosi", *mosi)?;
                                        settings.set_i32("lora.cs", *cs)?;
                                        settings.set_i32("lora.rst", *rst)?;
                                        settings.set_i32("lora.dio0", *dio0)?;
                                        return Ok(CommandResponse::ok(format!(
                                            "loraprobe matched host={host} sck={sck} miso={miso} mosi={mosi} cs={cs} rst={rst} dio0={dio0} saved=true"
                                        )));
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
        if payload.len() > 255 {
            bail!("LoRa payload too large: {}", payload.len());
        }
        let timeout_ms = parse_arg_or(request, "timeout", 2000)? as u32;
        let state = LoraState::load(&self.settings)?;
        let mut radio = Sx127x::open(&state.config)?;
        radio.configure_radio()?;
        radio.send_packet(&payload, timeout_ms)?;
        Ok(CommandResponse::ok(format!(
            "lorasend bytes={} freq={} bw={} sf={} cr={}",
            payload.len(),
            state.config.frequency_hz,
            state.config.bandwidth_hz,
            state.config.sf,
            state.config.cr
        )))
    }

    fn listen(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let ms = parse_arg_or(request, "ms", 5000)?.max(1) as u32;
        let max_packets = parse_arg_or(request, "count", 4)?.clamp(1, 16) as usize;
        let state = LoraState::load(&self.settings)?;
        let mut radio = Sx127x::open(&state.config)?;
        radio.configure_radio()?;
        radio.start_rx()?;

        let deadline = Instant::now() + Duration::from_millis(ms as u64);
        let mut packets = Vec::new();
        while Instant::now() < deadline && packets.len() < max_packets {
            if let Some(packet) = radio.poll_packet()? {
                packets.push(format!(
                    "len={} rssi={} snr={} data={}",
                    packet.data.len(),
                    packet.rssi,
                    packet.snr,
                    hex_bytes(&packet.data)
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(CommandResponse::ok(format!(
            "loralisten packets={} {}",
            packets.len(),
            packets.join(" | ")
        )))
    }

    fn dump(&mut self, _request: &CommandRequest) -> Result<CommandResponse> {
        let state = LoraState::load(&self.settings)?;
        let mut radio = Sx127x::open(&state.config)?;
        let mut regs = Vec::new();
        for reg in 0x00_u8..=0x4f {
            regs.push(format!("{reg:02x}:{:02x}", radio.read_reg(reg)?));
        }
        Ok(CommandResponse::ok(format!("loradump {}", regs.join(" "))))
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
                sf: 7,
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

struct Sx127x {
    config: LoraConfig,
    host: sys::spi_host_device_t,
    handle: sys::spi_device_handle_t,
}

impl Sx127x {
    fn open(config: &LoraConfig) -> Result<Self> {
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
        radio.reset()?;
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

fn probe_lora(config: &LoraConfig) -> String {
    match Sx127x::open(config) {
        Ok(mut radio) => match radio.read_reg(REG_VERSION) {
            Ok(version) => format!("ready(version=0x{version:02x})"),
            Err(err) => format!("err:{err}"),
        },
        Err(err) => format!("err:{err}"),
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

fn parse_pin_list(value: Option<&str>, default: i32) -> Result<Vec<i32>> {
    let values = parse_i32_list(value, default)?;
    for pin in &values {
        validate_pin(*pin)?;
    }
    Ok(values)
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

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn has_duplicate_pins(pins: &[i32]) -> bool {
    for (idx, pin) in pins.iter().enumerate() {
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
