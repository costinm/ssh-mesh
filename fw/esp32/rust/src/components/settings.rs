use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use anyhow::{anyhow, Result};
use esp_idf_svc::nvs::{EspDefaultNvs, EspDefaultNvsPartition};

pub type SharedSettings = Rc<RefCell<Settings>>;

const NAMESPACE: &str = "dmesh";
const STRING_BUF_LEN: usize = 128;

pub fn open_shared() -> SharedSettings {
    Rc::new(RefCell::new(Settings::open()))
}

pub struct Settings {
    nvs: Option<EspDefaultNvs>,
    cache: BTreeMap<String, String>,
    known_keys: Vec<&'static str>,
}

impl Settings {
    pub fn open() -> Self {
        let nvs = EspDefaultNvsPartition::take()
            .and_then(|partition| EspDefaultNvs::new(partition, NAMESPACE, true))
            .map_err(|err| {
                log::warn!("NVS unavailable for settings, using volatile cache: {err}");
                err
            })
            .ok();

        Self {
            nvs,
            cache: BTreeMap::new(),
            known_keys: vec![
                "i2c.port",
                "i2c.sda",
                "i2c.scl",
                "i2c.freq",
                "lora.freq",
                "lora.beacon",
                "lora.bw",
                "lora.crc",
                "lora.preamble",
                "lora.spi_host",
                "lora.sck",
                "lora.miso",
                "lora.mosi",
                "lora.cs",
                "lora.rst",
                "lora.dio0",
                "lora.sf",
                "lora.cr",
                "lora.sync_word",
                "lora.tx_power",
            ],
        }
    }

    pub fn namespace(&self) -> &'static str {
        NAMESPACE
    }

    pub fn known_keys(&self) -> &[&'static str] {
        &self.known_keys
    }

    pub fn get_str(&self, key: &str) -> Result<Option<String>> {
        if let Some(value) = self.cache.get(key) {
            return Ok(Some(value.clone()));
        }

        if let Some(nvs) = &self.nvs {
            let mut buf = [0_u8; STRING_BUF_LEN];
            if let Some(value) = nvs.get_str(key, &mut buf)? {
                return Ok(Some(value.to_string()));
            }
        }

        Ok(None)
    }

    pub fn set_str(&mut self, key: &str, value: &str) -> Result<()> {
        validate_key(key)?;
        validate_value(value)?;
        if let Some(nvs) = &mut self.nvs {
            nvs.set_str(key, value)?;
        }
        self.cache.insert(key.to_string(), value.to_string());
        Ok(())
    }

    pub fn get_i32(&self, key: &str, default: i32) -> Result<i32> {
        match self.get_str(key)? {
            Some(value) => parse_i32(&value),
            None => Ok(default),
        }
    }

    pub fn set_i32(&mut self, key: &str, value: i32) -> Result<()> {
        self.set_str(key, &value.to_string())
    }

    pub fn get_bool(&self, key: &str, default: bool) -> Result<bool> {
        match self.get_str(key)? {
            Some(value) => parse_bool(&value),
            None => Ok(default),
        }
    }

    pub fn set_bool(&mut self, key: &str, value: bool) -> Result<()> {
        self.set_str(key, if value { "true" } else { "false" })
    }
}

pub fn parse_i32(value: &str) -> Result<i32> {
    if let Some(hex) = value.strip_prefix("0x") {
        i32::from_str_radix(hex, 16).map_err(|err| anyhow!("invalid hex integer {value}: {err}"))
    } else {
        value
            .parse::<i32>()
            .map_err(|err| anyhow!("invalid integer {value}: {err}"))
    }
}

pub fn parse_bool(value: &str) -> Result<bool> {
    match value {
        "1" | "true" | "on" | "yes" => Ok(true),
        "0" | "false" | "off" | "no" => Ok(false),
        _ => Err(anyhow!("invalid boolean {value}")),
    }
}

fn validate_key(key: &str) -> Result<()> {
    if key.is_empty() || key.len() > 15 {
        return Err(anyhow!("NVS key must be 1..15 bytes"));
    }
    if !key
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'_')
    {
        return Err(anyhow!("NVS key contains unsupported characters"));
    }
    Ok(())
}

fn validate_value(value: &str) -> Result<()> {
    if value.len() >= STRING_BUF_LEN {
        return Err(anyhow!("setting value is too long"));
    }
    Ok(())
}
