use std::convert::TryInto;
use std::ffi::CString;

use anyhow::{anyhow, bail, Context, Result};
use embedded_svc::wifi::{
    AccessPointConfiguration, AuthMethod, ClientConfiguration, Configuration,
};
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::wifi::{BlockingWifi, EspWifi};
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::settings::{parse_bool, parse_i32};

pub fn register_commands(registry: &mut CommandRegistry) {
    registry.register(WifiCommand::default());
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum WifiMode {
    Stopped,
    Sta,
    Ap,
}

impl Default for WifiMode {
    fn default() -> Self {
        Self::Stopped
    }
}

type WifiDriver = BlockingWifi<EspWifi<'static>>;

#[derive(Default)]
struct WifiCommand {
    mode: WifiMode,
    ssid: Option<String>,
    psk: Option<String>,
    timeout_ms: u32,
    wifi: Option<WifiDriver>,
}

impl CommandHandler for WifiCommand {
    fn name(&self) -> &'static str {
        "wifi"
    }

    fn help(&self) -> &'static str {
        "wifi ssid=SSID psk=PSK timeout=MS | wifi ap=true ssid=SSID psk=PSK channel=6 | wifi scan=true | wifi stop=true | wifi time=true"
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if request.arg("stop").is_some() {
            self.stop()?;
            return Ok(CommandResponse::ok("wifi stopped"));
        }
        if request.arg("time").is_some() {
            start_sntp(request.arg("time").unwrap_or("pool.ntp.org"))?;
            return Ok(CommandResponse::ok("wifi sntp started"));
        }
        if request.arg("scan").is_some() {
            return self.scan();
        }

        if let Some(timeout) = request.arg_i32("timeout")? {
            self.timeout_ms = timeout.max(0) as u32;
        }
        if request
            .arg("ap")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            self.start_ap(request)
        } else if request.arg("ssid").is_some() {
            self.start_sta(request)
        } else {
            Ok(CommandResponse::ok(format!(
                "wifi mode={:?} ssid={} timeout_ms={}",
                self.mode,
                self.ssid.as_deref().unwrap_or(""),
                self.timeout_ms
            )))
        }
    }
}

impl WifiCommand {
    fn driver(&mut self) -> Result<&mut WifiDriver> {
        if self.wifi.is_none() {
            let peripherals = Peripherals::take()?;
            let sys_loop = EspSystemEventLoop::take()?;
            let wifi = EspWifi::new(peripherals.modem, sys_loop.clone(), None)?;
            self.wifi = Some(BlockingWifi::wrap(wifi, sys_loop)?);
        }
        Ok(self.wifi.as_mut().expect("wifi initialized"))
    }

    fn start_sta(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let ssid = request.arg("ssid").context("wifi sta requires ssid=...")?;
        let psk = request.arg("psk").unwrap_or("");
        validate_wifi_string("ssid", ssid, 32)?;
        validate_wifi_string("psk", psk, 64)?;
        self.ssid = Some(ssid.to_string());
        self.psk = Some(psk.to_string());

        let timeout_ms = self.timeout_ms;
        let wifi = self.driver()?;
        wifi.set_configuration(&Configuration::Client(ClientConfiguration {
            ssid: ssid.try_into().map_err(|_| anyhow!("ssid too long"))?,
            password: psk.try_into().map_err(|_| anyhow!("psk too long"))?,
            auth_method: if psk.is_empty() {
                AuthMethod::None
            } else {
                AuthMethod::WPA2Personal
            },
            ..Default::default()
        }))?;
        wifi.start()?;
        wifi.connect()?;
        if timeout_ms > 0 {
            let _ = wifi.wait_netif_up();
        }
        self.mode = WifiMode::Sta;
        Ok(CommandResponse::ok(format!(
            "wifi mode=Sta ssid={} timeout_ms={}",
            self.ssid.as_deref().unwrap_or(""),
            timeout_ms
        )))
    }

    fn start_ap(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let ssid = request.arg("ssid").unwrap_or("dmesh");
        let psk = request.arg("psk").unwrap_or("");
        let channel = request
            .arg("channel")
            .map(parse_i32)
            .transpose()?
            .unwrap_or(6)
            .clamp(1, 13) as u8;
        validate_wifi_string("ssid", ssid, 32)?;
        validate_wifi_string("psk", psk, 64)?;
        if !psk.is_empty() && psk.len() < 8 {
            bail!("AP psk must be empty or at least 8 bytes");
        }
        self.ssid = Some(ssid.to_string());
        self.psk = Some(psk.to_string());

        let wifi = self.driver()?;
        wifi.set_configuration(&Configuration::AccessPoint(AccessPointConfiguration {
            ssid: ssid.try_into().map_err(|_| anyhow!("ssid too long"))?,
            password: psk.try_into().map_err(|_| anyhow!("psk too long"))?,
            channel,
            auth_method: if psk.is_empty() {
                AuthMethod::None
            } else {
                AuthMethod::WPA2Personal
            },
            ..Default::default()
        }))?;
        wifi.start()?;
        self.mode = WifiMode::Ap;
        Ok(CommandResponse::ok(format!(
            "wifi mode=Ap ssid={} channel={}",
            self.ssid.as_deref().unwrap_or(""),
            channel
        )))
    }

    fn scan(&mut self) -> Result<CommandResponse> {
        let wifi = self.driver()?;
        wifi.set_configuration(&Configuration::Client(ClientConfiguration::default()))?;
        wifi.start()?;
        let aps = wifi.scan()?;
        let summary = aps
            .iter()
            .take(16)
            .map(|ap| format!("{}:{}:ch{}", ap.ssid, ap.signal_strength, ap.channel))
            .collect::<Vec<_>>()
            .join(",");
        Ok(CommandResponse::ok(format!(
            "wifi scan count={} {}",
            aps.len(),
            summary
        )))
    }

    fn stop(&mut self) -> Result<()> {
        if let Some(wifi) = self.wifi.as_mut() {
            let _ = wifi.disconnect();
            let _ = wifi.stop();
        }
        self.mode = WifiMode::Stopped;
        Ok(())
    }
}

fn start_sntp(server: &str) -> Result<()> {
    let server = if server == "true" || server.is_empty() {
        "pool.ntp.org"
    } else {
        server
    };
    let server = CString::new(server)?;
    unsafe {
        if sys::esp_sntp_enabled() {
            sys::esp_sntp_stop();
        }
        sys::esp_sntp_setoperatingmode(sys::esp_sntp_operatingmode_t_ESP_SNTP_OPMODE_POLL);
        sys::esp_sntp_setservername(0, server.as_ptr());
        sys::esp_sntp_init();
    }
    Ok(())
}

fn validate_wifi_string(name: &str, value: &str, max: usize) -> Result<()> {
    if value.len() > max {
        bail!("{name} must be at most {max} bytes");
    }
    Ok(())
}
