use std::ffi::CString;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::settings::{parse_bool, SharedSettings};
use super::telemetry;

const DEFAULT_BUTTON_GPIO: i32 = 0;
const BUTTON_DEBOUNCE_MS: u64 = 250;

static BUTTON_ENABLED: AtomicBool = AtomicBool::new(false);
static BUTTON_GPIO: AtomicI32 = AtomicI32::new(DEFAULT_BUTTON_GPIO);
static BUTTON_PRESSES: AtomicU32 = AtomicU32::new(0);
static BUTTON_TASK: AtomicPtr<sys::tskTaskControlBlock> = AtomicPtr::new(std::ptr::null_mut());
static GPIO_ISR_SERVICE_READY: AtomicBool = AtomicBool::new(false);

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    if let Err(err) = init_from_settings(&settings) {
        telemetry::record_log(format!(
            "ev=button.err op=init err={}",
            crate::commands::protocol::escape_value(&err.to_string())
        ));
    }
    registry.register(ButtonCommand { settings });
}

pub fn configure_light_wake(settings: &SharedSettings) -> Result<Option<i32>> {
    let pin = settings
        .borrow()
        .get_i32("button.gpio", DEFAULT_BUTTON_GPIO)?
        .clamp(0, 39);
    unsafe {
        esp_ok(sys::gpio_wakeup_enable(
            pin as sys::gpio_num_t,
            sys::gpio_int_type_t_GPIO_INTR_LOW_LEVEL,
        ))?;
        esp_ok(sys::esp_sleep_enable_gpio_wakeup())?;
    }
    Ok(Some(pin))
}

fn init_from_settings(settings: &SharedSettings) -> Result<()> {
    let settings = settings.borrow();
    let enabled = settings.get_bool("button.enabled", true)?;
    let pin = settings
        .get_i32("button.gpio", DEFAULT_BUTTON_GPIO)?
        .clamp(0, 39);
    drop(settings);
    if enabled {
        configure_button(pin)?;
    }
    BUTTON_ENABLED.store(enabled, Ordering::Relaxed);
    BUTTON_GPIO.store(pin, Ordering::Relaxed);
    Ok(())
}

fn configure_button(pin: i32) -> Result<()> {
    start_button_task()?;
    unsafe {
        let config = sys::gpio_config_t {
            pin_bit_mask: 1_u64 << pin,
            mode: sys::gpio_mode_t_GPIO_MODE_INPUT,
            pull_up_en: sys::gpio_pullup_t_GPIO_PULLUP_ENABLE,
            pull_down_en: sys::gpio_pulldown_t_GPIO_PULLDOWN_DISABLE,
            intr_type: sys::gpio_int_type_t_GPIO_INTR_NEGEDGE,
        };
        esp_ok(sys::gpio_config(&config))?;
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
            sys::gpio_int_type_t_GPIO_INTR_NEGEDGE,
        ))?;
        esp_ok(sys::gpio_isr_handler_add(
            pin,
            Some(button_isr),
            std::ptr::null_mut(),
        ))?;
    }
    Ok(())
}

fn start_button_task() -> Result<()> {
    if !BUTTON_TASK.load(Ordering::SeqCst).is_null() {
        return Ok(());
    }
    let name = CString::new("button")?;
    let mut task = std::ptr::null_mut();
    let ret = unsafe {
        sys::xTaskCreatePinnedToCore(
            Some(button_task),
            name.as_ptr(),
            3072,
            std::ptr::null_mut(),
            5,
            &mut task,
            0,
        )
    };
    if ret != 1 || task.is_null() {
        bail!("button task create failed ret={ret}");
    }
    BUTTON_TASK.store(task, Ordering::SeqCst);
    Ok(())
}

unsafe extern "C" fn button_isr(_arg: *mut core::ffi::c_void) {
    let task = BUTTON_TASK.load(Ordering::SeqCst);
    if !task.is_null() {
        let mut woken = 0;
        unsafe {
            let _ = sys::xTaskGenericNotifyFromISR(
                task,
                0,
                1,
                sys::eNotifyAction_eIncrement,
                std::ptr::null_mut(),
                &mut woken,
            );
        }
    }
}

unsafe extern "C" fn button_task(_arg: *mut core::ffi::c_void) {
    let mut last = Instant::now() - Duration::from_millis(BUTTON_DEBOUNCE_MS);
    loop {
        let count = unsafe { sys::ulTaskGenericNotifyTake(0, 1, sys::TickType_t::MAX) };
        if count == 0 || last.elapsed() < Duration::from_millis(BUTTON_DEBOUNCE_MS) {
            continue;
        }
        last = Instant::now();
        let total = BUTTON_PRESSES.fetch_add(1, Ordering::Relaxed) + 1;
        let pin = BUTTON_GPIO.load(Ordering::Relaxed);
        let line = format!("ev=button.press gpio={} n={}", pin, total);
        telemetry::record_log(line.clone());
        telemetry::emit_console(&line);
    }
}

struct ButtonCommand {
    settings: SharedSettings,
}

impl CommandHandler for ButtonCommand {
    fn name(&self) -> &'static str {
        "button"
    }

    fn help(&self) -> &'static str {
        "button status=true | button gpio=0 enabled=true save=true"
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if let Some(enabled) = request.arg("enabled").or_else(|| request.arg("enable")) {
            BUTTON_ENABLED.store(parse_bool(enabled)?, Ordering::Relaxed);
        }
        if let Some(gpio) = request.arg_i32("gpio")? {
            BUTTON_GPIO.store(gpio.clamp(0, 39), Ordering::Relaxed);
        }
        let enabled = BUTTON_ENABLED.load(Ordering::Relaxed);
        let pin = BUTTON_GPIO.load(Ordering::Relaxed);
        if request
            .arg("save")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            let mut settings = self.settings.borrow_mut();
            settings.set_bool("button.enabled", enabled)?;
            settings.set_i32("button.gpio", pin)?;
        }
        if enabled {
            configure_button(pin)?;
        }
        Ok(CommandResponse::ok(format!(
            "button enabled={} gpio={} presses={}",
            enabled,
            pin,
            BUTTON_PRESSES.load(Ordering::Relaxed)
        )))
    }
}

fn esp_ok(ret: sys::esp_err_t) -> Result<()> {
    if ret == sys::ESP_OK {
        Ok(())
    } else {
        bail!("esp_err=0x{ret:x}")
    }
}
