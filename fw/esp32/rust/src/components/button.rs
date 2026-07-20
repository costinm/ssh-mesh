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
const BUTTON_LONG_PRESS_MS: u32 = 2_500;
const BUTTON_DOUBLE_CLICK_MS: u32 = 500;
const BUTTON_CLASSIFY_MAX_MS: u32 = 3_500;
const BUTTON_CLASSIFY_SAMPLE_MS: u64 = 25;
#[allow(dead_code)]
const BOOT_SAMPLE_MS: u64 = 100;

static BUTTON_ENABLED: AtomicBool = AtomicBool::new(false);
static BUTTON_GPIO: AtomicI32 = AtomicI32::new(DEFAULT_BUTTON_GPIO);
static BUTTON_PRESSES: AtomicU32 = AtomicU32::new(0);
static BUTTON_SYNC_PENDING: AtomicU32 = AtomicU32::new(0);
static BUTTON_LEVEL_HELD: AtomicBool = AtomicBool::new(false);
static BUTTON_LEVEL_LONG_REPORTED: AtomicBool = AtomicBool::new(false);
static BUTTON_LEVEL_START_MS: AtomicU32 = AtomicU32::new(0);
static BUTTON_LONG_PENDING: AtomicU32 = AtomicU32::new(0);
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

pub fn take_sync_requests() -> u32 {
    BUTTON_SYNC_PENDING.swap(0, Ordering::Relaxed)
}

pub fn take_long_presses() -> u32 {
    BUTTON_LONG_PENDING.swap(0, Ordering::Relaxed)
}

pub fn configured_gpio() -> Option<i32> {
    if BUTTON_ENABLED.load(Ordering::Relaxed) {
        Some(BUTTON_GPIO.load(Ordering::Relaxed))
    } else {
        None
    }
}

pub fn is_pressed() -> bool {
    if !BUTTON_ENABLED.load(Ordering::Relaxed) {
        return false;
    }
    let pin = BUTTON_GPIO.load(Ordering::Relaxed);
    unsafe { sys::gpio_get_level(pin as sys::gpio_num_t) == 0 }
}

pub fn suppress_until_release() {
    BUTTON_LEVEL_HELD.store(true, Ordering::Relaxed);
    BUTTON_LEVEL_LONG_REPORTED.store(true, Ordering::Relaxed);
    BUTTON_LEVEL_START_MS.store(now_ms(), Ordering::Relaxed);
}

#[allow(dead_code)]
pub fn detect_boot_long_press(window_ms: u32, hold_ms: u32) -> bool {
    if !BUTTON_ENABLED.load(Ordering::Relaxed) {
        return false;
    }
    let pin = BUTTON_GPIO.load(Ordering::Relaxed);
    let deadline = Instant::now() + Duration::from_millis(window_ms as u64);
    let mut pressed_since: Option<Instant> = None;
    while Instant::now() < deadline {
        let pressed = unsafe { sys::gpio_get_level(pin as sys::gpio_num_t) == 0 };
        if pressed {
            let start = *pressed_since.get_or_insert_with(Instant::now);
            if start.elapsed() >= Duration::from_millis(hold_ms as u64) {
                telemetry::record_log(format!(
                    "ev=button.boot_long gpio={} hold_ms={}",
                    pin, hold_ms
                ));
                return true;
            }
        } else {
            pressed_since = None;
        }
        task_delay(Duration::from_millis(BOOT_SAMPLE_MS));
    }
    false
}

#[allow(dead_code)]
fn task_delay(timeout: Duration) {
    unsafe {
        sys::vTaskDelay(duration_to_ticks(timeout).max(1));
    }
}

#[allow(dead_code)]
fn duration_to_ticks(timeout: Duration) -> sys::TickType_t {
    let hz = sys::configTICK_RATE_HZ as u128;
    let ticks = timeout.as_millis().saturating_mul(hz).div_ceil(1000);
    ticks.min(sys::TickType_t::MAX as u128) as sys::TickType_t
}

#[allow(dead_code)]
pub fn poll_level_press() {
    if !BUTTON_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let pin = BUTTON_GPIO.load(Ordering::Relaxed);
    let pressed = unsafe { sys::gpio_get_level(pin as sys::gpio_num_t) == 0 };
    let now = now_ms();
    if pressed {
        if !BUTTON_LEVEL_HELD.swap(true, Ordering::Relaxed) {
            BUTTON_LEVEL_START_MS.store(now, Ordering::Relaxed);
            BUTTON_LEVEL_LONG_REPORTED.store(false, Ordering::Relaxed);
            super::ble_bt::open_companion_active_window(10_000);
            telemetry::record_log(format!("ev=button.down gpio={} source=level", pin));
            record_button_press("short", false);
        } else {
            let start = BUTTON_LEVEL_START_MS.load(Ordering::Relaxed);
            let elapsed = now.wrapping_sub(start);
            if elapsed >= BUTTON_LONG_PRESS_MS
                && !BUTTON_LEVEL_LONG_REPORTED.swap(true, Ordering::Relaxed)
            {
                record_button_press("long", true);
            }
        }
    } else {
        BUTTON_LEVEL_HELD.swap(false, Ordering::Relaxed);
        BUTTON_LEVEL_HELD.store(false, Ordering::Relaxed);
        BUTTON_LEVEL_LONG_REPORTED.store(false, Ordering::Relaxed);
    }
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
    unsafe {
        let config = sys::gpio_config_t {
            pin_bit_mask: 1_u64 << pin,
            mode: sys::gpio_mode_t_GPIO_MODE_INPUT,
            pull_up_en: sys::gpio_pullup_t_GPIO_PULLUP_ENABLE,
            pull_down_en: sys::gpio_pulldown_t_GPIO_PULLDOWN_DISABLE,
            intr_type: sys::gpio_int_type_t_GPIO_INTR_NEGEDGE,
        };
        esp_ok(sys::gpio_config(&config))?;
        let _ = sys::gpio_isr_handler_remove(pin);
        let _ = sys::gpio_intr_disable(pin as sys::gpio_num_t);
        if !GPIO_ISR_SERVICE_READY.load(Ordering::SeqCst) {
            let ret = sys::gpio_install_isr_service(0);
            if ret == sys::ESP_OK || ret == sys::ESP_ERR_INVALID_STATE {
                GPIO_ISR_SERVICE_READY.store(true, Ordering::SeqCst);
            } else {
                esp_ok(ret)?;
            }
        }
    }
    start_button_task()?;
    unsafe {
        esp_ok(sys::gpio_isr_handler_add(
            pin as sys::gpio_num_t,
            Some(button_isr),
            std::ptr::null_mut(),
        ))?;
        esp_ok(sys::gpio_wakeup_enable(
            pin as sys::gpio_num_t,
            sys::gpio_int_type_t_GPIO_INTR_LOW_LEVEL,
        ))?;
        esp_ok(sys::esp_sleep_enable_gpio_wakeup())?;
        esp_ok(sys::gpio_intr_enable(pin as sys::gpio_num_t))?;
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
    let pin = BUTTON_GPIO.load(Ordering::SeqCst);
    unsafe {
        let _ = sys::gpio_intr_disable(pin as sys::gpio_num_t);
    }
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
            reenable_button_interrupt();
            continue;
        }
        last = Instant::now();
        // Automatic light sleep may dispatch the GPIO edge before its clock
        // restore path has fully unwound. Acquiring PM locks immediately can
        // deadlock that transition and trip the interrupt watchdog.
        task_delay(Duration::from_millis(20));
        super::serial::rearm_after_wake();
        telemetry::record_log("ev=button.edge source=isr".to_string());
        telemetry::record_log("event type=uart.wake source=button".to_string());
        telemetry::emit_console("event type=uart.wake source=button");
        super::wake::notify();
        classify_button_press();
        reenable_button_interrupt();
    }
}

fn record_button_press(source: &str, long_press: bool) {
    let total = BUTTON_PRESSES.fetch_add(1, Ordering::Relaxed) + 1;
    let pin = BUTTON_GPIO.load(Ordering::Relaxed);
    let line = format!("ev=button.press gpio={} n={} source={}", pin, total, source);
    telemetry::record_log(line.clone());
    telemetry::emit_console(&line);
    super::ble_bt::open_companion_active_window(10_000);
    if long_press {
        BUTTON_LONG_PENDING.fetch_add(1, Ordering::Relaxed);
        BUTTON_SYNC_PENDING.fetch_add(1, Ordering::Relaxed);
        let line = "ev=button.long action=sync".to_string();
        telemetry::record_log(line.clone());
        telemetry::emit_console(&line);
    } else {
        // A short PRG press is the physical equivalent of a console/DTR wake.
        // Keep it side-effect free so it is safe as a recovery action.
        let line = "ev=button.short action=console".to_string();
        telemetry::record_log(line.clone());
        telemetry::emit_console(&line);
    }
    super::wake::notify();
}

fn record_button_double() {
    let total = BUTTON_PRESSES.fetch_add(1, Ordering::Relaxed) + 1;
    let pin = BUTTON_GPIO.load(Ordering::Relaxed);
    let line = format!("ev=button.press gpio={} n={} source=double", pin, total);
    telemetry::record_log(line.clone());
    telemetry::emit_console(&line);
    super::ble_bt::open_companion_active_window(10_000);
    BUTTON_SYNC_PENDING.fetch_add(1, Ordering::Relaxed);
    let line = "ev=button.double action=sync".to_string();
    telemetry::record_log(line.clone());
    telemetry::emit_console(&line);
    super::wake::notify();
}

fn classify_button_press() {
    let start = now_ms();
    let mut press_start: Option<u32> = None;
    let mut clicks = 0_u32;
    let mut release_deadline = start.wrapping_add(BUTTON_CLASSIFY_MAX_MS);
    loop {
        let now = now_ms();
        let pressed = is_pressed();
        if pressed {
            if press_start.is_none() {
                press_start = Some(now);
            }
            let held_ms = now.wrapping_sub(press_start.unwrap_or(now));
            if held_ms >= BUTTON_LONG_PRESS_MS {
                record_button_press("long", true);
                wait_for_release();
                return;
            }
        } else if let Some(down_at) = press_start.take() {
            let held_ms = now.wrapping_sub(down_at);
            if held_ms >= BUTTON_LONG_PRESS_MS {
                record_button_press("long", true);
                return;
            }
            clicks = clicks.saturating_add(1);
            if clicks >= 2 {
                record_button_double();
                return;
            }
            release_deadline = now.wrapping_add(BUTTON_DOUBLE_CLICK_MS);
        } else if clicks == 1 && release_deadline.wrapping_sub(now) >= i32::MAX as u32 {
            record_button_press("short", false);
            return;
        }
        if now.wrapping_sub(start) >= BUTTON_CLASSIFY_MAX_MS {
            if clicks == 1 {
                record_button_press("short", false);
            }
            return;
        }
        task_delay(Duration::from_millis(BUTTON_CLASSIFY_SAMPLE_MS));
    }
}

fn wait_for_release() {
    while is_pressed() {
        task_delay(Duration::from_millis(BUTTON_CLASSIFY_SAMPLE_MS));
    }
}

fn reenable_button_interrupt() {
    if !BUTTON_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let pin = BUTTON_GPIO.load(Ordering::Relaxed);
    unsafe {
        let _ = sys::gpio_intr_enable(pin as sys::gpio_num_t);
    }
}

fn now_ms() -> u32 {
    (unsafe { sys::esp_timer_get_time() } / 1000) as u32
}

struct ButtonCommand {
    settings: SharedSettings,
}

impl CommandHandler for ButtonCommand {
    fn name(&self) -> &'static str {
        "button"
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
