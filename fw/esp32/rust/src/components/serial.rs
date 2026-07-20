use std::ffi::c_char;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};

use esp_idf_sys as sys;

use super::settings::SharedSettings;

/// Keep the debug transport usable long enough to issue a command after it wakes.
///
/// ESP UART light-sleep wake can consume the first received byte(s), so callers that
/// wake the port should send a blank line before their actual command.
pub const DEFAULT_ACTIVE_MS: u32 = 20_000;
const MIN_ACTIVE_MS: u32 = 20_000;
#[cfg(target_feature = "esp32s3ops")]
const UART_REQUIRES_APB_LOCK: bool = false;
#[cfg(not(target_feature = "esp32s3ops"))]
const UART_REQUIRES_APB_LOCK: bool = true;

static UART0_APB_LOCK: AtomicPtr<sys::esp_pm_lock> = AtomicPtr::new(core::ptr::null_mut());
static UART0_APB_LOCK_HELD: AtomicBool = AtomicBool::new(false);
static UART0_NO_LIGHT_SLEEP_LOCK: AtomicPtr<sys::esp_pm_lock> =
    AtomicPtr::new(core::ptr::null_mut());
static UART0_NO_LIGHT_SLEEP_LOCK_HELD: AtomicBool = AtomicBool::new(false);
static UART0_ACTIVE_UNTIL_MS: AtomicU32 = AtomicU32::new(0);
static UART0_ACTIVE_WINDOW_MS: AtomicU32 = AtomicU32::new(DEFAULT_ACTIVE_MS);
static UART0_DEBUG_ENABLED: AtomicBool = AtomicBool::new(true);
static UART0_SUSPENDED_UNTIL_DTR: AtomicBool = AtomicBool::new(false);
static UART0_SUSPEND_AFTER_RESPONSE: AtomicBool = AtomicBool::new(false);
static UART0_UNINSTALL_AFTER_RESPONSE: AtomicBool = AtomicBool::new(false);
static UART0_DRIVER_INSTALLED: AtomicBool = AtomicBool::new(true);

/// Remove the UART0 driver for a one-boot power measurement.
///
/// This is intentionally one-way: reset reinstates the normal boot console.
/// The deletion is deferred so the command acknowledgement can leave UART0.
pub fn request_uninstall_for_measurement() {
    UART0_UNINSTALL_AFTER_RESPONSE.store(true, Ordering::Release);
}

/// Delete UART0 after the response to `power uart_uninstall=true` is sent.
pub fn finish_pending_uninstall() -> std::result::Result<bool, sys::esp_err_t> {
    if !UART0_UNINSTALL_AFTER_RESPONSE.swap(false, Ordering::AcqRel) {
        return Ok(false);
    }
    UART0_DEBUG_ENABLED.store(false, Ordering::Relaxed);
    UART0_ACTIVE_UNTIL_MS.store(0, Ordering::Relaxed);
    release_apb_lock();
    unsafe {
        // The command response was queued synchronously. Give the FIFO time to
        // drain before removing the driver that owns it.
        let _ = sys::uart_wait_tx_done(
            sys::uart_port_t_UART_NUM_0,
            (250 * sys::configTICK_RATE_HZ / 1_000).max(1),
        );
    }
    let ret = unsafe { sys::uart_driver_delete(sys::uart_port_t_UART_NUM_0) };
    if ret == sys::ESP_OK || ret == sys::ESP_ERR_INVALID_STATE {
        UART0_DRIVER_INSTALLED.store(false, Ordering::Relaxed);
        Ok(true)
    } else {
        Err(ret)
    }
}

pub fn measurement_status_fields() -> String {
    format!(
        "uart_driver={} uart_active={}",
        UART0_DRIVER_INSTALLED.load(Ordering::Relaxed),
        is_active()
    )
}

pub fn configure_active_window(settings: &SharedSettings) {
    let configured_ms = settings
        .borrow()
        .get_i32("uart.active_ms", DEFAULT_ACTIVE_MS as i32)
        .unwrap_or(DEFAULT_ACTIVE_MS as i32)
        .max(0) as u32;
    // A short window makes a sleeping console unusable: UART wake may consume the
    // first character, then the operator still needs time to send the command.
    let active_ms = configured_ms.max(MIN_ACTIVE_MS);
    UART0_ACTIVE_WINDOW_MS.store(active_ms, Ordering::Relaxed);
    activate_window();
}

pub fn activate_window() {
    if !UART0_DEBUG_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let active_ms = UART0_ACTIVE_WINDOW_MS.load(Ordering::Relaxed);
    if active_ms == 0 {
        release_apb_lock();
        UART0_ACTIVE_UNTIL_MS.store(0, Ordering::Relaxed);
        return;
    }
    let until = now_ms().wrapping_add(active_ms);
    UART0_ACTIVE_UNTIL_MS.store(until, Ordering::Relaxed);
    let _ = ensure_power_locks();
}

pub fn poll_active_window() {
    if !UART0_APB_LOCK_HELD.load(Ordering::Relaxed) {
        return;
    }
    let until = UART0_ACTIVE_UNTIL_MS.load(Ordering::Relaxed);
    if until == 0 || !time_after_or_equal(now_ms(), until) {
        return;
    }
    release_apb_lock();
}

pub fn is_active() -> bool {
    UART0_DEBUG_ENABLED.load(Ordering::Relaxed) && UART0_APB_LOCK_HELD.load(Ordering::Relaxed)
}

pub fn set_debug_enabled(enabled: bool) {
    UART0_DEBUG_ENABLED.store(enabled, Ordering::Relaxed);
    if enabled {
        activate_window();
    } else {
        release_apb_lock();
        UART0_ACTIVE_UNTIL_MS.store(0, Ordering::Relaxed);
    }
}

/// Called from the UART event task as soon as RX data arrives.
///
/// This runs before the main task parses the line. RX extends an open debug
/// window, but a console suspended for measurement remains closed until PRG/DTR
/// wakes it.
pub fn note_rx_activity() {
    if UART0_SUSPENDED_UNTIL_DTR.load(Ordering::Relaxed) {
        return;
    }
    set_debug_enabled(true);
}

/// Restore UART RX after a GPIO/DTR light-sleep wake.
///
/// ESP-IDF can leave the UART RX interrupt disabled after a GPIO wake even
/// though the UART peripheral and its driver queue remain installed. Re-arm
/// the interrupt and wake threshold before the host sends the first command.
pub fn rearm_after_wake() {
    UART0_SUSPENDED_UNTIL_DTR.store(false, Ordering::Relaxed);
    unsafe {
        let _ = sys::uart_flush_input(sys::uart_port_t_UART_NUM_0);
        let _ = sys::uart_set_wakeup_threshold(sys::uart_port_t_UART_NUM_0, 3);
        let _ = sys::uart_enable_rx_intr(sys::uart_port_t_UART_NUM_0);
    }
    note_rx_activity();
}

/// Close the console immediately after the current command response is sent.
/// A PRG/DTR GPIO wake is then required before UART can be used again.
pub fn request_suspend_until_dtr() {
    UART0_SUSPEND_AFTER_RESPONSE.store(true, Ordering::Relaxed);
}

/// Consume the post-response close request. Call only after writing the
/// response to the command that requested the transition.
pub fn finish_pending_suspend() -> bool {
    if !UART0_SUSPEND_AFTER_RESPONSE.swap(false, Ordering::SeqCst) {
        return false;
    }
    UART0_SUSPENDED_UNTIL_DTR.store(true, Ordering::Relaxed);
    UART0_DEBUG_ENABLED.store(false, Ordering::Relaxed);
    UART0_ACTIVE_UNTIL_MS.store(0, Ordering::Relaxed);
    unsafe {
        let _ = sys::uart_disable_rx_intr(sys::uart_port_t_UART_NUM_0);
        let _ = sys::uart_flush_input(sys::uart_port_t_UART_NUM_0);
    }
    release_apb_lock();
    true
}

/// Power down UART RX while retaining the independent GPIO/DTR wake.
pub fn suspend_for_light_sleep() {
    unsafe {
        let _ = sys::uart_disable_rx_intr(sys::uart_port_t_UART_NUM_0);
    }
    release_apb_lock();
}

pub fn write(text: &str) {
    write_bytes(text.as_bytes());
}

pub fn write_bytes(bytes: &[u8]) {
    if !is_active() {
        return;
    }
    unsafe {
        let _ = sys::uart_write_bytes(
            sys::uart_port_t_UART_NUM_0,
            bytes.as_ptr() as *const core::ffi::c_void,
            bytes.len(),
        );
    }
}

pub fn read(buf: &mut [u8], ticks_to_wait: u32) -> i32 {
    if buf.is_empty() {
        return 0;
    }
    unsafe {
        sys::uart_read_bytes(
            sys::uart_port_t_UART_NUM_0,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            buf.len() as u32,
            ticks_to_wait,
        )
    }
}

fn ensure_power_locks() -> bool {
    let apb_ok = ensure_apb_lock();
    let no_light_sleep_ok = ensure_no_light_sleep_lock();
    apb_ok && no_light_sleep_ok
}

fn ensure_apb_lock() -> bool {
    if !UART_REQUIRES_APB_LOCK {
        if !UART0_APB_LOCK_HELD.swap(true, Ordering::SeqCst) {
            rom_print(b"event type=uart.active ok=true state=held lock=none\n\0");
        }
        return true;
    }

    unsafe {
        let mut lock = UART0_APB_LOCK.load(Ordering::SeqCst);
        if lock.is_null() {
            let mut created: sys::esp_pm_lock_handle_t = core::ptr::null_mut();
            let create = sys::esp_pm_lock_create(
                sys::esp_pm_lock_type_t_ESP_PM_APB_FREQ_MAX,
                0,
                b"uart0_apb\0".as_ptr() as *const c_char,
                &mut created,
            );
            if create != sys::ESP_OK || created.is_null() {
                rom_print(b"event type=uart.pm_lock ok=false phase=create\n\0");
                return false;
            }
            match UART0_APB_LOCK.compare_exchange(
                core::ptr::null_mut(),
                created,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => lock = created,
                Err(existing) => {
                    let _ = sys::esp_pm_lock_delete(created);
                    lock = existing;
                }
            }
        }
        if !UART0_APB_LOCK_HELD.swap(true, Ordering::SeqCst) {
            let acquire = sys::esp_pm_lock_acquire(lock);
            if acquire != sys::ESP_OK {
                UART0_APB_LOCK_HELD.store(false, Ordering::SeqCst);
                rom_print(b"event type=uart.pm_lock ok=false phase=acquire\n\0");
                return false;
            }
            rom_print(b"event type=uart.pm_lock ok=true type=apb_max state=held\n\0");
        }
        true
    }
}

fn ensure_no_light_sleep_lock() -> bool {
    unsafe {
        let mut lock = UART0_NO_LIGHT_SLEEP_LOCK.load(Ordering::SeqCst);
        if lock.is_null() {
            let mut created: sys::esp_pm_lock_handle_t = core::ptr::null_mut();
            let create = sys::esp_pm_lock_create(
                sys::esp_pm_lock_type_t_ESP_PM_NO_LIGHT_SLEEP,
                0,
                b"uart0_no_ls\0".as_ptr() as *const c_char,
                &mut created,
            );
            if create != sys::ESP_OK || created.is_null() {
                rom_print(b"event type=uart.pm_lock ok=false phase=create_no_light_sleep\n\0");
                return false;
            }
            match UART0_NO_LIGHT_SLEEP_LOCK.compare_exchange(
                core::ptr::null_mut(),
                created,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => lock = created,
                Err(existing) => {
                    let _ = sys::esp_pm_lock_delete(created);
                    lock = existing;
                }
            }
        }
        if !UART0_NO_LIGHT_SLEEP_LOCK_HELD.swap(true, Ordering::SeqCst) {
            let acquire = sys::esp_pm_lock_acquire(lock);
            if acquire != sys::ESP_OK {
                UART0_NO_LIGHT_SLEEP_LOCK_HELD.store(false, Ordering::SeqCst);
                rom_print(b"event type=uart.pm_lock ok=false phase=acquire_no_light_sleep\n\0");
                return false;
            }
            rom_print(b"event type=uart.pm_lock ok=true type=no_light_sleep state=held\n\0");
        }
        true
    }
}

fn release_apb_lock() {
    release_no_light_sleep_lock();
    if !UART0_APB_LOCK_HELD.swap(false, Ordering::SeqCst) {
        return;
    }
    if !UART_REQUIRES_APB_LOCK {
        rom_print(b"event type=uart.active ok=true state=released lock=none\n\0");
        return;
    }
    let lock = UART0_APB_LOCK.load(Ordering::SeqCst);
    if lock.is_null() {
        return;
    }
    unsafe {
        let ret = sys::esp_pm_lock_release(lock);
        if ret == sys::ESP_OK {
            if UART0_DEBUG_ENABLED.load(Ordering::Relaxed) {
                rom_print(b"event type=uart.pm_lock ok=true state=released\n\0");
            }
        } else {
            rom_print(b"event type=uart.pm_lock ok=false phase=release\n\0");
            UART0_APB_LOCK_HELD.store(true, Ordering::SeqCst);
        }
    }
}

fn release_no_light_sleep_lock() {
    if !UART0_NO_LIGHT_SLEEP_LOCK_HELD.swap(false, Ordering::SeqCst) {
        return;
    }
    let lock = UART0_NO_LIGHT_SLEEP_LOCK.load(Ordering::SeqCst);
    if lock.is_null() {
        return;
    }
    unsafe {
        let ret = sys::esp_pm_lock_release(lock);
        if ret == sys::ESP_OK {
            if UART0_DEBUG_ENABLED.load(Ordering::Relaxed) {
                rom_print(
                    b"event type=uart.pm_lock ok=true type=no_light_sleep state=released\n\0",
                );
            }
        } else {
            rom_print(b"event type=uart.pm_lock ok=false phase=release_no_light_sleep\n\0");
            UART0_NO_LIGHT_SLEEP_LOCK_HELD.store(true, Ordering::SeqCst);
        }
    }
}

fn now_ms() -> u32 {
    let ticks = unsafe { sys::xTaskGetTickCount() } as u64;
    let hz = sys::configTICK_RATE_HZ as u64;
    ticks.saturating_mul(1000).saturating_div(hz.max(1)) as u32
}

fn time_after_or_equal(now: u32, deadline: u32) -> bool {
    now.wrapping_sub(deadline) < i32::MAX as u32
}

fn rom_print(message: &'static [u8]) {
    // PM transitions can happen while the IDF UART driver is manipulating its
    // TX interrupt state. Diagnostics here used to bypass the driver via ROM
    // printf and caused an interrupt watchdog on CP2104-connected boards.
    // Normal command/telemetry output remains available after boot.
    let _ = message;
}
