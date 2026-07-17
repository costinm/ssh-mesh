use std::ffi::c_char;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};

use esp_idf_sys as sys;

use super::settings::SharedSettings;

const DEFAULT_ACTIVE_MS: u32 = 10_000;
#[cfg(target_feature = "esp32s3ops")]
const UART_REQUIRES_APB_LOCK: bool = false;
#[cfg(not(target_feature = "esp32s3ops"))]
const UART_REQUIRES_APB_LOCK: bool = true;

static UART0_APB_LOCK: AtomicPtr<sys::esp_pm_lock> = AtomicPtr::new(core::ptr::null_mut());
static UART0_APB_LOCK_HELD: AtomicBool = AtomicBool::new(false);
static UART0_ACTIVE_UNTIL_MS: AtomicU32 = AtomicU32::new(0);
static UART0_ACTIVE_WINDOW_MS: AtomicU32 = AtomicU32::new(DEFAULT_ACTIVE_MS);
static UART0_DEBUG_ENABLED: AtomicBool = AtomicBool::new(true);

pub fn configure_active_window(settings: &SharedSettings) {
    let active_ms = settings
        .borrow()
        .get_i32("uart.active_ms", DEFAULT_ACTIVE_MS as i32)
        .unwrap_or(DEFAULT_ACTIVE_MS as i32)
        .max(0) as u32;
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
    let _ = ensure_apb_lock();
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

pub fn write(text: &str) {
    if !is_active() {
        return;
    }
    unsafe {
        let bytes = text.as_bytes();
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

fn release_apb_lock() {
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
            rom_print(b"event type=uart.pm_lock ok=true state=released\n\0");
        } else {
            rom_print(b"event type=uart.pm_lock ok=false phase=release\n\0");
            UART0_APB_LOCK_HELD.store(true, Ordering::SeqCst);
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
    unsafe {
        sys::esp_rom_printf(message.as_ptr() as *const c_char);
    }
}
