use std::ffi::{c_char, c_void, CString};
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

/// Classic ESP32 retains UART/GPIO wake for its explicit raw-NAN sleep path.
/// ESP32-S3 uses automatic light sleep instead; its console wakes through the
/// normal UART/GPIO interrupt path.
#[cfg(not(target_feature = "esp32s3ops"))]
pub const RAW_NAN_UART_WAKE: bool = true;
#[cfg(not(target_feature = "esp32s3ops"))]
pub const RAW_NAN_BUTTON_WAKE: bool = true;

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
static UART0_EVENT_TASK: AtomicPtr<sys::tskTaskControlBlock> =
    AtomicPtr::new(core::ptr::null_mut());
static UART0_TX_TASK: AtomicPtr<sys::tskTaskControlBlock> = AtomicPtr::new(core::ptr::null_mut());
static UART0_FRAME_QUEUE: AtomicPtr<sys::QueueDefinition> = AtomicPtr::new(core::ptr::null_mut());
static UART0_TX_QUEUE: AtomicPtr<sys::QueueDefinition> = AtomicPtr::new(core::ptr::null_mut());
static UART0_RX_EVENTS: AtomicU32 = AtomicU32::new(0);
static UART0_RX_DROPS: AtomicU32 = AtomicU32::new(0);
static UART0_RX_ERRORS: AtomicU32 = AtomicU32::new(0);
static UART0_TX_DROPS_IDLE: AtomicU32 = AtomicU32::new(0);
static UART0_TX_DROPS_QUEUE: AtomicU32 = AtomicU32::new(0);
static UART0_QUEUED_FRAMES: AtomicU32 = AtomicU32::new(0);
static UART0_OUTPUT_PROBE_DEADLINE_MS: AtomicU32 = AtomicU32::new(0);
static UART0_OUTPUT_PROBE_ATTEMPTS: AtomicU32 = AtomicU32::new(0);
static UART0_OUTPUT_PROBE_SENT: AtomicU32 = AtomicU32::new(0);
static UART0_OUTPUT_PROBE_DROPPED: AtomicU32 = AtomicU32::new(0);

const UART_FRAME_QUEUE_LEN: u32 = 8;
const UART_MAX_FRAME: usize = 512;
const UART_TX_QUEUE_LEN: u32 = 16;
// Keep every driver write below the hardware FIFO capacity. The task waits
// for idle before each chunk, so ESP-IDF never enables its TX-empty ISR.
const UART_TX_FRAME_MAX: usize = 512;
const UART_TX_FIFO_CHUNK: usize = 64;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UartFrameKind {
    Text = 1,
    Binary = 2,
}

/// An owned complete UART record. The ingress task is the only code that
/// reads the IDF UART driver; consumers only receive parsed records.
pub struct UartFrame {
    pub kind: UartFrameKind,
    pub data: Vec<u8>,
}

#[repr(C)]
struct QueuedFrame {
    kind: u8,
    data: *mut Vec<u8>,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct QueuedTx {
    len: u16,
    data: [u8; UART_TX_FRAME_MAX],
}

/// Remove the UART0 driver for a one-boot power measurement.
///
/// This is intentionally one-way: reset reinstates the normal boot console.
/// The deletion is deferred so the command acknowledgement can leave UART0.
pub fn request_uninstall_for_measurement() {
    UART0_UNINSTALL_AFTER_RESPONSE.store(true, Ordering::Release);
}

pub fn measurement_status_fields() -> String {
    format!(
        "uart_driver={} uart_active={} uart_rx_wake={} uart_rx_events={} uart_rx_drop={} uart_rx_err={} uart_tx_drop_idle={} uart_tx_drop_queue={} uart_probe_attempts={} uart_probe_sent={} uart_probe_dropped={}",
        UART0_DRIVER_INSTALLED.load(Ordering::Relaxed),
        is_active(),
        !UART0_SUSPENDED_UNTIL_DTR.load(Ordering::Relaxed),
        UART0_RX_EVENTS.load(Ordering::Relaxed),
        UART0_RX_DROPS.load(Ordering::Relaxed),
        UART0_RX_ERRORS.load(Ordering::Relaxed),
        UART0_TX_DROPS_IDLE.load(Ordering::Relaxed),
        UART0_TX_DROPS_QUEUE.load(Ordering::Relaxed),
        UART0_OUTPUT_PROBE_ATTEMPTS.load(Ordering::Relaxed),
        UART0_OUTPUT_PROBE_SENT.load(Ordering::Relaxed),
        UART0_OUTPUT_PROBE_DROPPED.load(Ordering::Relaxed),
    )
}

/// Schedule one debug-only output attempt after `delay_ms`.
///
/// The power command uses this to verify that output really is gated after a
/// console active window expires. It never changes radio or sleep policy.
pub fn schedule_output_probe(delay_ms: u32) -> u32 {
    let deadline = now_ms().wrapping_add(delay_ms).max(1);
    UART0_OUTPUT_PROBE_DEADLINE_MS.store(deadline, Ordering::Release);
    deadline
}

/// Clear output-gate probe state before a bounded verification run.
pub fn reset_output_probe() {
    UART0_OUTPUT_PROBE_DEADLINE_MS.store(0, Ordering::Release);
    UART0_OUTPUT_PROBE_ATTEMPTS.store(0, Ordering::Relaxed);
    UART0_OUTPUT_PROBE_SENT.store(0, Ordering::Relaxed);
    UART0_OUTPUT_PROBE_DROPPED.store(0, Ordering::Relaxed);
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

/// Start the single UART ingress task after UART0 has been installed with an
/// IDF event queue. No other firmware task may call `uart_read_bytes`.
pub fn start_ingress_task(event_queue: sys::QueueHandle_t) -> Result<(), sys::esp_err_t> {
    if !UART0_EVENT_TASK.load(Ordering::Acquire).is_null() {
        return Ok(());
    }
    let frame_queue = unsafe {
        sys::xQueueGenericCreate(
            UART_FRAME_QUEUE_LEN,
            core::mem::size_of::<QueuedFrame>() as u32,
            0,
        )
    };
    if frame_queue.is_null() {
        return Err(sys::ESP_ERR_NO_MEM);
    }
    UART0_FRAME_QUEUE.store(frame_queue, Ordering::Release);
    let tx_queue = unsafe {
        sys::xQueueGenericCreate(
            UART_TX_QUEUE_LEN,
            core::mem::size_of::<QueuedTx>() as u32,
            0,
        )
    };
    if tx_queue.is_null() {
        unsafe { sys::vQueueDelete(frame_queue) };
        UART0_FRAME_QUEUE.store(core::ptr::null_mut(), Ordering::Release);
        return Err(sys::ESP_ERR_NO_MEM);
    }
    UART0_TX_QUEUE.store(tx_queue, Ordering::Release);
    let name = CString::new("uart_mgr").map_err(|_| sys::ESP_FAIL)?;
    let mut task = core::ptr::null_mut();
    let ret = unsafe {
        sys::xTaskCreatePinnedToCore(
            Some(uart_manager_task),
            name.as_ptr(),
            4096,
            event_queue.cast::<c_void>(),
            6,
            &mut task,
            0,
        )
    };
    if ret != 1 || task.is_null() {
        unsafe { sys::vQueueDelete(frame_queue) };
        unsafe { sys::vQueueDelete(tx_queue) };
        UART0_FRAME_QUEUE.store(core::ptr::null_mut(), Ordering::Release);
        UART0_TX_QUEUE.store(core::ptr::null_mut(), Ordering::Release);
        return Err(sys::ESP_FAIL);
    }
    UART0_EVENT_TASK.store(task, Ordering::Release);
    let tx_name = CString::new("uart_tx").map_err(|_| sys::ESP_FAIL)?;
    let mut tx_task = core::ptr::null_mut();
    let tx_ret = unsafe {
        sys::xTaskCreatePinnedToCore(
            Some(uart_tx_task),
            tx_name.as_ptr(),
            4096,
            tx_queue.cast::<c_void>(),
            5,
            &mut tx_task,
            0,
        )
    };
    if tx_ret != 1 || tx_task.is_null() {
        unsafe { sys::vTaskDelete(task) };
        unsafe { sys::vQueueDelete(frame_queue) };
        unsafe { sys::vQueueDelete(tx_queue) };
        UART0_EVENT_TASK.store(core::ptr::null_mut(), Ordering::Release);
        UART0_FRAME_QUEUE.store(core::ptr::null_mut(), Ordering::Release);
        UART0_TX_QUEUE.store(core::ptr::null_mut(), Ordering::Release);
        return Err(sys::ESP_FAIL);
    }
    UART0_TX_TASK.store(tx_task, Ordering::Release);
    Ok(())
}

pub fn take_frame() -> Option<UartFrame> {
    let queue = UART0_FRAME_QUEUE.load(Ordering::Acquire);
    if queue.is_null() {
        return None;
    }
    let mut queued = QueuedFrame {
        kind: 0,
        data: core::ptr::null_mut(),
    };
    let received =
        unsafe { sys::xQueueReceive(queue, (&mut queued as *mut QueuedFrame).cast::<c_void>(), 0) };
    if received != 1 || queued.data.is_null() {
        return None;
    }
    UART0_QUEUED_FRAMES.fetch_sub(1, Ordering::Relaxed);
    let kind = match queued.kind {
        1 => UartFrameKind::Text,
        2 => UartFrameKind::Binary,
        _ => {
            unsafe { drop(Box::from_raw(queued.data)) };
            UART0_RX_ERRORS.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    };
    Some(UartFrame {
        kind,
        data: *unsafe { Box::from_raw(queued.data) },
    })
}

/// Return whether the event-driven UART ingress task has a complete record
/// ready for the command owner. This deliberately does not touch the UART
/// driver; `uart_manager_task` is its sole reader.
pub fn has_pending_frame() -> bool {
    UART0_QUEUED_FRAMES.load(Ordering::Acquire) != 0
}

/// Let the ingress task process a deferred driver deletion after the command
/// acknowledgement has been transmitted. This operation is reset-only.
pub fn finish_pending_uninstall() -> std::result::Result<bool, sys::esp_err_t> {
    if !UART0_UNINSTALL_AFTER_RESPONSE.swap(false, Ordering::AcqRel) {
        return Ok(!UART0_DRIVER_INSTALLED.load(Ordering::Acquire));
    }

    UART0_DEBUG_ENABLED.store(false, Ordering::Release);
    UART0_ACTIVE_UNTIL_MS.store(0, Ordering::Release);
    release_apb_lock();
    let task = UART0_EVENT_TASK.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !task.is_null() {
        unsafe { sys::vTaskDelete(task) };
    }
    let tx_task = UART0_TX_TASK.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !tx_task.is_null() {
        unsafe { sys::vTaskDelete(tx_task) };
    }
    let delete = unsafe { sys::uart_driver_delete(sys::uart_port_t_UART_NUM_0) };
    if delete != sys::ESP_OK && delete != sys::ESP_ERR_INVALID_STATE {
        UART0_RX_ERRORS.fetch_add(1, Ordering::Relaxed);
        return Err(delete);
    }
    UART0_DRIVER_INSTALLED.store(false, Ordering::Release);
    UART0_FRAME_QUEUE.store(core::ptr::null_mut(), Ordering::Release);
    UART0_TX_QUEUE.store(core::ptr::null_mut(), Ordering::Release);
    Ok(true)
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

/// Run a due output-gate probe from the control task.
pub fn poll_output_probe() {
    let deadline = UART0_OUTPUT_PROBE_DEADLINE_MS.load(Ordering::Acquire);
    if deadline == 0 || !time_after_or_equal(now_ms(), deadline) {
        return;
    }
    if UART0_OUTPUT_PROBE_DEADLINE_MS
        .compare_exchange(deadline, 0, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let attempt = UART0_OUTPUT_PROBE_ATTEMPTS.fetch_add(1, Ordering::Relaxed) + 1;
    if is_active() {
        UART0_OUTPUT_PROBE_SENT.fetch_add(1, Ordering::Relaxed);
        write(&format!(
            "event type=uart.output_probe n={} sent=true\n",
            attempt
        ));
    } else {
        UART0_OUTPUT_PROBE_DROPPED.fetch_add(1, Ordering::Relaxed);
        // Keep this on the normal write path so uart_tx_drop_idle confirms the
        // output gate, while the dedicated counter distinguishes this test
        // from expected background notification drops.
        write(&format!(
            "event type=uart.output_probe n={} sent=false\n",
            attempt
        ));
    }
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
    if !UART0_DRIVER_INSTALLED.load(Ordering::Acquire) {
        return;
    }
    UART0_SUSPENDED_UNTIL_DTR.store(false, Ordering::Release);
    set_debug_enabled(true);
}

/// Restore UART RX after a GPIO/DTR light-sleep wake.
///
/// ESP-IDF can leave the UART RX interrupt disabled after a GPIO wake even
/// though the UART peripheral and its driver queue remain installed. Re-arm
/// the interrupt and wake threshold before the host sends the first command.
pub fn rearm_after_wake() {
    if !UART0_DRIVER_INSTALLED.load(Ordering::Acquire) {
        return;
    }
    UART0_SUSPENDED_UNTIL_DTR.store(false, Ordering::Relaxed);
    unsafe {
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
    // "quiet" suppresses TX and permits light sleep. RX remains armed so a
    // line (or its wake preamble) is sufficient to reopen the console.
    UART0_SUSPENDED_UNTIL_DTR.store(false, Ordering::Relaxed);
    UART0_DEBUG_ENABLED.store(false, Ordering::Relaxed);
    UART0_ACTIVE_UNTIL_MS.store(0, Ordering::Relaxed);
    release_apb_lock();
    true
}

/// Power down UART RX while retaining the independent GPIO/DTR wake.
pub fn suspend_for_light_sleep() {
    // Keep RX interrupt and UART wake armed. The ingress task turns received
    // bytes into a console-active window; disabling RX here made sleeping
    // boards require a physical DTR edge and stranded remote consoles.
    release_apb_lock();
}

pub fn write(text: &str) {
    write_bytes(text.as_bytes());
}

pub fn write_bytes(bytes: &[u8]) {
    if !is_active() {
        UART0_TX_DROPS_IDLE.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let queue = UART0_TX_QUEUE.load(Ordering::Acquire);
    if queue.is_null() {
        UART0_TX_DROPS_QUEUE.fetch_add(1, Ordering::Relaxed);
        return;
    }
    for chunk in bytes.chunks(UART_TX_FRAME_MAX) {
        let mut queued = QueuedTx {
            len: chunk.len() as u16,
            data: [0; UART_TX_FRAME_MAX],
        };
        queued.data[..chunk.len()].copy_from_slice(chunk);
        let sent = unsafe {
            sys::xQueueGenericSend(queue, (&queued as *const QueuedTx).cast::<c_void>(), 0, 0)
        };
        if sent != 1 {
            UART0_TX_DROPS_QUEUE.fetch_add(1, Ordering::Relaxed);
        }
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

unsafe extern "C" fn uart_manager_task(arg: *mut c_void) {
    let event_queue = arg.cast::<sys::QueueDefinition>();
    let mut parser = UartParser::default();
    loop {
        let mut event = sys::uart_event_t::default();
        let received = unsafe {
            sys::xQueueReceive(
                event_queue,
                (&mut event as *mut sys::uart_event_t).cast::<c_void>(),
                sys::TickType_t::MAX,
            )
        };
        if received != 1 {
            continue;
        }
        match event.type_ {
            x if x == sys::uart_event_type_t_UART_DATA => {
                UART0_RX_EVENTS.fetch_add(1, Ordering::Relaxed);
                note_rx_activity();
                drain_driver_rx(&mut parser);
            }
            x if x == sys::uart_event_type_t_UART_FIFO_OVF
                || x == sys::uart_event_type_t_UART_BUFFER_FULL =>
            unsafe {
                UART0_RX_ERRORS.fetch_add(1, Ordering::Relaxed);
                let _ = sys::uart_flush_input(sys::uart_port_t_UART_NUM_0);
                let _ = sys::xQueueGenericReset(event_queue, 0);
                parser.reset();
            },
            _ => {
                UART0_RX_ERRORS.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// The only task that writes UART0 after the driver is installed. Radio and
/// BLE callbacks enqueue records; each write is FIFO-bounded so the driver's
/// TX-empty ISR is never armed on classic ESP32.
unsafe extern "C" fn uart_tx_task(arg: *mut c_void) {
    let queue = arg.cast::<sys::QueueDefinition>();
    loop {
        let mut queued = QueuedTx {
            len: 0,
            data: [0; UART_TX_FRAME_MAX],
        };
        let received = unsafe {
            sys::xQueueReceive(
                queue,
                (&mut queued as *mut QueuedTx).cast::<c_void>(),
                sys::TickType_t::MAX,
            )
        };
        if received != 1 || queued.len == 0 || queued.len as usize > UART_TX_FRAME_MAX {
            continue;
        }
        let len = queued.len as usize;
        for chunk in queued.data[..len].chunks(UART_TX_FIFO_CHUNK) {
            let wait = unsafe {
                sys::uart_wait_tx_done(
                    sys::uart_port_t_UART_NUM_0,
                    (100 * sys::configTICK_RATE_HZ / 1_000).max(1),
                )
            };
            let written = if wait == sys::ESP_OK {
                unsafe {
                    sys::uart_write_bytes(
                        sys::uart_port_t_UART_NUM_0,
                        chunk.as_ptr().cast::<c_void>(),
                        chunk.len(),
                    )
                }
            } else {
                -1
            };
            if written != chunk.len() as i32 {
                UART0_RX_ERRORS.fetch_add(1, Ordering::Relaxed);
                break;
            }
        }
    }
}

fn drain_driver_rx(parser: &mut UartParser) {
    let mut buf = [0_u8; 128];
    loop {
        let read = unsafe {
            sys::uart_read_bytes(
                sys::uart_port_t_UART_NUM_0,
                buf.as_mut_ptr().cast::<c_void>(),
                buf.len() as u32,
                0,
            )
        };
        if read <= 0 {
            break;
        }
        crate::components::telemetry::record_uart_read(read as usize);
        for byte in &buf[..read as usize] {
            if let Some((kind, frame)) = parser.push(*byte) {
                enqueue_frame(kind, frame);
            }
        }
    }
}

fn enqueue_frame(kind: UartFrameKind, data: Vec<u8>) {
    let queue = UART0_FRAME_QUEUE.load(Ordering::Acquire);
    if queue.is_null() {
        UART0_RX_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let queued = QueuedFrame {
        kind: kind as u8,
        data: Box::into_raw(Box::new(data)),
    };
    let sent = unsafe {
        sys::xQueueGenericSend(
            queue,
            (&queued as *const QueuedFrame).cast::<c_void>(),
            0,
            0,
        )
    };
    if sent != 1 {
        unsafe { drop(Box::from_raw(queued.data)) };
        UART0_RX_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    UART0_QUEUED_FRAMES.fetch_add(1, Ordering::Release);
    crate::components::wake::notify();
}

#[derive(Default)]
struct UartParser {
    mode: UartParseMode,
    data: Vec<u8>,
    remaining: usize,
    length_bytes: [u8; 3],
    length_count: usize,
}

#[derive(Default)]
enum UartParseMode {
    #[default]
    Text,
    BinaryLength,
    Binary,
}

impl UartParser {
    fn reset(&mut self) {
        self.mode = UartParseMode::Text;
        self.data.clear();
        self.remaining = 0;
        self.length_count = 0;
    }

    fn push(&mut self, byte: u8) -> Option<(UartFrameKind, Vec<u8>)> {
        match self.mode {
            UartParseMode::Text => {
                if byte == 0 {
                    if !self.data.is_empty() {
                        self.data.clear();
                        UART0_RX_ERRORS.fetch_add(1, Ordering::Relaxed);
                    }
                    self.mode = UartParseMode::BinaryLength;
                    self.length_count = 0;
                    return None;
                }
                if byte == b'\n' || byte == b'\r' {
                    if self.data.is_empty() {
                        return None;
                    }
                    let data = core::mem::take(&mut self.data);
                    return Some((UartFrameKind::Text, data));
                }
                if self.data.len() >= UART_MAX_FRAME {
                    self.data.clear();
                    UART0_RX_DROPS.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.data.push(byte);
                }
                None
            }
            UartParseMode::BinaryLength => {
                self.length_bytes[self.length_count] = byte;
                self.length_count += 1;
                if self.length_count != 3 {
                    return None;
                }
                self.remaining = self.length_bytes[0] as usize
                    | ((self.length_bytes[1] as usize) << 8)
                    | ((self.length_bytes[2] as usize) << 16);
                self.data.clear();
                if self.remaining == 0 || self.remaining > UART_MAX_FRAME {
                    UART0_RX_DROPS.fetch_add(1, Ordering::Relaxed);
                    self.reset();
                } else {
                    self.data.reserve(self.remaining);
                    self.mode = UartParseMode::Binary;
                }
                None
            }
            UartParseMode::Binary => {
                self.data.push(byte);
                self.remaining = self.remaining.saturating_sub(1);
                if self.remaining == 0 {
                    self.mode = UartParseMode::Text;
                    return Some((UartFrameKind::Binary, core::mem::take(&mut self.data)));
                }
                None
            }
        }
    }
}

fn rom_print(message: &'static [u8]) {
    // PM transitions can happen while the IDF UART driver is manipulating its
    // TX interrupt state. Diagnostics here used to bypass the driver via ROM
    // printf and caused an interrupt watchdog on CP2104-connected boards.
    // Normal command/telemetry output remains available after boot.
    let _ = message;
}
