#![cfg(feature = "program-host")]

use micro_cel::{
    host::program::{Format, compile},
    program::{Event, ProgramLimits, Runner},
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static TOTAL: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "linux")]
fn cpu_ns() -> u64 {
    #[repr(C)]
    struct Timespec {
        sec: i64,
        nsec: i64,
    }
    unsafe extern "C" {
        fn clock_gettime(clock: i32, time: *mut Timespec) -> i32;
    }
    let mut t = Timespec { sec: 0, nsec: 0 };
    // Linux CLOCK_PROCESS_CPUTIME_ID: process CPU, not elapsed wall time.
    assert_eq!(unsafe { clock_gettime(2, &mut t) }, 0);
    t.sec as u64 * 1_000_000_000 + t.nsec as u64
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: delegate the allocator contract unchanged.
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
            TOTAL.fetch_add(layout.size(), Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        // SAFETY: p was allocated by System with the same layout.
        unsafe { System.dealloc(p, layout) };
    }
}
#[global_allocator]
static ALLOC: Counting = Counting;

fn main() {
    let limits = ProgramLimits::default();
    let program = compile(
        include_str!("programs/interleaved.toml"),
        Format::Toml,
        &limits,
    )
    .unwrap();
    let baseline = LIVE.load(Ordering::Relaxed);
    let start = Instant::now();
    #[cfg(target_os = "linux")]
    let cpu_start = cpu_ns();
    let mut calls = 0;
    let mut completions = 0;
    for _ in 0..5000 {
        let mut runner = Runner::new(program.clone(), limits).unwrap();
        let mut now = 0;
        loop {
            match runner.poll(now) {
                Event::Call {
                    token,
                    component,
                    method,
                    ..
                } => {
                    calls += 1;
                    runner.resume(token, component, method, Ok(&[7])).unwrap();
                }
                Event::Complete { .. } => completions += 1,
                Event::Sleep { until_ms } => now = until_ms,
                Event::Finished => break,
                other => panic!("unexpected event: {other:?}"),
            }
        }
    }
    let elapsed = start.elapsed();
    #[cfg(target_os = "linux")]
    let cpu_elapsed = cpu_ns() - cpu_start;
    let live = LIVE.load(Ordering::Relaxed);
    assert_eq!((calls, completions), (5000, 10000));
    assert_eq!(
        live, baseline,
        "runner allocations must be released each iteration"
    );
    println!(
        "runs=5000 calls={calls} completions={completions} elapsed={elapsed:?} live_bytes={live} peak_bytes={} total_allocated_bytes={}",
        PEAK.load(Ordering::Relaxed),
        TOTAL.load(Ordering::Relaxed)
    );
    #[cfg(target_os = "linux")]
    {
        println!(
            "process_cpu_ns={cpu_elapsed} cpu_ns_per_run={}",
            cpu_elapsed / 5000
        );
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status
                .lines()
                .filter(|s| s.starts_with("VmRSS:") || s.starts_with("VmHWM:"))
            {
                println!("{line}");
            }
        }
    }
}
