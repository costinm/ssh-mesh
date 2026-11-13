//! Packet pool traits, owner-task policy, and (on host/test builds with `host-pools` or `std`)
//! three zero-copy pool implementations (`StaticPacketPool`, `HeapPacketPool`, `XipLazyPool`).
//! On device targets, the C runtime pool (`xip_pool.c`) is the sole packet pool and implements
//! [`PacketPool`] directly via the module ABI.

#[cfg(any(feature = "std", feature = "host-pools", test))]
use alloc::boxed::Box;
#[cfg(any(feature = "std", feature = "host-pools", test))]
use alloc::sync::Arc;
#[cfg(any(feature = "std", feature = "host-pools", test))]
use alloc::vec::Vec;
#[cfg(any(feature = "std", feature = "host-pools", test))]
use core::cell::UnsafeCell;
#[cfg(any(feature = "std", feature = "host-pools", test))]
use core::marker::PhantomData;
use core::ops::Range;
#[cfg(any(feature = "std", feature = "host-pools", test))]
use core::ptr;
#[cfg(any(feature = "std", feature = "host-pools", test))]
use core::sync::atomic::{
    AtomicBool, AtomicPtr, AtomicU8, AtomicU16, AtomicU32, AtomicUsize, Ordering,
};

/// Default headroom matching `XIP_PKT_HEADROOM` (144 bytes).
pub const DEFAULT_HEADROOM: usize = 144;
/// Default maximum payload matching `XIP_PKT_MAX` (1500 bytes).
pub const DEFAULT_MAX_PAYLOAD: usize = 1500;
/// Default tail space matching `XIP_PKT_SLOT_MIN - XIP_PKT_HEADROOM - XIP_PKT_MAX` (60 bytes).
pub const DEFAULT_TAIL: usize = 60;
/// Default full slot size (`144 + 1500 + 60 = 1704` bytes, matching `XIP_PKT_SLOT_MIN`).
pub const DEFAULT_SLOT_SIZE: usize = DEFAULT_HEADROOM + DEFAULT_MAX_PAYLOAD + DEFAULT_TAIL;

/// Capacity growth and idle-shrink policy for a shared packet pool.
#[derive(Clone, Debug)]
pub struct PacketPoolPolicy {
    /// Minimum number of slots the pool retains even when idle.
    pub minimum: usize,
    /// Hard ceiling on total pool capacity.
    pub maximum: usize,
    /// Target number of free slots maintained above active in-use slots.
    pub free_target: usize,
    /// Idle duration in milliseconds required before shrinking excess free slots.
    pub idle_ms: u64,
    low_since: Option<u64>,
    pressure_capacity: Option<usize>,
}

impl PacketPoolPolicy {
    /// Construct a new [`PacketPoolPolicy`].
    pub const fn new(minimum: usize, maximum: usize, free_target: usize, idle_ms: u64) -> Self {
        Self {
            minimum,
            maximum,
            free_target,
            idle_ms,
            low_since: None,
            pressure_capacity: None,
        }
    }

    /// Compute the target pool capacity at `now_ms`.
    ///
    /// Growth is immediate; excess free storage must remain idle for `idle_ms` before shrink.
    /// Allocation failure is handled by the pool, not by this policy.
    pub fn target(&mut self, now_ms: u64, capacity: usize, in_use: usize) -> usize {
        let pressure = self
            .pressure_capacity
            .take()
            .map_or(0, |capacity| capacity.saturating_add(self.free_target));
        let desired = in_use
            .saturating_add(self.free_target)
            .max(pressure)
            .max(self.minimum)
            .min(self.maximum);
        if desired >= capacity {
            self.low_since = None;
            return desired;
        }
        let since = *self.low_since.get_or_insert(now_ms);
        if now_ms.saturating_sub(since) >= self.idle_ms {
            desired
        } else {
            capacity
        }
    }

    /// Timestamp (`now_ms`) at which excess idle slots become eligible for reclamation.
    pub fn shrink_deadline(&self) -> Option<u64> {
        self.low_since
            .map(|since| since.saturating_add(self.idle_ms))
    }

    /// Record a callback pressure latch so it survives until the owner samples the pool,
    /// even if the burst's leases have already drained by then.
    pub fn note_pressure(&mut self, capacity: usize) {
        self.pressure_capacity = Some(capacity);
    }
}

/// Errors returned by packet pool and packet range operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolError {
    /// Pool has no free slots or caller reached its quota/reserve.
    Exhausted,
    /// Packet is shared (`refs > 1`) and cannot be mutated in-place.
    Shared,
    /// Requested byte range is outside the slot bounds.
    InvalidRange,
}

/// Owned or reference-counted packet handle from a packet pool.
pub trait PoolPacket: Sized {
    /// Full underlying slot buffer `[0 .. slot_capacity]`.
    fn slot_slice(&self) -> &[u8];

    /// Mutable access to the full slot buffer when uniquely owned (`refs == 1`).
    fn slot_slice_mut(&mut self) -> Result<&mut [u8], PoolError>;

    /// Active byte range `[start .. end]` within `slot_slice()`.
    fn range(&self) -> Range<usize>;

    /// Update the active byte range `[start .. end]` (used to strip/prepend headers or slice).
    fn set_range(&mut self, range: Range<usize>) -> Result<(), PoolError>;

    /// Whether this packet reference is currently unique (`refs == 1`).
    fn is_unique(&self) -> bool;

    /// Retain an additional reference (`pkt_keep` / reference-count increment).
    fn try_clone(&self) -> Result<Self, PoolError>;

    /// Active slice `&self.slot_slice()[self.range()]`.
    #[inline]
    fn bytes(&self) -> &[u8] {
        &self.slot_slice()[self.range()]
    }

    /// Writable headroom bytes before `self.range().start`.
    #[inline]
    fn headroom(&self) -> usize {
        self.range().start
    }

    /// Writable tailroom bytes after `self.range().end`.
    #[inline]
    fn tailroom(&self) -> usize {
        self.slot_slice().len().saturating_sub(self.range().end)
    }

    /// Prepend `header` immediately in front of `self.range().start` in-place.
    #[inline]
    fn prepend(&mut self, header: &[u8]) -> Result<(), PoolError> {
        let r = self.range();
        let new_start = r
            .start
            .checked_sub(header.len())
            .ok_or(PoolError::InvalidRange)?;
        let slot = self.slot_slice_mut()?;
        slot[new_start..r.start].copy_from_slice(header);
        self.set_range(new_start..r.end)
    }

    /// Append `payload` at the end of `self.range()` in-place.
    #[inline]
    fn append(&mut self, payload: &[u8]) -> Result<(), PoolError> {
        let r = self.range();
        let new_end = r
            .end
            .checked_add(payload.len())
            .ok_or(PoolError::InvalidRange)?;
        let slot = self.slot_slice_mut()?;
        if new_end > slot.len() {
            return Err(PoolError::InvalidRange);
        }
        slot[r.end..new_end].copy_from_slice(payload);
        self.set_range(r.start..new_end)
    }
}

/// Abstracted packet pool provider.
pub trait PacketPool {
    /// Packet handle type produced by this pool.
    type Packet: PoolPacket;

    /// Default payload start offset (`144` on ESP-XIP).
    fn headroom(&self) -> usize;

    /// Maximum payload bytes after `headroom` (`1500` on ESP-XIP).
    fn max_payload(&self) -> usize;

    /// Allocate a uniquely-owned packet with initial range `headroom()..headroom()`.
    fn alloc(&self) -> Result<Self::Packet, PoolError>;

    /// Allocate a uniquely-owned packet positioned at custom `headroom..headroom`.
    fn alloc_with_headroom(&self, headroom: usize) -> Result<Self::Packet, PoolError> {
        let mut pkt = self.alloc()?;
        pkt.set_range(headroom..headroom)?;
        Ok(pkt)
    }

    /// Allocate a uniquely-owned packet while leaving at least `reserved` slots free.
    fn alloc_reserving(&self, reserved: usize) -> Result<Self::Packet, PoolError> {
        if self.available() <= reserved {
            return Err(PoolError::Exhausted);
        }
        self.alloc()
    }

    /// Remaining free packets in the pool.
    fn available(&self) -> usize;
}

// ============================================================================
// Host-only Pool Implementations (StaticPacketPool, HeapPacketPool, XipLazyPool)
// ============================================================================

#[cfg(any(feature = "std", feature = "host-pools", test))]
mod host_pools {
    use super::*;

    /// Fixed-capacity inline `[[u8; MTU]; SLOTS]` packet pool (`SLOTS <= 32`).
    pub struct StaticPacketPool<const SLOTS: usize, const MTU: usize = DEFAULT_SLOT_SIZE> {
    free: AtomicU32,
    references: [AtomicU8; SLOTS],
    headroom: usize,
    max_payload: usize,
    packets: UnsafeCell<[[u8; MTU]; SLOTS]>,
}

// SAFETY: A slot is accessed mutably (`slot_slice_mut`) only when:
// 1. Its bit in `free` is 0 and `references[slot] == 1` (checked via `Acquire` load), AND
// 2. The caller holds `&'a mut StaticPacketLease`, and `StaticPacketLease` is `!Sync`
//    (`PhantomData<*const ()>`), so no other thread can concurrently call `try_clone(&self)`
//    or `slot_slice(&self)` on that sole lease instance while `&'a mut [u8]` is live.
// Conversely, whenever `references[slot] > 1`, `slot_slice_mut` returns `Err(PoolError::Shared)`,
// so all live leases only ever obtain shared `&[u8]` slices via `slot_slice(&self)`.
unsafe impl<const SLOTS: usize, const MTU: usize> Sync for StaticPacketPool<SLOTS, MTU> {}
unsafe impl<const SLOTS: usize, const MTU: usize> Send for StaticPacketPool<SLOTS, MTU> {}

const fn slot_mask(slots: usize) -> u32 {
    if slots == 32 {
        u32::MAX
    } else {
        (1u32 << slots) - 1
    }
}

impl<const SLOTS: usize, const MTU: usize> StaticPacketPool<SLOTS, MTU> {
    /// Construct a fixed-capacity static pool with `DEFAULT_HEADROOM` (`144`) and `DEFAULT_TAIL` (`60`).
    pub const fn new() -> Self {
        Self::with_geometry(
            DEFAULT_HEADROOM,
            MTU.saturating_sub(DEFAULT_HEADROOM + DEFAULT_TAIL),
        )
    }

    /// Construct a fixed-capacity static pool with explicit `headroom` and `max_payload`.
    pub const fn with_geometry(headroom: usize, max_payload: usize) -> Self {
        assert!(SLOTS > 0 && SLOTS <= 32);
        assert!(headroom + max_payload <= MTU);
        Self {
            free: AtomicU32::new(slot_mask(SLOTS)),
            references: [const { AtomicU8::new(0) }; SLOTS],
            headroom,
            max_payload,
            packets: UnsafeCell::new([[0; MTU]; SLOTS]),
        }
    }

    /// Total configured slots.
    pub const fn capacity(&self) -> usize {
        SLOTS
    }

    /// Number of slots currently free.
    pub fn available(&self) -> usize {
        self.free.load(Ordering::Acquire).count_ones() as usize
    }

    /// Acquire one slot while leaving `reserved` slots free.
    pub fn acquire_reserving(
        &self,
        reserved: usize,
    ) -> Result<StaticPacketLease<'_, SLOTS, MTU>, PoolError> {
        let mut current = self.free.load(Ordering::Acquire);
        loop {
            if (current.count_ones() as usize) <= reserved {
                return Err(PoolError::Exhausted);
            }
            let bit = current.trailing_zeros() as usize;
            let next = current & !(1u32 << bit);
            match self.free.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.references[bit].store(1, Ordering::Release);
                    return Ok(StaticPacketLease {
                        pool: self,
                        slot: bit as u8,
                        range: self.headroom..self.headroom,
                        _not_sync: PhantomData,
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }

    fn release_slot(&self, slot: usize) {
        let bit = 1u32 << slot;
        self.free.fetch_or(bit, Ordering::AcqRel);
    }
}

impl<const SLOTS: usize, const MTU: usize> Default for StaticPacketPool<SLOTS, MTU> {
    fn default() -> Self {
        Self::new()
    }
}

/// Clonable reference-counted lease into a [`StaticPacketPool`].
///
/// Intentionally `Send` + `!Sync`: cross-thread sharing uses [`PoolPacket::try_clone`] rather than
/// `&StaticPacketLease`, guaranteeing that `&mut self` + `references[slot] == 1` provides
/// non-aliased exclusive mutable access without racing a concurrent `try_clone(&self)` or
/// `slot_slice(&self)` on another thread.
pub struct StaticPacketLease<'a, const SLOTS: usize, const MTU: usize = DEFAULT_SLOT_SIZE> {
    pool: &'a StaticPacketPool<SLOTS, MTU>,
    slot: u8,
    range: Range<usize>,
    _not_sync: PhantomData<*const ()>,
}

// SAFETY: Moving ownership of a `StaticPacketLease` to another thread is safe because
// `StaticPacketPool` is `Sync` and reference counting uses `AcqRel` atomics.
unsafe impl<const SLOTS: usize, const MTU: usize> Send for StaticPacketLease<'_, SLOTS, MTU> {}

impl<const SLOTS: usize, const MTU: usize> core::fmt::Debug for StaticPacketLease<'_, SLOTS, MTU> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StaticPacketLease")
            .field("slot", &self.slot)
            .field("range", &self.range)
            .finish()
    }
}

impl<const SLOTS: usize, const MTU: usize> PoolPacket for StaticPacketLease<'_, SLOTS, MTU> {
    fn slot_slice(&self) -> &[u8] {
        let idx = self.slot as usize;
        debug_assert!(self.pool.references[idx].load(Ordering::Acquire) >= 1);
        // SAFETY: While `self` exists, `references[idx] >= 1` and the slot cannot be reallocated.
        // Because `StaticPacketLease` is `!Sync`, if `&self` is held here, either `references[idx] == 1`
        // (and Rust's borrow checker forbids `&mut self` / `slot_slice_mut` concurrently on this single
        // lease) or `references[idx] > 1` (in which case `slot_slice_mut` rejects all leases with
        // `Err(PoolError::Shared)`). Thus no `&mut [u8]` into `packets[idx]` can coexist.
        unsafe { &(*self.pool.packets.get())[idx] }
    }

    fn slot_slice_mut(&mut self) -> Result<&mut [u8], PoolError> {
        let idx = self.slot as usize;
        if self.pool.references[idx].load(Ordering::Acquire) != 1 {
            return Err(PoolError::Shared);
        }
        // SAFETY: `references[idx] == 1` proves `self` is the sole live lease for `idx`.
        // Because `StaticPacketLease` is `!Sync` and we hold `&'a mut self`, neither `try_clone(&self)`
        // nor `slot_slice(&self)` can be called on any thread for the lifetime `'a` of the returned `&mut [u8]`.
        Ok(unsafe { &mut (*self.pool.packets.get())[idx] })
    }

    fn range(&self) -> Range<usize> {
        self.range.clone()
    }

    fn set_range(&mut self, range: Range<usize>) -> Result<(), PoolError> {
        if range.start > range.end || range.end > MTU {
            return Err(PoolError::InvalidRange);
        }
        self.range = range;
        Ok(())
    }

    fn is_unique(&self) -> bool {
        self.pool.references[self.slot as usize].load(Ordering::Acquire) == 1
    }

    fn try_clone(&self) -> Result<Self, PoolError> {
        let refs = &self.pool.references[self.slot as usize];
        let mut cur = refs.load(Ordering::Acquire);
        loop {
            if cur == 0 || cur == u8::MAX {
                return Err(PoolError::Exhausted);
            }
            match refs.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(Self {
                        pool: self.pool,
                        slot: self.slot,
                        range: self.range.clone(),
                        _not_sync: PhantomData,
                    });
                }
                Err(observed) => cur = observed,
            }
        }
    }
}

impl<const SLOTS: usize, const MTU: usize> Drop for StaticPacketLease<'_, SLOTS, MTU> {
    fn drop(&mut self) {
        let idx = self.slot as usize;
        if self.pool.references[idx].fetch_sub(1, Ordering::AcqRel) == 1 {
            self.pool.release_slot(idx);
        }
    }
}

impl<'a, const SLOTS: usize, const MTU: usize> PacketPool for &'a StaticPacketPool<SLOTS, MTU> {
    type Packet = StaticPacketLease<'a, SLOTS, MTU>;

    fn headroom(&self) -> usize {
        self.headroom
    }

    fn max_payload(&self) -> usize {
        self.max_payload
    }

    fn alloc(&self) -> Result<Self::Packet, PoolError> {
        self.acquire_reserving(0)
    }

    fn alloc_reserving(&self, reserved: usize) -> Result<Self::Packet, PoolError> {
        self.acquire_reserving(reserved)
    }

    fn available(&self) -> usize {
        StaticPacketPool::available(self)
    }
}

// ============================================================================
// 2. HeapPacketPool
// ============================================================================

const HEAP_WRITER: u8 = u8::MAX;

/// Conservative allocator/header allowance charged to every heap packet slot.
pub const HEAP_PACKET_SLOT_OVERHEAD: usize = 32;

/// Failure to resize a [`HeapPacketPool`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeapPacketPoolError {
    /// Requested active slots exceed `MAX_SLOTS`.
    CapacityTooLarge,
    /// Allocator could not provide all slots for an atomic growth step.
    AllocationFailed,
}

/// Platform allocation and deallocation hooks used by [`HeapPacketPool`].
#[derive(Clone, Copy)]
pub struct HeapPacketAllocator {
    allocate: fn(usize) -> *mut u8,
    deallocate: unsafe fn(*mut u8, usize),
}

impl HeapPacketAllocator {
    /// Define custom platform allocation and deallocation callbacks.
    ///
    /// # Safety
    ///
    /// - `allocate(size)` must return either null (on allocation failure) or a non-null pointer
    ///   uniquely valid for reads and writes of `size` initialized bytes across threads (`Send + Sync`).
    /// - `deallocate(ptr, size)` must safely reclaim any non-null pointer previously returned by
    ///   `allocate(size)` with the exact same `size`.
    pub const unsafe fn new(
        allocate: fn(usize) -> *mut u8,
        deallocate: unsafe fn(*mut u8, usize),
    ) -> Self {
        Self {
            allocate,
            deallocate,
        }
    }

    /// Use Rust's global allocator (`alloc::vec::Vec` / `Box`).
    pub const fn global() -> Self {
        // SAFETY: `global_allocate` produces a zero-initialized `Box<[u8]>` of `bytes` length and
        // `global_deallocate` reconstructs and drops `Box<[u8]>` with that exact `(ptr, bytes)`.
        unsafe { Self::new(global_allocate, global_deallocate) }
    }
}

fn global_allocate(bytes: usize) -> *mut u8 {
    let mut storage = Vec::new();
    if storage.try_reserve_exact(bytes).is_err() {
        return ptr::null_mut();
    }
    storage.resize(bytes, 0);
    Box::into_raw(storage.into_boxed_slice()).cast::<u8>()
}

unsafe fn global_deallocate(buffer: *mut u8, bytes: usize) {
    let slice = ptr::slice_from_raw_parts_mut(buffer, bytes);
    unsafe { drop(Box::from_raw(slice)) };
}

struct PendingHeapSlot<const MTU: usize> {
    slot: usize,
    buffer: *mut u8,
    deallocate: unsafe fn(*mut u8, usize),
}

impl<const MTU: usize> Drop for PendingHeapSlot<MTU> {
    fn drop(&mut self) {
        if !self.buffer.is_null() {
            unsafe { (self.deallocate)(self.buffer, MTU) };
        }
    }
}

/// Dynamically resizable heap-backed packet pool.
pub struct HeapPacketPool<const MAX_SLOTS: usize, const MTU: usize = DEFAULT_SLOT_SIZE> {
    lock: AtomicBool,
    capacity: AtomicUsize,
    headroom: usize,
    max_payload: usize,
    buffers: [AtomicPtr<u8>; MAX_SLOTS],
    references: [AtomicU8; MAX_SLOTS],
    allocator: HeapPacketAllocator,
    _exclusive_write: UnsafeCell<()>,
}

// SAFETY: Slot buffers are heap allocations owned by `HeapPacketPool`. Mutable access (`slot_slice_mut`)
// requires `references[slot] == 1` and `&mut HeapPacketLease` (`HeapPacketLease` is `!Sync`), preventing
// any concurrent `try_clone(&self)` or `slot_slice(&self)`. Slot retirement only deallocates when
// `references[slot] == 0` under `HeapPoolGuard`.
unsafe impl<const MAX_SLOTS: usize, const MTU: usize> Sync for HeapPacketPool<MAX_SLOTS, MTU> {}
unsafe impl<const MAX_SLOTS: usize, const MTU: usize> Send for HeapPacketPool<MAX_SLOTS, MTU> {}

impl<const MAX_SLOTS: usize, const MTU: usize> HeapPacketPool<MAX_SLOTS, MTU> {
    /// Create an empty pool using Rust's global allocator. Call [`Self::resize`] to activate slots.
    pub const fn new() -> Self {
        Self::new_with_allocator(HeapPacketAllocator::global())
    }

    /// Create an empty pool using custom platform allocation callbacks.
    pub const fn new_with_allocator(allocator: HeapPacketAllocator) -> Self {
        assert!(MAX_SLOTS > 0 && MAX_SLOTS <= u8::MAX as usize);
        Self {
            lock: AtomicBool::new(false),
            capacity: AtomicUsize::new(0),
            headroom: DEFAULT_HEADROOM,
            max_payload: MTU.saturating_sub(DEFAULT_HEADROOM + DEFAULT_TAIL),
            buffers: [const { AtomicPtr::new(ptr::null_mut()) }; MAX_SLOTS],
            references: [const { AtomicU8::new(HEAP_WRITER) }; MAX_SLOTS],
            allocator,
            _exclusive_write: UnsafeCell::new(()),
        }
    }

    /// Change active slot capacity. Growth allocates each new slot before taking the lock;
    /// shrinking frees idle slots immediately and retires leased slots on final drop.
    pub fn resize(&self, target: usize) -> Result<(), HeapPacketPoolError> {
        if target > MAX_SLOTS {
            return Err(HeapPacketPoolError::CapacityTooLarge);
        }
        let current = self.capacity();
        if target > current {
            let mut pending: Vec<PendingHeapSlot<MTU>> = Vec::new();
            pending
                .try_reserve_exact(target - current)
                .map_err(|_| HeapPacketPoolError::AllocationFailed)?;
            for slot in current..target {
                if self.buffers[slot].load(Ordering::Acquire).is_null() {
                    let buf = (self.allocator.allocate)(MTU);
                    if buf.is_null() {
                        return Err(HeapPacketPoolError::AllocationFailed);
                    }
                    pending.push(PendingHeapSlot {
                        slot,
                        buffer: buf,
                        deallocate: self.allocator.deallocate,
                    });
                }
            }
            let _guard = self.guard();
            for mut p in pending {
                if self.buffers[p.slot].load(Ordering::Relaxed).is_null() {
                    self.buffers[p.slot].store(p.buffer, Ordering::Release);
                    self.references[p.slot].store(0, Ordering::Release);
                    p.buffer = ptr::null_mut();
                }
            }
            self.capacity.store(target, Ordering::Release);
            self.reclaim_retired_locked(target);
            return Ok(());
        }
        let _guard = self.guard();
        self.capacity.store(target, Ordering::Release);
        for slot in target..current {
            if self.references[slot].load(Ordering::Acquire) == 0 {
                self.retire_locked(slot);
            }
        }
        self.reclaim_retired_locked(target);
        Ok(())
    }

    /// Grow only from RAM available above `reserve_bytes`.
    pub fn resize_with_budget(
        &self,
        target: usize,
        available_bytes: usize,
        reserve_bytes: usize,
    ) -> Result<usize, HeapPacketPoolError> {
        if target > MAX_SLOTS {
            return Err(HeapPacketPoolError::CapacityTooLarge);
        }
        let current = self.capacity();
        if target <= current {
            self.resize(target)?;
            return Ok(target);
        }
        let slot_bytes = MTU.saturating_add(HEAP_PACKET_SLOT_OVERHEAD).max(1);
        let affordable = available_bytes.saturating_sub(reserve_bytes) / slot_bytes;
        let admitted = target.min(current.saturating_add(affordable));
        for cap in (current + 1)..=admitted {
            if self.resize(cap).is_err() {
                return Ok(self.capacity());
            }
        }
        Ok(self.capacity())
    }

    /// Worker/task maintenance for a free-packet target (`target_free`).
    pub fn maintain_free(
        &self,
        target_free: usize,
        device_limit: usize,
        available_bytes: usize,
        largest_free_block: usize,
        reserve_bytes: usize,
    ) -> Result<usize, HeapPacketPoolError> {
        if device_limit > MAX_SLOTS {
            return Err(HeapPacketPoolError::CapacityTooLarge);
        }
        let in_use = self.in_use();
        let desired = in_use.saturating_add(target_free).min(device_limit);
        if desired <= self.capacity() {
            self.resize(desired)?;
            return Ok(self.capacity());
        }
        let slot_bytes = MTU.saturating_add(HEAP_PACKET_SLOT_OVERHEAD).max(1);
        if largest_free_block < slot_bytes {
            return Ok(self.capacity());
        }
        self.resize_with_budget(desired, available_bytes, reserve_bytes)
    }

    /// Active slot capacity.
    pub fn capacity(&self) -> usize {
        self.capacity.load(Ordering::Acquire)
    }

    /// Number of slots currently owning heap storage (including retired slots still leased).
    pub fn allocated(&self) -> usize {
        self.buffers
            .iter()
            .filter(|b| !b.load(Ordering::Acquire).is_null())
            .count()
    }

    /// Number of active slots currently free.
    pub fn available(&self) -> usize {
        let cap = self.capacity();
        self.references[..cap]
            .iter()
            .filter(|r| r.load(Ordering::Acquire) == 0)
            .count()
    }

    /// Number of slots currently in use.
    pub fn in_use(&self) -> usize {
        self.references
            .iter()
            .filter(|r| {
                let v = r.load(Ordering::Acquire);
                v != 0 && v != HEAP_WRITER
            })
            .count()
    }

    /// Acquire a lease while leaving `reserved` active slots free. Never spins on resize lock.
    pub fn acquire_reserving(
        &self,
        reserved: usize,
    ) -> Result<HeapPacketLease<'_, MAX_SLOTS, MTU>, PoolError> {
        let _guard = self.try_guard().ok_or(PoolError::Exhausted)?;
        let cap = self.capacity.load(Ordering::Relaxed);
        let avail = self.references[..cap]
            .iter()
            .filter(|r| r.load(Ordering::Relaxed) == 0)
            .count();
        if avail <= reserved {
            return Err(PoolError::Exhausted);
        }
        let slot = self.references[..cap]
            .iter()
            .position(|r| r.load(Ordering::Relaxed) == 0)
            .ok_or(PoolError::Exhausted)?;
        self.references[slot].store(1, Ordering::Release);
        Ok(HeapPacketLease {
            pool: self,
            slot: slot as u8,
            range: self.headroom..self.headroom,
            _not_sync: PhantomData,
        })
    }

    fn guard(&self) -> HeapPoolGuard<'_> {
        while self
            .lock
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        HeapPoolGuard { lock: &self.lock }
    }

    fn try_guard(&self) -> Option<HeapPoolGuard<'_>> {
        self.lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| HeapPoolGuard { lock: &self.lock })
    }

    fn retire_locked(&self, slot: usize) {
        self.references[slot].store(HEAP_WRITER, Ordering::Release);
        let buf = self.buffers[slot].swap(ptr::null_mut(), Ordering::AcqRel);
        if !buf.is_null() {
            unsafe { (self.allocator.deallocate)(buf, MTU) };
        }
    }

    fn final_release(&self, slot: usize) {
        if slot < self.capacity() {
            return;
        }
        let Some(_guard) = self.try_guard() else {
            return;
        };
        if slot >= self.capacity() && self.references[slot].load(Ordering::Acquire) == 0 {
            self.retire_locked(slot);
        }
    }

    fn reclaim_retired_locked(&self, capacity: usize) {
        for slot in capacity..MAX_SLOTS {
            if self.references[slot].load(Ordering::Acquire) == 0
                && !self.buffers[slot].load(Ordering::Acquire).is_null()
            {
                self.retire_locked(slot);
            }
        }
    }
}

impl<const MAX_SLOTS: usize, const MTU: usize> Default for HeapPacketPool<MAX_SLOTS, MTU> {
    fn default() -> Self {
        Self::new()
    }
}

struct HeapPoolGuard<'a> {
    lock: &'a AtomicBool,
}

impl Drop for HeapPoolGuard<'_> {
    fn drop(&mut self) {
        self.lock.store(false, Ordering::Release);
    }
}

/// Reference-counted packet lease from a [`HeapPacketPool`].
///
/// Intentionally `Send` + `!Sync` so `&mut self` + `references[slot] == 1` guarantees exclusive
/// mutable access with no concurrent `try_clone(&self)` or `slot_slice(&self)` on another thread.
pub struct HeapPacketLease<'a, const MAX_SLOTS: usize, const MTU: usize = DEFAULT_SLOT_SIZE> {
    pool: &'a HeapPacketPool<MAX_SLOTS, MTU>,
    slot: u8,
    range: Range<usize>,
    _not_sync: PhantomData<*const ()>,
}

// SAFETY: Moving a `HeapPacketLease` across threads is safe because `HeapPacketPool` is `Sync`
// and reference counting / retirement synchronize via `AcqRel` atomics.
unsafe impl<const MAX_SLOTS: usize, const MTU: usize> Send for HeapPacketLease<'_, MAX_SLOTS, MTU> {}

impl<const MAX_SLOTS: usize, const MTU: usize> core::fmt::Debug
    for HeapPacketLease<'_, MAX_SLOTS, MTU>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HeapPacketLease")
            .field("slot", &self.slot)
            .field("range", &self.range)
            .finish()
    }
}

impl<const MAX_SLOTS: usize, const MTU: usize> PoolPacket for HeapPacketLease<'_, MAX_SLOTS, MTU> {
    fn slot_slice(&self) -> &[u8] {
        let idx = self.slot as usize;
        let refs = self.pool.references[idx].load(Ordering::Acquire);
        debug_assert!(refs >= 1 && refs < HEAP_WRITER);
        let ptr = self.pool.buffers[idx].load(Ordering::Acquire);
        debug_assert!(!ptr.is_null());
        // SAFETY: `self` owns an active reference (`1 <= refs < HEAP_WRITER`), keeping `buffers[idx]`
        // live, and `!Sync` + `slot_slice_mut`'s `refs == 1` check preclude any coexisting `&mut [u8]`.
        unsafe { core::slice::from_raw_parts(ptr, MTU) }
    }

    fn slot_slice_mut(&mut self) -> Result<&mut [u8], PoolError> {
        let idx = self.slot as usize;
        if self.pool.references[idx].load(Ordering::Acquire) != 1 {
            return Err(PoolError::Shared);
        }
        let ptr = self.pool.buffers[idx].load(Ordering::Acquire);
        if ptr.is_null() {
            return Err(PoolError::InvalidRange);
        }
        // SAFETY: `references[idx] == 1` + `&'a mut self` + `!Sync` guarantee no other lease or
        // shared borrow of `self` exists on any thread for `'a`.
        Ok(unsafe { core::slice::from_raw_parts_mut(ptr, MTU) })
    }

    fn range(&self) -> Range<usize> {
        self.range.clone()
    }

    fn set_range(&mut self, range: Range<usize>) -> Result<(), PoolError> {
        if range.start > range.end || range.end > MTU {
            return Err(PoolError::InvalidRange);
        }
        self.range = range;
        Ok(())
    }

    fn is_unique(&self) -> bool {
        self.pool.references[self.slot as usize].load(Ordering::Acquire) == 1
    }

    fn try_clone(&self) -> Result<Self, PoolError> {
        let refs = &self.pool.references[self.slot as usize];
        let mut cur = refs.load(Ordering::Acquire);
        loop {
            if cur == 0 || cur >= HEAP_WRITER - 1 {
                return Err(PoolError::Exhausted);
            }
            match refs.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(Self {
                        pool: self.pool,
                        slot: self.slot,
                        range: self.range.clone(),
                        _not_sync: PhantomData,
                    });
                }
                Err(observed) => cur = observed,
            }
        }
    }
}

impl<const MAX_SLOTS: usize, const MTU: usize> Drop for HeapPacketLease<'_, MAX_SLOTS, MTU> {
    fn drop(&mut self) {
        let idx = self.slot as usize;
        if self.pool.references[idx].fetch_sub(1, Ordering::AcqRel) == 1 {
            self.pool.final_release(idx);
        }
    }
}

impl<'a, const MAX_SLOTS: usize, const MTU: usize> PacketPool
    for &'a HeapPacketPool<MAX_SLOTS, MTU>
{
    type Packet = HeapPacketLease<'a, MAX_SLOTS, MTU>;

    fn headroom(&self) -> usize {
        self.headroom
    }

    fn max_payload(&self) -> usize {
        self.max_payload
    }

    fn alloc(&self) -> Result<Self::Packet, PoolError> {
        self.acquire_reserving(0)
    }

    fn alloc_reserving(&self, reserved: usize) -> Result<Self::Packet, PoolError> {
        self.acquire_reserving(reserved)
    }

    fn available(&self) -> usize {
        HeapPacketPool::available(self)
    }
}

// ============================================================================
// 3. XipLazyPool (replicates ESP-XIP `xip_pool.c` & `xip-runtime-host::pool::Pool`)
// ============================================================================

/// Generation-tagged packet handle descriptor matching `xip_packet_ref` in `xip_pool.h`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XipPacketRef {
    /// Slot index (`0..slots`).
    pub slot: u16,
    /// Start offset within the slot.
    pub start: u16,
    /// Initialized payload length.
    pub len: u16,
}

struct XipLazyInner {
    slots: u16,
    slot_size: usize,
    headroom: usize,
    max_payload: usize,
    keep: AtomicU16,
    free_count: AtomicU32,
    buffers: AtomicU32,
    refs: Box<[AtomicU32]>,
    mem: Box<[AtomicPtr<u8>]>,
    generations: Box<[AtomicU16]>,
    packets: Box<[AtomicU32]>, // packs (start: u16) << 16 | (len: u16)
    free_heap: Option<fn() -> usize>,
    reserve_bytes: usize,
}

impl Drop for XipLazyInner {
    fn drop(&mut self) {
        for ptr_cell in self.mem.iter() {
            let p = ptr_cell.swap(ptr::null_mut(), Ordering::AcqRel);
            if !p.is_null() {
                unsafe { global_deallocate(p, self.slot_size) };
            }
        }
    }
}

/// Thread-safe Rust implementation of the ESP-XIP C runtime pool (`xip_pool.c` / `xip-runtime-host::pool::Pool`).
///
/// Key properties matching `xip_pool.c`:
/// - **Two-pass cached-first acquisition (`acquire` / `acquire_cached`):** Pass 0 claims an idle
///   slot that already holds an allocated buffer (`mem[i] != NULL`), avoiding heap allocation in
///   the steady state. Pass 1 allocates a buffer on demand if `free_heap() >= slot_size + reserve_bytes`.
/// - **Idle warm cache (`keep`, default `2`):** When the last reference to a slot is released
///   (`refs: 1 -> 0`), if `buffers + 1 > in_use + keep`, the slot's buffer is freed immediately;
///   otherwise it stays cached for future Pass-0 acquisitions.
/// - **`trim()` and `prepare_rx()`:** Explicit cache shrinking and pre-warming.
/// - **16-bit per-slot generation counter (`handle` / `get_handle`):** Prevents ABA stale handles.
#[derive(Clone)]
pub struct XipLazyPool {
    inner: Arc<XipLazyInner>,
}

/// Alias preserving compatibility with existing `SlabPool` callers.
pub type SlabPool = XipLazyPool;
/// Alias preserving compatibility with existing `SlabPacket` callers.
pub type SlabPacket = XipLazyPacket;

/// Packet lease allocated from [`XipLazyPool`].
///
/// Intentionally `Send` + `!Sync` (`PhantomData<*const ()>`): cross-thread sharing uses
/// [`PoolPacket::try_clone`], ensuring `&mut self` + `refs == 1` provides non-aliased exclusive
/// access to the underlying slot buffer.
pub struct XipLazyPacket {
    pool: Arc<XipLazyInner>,
    slot_idx: usize,
    range: Range<usize>,
    _not_sync: PhantomData<*const ()>,
}

// SAFETY: Moving `XipLazyPacket` across threads is safe because `XipLazyInner` synchronizes
// slot ownership and buffer lifetime via `AcqRel` atomics.
unsafe impl Send for XipLazyPacket {}

impl XipLazyPool {
    /// Create a pool with `capacity` slots of `(headroom, max_payload, tail)` and `keep = 2` warm idle slots.
    pub fn new(capacity: usize, headroom: usize, max_payload: usize, tail: usize) -> Self {
        let slots = u16::try_from(capacity.max(1)).unwrap_or(u16::MAX);
        let slot_size = headroom + max_payload + tail;
        let mut refs = Vec::with_capacity(slots as usize);
        let mut mem = Vec::with_capacity(slots as usize);
        let mut generations = Vec::with_capacity(slots as usize);
        let mut packets = Vec::with_capacity(slots as usize);
        for _ in 0..slots {
            refs.push(AtomicU32::new(0));
            mem.push(AtomicPtr::new(ptr::null_mut()));
            generations.push(AtomicU16::new(0));
            packets.push(AtomicU32::new(0));
        }
        Self {
            inner: Arc::new(XipLazyInner {
                slots,
                slot_size,
                headroom,
                max_payload,
                keep: AtomicU16::new(2),
                free_count: AtomicU32::new(u32::from(slots)),
                buffers: AtomicU32::new(0),
                refs: refs.into_boxed_slice(),
                mem: mem.into_boxed_slice(),
                generations: generations.into_boxed_slice(),
                packets: packets.into_boxed_slice(),
                free_heap: None,
                reserve_bytes: 0,
            }),
        }
    }

    /// Create a pool with default ESP-XIP geometry (`144` headroom, `1500` max payload, `60` tail).
    pub fn with_default_geometry(capacity: usize) -> Self {
        Self::new(capacity, DEFAULT_HEADROOM, DEFAULT_MAX_PAYLOAD, DEFAULT_TAIL)
    }

    /// Create a pool with a custom `free_heap` callback and `reserve_bytes` floor.
    pub fn with_heap_policy(
        capacity: usize,
        keep: u16,
        free_heap: fn() -> usize,
        reserve_bytes: usize,
    ) -> Self {
        let mut p = Self::with_default_geometry(capacity);
        if let Some(inner) = Arc::get_mut(&mut p.inner) {
            inner.keep.store(keep, Ordering::Relaxed);
            inner.free_heap = Some(free_heap);
            inner.reserve_bytes = reserve_bytes;
        }
        p
    }

    /// Total number of slots in the pool.
    #[inline]
    pub fn slots(&self) -> u16 {
        self.inner.slots
    }

    /// Byte size of each slot.
    #[inline]
    pub fn slot_size(&self) -> usize {
        self.inner.slot_size
    }

    /// Set the number of idle slots that retain their heap buffer (`keep`, default `2`).
    #[inline]
    pub fn set_keep(&self, keep: u16) {
        self.inner.keep.store(keep, Ordering::Release);
    }

    /// Current `keep` setting.
    #[inline]
    pub fn keep(&self) -> u16 {
        self.inner.keep.load(Ordering::Acquire)
    }

    /// Number of slots currently holding allocated buffers (in use + warm idle).
    #[inline]
    pub fn allocated(&self) -> usize {
        self.inner.buffers.load(Ordering::Acquire) as usize
    }

    /// Number of idle slots that currently hold a pre-allocated buffer ready for zero-malloc acquisition.
    pub fn cached_available(&self) -> usize {
        let mut n = 0usize;
        for i in 0..self.inner.slots as usize {
            if !self.inner.mem[i].load(Ordering::Acquire).is_null()
                && self.inner.refs[i].load(Ordering::Acquire) == 0
            {
                n += 1;
            }
        }
        n
    }

    /// Pre-allocate up to `keep` (capped at 32) warm idle slot buffers (matching `xip_pool_prepare_rx`).
    pub fn prepare_rx(&self) {
        self.prewarm(usize::from(self.keep()).min(32));
    }

    /// Pre-allocate up to `target` warm idle slot buffers so steady-state transfers do not
    /// allocate from the global heap during bursts.
    pub fn prewarm(&self, target: usize) {
        let cap = target.min(self.inner.slots as usize);
        let mut held = Vec::with_capacity(cap);
        for _ in 0..cap {
            let Some(slot) = self.acquire_slot(0, 2) else {
                break;
            };
            held.push(slot);
        }
        for slot in held {
            self.release_slot(slot);
        }
    }

    /// Free idle slot buffers above `keep` (matching `xip_pool_trim`).
    pub fn trim(&self) {
        let slots = u32::from(self.inner.slots);
        for i in 0..self.inner.slots as usize {
            let keep = u32::from(self.inner.keep.load(Ordering::Acquire));
            let in_use = slots.saturating_sub(self.inner.free_count.load(Ordering::Acquire));
            if self.inner.buffers.load(Ordering::Acquire) <= keep + in_use {
                return;
            }
            if self.inner.mem[i].load(Ordering::Acquire).is_null() {
                continue;
            }
            if self.inner.refs[i]
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let old = self.inner.mem[i].swap(ptr::null_mut(), Ordering::AcqRel);
                if !old.is_null() {
                    unsafe { global_deallocate(old, self.inner.slot_size) };
                    self.inner.buffers.fetch_sub(1, Ordering::AcqRel);
                }
                self.inner.refs[i].store(0, Ordering::Release);
            }
        }
    }

    /// Acquire a slot only from already-allocated warm idle buffers (`allocate = 0`, matching `xip_pool_acquire_cached`).
    pub fn acquire_cached(&self, reserve: usize) -> Result<XipLazyPacket, PoolError> {
        let slot = self.acquire_slot(reserve, 0).ok_or(PoolError::Exhausted)?;
        let h = self.inner.headroom;
        Ok(XipLazyPacket {
            pool: self.inner.clone(),
            slot_idx: slot,
            range: h..h,
            _not_sync: PhantomData,
        })
    }

    /// Encode a 32-bit generation-checked handle `((generation & 0xffff) << 16) | (slot + 1)`
    /// (matching `xip_packet_handle`).
    pub fn packet_handle(&self, pkt: &XipLazyPacket) -> u32 {
        let slot = pkt.slot_idx;
        if self.inner.refs[slot].load(Ordering::Acquire) == 0 {
            return 0;
        }
        let start = pkt.range.start as u16;
        let len = pkt.range.len() as u16;
        self.inner.packets[slot].store(
            (u32::from(start) << 16) | u32::from(len),
            Ordering::Release,
        );
        let generation = u32::from(self.inner.generations[slot].load(Ordering::Acquire));
        ((generation & 0xffff) << 16) | ((slot as u32) + 1)
    }

    /// Resolve a 32-bit generation-checked handle (matching `xip_packet_get`).
    pub fn get_handle(&self, handle: u32) -> Option<XipPacketRef> {
        let index = (handle & 0xffff).checked_sub(1)? as usize;
        if index >= self.inner.slots as usize {
            return None;
        }
        if self.inner.refs[index].load(Ordering::Acquire) == 0 {
            return None;
        }
        let generation = u32::from(self.inner.generations[index].load(Ordering::Acquire));
        if generation != (handle >> 16) {
            return None;
        }
        let packed = self.inner.packets[index].load(Ordering::Acquire);
        Some(XipPacketRef {
            slot: index as u16,
            start: (packed >> 16) as u16,
            len: (packed & 0xffff) as u16,
        })
    }

    fn claim_slot(&self, i: usize, allocate: u8) -> i8 {
        if self.inner.refs[i]
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return 0;
        }
        let existing = self.inner.mem[i].load(Ordering::Acquire);
        if allocate == 2 && !existing.is_null() {
            self.inner.refs[i].store(0, Ordering::Release);
            return 0;
        }
        if existing.is_null() {
            if allocate == 0 {
                self.inner.refs[i].store(0, Ordering::Release);
                return 0;
            }
            if let Some(free_heap) = self.inner.free_heap {
                if free_heap() < self.inner.slot_size.saturating_add(self.inner.reserve_bytes) {
                    self.inner.refs[i].store(0, Ordering::Release);
                    return -1;
                }
            }
            let buf = global_allocate(self.inner.slot_size);
            if buf.is_null() {
                self.inner.refs[i].store(0, Ordering::Release);
                return -1;
            }
            self.inner.mem[i].store(buf, Ordering::Release);
            self.inner.buffers.fetch_add(1, Ordering::AcqRel);
        }
        1
    }

    fn acquire_slot(&self, reserve: usize, allocate: u8) -> Option<usize> {
        let mut n = self.inner.free_count.load(Ordering::Acquire);
        loop {
            if (n as usize) <= reserve {
                return None;
            }
            match self.inner.free_count.compare_exchange_weak(
                n,
                n - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(obs) => n = obs,
            }
        }

        let start_pass = if allocate == 2 { 1 } else { 0 };
        for pass in start_pass..2 {
            for i in 0..self.inner.slots as usize {
                let has_mem = !self.inner.mem[i].load(Ordering::Acquire).is_null();
                if pass == 0 && !has_mem {
                    continue;
                }
                if allocate == 2 && has_mem {
                    continue;
                }
                let c = self.claim_slot(i, allocate);
                if c > 0 {
                    self.inner.generations[i].fetch_add(1, Ordering::AcqRel);
                    return Some(i);
                }
                if c < 0 {
                    self.inner.free_count.fetch_add(1, Ordering::AcqRel);
                    return None;
                }
            }
        }
        self.inner.free_count.fetch_add(1, Ordering::AcqRel);
        None
    }

    fn release_slot(&self, slot: usize) {
        release_xip_inner(&self.inner, slot);
    }
}

fn release_xip_inner(inner: &XipLazyInner, slot: usize) {
    if slot >= inner.slots as usize {
        return;
    }
    let mut r = inner.refs[slot].load(Ordering::Acquire);
    loop {
        if r == 0 {
            return;
        }
        if r > 1 {
            match inner.refs[slot].compare_exchange_weak(
                r,
                r - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(obs) => {
                    r = obs;
                    continue;
                }
            }
        }
        // Last reference (r == 1): free buffer first if `buffers + 1 > in_use + keep`
        let in_use =
            u32::from(inner.slots).saturating_sub(inner.free_count.load(Ordering::Acquire));
        let buffers = inner.buffers.load(Ordering::Acquire);
        let keep = u32::from(inner.keep.load(Ordering::Acquire));
        if buffers + 1 > in_use + keep {
            let old = inner.mem[slot].swap(ptr::null_mut(), Ordering::AcqRel);
            if !old.is_null() {
                unsafe { global_deallocate(old, inner.slot_size) };
                inner.buffers.fetch_sub(1, Ordering::AcqRel);
            }
        }
        inner.refs[slot].store(0, Ordering::Release);
        inner.free_count.fetch_add(1, Ordering::AcqRel);
        return;
    }
}

impl PacketPool for XipLazyPool {
    type Packet = XipLazyPacket;

    fn headroom(&self) -> usize {
        self.inner.headroom
    }

    fn max_payload(&self) -> usize {
        self.inner.max_payload
    }

    fn alloc(&self) -> Result<Self::Packet, PoolError> {
        self.alloc_reserving(0)
    }

    fn alloc_reserving(&self, reserved: usize) -> Result<Self::Packet, PoolError> {
        let slot = self
            .acquire_slot(reserved, 1)
            .ok_or(PoolError::Exhausted)?;
        let h = self.inner.headroom;
        Ok(XipLazyPacket {
            pool: self.inner.clone(),
            slot_idx: slot,
            range: h..h,
            _not_sync: PhantomData,
        })
    }

    fn available(&self) -> usize {
        self.inner.free_count.load(Ordering::Acquire) as usize
    }
}

impl XipLazyPacket {
    /// Raw memory address of the start of the underlying slot (for zero-copy verification).
    pub fn slot_ptr(&self) -> *const u8 {
        self.slot_slice().as_ptr()
    }

    /// Raw memory address of the active payload start (for zero-copy verification).
    pub fn payload_ptr(&self) -> *const u8 {
        self.bytes().as_ptr()
    }

    /// Slot index within the pool (`0..slots`).
    pub const fn slot_index(&self) -> usize {
        self.slot_idx
    }
}

impl PoolPacket for XipLazyPacket {
    fn slot_slice(&self) -> &[u8] {
        debug_assert!(self.pool.refs[self.slot_idx].load(Ordering::Acquire) >= 1);
        let ptr = self.pool.mem[self.slot_idx].load(Ordering::Acquire);
        debug_assert!(!ptr.is_null());
        // SAFETY: `ptr` is non-null and valid for `slot_size` bytes while `refs >= 1`.
        // Because `XipLazyPacket` is `!Sync`, if `&self` is borrowed here, either `refs == 1`
        // (and Rust's borrow checker precludes `&mut self` / `slot_slice_mut` concurrently)
        // or `refs > 1` (and `slot_slice_mut` rejects all leases with `PoolError::Shared`).
        unsafe { core::slice::from_raw_parts(ptr, self.pool.slot_size) }
    }

    fn slot_slice_mut(&mut self) -> Result<&mut [u8], PoolError> {
        if self.pool.refs[self.slot_idx].load(Ordering::Acquire) != 1 {
            return Err(PoolError::Shared);
        }
        let ptr = self.pool.mem[self.slot_idx].load(Ordering::Acquire);
        if ptr.is_null() {
            return Err(PoolError::InvalidRange);
        }
        // SAFETY: `refs == 1` + `&'a mut self` + `!Sync` guarantee exclusive access to `mem[slot_idx]`
        // with no concurrent `try_clone(&self)` or `slot_slice(&self)` on any thread.
        Ok(unsafe { core::slice::from_raw_parts_mut(ptr, self.pool.slot_size) })
    }

    fn range(&self) -> Range<usize> {
        self.range.clone()
    }

    fn set_range(&mut self, range: Range<usize>) -> Result<(), PoolError> {
        if range.start > range.end || range.end > self.pool.slot_size {
            return Err(PoolError::InvalidRange);
        }
        self.range = range;
        Ok(())
    }

    fn is_unique(&self) -> bool {
        self.pool.refs[self.slot_idx].load(Ordering::Acquire) == 1
    }

    fn try_clone(&self) -> Result<Self, PoolError> {
        let refs = &self.pool.refs[self.slot_idx];
        let mut cur = refs.load(Ordering::Acquire);
        loop {
            if cur == 0 || cur == u32::MAX {
                return Err(PoolError::Exhausted);
            }
            match refs.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(Self {
                        pool: self.pool.clone(),
                        slot_idx: self.slot_idx,
                        range: self.range.clone(),
                        _not_sync: PhantomData,
                    });
                }
                Err(observed) => cur = observed,
            }
        }
    }
}

impl core::fmt::Debug for XipLazyPacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XipLazyPacket")
            .field("slot_idx", &self.slot_idx)
            .field("range", &self.range)
            .finish()
    }
}

impl Drop for XipLazyPacket {
    fn drop(&mut self) {
        release_xip_inner(&self.pool, self.slot_idx);
    }
}
}

#[cfg(any(feature = "std", feature = "host-pools", test))]
pub use host_pools::{
    HEAP_PACKET_SLOT_OVERHEAD, HeapPacketAllocator, HeapPacketLease, HeapPacketPool,
    HeapPacketPoolError, SlabPacket, SlabPool, StaticPacketLease, StaticPacketPool, XipLazyPacket,
    XipLazyPool, XipPacketRef,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_growth_and_idle_shrink() {
        let mut policy = PacketPoolPolicy::new(8, 128, 8, 2_000);
        assert_eq!(policy.target(0, 0, 0), 8);
        assert_eq!(policy.target(1, 8, 6), 14);
        assert_eq!(policy.target(2, 14, 0), 14);
        assert_eq!(policy.shrink_deadline(), Some(2_002));
        assert_eq!(policy.target(2_001, 14, 0), 14);
        assert_eq!(policy.target(2_002, 14, 0), 8);
    }

    #[test]
    fn pressure_cancels_idle_and_limit_is_enforced() {
        let mut policy = PacketPoolPolicy::new(8, 32, 8, 2_000);
        assert_eq!(policy.target(0, 16, 0), 16);
        assert_eq!(policy.target(1, 16, 8), 16);
        assert_eq!(policy.shrink_deadline(), None);
        assert_eq!(policy.target(2, 16, usize::MAX), 32);
        assert_eq!(policy.target(3, 32, 0), 32);
        assert_eq!(policy.target(2_003, 32, 0), 8);
    }

    #[test]
    fn drained_burst_still_grows_and_later_reclaims() {
        let mut policy = PacketPoolPolicy::new(8, 128, 8, 2_000);
        policy.note_pressure(8);
        assert_eq!(policy.target(0, 8, 0), 16);
        assert_eq!(policy.target(1, 16, 0), 16);
        assert_eq!(policy.target(2_001, 16, 0), 8);
    }
}
