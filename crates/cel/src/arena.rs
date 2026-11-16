use core::{marker::PhantomData, ptr::NonNull};

/// Three-word view borrowing caller-provided scratch storage; it allocates no storage.
/// The caller chooses stack, static, or heap backing; the suspendable Runner uses a heap Vec.
/// Allocations never overlap, remain valid until
/// eval returns, and no reference into the arena is exposed by the public API.
pub(crate) struct Arena<'a> {
    ptr: *mut u8,
    cap: usize,
    pos: usize,
    _borrow: PhantomData<&'a mut [u8]>,
}

impl<'a> Arena<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            ptr: buf.as_mut_ptr(),
            cap: buf.len(),
            pos: 0,
            _borrow: PhantomData,
        }
    }

    fn alloc_raw(&mut self, n: usize) -> Option<NonNull<u8>> {
        let end = self.pos.checked_add(n)?;
        if end > self.cap {
            return None;
        }
        // SAFETY: the range is within the original exclusive buffer, each range
        // is allocated once, and all returned slices die before eval returns.
        let ptr = unsafe { NonNull::new_unchecked(self.ptr.add(self.pos)) };
        self.pos = end;
        Some(ptr)
    }

    pub fn alloc(&mut self, n: usize) -> Option<&'a mut [u8]> {
        let ptr = self.alloc_raw(n)?;
        // SAFETY: alloc_raw reserves this disjoint, in-bounds range for 'a.
        Some(unsafe { core::slice::from_raw_parts_mut(ptr.as_ptr(), n) })
    }

    pub fn remaining(&self) -> usize {
        self.cap - self.pos
    }
    pub fn used(&self) -> usize {
        self.pos
    }

    /// Copy an initialized, finalized allocation into a disjoint output range.
    /// Offsets are checked here; callers never reconstruct pointers or slices
    /// from serialized descriptors. No reference to the source escapes.
    pub fn copy_allocated(&self, offset: usize, out: &mut [u8]) -> Option<()> {
        let end = offset.checked_add(out.len())?;
        if end > self.pos {
            return None;
        }
        let source = (self.ptr as usize).checked_add(offset)?;
        let source_end = source.checked_add(out.len())?;
        let dest = out.as_ptr() as usize;
        let dest_end = dest.checked_add(out.len())?;
        if !out.is_empty() && source < dest_end && dest < source_end {
            return None;
        }
        // SAFETY: the checked range is within the initialized backing buffer;
        // the destination is valid for its length and cannot overlap it. All
        // mutable access to each source chunk has finished before this call.
        unsafe {
            core::ptr::copy_nonoverlapping(self.ptr.add(offset), out.as_mut_ptr(), out.len());
        }
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::Arena;
    #[test]
    fn offsets_copy_only_allocated_disjoint_ranges() {
        let mut storage = [0u8; 16];
        let mut arena = Arena::new(&mut storage);
        let start = arena.used();
        arena.alloc(4).unwrap().copy_from_slice(&[1, 2, 3, 4]);
        let out_start = arena.used();
        let out = arena.alloc(4).unwrap();
        assert_eq!(arena.copy_allocated(start, out), Some(()));
        assert_eq!(out, &[1, 2, 3, 4]);
        assert_eq!(arena.copy_allocated(out_start, out), None);
        assert_eq!(arena.copy_allocated(usize::MAX, out), None);
        assert_eq!(arena.copy_allocated(arena.used(), out), None);
    }
}
