//! Portable statuses for RPC and platform-call callbacks.
//!
//! These values describe transport outcomes, not a hardware ABI. Other callback
//! error codes remain opaque to the evaluator.

/// Invalid argument.
pub const ERR_ARG: i32 = -1;
/// Operation is unsupported.
pub const ERR_UNSUPPORTED: i32 = -2;
/// Resource is busy.
pub const ERR_BUSY: i32 = -5;
/// Output or input exceeds a size limit.
pub const ERR_SIZE: i32 = -8;
