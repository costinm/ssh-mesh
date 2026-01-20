//! PMON (Process Monitor) module for monitoring system processes

pub mod handlers;
pub mod mcp;

pub mod proc;
pub mod proc_netlink;
pub mod psi;

pub use handlers::handle_ps_request;
pub use proc::{ProcMon, ProcessInfo};
pub use psi::{PressureEvent, PsiWatcher};
