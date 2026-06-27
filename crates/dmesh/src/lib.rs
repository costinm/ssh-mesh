//! Creates a mesh environment, allowing execution of on-demand services.
//!
//! The `dmesh` crate provides a unified interface to the ssh-mesh ecosystem.
//! Language-specific wrappers are feature-gated:
//!
//! - `python` — PyO3 bindings for Python (`mesh_python` module)
//!
//! Java/Android JNI bindings live in the Android dmesh checkout.

// Re-export workspace crates
pub use lmesh;
pub use mesh_tun;
pub use pmond;
pub use ssh_mesh;

pub mod mesh_common;

#[cfg(feature = "python")]
pub mod mesh_python;
