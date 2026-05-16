//! Creates a mesh environment, allowing execution of on-demand services.
//!
//! The `dmesh` crate provides a unified interface to the ssh-mesh ecosystem.
//! Language-specific wrappers are feature-gated:
//!
//! - `jni-wrapper` — JNI bindings for Java/Android (`mesh_jni` module)
//! - `python` — PyO3 bindings for Python (`mesh_python` module)
//!
//! Both wrappers share common logic in `mesh_common`.

// Re-export workspace crates
pub use ssh_mesh;
pub use pmond;
pub use lmesh;
pub use mesh_tun;

pub mod mesh_common;

#[cfg(feature = "jni-wrapper")]
pub mod mesh_jni;

#[cfg(feature = "python")]
pub mod mesh_python;
