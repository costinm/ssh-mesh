//! Compatibility re-export for the transport-neutral mux client.
//!
//! New code should import [`mesh::mux_client::MuxClient`] directly. The
//! implementation moved to `mesh` so local clients do not pull in `russh`.

pub use mesh::mux_client::MuxClient;
