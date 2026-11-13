//! Transport-neutral `#![no_std]` stream workload generator, tagged-CBOR `probe` protocol
//! (`# \`probe\` API (8)`), and optional Tokio stream client helpers (`quic-tools`).
//!
//! Can be driven over any stream or byte-pipe abstraction (`quic-mux`, `quic-link`, `quic-lite`,
//! standard TCP, or UDS) for throughput/integrity diagnostics and stress testing.

#![no_std]
#![deny(missing_docs)]

extern crate alloc;
#[cfg(any(test, feature = "std", feature = "tokio"))]
extern crate std;

/// Passive generated [`mesh_api::ComponentSpec`] and [`mesh_api::MethodSpec`] constants for `probe`.
pub mod generated_specs;
pub mod probe;
pub mod service;
#[cfg(feature = "tokio")]
pub mod stream_client;

pub use generated_specs::{
    COMPONENT_PROBE, COMPONENTS as PROBE_COMPONENTS, METHOD_PROBE_HANDLER, METHOD_PROBE_START,
    PROBE_METHODS,
};

pub use probe::{
    MAX_BYTES, MAX_NORMAL_STREAMS, ProbeChunk, ProbeError, ProbePayload, ProbePlan, ProbeReceiver,
    ProbeRequest, ProbeResult, ProbeRun, ProbeSender,
};
pub use service::{
    DEFAULT_PROBE_MAX_STREAM_PAYLOAD, MAX_PROBE_DESTINATION_URI, PROBE_COMPONENT, PROBE_HANDLER,
    PROBE_REQUEST_MAX, PROBE_START, ProbeClientError, ProbeDestination, ProbeDirection,
    ProbeResponseReader, ProbeServiceRequest, decode_probe_fields, encode_probe_handler_request,
    encode_probe_handler_response, encode_probe_handler_upload_response,
    encode_probe_result_response, encode_probe_result_value, encode_probe_start_request,
    extract_envelope_id, probe_timeout_ms,
};
#[cfg(feature = "tokio")]
pub use stream_client::{
    StreamProbeResult, exchange, probe as probe_stream, probe_duplex, probe_mux,
    serve_framed_probe_stream, serve_probe_stream,
};
