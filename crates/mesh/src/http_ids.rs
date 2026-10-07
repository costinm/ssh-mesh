//! Reserved numbers of the `http` component: REST-style requests in the tagged-CBOR envelope.
//!
//! A request is `component = 2002`, `method` = one of the verbs below, `params` = the path (an array
//! of segments, each an unsigned number or a text string), `fields` = the request headers (a map
//! whose keys are unsigned numbers or text), then the raw body on the stream. See
//! `mesh-api/PROTOCOLS.md`, section "HTTP component", and the `http` component in `API.md`. The
//! numbers are protocol constants only: a service decides which resources it serves.

/// The reserved component number, beside `mesh` (2000) and `trace` (2001). Generated from `API.md`.
pub use crate::generated_api_ids::COMPONENT_HTTP;

/// Verbs, numbered as the CoAP request codes (RFC 7252 / 8132) so a CoAP gateway maps one to one.
/// Generated from `API.md`.
pub use crate::generated_api_ids::{
    METHOD_HTTP_DELETE as METHOD_DELETE, METHOD_HTTP_FETCH as METHOD_FETCH,
    METHOD_HTTP_GET as METHOD_GET, METHOD_HTTP_PATCH as METHOD_PATCH,
    METHOD_HTTP_POST as METHOD_POST, METHOD_HTTP_PUT as METHOD_PUT,
};

/// Canonical lower-case verb names, indexed by `method - 1`.
pub const METHOD_NAMES: [&str; 6] = ["get", "post", "put", "delete", "fetch", "patch"];

/// Header keys 0..=63 are reserved here; a resource defines its own from 64 up (or uses text keys).
pub mod header {
    /// Response only: the status, an HTTP status number (200, 204, 400, 404, 413, 503, ...).
    pub const STATUS: u64 = 0;
    /// The number of body bytes that follow the header (request or response).
    pub const CONTENT_LENGTH: u64 = 1;
    /// Media type of the body: a text string, or a CoAP content-format number.
    pub const CONTENT_TYPE: u64 = 2;
    /// First key a resource may define for its own headers.
    pub const APPLICATION_BASE: u64 = 64;

    /// The text spelling of each reserved key, for JSON/HTTP gateways.
    pub const NAMES: [(u64, &str); 3] =
        [(STATUS, "status"), (CONTENT_LENGTH, "content-length"), (CONTENT_TYPE, "content-type")];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbs_follow_the_coap_request_codes_and_names_line_up() {
        assert_eq!(
            [METHOD_GET, METHOD_POST, METHOD_PUT, METHOD_DELETE, METHOD_FETCH, METHOD_PATCH],
            [1, 2, 3, 4, 5, 6]
        );
        assert_eq!(METHOD_NAMES[(METHOD_POST - 1) as usize], "post");
        assert_eq!(COMPONENT_HTTP, 2002);
    }
}
