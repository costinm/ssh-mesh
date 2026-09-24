# Shared Mesh API and structures

This crate defines common structures and methods/traits that are common between
Linux and firmware/Android/other platforms and relate to mesh association, circuits, paths, node info.

'Mesh' is defined as an administrative domain containing multiple devices - with zero trust in infrastructure. Multiple Meshes (devices under different control) can communicate and cooperate in data forwarding - still with zero trust.

Core concepts are identity (P-256 or ED25519 key pairs), authentication (including shared secret and per-sender key derivation), path/circuit formation - and a set of protocols that are supported and used in different scenarios.

'Tagged CBOR' is used as primary wire protocol - it has similar features with protobuf but the 
wire format has more structure (inner messages are not 'bytes') and variable-width numbers are
 more efficient on embedded devices - and is used in
various standards like WebAuthn, COAP, etc. It can be mechanically translated 
to JSON - or protobuf - using a schema that maps tags to field names.

JSON-RPC and a structured text format are also available - with automated conversion if schema is available.

## APIs and schemas

The source of truth is an `API.md` file containing ordinary documentation,
examples, component and method headings, and tagged field tables. It defines
the stable tags for each request and response structure without embedding a
second schema language in a code fence.

The main reason is that all APIs need docs - and markdown is more neutral
and friendly than various encoding-specific-schemas. CBOR schemas, protobuf
schemas, ASN.1, JsonSchema/OpenAPI are all great for single-encoding projects,
but the intention is to be encoding and transport neutral - with automated
schema-driven conversions between protocols in gateways when needed or 
negotiation/auto-detection.


