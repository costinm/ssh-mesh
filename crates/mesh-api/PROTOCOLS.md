# Mesh protocols and transports

This is the shared contract for mesh APIs. Individual `API.md` files define
components, methods, request fields, response fields, authorization, and
platform-specific behavior; they do not redefine these transports or record
encodings.

## Transports

### Unix-domain sockets (UDS)

Local services normally expose an AF_UNIX socket. `SO_PEERCRED` authenticates
the kernel-reported local peer identity. The socket pathname and authorization
policy are service-specific.

`SOCK_STREAM` supports JSON-RPC and structured text lines, using first byte
in the connection to detect - '{' for JSON, ASCII letter for text.

A 0x00 followed by 3 bytes length is also supported with binary content.

`SOCK_SEQPACKET` is the programmatic local CBOR transport when an operation
needs file descriptors. One complete tagged-CBOR record and its `SCM_RIGHTS`
ancillary data form one packet; receivers reject truncated packets or
descriptor control messages. CBOR encodes request data, not OS descriptor
numbers—the UDS ancillary message transfers the descriptors.

The stream and seqpacket endpoints have distinct paths because a Unix path can
name only one socket type. Services retain legacy stream endpoints while
clients migrate.

### SSH

SSH is a remote user transport. SSH services authenticate the remote principal
then use local mesh APIs under their own authenticated UDS peer identity.

### HTTP/1.1

HTTP/1.1 is used in gateways and in ssh-mesh per-node server - authenticate using 
Authorization, Cookie or mTLS and may forward over one of the local protocol (UDS, virtio, 
localhost TCP). Only POST/GET - no duplex streaming supported.

### HTTP/2

Like HTTP/1.1 - but with H2 streaming, same features as SSH in terms of forwarding.

### WebSocket

Like HTTP/1.1 - but supports streaming. 

### QUIC-lite

Specific to device mesh - a subset of QUIC protocol, but with different association
that account for untrusted devices and local addresses - and supports multi-path 
adapted for unreliable/untrusted relays.

## Encodings

### Tagged CBOR

Tagged-CBOR is the primary programmatic record encoding. Every API document's
`mesh-api` blocks assign stable component, method, and field identifiers.
Generated catalogs translate those identifiers to method and field names at
service boundaries. Stream transports add a four-byte big-endian frame length;
seqpacket transports preserve each encoded record as one packet and do not need
an additional framing boundary.

### JSON-RPC

JSON-RPC 2.0 is the human-facing and compatibility gateway: a request carries
`jsonrpc`, `id`, `method`, and object `params`; a response has the matching id
and either `result` or `error`. 

### Text

Text records are a human and shell-friendly gateway (`method key=value`). They
use string method names - may use tags as keys.

### Protobuf

Planned/possible - in particular for Meshtastic and other integrations. Tags in CBOR
should match the tags in proto schema.