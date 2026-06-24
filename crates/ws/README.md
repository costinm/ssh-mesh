# WebSocket Crate

This crate provides the optional WebSocket transport. HTTP/2 and SSH provide
better multiplexed streaming capabilities - but WS is still useful from
browsers.

WebTansport is based on Quic/H3 and has less adoption, SSE and fetch() are too
limitted - WS is just right.

The use case is mainly tunneling SSH and HTTP/2 over - but a light push, similar 
to SSE is also useful.

Since WS is over encrypted or local connection - SSH with encryption off or H2C 
tunneled over are better options, along with Yamux equivalent.

## Features

- WSServer struct for managing WebSocket connections
- Add/remove/list clients
- Send messages to specific clients or broadcast to all clients
- Proper connection handling and cleanup
- Start the HTTP server on a port with the right config.

## Usage

```rust
use ws::WSServer;
use std::sync::Arc;

let server = Arc::new(WSServer::new());

// Add a client
// (Handled automatically by the WebSocket upgrade handler)

// List clients
let clients = server.list_clients().await;

// Send to specific client
server.send_to_client("client_id", "Hello").await;

// Broadcast to all clients
server.broadcast_message("Hello everyone").await;
```

## Testing

Run tests with:
```bash
cargo test
```

## Implementation

The crate provides a clean WebSocket server framework built on fastwebsockets that can be integrated with HTTP servers or used directly for WebSocket communication.

# TODO

- remove the open API API - instead add hooks for client connect/disconnect to be 
used by a common cross-transport API (along with SSH-TCP/UDS, HTTP/2, vsock)

- all transports should support message/broadcast.

- stream: one stream per WSS connection (no per-stream flow control)