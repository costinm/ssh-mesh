# WebSocket Server Crate

This crate provides a WebSocket server implementation with client management capabilities. Refactored to a separate package because 
I always have trouble setting the right config, it is also pretty 
generic boilerplate.

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