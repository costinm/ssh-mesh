# JSON-RPC echo service

This is the Serde/JSON-RPC counterpart to the native-minicbor
[`echo`](../echo) example. It uses newline-delimited JSON-RPC 2.0, delegates
the common mesh methods to `ServiceRegistry`, and uses Serde for its
application request.

Build and install it with:

```sh
source env.sh
cargo build --release -p mesh --example echo_json
install -Dm755 target/x86_64-unknown-linux-musl/release/examples/echo_json \
  /home/echo-json/bin/mesh-echo-json
```

Install [`echo-json.toml`](echo-json.toml) in the mesh-init configuration
directory. Its empty `[Socket]` uses
`/run/mesh/echo-json/mesh.sock` and activation-only startup.
