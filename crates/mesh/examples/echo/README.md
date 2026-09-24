# Minimal echo service

This example is a small native-minicbor service that still uses the shared
mesh features. Its application request and response use minicbor derives and
contain no Serde or JSON code:

- socket activation through `MeshListener`;
- framing and request correlation through `serve_cbor_session`;
- named component/method dispatch with the request field tag declared by the
  handler and documented in [`API.md`](API.md);
- `mesh.initialize`, `mesh.tools`, lifecycle, and trace methods installed by
  `ServiceRegistry`;
- the standard reloadable trace subscriber through `local_trace::init`.

The application-specific code is the minicbor request/response definition and
the `echo.echo` method check.

For the corresponding Serde and newline-delimited JSON-RPC implementation,
see [`echo_json`](../echo_json).

Build and install it with:

```sh
source env.sh
cargo build --release -p mesh --example echo
install -Dm755 target/x86_64-unknown-linux-musl/release/examples/echo \
  /home/echo/bin/mesh-echo
```

Install [`echo.toml`](echo.toml) as `echo.toml` in mesh-init's configuration
directory and start or reload mesh-init. The omitted `Service.Type` is
intentional: the process is not started at boot. The otherwise empty `[Socket]`
uses the standard `/run/mesh/echo/mesh.sock`; mesh-init binds it, starts the
worker on the first connection, and passes the listener using `LISTEN_FDS`
beginning at fd 3. It finds `mesh-echo` through the service PATH, which begins with
`/home/echo/bin` and `/home/echo/.nix-profile/bin`, and runs it with
`/home/echo` as HOME and its default working directory.

`tools.json` is an external discovery artifact for mesh-cli and gateways. It
is generated from this example's API plus the common mesh API, but is not
linked into the worker:

```sh
source env.sh
cargo run -p mesh-api-gen -- \
  --api crates/mesh/examples/echo/API.md \
  --base-tools crates/mesh/resources/tools.json \
  --out-tools crates/mesh/examples/echo/tools.json
```
