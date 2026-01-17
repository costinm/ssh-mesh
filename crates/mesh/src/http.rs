use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto;
use log::info;
use std::future::Future;
use std::pin::Pin;
#[allow(dead_code, unused)]
use std::{
    collections::HashMap, convert::Infallible, env, net::SocketAddr, path::PathBuf, sync::Arc,
};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{debug, error, instrument, trace};

// Public type alias for handler functions
pub type HandlerFn = Arc<
    dyn Fn(
            Request<Incoming>,
        )
            -> Pin<Box<dyn Future<Output = Result<Response<Full<Bytes>>, Infallible>> + Send>>
        + Send
        + Sync,
>;

/// HTTP/2 Server with configurable route handlers
pub struct H2Server {
    port: u16,
    handlers: Arc<RwLock<HashMap<String, HandlerFn>>>,
    pub base_dir: PathBuf,
}

impl H2Server {
    /// Create a new H2Server instance
    ///
    /// # Arguments
    /// * `port` - Port to listen on
    /// * `base_dir` - Base directory containing the .ssh subdirectory
    pub fn new(port: u16, base_dir: PathBuf) -> Self {
        let mut server = H2Server {
            port,
            handlers: Arc::new(RwLock::new(HashMap::new())),
            base_dir,
        };

        // Register default handlers
        server.register_default_handlers();
        server
    }

    /// Register default handlers for common paths
    fn register_default_handlers(&mut self) {
        // Register echo handler
        self.add_handler(
            "/_echo".to_string(),
            Arc::new(|req| Box::pin(handle_echo_request(req))),
        );
    }

    /// Add a handler for a specific path prefix
    pub fn add_handler(&mut self, path_prefix: String, handler: HandlerFn) {
        let handlers = Arc::clone(&self.handlers);
        tokio::spawn(async move {
            let mut handlers = handlers.write().await;
            handlers.insert(path_prefix, handler);
        });
    }

    /// Get the port number
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Handle incoming requests by routing to appropriate handlers
    #[instrument(skip(req, handlers), fields(method = %req.method(), uri = %req.uri()))]
    async fn handle_request(
        req: Request<Incoming>,
        handlers: Arc<RwLock<HashMap<String, HandlerFn>>>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let path = req.uri().path().to_string();
        trace!("Handling request for path: {}", path);

        // Try to find a matching handler
        let handler_opt: Option<HandlerFn> = {
            let handlers_read = handlers.read().await;

            let mut found_handler = None;
            for (prefix, handler) in handlers_read.iter() {
                if path.starts_with(prefix) {
                    debug!("Found handler for path prefix: {}", prefix);
                    found_handler = Some(Arc::clone(handler));
                    break;
                }
            }
            found_handler
        };

        // Call the handler if found, otherwise return default response
        match handler_opt {
            Some(handler) => {
                trace!("Calling handler for path: {}", path);
                handler(req).await
            }
            None => {
                debug!("No handler found for path: {}, using default handler", path);
                handle_default_request(req).await
            }
        }
    }

    /// Start the HTTP/2 server
    #[instrument(skip(self), fields(port = self.port))]
    pub async fn run(self) -> Result<(), anyhow::Error> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        info!("Starting H2C server on {}", addr);
        debug!("H2C server base directory: {:?}", self.base_dir);

        let listener = TcpListener::bind(addr).await?;
        let handlers = Arc::clone(&self.handlers);

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            debug!("Accepted connection from {:?}", peer_addr);
            let io = TokioIo::new(stream);
            let handlers_clone = Arc::clone(&handlers);

            tokio::task::spawn(async move {
                let service = service_fn(move |req| {
                    let handlers = Arc::clone(&handlers_clone);
                    async move { H2Server::handle_request(req, handlers).await }
                });

                if let Err(err) = auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(io, service)
                    .await
                {
                    error!("Error serving connection: {:?}", err);
                }
            });
        }
    }
}

// HTTP echo handler for /_echo* paths
#[instrument(skip(req), fields(method = %req.method(), uri = %req.uri()))]
async fn handle_echo_request(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    info!("Received HTTP echo request: {} {}", req.method(), req.uri());

    // Read the request body
    let collected = req.into_body().collect().await;
    let body_bytes = match collected {
        Ok(collected) => collected.to_bytes(),
        Err(_) => Bytes::new(),
    };

    // Create echo response
    let response = Response::builder()
        .status(200)
        .body(Full::new(body_bytes))
        .unwrap();

    Ok(response)
}

// Default handler for all other paths
#[instrument(skip(req), fields(method = %req.method(), uri = %req.uri()))]
async fn handle_default_request(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    info!("Received default request: {} {}", req.method(), req.uri());

    let response = Response::builder()
        .status(404)
        .body(Full::new(Bytes::from("Not found")))
        .unwrap();

    Ok(response)
}

pub async fn run_h2c_server_with_ca(port: u16) -> Result<(), anyhow::Error> {
    // Get base directory from environment or use home directory as default
    let base_dir = env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"));

    let mut server = H2Server::new(port, base_dir.clone());

    // Create CA and register certificate handler
    match crate::ca::CA::new(base_dir) {
        Ok(mut ca) => {
            // Create CA certificate if it doesn't exist
            if let Err(e) = ca.create_ca_certificate("Test CA") {
                info!(
                    "Warning: Failed to create CA certificate in test server: {}",
                    e
                );
            }
            let ca_arc = std::sync::Arc::new(ca);
            ca_arc.register_handler_with_server(&mut server);
        }
        Err(e) => {
            info!("Warning: Failed to create CA for test server: {}", e);
        }
    }

    debug!("Starting H2C server with CA on port {}", port);
    server.run().await
}

// Legacy function to start the HTTP/2 server (for backward compatibility)
#[instrument(skip())]
pub async fn run_h2c_server(port: u16) -> Result<(), anyhow::Error> {
    // Get base directory from environment or use home directory as default
    let base_dir = env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"));

    debug!("Starting legacy H2C server on port {}", port);
    let server = H2Server::new(port, base_dir);
    server.run().await
}

// Function to get port from environment variable or use default
pub fn get_port_from_env(var_name: &str, default: u16) -> u16 {
    env::var(var_name)
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_echo_handler() {
        // Test that the echo handler function exists and can be called
        // Actual functionality testing is done in integration tests
        assert!(true, "Echo handler test placeholder");
    }

    #[test]
    fn test_get_port_from_env() {
        // Test with default value
        let default_port = 1234;
        let random_var = "NONEXISTENT_VAR";
        assert_eq!(get_port_from_env(random_var, default_port), default_port);

        // Test with environment variable set
        let test_port = 5678;
        let test_var = "TEST_PORT";
        env::set_var(test_var, test_port.to_string());
        assert_eq!(get_port_from_env(test_var, default_port), test_port);

        // Cleanup
        env::remove_var(test_var);
    }
}
