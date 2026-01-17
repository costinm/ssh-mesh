use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use log::{error, info};
use pmond::ProcMon;
use std::sync::Arc;
use tokio::net::TcpListener;

mod handlers;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    env_logger::init();

    info!("Starting PMON process monitor");

    // Create a new ProcMon instance
    let proc_mon = ProcMon::new()?;

    // Enable listening for events
    proc_mon.listen(true)?;

    // Wrap the monitor in an Arc for shared ownership
    let proc_mon = Arc::new(proc_mon);

    // Start monitoring in a background thread
    proc_mon.start(true, true)?;

    info!("PMON process monitor started successfully");

    // Set up HTTP server
    let addr = "127.0.0.1:8081";
    let listener = TcpListener::bind(addr).await?;
    info!("Listening on http://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let proc_mon = proc_mon.clone();

        tokio::task::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| {
                let proc_mon = proc_mon.clone();
                async move { handlers::http_service(req, proc_mon).await }
            });

            let conn = ConnBuilder::new(TokioExecutor::new());
            let conn = conn.serve_connection_with_upgrades(io, service);

            if let Err(err) = conn.await {
                error!("Error serving connection: {:?}", err);
            }
        });
    }
}
