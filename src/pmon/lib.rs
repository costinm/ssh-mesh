use crate::pmon::proc::{ProcMon, ProcessInfo};
use std::sync::Arc;
use std::convert::Infallible;
use hyper::{Request, Response, body::Incoming};
use hyper::body::Bytes;
use http_body_util::Full;
use log::info;

/// PMON (Process Monitor) command implementation
pub async fn pmon_main(
    _interval: u64,
    _timeout: u64,
    _processes: Vec<String>,
    _verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create a new ProcMon instance
    let proc_mon = ProcMon::new()?;

    // Set a callback to handle new processes
    proc_mon.set_callback(|p: ProcessInfo| {
        println!(
            "New process observed: pid={}, ppid={}, comm={}",
            p.pid,
            p.ppid,
            p.comm
        );
    });

    // Enable listening for events
    proc_mon.listen(true)?;

    // Wrap the monitor in an Arc for shared ownership
    let proc_mon = Arc::new(proc_mon);

    // Start monitoring in a background thread
    proc_mon.start(true, true)?;
    Ok(())
}

/// HTTP handler for /_ps endpoint - returns all processes as JSON
pub async fn handle_ps_request(
    req: Request<Incoming>,
    proc_mon: Arc<ProcMon>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    info!("Received PS request: {} {}", req.method(), req.uri());
    
    // Get all processes
    let processes = proc_mon.get_all_processes();
    
    // Convert to JSON
    let json_response = match serde_json::to_string(&processes) {
        Ok(json) => json,
        Err(e) => {
            let error_msg = format!(r#"{{"error": "Failed to serialize processes: {}"}}"#, e);
            return Ok(Response::builder()
                .status(500)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(error_msg)))
                .unwrap());
        }
    };
    
    // Return JSON response
    let response = Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(json_response)))
        .unwrap();
    
    Ok(response)
}