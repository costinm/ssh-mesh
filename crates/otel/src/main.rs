use clap::Parser;
use tracing::{info, info_span};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Use trace (span) instead of log
    #[arg(long)]
    trace: bool,

    /// The message to send
    #[arg(required = true)]
    message: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    // Initialize telemetry
    otel::init_telemetry();

    let message = args.message.join(" ");
    if message.is_empty() {
        eprintln!("Error: No message provided");
        std::process::exit(1);
    }

    if args.trace {
        let span = info_span!("otel-cli-trace", message = %message);
        let _guard = span.enter();
        info!("Sending trace message");
    } else {
        info!(message = %message, "Sending log message");
    }

    // Give some time for the batch exporter to flush
    // OTLP batch exporter usually needs a bit of time or a shutdown signal.
    // opentelemetry-sdk doesn't have a simple synchronous flush for the global provider easily accessible here 
    // without keeping handle to the providers.
    // However, init_telemetry() doesn't return the providers.
    // Let's add a small sleep to ensure data is sent before exit.
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
    
    // Explicitly shut down the global providers if possible, 
    // but they are held in the tracing layers.
    opentelemetry::global::shutdown_tracer_provider();
    // logger provider shutdown is also needed but init_telemetry doesn't set it globally in a way we can easily shutdown here via global.
    // (It sets it in the tracing layer).

    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
    Ok(())
}
