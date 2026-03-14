use clap::{Parser, Subcommand};
use otel::perfetto_pull::PerfettoPull;
use tracing::{info, info_span};

// Shim for libstdc++ or perfetto code expecting __libc_single_threaded
// This symbol is a glibc extension not present in musl, but some C++ headers/code might reference it.
#[cfg(target_env = "musl")]
#[no_mangle]
pub static __libc_single_threaded: u8 = 0;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Use trace (span) instead of log
    #[arg(long, global = true)]
    trace: bool,

    /// The message to send (default if no subcommand)
    #[arg(trailing_var_arg = true)]
    message: Vec<String>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Pull traces from a Perfetto consumer socket
    Pull {
        /// Socket name
        #[arg(
            long,
            env = "PERFETTO_CONSUMER",
            default_value = "/tmp/perfetto-consumer"
        )]
        socket: String,

        /// Duration to record (seconds)
        #[arg(long, default_value_t = 10)]
        duration: u64,
    },

    /// Start the trace hub HTTP server
    Serve {
        /// Base directory for UDS trace sockets.
        /// Each producer creates a `<name>.sock` file here.
        #[arg(long, env = "TRACE_BASE_DIR")]
        base_dir: Option<String>,

        /// HTTP port for the trace hub UI
        #[arg(long, env = "TRACE_PORT", default_value_t = 9090)]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();

    // Initialize telemetry
    otel::init_telemetry();

    match args.command {
        Some(Commands::Pull { socket, duration }) => {
            info!("Connecting to perfetto consumer socket: {}", socket);

            let mut pull = PerfettoPull::new_system(&socket)?;
            pull.start();

            info!("Tracing started for {} seconds...", duration);
            tokio::time::sleep(tokio::time::Duration::from_secs(duration)).await;

            pull.stop()?;

            info!("Trace reading complete.");
        }

        Some(Commands::Serve { base_dir, port }) => {
            let base_dir = base_dir.map(std::path::PathBuf::from).unwrap_or_else(|| {
                let span = info_span!("otel-cli-trace", message = "hi");
                let _guard = span.enter();
                let uid = unsafe { libc::getuid() };
                std::path::PathBuf::from(format!("/run/user/{}/trace", uid))
            });

            info!("Starting trace hub at http://127.0.0.1:{}", port);
            info!("Base directory: {:?}", base_dir);

            otel::trace_server::run_trace_server(base_dir, port).await?;
        }

        None => {
            // Default: send a message as log or trace
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
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

            opentelemetry::global::shutdown_tracer_provider();

            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        }
    }

    Ok(())
}
