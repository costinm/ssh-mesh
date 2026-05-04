use clap::{Parser, Subcommand};
use tracing::{info, info_span};

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

    match args.command {
        Some(Commands::Serve { base_dir, port }) => {
            let base_dir = base_dir.map(std::path::PathBuf::from).unwrap_or_else(|| {
                let span = info_span!("otel-cli-trace", message = "hi");
                let _guard = span.enter();
                let uid = unsafe { libc::getuid() };
                std::path::PathBuf::from(format!("/run/user/{}/trace", uid))
            });

            info!("Starting trace hub at http://127.0.0.1:{}", port);
            info!("Base directory: {:?}", base_dir);

            traceweb::trace_server::run_trace_server(base_dir, port).await?;
        }

        None => {
            std::process::exit(1);
        }
    }

    Ok(())
}
