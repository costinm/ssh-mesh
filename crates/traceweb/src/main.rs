use clap::{Parser, Subcommand};
use tracing::info;

#[derive(Parser, Debug)]
#[command(author, version, about = "Mesh trace aggregator JSONL service", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the trace hub JSONL service.
    Serve {
        /// Base directory for UDS trace sockets.
        /// Each producer creates a `<name>.sock` file here. Defaults to the
        /// shared `TRACE_SOCKET_DIR` (or `/home/traceweb/run/traceweb`) so producers
        /// are discovered with no extra config.
        #[arg(long, env = "TRACE_BASE_DIR")]
        base_dir: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();

    match args.command.unwrap_or(Commands::Serve { base_dir: None }) {
        Commands::Serve { base_dir } => {
            let base_dir = match base_dir {
                Some(p) => std::path::PathBuf::from(p),
                None => mesh::local_trace::default_trace_socket_dir().ok_or_else(|| {
                    "cannot determine trace socket directory: set TRACE_BASE_DIR, TRACE_SOCKET_DIR, or HOME"
                })?,
            };

            info!(base_dir = %base_dir.display(), "starting traceweb JSONL service");
            traceweb::trace_server::run_trace_server(base_dir).await?;
        }
    }

    Ok(())
}
