use clap::{Parser, Subcommand};
use tracing::info;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the trace hub HTTP server
    Serve {
        /// Base directory for UDS trace sockets.
        /// Each producer creates a `<name>.sock` file here. Defaults to the
        /// shared `TRACE_SOCKET_DIR` (or `$HOME/.run/traceweb`) so producers
        /// are discovered with no extra config.
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
            let base_dir = match base_dir {
                Some(p) => std::path::PathBuf::from(p),
                None => mesh::local_trace::default_trace_socket_dir().ok_or_else(|| {
                    "cannot determine trace socket directory: set TRACE_BASE_DIR, TRACE_SOCKET_DIR, or HOME"
                })?,
            };

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
