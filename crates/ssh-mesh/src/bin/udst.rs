use std::env;
use std::process;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// udst is a minimal TCP tunnel over Unix Domain Sockets, forwarding stdin/stdout.
///
/// On client - use with 'ProxyCommand':
///   `ssh -o ProxyCommand="udst /tmp/ssh-mesh.sock" user@host`

async fn handle_stdio(path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let stream = UnixStream::connect(path).await?;
    let (mut read, mut write) = tokio::io::split(stream);

    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    let stdin_to_uds = tokio::spawn(async move {
        let mut buffer = [0u8; 8192];
        loop {
            match stdin.read(&mut buffer).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if write.write_all(&buffer[..n]).await.is_err() {
                        break;
                    }
                    if write.flush().await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Error reading from stdin: {}", e);
                    break;
                }
            }
        }
    });

    let uds_to_stdout = tokio::spawn(async move {
        let mut buffer = [0u8; 8192];
        loop {
            match read.read(&mut buffer).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if stdout.write_all(&buffer[..n]).await.is_err() {
                        break;
                    }
                    if stdout.flush().await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Error reading from UDS: {}", e);
                    break;
                }
            }
        }
    });

    tokio::select! {
        _ = stdin_to_uds => {}
        _ = uds_to_stdout => {}
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <UDS_PATH>", args[0]);
        process::exit(1);
    }

    handle_stdio(&args[1]).await?;

    Ok(())
}
