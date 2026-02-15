//! sshmc — CLI client for the extended OpenSSH mux protocol.
//!
//! This emulates `ssh -S PATH HOST` - the PATH points to an UDS socket
//! created based on ssh config ControlPath, when ControlMaster is set,
//!
//! Usage:
//!   sshmc example.com
//! Forwards stdin/stdout/stderr to a new shell connection running on example.com
//!
//!   sshmc -L local_port:remote_host:remote_port example.com
//!   sshmc -L local_port:remote_UDS example.com
//!   sshmc -L local_UDS:remote_host:remote_port example.com
//!   sshmc -L local_UDS:remote_UDS example.com
//! Opens a listener on local_port or local_UDS. 
//! All accepted connections are forwarded to remote_host:remote_port via example.com.
//! Unlike ssh, the bind address is not supported, localhost is used in all cases.
//! A separate option may be added to support a bind address forwarding and other 
//! special local transports (virtio, etc).
//! 
//!   sshmc -W dest.com:80 example.com
//! Forwards stdin/stdout to dest.com:80, via example.com. This can be used as ProxyCommand
//! for ProxyJump, `ssh -W '[%h]:%p jump`.
//!   
//!  sshmc -R bind_addr:remote_port:local_host:local_port example.com
//! Opens a listeners on example.com on bind_addr:remote_port. The port is 
//! typically 80, 443, 22 - used for multiplexing
//! 
//!   sshmc -R remote_uds:local_uds
//!   sshmc -R remote_uds:local_host:local_port
//!   sshmc -R port
//!   sshmc -R remote_port:local_uds 
//! 
//! The SSH_MUX env will point to the directory for the control sockets, defaulting
//! to  /run/user/${UID}/sshmux
//! 
//! The control sockets are named by the hostname ('example.com').
//! The `-S` option can override this and point to a specific file. 
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;


#[derive(Parser)]
#[command(name = "sshmuxc", about = "OpenSSH mux protocol client")]
struct Cli {
    /// Path to the mux control socket.
    #[arg(short = 'S', long)]
    socket: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check if the master is alive and get its PID.
    Check,

    /// Execute a command via the mux master.
    Exec {
        /// The command to execute.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,

        /// Request a TTY.
        #[arg(short, long)]
        tty: bool,
    },

    /// Set up a local port forward.
    ForwardLocal {
        /// Listen address (host:port).
        #[arg(short = 'L', long)]
        listen: String,

        /// Connect address (host:port).
        #[arg(short = 'C', long)]
        connect: String,
    },

    /// Set up a remote port forward.
    ForwardRemote {
        /// Listen address (host:port).
        #[arg(short = 'R', long)]
        listen: String,

        /// Connect address (host:port).
        #[arg(short = 'C', long)]
        connect: String,
    },

    /// Request the master to terminate.
    Terminate,

    /// Request the master to stop listening.
    Stop,
}

fn parse_host_port(s: &str) -> Result<(String, u16)> {
    let parts: Vec<&str> = s.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        anyhow::bail!("expected host:port, got {:?}", s);
    }
    let port: u16 = parts[0].parse()?;
    Ok((parts[1].to_string(), port))
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    let mut client = ssh_mesh::sshmuxc::MuxClient::connect(&cli.socket).await?;

    match cli.command {
        Commands::Check => {
            let pid = client.alive_check().await?;
            println!("Master running (pid={})", pid);
        }
        Commands::Exec { command, tty } => {
            let cmd = command.join(" ");
            let (session_id, exit_code) = client.new_session(&cmd, tty, 0, 1, 2).await?;
            println!("Session {} exited with code {}", session_id, exit_code);
            std::process::exit(exit_code as i32);
        }
        Commands::ForwardLocal { listen, connect } => {
            let (lhost, lport) = parse_host_port(&listen)?;
            let (chost, cport) = parse_host_port(&connect)?;
            let actual = client
                .open_local_forward(&lhost, lport, &chost, cport)
                .await?;
            if let Some(port) = actual {
                println!("Local forward established on port {}: -> {}", port, connect);
            } else {
                println!("Local forward established: {} -> {}", listen, connect);
            }
            // Keep running until interrupted
            tokio::signal::ctrl_c().await?;
        }
        Commands::ForwardRemote { listen, connect } => {
            let (lhost, lport) = parse_host_port(&listen)?;
            let (chost, cport) = parse_host_port(&connect)?;
            let actual = client
                .open_remote_forward(&lhost, lport, &chost, cport)
                .await?;
            if let Some(port) = actual {
                println!(
                    "Remote forward established on port {}: -> {}",
                    port, connect
                );
            } else {
                println!("Remote forward established: {} -> {}", listen, connect);
            }
            // Keep running until interrupted
            tokio::signal::ctrl_c().await?;
        }
        Commands::Terminate => {
            client.terminate().await?;
            println!("Master terminated");
        }
        Commands::Stop => {
            client.stop_listening().await?;
            println!("Master stopped listening");
        }
    }

    Ok(())
}
