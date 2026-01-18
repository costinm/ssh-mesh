// UDS (Unix Domain Socket) echo server
// This server provides an echo service using Unix domain sockets

use anyhow::Result;
use clap::Parser;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Socket path for the UDS server
    #[arg(short, long, default_value = "/tmp/uds_echo.socket")]
    pub socket: PathBuf,

    /// Buffer size for read/write operations
    #[arg(short, long, default_value_t = 4096)]
    pub buffer_size: usize,
}

pub fn run_server(args: Args) -> Result<()> {
    // Initialize logging
    env_logger::init();

    println!("Starting UDS echo server...");
    println!("Socket: {}", args.socket.display());
    println!("Buffer size: {}", args.buffer_size);

    // Remove existing socket file if it exists
    if args.socket.exists() {
        fs::remove_file(&args.socket)?;
        println!("Removed existing socket file");
    }

    // Create the Unix domain socket listener
    let listener = UnixListener::bind(&args.socket)?;
    println!("UDS echo server listening on {}", args.socket.display());

    println!("Waiting for connections... (Press Ctrl+C to exit)");

    // Accept incoming connections
    for stream_result in listener.incoming() {
        match stream_result {
            Ok(mut stream) => {
                println!("New connection established");

                // Handle the connection
                if let Err(e) = handle_client(&mut stream, args.buffer_size) {
                    eprintln!("Error handling client: {}", e);
                }

                println!("Connection closed");
            }
            Err(e) => {
                eprintln!("Error accepting connection: {}", e);
                continue;
            }
        }
    }

    // Clean up
    fs::remove_file(&args.socket).ok();
    println!("UDS echo server shut down");

    Ok(())
}

fn handle_client(stream: &mut UnixStream, buffer_size: usize) -> Result<()> {
    let mut buf = vec![0u8; buffer_size];

    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                // Connection closed by client
                break;
            }
            Ok(n) => {
                // Echo the data back to the client
                stream.write_all(&buf[..n])?;
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    // Non-blocking I/O would return this, but we're using blocking
                    continue;
                }
                return Err(e.into());
            }
        }
    }

    Ok(())
}
