// TCP echo server
// This server provides an echo service using TCP sockets

use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use clap::Parser;
use anyhow::Result;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// TCP address to bind to
    #[arg(short, long, default_value = "127.0.0.1:9999")]
    pub address: String,
    
    /// Buffer size for read/write operations
    #[arg(short, long, default_value_t = 4096)]
    pub buffer_size: usize,
}

pub fn run_server(args: Args) -> Result<()> {
    // Initialize logging
    env_logger::init();
    
    println!("Starting TCP echo server...");
    println!("Address: {}", args.address);
    println!("Buffer size: {}", args.buffer_size);
    
    // Create the TCP listener
    let listener = TcpListener::bind(&args.address)?;
    println!("TCP echo server listening on {}", args.address);
    
    println!("Waiting for connections... (Press Ctrl+C to exit)");
    
    // Accept incoming connections
    for stream_result in listener.incoming() {
        match stream_result {
            Ok(mut stream) => {
                println!("New connection established from {}", 
                         stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "unknown".to_string()));
                
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
    
    println!("TCP echo server shut down");
    
    Ok(())
}

fn handle_client(stream: &mut TcpStream, buffer_size: usize) -> Result<()> {
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