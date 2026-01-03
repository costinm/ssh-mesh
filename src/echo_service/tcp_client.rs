// TCP echo client
// This client connects to the TCP echo service and performs benchmarking

use std::net::TcpStream;
use std::io::{Read, Write};
use std::time::Instant;
use clap::Parser;
use anyhow::Result;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// TCP address to connect to
    #[arg(short, long, default_value = "127.0.0.1:9999")]
    pub address: String,
    
    /// Number of iterations for benchmarking
    #[arg(short, long, default_value_t = 100)]
    pub iterations: usize,
    
    /// Message size for benchmarking
    #[arg(short, long, default_value_t = 100)]
    pub message_size: usize,
    
    /// Run in benchmark mode
    #[arg(short, long, default_value_t = false)]
    pub benchmark: bool,
}

pub fn run_client(args: &Args) -> Result<()> {
    // Initialize logging
    env_logger::init();
    
    println!("Starting TCP echo client...");
    println!("Address: {}", args.address);
    
    if args.benchmark {
        println!("Running in benchmark mode");
        println!("Iterations: {}", args.iterations);
        println!("Message size: {} bytes", args.message_size);
        run_benchmark(args)?;
    } else {
        println!("Running in interactive mode");
        run_interactive(args)?;
    }
    
    Ok(())
}

fn run_interactive(args: &Args) -> Result<()> {
    let mut stream = TcpStream::connect(&args.address)?;
    println!("Connected to TCP echo server");
    
    // Test messages
    let test_messages = vec![
        "Hello, TCP!",
        "This is a test message.",
        "TCP echo is working!",
        "🚀 TCP sockets are reliable! 🚀",
    ];
    
    println!("Sending test messages to TCP echo service:");
    
    for message in test_messages {
        let start = Instant::now();
        
        // Send message
        stream.write_all(message.as_bytes())?;
        println!("Sent: '{}'", message);
        
        // Receive echo
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf)?;
        let response = String::from_utf8_lossy(&buf[..n]);
        
        let duration = start.elapsed();
        println!("Received: '{}'", response);
        println!("Time: {:?}", duration);
        println!("---");
    }
    
    Ok(())
}

fn run_benchmark(args: &Args) -> Result<()> {
    let mut stream = TcpStream::connect(&args.address)?;
    println!("Connected to TCP echo server for benchmarking");
    
    // Create a test message of the specified size
    let message = "A".repeat(args.message_size);
    let message_bytes = message.as_bytes();
    
    println!("Starting benchmark with {} iterations...", args.iterations);
    
    let start = Instant::now();
    let mut total_bytes = 0;
    
    for i in 0..args.iterations {
        // Send message
        stream.write_all(message_bytes)?;
        
        // Receive echo
        let mut buf = vec![0u8; args.message_size];
        let n = stream.read(&mut buf)?;
        
        assert_eq!(n, args.message_size, "Received wrong number of bytes");
        assert_eq!(&buf[..n], message_bytes, "Received wrong data");
        
        total_bytes += n * 2; // Send + receive
        
        if (i + 1) % 1000 == 0 || i == args.iterations - 1 {
            println!("Completed {}/{} iterations", i + 1, args.iterations);
        }
    }
    
    let duration = start.elapsed();
    let total_seconds = duration.as_secs_f64();
    
    println!("\n=== BENCHMARK RESULTS ===");
    println!("Total iterations: {}", args.iterations);
    println!("Message size: {} bytes", args.message_size);
    println!("Total time: {:.6} seconds", total_seconds);
    println!("Total bytes transferred: {}", total_bytes);
    println!("Throughput: {:.2} bytes/sec", total_bytes as f64 / total_seconds);
    println!("Throughput: {:.2} Mbps", (total_bytes as f64 * 8.0) / total_seconds / 1_000_000.0);
    println!("Average latency: {:.6} sec/call", total_seconds / args.iterations as f64);
    println!("Average latency: {:.3} µs/call", total_seconds * 1_000_000.0 / args.iterations as f64);
    println!("Requests per second: {:.2}", args.iterations as f64 / total_seconds);
    
    Ok(())
}