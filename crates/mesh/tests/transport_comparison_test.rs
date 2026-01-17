// Comprehensive test comparing UDS and TCP transport performance
// Note: NetLink implementation is available but complex for comprehensive testing

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;

#[test]
fn compare_transport_performance() {
    println!("\n=== COMPREHENSIVE TRANSPORT PERFORMANCE COMPARISON ===");
    println!("Comparing UDS and TCP echo services");
    println!("Note: NetLink available for basic testing (see test_netlink_basic_communication)");

    // Test parameters
    let iterations = 1000;
    let message_size = 1000;
    let message = "A".repeat(message_size);

    println!("\nTest Parameters:");
    println!("  Iterations: {}", iterations);
    println!("  Message size: {} bytes", message_size);
    println!("  Total data per test: {} bytes", iterations * message_size);

    // Test UDS performance
    let uds_results = test_uds_performance(iterations, message.clone());
    println!("\nUDS Results:");
    print_results(&uds_results);

    // Test TCP performance
    let tcp_results = test_tcp_performance(iterations, message.clone());
    println!("\nTCP Results:");
    print_results(&tcp_results);

    // Compare transports
    println!("\n=== COMPARISON SUMMARY ===");
    compare_results("UDS vs TCP", &uds_results, &tcp_results);

    // Find the fastest transport
    let transports = vec![("UDS", uds_results), ("TCP", tcp_results)];

    let fastest = transports
        .iter()
        .max_by(|a, b| a.1.throughput.partial_cmp(&b.1.throughput).unwrap());

    if let Some((name, _)) = fastest {
        println!("\nFastest transport: {}", name);
    }
}

struct PerformanceResults {
    total_time: f64,
    throughput: f64,
    avg_latency: f64,
    transport: String,
}

fn print_results(results: &PerformanceResults) {
    println!("  Total time: {:.6} seconds", results.total_time);
    println!(
        "  Throughput: {:.2} bytes/sec ({:.2} Mbps)",
        results.throughput,
        (results.throughput * 8.0) / 1_000_000.0
    );
    println!(
        "  Avg latency: {:.6} sec/call ({:.3} µs/call)",
        results.avg_latency,
        results.avg_latency * 1_000_000.0
    );
}

fn compare_results(name: &str, a: &PerformanceResults, b: &PerformanceResults) {
    println!("\n{}:", name);
    let ratio = a.throughput / b.throughput;
    println!("  Throughput ratio: {:.2}x", ratio);

    if a.throughput > b.throughput {
        println!(
            "  {} is {:.1}% faster than {}",
            a.transport,
            (ratio - 1.0) * 100.0,
            b.transport
        );
    } else {
        println!(
            "  {} is {:.1}% faster than {}",
            b.transport,
            (1.0 / ratio - 1.0) * 100.0,
            a.transport
        );
    }
}

fn test_uds_performance(iterations: usize, message: String) -> PerformanceResults {
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let socket_path = temp_dir.path().join("uds_benchmark.socket");
    let socket_path_str = socket_path.to_str().unwrap().to_string();
    let message_len = message.len();

    // Start UDS echo server in a separate thread
    let server_handle = thread::spawn({
        let socket_path = socket_path_str.clone();
        let message_len = message_len;
        move || {
            let listener = UnixListener::bind(&socket_path).expect("Failed to bind UDS");

            // Signal that we're ready
            fs::write(socket_path.clone() + ".ready", "ready").expect("Failed to write ready file");

            for stream in listener.incoming() {
                match stream {
                    Ok(mut stream) => {
                        let mut buf = vec![0u8; message_len];
                        for _ in 0..iterations {
                            let n = stream.read(&mut buf).expect("Failed to read");
                            if n == 0 {
                                break;
                            }
                            stream.write_all(&buf[..n]).expect("Failed to write");
                        }
                        break;
                    }
                    Err(_) => break,
                }
            }
        }
    });

    // Wait for server to be ready
    let ready_path = socket_path_str.to_string() + ".ready";
    for _ in 0..10 {
        if std::path::Path::new(&ready_path).exists() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    // Connect and run benchmark
    let mut stream = UnixStream::connect(&socket_path).expect("Failed to connect to UDS");

    let start = Instant::now();

    for _ in 0..iterations {
        stream
            .write_all(message.as_bytes())
            .expect("Failed to write");
        let mut buf = vec![0u8; message.len()];
        let n = stream.read(&mut buf).expect("Failed to read");
        assert!(n > 0);
    }

    let duration = start.elapsed();
    let total_time = duration.as_secs_f64();
    let total_bytes = (message.len() * iterations * 2) as f64; // Send + receive
    let throughput = total_bytes / total_time;
    let avg_latency = total_time / iterations as f64;

    // Cleanup
    fs::remove_file(&ready_path).ok();
    drop(stream);
    server_handle.join().expect("Server thread panicked");

    PerformanceResults {
        total_time,
        throughput,
        avg_latency,
        transport: "UDS".to_string(),
    }
}

fn test_tcp_performance(iterations: usize, message: String) -> PerformanceResults {
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let ready_flag_path = temp_dir.path().join("tcp_ready.flag");
    let ready_flag_path_str = ready_flag_path.to_str().unwrap().to_string();
    let message_len = message.len();

    // Start TCP echo server in a separate thread
    let server_handle = thread::spawn({
        let ready_flag_path = ready_flag_path_str.clone();
        let message_len = message_len;
        move || {
            let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind TCP");
            let local_addr = listener.local_addr().unwrap();

            // Signal that we're ready
            fs::write(&ready_flag_path, local_addr.to_string())
                .expect("Failed to write ready file");

            for stream in listener.incoming() {
                match stream {
                    Ok(mut stream) => {
                        let mut buf = vec![0u8; message_len];
                        for _ in 0..iterations {
                            let n = stream.read(&mut buf).expect("Failed to read");
                            if n == 0 {
                                break;
                            }
                            stream.write_all(&buf[..n]).expect("Failed to write");
                        }
                        break;
                    }
                    Err(_) => break,
                }
            }
        }
    });

    // Wait for server to be ready
    for _ in 0..10 {
        if std::path::Path::new(&ready_flag_path_str).exists() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    let address = fs::read_to_string(&ready_flag_path_str).expect("Failed to read ready file");

    // Connect and run benchmark
    let mut stream = TcpStream::connect(address).expect("Failed to connect to TCP");

    let start = Instant::now();

    for _ in 0..iterations {
        stream
            .write_all(message.as_bytes())
            .expect("Failed to write");
        let mut buf = vec![0u8; message.len()];
        let n = stream.read(&mut buf).expect("Failed to read");
        assert!(n > 0);
    }

    let duration = start.elapsed();
    let total_time = duration.as_secs_f64();
    let total_bytes = (message.len() * iterations * 2) as f64; // Send + receive
    let throughput = total_bytes / total_time;
    let avg_latency = total_time / iterations as f64;

    // Cleanup
    fs::remove_file(&ready_flag_path_str).ok();
    drop(stream);
    server_handle.join().expect("Server thread panicked");

    PerformanceResults {
        total_time,
        throughput,
        avg_latency,
        transport: "TCP".to_string(),
    }
}

#[test]
fn test_transports_with_various_message_sizes() {
    println!("\n=== TRANSPORT PERFORMANCE BY MESSAGE SIZE ===");

    let message_sizes = vec![10, 100, 1000, 10000];
    let iterations_per_size = 100;

    for size in message_sizes {
        let message = "A".repeat(size);

        println!("\n--- Message size: {} bytes ---", size);

        // Test UDS
        let uds_results = test_uds_performance(iterations_per_size, message.clone());
        println!(
            "UDS: {:.2} bytes/sec, {:.3} µs/call",
            uds_results.throughput,
            uds_results.avg_latency * 1_000_000.0
        );

        // Test TCP
        let tcp_results = test_tcp_performance(iterations_per_size, message.clone());
        println!(
            "TCP: {:.2} bytes/sec, {:.3} µs/call",
            tcp_results.throughput,
            tcp_results.avg_latency * 1_000_000.0
        );
    }
}
