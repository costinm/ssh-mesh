use std::env;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

#[test]
#[ignore]
fn test_perfetto_trace_generation_and_pull() {
    // 1. Setup paths
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let bin_path = format!("{}/../../target/debug/otel", manifest_dir);
    // Ensure bin is built
    let status = Command::new("cargo")
        .arg("build")
        .arg("--bin")
        .arg("otel")
        .current_dir(&manifest_dir)
        .status()
        .expect("Failed to build otel");
    assert!(status.success(), "Build failed");

    // We rely on the system tracing service running at standard locations or as configured in environment.
    // For this test, we use the defaults which seem to work in the environment.

    // We assume 'traced' is running and we can point to it.
    // However, if we don't have control over 'traced', we rely on defaults.
    // But verify_perfetto.sh logic relies on setting env vars.
    // If we run this test in an environment without traced, it will likely fail on Producer::init or connection.
    // The user's environment seems to have /tmp/perfetto-producer and consumer.
    // We can try to use those, or rely on system traced.
    // Let's use the default sockets for now, as specifying custom ones usually requires launching our own traced instance.
    // But wait, the prompt "Add a command ... default to /tmp/perfetto-consumer" suggests we might not be using standard system paths.
    // Let's rely on the user provided defaults in main.rs (/tmp/perfetto-consumer).
    // The producer defaults to whatever perfetto-sdk defaults to, which is usually /run/perfetto/producer.sock or /tmp/perfetto-producer.

    // Let's just try to run the flow.

    // 2. Start Producer
    // We run `otel --trace "test-message"`
    // We need to keep it running?
    // The default `otel` command runs `init_telemetry`, sends message, waits 10s, then exits.
    // 10s is enough to capture.

    let mut producer = Command::new(&bin_path)
        .arg("--trace")
        .arg("trace-from-test")
        .env("PERFETTO_PRODUCER_SOCK_NAME", "/tmp/perfetto-producer") // Explicitly point to what seems to be available
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start producer");

    // Give it a moment to initialize and connect
    thread::sleep(Duration::from_secs(2));

    // 3. Run Pull
    let pull_status = Command::new(&bin_path)
        .arg("pull")
        .arg("--duration")
        .arg("3")
        .arg("--socket")
        .arg("/tmp/perfetto-consumer")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .status()
        .expect("Failed to run pull command");

    // 4. Cleanup
    let _ = producer.kill();
    let _ = producer.wait();

    // 5. Verify
    assert!(pull_status.success(), "Pull command failed");
}

#[tokio::test]
async fn test_perfetto_in_process_pull() {
    use std::sync::Once;
    use tracing::info_span;

    static INIT: Once = Once::new();
    INIT.call_once(|| {
        std::env::set_var("RUST_LOG", "info");
        otel::init_telemetry();
    });

    let mut pull = otel::perfetto_pull::PerfettoPull::new_in_process()
        .expect("Failed to create pulling session");
    pull.start();

    // Give it a moment to start
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Send a trace
    let trace_msg = "test-message-in-process-xyz123";
    {
        let span = info_span!("test-span", message = %trace_msg);
        let _guard = span.enter();
        tracing::info!("Sending test trace message");
    }

    // Give it time to flush
    tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;

    // Stop and pull the trace
    pull.stop().expect("Failed to stop and pull trace");
}
