package com.github.costinm.dmeshnative;

/**
 * DMesh — Single-node mesh launcher (Java).
 *
 * <p>Starts a mesh node with SSH server, HTTP server, and all available
 * features (process monitor, 9p export, SFTP, etc.).
 *
 * <p>Usage:
 * <pre>
 *   java -cp ... com.github.costinm.dmeshnative.Main --base-dir /path/to/data --ssh-port 15022 --http-port 8080
 * </pre>
 *
 * <p>Equivalent launchers exist in other languages — keep them in sync:
 * <ul>
 *   <li>Rust: {@code cargo run -p dmesh -- --base-dir ... --ssh-port ... --http-port ...}
 *   <li>Python: {@code python -m dmesh --base-dir ... --ssh-port ... --http-port ...}
 * </ul>
 *
 * @see MainTest Multi-node integration test
 */
public class Main {
    public static void main(String[] args) throws Exception {
        String baseDir = getEnvOrDefault("SSH_BASEDIR", System.getProperty("user.home", "."));
        int sshPort = Integer.parseInt(getEnvOrDefault("SSH_PORT", "15022"));
        int httpPort = Integer.parseInt(getEnvOrDefault("HTTP_PORT", "8080"));

        // Parse CLI args (override env vars)
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--base-dir":
                case "-d":
                    if (++i < args.length) baseDir = args[i];
                    break;
                case "--ssh-port":
                case "-s":
                    if (++i < args.length) sshPort = Integer.parseInt(args[i]);
                    break;
                case "--http-port":
                    if (++i < args.length) httpPort = Integer.parseInt(args[i]);
                    break;
                case "--help":
                    System.out.println("Usage: Main [OPTIONS]");
                    System.out.println();
                    System.out.println("Options:");
                    System.out.println("  -d, --base-dir <DIR>    Base directory (default: $SSH_BASEDIR or $HOME)");
                    System.out.println("  -s, --ssh-port <PORT>   SSH server port (default: $SSH_PORT or 15022)");
                    System.out.println("      --http-port <PORT>  HTTP server port (default: $HTTP_PORT or 8080)");
                    System.out.println();
                    System.out.println("See also:");
                    System.out.println("  Rust:   cargo run -p dmesh -- --base-dir ... --ssh-port ... --http-port ...");
                    System.out.println("  Python: python -m dmesh --base-dir ... --ssh-port ... --http-port ...");
                    System.exit(0);
                    break;
                default:
                    System.err.println("Unknown argument: " + args[i]);
                    System.exit(1);
            }
        }

        System.out.println("Starting dmesh node: base_dir=" + baseDir
                + ", ssh_port=" + sshPort + ", http_port=" + httpPort);

        MeshNode node = new MeshNode(baseDir);
        node.start(sshPort, httpPort);

        String pubKey = node.getPublicKey();
        System.out.println("Public key: " + pubKey);
        System.out.println("DMesh node started. Press Ctrl+C to stop.");

        // Shutdown hook for clean exit
        final MeshNode nodeRef = node;
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("Shutting down...");
            nodeRef.stop();
        }));

        // Block until interrupted
        try {
            Thread.currentThread().join();
        } catch (InterruptedException e) {
            // Clean exit
        }
    }

    private static String getEnvOrDefault(String name, String defaultValue) {
        String value = System.getenv(name);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }
}
