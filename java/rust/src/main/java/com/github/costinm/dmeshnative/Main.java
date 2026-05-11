package com.github.costinm.dmeshnative;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.UUID;

public class Main {
    public static void main(String[] args) throws Exception {
        System.out.println("Starting Mesh JNI Integration Test...");

        // 1. Create temp directories for nodes
        File serverDir = Files.createTempDirectory("mesh-server").toFile();
        File clientDir = Files.createTempDirectory("mesh-client").toFile();

        int serverSshPort = findFreePort();
        int serverHttpPort = findFreePort();

        try {
            // 2. Start client node first to get its public key
            MeshNode clientNode = new MeshNode(clientDir.getAbsolutePath());
            clientNode.start(0, 0); // Random ports
            String clientPubKey = clientNode.getPublicKey();
            System.out.println("Client Public Key: " + clientPubKey);

            // 3. Setup server authorized_keys with client key
            File authKeys = new File(serverDir, "authorized_keys");
            Files.write(authKeys.toPath(), (clientPubKey + "\n").getBytes(StandardCharsets.UTF_8));

            // 4. Start server node
            MeshNode serverNode = new MeshNode(serverDir.getAbsolutePath());
            serverNode.start(serverSshPort, serverHttpPort);
            System.out.println("Server started on ports " + serverSshPort + " (SSH) and " + serverHttpPort + " (HTTP)");

            serverNode.setCallback(new MeshNode.MeshCallback() {
                @Override
                public void onSshConnection(long clientId, String user) {
                    System.out.println("CALLBACK: serverNode onSshConnection: client=" + clientId + ", user=" + user);
                }

                @Override
                public void onStream(long clientId, String host, int port, long streamHandle) {
                    System.out.println("CALLBACK: serverNode onStream: host=" + host + ", port=" + port + ", streamHandle=" + streamHandle);
                    try (MeshStream s = new MeshStream(streamHandle)) {
                        byte[] b = new byte[1024];
                        int n = s.read(b);
                        if (n > 0) {
                            String msg = new String(b, 0, n, StandardCharsets.UTF_8);
                            System.out.println("CALLBACK: serverNode received: " + msg);
                            s.write(("ECHO: " + msg).getBytes(StandardCharsets.UTF_8));
                        }
                    } catch (Exception e) { e.printStackTrace(); }
                }

                @Override
                public void onForwardedTcpip(long connId, String host, int port, long streamHandle) {
                    System.out.println("CALLBACK: serverNode onForwardedTcpip: conn=" + connId + ", host=" + host + ", port=" + port);
                }
            });

            clientNode.setCallback(new MeshNode.MeshCallback() {
                @Override
                public void onSshConnection(long clientId, String user) {
                    System.out.println("CALLBACK: clientNode onSshConnection: client=" + clientId + ", user=" + user);
                }

                @Override
                public void onStream(long clientId, String host, int port, long streamHandle) {
                    System.out.println("CALLBACK: clientNode onStream: host=" + host + ", port=" + port);
                }

                @Override
                public void onForwardedTcpip(long connId, String host, int port, long streamHandle) {
                    System.out.println("CALLBACK: clientNode onForwardedTcpip: conn=" + connId + ", host=" + host + ", port=" + port);
                    try (MeshStream s = new MeshStream(streamHandle)) {
                        byte[] b = new byte[1024];
                        int n = s.read(b);
                        if (n > 0) {
                            String msg = new String(b, 0, n, StandardCharsets.UTF_8);
                            if ("REVERSE_ECHO_INIT".equals(msg)) {
                                s.write("REVERSE_ECHO_RESPONSE".getBytes(StandardCharsets.UTF_8));
                            }
                        }
                    } catch (Exception e) { e.printStackTrace(); }
                }
            });

            // 5. Connect client to server
            long connId = clientNode.connect("127.0.0.1", serverSshPort, "root", "");
            if (connId < 0) {
                throw new RuntimeException("Client failed to connect to server");
            }
            System.out.println("Client connected (connId=" + connId + ")");

            // 6. Test Exec
            String res = clientNode.exec(connId, "echo 'Hello from Mesh JNI'");
            System.out.println("Exec Result: " + res.trim());

            // 7. Test host="local" callback
            System.out.println("Testing host='local' callback...");
            try (MeshStream stream = clientNode.openStream(connId, "local", 1234)) {
                if (stream == null) throw new RuntimeException("Failed to open local stream");
                stream.write("Callback Test".getBytes(StandardCharsets.UTF_8));
                byte[] b = new byte[1024];
                int n = stream.read(b);
                if (n > 0) {
                    String resp = new String(b, 0, n, StandardCharsets.UTF_8);
                    System.out.println("Local stream response: " + resp);
                    if (!resp.equals("ECHO: Callback Test")) {
                        throw new RuntimeException("Local stream callback test failed");
                    }
                } else {
                    throw new RuntimeException("No response from local stream callback");
                }
            }

            // 8. Test Remote Forward (-R) callback
            System.out.println("Testing Remote Forward callback...");
            int requestedPort = 22222;
            int remotePort = clientNode.addRemoteForward(connId, requestedPort, "127.0.0.1", 0);
            if (remotePort == 0) remotePort = requestedPort;
            System.out.println("Remote forward added on port " + remotePort);
            
            // Trigger the remote forward by connecting to the server's port
            final int finalRemotePort = remotePort;
            final boolean[] remoteForwardTriggered = {false};
            Thread triggerThread = new Thread(() -> {
                try {
                    Thread.sleep(1000);
                    System.out.println("Connecting to remote forward port " + finalRemotePort + "...");
                    try (java.net.Socket s = new java.net.Socket("127.0.0.1", finalRemotePort)) {
                        java.io.OutputStream out = s.getOutputStream();
                        out.write("REVERSE_ECHO_INIT".getBytes(StandardCharsets.UTF_8));
                        java.io.InputStream in = s.getInputStream();
                        byte[] b = new byte[1024];
                        int n = in.read(b);
                        if (n > 0) {
                            String resp = new String(b, 0, n, StandardCharsets.UTF_8);
                            System.out.println("Remote forward trigger response: " + resp);
                            if ("REVERSE_ECHO_RESPONSE".equals(resp)) {
                                remoteForwardTriggered[0] = true;
                            }
                        }
                    }
                } catch (Exception e) { e.printStackTrace(); }
            });
            triggerThread.start();
            triggerThread.join(5000);

            if (!remoteForwardTriggered[0]) {
                System.err.println("Remote forward trigger test failed!");
            } else {
                System.out.println("Remote forward trigger test passed!");
            }

            // 9. Cleanup
            clientNode.stop();
            serverNode.stop();
            System.out.println("Test completed successfully!");

        } finally {
            deleteDir(serverDir);
            deleteDir(clientDir);
        }
    }

    private static int findFreePort() throws IOException {
        try (java.net.ServerSocket socket = new java.net.ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private static void deleteDir(File file) {
        File[] contents = file.listFiles();
        if (contents != null) {
            for (File f : contents) {
                deleteDir(f);
            }
        }
        file.delete();
    }
}
