"""Multi-node mesh integration tests.

Tests multiple MeshNode instances communicating over SSH, verifying
different communication paths: exec, stream callbacks, port forwarding.

Each test creates fresh node directories under testdata/ with auto-generated
keys, so no pre-seeded keys are required.

Usage:
    python tests/test_mesh.py          # standalone
    python -m pytest tests/test_mesh.py  # via pytest

See also:
- Java test: java/rust/src/main/java/.../MainTest.java
- Rust tests: crates/ssh-mesh/tests/
"""

import os
import shutil
import socket
import sys
import tempfile
import time
import threading

# Add python/ directory to path so we can import dmesh
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dmesh import PyMeshNode, PyMeshStream


def find_free_port():
    """Find an available TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


class MeshTestHarness:
    """Manages multiple mesh nodes for integration testing.

    Each node gets its own temporary base directory with auto-generated
    keys. The harness handles setup, authorization, and cleanup.
    """

    def __init__(self):
        self.nodes = {}
        self.temp_dirs = {}

    def create_node(self, name: str, base_dir: str = None) -> PyMeshNode:
        """Create a mesh node with a fresh temp directory."""
        if base_dir is None:
            base_dir = tempfile.mkdtemp(prefix=f"mesh-test-{name}-")
        else:
            os.makedirs(base_dir, exist_ok=True)

        node = PyMeshNode(base_dir)
        self.nodes[name] = node
        self.temp_dirs[name] = base_dir
        return node

    def get_node(self, name: str) -> PyMeshNode:
        return self.nodes[name]

    def get_base_dir(self, name: str) -> str:
        return self.temp_dirs[name]

    def authorize_client(self, server_name: str, client_name: str):
        """Add a client's public key to a server's authorized_keys."""
        client_node = self.nodes[client_name]
        server_dir = self.temp_dirs[server_name]

        pub_key = client_node.get_public_key()
        auth_keys_path = os.path.join(server_dir, "authorized_keys")

        # Append to existing file
        with open(auth_keys_path, "a") as f:
            f.write(pub_key + "\n")

    def cleanup(self):
        """Stop all nodes and remove temp directories."""
        for name, node in self.nodes.items():
            try:
                node.stop()
            except Exception:
                pass
        for name, temp_dir in self.temp_dirs.items():
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass


class ServerCallback:
    """Callback handler for the server node."""

    def __init__(self):
        self.connections = []
        self.streams = []

    def on_ssh_connection(self, client_id, user):
        print(f"  SERVER CALLBACK: on_ssh_connection: client={client_id}, user={user}")
        self.connections.append((client_id, user))

    def on_stream(self, client_id, host, port, stream):
        print(f"  SERVER CALLBACK: on_stream: host={host}, port={port}")
        self.streams.append((client_id, host, port))
        # Echo protocol: read, prefix with "ECHO: ", send back
        data = stream.read(1024)
        if data:
            msg = data.decode()
            print(f"  SERVER CALLBACK: received: {msg}")
            response = f"ECHO: {msg}"
            stream.write(response.encode())
            time.sleep(0.1)
        stream.close()

    def on_forwarded_tcpip(self, conn_id, host, port, stream):
        print(f"  SERVER CALLBACK: on_forwarded_tcpip: conn={conn_id}, host={host}, port={port}")


class ClientCallback:
    """Callback handler for the client node."""

    def __init__(self):
        self.forward_received = threading.Event()
        self.forward_response = None

    def on_ssh_connection(self, client_id, user):
        print(f"  CLIENT CALLBACK: on_ssh_connection: client={client_id}, user={user}")

    def on_stream(self, client_id, host, port, stream):
        print(f"  CLIENT CALLBACK: on_stream: host={host}, port={port}")

    def on_forwarded_tcpip(self, conn_id, host, port, stream):
        print(f"  CLIENT CALLBACK: on_forwarded_tcpip: conn={conn_id}, host={host}, port={port}")
        stream.write(b"REVERSE_ECHO_RESPONSE")
        time.sleep(0.1)
        stream.close()
        self.forward_received.set()


def test_two_node_exec():
    """Test: Client connects to server and executes a command."""
    print("\n=== Test: Two-node exec ===")
    harness = MeshTestHarness()

    try:
        ssh_port = find_free_port()
        http_port = find_free_port()

        # Create client first to get its public key
        client = harness.create_node("client")
        client.start(0, 0)
        time.sleep(0.5)

        # Authorize client on server
        harness.create_node("server")
        harness.authorize_client("server", "client")

        # Start server
        server = harness.get_node("server")
        server.start(ssh_port, http_port)
        time.sleep(1)

        # Connect client to server
        conn_id = client.connect("127.0.0.1", ssh_port, "root", "")
        print(f"  Connected with ID: {conn_id}")
        assert conn_id >= 0, f"Connection failed: {conn_id}"

        # Execute command
        result = client.exec(conn_id, "echo 'Hello from Python test'")
        print(f"  Exec result: {result.strip()}")
        assert "Hello from Python test" in result

        print("  PASSED")

    finally:
        harness.cleanup()


def test_two_node_stream_callback():
    """Test: Client opens a stream with host='local', triggering server callback."""
    print("\n=== Test: Two-node stream callback ===")
    harness = MeshTestHarness()

    try:
        ssh_port = find_free_port()
        http_port = find_free_port()

        client = harness.create_node("client")
        client.start(0, 0)
        time.sleep(0.5)

        harness.create_node("server")
        harness.authorize_client("server", "client")

        server = harness.get_node("server")
        server_cb = ServerCallback()
        server.set_callback(server_cb)
        server.start(ssh_port, http_port)
        time.sleep(1)

        conn_id = client.connect("127.0.0.1", ssh_port, "root", "")
        assert conn_id >= 0

        # Open stream with host='local' to trigger callback
        stream = client.open_stream(conn_id, "local", 1234)
        assert stream is not None

        msg = b"Stream Test from Python"
        stream.write(msg)
        resp = stream.read(1024)
        response = resp.decode()
        print(f"  Stream response: '{response}'")
        expected = f"ECHO: {msg.decode()}"
        assert response == expected, f"Expected '{expected}', got '{response}'"
        stream.close()

        print("  PASSED")

    finally:
        harness.cleanup()


def test_two_node_remote_forward():
    """Test: Client sets up a remote forward, then triggers it."""
    print("\n=== Test: Two-node remote forward ===")
    harness = MeshTestHarness()

    try:
        ssh_port = find_free_port()
        http_port = find_free_port()

        client = harness.create_node("client")
        client_cb = ClientCallback()
        client.set_callback(client_cb)
        client.start(0, 0)
        time.sleep(0.5)

        harness.create_node("server")
        harness.authorize_client("server", "client")

        server = harness.get_node("server")
        server.start(ssh_port, http_port)
        time.sleep(1)

        conn_id = client.connect("127.0.0.1", ssh_port, "root", "")
        assert conn_id >= 0

        # Add remote forward
        requested_port = find_free_port()
        remote_port = client.add_remote_forward(conn_id, requested_port, "127.0.0.1", 0)
        if remote_port == 0:
            remote_port = requested_port
        print(f"  Remote forward added on port {remote_port}")
        time.sleep(1)

        # Trigger the remote forward by connecting to the port
        with socket.create_connection(("127.0.0.1", remote_port)) as s:
            s.sendall(b"TRIGGER")
            resp = s.recv(1024)
            print(f"  Remote forward response: {resp.decode()}")
            assert resp.decode() == "REVERSE_ECHO_RESPONSE"

        print("  PASSED")

    finally:
        harness.cleanup()


def test_three_node_relay():
    """Test: Node A -> Node B -> Node C chain. A execs through B to C.

    This is a placeholder for future multi-hop testing.
    """
    print("\n=== Test: Three-node relay (placeholder) ===")
    print("  SKIPPED (not yet implemented)")


def run_all_tests():
    """Run all integration tests."""
    print("=" * 60)
    print("DMesh Multi-Node Integration Tests")
    print("=" * 60)

    tests = [
        test_two_node_exec,
        test_two_node_stream_callback,
        test_two_node_remote_forward,
        test_three_node_relay,
    ]

    passed = 0
    failed = 0
    skipped = 0

    for test_fn in tests:
        try:
            test_fn()
            passed += 1
        except AssertionError as e:
            print(f"  FAILED: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
        except Exception as e:
            print(f"  ERROR: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed, {skipped} skipped")
    print("=" * 60)

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    run_all_tests()
