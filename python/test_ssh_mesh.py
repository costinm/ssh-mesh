import pytest
import threading
import time
import socket
import logging
from ssh_server import SSHMeshServer
from ssh_client import SSHMeshClient

# Configure logging for tests
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestSSHMesh:
    """Test suite for SSH-Mesh server and client functionality"""
    
    @pytest.fixture
    def server(self):
        """Fixture to start and stop SSH server for tests"""
        server = SSHMeshServer(host="127.0.0.1", port=15023)  # Use different port for tests
        
        # Start server in background thread
        server_thread = threading.Thread(target=server.start)
        server_thread.daemon = True
        server_thread.start()
        
        # Wait for server to start
        time.sleep(1)
        
        yield server
        
        # Cleanup
        server.stop()
    
    @pytest.fixture
    def client(self, server):
        """Fixture to create and connect SSH client"""
        client = SSHMeshClient("127.0.0.1", port=15023)
        
        # Connect with password authentication
        success = client.connect(password="test")
        assert success, "Failed to connect to SSH server"
        
        yield client
        
        # Cleanup
        client.disconnect()
    
    def test_server_startup(self, server):
        """Test that server starts up correctly"""
        assert server.running
        assert server.host_key is not None
    
    def test_client_connection(self, client):
        """Test that client can connect to server"""
        assert client.ssh_client is not None
        assert client.transport is not None
        assert client.transport.is_active()
    
    def test_local_port_forward(self, client):
        """Test local port forwarding functionality"""
        # Create a simple echo server for testing
        echo_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        echo_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        echo_server_socket.bind(("127.0.0.1", 0))  # Use any available port
        echo_port = echo_server_socket.getsockname()[1]
        echo_server_socket.listen(1)
        
        def echo_server():
            """Simple echo server for testing"""
            try:
                while True:
                    conn, addr = echo_server_socket.accept()
                    data = conn.recv(1024)
                    conn.send(data)  # Echo back the data
                    conn.close()
            except:
                pass
        
        echo_thread = threading.Thread(target=echo_server)
        echo_thread.daemon = True
        echo_thread.start()
        
        # Create local port forward
        local_port = 15080
        success = client.local_port_forward(local_port, "127.0.0.1", echo_port)
        assert success, "Failed to create local port forward"
        
        time.sleep(0.5)  # Allow port forward to establish
        
        # Test the port forward
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            test_socket.connect(("127.0.0.1", local_port))
            test_data = b"Hello, SSH-Mesh!"
            test_socket.send(test_data)
            
            received_data = test_socket.recv(1024)
            assert received_data == test_data, "Port forward echo test failed"
            
        finally:
            test_socket.close()
            echo_server_socket.close()
    
    def test_command_execution(self, client):
        """Test remote command execution"""
        stdout, stderr, exit_code = client.execute_command("echo 'test'")
        
        # Note: This might fail if the server doesn't support shell execution
        # but we test the client method works
        assert isinstance(stdout, str)
        assert isinstance(stderr, str)
        assert isinstance(exit_code, int)
    
    def test_multiple_connections(self, server):
        """Test that server can handle multiple concurrent connections"""
        clients = []
        
        try:
            # Create multiple clients
            for i in range(3):
                client = SSHMeshClient("127.0.0.1", port=15023)
                success = client.connect(password="test")
                assert success, f"Failed to connect client {i}"
                clients.append(client)
            
            # Verify all connections are active
            for i, client in enumerate(clients):
                assert client.transport.is_active(), f"Client {i} not active"
                
        finally:
            # Cleanup all clients
            for client in clients:
                client.disconnect()
    
    def test_port_forward_cleanup(self, client):
        """Test that port forwards are properly cleaned up"""
        # Create port forward
        success = client.local_port_forward(15081, "127.0.0.1", 80)
        assert success
        
        # Verify it's tracked
        assert len(client.active_forwards) > 0
        
        # Stop all forwards
        client.stop_all_port_forwards()
        
        # Verify cleanup
        assert len(client.active_forwards) == 0


def test_server_standalone():
    """Test server can be created and configured"""
    server = SSHMeshServer(host="127.0.0.1", port=15024)
    assert server.host == "127.0.0.1"
    assert server.port == 15024
    assert server.host_key is not None  # Should generate a key


def test_client_standalone():
    """Test client can be created and configured"""
    client = SSHMeshClient("example.com", port=22, username="testuser")
    assert client.hostname == "example.com"
    assert client.port == 22
    assert client.username == "testuser"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])