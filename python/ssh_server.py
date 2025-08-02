import logging
import socket
import threading
import paramiko
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class SSHMeshServer:
    """
    SSH-Mesh server implementation using paramiko.
    Provides SSH server functionality with port forwarding capabilities.
    """
    
    def __init__(self, host: str = "0.0.0.0", port: int = 15022, 
                 host_key_path: Optional[str] = None):
        self.host = host
        self.port = port
        self.host_key = None
        self.running = False
        self.server_socket = None
        self.active_connections = {}
        
        # Load or generate host key
        if host_key_path:
            try:
                self.host_key = paramiko.RSAKey.from_private_key_file(host_key_path)
            except Exception as e:
                logger.warning(f"Failed to load host key from {host_key_path}: {e}")
        
        if not self.host_key:
            logger.info("Generating new RSA host key")
            self.host_key = paramiko.RSAKey.generate(2048)
    
    def start(self):
        """Start the SSH server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(100)
            self.running = True
            logger.info(f"SSH-Mesh server listening on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    logger.info(f"Connection from {addr}")
                    
                    # Handle connection in a separate thread
                    thread = threading.Thread(
                        target=self._handle_connection,
                        args=(client_socket, addr)
                    )
                    thread.daemon = True
                    thread.start()
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"Error accepting connection: {e}")
                        
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the SSH server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        
        # Close all active connections
        for conn_id, transport in list(self.active_connections.items()):
            try:
                transport.close()
                del self.active_connections[conn_id]
            except Exception as e:
                logger.error(f"Error closing connection {conn_id}: {e}")
        
        logger.info("SSH-Mesh server stopped")
    
    def _handle_connection(self, client_socket, addr):
        """Handle incoming SSH connection"""
        transport = None
        try:
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(self.host_key)
            
            # Create server interface
            server = SSHMeshServerInterface()
            transport.set_subsystem_handler('sftp', paramiko.SFTPServer)
            
            # Start server
            transport.start_server(server=server)
            
            conn_id = f"{addr[0]}:{addr[1]}"
            self.active_connections[conn_id] = transport
            
            # Wait for authentication
            channel = transport.accept(20)
            if channel is None:
                logger.warning(f"No channel from {addr}")
                return
            
            logger.info(f"Authenticated connection from {addr}")
            
            # Handle port forwarding requests
            while transport.is_active():
                try:
                    # Accept port forwarding requests
                    if transport.is_active():
                        threading.Event().wait(1)  # Small delay
                except Exception as e:
                    logger.error(f"Error in connection loop: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Connection handling error: {e}")
        finally:
            if transport:
                transport.close()
            client_socket.close()
            if conn_id in self.active_connections:
                del self.active_connections[conn_id]


class SSHMeshServerInterface(paramiko.ServerInterface):
    """SSH server interface for handling authentication and channels"""
    
    def check_auth_password(self, username, password):
        """Allow any username/password for demo purposes"""
        logger.info(f"Password auth attempt for user: {username}")
        return paramiko.AUTH_SUCCESSFUL
    
    def check_auth_publickey(self, username, key):
        """Allow any public key for demo purposes"""
        logger.info(f"Public key auth attempt for user: {username}")
        return paramiko.AUTH_SUCCESSFUL
    
    def check_channel_request(self, kind, chanid):
        """Allow channel requests"""
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_channel_shell_request(self, channel):
        """Allow shell requests"""
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        """Allow PTY requests"""
        return True
    
    def check_port_forward_request(self, address, port):
        """Allow port forwarding requests"""
        logger.info(f"Port forward request: {address}:{port}")
        return port
    
    def cancel_port_forward_request(self, address, port):
        """Handle port forward cancellation"""
        logger.info(f"Cancelling port forward: {address}:{port}")
        return True


def main():
    """Run SSH-Mesh server standalone"""
    logging.basicConfig(level=logging.INFO)
    
    server = SSHMeshServer()
    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("Shutting down server...")
        server.stop()


if __name__ == "__main__":
    main()