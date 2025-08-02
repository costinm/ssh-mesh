import logging
import socket
import threading
import paramiko
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


class SSHMeshClient:
    """
    SSH-Mesh client implementation using paramiko.
    Provides SSH client functionality with port forwarding capabilities.
    """
    
    def __init__(self, hostname: str, port: int = 15022, username: str = "sshm"):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.ssh_client = None
        self.transport = None
        self.active_forwards = {}
        self._lock = threading.Lock()
    
    def connect(self, password: Optional[str] = None, 
                key_filename: Optional[str] = None, 
                timeout: int = 10):
        """Connect to SSH-Mesh server"""
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs = {
                'hostname': self.hostname,
                'port': self.port,
                'username': self.username,
                'timeout': timeout
            }
            
            if password:
                connect_kwargs['password'] = password
            elif key_filename:
                connect_kwargs['key_filename'] = key_filename
            else:
                # Try default SSH keys
                connect_kwargs['look_for_keys'] = True
            
            self.ssh_client.connect(**connect_kwargs)
            self.transport = self.ssh_client.get_transport()
            
            logger.info(f"Connected to SSH-Mesh server at {self.hostname}:{self.port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to {self.hostname}:{self.port}: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from SSH-Mesh server"""
        # Stop all port forwards
        self.stop_all_port_forwards()
        
        if self.ssh_client:
            self.ssh_client.close()
            self.ssh_client = None
            self.transport = None
        
        logger.info("Disconnected from SSH-Mesh server")
    
    def local_port_forward(self, local_port: int, remote_host: str, remote_port: int,
                          local_host: str = "127.0.0.1") -> bool:
        """
        Create a local port forward (L tunnel)
        Traffic to local_host:local_port is forwarded to remote_host:remote_port via the SSH server
        """
        if not self.transport or not self.transport.is_active():
            logger.error("Not connected to SSH server")
            return False
        
        try:
            # Create a listening socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((local_host, local_port))
            server_socket.listen(100)
            
            forward_key = f"L:{local_host}:{local_port}->{remote_host}:{remote_port}"
            
            # Start forwarding thread
            forward_thread = threading.Thread(
                target=self._local_forward_handler,
                args=(server_socket, remote_host, remote_port, forward_key)
            )
            forward_thread.daemon = True
            forward_thread.start()
            
            with self._lock:
                self.active_forwards[forward_key] = {
                    'socket': server_socket,
                    'thread': forward_thread,
                    'type': 'local'
                }
            
            logger.info(f"Local port forward: {local_host}:{local_port} -> {remote_host}:{remote_port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create local port forward: {e}")
            return False
    
    def remote_port_forward(self, remote_port: int, local_host: str, local_port: int,
                           remote_host: str = "0.0.0.0") -> bool:
        """
        Create a remote port forward (R tunnel)
        Traffic to remote_host:remote_port on the SSH server is forwarded to local_host:local_port
        """
        if not self.transport or not self.transport.is_active():
            logger.error("Not connected to SSH server")
            return False
        
        try:
            # Request remote port forward
            self.transport.request_port_forward(remote_host, remote_port)
            
            forward_key = f"R:{remote_host}:{remote_port}->{local_host}:{local_port}"
            
            # Start handler thread for incoming connections
            handler_thread = threading.Thread(
                target=self._remote_forward_handler,
                args=(local_host, local_port, forward_key)
            )
            handler_thread.daemon = True
            handler_thread.start()
            
            with self._lock:
                self.active_forwards[forward_key] = {
                    'thread': handler_thread,
                    'type': 'remote',
                    'remote_host': remote_host,
                    'remote_port': remote_port
                }
            
            logger.info(f"Remote port forward: {remote_host}:{remote_port} -> {local_host}:{local_port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create remote port forward: {e}")
            return False
    
    def stop_port_forward(self, forward_key: str):
        """Stop a specific port forward"""
        with self._lock:
            if forward_key in self.active_forwards:
                forward_info = self.active_forwards[forward_key]
                
                if forward_info['type'] == 'local' and 'socket' in forward_info:
                    forward_info['socket'].close()
                elif forward_info['type'] == 'remote':
                    try:
                        self.transport.cancel_port_forward(
                            forward_info['remote_host'],
                            forward_info['remote_port']
                        )
                    except Exception as e:
                        logger.error(f"Error canceling remote port forward: {e}")
                
                del self.active_forwards[forward_key]
                logger.info(f"Stopped port forward: {forward_key}")
    
    def stop_all_port_forwards(self):
        """Stop all active port forwards"""
        with self._lock:
            for forward_key in list(self.active_forwards.keys()):
                self.stop_port_forward(forward_key)
    
    def _local_forward_handler(self, server_socket, remote_host, remote_port, forward_key):
        """Handle local port forwarding connections"""
        try:
            while True:
                try:
                    client_socket, addr = server_socket.accept()
                    logger.debug(f"Local forward connection from {addr}")
                    
                    # Create SSH channel
                    channel = self.transport.open_channel(
                        'direct-tcpip',
                        (remote_host, remote_port),
                        addr
                    )
                    
                    if channel is None:
                        logger.error("Failed to open SSH channel")
                        client_socket.close()
                        continue
                    
                    # Start bidirectional data forwarding
                    threading.Thread(
                        target=self._forward_data,
                        args=(client_socket, channel, f"{forward_key}-{addr}")
                    ).start()
                    
                except Exception as e:
                    if forward_key in self.active_forwards:
                        logger.error(f"Local forward handler error: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Local forward handler fatal error: {e}")
        finally:
            server_socket.close()
    
    def _remote_forward_handler(self, local_host, local_port, forward_key):
        """Handle remote port forwarding connections"""
        try:
            while forward_key in self.active_forwards:
                try:
                    channel = self.transport.accept(1)
                    if channel is None:
                        continue
                    
                    logger.debug(f"Remote forward connection to {local_host}:{local_port}")
                    
                    # Connect to local service
                    local_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    local_socket.connect((local_host, local_port))
                    
                    # Start bidirectional data forwarding
                    threading.Thread(
                        target=self._forward_data,
                        args=(local_socket, channel, f"{forward_key}-local")
                    ).start()
                    
                except Exception as e:
                    if forward_key in self.active_forwards:
                        logger.error(f"Remote forward handler error: {e}")
                    
        except Exception as e:
            logger.error(f"Remote forward handler fatal error: {e}")
    
    def _forward_data(self, sock1, sock2, conn_id):
        """Forward data bidirectionally between two sockets"""
        def forward(src, dst, direction):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.send(data)
            except Exception as e:
                logger.debug(f"Forward error {direction} for {conn_id}: {e}")
            finally:
                try:
                    src.close()
                    dst.close()
                except:
                    pass
        
        # Start forwarding in both directions
        thread1 = threading.Thread(target=forward, args=(sock1, sock2, "->"))
        thread2 = threading.Thread(target=forward, args=(sock2, sock1, "<-"))
        
        thread1.daemon = True
        thread2.daemon = True
        
        thread1.start()
        thread2.start()
        
        thread1.join()
        thread2.join()
        
        logger.debug(f"Connection closed: {conn_id}")
    
    def execute_command(self, command: str) -> Tuple[str, str, int]:
        """Execute a command on the remote server"""
        if not self.ssh_client:
            return "", "Not connected", 1
        
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(command)
            stdout_data = stdout.read().decode('utf-8')
            stderr_data = stderr.read().decode('utf-8')
            exit_status = stdout.channel.recv_exit_status()
            
            return stdout_data, stderr_data, exit_status
            
        except Exception as e:
            return "", str(e), 1


def main():
    """Run SSH-Mesh client standalone"""
    import sys
    
    logging.basicConfig(level=logging.INFO)
    
    if len(sys.argv) < 2:
        print("Usage: python ssh_client.py <hostname> [port]")
        sys.exit(1)
    
    hostname = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 15022
    
    client = SSHMeshClient(hostname, port)
    
    try:
        if client.connect():
            print(f"Connected to {hostname}:{port}")
            
            # Example: Create a local port forward
            client.local_port_forward(18080, "httpbin.org", 80)
            print("Created local port forward: localhost:18080 -> httpbin.org:80")
            
            # Keep running
            try:
                while True:
                    threading.Event().wait(1)
            except KeyboardInterrupt:
                print("Shutting down...")
        else:
            print("Failed to connect")
            
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()