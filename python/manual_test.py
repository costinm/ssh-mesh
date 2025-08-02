#!/usr/bin/env python3

import threading
import time
import socket
from ssh_server import SSHMeshServer
from ssh_client import SSHMeshClient

def test_port_forwarding():
    """Manual test for port forwarding functionality"""
    
    # Create a simple echo server
    echo_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    echo_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    echo_socket.bind(('127.0.0.1', 0))
    echo_port = echo_socket.getsockname()[1]
    echo_socket.listen(1)
    
    def echo_server():
        while True:
            try:
                conn, addr = echo_socket.accept()
                data = conn.recv(1024)
                conn.send(data)
                conn.close()
            except:
                break
    
    echo_thread = threading.Thread(target=echo_server)
    echo_thread.daemon = True
    echo_thread.start()
    
    # Start SSH server
    server = SSHMeshServer('127.0.0.1', 15026)
    server_thread = threading.Thread(target=server.start)
    server_thread.daemon = True
    server_thread.start()
    time.sleep(1)
    
    try:
        # Connect client
        client = SSHMeshClient('127.0.0.1', 15026)
        if not client.connect(password='test'):
            print("Failed to connect")
            return False
        
        print("Connected to SSH server successfully")
        
        # Create port forward
        local_port = 15080
        success = client.local_port_forward(local_port, '127.0.0.1', echo_port)
        print(f"Port forward created: {success}")
        
        if success:
            time.sleep(0.5)  # Allow port forward to establish
            
            # Test the port forward
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                test_socket.connect(('127.0.0.1', local_port))
                test_data = b'Hello SSH-Mesh!'
                test_socket.send(test_data)
                received = test_socket.recv(1024)
                
                print(f"Sent: {test_data}")
                print(f"Received: {received}")
                print(f"Port forwarding works: {test_data == received}")
                
            except Exception as e:
                print(f"Port forward test failed: {e}")
            finally:
                test_socket.close()
        
        client.disconnect()
        
    except Exception as e:
        print(f"Test error: {e}")
    finally:
        server.stop()
        echo_socket.close()
    
    return True

if __name__ == "__main__":
    test_port_forwarding()