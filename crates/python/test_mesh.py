import os
import time
import socket
import shutil
from ssh_mesh import PyMeshNode, PyMeshStream

class MyCallback:
    def on_ssh_connection(self, client_id, user):
        print(f"CALLBACK: on_ssh_connection: client={client_id}, user={user}")

    def on_stream(self, client_id, host, port, stream):
        print(f"CALLBACK: on_stream: host={host}, port={port}")
        # Read the message from client
        data = stream.read(1024)
        print(f"CALLBACK received: {data.decode()}")
        # Echo it back
        response = f"ECHO: {data.decode()}"
        print(f"CALLBACK sending: {response}")
        stream.write(response.encode())
        # Give it a tiny bit of time before closing to ensure it's sent
        time.sleep(0.1)
        stream.close()

    def on_forwarded_tcpip(self, conn_id, host, port, stream):
        print(f"CALLBACK: on_forwarded_tcpip: conn={conn_id}, host={host}, port={port}")
        stream.write(b"REVERSE_ECHO_RESPONSE")
        time.sleep(0.1)
        stream.close()

def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

def test_mesh():
    base_dir_server = "/tmp/mesh_test_server"
    base_dir_client = "/tmp/mesh_test_client"
    for d in [base_dir_server, base_dir_client]:
        if os.path.exists(d):
            shutil.rmtree(d)
        os.makedirs(d)
    
    try:
        ssh_port = find_free_port()
        http_port = find_free_port()

        print(f"Starting Client in {base_dir_client}")
        client_node = PyMeshNode(base_dir_client)
        client_node.set_callback(MyCallback())
        client_node.start(0, 0)
        
        time.sleep(1)
        client_pub_key = client_node.get_public_key()
        print(f"Client Public Key: {client_pub_key}")
        
        # Add client key to server authorized_keys
        with open(os.path.join(base_dir_server, "authorized_keys"), "w") as f:
            f.write(client_pub_key + "\n")

        print(f"Starting Server in {base_dir_server} on port {ssh_port}")
        server_node = PyMeshNode(base_dir_server)
        server_node.set_callback(MyCallback())
        server_node.start(ssh_port, http_port)
        
        time.sleep(2)
        
        # Connect
        print("Connecting client to server...")
        conn_id = client_node.connect("127.0.0.1", ssh_port, "root", "")
        print(f"Connected with ID: {conn_id}")
        
        # Test Exec
        res = client_node.exec(conn_id, "echo 'Hello from Python'")
        print(f"Exec Result: {res.strip()}")
        
        # Test host='local' callback
        print("Testing host='local' callback...")
        stream = client_node.open_stream(conn_id, "local", 1234)
        msg = b"Python Callback Test"
        stream.write(msg)
        print("Sent stream data, waiting for response...")
        resp = stream.read(1024)
        print(f"Local stream response: '{resp.decode()}'")
        expected = f"ECHO: {msg.decode()}"
        assert resp.decode() == expected
        stream.close()

        # Test Remote Forward
        print("Testing Remote Forward callback...")
        remote_port = client_node.add_remote_forward(conn_id, 22222, "127.0.0.1", 0)
        if remote_port == 0: remote_port = 22222
        print(f"Remote forward added on port {remote_port}")
        
        time.sleep(1)
        
        # Trigger remote forward
        print(f"Connecting to remote forward port {remote_port}...")
        with socket.create_connection(("127.0.0.1", remote_port)) as s:
            s.sendall(b"TRIGGER")
            resp = s.recv(1024)
            print(f"Remote forward trigger response: {resp.decode()}")
            assert resp.decode() == "REVERSE_ECHO_RESPONSE"

        print("Test completed successfully!")

    except Exception as e:
        print(f"Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
    finally:
        pass

if __name__ == "__main__":
    test_mesh()
