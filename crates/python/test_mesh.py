import os
import time
from python_package import ssh_mesh_py

def test_mesh():
    base_dir = "/tmp/mesh_test"
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)
    
    print(f"Starting MeshNode in {base_dir}")
    # SSH port 2222, HTTP port 8081
    node = ssh_mesh_py.PyMeshNode(base_dir, 2222, 8081)
    node.start()
    
    # Wait for server to start
    time.sleep(2)
    
    pub_key = node.get_public_key()
    print(f"Server Public Key: {pub_key}")
    assert len(pub_key) > 0
    
    # Since we don't have a real client running to connect to this node,
    # we just test the non-blocking connect which should fail if no one is listening.
    # However, we can test that the node is up.
    
    print("MeshNode started successfully.")
    # In a real test, we would connect a client here.
    # For now, we just ensure we can create and start it without crashing.

if __name__ == "__main__":
    test_mesh()
