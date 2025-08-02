# SSH-Mesh Python Module

A Python implementation of ssh-mesh functionality using paramiko for SSH transport. Provides secure SSH tunneling with port forwarding capabilities.

## Installation

```bash
pip install -r requirements.txt
```

Or install the package:

```bash
pip install -e .
```

## Usage

### SSH Server

```python
from ssh_server import SSHMeshServer

# Create and start server
server = SSHMeshServer(host="0.0.0.0", port=15022)
server.start()  # Blocks until stopped
```

### SSH Client

```python
from ssh_client import SSHMeshClient

# Connect to server
client = SSHMeshClient("hostname", port=15022)
client.connect(password="your_password")

# Create local port forward (L tunnel)
# Forwards localhost:8080 to httpbin.org:80 via SSH server
client.local_port_forward(8080, "httpbin.org", 80)

# Create remote port forward (R tunnel)
# Forwards SSH server's port 8080 to localhost:3000
client.remote_port_forward(8080, "localhost", 3000)

# Execute command
stdout, stderr, exit_code = client.execute_command("ls -la")

# Cleanup
client.disconnect()
```

## Running Tests

```bash
pytest test_ssh_mesh.py -v
```

## Features

- SSH server with paramiko backend
- SSH client with connection management
- Local port forwarding (L tunnels)
- Remote port forwarding (R tunnels)
- Multi-threaded connection handling
- Automatic host key generation
- Comprehensive test suite

## Architecture

- `ssh_server.py`: SSH server implementation with paramiko
- `ssh_client.py`: SSH client with port forwarding
- `test_ssh_mesh.py`: Test suite for functionality
- Default ports align with main ssh-mesh project (15022)


# Human notes

- this was initially LLM generated.
- Despite the tests section - it used `(cd /x/ws/ssh-mesh/python && python -m pytest test_ssh_mesh.py -v)` and took few iterations before creating a venv.