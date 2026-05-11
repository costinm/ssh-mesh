# ssh-mesh-python

Python wrapper for the `ssh-mesh` library.

## Installation

You can install this package using `pip` or `uv`:

```bash
# Using pip
pip install .

# Using uv
uv pip install .
```

Note: This requires a Rust toolchain to be installed on your system to compile the Rust extension.

## Usage

```python
from ssh_mesh import PyMeshNode

node = PyMeshNode("/path/to/base/dir")
node.start(15022, 8080)
```

## Features

- SSH Server and Client management
- Local and Remote Port Forwarding
- Stream-based communication
- Asynchronous callbacks for connections and streams
