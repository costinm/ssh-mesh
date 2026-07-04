"""DMesh — Pure Python implementation of crates/mesh.

Provides protocol parsing (JSONL, JSON-RPC 2.0, Text), systemd socket activation,
SO_PEERCRED peer authentication, UDS SCM_RIGHTS FD passing, and mesh-init control.
"""

# Re-export pure Python implementation
from .jsonl import ProtocolFormat, RawRequest, Response, parse_line, format_response
from .listener import MeshListener, StdioConnection
from .client import MeshClient
from .mcp import McpRegistry
from .process import (
    resolve_control_socket_path,
    is_mesh_init_alive,
    start_mesh_init,
    ServiceController,
)

# Optional: Try importing legacy PyO3 bindings if compiled, for backward compatibility
try:
    from . import dmesh_py
    PyMeshNode = dmesh_py.PyMeshNode
    PyMeshStream = dmesh_py.PyMeshStream
except ImportError:
    # If not compiled, we can define dummy/mock classes if needed
    class PyMeshNode:
        def __init__(self, *args, **kwargs):
            raise ImportError("PyMeshNode requires legacy compiled Rust dmesh_py extension module.")
    class PyMeshStream:
        def __init__(self, *args, **kwargs):
            raise ImportError("PyMeshStream requires legacy compiled Rust dmesh_py extension module.")

__all__ = [
    "ProtocolFormat",
    "RawRequest",
    "Response",
    "parse_line",
    "format_response",
    "MeshListener",
    "StdioConnection",
    "MeshClient",
    "McpRegistry",
    "resolve_control_socket_path",
    "is_mesh_init_alive",
    "start_mesh_init",
    "ServiceController",
    "PyMeshNode",
    "PyMeshStream",
]
