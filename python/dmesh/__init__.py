"""DMesh — Python bindings for the ssh-mesh network stack.

Usage:
    from dmesh import PyMeshNode, PyMeshStream

    node = PyMeshNode("/path/to/data")
    node.start(15022, 8080)
    pub_key = node.get_public_key()
"""

import importlib.util
import sys
from pathlib import Path

# 1. Try standard import (installed via maturin/pip)
try:
    from . import dmesh_py
except ImportError:
    # 2. Development mode: find the .so in target/
    current_file = Path(__file__).resolve()
    # Structure: .../python/dmesh/__init__.py
    # parents[0]: dmesh
    # parents[1]: python (where target/ lives)
    python_root = current_file.parents[1]

    potential_libs = [
        python_root / "target" / "debug" / "libdmesh.so",
        python_root / "target" / "release" / "libdmesh.so",
        python_root / "target" / "x86_64-unknown-linux-gnu" / "debug" / "libdmesh.so",
        python_root / "target" / "x86_64-unknown-linux-gnu" / "release" / "libdmesh.so",
    ]

    lib_path = None
    for p in potential_libs:
        if p.exists():
            lib_path = p
            break

    if lib_path:
        spec = importlib.util.spec_from_file_location("dmesh_py", str(lib_path))
        if spec and spec.loader:
            dmesh_py = importlib.util.module_from_spec(spec)
            sys.modules["dmesh.dmesh_py"] = dmesh_py
            spec.loader.exec_module(dmesh_py)
        else:
            raise ImportError(f"Could not load dmesh_py from {lib_path}")
    else:
        raise ImportError(
            "Could not find dmesh_py extension. "
            "Run 'cargo build -p dmesh --features python' in python/ or install via 'maturin develop'."
        )

# Re-export key classes
PyMeshNode = dmesh_py.PyMeshNode
PyMeshStream = dmesh_py.PyMeshStream

__all__ = ["PyMeshNode", "PyMeshStream"]
