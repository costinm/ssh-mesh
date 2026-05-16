import importlib.util
import sys
from pathlib import Path

# 1. Try to import the compiled extension if it's already in the package (standard install)
try:
    from . import ssh_mesh_py
except ImportError:
    # 2. If not found, try to find it in the target directory (development mode)
    current_file = Path(__file__).resolve()
    # Structure: .../crates/python/ssh_mesh/__init__.py
    # parents[0]: ssh_mesh
    # parents[1]: python
    # parents[2]: crates
    # parents[3]: workspace root
    workspace_root = current_file.parents[3]
    
    potential_libs = [
        workspace_root / "target" / "debug" / "libssh_mesh_py.so",
        workspace_root / "target" / "release" / "libssh_mesh_py.so",
    ]
    
    lib_path = None
    for p in potential_libs:
        if p.exists():
            lib_path = p
            break
            
    if lib_path:
        # Load the .so as 'ssh_mesh_py' module
        spec = importlib.util.spec_from_file_location("ssh_mesh_py", str(lib_path))
        if spec and spec.loader:
            ssh_mesh_py = importlib.util.module_from_spec(spec)
            # Register it in sys.modules so relative imports work if needed
            sys.modules["ssh_mesh.ssh_mesh_py"] = ssh_mesh_py
            spec.loader.exec_module(ssh_mesh_py)
        else:
            raise ImportError(f"Could not load ssh_mesh_py from {lib_path}")
    else:
        raise ImportError("Could not find ssh_mesh_py extension. Run 'cargo build' or install the package.")

# Re-export key classes
PyMeshNode = ssh_mesh_py.PyMeshNode
PyMeshStream = ssh_mesh_py.PyMeshStream

__all__ = ["PyMeshNode", "PyMeshStream"]
