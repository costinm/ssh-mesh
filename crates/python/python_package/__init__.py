import os
import sys
from pathlib import Path

# Add the build directory to sys.path to find the .so file
# The .so file is typically in target/debug/libssh_mesh_py.so
lib_path = Path(__file__).parent.parent.parent.parent / "target" / "debug"
sys.path.append(str(lib_path))

try:
    import ssh_mesh_py
except ImportError as e:
    print(f"Error: Could not import ssh_mesh_py. Make sure you have built the Rust crate with 'cargo build'.")
    print(f"Current sys.path: {sys.path}")
    raise e
