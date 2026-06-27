# DMesh Python Wrapper

This crate owns the Python wrapper for the dmesh mesh runtime in the
`ssh-mesh` repository.

- Python bindings live in `src/mesh_python.rs`.
- Shared mesh startup and stream helpers live in `src/mesh_common.rs`.
- Java/Android JNI bindings are intentionally not included here; they live in
  the Android dmesh repository.
