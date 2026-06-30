# DMesh Python Wrapper

Python bindings for the ssh-mesh network stack via PyO3/maturin.

This directory is self-contained: Rust source, Cargo config, Python package,
and tests all live here. It is the **only** place in the repository that uses
Python and glibc (the `.cargo/config.toml` forces `x86_64-unknown-linux-gnu`).

## Structure

- `src/` — Rust crate (PyO3 extension module)
  - `lib.rs` — crate root, re-exports workspace crates
  - `mesh_common.rs` — shared mesh node logic
  - `mesh_python.rs` — PyO3 bindings
- `dmesh/` — Python package
  - `__init__.py` — re-exports `PyMeshNode`, `PyMeshStream`
  - `__main__.py` — CLI launcher (`python -m dmesh`)
- `tests/` — integration tests
- `.cargo/config.toml` — forces glibc target
- `Cargo.toml` — Rust crate manifest
- `pyproject.toml` — maturin build config

## Quick Start

```bash
# Build the native extension (development mode)
cd python/
cargo build --features python

# Or install via maturin
pip install maturin
maturin develop

# Run the CLI
python -m dmesh --base-dir /tmp/dmesh --ssh-port 15022 --http-port 8080

# Run tests (requires native extension to be built)
python -m pytest tests/
```

Java/Android JNI bindings are intentionally not included here; they live in
the Android dmesh repository.
