"""Basic tests for the dmesh Python package structure.

These tests verify the package layout and importability without
requiring the native Rust extension to be built. Integration tests
that exercise PyMeshNode live in test_mesh.py.

Usage:
    python -m pytest python/tests/test_package.py
"""

import importlib
import os
import sys

# Ensure python/ is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def test_package_has_init():
    """dmesh/__init__.py exists."""
    init_path = os.path.join(os.path.dirname(__file__), "..", "dmesh", "__init__.py")
    assert os.path.isfile(init_path), f"Missing {init_path}"


def test_package_has_main():
    """dmesh/__main__.py exists so 'python -m dmesh' works."""
    main_path = os.path.join(os.path.dirname(__file__), "..", "dmesh", "__main__.py")
    assert os.path.isfile(main_path), f"Missing {main_path}"


def test_rust_source_present():
    """Rust source files exist in src/."""
    src_dir = os.path.join(os.path.dirname(__file__), "..", "src")
    for fname in ("lib.rs", "mesh_common.rs", "mesh_python.rs"):
        fpath = os.path.join(src_dir, fname)
        assert os.path.isfile(fpath), f"Missing Rust source: {fpath}"


def test_cargo_toml_present():
    """Cargo.toml exists in python/."""
    cargo_path = os.path.join(os.path.dirname(__file__), "..", "Cargo.toml")
    assert os.path.isfile(cargo_path), f"Missing {cargo_path}"


def test_cargo_toml_no_bin_section():
    """Cargo.toml should NOT have a [[bin]] section (main.rs was removed)."""
    cargo_path = os.path.join(os.path.dirname(__file__), "..", "Cargo.toml")
    with open(cargo_path) as f:
        content = f.read()
    assert "[[bin]]" not in content, "Cargo.toml should not have a [[bin]] section"


def test_no_main_rs():
    """main.rs should NOT exist (removed per migration)."""
    main_rs = os.path.join(os.path.dirname(__file__), "..", "src", "main.rs")
    assert not os.path.exists(main_rs), f"main.rs should not exist: {main_rs}"


def test_cargo_config_forces_gnu_target():
    """.cargo/config.toml should force x86_64-unknown-linux-gnu."""
    config_path = os.path.join(os.path.dirname(__file__), "..", ".cargo", "config.toml")
    assert os.path.isfile(config_path), f"Missing {config_path}"
    with open(config_path) as f:
        content = f.read()
    assert "x86_64-unknown-linux-gnu" in content, (
        ".cargo/config.toml should target x86_64-unknown-linux-gnu"
    )


def test_pyproject_toml_manifest_path():
    """pyproject.toml should point to local Cargo.toml, not ../crates/dmesh/."""
    pyproject_path = os.path.join(os.path.dirname(__file__), "..", "pyproject.toml")
    with open(pyproject_path) as f:
        content = f.read()
    assert 'manifest-path = "Cargo.toml"' in content, (
        "pyproject.toml should reference local Cargo.toml"
    )
    assert "crates/dmesh" not in content, (
        "pyproject.toml should not reference crates/dmesh"
    )


def test_init_exports():
    """__init__.py should declare __all__ with expected exports."""
    init_path = os.path.join(os.path.dirname(__file__), "..", "dmesh", "__init__.py")
    with open(init_path) as f:
        content = f.read()
    assert "PyMeshNode" in content
    assert "PyMeshStream" in content
    assert '__all__' in content


if __name__ == "__main__":
    # Run tests standalone without requiring pytest
    import unittest
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Discover test functions (test_*) in this module
    for name, obj in list(globals().items()):
        if name.startswith("test_") and callable(obj):
            # Wrap each test function into a unittest TestCase
            class _Test(unittest.TestCase):
                pass
            _method_name = f"test_{name}"
            setattr(_Test, _method_name, lambda self, fn=obj: fn())
            suite.addTest(_Test(_method_name))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)

