#!/usr/bin/env python3
"""Cert + terminal delegation test, using scripts/start_bwrap.sh.

Verifies the ssh-mesh <-> mesh-init SSH terminal contract end to end:

1. mesh-init binds the ssh listener declared by the service's
   ``[[Socket.Listen]]`` and transfers it to ssh-mesh at activation
   (systemd-style fd 3 + ``LISTEN_FDS``, fd name ``ssh``).
2. A CA-signed certificate login (``alice@test.m``) and a plain
   authorized-key login (``alice``) both delegate through mesh-init's
   tagged-CBOR ``start_terminal`` and run with the home directory owner's
   uid (``tests/cert_terminal_inner.py`` holds the assertion logic).

Binaries are not built: the runtime comes from the release tree staged by
``scripts/build.sh`` (``target/dist/opt/ssh-mesh/bin``), a plain cargo
release dir, or ``SSH_MESH_TEST_BIN`` (which may select a Nix result path).
Missing binaries lead to an exit status of 77.

Usage:
    python3 tests/test_cert_terminal_mesh_init.py [--case root|subuid|all]

Environment:
    SSH_MESH_TEST_BIN    directory with ssh-mesh, mesh-init, mesh (overrides)
    SSH_MESH_TEST_KEEP   keep the scratch dir for debugging
"""

import argparse
import atexit
import logging
import os
import pathlib
import shutil
import stat
import socket
import subprocess
import sys
import tempfile
import time

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
START_BWRAP = REPO_ROOT / "scripts" / "start_bwrap.sh"
INNER = REPO_ROOT / "tests" / "cert_terminal_inner.py"
BIN_NAMES = ("ssh-mesh", "mesh-init", "mesh")

# Fixed paths inside the bwrap namespace (sources are staged under the
# scratch dir and are bind-mounted by start_bwrap.sh at these locations).
BIN_DIR_IN_NS = "/opt/ssh-mesh/bin"
CERTS_DIR_IN_NS = "/certs"
SSH_CONFIG_DIR_IN_NS = "/certs/ssh-mesh-config"
SSH_SERVER_DIR_IN_NS = "/certs/server-ssh"
ALICE_HOME_IN_NS = "/home/alice"

# Mapped identities and expected owner of the alice home.
ROOT_CASE_HOME_UID = 1234
SUBUID_REGULAR_UID = 1000
SUBUID_ALICE_UID = 1001

# The test's own namespace (network is not isolated, so ssh runs from the
# host against the socket-activated ssh-mesh listener).
def free_port():
    """Bind 0.0.0.0:0 to pick a free host port; mesh-init binds them in-ns and
    ssh checks them from the host."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("0.0.0.0", 0))
        return sock.getsockname()[1]


def test_ports(case):
    """Fresh pair of free host ports; mesh-init owns them inside the ns."""
    ssh_port = free_port()
    http_port = free_port()
    while http_port == ssh_port:
        http_port = free_port()
    return ssh_port, http_port


def find_bin_dir(pathlib_path):
    candidates = []
    if "SSH_MESH_TEST_BIN" in os.environ:
        candidates.append(pathlib_path(os.environ["SSH_MESH_TEST_BIN"]))
    candidates.append(REPO_ROOT / "target/dist/opt/ssh-mesh/bin")
    candidates.append(REPO_ROOT / "target/x86_64-unknown-linux-musl/release")
    candidates.append(REPO_ROOT / "result-sshm/bin")
    for candidate in candidates:
        if all(
            (candidate / name).is_file() and os.access(candidate / name, os.X_OK)
            for name in BIN_NAMES
        ):
            return candidate.resolve()
    rendered = ", ".join(str(candidate) for candidate in candidates)
    print(
        f"SKIP: no release binaries with {BIN_NAMES} under {rendered}; "
        "run `scripts/build.sh rust` or set SSH_MESH_TEST_BIN"
    )
    sys.exit(77)


def require_commands(*commands):
    missing = [command for command in commands if shutil.which(command) is None]
    if missing:
        print(f"SKIP: required commands missing: {', '.join(missing)}")
        sys.exit(77)


def prepare_artifacts(scratch):
    """CA, CA-signed alice key/cert, sshd key, authorized_keys."""
    logging.info("Preparing certificates and sshd config in %s", scratch)
    cert = scratch / "certs"
    server = cert / "server-ssh"
    admin_keys = cert / "ssh-mesh-config" / "users" / "alice"
    for directory in (server, admin_keys):
        directory.mkdir(parents=True, exist_ok=True)
    ca = cert / "ca"
    alice = cert / "alice"
    for target in (ca, alice, server / "id_ecdsa"):
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ecdsa", "-N", "", "-f", str(target)],
            check=True,
        )
    subprocess.run(
        [
            "ssh-keygen", "-q",
            "-s", str(ca),
            "-I", "alice-test",
            "-n", "alice@test.m",
            "-V", "-1h:+1h",
            f"{alice}.pub",
        ],
        check=True,
    )
    (server / "authorized_cas").write_text((cert / "ca.pub").read_text())
    shutil.copy(alice.with_suffix(".pub"), admin_keys / "authorized_keys")
    # sshd refuses keys with loose ownership; only private key files get
    # 0600; the certificates, public keys, and authorized_keys stay 0644.
    for path in cert.rglob("*"):
        if not path.is_file():
            os.chmod(str(path), stat.S_IRWXU | stat.S_IXGRP | stat.S_IXOTH)
        elif path.name.endswith(".pub") or path.name == "authorized_keys":
            os.chmod(str(path), stat.S_IRUSR | stat.S_IWUSR | stat.S_IROTH)
        else:
            os.chmod(str(path), stat.S_IRUSR | stat.S_IWUSR)
    return cert


def write_service_config(scratch_root, ssh_port, http_port):
    """ssh-mesh service config consumed via MESH_INIT_DIR."""
    mesh_init_etc = scratch_root / "mesh-init-etc"
    mesh_init_etc.mkdir(parents=True, exist_ok=True)
    service_toml = f"""[Service]
Type = "exec"
ExecStart = "{BIN_DIR_IN_NS}/ssh-mesh"

[Socket]
Accept = false

[[Socket.Listen]]
Type = "stream"
Address = "0.0.0.0:{ssh_port}"
Name = "ssh"

[[Socket.Listen]]
Type = "stream"
Address = "0.0.0.0:{http_port}"
Name = "http"

[Environment]
RUST_LOG = "info"
SSH_BASEDIR = "{SSH_SERVER_DIR_IN_NS}"
SSH_MESH_CONFIG = "{SSH_CONFIG_DIR_IN_NS}"
SSH_MESH_HOME_ROOT = "/home"
MESH_INIT_SOCK = "/run/mesh/mesh-init/mesh.sock"
MESH_INIT_SEQPACKET_SOCK = "/run/mesh/mesh-init/mesh.sock.cbor"
"""
    (mesh_init_etc / "ssh-mesh.toml").write_text(service_toml, encoding="utf-8")
    return mesh_init_etc


def run_case(case, bin_dir, scratch_root):
    """One namespace per call. `case` is `root` or `subuid`."""
    logging.info("%s: preparing artifacts under %s", case, scratch_root)
    ssh_port, http_port = test_ports(case)
    certs = prepare_artifacts(scratch_root)
    user_spec = ""
    expected_uid = ROOT_CASE_HOME_UID
    if case == "subuid":
        user_spec = f"{SUBUID_REGULAR_UID}:{SUBUID_REGULAR_UID}"
        expected_uid = SUBUID_ALICE_UID
    mesh_init_etc = write_service_config(scratch_root, ssh_port, http_port)

    # The inner check runs from the mounted certs dir: the sandbox is
    # intentionally narrowly scoped (only /certs and /opt bind in).
    shutil.copy(INNER, certs / "inner.py")
    os.chmod(str(certs / "inner.py"), 0o755)

    argv = [
        "bash", str(START_BWRAP),
        "--bin", str(bin_dir),
        "--mount", f"{certs}:{CERTS_DIR_IN_NS}",
        "--mesh-init-config", str(mesh_init_etc),
        "--exec", "python3", str((pathlib.Path(CERTS_DIR_IN_NS) / "inner.py")),
        "--ssh-port", str(ssh_port),
        "--expected-uid", str(expected_uid),
    ]
    logging.info("%s: start_bwrap.sh --exec inner", case)
    result = subprocess.run(
        argv, capture_output=True, text=True, timeout=120
    )
    if result.returncode != 0:
        logging.error("%s: helper exit code %s", case, result.returncode)
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr)
        return result.returncode
    return result.stdout.count("PASS")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", default="all", choices=("all", "root", "subuid"))
    return parser.parse_args()


def main():
    args = parse_args()
    cases = ["root", "subuid"] if args.case == "all" else [args.case]
    bin_dir = find_bin_dir(pathlib.Path)
    require_commands("bash", "ssh", "ssh-keygen", "bwrap")

    keep = os.environ.get("SSH_MESH_TEST_KEEP")
    scratch_root = pathlib.Path(tempfile.mkdtemp(prefix="ssh-mesh-cert-terminal-test."))
    if keep:
        print(f"keeping scratch dir: {scratch_root}")
        atexit.register(shutil.rmtree, str(scratch_root), ignore_errors=True)
        atexit.register(lambda: print(f"kept: {scratch_root}"))
    else:
        atexit.register(shutil.rmtree, str(scratch_root), ignore_errors=True)

    failed = []
    for case_name in cases:
        scratch = scratch_root / case_name
        scratch.mkdir(parents=True, exist_ok=True)
        if run_case(case_name, bin_dir, scratch) == 0:
            print(f"PASS: case {case_name}")
        else:
            failed.append(case_name)
    if failed:
        print(f"FAIL: cases {failed}")
        return 1
    print("all cert terminal cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
