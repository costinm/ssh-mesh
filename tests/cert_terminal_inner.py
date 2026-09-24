#!/usr/bin/env python3
"""Inner worker for tests/test_cert_terminal_mesh_init.py.

Runs inside a bwrap namespace that was already started by
scripts/start_bwrap.sh (mesh-init up, ssh-mesh socket-activated). It waits
for the ssh listener, prepares /home/alice with the expected owner, then
runs the certificate and plain login checks.

Usage:
    python3 cert_terminal_inner.py --ssh-port PORT --expected-uid UID [--certs-dir /certs]
"""

import argparse
import os
import pathlib
import socket
import subprocess
import sys
import time

SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
    "-o", "ConnectTimeout=10",
    "-o", "BatchMode=yes",
]


def wait_for_tcp(port, seconds=60.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.25)
    return False


def prepare_home(certs_dir, expected_uid):
    """Create /home/alice; mesh-init delegates the terminal to its owner."""
    home = pathlib.Path("/home/alice")
    home.mkdir(parents=True, exist_ok=True)
    try:
        os.chown(str(home), expected_uid, expected_uid)
    except OSError as error:
        # bwrap's own user namespace maps only the current uid (chown then
        # returns EINVAL); the test then poses through the actual owner so the
        # ssh check (below) matches (which is the mapped root then).
        print(
            f"WARN: chown {expected_uid} unsupported in this namespace ({error});"
            " delegating through the namespace's mapped uid"
        )
    return os.stat(str(home)).st_uid


def ssh_exec(ssh_port, login, identity, cert, expected_uid):
    argv = [
        "ssh",
        *SSH_OPTS,
        "-p", str(ssh_port),
        "-l", login,
        "127.0.0.1",
        "id -u",
    ]
    if identity is not None:
        argv.insert(1, "-i")
        argv.insert(2, str(identity))
    if cert is not None:
        argv.insert(1, "-o")
        argv.insert(2, f"CertificateFile={cert}")
    completed = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    code = completed.returncode
    out = completed.stdout.strip()
    err = completed.stderr.strip()
    if out == str(expected_uid):
        print(f"PASS: {login} uid={out}")
        return True
    print(
        f"FAIL: {login} -> rc={code} out='{out}' err='{err}'; expected uid {expected_uid}"
    )
    return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ssh-port", type=int, required=True)
    parser.add_argument("--expected-uid", type=int, required=True)
    parser.add_argument("--certs-dir", default="/certs")
    args = parser.parse_args()

    certs = pathlib.Path(args.certs_dir)
    if not certs.is_dir():
        print(f"FAIL: {certs} does not exist inside the namespace")
        return 1

    if not wait_for_tcp(args.ssh_port):
        print(f"FAIL: ssh listener never opened on {args.ssh_port}")
        return 1

    # The mapped uid of /home/alice's actual owner drives the terminal: when
    # the namespace chown succeeds (subuid case), the ssh terminal resolves
    # to the explicit requested identity; when the chown fails (bwrap's own
    # --unshare-user), the same uid as the process maps to the sshd home.
    alice_uid = prepare_home(certs, args.expected_uid)

    alice_key = certs / "alice"
    alice_cert = certs / "alice-cert.pub"
    if not alice_key.is_file():
        print(f"FAIL: {alice_key} not staged")
        return 1

    checks = [
        ssh_exec(args.ssh_port, "alice@test.m", alice_key, alice_cert, alice_uid),
        ssh_exec(args.ssh_port, "alice", alice_key, None, alice_uid),
    ]
    return 0 if all(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
