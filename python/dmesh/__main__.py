"""DMesh — Single-node mesh launcher (Python).

Starts a mesh node with SSH server, HTTP server, and all available
features (process monitor, 9p export, SFTP, etc.).

Usage:
    python -m dmesh --base-dir /path/to/data --ssh-port 15022 --http-port 8080

Equivalent launchers exist in other languages — keep them in sync:
- Java:  java -cp ... com.github.costinm.dmeshnative.Main --base-dir ... --ssh-port ...
"""

import argparse
import os
import signal
import sys
import time

from dmesh import PyMeshNode


def main():
    parser = argparse.ArgumentParser(
        prog="dmesh",
        description="Start a DMesh node with SSH + HTTP servers and all features.",
    )
    parser.add_argument(
        "--base-dir", "-d",
        default=os.environ.get("SSH_BASEDIR", os.environ.get("HOME", ".")),
        help="Base directory for keys and config (default: $SSH_BASEDIR or $HOME)",
    )
    parser.add_argument(
        "--ssh-port", "-s",
        type=int,
        default=int(os.environ.get("SSH_PORT", "15022")),
        help="SSH server port (default: $SSH_PORT or 15022)",
    )
    parser.add_argument(
        "--http-port",
        type=int,
        default=int(os.environ.get("HTTP_PORT", "15080")),
        help="HTTP server port (default: $HTTP_PORT or 15080)",
    )
    args = parser.parse_args()

    print(f"Starting dmesh node: base_dir={args.base_dir}, ssh_port={args.ssh_port}, http_port={args.http_port}")

    node = PyMeshNode(args.base_dir)
    node.start(args.ssh_port, args.http_port)

    pub_key = node.get_public_key()
    print(f"Public key: {pub_key}")
    print("DMesh node started. Press Ctrl+C to stop.")

    # Block until Ctrl-C
    stop = False

    def handle_signal(signum, frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        while not stop:
            time.sleep(1)
    finally:
        print("Shutting down...")
        node.stop()


if __name__ == "__main__":
    main()
