#!/usr/bin/env python3
"""Run ESP32 Rust firmware console commands over one or more serial ports."""

from __future__ import annotations

import argparse
import array
import fcntl
import os
import select
import socket
import sys
import termios
import time
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "python"))

from dmesh import RadioClient  # noqa: E402

PROMPT = b"dm-rs> "
DEFAULT_DTR_PULSE_MS = 120
TIOCMGET = 0x5415
TIOCMSET = 0x5418
TIOCM_DTR = 0x002


class Console:
    def __init__(self, port: str, baud: int, timeout: float, dtr_pulse_ms: int) -> None:
        self.port = port
        self.timeout = timeout
        self.endpoint = open_endpoint(port, baud)
        if dtr_pulse_ms:
            self.endpoint.pulse_dtr(dtr_pulse_ms)

    def close(self) -> None:
        self.endpoint.close()

    def sync(self) -> str:
        self.endpoint.write(b"\n\n\n")
        # UART light-sleep wake can consume the initial bytes. Let a forwarded
        # logical-DTR wake finish before clearing the wake prompts and sending
        # the delimiter for the first real command.
        time.sleep(0.55)
        self.endpoint.flush_input()
        self.endpoint.write(b"\n")
        time.sleep(0.25)
        return self.read_until_prompt(self.timeout, require_prompt=True)

    def cmd(self, command: str, timeout: float | None = None) -> str:
        self.endpoint.write((command + "\n").encode("utf-8"))
        return self.read_until_prompt(timeout or self.timeout, require_prompt=True)

    def read_until_prompt(self, timeout: float, *, require_prompt: bool = False) -> str:
        deadline = time.monotonic() + timeout
        buf = bytearray()
        saw_prompt = False
        while time.monotonic() < deadline:
            remaining = max(0.0, min(0.05, deadline - time.monotonic()))
            readable, _, _ = select.select([self.endpoint.fd], [], [], remaining)
            if not readable:
                continue
            try:
                chunk = self.endpoint.read(4096)
            except BlockingIOError:
                continue
            if not chunk:
                continue
            buf.extend(chunk)
            if PROMPT in buf:
                saw_prompt = True
                break
        if require_prompt and not saw_prompt:
            preview = bytes(buf[-240:]).decode("utf-8", "replace").replace("\r", "")
            raise TimeoutError(f"console prompt not seen after {timeout:.1f}s; tail={preview!r}")
        return bytes(buf).decode("utf-8", "replace").replace("\r", "")


class Endpoint:
    def __init__(self, fd: int) -> None:
        self.fd = fd

    def read(self, size: int) -> bytes:
        return os.read(self.fd, size)

    def write(self, data: bytes) -> None:
        os.write(self.fd, data)

    def flush_input(self) -> None:
        try:
            termios.tcflush(self.fd, termios.TCIFLUSH)
        except termios.error:
            drain_socket_input(self.fd)

    def pulse_dtr(self, hold_ms: int) -> None:
        """Pulse the board PRG/DTR line and leave it deasserted.

        Physical ESP consoles use this as a wake request. Socket transports
        have no modem-control line and deliberately override this as a no-op.
        """
        bits = array.array("i", [0])
        fcntl.ioctl(self.fd, TIOCMGET, bits, True)
        deasserted = bits[0] & ~TIOCM_DTR
        fcntl.ioctl(self.fd, TIOCMSET, array.array("i", [bits[0] | TIOCM_DTR]))
        time.sleep(hold_ms / 1000.0)
        fcntl.ioctl(self.fd, TIOCMSET, array.array("i", [deasserted]))

    def close(self) -> None:
        os.close(self.fd)


class SocketEndpoint(Endpoint):
    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        super().__init__(sock.fileno())

    def read(self, size: int) -> bytes:
        return self.sock.recv(size)

    def write(self, data: bytes) -> None:
        self.sock.sendall(data)

    def close(self) -> None:
        self.sock.close()

    def pulse_dtr(self, hold_ms: int) -> None:
        _ = hold_ms


def open_endpoint(port: str, baud: int) -> Endpoint:
    if port.startswith(("uds://", "unix://")) or port.endswith(".sock"):
        path = parse_uds_path(port)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(path)
        sock.setblocking(False)
        return SocketEndpoint(sock)
    if port.startswith(("tcp://", "socket://")):
        host, tcp_port = parse_tcp_target(port)
        sock = socket.create_connection((host, tcp_port), timeout=5.0)
        sock.setblocking(False)
        return SocketEndpoint(sock)
    fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    configure_serial(fd, baud)
    return Endpoint(fd)


def parse_uds_path(port: str) -> str:
    if port.endswith(".sock") and "://" not in port:
        return port
    parsed = urlparse(port)
    if parsed.scheme == "uds":
        if parsed.netloc and parsed.path:
            return f"/{parsed.netloc}{parsed.path}"
        return parsed.path
    if parsed.scheme == "unix":
        return parsed.path
    raise ValueError(f"unsupported UDS target {port}")


def parse_tcp_target(port: str) -> tuple[str, int]:
    parsed = urlparse(port)
    if parsed.scheme not in {"tcp", "socket"} or not parsed.hostname or not parsed.port:
        raise ValueError(f"unsupported TCP target {port}")
    return parsed.hostname, parsed.port


def drain_socket_input(fd: int) -> None:
    while True:
        readable, _, _ = select.select([fd], [], [], 0)
        if not readable:
            return
        try:
            if not os.read(fd, 4096):
                return
        except BlockingIOError:
            return


def configure_serial(fd: int, baud: int) -> None:
    speeds = {
        9600: termios.B9600,
        19200: termios.B19200,
        38400: termios.B38400,
        57600: termios.B57600,
        115200: termios.B115200,
        230400: termios.B230400,
        460800: termios.B460800,
        921600: termios.B921600,
    }
    if baud not in speeds:
        raise ValueError(f"unsupported baud rate {baud}")
    attrs = termios.tcgetattr(fd)
    attrs[0] = 0
    attrs[1] = 0
    attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
    attrs[3] = 0
    attrs[4] = speeds[baud]
    attrs[5] = speeds[baud]
    termios.tcsetattr(fd, termios.TCSANOW, attrs)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--port",
        action="append",
        required=True,
        help=(
            "Endpoint to query: /dev/ttyUSB0, uds:///run/.../USB0.sock, "
            "lora1.lmesh, tcp://127.0.0.1:3330, socket://127.0.0.1:3330, "
            "or a bare .sock path. Logical/UDS radios use the shared dmesh driver."
        ),
    )
    parser.add_argument("--baud", type=int, default=460800)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument(
        "--dtr-pulse-ms",
        type=int,
        default=DEFAULT_DTR_PULSE_MS,
        help="Physical UART wake pulse duration; use 0 to suppress it (default: 120).",
    )
    parser.add_argument(
        "--cmd",
        action="append",
        required=True,
        help="Command to run. Repeat for multiple commands in order.",
    )
    parser.add_argument("--no-sync", action="store_true", help="Skip initial prompt sync.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rc = 0
    for port in args.port:
        print(f"=== {port} ===", flush=True)
        if port.endswith(".lmesh") or port.startswith(("uds://", "unix://")) or port.endswith(
            ".sock"
        ):
            radio = RadioClient(port, timeout=args.timeout)
            try:
                radio.connect()
                if not args.no_sync:
                    print(radio.wake(timeout=args.timeout).rstrip(), flush=True)
                for command in args.cmd:
                    print(f"[{port}] $ {command}", flush=True)
                    print(radio.command(command, timeout=args.timeout).raw.rstrip(), flush=True)
            except Exception as exc:  # noqa: BLE001 - report every device failure.
                print(f"{port}: {exc}", file=sys.stderr, flush=True)
                rc = 1
            finally:
                radio.close()
            continue
        console = Console(port, args.baud, args.timeout, args.dtr_pulse_ms)
        try:
            if not args.no_sync:
                print(console.sync().rstrip(), flush=True)
            for command in args.cmd:
                print(f"[{port}] $ {command}", flush=True)
                out = console.cmd(command, args.timeout)
                print(out.rstrip(), flush=True)
                text = out.strip()
                if text.startswith("error ") or "\nerror " in text:
                    rc = 1
        except Exception as exc:  # noqa: BLE001 - serial tooling should report all failures.
            print(f"{port}: {exc}", file=sys.stderr, flush=True)
            rc = 1
        finally:
            console.close()
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
