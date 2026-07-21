#!/usr/bin/env python3
"""Run ESP32 Rust firmware console commands over one or more serial ports."""

from __future__ import annotations

import argparse
import array
import fcntl
import os
import re
import select
import socket
import sys
import termios
import time
from urllib.parse import urlparse

PROMPT = b"dm-rs> "
FIRMWARE_FATAL_MARKERS = ("Guru Meditation", "Interrupt wdt timeout", "Rebooting...")
DEFAULT_DTR_PULSE_MS = 120
DEFAULT_RESET_HOLD_MS = 120
TIOCMGET = 0x5415
TIOCMSET = 0x5418
TIOCMBIS = 0x5416
TIOCMBIC = 0x5417
TIOCM_DTR = 0x002
TIOCM_RTS = 0x004


class Console:
    def __init__(
        self, port: str, baud: int, timeout: float, dtr_pulse_ms: int, wake_line: str
    ) -> None:
        self.port = port
        self.timeout = timeout
        self.endpoint = open_endpoint(port, baud)
        if dtr_pulse_ms:
            self.endpoint.pulse_modem_line(wake_line, dtr_pulse_ms)

    def close(self) -> None:
        self.endpoint.close()

    def sync(self) -> str:
        # Classic ESP32 UART0 wakes from light sleep after a few RX edges and
        # consumes or corrupts those bytes. Send separate disposable lines so
        # a wake transition cannot merge the tail of the preamble into the
        # first real command. A single bulk write previously produced records
        # such as "!tus" when the receiver resumed mid-frame.
        time.sleep(0.55)
        for _ in range(4):
            self.endpoint.write(b"\n")
            time.sleep(0.06)
        self.endpoint.flush_input()
        time.sleep(0.20)
        self.endpoint.write(b"status\n")
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

    def pulse_modem_line(self, line_name: str, hold_ms: int) -> None:
        """Pulse one modem-control line without disturbing the other.

        CP210x ESP boards commonly wire one line to GPIO0/PRG and the other
        to EN. TIOCMSET writes both, so use set/clear-bit ioctls here to keep
        a console wake from inadvertently resetting the chip.
        """
        line = {"dtr": TIOCM_DTR, "rts": TIOCM_RTS}.get(line_name)
        if line is None:
            raise ValueError(f"unsupported modem line {line_name}")
        fcntl.ioctl(self.fd, TIOCMBIS, array.array("i", [line]))
        time.sleep(hold_ms / 1000.0)
        fcntl.ioctl(self.fd, TIOCMBIC, array.array("i", [line]))

    def deassert_modem_lines(self) -> None:
        """Leave DTR/PRG and RTS/EN released before command traffic."""
        fcntl.ioctl(self.fd, TIOCMSET, array.array("i", [0]))

    def reset_run(self, hold_ms: int = DEFAULT_RESET_HOLD_MS) -> None:
        """Reset an ESP into its running application with DTR/PRG released."""
        # This is the same safe sequence used by lmesh: EN/RTS is asserted
        # while GPIO0/DTR remains released, then both lines are released.
        # Keep it here so boot-window UART tests do not need ad-hoc scripts.
        fcntl.ioctl(self.fd, TIOCMSET, array.array("i", [0]))
        time.sleep(0.05)
        fcntl.ioctl(self.fd, TIOCMSET, array.array("i", [TIOCM_RTS]))
        time.sleep(hold_ms / 1000.0)
        fcntl.ioctl(self.fd, TIOCMSET, array.array("i", [0]))

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

    def pulse_modem_line(self, line_name: str, hold_ms: int) -> None:
        _ = (line_name, hold_ms)

    def deassert_modem_lines(self) -> None:
        pass

    def reset_run(self, hold_ms: int = DEFAULT_RESET_HOLD_MS) -> None:
        _ = hold_ms
        raise OSError("reset-run requires a physical UART endpoint")


def open_endpoint(port: str, baud: int) -> Endpoint:
    if port.endswith(".lmesh") and "/" not in port:
        port = f"/run/mesh/lmesh/{port.removesuffix('.lmesh')}.sock"
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
            "or a bare .sock path. UDS/TCP endpoints use the same debug-console "
            "newline/prompt protocol as a physical UART."
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
        "--wake-line",
        choices=["dtr", "rts"],
        default="dtr",
        help="Physical modem-control line used for --dtr-pulse-ms (default: dtr).",
    )
    parser.add_argument(
        "--cmd", action="append", help="Command to run. Repeat for multiple commands in order."
    )
    parser.add_argument("--no-sync", action="store_true", help="Skip initial prompt sync.")
    parser.add_argument(
        "--reset-run",
        action="store_true",
        help="Reset a physical ESP into normal firmware before the command sequence.",
    )
    parser.add_argument(
        "--boot-delay-ms",
        type=int,
        default=0,
        help="Delay after --reset-run before console sync; useful for the 10 s boot window.",
    )
    parser.add_argument(
        "--capture-ms",
        type=int,
        default=0,
        help="After wake/reset, print raw UART output for this long without sending a command.",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="Repeat the complete connect/DTR-wake/command round for each port.",
    )
    parser.add_argument(
        "--repeat-delay-ms",
        type=int,
        default=250,
        help="Delay between repeated rounds (default: 250).",
    )
    parser.add_argument(
        "--repeat-cmds",
        type=int,
        default=1,
        help=(
            "Run the complete command set this many times on each open connection; "
            "unlike --repeat this does not toggle modem-control lines between sets."
        ),
    )
    parser.add_argument(
        "--assert-uptime-monotonic",
        action="store_true",
        help=(
            "Fail when a status/xstatus response reports uptime_ms that does not increase; "
            "use with --repeat to detect firmware resets during console stress."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.cmd and args.capture_ms <= 0:
        raise SystemExit("at least one --cmd or a positive --capture-ms is required")
    if args.boot_delay_ms < 0 or args.capture_ms < 0 or args.repeat_delay_ms < 0:
        raise SystemExit("timing arguments must be non-negative")
    if args.repeat < 1 or args.repeat_cmds < 1:
        raise SystemExit("--repeat and --repeat-cmds must be at least one")
    rc = 0
    for port in args.port:
        print(f"=== {port} ===", flush=True)
        previous_uptime_ms: int | None = None
        for iteration in range(args.repeat):
            if args.repeat > 1:
                print(f"--- round {iteration + 1}/{args.repeat} ---", flush=True)
            reset_run = args.reset_run and iteration == 0
            console = Console(
                port,
                args.baud,
                args.timeout,
                0 if reset_run else args.dtr_pulse_ms,
                args.wake_line,
            )
            try:
                if reset_run:
                    console.endpoint.reset_run()
                    if args.boot_delay_ms:
                        time.sleep(args.boot_delay_ms / 1000.0)
                    # A reset emits boot diagnostics and an early prompt. In the
                    # boot-window mode we send the first command without sync, so
                    # discard that stale prompt instead of attributing it to the
                    # first command response.
                    if args.no_sync:
                        console.endpoint.flush_input()
                if args.capture_ms:
                    print(console.read_until_prompt(args.capture_ms / 1000.0).rstrip(), flush=True)
                    if not args.cmd:
                        continue
                if not args.no_sync:
                    print(console.sync().rstrip(), flush=True)
                for command_set in range(args.repeat_cmds):
                    if args.repeat_cmds > 1:
                        print(
                            f"--- command set {command_set + 1}/{args.repeat_cmds} ---",
                            flush=True,
                        )
                    for command in args.cmd:
                        print(f"[{port}] $ {command}", flush=True)
                        out = console.cmd(command, args.timeout)
                        print(out.rstrip(), flush=True)
                        assert_no_firmware_fault(out, args.assert_uptime_monotonic)
                        text = out.strip()
                        if text.startswith("error ") or "\nerror " in text:
                            rc = 1
                        previous_uptime_ms = assert_monotonic_uptime(
                            out,
                            previous_uptime_ms,
                            args.assert_uptime_monotonic,
                        )
            except Exception as exc:  # noqa: BLE001 - serial tooling should report all failures.
                print(f"{port}: {exc}", file=sys.stderr, flush=True)
                rc = 1
            finally:
                console.close()
            if iteration + 1 < args.repeat and args.repeat_delay_ms:
                time.sleep(args.repeat_delay_ms / 1000.0)
    return rc


def assert_monotonic_uptime(
    output: str, previous_uptime_ms: int | None, enabled: bool
) -> int | None:
    """Extract status uptime and reject a reboot during a repeated stress run."""
    match = re.search(r"\buptime_ms=(\d+)", output)
    if not match:
        return previous_uptime_ms
    current = int(match.group(1))
    if enabled and previous_uptime_ms is not None and current <= previous_uptime_ms:
        raise RuntimeError(
            "firmware uptime regressed or stalled: "
            f"previous={previous_uptime_ms}ms current={current}ms"
        )
    return current


def assert_no_firmware_fault(output: str, enabled: bool) -> None:
    """Turn a watchdog/reset banner into a deterministic stress-test failure."""
    if not enabled:
        return
    for marker in FIRMWARE_FATAL_MARKERS:
        if marker in output:
            raise RuntimeError(f"firmware fault marker seen: {marker}")


if __name__ == "__main__":
    raise SystemExit(main())
