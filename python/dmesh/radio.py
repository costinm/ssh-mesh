"""Persistent client for an lmesh-managed firmware radio stream."""

import re
import shlex
import socket
import time
from dataclasses import dataclass, field


PROMPT = "dm-rs> "
_INTEGER = re.compile(r"^-?\d+$")
_FLOAT = re.compile(r"^-?(?:\d+\.\d*|\d*\.\d+)$")


def resolve_radio_socket(destination):
    """Resolve a local radio name or explicit UDS URL.

    Remote transport remains outside this client. ssh-mesh may create the
    locally visible UDS before this function is called.
    """
    if destination.startswith(("unix://", "uds://")):
        return destination.split("://", 1)[1]
    if destination.startswith("/") or destination.startswith("_"):
        return destination
    parts = destination.split(".")
    if len(parts) == 2 and parts[1] == "lmesh":
        return "/run/mesh/lmesh/{}.sock".format(parts[0])
    raise ValueError(
        "radio destination must be NAME.lmesh or a locally visible UDS path: {}".format(
            destination
        )
    )


def _value(text):
    if text == "true":
        return True
    if text == "false":
        return False
    if _INTEGER.match(text):
        return int(text)
    if _FLOAT.match(text):
        return float(text)
    return text


def parse_text_record(line):
    """Parse one firmware key=value record without guessing missing fields."""
    line = line.strip()
    while line.startswith(PROMPT):
        line = line[len(PROMPT) :].lstrip()
    if not line:
        return None
    try:
        words = shlex.split(line)
    except ValueError:
        words = line.split()
    if not words:
        return None
    fields = {}
    positional = []
    for word in words[1:]:
        if "=" in word:
            key, value = word.split("=", 1)
            fields[key] = _value(value)
        else:
            positional.append(_value(word))
    return {
        "type": words[0],
        "fields": fields,
        "positional": positional,
        "raw": line,
    }


@dataclass
class CommandResult:
    command: str
    started_monotonic: float
    completed_monotonic: float
    raw: str
    records: list = field(default_factory=list)

    @property
    def latency_ms(self):
        return (self.completed_monotonic - self.started_monotonic) * 1000.0

    def record(self, record_type=None):
        candidates = self.records
        if record_type is not None:
            candidates = [item for item in candidates if item["type"] == record_type]
        if not candidates:
            raise KeyError(
                "response to {!r} has no {!r} record: {!r}".format(
                    self.command, record_type, self.raw[-300:]
                )
            )
        return candidates[-1]


class RadioClient:
    """One serialized firmware command/event stream owned by lmesh."""

    def __init__(self, destination, timeout=5.0, socket_factory=None):
        self.destination = destination
        self.socket_path = resolve_radio_socket(destination)
        self.timeout = timeout
        self.socket_factory = socket_factory or socket.socket
        self.sock = None
        self._buffer = bytearray()

    def connect(self):
        if self.sock is None:
            path = self.socket_path
            if path.startswith("_"):
                path = "\0" + path[1:]
            self.sock = self.socket_factory(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(path)
            self.sock.settimeout(0.1)
        return self

    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, exc_type, exc, traceback):
        self.close()

    def send_line(self, line):
        self.connect()
        data = line.encode("utf-8") if isinstance(line, str) else line
        if not data.endswith(b"\n"):
            data += b"\n"
        self.sock.sendall(data)

    def _receive(self, timeout, matcher, quiet_after_match=0.12):
        deadline = time.monotonic() + timeout
        matched_at = None
        while time.monotonic() < deadline:
            if matched_at is not None and time.monotonic() - matched_at >= quiet_after_match:
                break
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                raise EOFError("radio stream closed")
            self._buffer.extend(chunk)
            text = self._buffer.decode("utf-8", "replace").replace("\r", "")
            if matcher(text):
                matched_at = matched_at or time.monotonic()
        text = self._buffer.decode("utf-8", "replace").replace("\r", "")
        if matched_at is None:
            raise TimeoutError("radio response timeout; tail={!r}".format(text[-400:]))
        self._buffer.clear()
        return text

    def read_available(self, duration=0.2):
        """Drain already available events without writing to or waking the radio."""
        self.connect()
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                raise EOFError("radio stream closed")
            self._buffer.extend(chunk)
        text = self._buffer.decode("utf-8", "replace").replace("\r", "")
        self._buffer.clear()
        return text

    def wake(self, milliseconds=120, timeout=None):
        if not 1 <= milliseconds <= 10000:
            raise ValueError("DTR duration must be between 1 and 10000 ms")
        self.send_line("dtr {}".format(milliseconds))
        raw = self._receive(
            timeout or self.timeout,
            lambda text: "event type=lmesh.dtr ok=true" in text,
        )
        # The lmesh acknowledgement confirms the modem-control pulse, while
        # firmware still needs a short interval to restore UART and PM locks.
        # Sending immediately races resume and loses the first command.
        time.sleep(0.3)
        return raw

    def wake_uart(self):
        """Wake a light-sleeping firmware UART without touching modem lines."""
        self.send_line(b"\n\n\n\n")
        time.sleep(0.3)

    def reset(self, timeout=None):
        self.send_line("rst")
        return self._receive(
            timeout or self.timeout,
            lambda text: "event type=lmesh.rst ok=true" in text,
        )

    def command(self, command, timeout=None, wake=False, expected=None):
        if wake == "uart":
            self.wake_uart()
        elif wake:
            self.wake(timeout=timeout)
        method = expected or command.split(None, 1)[0]
        started = time.monotonic()
        self.send_line(command)

        def matches(text):
            normalized = text.replace(PROMPT, "\n")
            for line in normalized.splitlines():
                line = line.strip()
                if line == method or line.startswith(method + " ") or line.startswith("error "):
                    return True
            return False

        raw = self._receive(timeout or self.timeout, matches)
        completed = time.monotonic()
        normalized = raw.replace(PROMPT, "\n")
        records = []
        for line in normalized.splitlines():
            parsed = parse_text_record(line)
            if parsed is not None:
                records.append(parsed)
        errors = [item for item in records if item["type"] == "error"]
        if errors:
            raise RuntimeError(errors[-1]["raw"])
        return CommandResult(command, started, completed, raw, records)
