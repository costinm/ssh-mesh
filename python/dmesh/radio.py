"""Persistent client for an lmesh-managed firmware radio stream."""

import re
import shlex
import socket
import time
from dataclasses import dataclass, field

from dmesh.binary import MESH_RPC_META, cbor_decode


PROMPT = "dm-rs> "
FIRMWARE_RECORD_MAX = 4_000
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
    record_type = words[0]
    if "=" in record_type:
        record_type, value = record_type.split("=", 1)
        fields[record_type] = _value(value)
    for word in words[1:]:
        if "=" in word:
            key, value = word.split("=", 1)
            fields[key] = _value(value)
        else:
            positional.append(_value(word))
    return {
        "type": record_type,
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

    @staticmethod
    def _render_cbor_record(payload):
        """Render the firmware compact-CBOR response for legacy test parsers."""
        try:
            record = cbor_decode(payload)
        except (TypeError, ValueError) as error:
            return "error message=invalid_cbor_response:{}".format(error)
        if not isinstance(record, dict):
            return repr(record)
        fields = record.get(6)
        if isinstance(fields, dict) and isinstance(fields.get(32), str):
            return fields[32]
        if isinstance(record.get(5), str):
            return "error message={}".format(record[5])
        if isinstance(record.get(4), str):
            return "status={}".format(record[4])
        return repr(record)

    def _drain_records(self):
        """Decode binary firmware records, retaining lmesh control text."""
        records = []
        while self._buffer:
            # A reset can leave arbitrary bytes in the managed stream. Scan
            # for a complete record rather than trusting the first four bytes
            # as a length prefix. A candidate is authoritative only when it
            # has the generic UDS metadata *and* its CBOR payload decodes.
            valid = None
            limit = max(0, len(self._buffer) - 7)
            for offset in range(limit):
                body_len = int.from_bytes(self._buffer[offset : offset + 4], "big")
                frame_len = body_len + 4
                if not 4 <= body_len <= FIRMWARE_RECORD_MAX + 4:
                    continue
                if offset + frame_len > len(self._buffer):
                    continue
                body = bytes(self._buffer[offset + 4 : offset + frame_len])
                if not body.startswith(MESH_RPC_META):
                    continue
                rendered = self._render_cbor_record(body[4:])
                if rendered.startswith("error message=invalid_cbor_response:"):
                    continue
                valid = (offset, frame_len, rendered)
                break
            if valid is not None:
                offset, frame_len, rendered = valid
                del self._buffer[: offset + frame_len]
                records.append(rendered)
                continue
            if self._buffer[0] == 0:
                # A partial binary frame may contain newline bytes. Do not
                # mistake those payload bytes for lmesh control text.
                break
            newline = self._buffer.find(b"\n")
            if newline < 0:
                break
            line = bytes(self._buffer[:newline]).decode("utf-8", "replace").rstrip("\r")
            del self._buffer[: newline + 1]
            if line:
                records.append(line)
        return records

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
        records = []
        text = ""
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
            records.extend(self._drain_records())
            text = "\n".join(records)
            if matcher(text):
                matched_at = matched_at or time.monotonic()
        if matched_at is None:
            raise TimeoutError("radio response timeout; tail={!r}".format(text[-400:]))
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
        return "\n".join(self._drain_records())

    def prime_uart(self, settle_sec=4.5):
        """Consume one UART RX-wake frame before a test command.

        A dormant ESP may consume its first framed command while the UART
        clock resumes. This intentionally sends only a disposable ``status``
        request and drains the resulting marker/event/response. Callers then
        issue their real command once, avoiding an ambiguous retry of a
        side-effecting operation.
        """
        if settle_sec < 0:
            raise ValueError("settle_sec must not be negative")
        self.send_line("status")
        self.read_available(duration=settle_sec)

    def reset(self, timeout=None):
        self.send_line("rst")
        return self._receive(
            timeout or self.timeout,
            lambda text: "event type=lmesh.rst ok=true" in text,
        )

    def command(self, command, timeout=None, wake=False, expected=None):
        # ``wake`` remains an accepted keyword for older scenario files, but
        # runtime wake/reset is owned by firmware NAN heartbeats and the
        # managed lmesh service. Never turn it into a modem-line operation.
        del wake
        method = expected or command.split(None, 1)[0]
        started = time.monotonic()
        self.send_line(command)

        def matches(text):
            normalized = text.replace(PROMPT, "\n")
            for line in normalized.splitlines():
                line = line.strip()
                if (
                    line == method
                    or line.startswith(method + " ")
                    or line.startswith(method + "=")
                    or line.startswith("error ")
                ):
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
