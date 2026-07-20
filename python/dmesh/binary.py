"""Mesh framed-CBOR baseline: ``length | 00 cb 00 00 | tagged CBOR``."""

import socket
import struct

MESH_RPC_META = b"\x00\xcb\x00\x00"
MAX_FRAME = 64 * 1024


def _head(major, value):
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 256:
        return bytes([(major << 5) | 24, value])
    if value < 65536:
        return bytes([(major << 5) | 25]) + struct.pack(">H", value)
    return bytes([(major << 5) | 26]) + struct.pack(">I", value)


def cbor_encode(value):
    """Encode the JSON-shaped CBOR subset used by mesh tagged records."""
    if value is None:
        return b"\xf6"
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode()
        return _head(3, len(data)) + data
    if isinstance(value, (list, tuple)):
        return _head(4, len(value)) + b"".join(cbor_encode(item) for item in value)
    if isinstance(value, dict):
        return _head(5, len(value)) + b"".join(cbor_encode(key) + cbor_encode(item) for key, item in value.items())
    if isinstance(value, float):
        return b"\xfb" + struct.pack(">d", value)
    raise TypeError(f"unsupported CBOR value: {type(value)!r}")


def cbor_decode(data):
    def take(offset, count):
        end = offset + count
        if end > len(data):
            raise ValueError("truncated CBOR")
        return data[offset:end], end

    def length(extra, offset):
        if extra < 24:
            return extra, offset
        sizes = {24: 1, 25: 2, 26: 4, 27: 8}
        size = sizes.get(extra)
        if size is None:
            raise ValueError("indefinite-length CBOR is unsupported")
        raw, offset = take(offset, size)
        return int.from_bytes(raw, "big"), offset

    def read(offset):
        initial, offset = take(offset, 1)
        initial = initial[0]
        major, extra = initial >> 5, initial & 31
        if major in (0, 1):
            value, offset = length(extra, offset)
            return (value if major == 0 else -1 - value), offset
        if major in (2, 3):
            size, offset = length(extra, offset)
            raw, offset = take(offset, size)
            return (raw if major == 2 else raw.decode()), offset
        if major == 4:
            size, offset = length(extra, offset)
            result = []
            for _ in range(size):
                value, offset = read(offset)
                result.append(value)
            return result, offset
        if major == 5:
            size, offset = length(extra, offset)
            result = {}
            for _ in range(size):
                key, offset = read(offset)
                value, offset = read(offset)
                result[key] = value
            return result, offset
        if major == 7 and extra in (20, 21, 22):
            return ({20: False, 21: True, 22: None}[extra]), offset
        if major == 7 and extra == 27:
            raw, offset = take(offset, 8)
            return struct.unpack(">d", raw)[0], offset
        raise ValueError("unsupported CBOR value")

    result, offset = read(0)
    if offset != len(data):
        raise ValueError("trailing CBOR data")
    return result


class BinaryClient:
    """Client for mesh's framed CBOR RPC records, without external packages."""

    def __init__(self, socket_path):
        self.socket_path = socket_path
        self.sock = None

    def connect(self):
        if self.sock is None:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(self.socket_path)
        return self

    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, exc_type, exc, traceback):
        self.close()

    def _exact(self, size):
        output = bytearray()
        while len(output) < size:
            data = self.sock.recv(size - len(output))
            if not data:
                raise EOFError("mesh binary service closed the connection")
            output += data
        return bytes(output)

    def send_record(self, component, method, *, record_id=None, params=(), fields=None):
        """Send mesh's tagged record envelope (keys 1-5) and return a response record."""
        record = {1: component, 2: method}
        if record_id is not None:
            record[3] = record_id
        if params:
            record[4] = list(params)
        if fields:
            record[5] = fields
        payload = cbor_encode(record)
        frame = MESH_RPC_META + payload
        self.connect()
        self.sock.sendall(struct.pack(">I", len(frame)) + frame)
        return self.read_record()

    def read_record(self):
        length = struct.unpack(">I", self._exact(4))[0]
        if not 4 <= length <= MAX_FRAME:
            raise RuntimeError(f"invalid mesh frame length {length}")
        frame = self._exact(length)
        if frame[:4] != MESH_RPC_META:
            raise RuntimeError(f"unexpected mesh frame metadata {frame[:4].hex()}")
        return cbor_decode(frame[4:])
