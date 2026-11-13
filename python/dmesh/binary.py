"""Mesh framed-CBOR baseline: ``length | 00 cb 00 00 | tagged CBOR``."""

import io
import socket
import struct

try:
    import cbor2
except ModuleNotFoundError as exc:
    if exc.name != "cbor2":
        raise
    raise ModuleNotFoundError(
        "BinaryClient requires cbor2; install dmesh with 'python -m pip install -e .' from the python directory"
    ) from exc

MESH_RPC_META = b"\x00\xcb\x00\x00"
MAX_FRAME = 64 * 1024


def _validate_value(value, *, encoding):
    """Validate the decoded RPC value types without interpreting CBOR bytes."""
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if depth > 64:
            raise ValueError("CBOR nesting exceeds 64 levels")
        kind = type(item)
        if item is None or kind in (bool, bytes, str, float):
            continue
        if kind is int:
            if not -(1 << 64) <= item < (1 << 64):
                raise ValueError("integer outside CBOR 64-bit range")
        elif kind in ((list, tuple) if encoding else (list,)):
            stack.extend((child, depth + 1) for child in item)
        elif kind is dict:
            for key, child in item.items():
                stack.append((key, depth + 1))
                stack.append((child, depth + 1))
        else:
            error = TypeError if encoding else ValueError
            raise error(f"unsupported CBOR value: {kind!r}")


class _RejectSemanticTags(dict):
    """Override all backend tag decoders, including built-in semantic tags."""

    def __missing__(self, key):
        def reject(decoder):
            raise ValueError("CBOR semantic tags are unsupported")
        return reject


def cbor_encode(value):
    """Encode the mesh CBOR value profile using shortest integer widths."""
    _validate_value(value, encoding=True)
    return cbor2.dumps(value)


def cbor_decode(data):
    """Decode exactly one finite, duplicate-free mesh CBOR value."""
    if len(data) > MAX_FRAME:
        raise ValueError("CBOR value exceeds maximum frame size")
    stream = io.BytesIO(data)
    try:
        decoder = cbor2.CBORDecoder(
            stream, read_size=1, max_depth=64, allow_indefinite=False,
            allow_duplicate_keys=False, semantic_decoders=_RejectSemanticTags(),
        )
        result = decoder.decode()
    except (cbor2.CBORDecodeError, UnicodeError, OverflowError, RecursionError) as exc:
        raise ValueError(f"invalid CBOR: {exc}") from exc
    if stream.read(1):
        raise ValueError("trailing CBOR data")
    _validate_value(result, encoding=False)
    return result


class BinaryClient:
    """Client for mesh's framed CBOR RPC records."""

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
        if len(frame) > MAX_FRAME:
            raise ValueError(f"mesh frame length {len(frame)} exceeds maximum {MAX_FRAME}")
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
