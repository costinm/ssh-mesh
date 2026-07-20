"""OpenSSH ControlMaster mux client used by the mesh binary baseline."""

import array
import socket
import struct

MUX_MSG_HELLO = 0x00000001
MUX_C_ALIVE_CHECK = 0x10000004
MUX_C_OPEN_FWD = 0x10000006
MUX_S_OK = 0x80000001
MUX_S_FAILURE = 0x80000003
MUX_S_ALIVE = 0x80000005
MUX_S_REMOTE_PORT = 0x80000007
MUX_PROTOCOL_VERSION = 4
MUX_FWD_LOCAL = 1
MUX_FWD_REMOTE = 2
MAX_PACKET = 64 * 1024


def _u32(value):
    return struct.pack(">I", value)


def _string(value):
    value = value.encode("utf-8")
    return _u32(len(value)) + value


class MuxClient:
    """Synchronous OpenSSH ControlMaster client for forwarding operations."""

    def __init__(self, socket_path):
        self.socket_path = socket_path
        self.sock = None
        self._next_id = 1

    def connect(self):
        if self.sock is not None:
            return self
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.socket_path)
        message_type, payload = self._read_packet()
        if message_type != MUX_MSG_HELLO or self._read_u32(payload)[0] != MUX_PROTOCOL_VERSION:
            raise RuntimeError("peer is not an OpenSSH mux protocol v4 server")
        self._send_packet(_u32(MUX_MSG_HELLO) + _u32(MUX_PROTOCOL_VERSION))
        return self

    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, exc_type, exc, traceback):
        self.close()

    def _read_exact(self, size):
        result = bytearray()
        while len(result) < size:
            data = self.sock.recv(size - len(result))
            if not data:
                raise EOFError("mux socket closed")
            result += data
        return bytes(result)

    def _read_packet(self):
        length = struct.unpack(">I", self._read_exact(4))[0]
        if not 4 <= length <= MAX_PACKET:
            raise RuntimeError(f"invalid mux packet length {length}")
        body = self._read_exact(length)
        return struct.unpack(">I", body[:4])[0], body[4:]

    def _send_packet(self, payload):
        self.sock.sendall(_u32(len(payload)) + payload)

    @staticmethod
    def _read_u32(payload, offset=0):
        if offset + 4 > len(payload):
            raise RuntimeError("short mux u32")
        return struct.unpack(">I", payload[offset:offset + 4])[0], offset + 4

    @classmethod
    def _read_string(cls, payload, offset):
        length, offset = cls._read_u32(payload, offset)
        if offset + length > len(payload):
            raise RuntimeError("short mux string")
        return payload[offset:offset + length].decode("utf-8", "replace"), offset + length

    def _request_id(self):
        result = self._next_id
        self._next_id = (result + 1) & 0xFFFFFFFF or 1
        return result

    @classmethod
    def _failure(cls, payload):
        _, offset = cls._read_u32(payload)
        reason, _ = cls._read_string(payload, offset)
        raise RuntimeError(reason)

    def alive(self):
        request_id = self._request_id()
        self._send_packet(_u32(MUX_C_ALIVE_CHECK) + _u32(request_id))
        message_type, payload = self._read_packet()
        if message_type != MUX_S_ALIVE:
            raise RuntimeError(f"expected MUX_S_ALIVE, got 0x{message_type:08x}")
        response_id, offset = self._read_u32(payload)
        pid, _ = self._read_u32(payload, offset)
        if response_id != request_id:
            raise RuntimeError("mux alive response request ID mismatch")
        return pid

    def open_forward(self, kind, listen_host, listen_port, connect_host, connect_port):
        """Open a local or remote TCP forward and return dynamic remote port if any."""
        request_id = self._request_id()
        payload = b"".join((
            _u32(MUX_C_OPEN_FWD), _u32(request_id), _u32(kind),
            _string(listen_host), _u32(listen_port),
            _string(connect_host), _u32(connect_port),
        ))
        self._send_packet(payload)
        message_type, response = self._read_packet()
        if message_type == MUX_S_OK:
            return None
        if message_type == MUX_S_REMOTE_PORT:
            _, offset = self._read_u32(response)
            return self._read_u32(response, offset)[0]
        if message_type == MUX_S_FAILURE:
            self._failure(response)
        raise RuntimeError(f"unexpected mux forward response 0x{message_type:08x}")

    def open_local_forward(self, listen_host, listen_port, connect_host, connect_port):
        return self.open_forward(MUX_FWD_LOCAL, listen_host, listen_port, connect_host, connect_port)

    def open_remote_forward(self, listen_host, listen_port, connect_host, connect_port):
        return self.open_forward(MUX_FWD_REMOTE, listen_host, listen_port, connect_host, connect_port)

    def send_fd(self, fd):
        """Send one mux descriptor using the OpenSSH one-byte marker convention."""
        self.sock.sendmsg([b"\0"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))])
