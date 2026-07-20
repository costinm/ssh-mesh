"""Unbuffered Unix-domain client for mesh JSONL and text services."""

import array
import json
import os
import socket


DEFAULT_SOCKETS = {
    "mesh-init": "/run/mesh/mesh-init/mesh.sock",
    "lmesh": "/run/mesh/lmesh/mesh.sock",
}


def resolve_socket(destination):
    """Resolve a service name, ``unix://`` URL, filesystem, or abstract UDS path."""
    if destination in DEFAULT_SOCKETS:
        return DEFAULT_SOCKETS[destination]
    if destination.startswith("unix://"):
        return destination[len("unix://"):]
    return destination


class MeshClient:
    """A persistent connection to one mesh service.

    JSONL requests are newline-delimited objects. Passenger file descriptors
    are sent immediately after their request as one ``F`` byte carrying one
    ``SCM_RIGHTS`` cmsg. This exactly matches ``mesh-init``'s one-``recvmsg``
    contract for `start_terminal` and `register_namespace`.
    """

    def __init__(self, destination):
        self.destination = destination
        self.socket_path = resolve_socket(destination)
        self.sock = None

    def connect(self):
        if self.sock is None:
            path = self.socket_path
            if path.startswith("_"):
                path = "\0" + path[1:]
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(path)
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
        """Send exactly one JSONL or text record."""
        self.connect()
        data = line.encode("utf-8") if isinstance(line, str) else line
        if not data.endswith(b"\n"):
            data += b"\n"
        self.sock.sendall(data)

    def read_line(self):
        """Read one record without read-ahead that could consume a passenger."""
        self.connect()
        data = bytearray()
        while True:
            byte = self.sock.recv(1)
            if not byte:
                if data:
                    return data.decode("utf-8")
                raise EOFError("mesh service closed the connection")
            data += byte
            if byte == b"\n":
                return data.decode("utf-8")

    def send_passengers(self, fds):
        """Attach all descriptors as one ancillary-data passenger transfer."""
        self.connect()
        fds = list(fds)
        if not fds:
            return
        rights = array.array("i", fds)
        self.sock.sendmsg(
            [b"F"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)]
        )

    def recv_passengers(self, max_fds=4):
        """Receive a marker and the descriptors attached to that marker."""
        self.connect()
        ints = array.array("i")
        marker, ancdata, _flags, _address = self.sock.recvmsg(
            1, socket.CMSG_SPACE(max_fds * ints.itemsize)
        )
        if marker != b"F":
            raise RuntimeError(f"expected passenger marker b'F', got {marker!r}")
        for level, kind, payload in ancdata:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                payload = payload[:len(payload) - (len(payload) % ints.itemsize)]
                ints.frombytes(payload)
        if not ints:
            raise RuntimeError("passenger marker carried no file descriptors")
        return list(ints)

    def request(self, method, params=None, *, request_id=1, passengers=()):
        """Send a flat JSON request and decode its JSON response."""
        request = dict(params or {})
        request["method"] = method
        if request_id is not None:
            request["id"] = request_id
        self.send_line(json.dumps(request, separators=(",", ":")))
        self.send_passengers(passengers)
        return json.loads(self.read_line())

    def jsonrpc(self, method, params=None, *, request_id=1, passengers=()):
        """Send a JSON-RPC 2.0 request and decode its response."""
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": request_id,
        }
        self.send_line(json.dumps(request, separators=(",", ":")))
        self.send_passengers(passengers)
        return json.loads(self.read_line())

    def text(self, record):
        """Send a mesh text-protocol record and return the response record."""
        self.send_line(record)
        return self.read_line().rstrip("\n")


def open_fd(path, flags=os.O_RDONLY):
    """Open a passenger descriptor; callers remain responsible for closing it."""
    return os.open(path, flags)
