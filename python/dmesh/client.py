import os
import socket
import json
import array
from .jsonl import parse_line, format_response, Response, ProtocolFormat

class MeshClient:
    def __init__(self, socket_path: str, protocol_format: str = ProtocolFormat.JSONRPC):
        self.socket_path = socket_path
        self.protocol_format = protocol_format
        self.sock = None

    def connect(self):
        if self.sock:
            return
        actual_path = self.socket_path
        if actual_path.startswith("_"):
            actual_path = "\x00" + actual_path[1:]
        
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(actual_path)

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def _read_line(self) -> str:
        """Reads a single line byte-by-byte to prevent read-ahead buffering issues with SCM_RIGHTS."""
        buf = []
        while True:
            char = self.sock.recv(1)
            if not char:
                break
            buf.append(char)
            if char == b"\n":
                break
        return b"".join(buf).decode("utf-8")

    def send_line(self, line: str):
        self.sock.sendall(line.encode("utf-8"))

    def send_fd(self, fd: int):
        """Sends a single file descriptor attached to a single byte message b'F'."""
        ancdata = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))]
        self.sock.sendmsg([b"F"], ancdata)

    def recv_fd(self) -> int:
        """Receives a single file descriptor attached to the b'F' byte."""
        fds = array.array("i")
        msg, ancdata, flags, addr = self.sock.recvmsg(1, socket.CMSG_LEN(fds.itemsize))
        if not msg:
            raise RuntimeError("Connection closed while waiting for FD")
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
                fds.frombytes(cmsg_data[:fds.itemsize])
                if fds:
                    return fds[0]
        raise RuntimeError("No file descriptor received")

    def request(self, method: str, params: dict = None, pass_fds: list[int] = None, req_id: any = 1) -> dict:
        """Sends a request (JSON-RPC or Flat) and waits for the response.

        Optionally passes file descriptors.
        """
        self.connect()
        if params is None:
            params = {}

        # 1. Format the request line
        if self.protocol_format == ProtocolFormat.JSONRPC:
            payload = {
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
                "id": req_id
            }
        else:
            payload = dict(params)
            payload["method"] = method
            if req_id is not None:
                payload["id"] = req_id

        line = json.dumps(payload) + "\n"
        try:
            self.send_line(line)

            # 2. Pass FDs if requested
            if pass_fds:
                for fd in pass_fds:
                    self.send_fd(fd)

            # 3. Read and parse response
            resp_line = self._read_line()
            if not resp_line:
                raise RuntimeError("EOF reached while waiting for response")

            raw_resp = json.loads(resp_line.strip())
            return raw_resp
        finally:
            self.close()
