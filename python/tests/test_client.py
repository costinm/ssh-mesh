import array
import json
import os
import socket
import tempfile
import threading

from dmesh import MeshClient, resolve_socket
from dmesh.binary import BinaryClient, MESH_RPC_META, cbor_decode, cbor_encode
from dmesh.mux import MUX_MSG_HELLO, MUX_PROTOCOL_VERSION, MUX_S_ALIVE, MuxClient


def test_resolve_socket_defaults_and_urls():
    assert resolve_socket("mesh-init") == "/run/mesh/mesh-init/mesh.sock"
    assert resolve_socket("unix:///tmp/service.sock") == "/tmp/service.sock"


def test_jsonl_request_and_all_passengers_share_one_message():
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    received = {}

    def server():
        line = bytearray()
        while not line.endswith(b"\n"):
            line += right.recv(1)
        received["request"] = json.loads(line)
        payload = array.array("i")
        marker, ancillary, _, _ = right.recvmsg(1, socket.CMSG_SPACE(2 * payload.itemsize))
        received["marker"] = marker
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                payload.frombytes(data[:len(data) - len(data) % payload.itemsize])
        received["fds"] = list(payload)
        right.sendall(b'{"success":true}\n')

    thread = threading.Thread(target=server)
    thread.start()
    read_fd, write_fd = os.pipe()
    client = MeshClient("unused")
    client.sock = left
    try:
        assert client.request("start_terminal", {"fd_count": 2}, passengers=[read_fd, write_fd]) == {"success": True}
    finally:
        os.close(read_fd)
        os.close(write_fd)
        client.close()
    thread.join(timeout=2)
    assert received["request"] == {"method": "start_terminal", "fd_count": 2, "id": 1}
    assert received["marker"] == b"F"
    assert len(received["fds"]) == 2
    for fd in received["fds"]:
        os.close(fd)
    right.close()


def test_text_protocol_round_trip():
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    client = MeshClient("unused")
    client.sock = left

    def server():
        assert right.recv(1024) == b"status name=lmesh\n"
        right.sendall(b"response success=true\n")

    thread = threading.Thread(target=server)
    thread.start()
    try:
        assert client.text("status name=lmesh") == "response success=true"
    finally:
        client.close()
        right.close()
    thread.join(timeout=2)


def test_cbor_and_mesh_binary_frame_round_trip():
    value = {1: "lmesh", 2: "nodes", 4: [True, None, b"raw"]}
    assert cbor_decode(cbor_encode(value)) == value
    assert MESH_RPC_META == b"\x00\xcb\x00\x00"


def test_binary_client_uses_mesh_frame_metadata():
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    client = BinaryClient("unused")
    client.sock = left

    def exact(size):
        data = bytearray()
        while len(data) < size:
            data += right.recv(size - len(data))
        return bytes(data)

    def server():
        size = int.from_bytes(exact(4), "big")
        frame = exact(size)
        assert frame[:4] == MESH_RPC_META
        assert cbor_decode(frame[4:]) == {1: "lmesh", 2: "nodes"}
        response = MESH_RPC_META + cbor_encode({1: "lmesh", 2: "response"})
        right.sendall(len(response).to_bytes(4, "big") + response)

    thread = threading.Thread(target=server)
    thread.start()
    try:
        assert client.send_record("lmesh", "nodes") == {1: "lmesh", 2: "response"}
    finally:
        client.close()
        right.close()
    thread.join(timeout=2)


def test_mux_handshake_and_alive_check():
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    client = MuxClient("unused")
    client.sock = left

    def packet(payload):
        right.sendall(len(payload).to_bytes(4, "big") + payload)

    def exact(size):
        data = bytearray()
        while len(data) < size:
            data += right.recv(size - len(data))
        return bytes(data)

    def read_packet():
        size = int.from_bytes(exact(4), "big")
        return exact(size)

    def server():
        packet(MUX_MSG_HELLO.to_bytes(4, "big") + MUX_PROTOCOL_VERSION.to_bytes(4, "big"))
        assert read_packet() == MUX_MSG_HELLO.to_bytes(4, "big") + MUX_PROTOCOL_VERSION.to_bytes(4, "big")
        request = read_packet()
        assert int.from_bytes(request[:4], "big") == 0x10000004
        request_id = request[4:8]
        packet(MUX_S_ALIVE.to_bytes(4, "big") + request_id + (1234).to_bytes(4, "big"))

    thread = threading.Thread(target=server)
    thread.start()
    try:
        # connect() is normally responsible for the handshake. The injected
        # socket lets this test use socketpair while exercising the wire path.
        message_type, payload = client._read_packet()
        assert message_type == MUX_MSG_HELLO
        client._send_packet(MUX_MSG_HELLO.to_bytes(4, "big") + MUX_PROTOCOL_VERSION.to_bytes(4, "big"))
        assert client.alive() == 1234
    finally:
        client.close()
        right.close()
    thread.join(timeout=2)
