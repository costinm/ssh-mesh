import socket
import threading

import pytest

from dmesh.binary import BinaryClient, MAX_FRAME, MESH_RPC_META, cbor_decode, cbor_encode


def test_nested_round_trip_and_binary_payload():
    value = {1: [None, True, False, b"\xf7\x00", "héllo", {"n": -1}, 1.5]}
    assert cbor_decode(cbor_encode(value)) == value


@pytest.mark.parametrize("value, encoded", [
    (2**64 - 1, bytes.fromhex("1bffffffffffffffff")),
    (-2**63, bytes.fromhex("3b7fffffffffffffff")),
    (-2**64, bytes.fromhex("3bffffffffffffffff")),
    (2**32, bytes.fromhex("1b0000000100000000")),
])
def test_integer_boundaries(value, encoded):
    assert cbor_encode(value) == encoded
    assert cbor_decode(encoded) == value


@pytest.mark.parametrize("value", [2**64, -2**64 - 1])
def test_integer_out_of_range(value):
    with pytest.raises(ValueError):
        cbor_encode(value)


@pytest.mark.parametrize("data", [
    b"\xf7", b"\x81\xf7", b"\xa1\x01\xf7",  # undefined
    b"\xff", b"\x1f", b"\x9b\xff\xff\xff\xff\xff\xff\xff\xff\xff",
    b"\x18", b"\x82\x01", b"\x01\x02", b"\x61\xff",
    b"\xa2\x01\x01\x01\x02",  # duplicate keys
    b"\x9f\x01\xff", b"\xc2\x41\x01", b"\xd9\x27\x0f\x01",
])
def test_reject_invalid_or_unsupported(data):
    with pytest.raises(ValueError):
        cbor_decode(data)


def test_send_record_all_parameters():
    left, right = socket.socketpair()
    client = BinaryClient("unused")
    client.sock = left
    received = []

    def server():
        def exact(n):
            data = bytearray()
            while len(data) < n:
                chunk = right.recv(n - len(data))
                if not chunk:
                    raise EOFError()
                data.extend(chunk)
            return bytes(data)
        size = int.from_bytes(exact(4), "big")
        frame = exact(size)
        received.append((frame[:4], cbor_decode(frame[4:])))
        response = MESH_RPC_META + cbor_encode({3: 7, 5: {"data": b"\xf7"}})
        right.sendall(len(response).to_bytes(4, "big") + response)

    thread = threading.Thread(target=server)
    thread.start()
    try:
        assert client.send_record("radio", "send", record_id=7, params=(b"\xf7",),
                                  fields={"enabled": True}) == {3: 7, 5: {"data": b"\xf7"}}
    finally:
        client.close()
        thread.join(timeout=2)
        right.close()
    assert received == [(MESH_RPC_META, {1: "radio", 2: "send", 3: 7,
                                          4: [b"\xf7"], 5: {"enabled": True}})]


def test_send_record_frame_size_boundary():
    class FakeSocket:
        def __init__(self):
            self.writes = []
            response = MESH_RPC_META + cbor_encode({1: "ok"})
            self.response = len(response).to_bytes(4, "big") + response

        def sendall(self, data):
            self.writes.append(data)

        def recv(self, size):
            data, self.response = self.response[:size], self.response[size:]
            return data

    client = BinaryClient("unused")
    sock = FakeSocket()
    client.sock = sock
    # At this size the CBOR bytestring header has a fixed three-byte width.
    base = len(MESH_RPC_META + cbor_encode({1: "x", 2: "y", 4: [b""]}))
    # The empty bytestring header is two bytes shorter than the large one.
    payload_size = MAX_FRAME - base - 2
    assert client.send_record("x", "y", params=(b"x" * payload_size,)) == {1: "ok"}
    assert len(sock.writes) == 1
    assert int.from_bytes(sock.writes[0][:4], "big") == MAX_FRAME
    assert len(sock.writes[0]) == MAX_FRAME + 4

    sock.writes.clear()
    with pytest.raises(ValueError, match="exceeds maximum"):
        client.send_record("x", "y", params=(b"x" * (payload_size + 1),))
    assert sock.writes == []

    with pytest.raises(ValueError, match="exceeds maximum"):
        client.send_record("x", "y", params=(b"x" * 65536,))
    assert sock.writes == []
