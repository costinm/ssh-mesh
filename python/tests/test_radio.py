import json
import socket
import threading
import time

from dmesh.lab import LabConfig, parse_power_sample
from dmesh.binary import MESH_RPC_META, cbor_encode
from dmesh.radio import RadioClient, parse_text_record, resolve_radio_socket


class RecordingSocket:
    def __init__(self):
        self.sent = []

    def sendall(self, data):
        self.sent.append(data)


def firmware_frame(message, *, method=33, status="ok"):
    payload = cbor_encode({0: method, 4: status, 6: {32: message}})
    body = MESH_RPC_META + payload
    return len(body).to_bytes(4, "big") + body


def test_resolve_radio_socket_is_local_only():
    assert resolve_radio_socket("lora1.lmesh") == "/run/mesh/lmesh/lora1.sock"
    assert resolve_radio_socket("unix:///tmp/radio.sock") == "/tmp/radio.sock"
    try:
        resolve_radio_socket("lora1.lmesh.remote.example")
    except ValueError as error:
        assert "locally visible UDS" in str(error)
    else:
        raise AssertionError("remote FQDN unexpectedly resolved inside Python")


def test_parse_text_record_keeps_types_and_requires_present_fields():
    record = parse_text_record(
        "dm-rs> status uptime_ms=123 pm=true current=18.5 name=DMesh"
    )
    assert record["type"] == "status"
    assert record["fields"] == {
        "uptime_ms": 123,
        "pm": True,
        "current": 18.5,
        "name": "DMesh",
    }


def test_radio_command_ignores_wake_prompt_before_matching_response():
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    client = RadioClient("unused.lmesh", timeout=1.0)
    client.sock = left
    left.settimeout(0.05)

    def server():
        assert right.recv(1024) == b"status\n"
        right.sendall(firmware_frame("status uptime_ms=42 pm=true"))

    thread = threading.Thread(target=server)
    thread.start()
    try:
        result = client.command("status")
        assert result.record("status")["fields"]["uptime_ms"] == 42
    finally:
        client.close()
        right.close()
    thread.join(timeout=2)


def test_radio_command_matches_compact_equals_record():
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    client = RadioClient("unused.lmesh", timeout=1.0)
    client.sock = left
    left.settimeout(0.05)

    def server():
        assert right.recv(1024) == b"power uart_status=true\n"
        right.sendall(firmware_frame("uart_driver=true uart_active=true", method=50))

    thread = threading.Thread(target=server)
    thread.start()
    try:
        result = client.command("power uart_status=true", expected="uart_driver")
        assert result.record("uart_driver")["fields"]["uart_driver"] is True
        assert result.record("uart_driver")["fields"]["uart_active"] is True
    finally:
        client.close()
        right.close()
    thread.join(timeout=2)


def test_radio_decoder_resynchronizes_after_invalid_length_candidate():
    client = RadioClient("unused.lmesh")
    # This looks like a length-prefixed record, but its body is not CBOR. A
    # reset/boot fragment must not consume the valid frame that follows.
    malformed = (5).to_bytes(4, "big") + MESH_RPC_META[:1]
    client._buffer.extend(malformed + firmware_frame("status uptime_ms=77"))

    records = client._drain_records()

    assert records == ["status uptime_ms=77"]


def test_read_available_is_passive_and_drains_buffer():
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    client = RadioClient("unused.lmesh", timeout=1.0)
    client.sock = left
    left.settimeout(0.01)
    right.sendall(firmware_frame("event type=boot_window start=true", method=0, status="event"))
    try:
        assert "boot_window" in client.read_available(duration=0.03)
        started = time.monotonic()
        assert client.read_available(duration=0.02) == ""
        assert time.monotonic() - started >= 0.015
        right.settimeout(0.01)
        try:
            assert right.recv(1) == b""
        except socket.timeout:
            pass
    finally:
        client.close()
        right.close()


def test_wake_uses_lmesh_control_text_not_firmware_cbor():
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    client = RadioClient("unused.lmesh", timeout=1.0)
    client.sock = left
    left.settimeout(0.05)

    def server():
        assert right.recv(1024) == b"dtr 120\n"
        right.sendall(b"event type=lmesh.dtr ok=true hold_ms=120\n")

    thread = threading.Thread(target=server)
    thread.start()
    try:
        assert "lmesh.dtr" in client.wake()
    finally:
        client.close()
        right.close()
    thread.join(timeout=2)


def test_power_sample_and_lab_config(tmp_path):
    sample = parse_power_sample("2.400 0.0372 0.000 0.0351 1800 600 7 1", 1234)
    assert sample.current_ma == 37.2
    assert sample.average_ma == 35.1
    assert sample.energy_counter == 600
    assert sample.wakeups == 7

    path = tmp_path / "lab.json"
    path.write_text(
        json.dumps(
            {
                "nodes": {
                    "sut": {
                        "destination": "lora1.lmesh",
                        "capabilities": ["nan", "lora"],
                    }
                },
                "power_meters": {
                    "meter": {
                        "destination": "power1.lmesh",
                        "measures": "sut",
                    }
                },
            }
        )
    )
    config = LabConfig.load(path)
    assert config.nodes["sut"].destination == "lora1.lmesh"
    assert config.power_meters["meter"].measures == "sut"
