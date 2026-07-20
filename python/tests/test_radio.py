import json
import socket
import threading
import time

from dmesh.lab import LabConfig, parse_power_sample
from dmesh.radio import RadioClient, parse_text_record, resolve_radio_socket


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
        right.sendall(
            b"event type=uart.wake source=button\ndm-rs> \n"
            b"dm-rs> status uptime_ms=42 pm=true\ndm-rs> "
        )

    thread = threading.Thread(target=server)
    thread.start()
    try:
        result = client.command("status")
        assert result.record("status")["fields"]["uptime_ms"] == 42
    finally:
        client.close()
        right.close()
    thread.join(timeout=2)


def test_read_available_is_passive_and_drains_buffer():
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    client = RadioClient("unused.lmesh", timeout=1.0)
    client.sock = left
    left.settimeout(0.01)
    right.sendall(b"event type=boot_window start=true\n")
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
