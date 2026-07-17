#!/usr/bin/env python3
"""Build, flash, and configure ESP boards through lmesh USB forwarding.

Run from /ws/rust/ssh-mesh after sourcing the firmware environment:

    . fw/esp32/env.sh
    python fw/esp32/rust/tools/flash_test_fleet.py

Defaults:
  * discover devices through lmesh usb.serial.list;
  * start lmesh UDS plus TCP forwards for each selected logical USB port;
  * flash through rfc2217://127.0.0.1:<port>;
  * configure baseline infra Wi-Fi mode, currently wifi.mode=nan;
  * configure all ESP targets for raw/custom NAN duty cycle with Wi-Fi off
    between discovery windows;
  * configure DFS and LoRa receive when the board has saved/probed LoRa pins.

Use explicit logical --port arguments such as USB0 or ACM1, or set
DMESH_FLASH_PORTS=USB0,USB1 when device order matters.
Keep test-specific roles, such as sleepy raw-NAN or pretend-sleep timing loops,
in separate test scripts or manual serial commands.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
FW_RUST = ROOT / "fw" / "esp32" / "rust"
SERIAL_CMD = FW_RUST / "tools" / "serial_cmd.py"
NAN_PAIR_TEST = FW_RUST / "tools" / "nan_pair_test.py"
LORA_CAD_TEST = FW_RUST / "tools" / "lora_cad_test.py"
LORA_PAIR_TEST = FW_RUST / "tools" / "lora_pair_test.py"
ESP32_MERGED_IMAGE = FW_RUST / "target" / "flash" / "esp32" / "dmesh-rs-merged.bin"
ESP32S3_MERGED_IMAGE = FW_RUST / "target" / "flash" / "esp32s3" / "dmesh-rs-merged.bin"
SPARSE_FLASH_DIR = FW_RUST / "target" / "flash" / "sparse"


@dataclass
class Device:
    port: str
    chip: str
    mac: str | None

    @property
    def logical_port(self) -> str:
        return logical_usb_port(self.port)

    @property
    def is_s3(self) -> bool:
        return self.chip == "esp32s3"

    @property
    def is_classic(self) -> bool:
        return self.chip == "esp32"


def run(
    argv: list[str],
    *,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
    check: bool = True,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(argv), flush=True)
    return subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )


def run_logged(
    label: str,
    argv: list[str],
    *,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
    tail_lines: int | None = None,
) -> str:
    print(f"{label}: + {' '.join(argv)}", flush=True)
    try:
        proc = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError as exc:
        output = exc.stdout or ""
        print_output_block(f"{label}: failed", output)
        raise
    output = proc.stdout or ""
    if output:
        if tail_lines is not None:
            output = "\n".join(output.rstrip().splitlines()[-tail_lines:]) + "\n"
        print_output_block(label, output)
    return proc.stdout or ""


def print_output_block(label: str, output: str) -> None:
    print(f"--- {label} output begin ---", flush=True)
    print(output.rstrip(), flush=True)
    print(f"--- {label} output end ---", flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--port",
        action="append",
        help=(
            "Logical lmesh USB port to probe/flash, for example USB0 or ACM1. "
            "Repeatable. Defaults to DMESH_FLASH_PORTS, then lmesh usb.serial.list."
        ),
    )
    parser.add_argument(
        "--raw-nan-port",
        action="append",
        default=[],
        help=(
            "Deprecated compatibility flag. Raw-NAN is now the default for every ESP board."
        ),
    )
    parser.add_argument("--wifi-mode", default=os.environ.get("DMESH_DEFAULT_WIFI_MODE", "nan"))
    parser.add_argument("--nan-channel", type=int, default=int(os.environ.get("DMESH_NAN_CHANNEL", "6")))
    parser.add_argument("--nan-service", default=os.environ.get("DMESH_NAN_SERVICE", "dmesh"))
    parser.add_argument("--nan-role", default=os.environ.get("DMESH_NAN_ROLE", "both"))
    parser.add_argument(
        "--expected-lora-port",
        action="append",
        default=split_env_list("DMESH_EXPECTED_LORA_PORTS") or ["USB0", "USB1", "USB2"],
        help=(
            "Logical port expected to have TLORA/SX127x wiring. Repeatable. "
            "Defaults to USB0, USB1, USB2 or DMESH_EXPECTED_LORA_PORTS."
        ),
    )
    parser.add_argument(
        "--meshcore-port",
        action="append",
        default=split_env_list("DMESH_MESHCORE_PORTS") or ["USB2"],
        help=(
            "Logical port to configure with MeshCore LoRa mode "
            "(910.525 MHz, BW 62.5 kHz, SF 7). Repeatable. "
            "Defaults to USB2 or DMESH_MESHCORE_PORTS."
        ),
    )
    parser.add_argument("--baud", type=int, default=460800)
    parser.add_argument("--probe-baud", type=int, default=460800)
    parser.add_argument(
        "--lmesh-mode",
        choices=("tcp", "local-release"),
        default=os.environ.get("DMESH_LMESH_MODE", "tcp"),
        help=(
            "tcp flashes through lmesh rfc2217:// forwards. local-release is an explicit "
            "local recovery mode: stop lmesh, flash /dev/ttyUSB*, then reopen UDS."
        ),
    )
    parser.add_argument(
        "--lmesh-control-socket",
        default=os.environ.get("LMESH_CONTROL_SOCKET"),
        help="lmesh JSONL control UDS.",
    )
    parser.add_argument(
        "--lmesh-tcp-base",
        type=int,
        default=int(os.environ.get("DMESH_LMESH_TCP_BASE", "3330")),
        help="First localhost TCP port to request from lmesh in tcp mode.",
    )
    parser.add_argument(
        "--lmesh-dtr",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Ask lmesh to pulse DTR on forwarded client connects.",
    )
    parser.add_argument(
        "--lmesh-multi",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Allow multiple forwarded clients to write during test bring-up.",
    )
    parser.add_argument("--flash-size-esp32", default="4mb")
    parser.add_argument("--flash-size-s3", default="16mb")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-flash", action="store_true")
    parser.add_argument("--skip-config", action="store_true")
    parser.add_argument("--skip-sanity", action="store_true")
    parser.add_argument(
        "--skip-feature-tests",
        action="store_true",
        help="Skip post-flash NAN/LoRa discovery and basic message tests.",
    )
    parser.add_argument(
        "--feature-test-iterations",
        type=int,
        default=int(os.environ.get("DMESH_FEATURE_TEST_ITERATIONS", "1")),
    )
    parser.add_argument(
        "--sleepy-port",
        default=os.environ.get("DMESH_SLEEPY_TEST_PORT", "USB1"),
        help="Preferred logical port for sleepy raw-NAN post-flash testing.",
    )
    parser.add_argument(
        "--sleepy-wake-ms",
        type=int,
        default=int(os.environ.get("DMESH_SLEEPY_WAKE_MS", "4000")),
    )
    parser.add_argument(
        "--sleepy-active-ms",
        type=int,
        default=int(os.environ.get("DMESH_SLEEPY_ACTIVE_MS", "500")),
    )
    parser.add_argument(
        "--sleepy-duration-sec",
        type=float,
        default=float(os.environ.get("DMESH_SLEEPY_DURATION_SEC", "30")),
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=int(os.environ.get("DMESH_FLASH_JOBS", "0")),
        help="Maximum parallel device jobs. Default 0 means one worker per device.",
    )
    parser.add_argument("--include-bad-probe", action="store_true")
    parser.add_argument(
        "--allow-local-physical-fallback",
        action="store_true",
        help="If TCP flashing fails, stop lmesh and retry the local /dev/ttyUSB* path.",
    )
    return parser.parse_args()


def default_ports(control_socket: str) -> list[str]:
    env_ports = split_env_list("DMESH_FLASH_PORTS")
    if env_ports:
        return [logical_usb_port(port) for port in env_ports]
    data = lmesh_request(control_socket, "usb.serial.list", handshake=False)
    devices = data.get("devices", [])
    if not isinstance(devices, list):
        return []
    ports = [
        item.get("port")
        for item in devices
        if isinstance(item, dict)
        and isinstance(item.get("port"), str)
        and not looks_like_android_acm(item)
    ]
    return list(dict.fromkeys(ports))


def split_env_list(key: str) -> list[str]:
    value = os.environ.get(key, "")
    return [item.strip() for item in value.split(",") if item.strip()]


def looks_like_android_acm(device: dict[str, object]) -> bool:
    text = " ".join(
        str(device.get(key, "")).lower() for key in ("by_id", "path", "kind")
    )
    return "android" in text or "samsung" in text


def logical_usb_port(port: str) -> str:
    if re.fullmatch(r"(USB|ACM)\d+", port):
        return port
    name = Path(port).name
    if name.startswith("ttyUSB"):
        return f"USB{name.removeprefix('ttyUSB')}"
    if name.startswith("ttyACM"):
        return f"ACM{name.removeprefix('ttyACM')}"
    raise ValueError(f"cannot derive lmesh logical USB port from {port}")


def physical_usb_port(port: str) -> str:
    if port.startswith("/dev/"):
        return port
    if port.startswith("USB") and port[3:].isdigit():
        return f"/dev/ttyUSB{port[3:]}"
    if port.startswith("ACM") and port[3:].isdigit():
        return f"/dev/ttyACM{port[3:]}"
    return port


def lmesh_socket_path(logical_port_name: str) -> str:
    return f"/run/mesh/lmesh-radio-build/{logical_port_name}.sock"


def lmesh_uds_url(logical_port_name: str) -> str:
    return f"uds://{lmesh_socket_path(logical_port_name)}"


def lmesh_tcp_url(tcp_port: int) -> str:
    return f"socket://127.0.0.1:{tcp_port}"


def lmesh_rfc2217_url(tcp_port: int) -> str:
    return f"rfc2217://127.0.0.1:{tcp_port}"


def lmesh_request(control_socket: str, method: str, **params: object) -> dict[str, object]:
    request = {"method": method, **{k: v for k, v in params.items() if v is not None}}
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(control_socket)
        sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
        response = bytearray()
        while not response.endswith(b"\n"):
            chunk = sock.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
    finally:
        sock.close()
    if not response:
        raise RuntimeError(f"empty lmesh response for {method}")
    decoded = json.loads(response.decode("utf-8"))
    if decoded.get("success") is False:
        raise RuntimeError(f"lmesh {method} failed: {decoded}")
    data = decoded.get("data", decoded.get("result", decoded))
    if isinstance(data, dict) and data.get("ok") is False:
        raise RuntimeError(f"lmesh {method} failed: {data}")
    if not isinstance(data, dict):
        return {"data": data}
    return data


def lmesh_stop_forward(args: argparse.Namespace, logical_port_name: str) -> None:
    assert args.lmesh_control_socket
    try:
        data = lmesh_request(
            args.lmesh_control_socket,
            "usb.serial.forward.stop",
            port=logical_port_name,
        )
        print(f"lmesh stop {logical_port_name}: {data}", flush=True)
    except Exception as exc:  # noqa: BLE001 - stale forwards should not block recovery.
        print(f"lmesh stop {logical_port_name}: {exc}", flush=True)


def lmesh_reset(args: argparse.Namespace, logical_port_name: str, mode: str) -> None:
    assert args.lmesh_control_socket
    data = lmesh_request(
        args.lmesh_control_socket,
        "usb.serial.reset",
        port=logical_port_name,
        mode=mode,
    )
    print(f"lmesh reset {logical_port_name} {mode}: {data}", flush=True)


def lmesh_start_forward(
    args: argparse.Namespace,
    logical_port_name: str,
    tcp_port: int | None,
) -> dict[str, object]:
    assert args.lmesh_control_socket
    data = lmesh_request(
        args.lmesh_control_socket,
        "usb.serial.forward.start",
        port=logical_port_name,
        baud=460800,
        tcp_port=tcp_port,
        tcp_mode="rfc2217" if tcp_port is not None else "framed",
        dtr=args.lmesh_dtr,
        multi=args.lmesh_multi,
        handshake=False,
    )
    print(f"lmesh start {logical_port_name}: {data}", flush=True)
    return data


def lmesh_forward_map(args: argparse.Namespace) -> dict[str, dict[str, object]]:
    assert args.lmesh_control_socket
    data = lmesh_request(args.lmesh_control_socket, "usb.serial.forward.list")
    forwards = data.get("forwards", [])
    if not isinstance(forwards, list):
        return {}
    mapped: dict[str, dict[str, object]] = {}
    for item in forwards:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            mapped[item["id"]] = item
    return mapped


def tcp_port_from_forward(forward: dict[str, object]) -> int | None:
    listen = forward.get("tcp_listen")
    if not isinstance(listen, str):
        return None
    match = re.search(r":(\d+)$", listen)
    if not match:
        return None
    return int(match.group(1))


def ensure_lmesh_forward(
    args: argparse.Namespace,
    logical_port_name: str,
    requested_tcp_port: int,
) -> int:
    existing = lmesh_forward_map(args).get(logical_port_name)
    if existing:
        tcp_port = tcp_port_from_forward(existing)
        if tcp_port is not None:
            print(
                f"lmesh reuse {logical_port_name}: tcp=127.0.0.1:{tcp_port}",
                flush=True,
            )
            return tcp_port
        print(f"lmesh reuse {logical_port_name}: UDS-only forward", flush=True)
        return requested_tcp_port
    data = lmesh_start_forward(args, logical_port_name, requested_tcp_port)
    return tcp_port_from_forward(data) or requested_tcp_port


def probe(
    port: str,
    baud: int,
    physical_port: str | None = None,
    before: str = "default_reset",
) -> Device | None:
    try:
        proc = run(
            [
                sys.executable,
                "-m",
                "esptool",
                "--port",
                port,
                "--baud",
                str(baud),
                "--before",
                before,
                "--after",
                "no_reset",
                "--no-stub",
                "chip_id",
            ],
            capture=True,
        )
    except subprocess.CalledProcessError as exc:
        output = exc.stdout or ""
        print(f"skip {physical_port or port}: probe failed through {port}\n{output}", flush=True)
        return None
    output = proc.stdout or ""
    chip = None
    if "ESP32-S3" in output:
        chip = "esp32s3"
    elif "ESP32" in output:
        chip = "esp32"
    mac_match = re.search(r"MAC:\s*([0-9a-f:]{17})", output, re.IGNORECASE)
    if not chip:
        print(f"skip {physical_port or port}: unsupported probe output through {port}\n{output}", flush=True)
        return None
    return Device(
        port=physical_port or port,
        chip=chip,
        mac=mac_match.group(1).lower() if mac_match else None,
    )


def build_targets(env: dict[str, str]) -> None:
    run(["cargo", "build", "--release", "--target", "xtensa-esp32-espidf"], cwd=FW_RUST, env=env)
    run(
        [
            "cargo",
            "espflash",
            "save-image",
            "--release",
            "--target",
            "xtensa-esp32-espidf",
            "--chip",
            "esp32",
            "--flash-size",
            "4mb",
            "--merge",
            "--skip-padding",
            str(ESP32_MERGED_IMAGE),
        ],
        cwd=FW_RUST,
        env=env,
    )
    s3_env = env.copy()
    s3_env.setdefault("ESP_IDF_SDKCONFIG_DEFAULTS", "sdkconfig.heltec_v3.defaults")
    run(
        ["cargo", "build", "--release", "--target", "xtensa-esp32s3-espidf"],
        cwd=FW_RUST,
        env=s3_env,
    )
    run(
        [
            "cargo",
            "espflash",
            "save-image",
            "--release",
            "--target",
            "xtensa-esp32s3-espidf",
            "--chip",
            "esp32s3",
            "--flash-size",
            "16mb",
            "--merge",
            "--skip-padding",
            str(ESP32S3_MERGED_IMAGE),
        ],
        cwd=FW_RUST,
        env=s3_env,
    )


def flash(device: Device, args: argparse.Namespace, env: dict[str, str], port: str) -> None:
    if port.startswith("rfc2217://"):
        chip = "esp32s3" if device.is_s3 else "esp32"
        flash_args, flash_files = sparse_flash_args(device)
        cmd = [
            sys.executable,
            "-m",
            "esptool",
            "--chip",
            chip,
            "--port",
            port,
            "--baud",
            str(args.baud),
            "--before",
            "no_reset" if args.lmesh_mode == "tcp" else "default_reset",
            "--after",
            "no_reset" if args.lmesh_mode == "tcp" else "hard_reset",
            "--no-stub",
            "write_flash",
        ]
        cmd.extend(flash_args)
        for offset, image in flash_files:
            cmd.extend([offset, str(image)])
        run_logged(f"flash {device.port}", cmd, cwd=FW_RUST, env=env, tail_lines=24)
        return

    if device.is_s3:
        cmd = [
            "cargo",
            "espflash",
            "flash",
            "--release",
            "--target",
            "xtensa-esp32s3-espidf",
            "--port",
            port,
            "--chip",
            "esp32s3",
            "--flash-size",
            args.flash_size_s3,
            "--baud",
            str(args.baud),
            "--non-interactive",
        ]
        flash_env = env.copy()
        flash_env.setdefault("ESP_IDF_SDKCONFIG_DEFAULTS", "sdkconfig.heltec_v3.defaults")
    else:
        cmd = [
            "cargo",
            "espflash",
            "flash",
            "--release",
            "--target",
            "xtensa-esp32-espidf",
            "--port",
            port,
            "--chip",
            "esp32",
            "--flash-size",
            args.flash_size_esp32,
            "--baud",
            str(args.baud),
            "--non-interactive",
        ]
        flash_env = env
    run_logged(f"flash {device.port}", cmd, cwd=FW_RUST, env=flash_env, tail_lines=24)


def sparse_flash_args(device: Device) -> tuple[list[str], list[tuple[str, Path]]]:
    image = ESP32S3_MERGED_IMAGE if device.is_s3 else ESP32_MERGED_IMAGE
    flash_size = "16MB" if device.is_s3 else "4MB"
    flash_freq = "80m" if device.is_s3 else "40m"
    boot_offset = 0x0 if device.is_s3 else 0x1000
    label = "esp32s3" if device.is_s3 else "esp32"
    data = image.read_bytes()
    chunks = [
        (boot_offset, 0x8000, f"{label}-bootloader.bin"),
        (0x8000, 0x9000, f"{label}-partition-table.bin"),
        (0x10000, len(data), f"{label}-app.bin"),
    ]
    out_dir = SPARSE_FLASH_DIR / label
    out_dir.mkdir(parents=True, exist_ok=True)
    flash_files: list[tuple[str, Path]] = []
    for start, end, name in chunks:
        chunk = trim_trailing_ff(data[start:end])
        if not chunk:
            continue
        path = out_dir / name
        path.write_bytes(chunk)
        flash_files.append((hex(start), path))
    return (
        ["--flash_mode", "dio", "--flash_size", flash_size, "--flash_freq", flash_freq],
        flash_files,
    )


def trim_trailing_ff(data: bytes) -> bytes:
    end = len(data)
    while end > 0 and data[end - 1] == 0xFF:
        end -= 1
    return data[:end]


def configure(device: Device, args: argparse.Namespace, port: str) -> None:
    channel = max(1, min(args.nan_channel, 13))
    commands = [
        "set key=mode value=infra",
        f"set key=wifi.mode value={args.wifi_mode}",
        "set key=power.profile value=dfs",
        "set key=nan.backend value=raw",
        "set key=nan.boot value=true",
        f"set key=nan.role value={args.nan_role}",
        f"set key=nan.service value={args.nan_service}",
        f"set key=nan.channel value={channel}",
        "set key=nan.wake_ms value=2000",
        "set key=nan.active_ms value=500",
        "mode infra=true",
        "nan stats=true",
        "lora status=true",
        "power status=true",
    ]
    if device.port in expected_lora_ports(args):
        commands[0:0] = [
            (
                "loraprobe chip=sx127x spi_host=2 sck=5 miso=19 mosi=27 "
                "cs=18 rst=23 dio0=26 save=true"
            ),
            "set key=lora.enabled value=true",
        ]
        meshcore_ports = {logical_usb_port(p) for p in args.meshcore_port}
        if device.port in meshcore_ports:
            commands.append("lora mode=meshcore")
        else:
            commands.append("lora mode=meshtastic")
    # Give the freshly flashed app a moment to boot and print the prompt.
    time.sleep(1.5)
    argv = [sys.executable, str(SERIAL_CMD), "--port", port, "--timeout", "20"]
    for item in commands:
        argv.extend(["--cmd", item])
    run_logged(f"configure {device.port}", argv, cwd=FW_RUST)


def sanity(device: Device, port: str) -> None:
    commands = [
        "status",
        "nan stats=true",
        "lora status=true",
        "power status=true",
        "logs count=20",
    ]
    argv = [sys.executable, str(SERIAL_CMD), "--port", port, "--timeout", "20"]
    for item in commands:
        argv.extend(["--cmd", item])
    print(f"sanity {device.port}: start", flush=True)
    run_logged(f"sanity {device.port}", argv, cwd=FW_RUST)
    print(f"sanity {device.port}: done", flush=True)


def console_output(device: Device, command: str, timeout: int = 20) -> str:
    argv = [
        sys.executable,
        str(SERIAL_CMD),
        "--port",
        lmesh_uds_url(device.port),
        "--timeout",
        str(timeout),
        "--cmd",
        command,
    ]
    return run_logged(f"query {device.port} {command}", argv, cwd=FW_RUST)


def discover_mac_from_console(device: Device) -> str | None:
    try:
        out = console_output(device, "wifi", timeout=8)
    except subprocess.CalledProcessError:
        return None
    match = re.search(r"\bsta_mac=([0-9a-f:]{17})\b", out, re.IGNORECASE)
    return match.group(1).lower() if match else None


def console_commands(device: Device, commands: list[str], timeout: int = 20) -> str:
    argv = [
        sys.executable,
        str(SERIAL_CMD),
        "--port",
        lmesh_uds_url(device.port),
        "--timeout",
        str(timeout),
    ]
    for command in commands:
        argv.extend(["--cmd", command])
    return run_logged(f"cmds {device.port}", argv, cwd=FW_RUST)


def send_console_line_no_wait(device: Device, command: str) -> None:
    path = lmesh_socket_path(device.port)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(path)
        sock.sendall(b"\n")
        time.sleep(0.1)
        sock.sendall((command + "\n").encode("utf-8"))
    finally:
        sock.close()


def stat_value(text: str, key: str) -> int:
    matches = re.findall(rf"\b{re.escape(key)}=(\d+)\b", text)
    return int(matches[-1]) if matches else 0


def expected_lora_ports(args: argparse.Namespace) -> set[str]:
    return {logical_usb_port(port) for port in args.expected_lora_port}


def post_flash_feature_tests(devices: list[Device], args: argparse.Namespace) -> None:
    nan_devices = [device for device in devices if device.mac and device.is_classic]
    if len(nan_devices) < 2:
        nan_devices = [
            device
            for device in devices
            if device.mac and device.port.startswith("USB")
        ]
    if len(nan_devices) < 2:
        nan_devices = [device for device in devices if device.mac]
    if len(nan_devices) >= 2:
        a, b = nan_devices[:2]
        argv = [
            sys.executable,
            str(NAN_PAIR_TEST),
            "--a",
            lmesh_uds_url(a.port),
            "--b",
            lmesh_uds_url(b.port),
            "--a-mac",
            a.mac or "",
            "--b-mac",
            b.mac or "",
            "--backend",
            "raw",
            "--channel",
            str(args.nan_channel),
            "--iterations",
            str(args.feature_test_iterations),
            "--settle-sec",
            "1.0",
            "--no-expect-response",
        ]
        run_logged(f"feature nan {a.port}->{b.port}", argv, cwd=FW_RUST)
    else:
        print("feature nan: skipped, need two devices with probed MACs", flush=True)

    sleepy_raw_nan_feature_test(devices, args)

    lora_devices: list[Device] = []
    expected_lora = expected_lora_ports(args)
    missing_expected_lora: list[str] = []
    for device in devices:
        try:
            out = console_output(device, "lora status=true")
        except subprocess.CalledProcessError:
            if device.port in expected_lora:
                missing_expected_lora.append(device.port)
            continue
        if re.search(r"\bconfigured=true\b", out) or re.search(r"\blora status=true\b", out):
            if not re.search(r"\bconfigured=false\b", out):
                lora_devices.append(device)
            elif device.port in expected_lora:
                missing_expected_lora.append(device.port)
        elif device.port in expected_lora:
            missing_expected_lora.append(device.port)
    if missing_expected_lora:
        raise RuntimeError(
            "expected LoRa ports are not configured: " + ", ".join(missing_expected_lora)
        )
    if len(lora_devices) >= 2:
        rx, tx = lora_devices[:2]
        argv = [
            sys.executable,
            str(LORA_PAIR_TEST),
            "--rx",
            lmesh_uds_url(rx.port),
            "--tx",
            lmesh_uds_url(tx.port),
        ]
        run_logged(f"feature lora {tx.port}->{rx.port}", argv, cwd=FW_RUST)
    else:
        print("feature lora: skipped, need two LoRa-configured devices", flush=True)


def sleepy_raw_nan_feature_test(devices: list[Device], args: argparse.Namespace) -> None:
    candidates = [device for device in devices if device.mac]
    if len(candidates) < 2:
        print("feature sleepy_nan: skipped, need two devices with probed MACs", flush=True)
        return
    sleepy = next((device for device in candidates if device.port == args.sleepy_port), None)
    if sleepy is None:
        sleepy = candidates[1]
    peer = next((device for device in candidates if device.port != sleepy.port), None)
    if peer is None:
        print("feature sleepy_nan: skipped, no awake peer", flush=True)
        return

    wake_ms = max(1000, args.sleepy_wake_ms)
    active_ms = max(100, min(args.sleepy_active_ms, wake_ms))
    duration = max(args.sleepy_duration_sec, 20.0)
    total = max(4, int(duration * 1000 / wake_ms) + 2)
    discovery = min(2, total)

    print(
        f"feature sleepy_nan: sleepy={sleepy.port} peer={peer.port} "
        f"wake_ms={wake_ms} active_ms={active_ms} duration_sec={duration}",
        flush=True,
    )
    before = console_output(peer, "nan stats=true")
    console_commands(
        sleepy,
        [
            f"set key=nan.wake_ms value={wake_ms}",
            f"set key=nan.active_ms value={active_ms}",
            f"set key=nan.channel value={args.nan_channel}",
            f"test cnt={total} wake_ms={wake_ms} active_ms={active_ms} discovery={discovery}",
        ],
    )
    send_console_line_no_wait(
        sleepy,
        (
            f"sleep mode=nan_raw wake_ms={wake_ms} active_ms={active_ms} "
            f"channel={args.nan_channel} serial=false ble=false lora=false start=true"
        ),
    )
    time.sleep(duration)
    after = console_output(peer, "nan stats=true")
    before_rx = stat_value(before, "raw_cmd_rx")
    after_rx = stat_value(after, "raw_cmd_rx")
    before_resp = stat_value(before, "raw_resp_tx")
    after_resp = stat_value(after, "raw_resp_tx")
    try:
        if after_rx <= before_rx:
            raise RuntimeError(
                f"peer raw_cmd_rx did not increase: before={before_rx} after={after_rx}"
            )
        if after_resp <= before_resp:
            raise RuntimeError(
                f"peer raw_resp_tx did not increase: before={before_resp} after={after_resp}"
            )
        print(
            "feature sleepy_nan: ok "
            f"raw_cmd_rx_delta={after_rx - before_rx} raw_resp_tx_delta={after_resp - before_resp}",
            flush=True,
        )
    finally:
        if args.lmesh_mode == "tcp":
            lmesh_reset(args, sleepy.port, "run")
            time.sleep(1.5)
            configure(sleepy, args, lmesh_uds_url(sleepy.port))


def run_parallel(
    label: str,
    devices: list[Device],
    jobs: int,
    func,
) -> tuple[list[Device], list[Device]]:
    if not devices:
        return ([], [])
    worker_count = jobs if jobs > 0 else len(devices)
    worker_count = max(1, min(worker_count, len(devices)))
    print(f"{label}: running {len(devices)} device job(s) with {worker_count} worker(s)", flush=True)
    ok: list[Device] = []
    failed: list[Device] = []
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(func, device): device
            for device in devices
        }
        for future in as_completed(futures):
            device = futures[future]
            try:
                future.result()
                print(f"{label} {device.port}: ok", flush=True)
                ok.append(device)
            except Exception as exc:
                print(f"{label} {device.port}: failed: {exc}", flush=True)
                failed.append(device)
    return (ok, failed)


def main() -> int:
    args = parse_args()
    if not args.lmesh_control_socket:
        print("--lmesh-control-socket or LMESH_CONTROL_SOCKET is required", file=sys.stderr)
        return 1
    env = os.environ.copy()
    ports = [logical_usb_port(port) for port in (args.port or default_ports(args.lmesh_control_socket))]
    if not ports:
        print("no lmesh USB serial ports found", file=sys.stderr)
        return 1

    tcp_ports = {port: args.lmesh_tcp_base + index for index, port in enumerate(ports)}
    for port in ports:
        if args.lmesh_mode == "tcp":
            tcp_ports[port] = ensure_lmesh_forward(args, port, tcp_ports[port])

    probed: list[Device] = []
    if args.skip_flash:
        probed = [Device(port=port, chip="unknown", mac=None) for port in ports]
    else:

        def probe_one(port: str) -> Device | None:
            if args.lmesh_mode == "tcp":
                lmesh_reset(args, port, "bootloader")
                time.sleep(0.8)
            probe_port = (
                lmesh_rfc2217_url(tcp_ports[port])
                if args.lmesh_mode == "tcp"
                else physical_usb_port(port)
            )
            return probe(
                probe_port,
                args.probe_baud,
                physical_port=port,
                before="no_reset" if args.lmesh_mode == "tcp" else "default_reset",
            )

        with ThreadPoolExecutor(max_workers=max(1, len(ports))) as executor:
            futures = {executor.submit(probe_one, port): port for port in ports}
            for future in as_completed(futures):
                port = futures[future]
                device = future.result()
                if device:
                    probed.append(device)
                elif args.include_bad_probe:
                    raise SystemExit(f"probe failed for {port}")

    devices = sorted(probed, key=lambda item: item.port)
    if args.skip_flash:
        devices = [
            Device(port=device.port, chip=device.chip, mac=discover_mac_from_console(device))
            for device in devices
        ]

    if not devices:
        print("no ESP devices detected", file=sys.stderr)
        return 1

    print("detected:", flush=True)
    for device in devices:
        print(f"  {device.port}: {device.chip} mac={device.mac or 'unknown'}", flush=True)

    if not args.skip_build:
        build_targets(env)

    if not args.skip_flash:
        def flash_one(device: Device) -> None:
            if args.lmesh_mode == "tcp":
                try:
                    lmesh_reset(args, device.port, "bootloader")
                    time.sleep(0.8)
                    flash(device, args, env, lmesh_rfc2217_url(tcp_ports[device.port]))
                    lmesh_reset(args, device.port, "run")
                except subprocess.CalledProcessError as exc:
                    print(exc.stdout or "", flush=True)
                    if not args.allow_local_physical_fallback:
                        raise
                    print(
                        f"TCP flash failed for {device.port}; using explicit local physical fallback.",
                        flush=True,
                    )
                    lmesh_stop_forward(args, device.port)
                    flash(device, args, env, physical_usb_port(device.port))
                    lmesh_start_forward(args, device.port, tcp_ports[device.port])
            else:
                lmesh_stop_forward(args, device.port)
                flash(device, args, env, physical_usb_port(device.port))
                lmesh_start_forward(args, device.port, None)

        flashed, flash_failed = run_parallel("flash", devices, args.jobs, flash_one)
        if flash_failed and args.lmesh_mode == "tcp" and args.baud != 460_800:
            original_baud = args.baud
            args.baud = 460_800
            print(
                f"flash: retrying {len(flash_failed)} failed device(s) at {args.baud} after {original_baud} failure",
                flush=True,
            )
            retry_ok, retry_failed = run_parallel("flash_retry", flash_failed, args.jobs, flash_one)
            flashed.extend(retry_ok)
            flash_failed = retry_failed
            args.baud = original_baud
        devices = sorted(flashed, key=lambda item: item.port)
        if flash_failed:
            print(
                "flash: failed devices: " + ", ".join(device.port for device in flash_failed),
                flush=True,
            )
        if not devices:
            print("flash: no devices flashed successfully", file=sys.stderr)
            return 1

    if not args.skip_config:
        def configure_one(device: Device) -> None:
            if args.lmesh_mode == "local-release":
                try:
                    lmesh_start_forward(args, device.port, None)
                except RuntimeError as exc:
                    if "already exists" not in str(exc):
                        raise
            configure(device, args, lmesh_uds_url(device.port))

        configured, config_failed = run_parallel("configure", devices, args.jobs, configure_one)
        devices = sorted(configured, key=lambda item: item.port)
        if config_failed:
            print(
                "configure: failed devices: " + ", ".join(device.port for device in config_failed),
                flush=True,
            )

    if not args.skip_sanity:
        _, sanity_failed = run_parallel(
            "sanity",
            devices,
            args.jobs,
            lambda device: sanity(device, lmesh_uds_url(device.port)),
        )
        if sanity_failed:
            print(
                "sanity: failed devices: " + ", ".join(device.port for device in sanity_failed),
                flush=True,
            )
            return 1

    if not args.skip_feature_tests:
        post_flash_feature_tests(devices, args)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
