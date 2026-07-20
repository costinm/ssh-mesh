"""Hardware-test topology, power samples, metrics, and result artifacts."""

import json
import os
import socket
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .radio import RadioClient, resolve_radio_socket


@dataclass
class NodeConfig:
    name: str
    destination: str
    capabilities: list = field(default_factory=list)
    required: bool = True
    restore: list = field(default_factory=list)
    reset_on_restore: bool = False


@dataclass
class PowerMeterConfig:
    name: str
    destination: str
    measures: str
    required: bool = False


@dataclass
class LabConfig:
    nodes: dict
    power_meters: dict
    thresholds: dict

    @classmethod
    def load(cls, path):
        raw = json.loads(Path(path).read_text())
        nodes = {
            name: NodeConfig(name=name, **value)
            for name, value in raw.get("nodes", {}).items()
        }
        meters = {
            name: PowerMeterConfig(name=name, **value)
            for name, value in raw.get("power_meters", {}).items()
        }
        return cls(nodes, meters, raw.get("thresholds", {}))


@dataclass
class PowerSample:
    received_unix_ms: int
    elapsed_sec: float
    current_ma: float
    average_ma: float
    energy_counter: float
    wakeups: int
    raw_fields: list


def parse_power_sample(line, received_unix_ms=None):
    fields = line.split()
    if len(fields) < 7:
        raise ValueError("power sample needs at least seven fields: {!r}".format(line))
    return PowerSample(
        received_unix_ms=received_unix_ms or int(time.time() * 1000),
        elapsed_sec=float(fields[0]),
        # The meter prints amperes with three decimals (0.018 == 18 mA).
        current_ma=round(float(fields[1]) * 1000.0, 6),
        average_ma=round(float(fields[3]) * 1000.0, 6),
        energy_counter=float(fields[5]),
        wakeups=int(fields[6]),
        raw_fields=fields,
    )


class ArtifactWriter:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write_json(self, name, value):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

    def append_jsonl(self, name, value):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, target.open("a") as stream:
            stream.write(json.dumps(value, sort_keys=True) + "\n")


class PowerCollector:
    def __init__(self, config, artifacts):
        self.config = config
        self.artifacts = artifacts
        self.samples = []
        self.errors = []
        self.phase_samples = {}
        self.phase = "startup"
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def set_phase(self, phase):
        self.phase = phase

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _run(self):
        path = resolve_radio_socket(self.config.destination)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(path)
            sock.settimeout(0.25)
            pending = bytearray()
            while not self._stop.is_set():
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                pending.extend(chunk)
                while b"\n" in pending:
                    raw, _, pending = pending.partition(b"\n")
                    line = raw.decode("utf-8", "replace").strip()
                    if not line:
                        continue
                    try:
                        sample = parse_power_sample(line)
                    except Exception as error:  # Preserve malformed meter output.
                        self.errors.append(str(error))
                        continue
                    self.samples.append(sample)
                    phase = self.phase
                    self.phase_samples.setdefault(phase, []).append(sample)
                    value = asdict(sample)
                    value["phase"] = phase
                    self.artifacts.append_jsonl(
                        "power/{}.jsonl".format(self.config.name), value
                    )
        finally:
            sock.close()

    def summary(self):
        if not self.samples:
            return {"count": 0, "errors": self.errors}
        currents = sorted(sample.current_ma for sample in self.samples)

        def percentile(fraction):
            return currents[min(len(currents) - 1, round((len(currents) - 1) * fraction))]

        result = {
            "count": len(currents),
            "mean_ma": sum(currents) / len(currents),
            "p50_ma": percentile(0.50),
            "p95_ma": percentile(0.95),
            "max_ma": currents[-1],
            "energy_delta": self.samples[-1].energy_counter - self.samples[0].energy_counter,
            "wakeup_delta": self.samples[-1].wakeups - self.samples[0].wakeups,
            "errors": self.errors,
        }
        result["phases"] = {}
        for phase, samples in self.phase_samples.items():
            values = [sample.current_ma for sample in samples]
            result["phases"][phase] = {
                "count": len(values),
                "mean_ma": sum(values) / len(values),
                "max_ma": max(values),
            }
        return result


class LabNode:
    def __init__(self, config, artifacts, timeout=8.0):
        self.config = config
        self.artifacts = artifacts
        self.radio = RadioClient(config.destination, timeout=timeout)

    def command(self, command, **kwargs):
        result = self.radio.command(command, **kwargs)
        self.artifacts.append_jsonl(
            "commands/{}.jsonl".format(self.config.name),
            {
                "ts_unix_ms": int(time.time() * 1000),
                "command": command,
                "latency_ms": result.latency_ms,
                "raw": result.raw,
                "records": result.records,
            },
        )
        return result

    def close(self):
        self.radio.close()

    def restore(self):
        try:
            for command in self.config.restore:
                self.command(command, timeout=12.0, wake=True)
            return
        except Exception:
            if not self.config.reset_on_restore:
                raise
        self.radio.reset(timeout=5.0)
        time.sleep(2.0)
        for command in self.config.restore:
            self.command(command, timeout=12.0)
