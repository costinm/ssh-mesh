"""Reusable ESP radio pre-submit scenarios driven through local mesh sockets."""

import hashlib
import statistics
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import asdict
from pathlib import Path

from .lab import ArtifactWriter, LabNode, PowerCollector


class CaseFailure(AssertionError):
    def __init__(self, message, details=None):
        super().__init__(message)
        self.details = details or {}


def _fields(result, record_type):
    return result.record(record_type)["fields"]


def _delta(before, after, key):
    if key not in before or key not in after:
        raise AssertionError("required counter {!r} is missing".format(key))
    return after[key] - before[key]


def _mac_suffix(mac):
    parts = mac.split(":")
    if len(parts) != 6:
        raise ValueError("invalid MAC {!r}".format(mac))
    return "".join(parts[-4:]).lower()


class PresubmitSuite:
    def __init__(self, config, artifact_dir, profile="quick", timeout=8.0):
        self.config = config
        self.profile = profile
        self.timeout = timeout
        self.run_id = uuid.uuid4().hex[:12]
        self.artifacts = ArtifactWriter(artifact_dir)
        self.nodes = {
            name: LabNode(node, self.artifacts, timeout=timeout)
            for name, node in config.nodes.items()
        }
        self.collectors = {
            name: PowerCollector(meter, self.artifacts)
            for name, meter in config.power_meters.items()
        }
        self.results = []
        self.available = set()

    def _result(self, name, status, started, **details):
        value = {
            "name": name,
            "status": status,
            "duration_sec": time.monotonic() - started,
            "details": details,
        }
        self.results.append(value)
        self.artifacts.append_jsonl("results.jsonl", value)

    def _run_case(self, name, function):
        started = time.monotonic()
        for collector in self.collectors.values():
            collector.set_phase(name)
        try:
            details = function() or {}
        except Exception as error:
            details = getattr(error, "details", {})
            self._result(name, "failed", started, error=str(error), **details)
            raise
        self._result(name, "passed", started, **details)

    def _capable(self, capability):
        return [
            node
            for name, node in self.nodes.items()
            if name in self.available and capability in node.config.capabilities
        ]

    def _require_nodes(self, capability, count):
        nodes = self._capable(capability)
        if len(nodes) < count:
            raise AssertionError(
                "topology requires {} {} nodes, found {}".format(
                    count, capability, len(nodes)
                )
            )
        return nodes

    def manifest(self):
        try:
            commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip()
            dirty = bool(
                subprocess.run(
                    ["git", "status", "--porcelain"],
                    check=True,
                    text=True,
                    stdout=subprocess.PIPE,
                ).stdout
            )
        except Exception:
            commit, dirty = "unknown", None
        images = {}
        for path in (
            Path("fw/esp32/rust/target/flash/sparse/esp32/esp32-app.bin"),
            Path("fw/esp32/rust/target/flash/sparse/esp32s3/esp32s3-app.bin"),
        ):
            if path.is_file():
                images[str(path)] = {
                    "bytes": path.stat().st_size,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
        return {
            "run_id": self.run_id,
            "profile": self.profile,
            "started_unix_ms": int(time.time() * 1000),
            "git_commit": commit,
            "git_dirty": dirty,
            "images": images,
            "nodes": {name: asdict(value) for name, value in self.config.nodes.items()},
            "power_meters": {
                name: asdict(value) for name, value in self.config.power_meters.items()
            },
            "thresholds": self.config.thresholds,
        }

    def inventory(self):
        inventory = {}
        for name, node in self.nodes.items():
            try:
                node.radio.connect()
                node.radio.wake(timeout=self.timeout)
                status = node.command("status", timeout=self.timeout)
                stats = node.command("stats", timeout=self.timeout)
                nan = node.command("nan stats=true", timeout=self.timeout)
            except Exception as error:
                if node.config.required:
                    raise
                inventory[name] = {"available": False, "error": str(error)}
                continue
            self.available.add(name)
            item = {
                "available": True,
                "status": _fields(status, "status"),
                "stats": _fields(stats, "stats"),
                "nan": _fields(nan, "nan"),
            }
            if "lora" in node.config.capabilities:
                item["lora"] = _fields(
                    node.command("lora status=true", timeout=self.timeout), "lora"
                )
                if item["lora"].get("configured") is False:
                    raise AssertionError("{} is declared LoRa but reports unconfigured".format(name))
            inventory[name] = item
        self.artifacts.write_json("inventory.json", inventory)
        return {"nodes": len(inventory)}

    def command_reliability(self):
        attempts = {"quick": 5, "full": 20, "stress": 100}[self.profile]
        summary = {
            name: {"latencies": [], "failures": []}
            for name in self.nodes
            if name in self.available
        }
        for sequence in range(attempts):
            for name, node in self.nodes.items():
                if name not in self.available:
                    continue
                try:
                    result = node.command("status", timeout=self.timeout)
                    _fields(result, "status")
                    summary[name]["latencies"].append(result.latency_ms)
                except Exception as error:
                    summary[name]["failures"].append(
                        {"sequence": sequence, "error": str(error)}
                    )
        result = {}
        for name, node in self.nodes.items():
            if name not in self.available:
                continue
            latencies = summary[name]["latencies"]
            failures = summary[name]["failures"]
            result[name] = {
                "sent": attempts,
                "received": len(latencies),
                "loss": len(failures),
                "latency_mean_ms": statistics.mean(latencies) if latencies else None,
                "latency_p95_ms": (
                    sorted(latencies)[round((len(latencies) - 1) * 0.95)]
                    if latencies
                    else None
                ),
                "failures": failures,
            }
            if failures:
                raise AssertionError("{} lost {}/{} status responses".format(name, len(failures), attempts))
        return result

    def _wifi_mac(self, node):
        fields = _fields(node.command("wifi", timeout=self.timeout), "wifi")
        for key in ("sta_mac", "mac", "ap_mac"):
            if fields.get(key):
                return fields[key]
        raise AssertionError("{} wifi response has no MAC".format(node.config.name))

    def nan_pair(self):
        a, b = self._require_nodes("nan", 2)[:2]
        channel = int(self.config.thresholds.get("nan", {}).get("channel", 6))
        settle = float(self.config.thresholds.get("nan", {}).get("settle_sec", 2.0))
        for node in (a, b):
            node.command("stats reset=true", timeout=self.timeout)
            node.command(
                "nan start=true backend=raw role=both service=dmesh channel={}".format(channel),
                timeout=self.timeout,
            )
        a_mac, b_mac = self._wifi_mac(a), self._wifi_mac(b)
        before_a = _fields(a.command("nan stats=true"), "nan")
        before_b = _fields(b.command("nan stats=true"), "nan")
        iterations = {"quick": 1, "full": 10, "stress": 100}[self.profile]
        spacing = float(self.config.thresholds.get("nan", {}).get("spacing_sec", 0.2))
        directions = (
            (a, b, a_mac, b_mac),
            (b, a, b_mac, a_mac),
        )
        for sequence in range(iterations):
            for sender, receiver, sender_mac, receiver_mac in directions:
                payload = "status to={} from={} run={} seq={}".format(
                    _mac_suffix(receiver_mac),
                    _mac_suffix(sender_mac),
                    self.run_id,
                    sequence,
                )
                sender.command(
                    'nan send="{}" backend=raw dst={}'.format(payload, receiver_mac),
                    timeout=self.timeout,
                )
            if sequence + 1 < iterations:
                time.sleep(spacing)
        time.sleep(settle)
        after_a = _fields(a.command("nan stats=true", wake=True), "nan")
        after_b = _fields(b.command("nan stats=true", wake=True), "nan")
        result = {
            "nodes": [a.config.name, b.config.name],
            "sent_each_direction": iterations,
            "a_raw_cmd_rx_delta": _delta(before_a, after_a, "raw_cmd_rx"),
            "b_raw_cmd_rx_delta": _delta(before_b, after_b, "raw_cmd_rx"),
            "a_raw_resp_tx_delta": _delta(before_a, after_a, "raw_resp_tx"),
            "b_raw_resp_tx_delta": _delta(before_b, after_b, "raw_resp_tx"),
            "a_raw_resp_rx_delta": _delta(before_a, after_a, "raw_resp_rx"),
            "b_raw_resp_rx_delta": _delta(before_b, after_b, "raw_resp_rx"),
            "beacon_seen_delta_a": _delta(before_a, after_a, "raw_beacon"),
            "beacon_seen_delta_b": _delta(before_b, after_b, "raw_beacon"),
        }
        min_ratio = float(self.config.thresholds.get("nan", {}).get("min_delivery_ratio", 1.0))
        minimum = max(1, int(iterations * min_ratio))
        for name in ("a", "b"):
            if result[name + "_raw_cmd_rx_delta"] < minimum:
                raise AssertionError(
                    "NAN {} received {}/{} commands, required {}".format(
                        name, result[name + "_raw_cmd_rx_delta"], iterations, minimum
                    )
                )
            if result[name + "_raw_resp_tx_delta"] < minimum:
                raise AssertionError("NAN {} did not transmit command responses".format(name))
            if result[name + "_raw_resp_rx_delta"] < minimum:
                raise AssertionError("NAN {} did not receive command responses".format(name))
        if self.config.thresholds.get("nan", {}).get("require_beacon") and (
            result["beacon_seen_delta_a"] < 1 or result["beacon_seen_delta_b"] < 1
        ):
            raise AssertionError("required NAN beacon source was not observed")
        return result

    def beacon_sync(self):
        nodes = self._require_nodes("nan", 2)[:2]
        before = {
            node.config.name: _fields(node.command("xstatus", wake=True), "xstatus")
            for node in nodes
        }
        observe_sec = float(self.config.thresholds.get("nan", {}).get("beacon_observe_sec", 6.0))
        time.sleep(observe_sec)
        after = {
            node.config.name: _fields(node.command("xstatus", wake=True), "xstatus")
            for node in nodes
        }
        result = {}
        for node in nodes:
            name = node.config.name
            result[name] = {
                key + "_delta": _delta(before[name], after[name], key)
                for key in (
                    "nan_beacon_seen",
                    "nan_beacon_missed",
                    "nan_beacon_late",
                    "nan_beacon_drift",
                )
            }
        if self.config.thresholds.get("nan", {}).get("require_beacon"):
            missing = [
                name
                for name, counters in result.items()
                if counters["nan_beacon_seen_delta"] < 1
            ]
            if missing:
                raise AssertionError("required NAN beacon not observed by " + ", ".join(missing))
        return {"observe_sec": observe_sec, "nodes": result}

    def lora_pair(self):
        a, b = self._require_nodes("lora", 2)[:2]
        lora = self.config.thresholds.get("lora", {})
        preset = lora.get("preset", "medium_fast")
        frequency = int(lora.get("frequency", 913125000))
        for node in (a, b):
            node.command(
                "lora preset={} freq={} apply=true".format(preset, frequency),
                timeout=12.0,
            )
            node.command("stats reset=true", timeout=self.timeout)
            node.command("lora rx=true", timeout=self.timeout)
        time.sleep(0.5)
        sent = {a.config.name: 0, b.config.name: 0}
        for sender in (a, b):
            sender.command(
                "lorasend text=presubmit_{}_{} hop=0".format(self.run_id, sender.config.name),
                timeout=12.0,
            )
            sent[sender.config.name] += 1
            time.sleep(float(lora.get("settle_sec", 2.0)))
        a_stats = _fields(a.command("stats", wake=True), "stats")
        b_stats = _fields(b.command("stats", wake=True), "stats")
        result = {
            "sent": sent,
            "received": {
                a.config.name: a_stats.get("lora_rx"),
                b.config.name: b_stats.get("lora_rx"),
            },
        }
        if not isinstance(result["received"][a.config.name], int) or result["received"][a.config.name] < 1:
            raise CaseFailure(
                "{} did not receive LoRa from {}".format(a.config.name, b.config.name), result
            )
        if not isinstance(result["received"][b.config.name], int) or result["received"][b.config.name] < 1:
            raise CaseFailure(
                "{} did not receive LoRa from {}".format(b.config.name, a.config.name), result
            )
        return result

    def lora_cad(self):
        receiver, sender = self._require_nodes("lora", 2)[:2]
        config = self.config.thresholds.get("lora", {})
        packets = int(config.get("cad_packets", 8 if self.profile == "full" else 30))
        receiver.command("stats reset=true", timeout=self.timeout)
        receiver.command(
            "lora cad_interval_ms={} cad_rx_ms={} cad_tx_tries=4".format(
                int(config.get("cad_interval_ms", 2000)),
                int(config.get("cad_rx_ms", 1000)),
            ),
            timeout=self.timeout,
        )
        receiver.command("lora rx=true", timeout=self.timeout)
        for sequence in range(packets):
            sender.command(
                "lorasend text=cad_{}_{} hop=0".format(self.run_id, sequence),
                timeout=12.0,
            )
            if sequence and sequence % 10 == 0:
                receiver.command("status", timeout=self.timeout)
            time.sleep(float(config.get("cad_spacing_sec", 1.0)))
        stats = _fields(receiver.command("stats", wake=True), "stats")
        lora = _fields(receiver.command("lora status=true"), "lora")
        received = stats.get("lora_rx")
        detected = lora.get("cad_detected")
        if not isinstance(received, int):
            raise AssertionError("LoRa stats omitted lora_rx")
        minimum = max(1, int(packets * float(config.get("cad_min_delivery_ratio", 0.5))))
        if received < minimum:
            raise CaseFailure(
                "CAD received {}/{} packets, required {}".format(received, packets, minimum),
                {
                    "receiver": receiver.config.name,
                    "sender": sender.config.name,
                    "sent": packets,
                    "received": received,
                    "cad_detected": detected,
                },
            )
        return {
            "receiver": receiver.config.name,
            "sender": sender.config.name,
            "sent": packets,
            "received": received,
            "cad_detected": detected,
        }

    def power_summary(self):
        result = {name: collector.summary() for name, collector in self.collectors.items()}
        thresholds = self.config.thresholds.get("power", {})
        for name, summary in result.items():
            meter = self.config.power_meters[name]
            if meter.required and summary["count"] == 0:
                raise AssertionError("required power meter {} produced no samples".format(name))
            limits = thresholds.get(name, {})
            if summary["count"] and "max_mean_ma" in limits:
                if summary["mean_ma"] > float(limits["max_mean_ma"]):
                    raise AssertionError(
                        "{} mean {:.2f} mA exceeds {:.2f} mA".format(
                            name, summary["mean_ma"], float(limits["max_mean_ma"])
                        )
                    )
        self.artifacts.write_json("power/summary.json", result)
        return result

    def run(self):
        self.artifacts.write_json("manifest.json", self.manifest())
        for collector in self.collectors.values():
            collector.start()
        failure = None

        def run_case(name, function):
            nonlocal failure
            try:
                self._run_case(name, function)
            except Exception as error:
                failure = failure or error

        try:
            run_case("inventory", self.inventory)
            run_case("command_reliability", self.command_reliability)
            if self._capable("nan"):
                run_case("nan_pair", self.nan_pair)
                if self.profile != "quick":
                    run_case("beacon_sync", self.beacon_sync)
            if self._capable("lora"):
                run_case("lora_pair", self.lora_pair)
                if self.profile != "quick":
                    run_case("lora_cad", self.lora_cad)
        finally:
            for collector in self.collectors.values():
                collector.stop()
            try:
                self._run_case("power", self.power_summary)
            except Exception as error:
                failure = failure or error
            for node in self.nodes.values():
                try:
                    node.restore()
                except Exception as error:
                    self.results.append(
                        {"name": "restore." + node.config.name, "status": "failed", "error": str(error)}
                    )
                    failure = failure or error
                node.close()
        summary = {
            "run_id": self.run_id,
            "profile": self.profile,
            "passed": failure is None,
            "results": self.results,
        }
        self.artifacts.write_json("summary.json", summary)
        self._write_junit(summary)
        self._write_tldr(summary)
        if failure is not None:
            raise failure
        return summary

    def _write_tldr(self, summary):
        by_name = {item["name"]: item for item in summary["results"]}

        def passed_details(name):
            result = by_name.get(name)
            if not result or result.get("status") != "passed":
                return None
            return result.get("details")

        lines = [
            "# ESP32 Pre-submit TL;DR",
            "",
            "- Run: `{}`".format(summary["run_id"]),
            "- Profile: `{}`".format(summary["profile"]),
            "- Result: **{}**".format("PASS" if summary["passed"] else "FAIL"),
        ]
        reliability = passed_details("command_reliability")
        if reliability:
            lines.extend(["", "## Command reliability", ""])
            for node, values in reliability.items():
                lines.append(
                    "- `{}`: {}/{} responses, loss {}, mean {:.1f} ms, p95 {:.1f} ms".format(
                        node,
                        values["received"],
                        values["sent"],
                        values["loss"],
                        values["latency_mean_ms"] or 0,
                        values["latency_p95_ms"] or 0,
                    )
                )
        nan = passed_details("nan_pair")
        if nan:
            sent = nan["sent_each_direction"]
            received_a = nan["a_raw_cmd_rx_delta"]
            received_b = nan["b_raw_cmd_rx_delta"]
            lines.extend(
                [
                    "",
                    "## NAN",
                    "",
                    "- Sent {} commands in each direction.".format(
                        sent
                    ),
                    "- RX counters: A {} events for {} sends (deficit {}); B {} events "
                    "for {} sends (deficit {}).".format(
                        received_a,
                        sent,
                        max(0, sent - received_a),
                        received_b,
                        sent,
                        max(0, sent - received_b),
                    ),
                    "- RX counters are aggregate events and may include retries; unique-sequence "
                    "loss is not measured yet.",
                    "- Response RX: A {}, B {}.".format(
                        nan["a_raw_resp_rx_delta"], nan["b_raw_resp_rx_delta"]
                    ),
                ]
            )
        lora_result = by_name.get("lora_pair")
        lora = lora_result.get("details") if lora_result else None
        if lora:
            lines.extend(["", "## LoRa", ""])
            lines.append("- Bidirectional sent: `{}`.".format(lora["sent"]))
            lines.append("- Received: `{}`.".format(lora["received"]))
            if lora_result.get("status") != "passed":
                lines.append("- Pair test result: **FAIL**.")
        cad_result = by_name.get("lora_cad")
        cad = cad_result.get("details") if cad_result else None
        if cad:
            lines.append(
                "- CAD: {}/{} packets received ({:.1f}%, loss {}); detections {}.".format(
                    cad["received"],
                    cad["sent"],
                    100.0 * cad["received"] / cad["sent"],
                    max(0, cad["sent"] - cad["received"]),
                    cad["cad_detected"],
                )
            )
            if cad_result.get("status") != "passed":
                lines.append("- CAD test result: **FAIL**.")
        beacon = passed_details("beacon_sync")
        if beacon:
            lines.extend(["", "## Beacon synchronization", ""])
            for node, counters in beacon["nodes"].items():
                lines.append("- `{}`: `{}`".format(node, counters))
        power = passed_details("power")
        if power:
            lines.extend(["", "## Power", ""])
            for meter, values in power.items():
                lines.append(
                    "- `{}`: {} samples, mean {:.2f} mA, p50 {:.2f} mA, "
                    "p95 {:.2f} mA, max {:.2f} mA.".format(
                        meter,
                        values.get("count", 0),
                        values.get("mean_ma", 0),
                        values.get("p50_ma", 0),
                        values.get("p95_ma", 0),
                        values.get("max_ma", 0),
                    )
                )
        failures = [item for item in summary["results"] if item.get("status") == "failed"]
        if failures:
            lines.extend(["", "## Failures", ""])
            for failure in failures:
                error = failure.get("error") or failure.get("details", {}).get("error", "failed")
                lines.append("- `{}`: {}".format(failure["name"], error))
        (self.artifacts.root / "tldr.md").write_text("\n".join(lines) + "\n")

    def _write_junit(self, summary):
        suite = ET.Element(
            "testsuite",
            name="esp32-presubmit.{}".format(self.profile),
            tests=str(len(summary["results"])),
            failures=str(sum(item.get("status") == "failed" for item in summary["results"])),
        )
        for result in summary["results"]:
            case = ET.SubElement(
                suite,
                "testcase",
                name=result["name"],
                time=str(result.get("duration_sec", 0)),
            )
            if result.get("status") == "failed":
                failure = ET.SubElement(case, "failure", message=result.get("error", "failed"))
                failure.text = str(result)
        ET.ElementTree(suite).write(
            self.artifacts.root / "junit.xml", encoding="utf-8", xml_declaration=True
        )
