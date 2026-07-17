#!/usr/bin/env python3
"""Exercise default Meshtastic-header LoRa send/receive between two ESP32 consoles."""

from __future__ import annotations

import argparse
import threading
import time

from serial_cmd import Console


PROMPT = b"dm-rs> "


def require_ok(output: str, context: str) -> None:
    text = output.strip()
    if text.startswith("error ") or "\nerror " in text:
        raise RuntimeError(f"{context} returned error")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rx", required=True, help="Receiver serial port")
    parser.add_argument("--tx", required=True, help="Sender serial port")
    parser.add_argument("--freq", type=int, default=913_125_000)
    parser.add_argument("--bw", type=int, default=250_000)
    parser.add_argument("--sf", type=int, default=9)
    parser.add_argument("--cr", type=int, default=5)
    parser.add_argument("--sync-word", default="0x2b")
    parser.add_argument("--payload", default="hex:0102030448656c6c6f")
    parser.add_argument("--timeout", type=float, default=12.0)
    args = parser.parse_args()

    rx = Console(args.rx, 460800, args.timeout)
    tx = Console(args.tx, 460800, args.timeout)
    try:
        print(f"[{args.rx}] sync")
        print(rx.sync().rstrip())
        print(f"[{args.tx}] sync")
        print(tx.sync().rstrip())

        require_ok(run(rx, "lora rx=false", args.timeout), "rx stop background")
        require_ok(run(tx, "lora rx=false", args.timeout), "tx stop background")
        time.sleep(0.5)

        config = (
            f"lora freq={args.freq} bw={args.bw} sf={args.sf} cr={args.cr} "
            f"sync_word={args.sync_word} preamble=16 crc=true apply=true"
        )
        require_ok(run(rx, config, args.timeout), "rx config")
        require_ok(run(tx, config, args.timeout), "tx config")

        rx_output: dict[str, str] = {}

        def listen() -> None:
            rx_output["text"] = run(rx, "loralisten ms=9000 count=2", args.timeout + 4)

        thread = threading.Thread(target=listen)
        thread.start()
        time.sleep(1.0)
        tx_out = run(tx, f"lorasend data={args.payload} timeout=4000", args.timeout)
        require_ok(tx_out, "tx send")
        thread.join(args.timeout + 6)
        if thread.is_alive():
            raise RuntimeError("receiver listen did not finish")

        out = rx_output.get("text", "")
        require_ok(out, "rx listen")
        if "packets=0" in out or "n=0" in out:
            raise RuntimeError("receiver saw zero packets")
        print("PASS")
        return 0
    finally:
        rx.close()
        tx.close()


def run(console: Console, command: str, timeout: float | None = None) -> str:
    print(f"[{console.port}] $ {command}", flush=True)
    out = console.cmd(command, timeout)
    print(out.rstrip(), flush=True)
    return out


if __name__ == "__main__":
    raise SystemExit(main())
