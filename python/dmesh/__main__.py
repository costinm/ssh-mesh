"""`mesh-cli`-style Python command line client."""

import argparse
import json

from .client import MeshClient
from .mux import MuxClient


def forward_spec(value):
    parts = value.split(":")
    if len(parts) == 3:
        return "127.0.0.1", int(parts[0]), parts[1], int(parts[2])
    if len(parts) == 4:
        return parts[0], int(parts[1]), parts[2], int(parts[3])
    raise argparse.ArgumentTypeError("forward must be [listen_host:]listen_port:target_host:target_port")


def main():
    parser = argparse.ArgumentParser(description="Call a mesh UDS service")
    parser.add_argument("destination", help="service name, UDS path, unix:// URL, or mux socket")
    parser.add_argument("method", nargs="?", help="JSONL method or complete text record with --text")
    parser.add_argument("--params", default="{}", help="JSON object (flat JSONL parameters)")
    parser.add_argument("--jsonrpc", action="store_true", help="use JSON-RPC 2.0 instead of flat JSONL")
    parser.add_argument("--text", action="store_true", help="send method as a mesh text record")
    parser.add_argument("--mux-alive", action="store_true", help="use destination as an OpenSSH mux socket")
    parser.add_argument("--forward-local", type=forward_spec, help="open a mux local forward")
    parser.add_argument("--forward-remote", type=forward_spec, help="open a mux remote forward")
    args = parser.parse_args()

    if args.mux_alive or args.forward_local or args.forward_remote:
        with MuxClient(args.destination) as mux:
            if args.mux_alive:
                print(mux.alive())
            if args.forward_local:
                print(mux.open_local_forward(*args.forward_local) or "ok")
            if args.forward_remote:
                print(mux.open_remote_forward(*args.forward_remote) or "ok")
        return
    if not args.method:
        parser.error("method is required unless a --mux option is used")

    with MeshClient(args.destination) as client:
        if args.text:
            print(client.text(args.method))
            return
        params = json.loads(args.params)
        if not isinstance(params, dict):
            parser.error("--params must be a JSON object")
        response = (client.jsonrpc if args.jsonrpc else client.request)(args.method, params)
        print(json.dumps(response, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
