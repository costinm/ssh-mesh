# DMesh Python client

`dmesh` is a pure-Python, `mesh-cli`-style client for local mesh services. It
does not compile or link `mesh`, `lmesh`, `ssh-mesh`, or `mesh-tun`. It speaks
the same UDS JSONL and text records, so one script can keep independent
connections to `mesh-init`, `lmesh`, and test services.

The Python client does not implement SSH or remote-host discovery. It always
opens a locally visible UDS. For remote tests, ssh-mesh configuration connects
to the remote service and forwards its UDS locally; the same Python topology
then names that local socket or logical `NAME.lmesh` radio.

```bash
cd python
python -m pip install -e .

# Named defaults: mesh-init and lmesh.
python -m dmesh mesh-init status
python -m dmesh lmesh nodes

# Explicit endpoint and JSON-RPC when a service needs it.
python -m dmesh unix:///run/mesh/lmesh/mesh.sock nodes --jsonrpc
python -m dmesh mesh-init 'status name=ssh-mesh' --text

# Query or open a forward through an OpenSSH-compatible ControlMaster.
python -m dmesh /run/user/1000/ssh-control --mux-alive
python -m dmesh /run/user/1000/ssh-control --forward-local 8080:127.0.0.1:80
```

For isolated development and tests, use a Python 3.10+ virtual environment
and install the package rather than relying on `PYTHONPATH` alone:

```bash
cd python
python3 -m venv .venv
.venv/bin/python -m pip install -e . pytest
.venv/bin/python -m pytest tests
```

The flake's `python-tools` output provides Python, pip, and pytest, but the
locked nixpkgs has cbor2 5.8.0, which does not satisfy this client's
`cbor2>=6.2.1,<6.3` requirement. It is therefore not a standalone runtime
for this client: use an isolated pip installation as above. Providing the
dependency directly in `python-tools` requires a compatible nixpkgs update or
another compatible Nix package; do not substitute the older codec.

## Python use

```python
from dmesh import MeshClient

with MeshClient("mesh-init") as init, MeshClient("lmesh") as radio:
    services = init.request("status")
    nodes = radio.request("nodes")
```

## Passenger descriptors

Mesh calls that carry non-JSON data use Unix `SCM_RIGHTS` ancillary data. The
descriptor transfer follows the request immediately, has the required `F`
marker byte, and carries every descriptor in **one** control message. This is
the mesh passenger convention and is critical for `mesh-init` requests such
as `start_terminal` and `register_namespace`.

```python
import os
from dmesh import MeshClient

netns = os.open("/proc/self/ns/net", os.O_RDONLY)
try:
    with MeshClient("mesh-init") as init:
        reply = init.request(
            "register_namespace",
            {"name": "worker", "kind": "net"},
            passengers=[netns],
        )
finally:
    os.close(netns)
```

For a three-stream terminal, pass the three descriptors in one list and set
`fd_count: 3` in the request parameters. The client remains connected after a
request, which also supports subscriptions and sequential control operations.

## Binary baseline and mux forwarding

`BinaryClient` implements the mesh binary baseline: a big-endian length,
`00 cb 00 00` mesh-RPC metadata, and the tagged CBOR envelope used by
`crates/mesh`. It uses the maintained `cbor2>=6.2.1,<6.3` codec, installed
with the package, without a fallback codec. Python 3.10+ is required by this
chosen cbor2 version, which provides the strict decoder options used here;
the minimum was raised intentionally. The RPC value profile permits finite
arrays/maps, bytes, UTF-8 text, booleans, null, floats (including non-finite
values), and integers from -2^64 through 2^64-1. JSON gateways may reject
non-finite floats separately.
Python text is UTF-8; arbitrary octets must use bytes. Undefined, semantic
tags, indefinite-length values, duplicate map keys, trailing bytes, and
nesting deeper than 64 levels are rejected. Frames are limited to 64 KiB,
including metadata but excluding the length prefix.

`MuxClient` implements the OpenSSH
ControlMaster version-4 handshake, alive check, and local/remote forwarding
requests. It intentionally has no SSH cryptography: it talks to an already
authenticated local mux master, exactly like `mesh-cli -S`.
