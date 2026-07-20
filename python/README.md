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

## Python use

```python
from dmesh import MeshClient

with MeshClient("mesh-init") as init, MeshClient("lmesh") as radio:
    services = init.request("status")
    nodes = radio.request("nodes")
```

## Firmware radio tests

`RadioClient` drives one lmesh-owned firmware stream without opening the
physical TTY. `LabConfig`, `PowerCollector`, and `PresubmitSuite` provide the
shared local/forwarded-node test driver used by ESP firmware pre-submit runs.

```python
from dmesh import RadioClient

with RadioClient("lora1.lmesh") as radio:
    radio.wake(120)
    status = radio.command("status")
    print(status.record("status")["fields"])
```

Run the checked-in lab topology with:

```bash
target/nix/profile/bin/python fw/esp32/rust/tools/presubmit.py \
  --topology fw/esp32/rust/tools/lab.example.json --profile quick
```

Each run writes a manifest, raw command records, phase-tagged power samples,
counter deltas, and a machine-readable summary under
`target/esp32-presubmit/`.

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
`crates/mesh`. It includes a dependency-free CBOR implementation for the
JSON-shaped values used by these records. `MuxClient` implements the OpenSSH
ControlMaster version-4 handshake, alive check, and local/remote forwarding
requests. It intentionally has no SSH cryptography: it talks to an already
authenticated local mux master, exactly like `mesh-cli -S`.
