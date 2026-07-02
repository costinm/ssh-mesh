# SSH-Mesh

`ssh-mesh` is a secure, daemonless process supervisor and L4 proxy system combining Android-like application process isolation, Kubernetes-like pod resource constraints, and Istio-like mTLS/certificate workload identity.

It is designed to orchestrate secure edge networks and run on-demand, socket-activated containers, bubblewrap sandboxes, or virtual machines.

---

## Key Features

- **On-Demand Process Supervisor (`mesh-init`)**: Coordinates process lifecycles, socket activation, and system configurations. Supports freezing/unfreezing applications when idle to eliminate daemon resource overhead.
- **Secure Multiplexed L4 Proxy (`ssh-mesh`)**: Built-in SSH client and server supporting SOCKS5, UDS/vsock forwarding, ControlMaster Control Socket multiplexing, and HTTP/2 and WebSocket tunneling.
- **Resource Limits & Monitoring (`mesh-init`)**: Real-time observer for process cgroups, CPU, and Memory Pressure Stall Information (PSI), exposed through generic mesh JSONL/MCP proxying.
- **Secure Workload Identity**: End-to-end encryption with OpenSSH ECDSA public keys and CA-signed user/host certificates.

---

## Workspace Layout

The project consists of several Rust crates:

- **[ssh-mesh](file:///ws/rust/ssh-mesh/crates/ssh-mesh)**: Core SSH/HTTP server/client and ControlMaster multiplexer.
- **[mesh-init](file:///ws/rust/ssh-mesh/crates/mesh-init)**: Minimal system init/supervisor daemon and root process observer.
- **[mesh](file:///ws/rust/ssh-mesh/crates/mesh)**: Common mesh library (Axum server, JSON protocol, UDS helpers).
- **[lmesh](file:///ws/rust/ssh-mesh/crates/lmesh)**: Lightweight mesh networking utilities.
- **[ws](file:///ws/rust/ssh-mesh/crates/ws)**: WebSocket bridging and client management.
- **[sftp](file:///ws/rust/ssh-mesh/crates/sftp)**: SFTP virtual file-system handler.
- **[ssh-config](file:///ws/rust/ssh-mesh/crates/ssh-config)**: SSH client configuration file parser.

---

## Documentation & Getting Started

- **[User Guide & Tutorial](file:///ws/rust/ssh-mesh/docs/USER_GUIDE.md)**: Conceptual overview, list of use cases, and a step-by-step local mesh tutorial.
- **[Local Multi-Host Examples](file:///ws/rust/ssh-mesh/docs/examples/README.md)**: Detailed multi-host mesh topology (Gateway, VMs, Bubblewrap) using checked-in certificates.
- **[App VM Debugging Guide](file:///ws/rust/ssh-mesh/docs/examples/app-vm-debugging.md)**: Detailed troubleshooting commands and logs for VM-based apps.
