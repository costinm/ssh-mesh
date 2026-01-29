# Rust 

[ ] Add ntest and cargo-nextest (test deps)

# Pmond

[x] if running as user, only report and watch processes with same UID (may include docker)
[x] add handler to return all files in the cgroup, frontend to show them.
[ ] code to auto-contain processes by ID after startup.
[ ] code to squeze and freeze processes if memory hits a limit.

End goal:
- integrate with mesh to reject work if memory low, kick out low priority, contain on-demand work, etc
- integrate with load balancers via mesh - feed info about memory capacity.
- integrate with CP/policy using optional config files for each workload (identified by exe file path and user) - priorities, dynamic limits for processes.


# Mesh

[x] ws: move tracing to sshd, remove main and html
[ ] sse/mcp: add generic transports for MCP and HTTP/1.1 without WS, abstract 'Send' and 'Broadcast' across transports.

Standalone binaries for testing and specialized cases with lower complexity:
[ ] h2p binary - single -L for http - listen on TCP/UDS/vsock port, forward to URL on client connection using WS, H2, SSH
[ ] h2ps binary - server side, h2/SSH/WS server forwarding to host:port (can be used with exec or part of forwarding)
[ ] h2r - equivalent to -R, connect to URL, when response is received forward to host:port
[ ] h2rs - server side for -R, listen on http, accept connection, listen on port - on accept respond.
[ ] add SOCKS, if SOCKS_PORT is defined
[ ] add TPROXY if TPROXY_PORT is defined

[ ] add a json/yaml config file, optional, in current working dir. 
    - add client ssh side, use it to auto-connect to upstream servers
    - define forwards for each auto-connected
    - support using ssh client for this purpose instead.
[ ] accept forward on 22 / 443 / 80 with special handling.
[x] support sftpd (as standalone binary)
[ ] support reverse sftp - mount client files on server (like 'cpu' util in go)
[ ] add SSH_AUTHORIZED_KEYS as env var

[ ] document all env vars, including rust ones

# JNI 

[ ] Add JNI interface - exposing the MCP-like protocol
[ ] Add JNI for common methods to start the servers, stream data. Focus on using rust-allocated/managed Arc objects - and/or DirectBuffers.

# Other

[ ] create control socket (UDS), maybe using SSH format and interop with ssh control socket
[ ] add MCP support for most public methods, along with rest.
