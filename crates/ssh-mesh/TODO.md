[ ] find common code in h2t, udst, wst, refactor as a library

[ ] add more transports - vsock:CID:port, TCP, TLS.

[ ] document the equivalent socat command

[ ] add an option for udst.rs and tcpt.rs to check if the file/port exists, and if not to run a program, using the remaining args after '--'. Example: 
  `udst /tmp/example -- example --server`

[ ] create a docs repo - or use the bug/feature tracker - and record all LLM and manual experiments, even if they fail. Seems useful for eval, associated with a commit.
    Would polute this repo probably, TMI.

[ ] move the MCP handling to separate crate. Switch the HTML frontend to use SSE and the MCP endpoint. Find if there are generic clients.

[ ] evaluate other MCP implementation, how well they work to decouple 'method' from MCP specific protocol complexity. Goal is to have one function that can serve both REST and MCP.

[ ] evaluate tonic::transport ('battery included h2 server')

[ ] identify and document all env variables used for logging/tracing in rust, how to fine tune.

[ ] identify how to register/subscribe to traces in code, use tracing as a local communication instead of only 'push to server'

[ ] make sure tracing is used consistently, maybe separate crate to have an opinionated common init - including using config file and dynamic updates.

[ ] SSH, tcp, UDS, Exec over WSS as well.

[ ] H2, shared private key and authorized

# Namespace/cgroup/mount

[ ] As client, auto-start 9p and forward, request a 9p exec and 
9p mount - server independent.

[ ] As a client, exec a shell with cgroup and all other options. 

[ ] Verify Wayland and X apps can be started with remote display.

[ ] As server, enforce the set of commands the client can give, 
including mounts, and use namespaces/cgroups for not-owner via 
trusted 'init-root' process.

# Architecture

[ ] Traits 

[ ] Local comms - same API as remote for forwards. 
UDS, MCP, chained shell, 'socat' - all the same and possible.
