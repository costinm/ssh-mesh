# MCP handling

MCP is a great protocol - but also very dangerous.

Using 'stdin' is easy and provides access to local files - if combined with
a sandbox it can have unique advantages over pure server implementations.

Server MCP needs to deal with auth - and can't operate on local files.

Both require specific libraries to support the handshake and schema - with larger and unnecessary dependencies.

## Stdin MCP

- generate the schema as static files, can be changed without recompiling.
- proxy to a server - either local, in a sandbox or over ssh/h2, using mesh auth (mTLS, ssh certs) or apikeys.
- the actual functionality is either on a server or in a sandbox, and doesn't need to be aware of MCP details.

The server doesn't have deps on MCP - it may be multi-tenant (xinet-style) or
single-tenant (inet style), handing one session by receiving json messages on
stdin and sending json messages on stdout. Or it may use other formats, with the
MCP proxy adapting formats as needed.

