# MCP handling

MCP is a great protocol - but also very dangerous.

Using 'stdin' is easy and provides access to local files - if combined with
a sandbox it can have unique advantages over pure server implementations, 
but the key is to keep it sandboxed and not allow broad access to $HOME.

Server MCP also needs to deal with auth - and can't operate on local files, 
creating expensive and complex interactions.


## Stdin MCP

One idea: instead of writing a custom MCP binary using the libraries:

- generate the schema as static files, can be changed without recompiling.

- implement the code either using http handlers or the simple json-line,
using the json-rpc layout but not necessarily using specific libraries.

- expect a 'workspace' directory to be mounted R/W, another fixed dir
for secrets (/var/run/secrets) and /nix and other system dirs read only - no HOME mounted.


The server doesn't have deps on MCP - it may be concurrent 
(HTTP or xinet-style) or single-connection (inet style), handing one session by receiving json messages on stdin and sending json messages on stdout. 

Or it may use other formats, with the MCP proxy adapting formats as needed.

## Mesh MCP

- use mesh-init (or another wrapper) to launch the MCP binary in bwrap (or VM)

- or use ssh-mesh as a proxy to a different VM or cloud service, passing
some configs and keys as env variables.

Either way - the MCP binary should be isolated, with encryption/auth if it is remote and clear boundaries.
