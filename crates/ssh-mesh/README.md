# SSH Mesh

The create combines russh and H2 stacks for a common 'mesh' transport, providing 
encryption and authentication on the wire along with forwarding.

It does act as a SSH server and client - including support for program execution 
and PTYs, remote and local forwarding, but with mesh style configuration: a single
key per host (not per user), authorized keys and configs handled at mesh level instead 
of user.

## mesh-init

The 'root' features are separated into mesh-init. SSH-mesh crate has heavy networking
dependencies - it should never run as root.

## Authenticated command execution

SSH shell/exec and the authenticated HTTP exec endpoint are two front ends for
the same command-execution policy. Both pass the terminal or stdio descriptors
to mesh-init; neither executes a command directly in ssh-mesh.

The authenticated identity is the execution identity for an ordinary command:
the command runs with that user's UID/GID and home directory. A requested PTY
is carried through the HTTP exec protocol as terminal metadata in its headers,
just as SSH carries it in its session requests.

Before launch, the gateway resolves the command's service target. A command
that names a registered mesh-init service runs with that service's configured
identity, home directory, working directory, environment, and normal
mesh-init execution setup — the same context it would have for a local start.
That elevation is allowed only when the authenticated caller is authorized for
that service. Commands that do not resolve to a service remain in the caller's
own home and identity.

This is the intended contract. The current HTTP handler still has a temporary
system-account launch path and does not yet propagate the authenticated
identity or perform service-target authorization; it must not be treated as
the final HTTP exec authorization model.

## Gateway and protocol adaptation

## Local routing

`MeshNode` owns one stream router and one component registry. HTTPS reverse-proxy
selection, authenticated HTTPS stream tunnels, and SSH direct-tcpip channels use
that same routing table and caller policy. HTTP forwarding continues to use the
shared pooled reverse proxy; byte streams use the router's common target opener.
The HTTPS adapter holds an `Arc` to the node router and creates no private table.

The authenticated HTTPS `/_m/stream[/component/method]` surface wires the existing
stream ingress to `Router::route_stream`. Local component lookup uses the same
node registry exposed by the admin API. mesh-init owns activation and process
identity changes; ssh-mesh owns route selection. Unmatched SSH destinations retain
the existing configured-jump and explicit open-relay behavior, while a denied
shared route cannot fall through to it. See [ENV.md](ENV.md) for configuration
and the distinction between browser reverse proxying and byte-stream tunnels.
