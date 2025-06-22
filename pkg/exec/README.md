# SSH Exec

The original, core feature of SSH is secure execution of commands. The 'secure' part is primarily focused on network encryption and authentication.

Modern secure execution also requires jailing the executed
program.

This package is like os/exec, but the actual command:

- can be run in (different forms of) jail
- may be run in a separate container, VM or remote machine

Networking is not tied to SSH - H2 can also be used, and
it allows handling requests by executing programs. Unlike the original CGI, SSH execution has extra controls and only allows authorized users, and with 2-way communication.

## API

The 2 main APIs to express execution are the Open Containers runtime (OCI) and the K8S/CloudRun 'container'.
Docker compose is also common.

As command line - docker CLI is emulated by podman and pretty well known.

K8S CRI translates from K8S Pod to containers using OCI spec, so they are more or less equivalent - but fewer people
 are familiar with the OCI json.

 ## Helper apps vs native go






