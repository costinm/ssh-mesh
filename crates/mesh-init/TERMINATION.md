# App termination

The main models for this project are 'Serverless' and 'Android'. In both, workloads are
expected to only run when the user needs them - no 'deamons'.

It is using systemd protocol for activation (systemd listens, pass listener for app, listens
again when app exists). There are additional protocols:
- app passing sockets to mesh-init for listening, exits, get started again on activity
- mesh-init accepts, passes the FD to the app.

Main questions are how to terminate gracefully ('lame duck') and how to upgrade.

## Upgrade

Since new version is expected to be in a different directory (nix store or /opt/app/version), the
mesh-init can start a new instance with the new version, pass it the same listener (in xinetd/systemd mode) or start passing newly accepted sockets as FD to the new version.

Old version needs to be notified to stop accepting, and it needs to exit when all existing connections and work is finished.

As an optimization, it may be possible for old version to pass the open FDs and state to the
new app over UDS. 

## Idle detection

This is pretty hard without cooperation from the app. Telemetry is one method - app reporting
some metric like active connections. Termination should send a
message first (and approaching it like an upgrade where a new version is not started first),
and without a response should kill the app, like K8S.

## Freeze instead of kill

For apps not supporting an explicit idle/termination protocol, freezing is another option.
Pages will be reclaimed and CPU no longer used. The problem is detecting when to unfreeze - 
for example in the 'mesh-init accept and send FDs' it can start polling the sockets for activity.
Not sure how reliable this can be either - I think explicit protocol for termination/idle is the
only safe option.

