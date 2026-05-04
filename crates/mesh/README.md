# Client library for (SSH) Mesh

This create provides an optional library for interacting with a Mesh, defined as a mechanism for running apps with 
configurable and (more) consistent security, telemetry, networking.

Any application using stdin/stdout/stderr or UDS or HTTP/1.1 or H2C can be used with no changes by SSH mesh - the library is optional, defining helpers and examples for the patterns used by ssh-mesh.

## Telemetry

The core idea is that telemetry data is not only for upload to servers, with the associated tradeoffs (privacy, bandwidth, storage, etc.) - but it can be extremely useful locally for the app itself and for other cooperating components on the same node. 

Apps are usually telemetry producers, but can also be consumers for their own telemetry or for other components, with proper permissions/policy.

Keeping recent logs and traces in a local circular buffer is also very useful for debugging and for using the telemetry data as part of the application logic or in tests without extra complexity. Metrics (counters) can be accessed locally - if the telemetry libraries don't intentionally hide them. 

Consumers can do the local processing or send data to cloud/remote backends - with some extra buffering, or may not send
all the data. 

Traces/logs should be off by default - and dynamically configurable per app, with a collector or telemetry app 
getting access to recent events and the buffer and new logs.


## Core service

It is useful for each app to create an opinionanted H2C over UDS service exposing core functionality - avoiding a TCP localhost port. In many cases H2C is overkill - many apps can just expose
an MCP-like JSON-RPC or plain JSON over stdin/stdout or UDS. In this case the mesh proxy can handle HTTP2 or SSH forwarding, with headers and metadata exposed as either env variables or in the json sent to the app.

## MCP and Open-API

To reduce dependencies and complexity, it's useful to generate static files with the schemas - 'skills' and 
'agents' as well. 

## Multi-codec

JSON is the most common format - but CBOR or Protobuf should also be possible, with translations in the mesh layer, so any-to-any format is possible.

## Serverless 

The expectation is that a VM or Pod/Container will contain multiple binaries implementing one or more services. The mesh can start a binary
and run requests, keeping track of idle process and terminating them.

In addition the mesh should monitor memory and memory pressure and take that into account on terminating processes or deciding to accept 
only specific requests when system is under heavy load. This needs to be more tightly integrated than in Istio or similar meshes.

## Jobs 

This is an extension of 'serverless' - based in large part on Android JobScheduler: like serverless the app is loaded on demand and in response to requests/pubsub or scheduled periodic runs, but there are additional constraints and flexibility in
scheduling to allow better resource utilization. 

The problem with 'cron' and exact scheduling is that many of the 
jobs don't really need to execute at a precise time - and the system should make sure whatever runs is the higest priority set of work that can be done with the available memory/cpu, delaying lower priority or flexible jobs.

'power' and 'network' events are also very relevant for laptops
and also for servers.

## Sessions 

## Exec

An app may exec other apps, and typically will just use the
same identity and resources.

Using containers or jails - via unshare, nsjail, bubblewrap, etc. - is a good pattern for limiting the
resources and capabilities of the executed app, but with
overhead and complexity, and with dependencies to another
component. Podman and user-mode containers are even heavier,
while root daemons and K8S are another level of complexity 
and security risks.

There are really 2 modes for isolating exec:

1. As pure user-space - creating namespaces, cgroups, etc,
via system calls (library) or one of the tools.

2. Using root - setuid or a daemon - with the main benefit 
of switching to a different UID and higher privileges than the original user.

Both are valid and important use cases, it is not a choice
on using one or the other, but to use both when appropriate.


### unshare

### Nsjail

### Bubblewrap
