# Trace aggregation service

The mesh crate provides a library for initializing an in-memory trace buffer
and exporting traces over UDS, as well as a control interface using JSON-L.

This crate is the activated trace aggregation JSONL service. It discovers trace
producer sockets, connects to them on demand, and streams structured trace
notifications. The browser-facing UI and HTTP/SSE adapter live in `ssh-mesh`.

## Security model

This is expected to be a trusted component - with a hardcoded UID, like android
statsd/traced - which is allowed by the mesh crate to control the tracing. 

Same UID can be used with SSH and proper auth to stream the logs and control the
levels from a remote host, with or without an HTTP UI.

## Runtime

This is intended to be an 'activated' service, not a daemon. 

App traces should stay in the buffers or app-owned files: the model is that
apps should have access to their own recent logs/traces for making decisions, 
with the UI used on-demand and rarely, and the collection happening off-peak or
at lower priority for low-priority telemetry.
