# Web interface for the mesh traces

The mesh crate provides a library for initializing an in-memory trace buffer
and exporting traces over UDS, as well as a control interface using JSON-L.

This crate is an example UI - exposing the controls (dynamic changes on 
logging levels, pulling metrics) and vieweing the buffers.

## Security model

This is expected to be a 'trusted' component - with a hardcoded UID, like android
statsd/traced - which is allowed by the mesh crate to control the tracing. 

Same UID can be used with SSH and proper auth to stream the logs and control the
levels from a remote host, with or without the UI.

## Runtime

This is intended to be an 'activated' service, not a daemon. 

App traces should stay in the buffers or app-owned files: the model is that
apps should have access to their own recent logs/traces for making decisions, 
with the UI used on-demand and rarely, and the collection happening off-peak or
at lower priority for low-priority telemetry.

