# mesh API

This file is the machine-readable contract for mesh's public control methods.
Protocol framing, gateway behavior, and examples live in [README.md](README.md).

Every service using `jsonl::McpRegistry` accepts the private `mesh.lifecycle`
method before component-specific request decoding. A service that needs to
reconnect hardware, rebuild listeners, or restore other state calls
`mesh::lifecycle::subscribe()` before it starts accepting requests, then
consumes `LifecycleEvent` values from the returned broadcast receiver. Services
that do not subscribe still acknowledge the notification and require no custom
request-enum variant.

An intentional freeze is announced before mesh-init freezes the service. Its
matching unfreeze is announced after the process can run again. If an external
host freezer prevented advance notice, mesh-init sends an observed external
freeze followed by the external unfreeze after it repairs the service cgroup.

```mesh-api
id = "mesh.lifecycle"
component = "mesh"
method = "lifecycle"
component-index = 1
method-index = 3
visibility = "private"
summary = "Receive a supervisor freeze or unfreeze notification"
[request]
fields = [
  { name = "action", index = 1, type = "string", required = true },
  { name = "cause", index = 2, type = "string", required = true },
  { name = "observed", index = 3, type = "bool", required = true },
]
[response]
fields = [{ name = "subscribers", index = 1, type = "u64", required = true }]
```

```mesh-api
id = "mesh.mcp.initialize"
component = "mesh"
method = "initialize"
component-index = 1
method-index = 1
visibility = "public"
summary = "Return MCP initialization info"
```

```mesh-api
id = "mesh.mcp.tools_list"
component = "mesh"
method = "tools/list"
component-index = 1
method-index = 2
visibility = "public"
summary = "List registered MCP tools from catalog"
```

```mesh-api
id = "mesh.trace.subscribe"
component = "trace"
method = "subscribe"
component-index = 2
method-index = 1
visibility = "public"
summary = "Subscribe to live trace log event stream"
```

```mesh-api
id = "mesh.trace.set_level"
component = "trace"
method = "set_level"
component-index = 2
method-index = 2
visibility = "public"
summary = "Dynamically update tracing filter level"

[[request.fields]]
name = "level"
index = 1
type = "string"
required = true
position = 1
```

```mesh-api
id = "mesh.trace.get_level"
component = "trace"
method = "get_level"
component-index = 2
method-index = 3
visibility = "public"
summary = "Get current tracing filter level info"
```
