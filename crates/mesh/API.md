# mesh API

This file is the machine-readable contract for mesh's public control methods.
Protocol framing, gateway behavior, and examples live in [README.md](README.md).

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
