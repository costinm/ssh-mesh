# mesh-mcp

Optional Model Context Protocol adapter for mesh services.

Workers expose their ordinary mesh API and ship a generated `tools.json`
catalog. They do not need this crate or MCP-specific request types. A gateway
such as ssh-mesh or mesh-init opts into `mesh-mcp`, loads the worker's catalog,
and translates MCP initialization, discovery, resources, and tool calls to the
worker's normal handlers or forwards them to another node.

