import json
from .jsonl import Response, RawRequest

class McpRegistry:
    def __init__(self, server_name: str, server_version: str = "0.0.1"):
        self.server_name = server_name
        self.server_version = server_version
        self.tools = []
        self.resources = {}

    def register_tool(self, name: str, description: str, input_schema: dict, handler):
        self.tools.append({
            "name": name,
            "description": description,
            "inputSchema": input_schema,
            "handler": handler
        })

    def register_resource(self, uri: str, name: str, content: str, mime_type: str = "text/plain"):
        self.resources[uri] = {
            "uri": uri,
            "name": name,
            "text": content,
            "mimeType": mime_type
        }

    def dispatch(self, raw_req: RawRequest, direct_handler=None) -> Response:
        method = raw_req.method
        params = raw_req.params

        if method == "initialize":
            return Response.ok({
                "protocolVersion": "2025-06-18",
                "capabilities": {
                    "resources": {"listChanged": False},
                    "tools": {"listChanged": False}
                },
                "serverInfo": {
                    "name": self.server_name,
                    "version": self.server_version
                }
            })
        elif method == "notifications/initialized":
            return None
        elif method == "tools/list":
            public_tools = []
            for t in self.tools:
                pt = dict(t)
                pt.pop("handler", None)
                public_tools.append(pt)
            return Response.ok({"tools": public_tools})
        elif method == "resources/list":
            public_res = []
            for uri, r in self.resources.items():
                pr = {
                    "uri": r["uri"],
                    "name": r["name"],
                    "mimeType": r["mimeType"]
                }
                public_res.append(pr)
            return Response.ok({"resources": public_res})
        elif method == "resources/read":
            uri = params.get("uri")
            if not uri or uri not in self.resources:
                return Response.err("resource not found")
            r = self.resources[uri]
            return Response.ok({
                "contents": [{
                    "uri": r["uri"],
                    "mimeType": r["mimeType"],
                    "text": r["text"]
                }]
            })
        elif method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {})
            for t in self.tools:
                if t["name"] == tool_name:
                    try:
                        res = t["handler"](args)
                        if isinstance(res, Response):
                            if res.success:
                                return Response.ok({
                                    "content": [{"type": "text", "text": json.dumps(res.data) if res.data is not None else "ok"}],
                                    "isError": False
                                })
                            else:
                                return Response.ok({
                                    "content": [{"type": "text", "text": res.error}],
                                    "isError": True
                                })
                        return Response.ok({
                            "content": [{"type": "text", "text": json.dumps(res) if res is not None else "ok"}],
                            "isError": False
                        })
                    except Exception as e:
                        return Response.ok({
                            "content": [{"type": "text", "text": str(e)}],
                            "isError": True
                        })
            return Response.err(f"tool {tool_name} not found")

        if direct_handler:
            return direct_handler(raw_req)

        return Response.err(f"method {method} not supported")
