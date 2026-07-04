import json

class ProtocolFormat:
    JSONRPC = "jsonrpc"
    FLAT = "flat"
    TEXT = "text"

class RawRequest:
    def __init__(self, method: str, params: dict, raw_line: str, protocol_format: str, req_id=None):
        self.method = method
        self.params = params
        self.raw_line = raw_line
        self.protocol_format = protocol_format
        self.req_id = req_id

    def __repr__(self):
        return f"RawRequest(method={self.method!r}, params={self.params!r}, format={self.protocol_format!r}, id={self.req_id!r})"

class Response:
    def __init__(self, success: bool, data=None, error: str = None):
        self.success = success
        self.data = data
        self.error = error

    @classmethod
    def ok(cls, data=None):
        return cls(success=True, data=data)

    @classmethod
    def err(cls, error_msg: str):
        return cls(success=False, error=error_msg)

    def to_dict(self) -> dict:
        d = {"success": self.success}
        if self.data is not None:
            d["data"] = self.data
        if self.error is not None:
            d["error"] = self.error
        return d

def parse_line(line: str) -> RawRequest:
    """Parses a line into a RawRequest supporting Flat JSON, JSON-RPC, or raw Text."""
    line_stripped = line.strip()
    if not line_stripped:
        return RawRequest(method="", params={}, raw_line=line, protocol_format=ProtocolFormat.TEXT)

    # Try parsing as JSON
    try:
        data = json.loads(line_stripped)
    except ValueError:
        # Not valid JSON -> treat as raw text
        return RawRequest(
            method="text",
            params={"text": line_stripped},
            raw_line=line,
            protocol_format=ProtocolFormat.TEXT
        )

    if not isinstance(data, dict):
        # JSON but not an object -> treat as raw text or error request
        return RawRequest(
            method="text",
            params={"text": line_stripped},
            raw_line=line,
            protocol_format=ProtocolFormat.TEXT
        )

    # Check for JSON-RPC 2.0
    if "jsonrpc" in data and data["jsonrpc"] == "2.0":
        method = data.get("method", "")
        req_id = data.get("id")
        params = data.get("params", {})
        if not isinstance(params, dict):
            params = {"params": params}
        return RawRequest(
            method=method,
            params=params,
            raw_line=line,
            protocol_format=ProtocolFormat.JSONRPC,
            req_id=req_id
        )

    # Otherwise treat as Flat JSON
    method = data.get("method", "")
    req_id = data.get("id")
    # All fields except method and id are params
    params = dict(data)
    params.pop("method", None)
    params.pop("id", None)
    return RawRequest(
        method=method,
        params=params,
        raw_line=line,
        protocol_format=ProtocolFormat.FLAT,
        req_id=req_id
    )

def format_response(response: Response, protocol_format: str, req_id=None) -> str:
    """Formats a Response according to the request's protocol format."""
    if protocol_format == ProtocolFormat.JSONRPC:
        res = {"jsonrpc": "2.0", "id": req_id}
        if response.success:
            res["result"] = response.data if response.data is not None else None
        else:
            res["error"] = {
                "code": -32603,
                "message": response.error or "Unknown error"
            }
        return json.dumps(res) + "\n"

    elif protocol_format == ProtocolFormat.FLAT:
        res = {"success": response.success}
        if response.data is not None:
            res["data"] = response.data
        if response.error is not None:
            res["error"] = response.error
        if req_id is not None:
            res["id"] = req_id
        return json.dumps(res) + "\n"

    else:
        # Text protocol
        if response.success:
            if isinstance(response.data, str):
                val = response.data
            elif response.data is not None:
                val = json.dumps(response.data)
            else:
                val = "ok"
        else:
            val = f"error: {response.error or 'Unknown error'}"
        # Ensure it has exactly one trailing newline
        if not val.endswith("\n"):
            val += "\n"
        return val
