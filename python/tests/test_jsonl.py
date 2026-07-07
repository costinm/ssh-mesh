import unittest
from dmesh import parse_line, format_response, Response, ProtocolFormat

class TestJsonl(unittest.TestCase):
    def test_parse_flat_json(self):
        line = '{"method":"status","name":"foo","id":"req-123"}\n'
        req = parse_line(line)
        self.assertEqual(req.protocol_format, ProtocolFormat.FLAT)
        self.assertEqual(req.method, "status")
        self.assertEqual(req.params, {"name": "foo"})
        self.assertEqual(req.req_id, "req-123")

    def test_parse_json_rpc(self):
        line = '{"jsonrpc":"2.0","method":"status","params":{"name":"bar"},"id":100}\n'
        req = parse_line(line)
        self.assertEqual(req.protocol_format, ProtocolFormat.JSONRPC)
        self.assertEqual(req.method, "status")
        self.assertEqual(req.params, {"name": "bar"})
        self.assertEqual(req.req_id, 100)

    def test_parse_text(self):
        line = "hello world\n"
        req = parse_line(line)
        self.assertEqual(req.protocol_format, ProtocolFormat.TEXT)
        self.assertEqual(req.method, "text")
        self.assertEqual(req.params, {"text": "hello world"})
        self.assertIsNone(req.req_id)

    def test_format_flat_success(self):
        resp = Response.ok({"pid": 123})
        formatted = format_response(resp, ProtocolFormat.FLAT, req_id="req-123")
        self.assertEqual(formatted, '{"success": true, "data": {"pid": 123}, "id": "req-123"}\n')

    def test_format_flat_error(self):
        resp = Response.err("something failed")
        formatted = format_response(resp, ProtocolFormat.FLAT, req_id="req-123")
        self.assertEqual(formatted, '{"success": false, "error": "something failed", "id": "req-123"}\n')

    def test_format_json_rpc_success(self):
        resp = Response.ok({"pid": 456})
        formatted = format_response(resp, ProtocolFormat.JSONRPC, req_id=200)
        self.assertEqual(formatted, '{"jsonrpc": "2.0", "id": 200, "result": {"pid": 456}}\n')

    def test_format_json_rpc_error(self):
        resp = Response.err("invalid method")
        formatted = format_response(resp, ProtocolFormat.JSONRPC, req_id=200)
        self.assertEqual(formatted, '{"jsonrpc": "2.0", "id": 200, "error": {"code": -32603, "message": "invalid method"}}\n')

    def test_format_text_success(self):
        resp = Response.ok("hello back")
        formatted = format_response(resp, ProtocolFormat.TEXT)
        self.assertEqual(formatted, "hello back\n")

if __name__ == "__main__":
    unittest.main()
