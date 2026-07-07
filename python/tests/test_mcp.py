import unittest
from dmesh import McpRegistry, parse_line, Response, RawRequest

class TestMcp(unittest.TestCase):
    def test_mcp_lifecycle(self):
        registry = McpRegistry("test-server", "1.2.3")

        # 1. Test initialize
        req = parse_line('{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}')
        resp = registry.dispatch(req)
        self.assertTrue(resp.success)
        self.assertEqual(resp.data["serverInfo"]["name"], "test-server")
        self.assertEqual(resp.data["serverInfo"]["version"], "1.2.3")
        self.assertEqual(resp.data["protocolVersion"], "2025-06-18")

        # 2. Test tools registration and list
        def echo_tool(args):
            return Response.ok({"echo": args.get("value")})

        registry.register_tool(
            "echo",
            "Echoes value back",
            {"type": "object"},
            echo_tool
        )

        req_list = parse_line('{"method":"tools/list"}')
        resp_list = registry.dispatch(req_list)
        self.assertTrue(resp_list.success)
        self.assertEqual(len(resp_list.data["tools"]), 1)
        self.assertEqual(resp_list.data["tools"][0]["name"], "echo")

        # 3. Test tools call
        req_call = parse_line(
            '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo","arguments":{"value":"hello"}},"id":2}'
        )
        resp_call = registry.dispatch(req_call)
        self.assertTrue(resp_call.success)
        self.assertFalse(resp_call.data["isError"])
        self.assertEqual(resp_call.data["content"][0]["text"], '{"echo": "hello"}')

        # 4. Test resource registration and read
        registry.register_resource("file://test.txt", "test.txt", "file content")
        req_res_list = parse_line('{"method":"resources/list"}')
        resp_res_list = registry.dispatch(req_res_list)
        self.assertTrue(resp_res_list.success)
        self.assertEqual(resp_res_list.data["resources"][0]["name"], "test.txt")

        req_res_read = parse_line('{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"file://test.txt"},"id":3}')
        resp_res_read = registry.dispatch(req_res_read)
        self.assertTrue(resp_res_read.success)
        self.assertEqual(resp_res_read.data["contents"][0]["text"], "file content")


if __name__ == "__main__":
    unittest.main()
