"""Optional MCP registration of business operations and Simulator; no album tools."""
import json
import sys
from mcp_server import command, tool_result

def main():
    for line in sys.stdin:
        req = json.loads(line)
        if "id" not in req:
            continue
        try:
            method = req["method"]
            if method == "initialize":
                result = {"protocolVersion": req["params"]["protocolVersion"], "capabilities": {"tools": {}},
                          "serverInfo": {"name": "camact-business", "version": "1.0.0"}}
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": command({"op": "business_tools"})["tools"] + [
                    {"name": "camact_ask_user", "description": "Ask this task's user simulator",
                     "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}, "required": ["message"]}}]}
            elif method == "tools/call":
                params = req["params"]
                payload = ({"op": "ask_user", "message": params.get("arguments", {}).get("message", "")}
                           if params["name"] == "camact_ask_user" else
                           {"op": "action", "tool": params["name"], "arguments": params.get("arguments", {})})
                result = tool_result(command(payload))
            else:
                raise ValueError("Unsupported method")
            response = {"jsonrpc": "2.0", "id": req["id"], "result": result}
        except Exception as exc:
            response = {"jsonrpc": "2.0", "id": req["id"], "error": {"code": -32603, "message": str(exc)}}
        print(json.dumps(response), flush=True)

if __name__ == "__main__":
    main()
