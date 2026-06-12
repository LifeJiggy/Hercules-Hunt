# Fast Hunt MCP Server

Fast hunting pipeline MCP server. Exposes tools for rapid endpoint discovery and lightweight vulnerability testing.

## Tools (4)

| Tool | Description |
|------|-------------|
| `fast_hunt_start` | Start fast hunt session on target |
| `fast_hunt_status` | Get session status and progress |
| `fast_hunt_results` | Retrieve findings from session |
| `fast_hunt_endpoints` | Quick endpoint discovery |

## Setup

```json
{
  "mcpServers": {
    "fast-hunt": {
      "command": "python3",
      "args": ["mcp/fast-hunt-mcp/server.py"]
    }
  }
}
```

## Requirements

- Python 3.8+
- `requests`
- Project tools: `tools/python/fast_hunt.py`
