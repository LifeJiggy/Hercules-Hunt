# Deep Hunt MCP Server

Deep hunting pipeline MCP server. Exposes tools for comprehensive multi-phase hunting sessions: recon → rank → hunt → validate.

## Tools (5)

| Tool | Description |
|------|-------------|
| `deep_hunt_start` | Start full deep hunt session on target |
| `deep_hunt_status` | Get session status and progress |
| `deep_hunt_results` | Retrieve findings from session |
| `deep_hunt_phase` | Run specific hunt phase |
| `deep_hunt_stop` | Stop running session |

## Setup

```json
{
  "mcpServers": {
    "deep-hunt": {
      "command": "python3",
      "args": ["mcp/deep-hunt-mcp/server.py"]
    }
  }
}
```

## Requirements

- Python 3.8+
- `requests`
- Project tools: `tools/python/deep_hunt.py`
