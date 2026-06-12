# Hydration MCP Server

Data hydration MCP server. Exposes tools for enriching recon data with vulnerability context and bug-class assignments.

## Tools (3)

| Tool | Description |
|------|-------------|
| `hydrate_recon` | Hydrate recon file with vulnerability context |
| `hydrate_endpoint` | Hydrate single endpoint with bug classes |
| `hydrate_batch` | Batch hydrate multiple recon files |

## Setup

```json
{
  "mcpServers": {
    "hydration": {
      "command": "python3",
      "args": ["mcp/hydration-mcp/server.py"]
    }
  }
}
```

## Requirements

- Python 3.8+
- `requests`
- Project tools: `tools/python/hydration.py`
