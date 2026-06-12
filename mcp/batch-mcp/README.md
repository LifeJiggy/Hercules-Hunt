# Batch Processing MCP Server

Batch processing MCP server. Exposes tools for multi-target scanning with rate limiting and result aggregation.

## Tools (4)

| Tool | Description |
|------|-------------|
| `batch_start` | Start batch scan on multiple targets |
| `batch_status` | Get batch job status |
| `batch_results` | Retrieve batch results |
| `batch_stop` | Stop running batch job |

## Setup

```json
{
  "mcpServers": {
    "batch": {
      "command": "python3",
      "args": ["mcp/batch-mcp/server.py"]
    }
  }
}
```

## Requirements

- Python 3.8+
- `requests`
- Project tools: `tools/python/batch_processor.py`
