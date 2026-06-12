# Orchestrator MCP Server

Pipeline orchestration MCP server. Exposes tools for full workflow orchestration: recon → rank → research → hunt → chain → validate → report.

## Tools (4)

| Tool | Description |
|------|-------------|
| `orchestrate_start` | Start full pipeline on target |
| `orchestrate_status` | Get pipeline status |
| `orchestrate_checkpoint` | Save/load checkpoint |
| `orchestrate_resume` | Resume from checkpoint |

## Setup

```json
{
  "mcpServers": {
    "orchestrator": {
      "command": "python3",
      "args": ["mcp/orchestrator-mcp/server.py"]
    }
  }
}
```

## Requirements

- Python 3.8+
- `requests`
- Project tools: `tools/python/python-hunter.py`
