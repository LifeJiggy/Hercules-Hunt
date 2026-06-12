# Validation MCP Server

Vulnerability validation MCP server. Exposes tools for 7-Question Gate, 4-Gate Checklist, and CVSS scoring.

## Tools (5)

| Tool | Description |
|------|-------------|
| `validate_finding` | Full validation: 7-Question + 4-Gate |
| `validate_gate7` | Run only 7-Question Gate |
| `validate_gate4` | Run only 4-Gate Checklist |
| `cvss_score` | Calculate CVSS score from vector |
| `severity_guide` | Get severity guide for bug class |

## Setup

```json
{
  "mcpServers": {
    "validation": {
      "command": "python3",
      "args": ["mcp/validation-mcp/server.py"]
    }
  }
}
```

## Requirements

- Python 3.8+
- `requests`
- Project tools: validation module
