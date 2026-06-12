# Evidence Toolkit MCP Server

Evidence management MCP server. Exposes tools for creating, sanitizing, validating, and exporting evidence packages.

## Tools (4)

| Tool | Description |
|------|-------------|
| `evidence_create_package` | Create evidence package for finding |
| `evidence_sanitize` | Sanitize: redact tokens, cookies, PII |
| `evidence_validate` | Validate package completeness |
| `evidence_export` | Export to zip/tar.gz/json |

## Setup

```json
{
  "mcpServers": {
    "evidence": {
      "command": "python3",
      "args": ["mcp/evidence-mcp/server.py"]
    }
  }
}
```

## Requirements

- Python 3.8+
- `requests`
- Project tools: `tools/python/report_builder.py`
