# JS Analysis MCP Server

JavaScript bundle analysis MCP server. Exposes tools for endpoint extraction, secret scanning, and functionality analysis from JS bundles.

## Tools (5)

| Tool | Description |
|------|-------------|
| `analyze_js_bundle` | Full analysis: endpoints + secrets + functionality |
| `extract_endpoints` | Extract API endpoints from bundle |
| `scan_secrets` | Scan for hardcoded secrets (regex + entropy) |
| `extract_functionalities` | Extract functional modules |
| `batch_analyze_bundles` | Analyze all bundles in a directory |

## Setup

Add to AI client config:

```json
{
  "mcpServers": {
    "js-analysis": {
      "command": "python3",
      "args": ["mcp/js-analysis-mcp/server.py"]
    }
  }
}
```

## Requirements

- Python 3.8+
- `requests`
- Project tools: `tools/python/js_analyzer.py`, `tools/python/secret_scanner.py`, `tools/python/extract_apis.py`

## Usage

```bash
python mcp/js-analysis-mcp/server.py --list-tools
```
