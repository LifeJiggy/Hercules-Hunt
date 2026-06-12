# HTTPS Probing MCP Server

HTTPS probing MCP server. Exposes tools for SSL/TLS analysis, certificate inspection, and security header testing.

## Tools (4)

| Tool | Description |
|------|-------------|
| `https_probe` | Probe HTTPS endpoint and collect SSL/TLS info |
| `https_certificate` | Extract SSL certificate details |
| `https_tls_version` | Check supported TLS versions and ciphers |
| `https_headers` | Analyze HTTPS security headers |

## Setup

```json
{
  "mcpServers": {
    "https-probe": {
      "command": "python3",
      "args": ["mcp/https-mcp/server.py"]
    }
  }
}
```

## Requirements

- Python 3.8+
- `requests`
- Project tools: `tools/python/https_probing.py`, `tools/python/network_utils.py`
