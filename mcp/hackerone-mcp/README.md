# HackerOne MCP — Public API Wrapper

Lightweight MCP server for HackerOne's public GraphQL API (no auth required).

## Tools

| Tool | Description |
|------|-------------|
| `search_disclosed_reports` | Search Hacktivity by keyword + program filter |
| `get_program_stats` | Bounty ranges, response times, resolved counts |
| `get_program_policy` | Safe harbor, response SLA, excluded vuln classes |

## Setup

```json
{
  "mcpServers": {
    "hackerone": {
      "command": "python3",
      "args": ["mcp/hackerone-mcp/server.py"]
    }
  }
}
```

## Usage

```bash
# Standalone CLI (not MCP)
python mcp/hackerone-mcp/server.py search "ssrf" --limit 5
python mcp/hackerone-mcp/server.py stats "shopify"
python mcp/hackerone-mcp/server.py policy "shopify"

# MCP — add to .claude/settings.json mcpServers (see config.json)
```

## Notes

- Public endpoints only — no API key required
- Rate limited by HackerOne (~30 req/min)
- Authenticated endpoints (submit_report, private scope) not included
- Search returns disclosed reports only

Depends on: Python standard library (ssl, urllib).
Optional: `certifi` package for SSL cert bundle.
