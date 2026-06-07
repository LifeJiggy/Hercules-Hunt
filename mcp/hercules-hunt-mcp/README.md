# Hercules-Hunt MCP — Python Hunter Toolkit

MCP server exposing all 7 P1 vulnerability hunters + secret scanner + network recon as callable tools.

## Tools

| Tool | Module | Description |
|------|--------|-------------|
| `rce_hunt` | `rce_hunter.py` | RCE/CMDi/SSTI/deserialization (25+ methods) |
| `sqli_hunt` | `sqli_hunter.py` | SQLi/NoSQLi/JSONi detection (22+ methods) |
| `idor_hunt` | `idor_hunter.py` | IDOR/mass assignment (24+ methods) |
| `auth_hunt` | `auth_hunter.py` | JWT/OAuth/MFA/CSRF (20+ methods) |
| `ssrf_hunt` | `ssrf_hunter.py` | SSRF/cloud metadata (22+ methods) |
| `xxe_hunt` | `xxe_hunter.py` | XXE/OOB/SVG/SOAP (20+ methods) |
| `file_upload_hunt` | `file_upload_hunter.py` | File upload RCE/XSS/XXE (22+ methods) |
| `secret_scan` | `secret_scanner.py` | Regex + entropy secrets |
| `network_recon` | `network_utils.py` | DNS/SSL/port scan/CDN |

## Setup

```json
{
  "mcpServers": {
    "hercules-hunt": {
      "command": "python3",
      "args": ["mcp/hercules-hunt-mcp/server.py"]
    }
  }
}
```

## Resources

| URI | Description |
|-----|-------------|
| `hercules://findings/latest` | Latest findings from last hunt |
| `hercules://tools/inventory` | Complete tool inventory |
| `hercules://config/profile` | Active config profile |

## Usage

```bash
python mcp/hercules-hunt-mcp/server.py --list-tools

# Direct tool call:
python mcp/hercules-hunt-mcp/server.py --tool rce_hunt '{"target_url":"https://target.com","cmd":"id"}'
```

Depends on: `requests` library (pip install requests).
All 7 P1 modules auto-load from `tools/python/`.
