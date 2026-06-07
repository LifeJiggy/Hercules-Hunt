# Hercules-Hunt MCP Adapters

MCP (Model Context Protocol) client configurations for integrating
Hercules-Hunt with web security tools and AI coding assistants.

## Clients

| Client | Directory | Purpose |
|--------|-----------|---------|
| Burp Suite | `burp-mcp-client/` | Live HTTP proxy traffic, collaborator, scanner |
| Caido | `caido-mcp-client/` | Lightweight Rust-based proxy alternative |
| HackerOne | `hackerone-mcp/` | Public Hacktivity, program stats, policy lookup |
| Hercules-Hunt | `hercules-hunt-mcp/` | Python hunter tools as MCP tools |

## Hercules-Hunt MCP Server

The `hercules-hunt-mcp/server.py` exposes all 7 P1 hunters + secret scanner +
network recon as MCP callable tools. Connect it to any MCP-compatible AI client.

### Tools (9)

| Tool | Description |
|------|-------------|
| `rce_hunt` | RCE/CMDi/SSTI/deserialization testing |
| `sqli_hunt` | SQLi/NoSQLi/JSONi detection |
| `idor_hunt` | IDOR/mass assignment testing |
| `auth_hunt` | JWT/OAuth/MFA/CSRF/rate limit testing |
| `ssrf_hunt` | SSRF/cloud metadata/localhost bypass |
| `xxe_hunt` | XXE/OOB/SVG/SOAP/DOCX testing |
| `file_upload_hunt` | File upload webshell/XSS/XXE testing |
| `secret_scan` | Regex + entropy secret scanning |
| `network_recon` | DNS/SSL/port scan/CDN detection |

### Resources (3)

| URI | Description |
|-----|-------------|
| `hercules://findings/latest` | Latest hunt findings |
| `hercules://tools/inventory` | Full tool inventory |
| `hercules://config/profile` | Active hunt profile |

### Setup

```bash
# Add to your Claude Code settings.json or OpenCode opencode.json:
# (Copy the entry from hercules-hunt-mcp/config.json)

# Test the server directly:
python mcp/hercules-hunt-mcp/server.py --list-tools

# Call a specific tool:
python mcp/hercules-hunt-mcp/server.py --tool rce_hunt '{"target_url":"https://target.com"}'
```

## Third-Party MCP Clients

- **Burp Suite**: Official PortSwigger MCP extension (BApp Store)
- **Caido**: Community `caido-mcp-server` (GitHub)
- **HackerOne**: Public GraphQL API wrapper (no auth needed)

See each client's README for setup instructions.
