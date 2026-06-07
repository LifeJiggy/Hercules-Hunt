# Hercules-Hunt MCP Adapters

MCP (Model Context Protocol) client configurations for integrating
Hercules-Hunt with web security tools and AI coding assistants.

## MCP Clients (10)

| Client | Directory | Tools | Purpose |
|--------|-----------|-------|---------|
| Burp Suite | `burp-mcp-client/` | — | Live HTTP proxy, collaborator, scanner |
| Caido | `caido-mcp-client/` | — | Rust-based proxy alternative |
| HackerOne | `hackerone-mcp/` | 3 | Hacktivity search, program stats, policy |
| Hercules-Hunt | `hercules-hunt-mcp/` | 9 | All 7 P1 hunters + secret scan + network |
| Interactsh | `interactsh-mcp/` | 5 | OOB callbacks, blind SSRF/XXE/RCE testing |
| DNS Recon | `dns-recon-mcp/` | 4 | DNS lookup, crt.sh, reverse DNS, sub brute-force |
| URL Crawl | `url-crawl-mcp/` | 4 | Wayback Machine, CommonCrawl, endpoint extraction |
| Payloads | `payload-mcp/` | 8 | XSS/SQLi/SSRF/XXE/CMDi/SSTI/NoSQLi + encoding |
| Reports | `report-mcp/` | 6 | Findings CRUD, reports (json/csv/html), summary |
| Recon | `recon-mcp/` | 5 | Subdomain discovery, live probe, fingerprint, port scan |

## Setup (all MCP servers)

Add to your AI client settings (`~/.claude/settings.json`, `opencode.json`, etc.):

```json
{
  "mcpServers": {
    "hercules-hunt": { "command": "python3", "args": ["mcp/hercules-hunt-mcp/server.py"] },
    "interactsh":   { "command": "python3", "args": ["mcp/interactsh-mcp/server.py"] },
    "dns-recon":    { "command": "python3", "args": ["mcp/dns-recon-mcp/server.py"] },
    "url-crawl":    { "command": "python3", "args": ["mcp/url-crawl-mcp/server.py"] },
    "payloads":     { "command": "python3", "args": ["mcp/payload-mcp/server.py"] },
    "reports":      { "command": "python3", "args": ["mcp/report-mcp/server.py"] },
    "recon":        { "command": "python3", "args": ["mcp/recon-mcp/server.py"] }
  }
}
```

## Tool Overview

### Hercules-Hunt MCP (9 tools)
| Tool | Description |
|------|-------------|
| `rce_hunt` | RCE/CMDi/SSTI/deserialization |
| `sqli_hunt` | SQLi/NoSQLi/JSONi |
| `idor_hunt` | IDOR/mass assignment |
| `auth_hunt` | JWT/OAuth/MFA/CSRF/rate limit |
| `ssrf_hunt` | SSRF/cloud metadata/localhost |
| `xxe_hunt` | XXE/OOB/SVG/SOAP/DOCX |
| `file_upload_hunt` | File upload webshell/XSS/XXE |
| `secret_scan` | Regex + entropy secret scanning |
| `network_recon` | DNS/SSL/port scan/CDN |

### Interactsh MCP (5 tools)
| Tool | Description |
|------|-------------|
| `generate_callback` | Unique OOB callback URL |
| `check_callbacks` | Poll for received interactions |
| `test_ssrf_blind` | SSRF + callback payload generation |
| `test_xxe_oob` | OOB XXE DTD with callback exfil |
| `test_rce_oob` | Blind RCE pingback payloads |

### DNS Recon MCP (4 tools)
| Tool | Description |
|------|-------------|
| `dns_lookup` | DNS record lookup (A/AAAA/MX/NS/TXT) |
| `crt_sh_search` | Certificate Transparency subdomains |
| `reverse_dns` | Reverse DNS IP lookup |
| `dns_bruteforce` | Common subdomain brute-force |

### URL Crawl MCP (4 tools)
| Tool | Description |
|------|-------------|
| `wayback_urls` | Wayback Machine URL history |
| `wayback_request_bodies` | Request/response details from Wayback |
| `common_crawl` | CommonCrawl index search |
| `extract_endpoints` | Parse endpoints from URL list |

### Payloads MCP (8 tools)
| Tool | Description |
|------|-------------|
| `generate_xss` | XSS payload variants |
| `generate_sqli` | SQL injection payloads |
| `generate_ssrf` | SSRF target URLs |
| `generate_xxe` | XXE entity payloads |
| `generate_cmdi` | Command injection payloads |
| `generate_ssti` | SSTI probes per engine |
| `generate_nosqli` | NoSQL injection (MongoDB) payloads |
| `encode_payload` | Encode in url/base64/hex/unicode |

### Reports MCP (6 tools)
| Tool | Description |
|------|-------------|
| `add_finding` | Register a new finding |
| `list_findings` | Filtered finding list |
| `get_finding` | Find by ID |
| `update_finding` | Update status/severity |
| `generate_report` | Export json/csv/html report |
| `get_summary` | Severity/type/status stats |

### Recon MCP (5 tools)
| Tool | Description |
|------|-------------|
| `discover_subdomains` | crt.sh multi-source discovery |
| `probe_live_hosts` | HTTP probe for live hosts |
| `fingerprint` | Tech stack identification |
| `port_scan` | Common port scan |
| `full_recon` | All-in-one pipeline |

## Test any server

```bash
python mcp/<server>/server.py --list-tools
```

See each client's README for detailed setup instructions.
