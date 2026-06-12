# Hercules-Hunt MCP Adapters

MCP (Model Context Protocol) client configurations for integrating
Hercules-Hunt with web security tools and AI coding assistants.

## MCP Clients (20)

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
| JS Analysis | `js-analysis-mcp/` | 5 | JS bundle endpoint extraction, secret scan, functionality |
| Deep Hunt | `deep-hunt-mcp/` | 5 | Deep hunt pipeline: start/status/results/phase/stop |
| Fast Hunt | `fast-hunt-mcp/` | 4 | Fast hunt: start/status/results/endpoints |
| Orchestrator | `orchestrator-mcp/` | 4 | Full pipeline orchestration with checkpoints |
| Batch | `batch-mcp/` | 4 | Multi-target batch scanning with rate limiting |
| Hydration | `hydration-mcp/` | 3 | Enrich recon data with vulnerability context |
| Auth Tester | `auth-tester-mcp/` | 5 | JWT, OAuth, MFA, CSRF, session testing |
| HTTPS Probe | `https-mcp/` | 4 | SSL/TLS analysis, certificate, headers |
| Evidence | `evidence-mcp/` | 4 | Evidence packaging, sanitization, validation, export |
| Validation | `validation-mcp/` | 5 | 7-Question Gate, 4-Gate Checklist, CVSS scoring |

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
    "recon":        { "command": "python3", "args": ["mcp/recon-mcp/server.py"] },
    "js-analysis":  { "command": "python3", "args": ["mcp/js-analysis-mcp/server.py"] },
    "deep-hunt":    { "command": "python3", "args": ["mcp/deep-hunt-mcp/server.py"] },
    "fast-hunt":    { "command": "python3", "args": ["mcp/fast-hunt-mcp/server.py"] },
    "orchestrator": { "command": "python3", "args": ["mcp/orchestrator-mcp/server.py"] },
    "batch":        { "command": "python3", "args": ["mcp/batch-mcp/server.py"] },
    "hydration":    { "command": "python3", "args": ["mcp/hydration-mcp/server.py"] },
    "auth-tester":  { "command": "python3", "args": ["mcp/auth-tester-mcp/server.py"] },
    "https-probe":  { "command": "python3", "args": ["mcp/https-mcp/server.py"] },
    "evidence":     { "command": "python3", "args": ["mcp/evidence-mcp/server.py"] },
    "validation":   { "command": "python3", "args": ["mcp/validation-mcp/server.py"] }
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

### JS Analysis MCP (5 tools)
| Tool | Description |
|------|-------------|
| `analyze_js_bundle` | Full JS bundle analysis (endpoints + secrets + funcs) |
| `extract_endpoints` | Extract API endpoints from JS bundle |
| `scan_secrets` | Scan for hardcoded secrets (regex + entropy) |
| `extract_functionalities` | Extract functional modules from bundle |
| `batch_analyze_bundles` | Analyze all bundles in a directory |

### Deep Hunt MCP (5 tools)
| Tool | Description |
|------|-------------|
| `deep_hunt_start` | Start full deep hunt session |
| `deep_hunt_status` | Get session status and progress |
| `deep_hunt_results` | Retrieve findings from session |
| `deep_hunt_phase` | Run specific hunt phase |
| `deep_hunt_stop` | Stop running session |

### Fast Hunt MCP (4 tools)
| Tool | Description |
|------|-------------|
| `fast_hunt_start` | Start fast hunt session |
| `fast_hunt_status` | Get session status |
| `fast_hunt_results` | Get results from session |
| `fast_hunt_endpoints` | Quick endpoint discovery |

### Orchestrator MCP (4 tools)
| Tool | Description |
|------|-------------|
| `orchestrate_start` | Start full pipeline orchestration |
| `orchestrate_status` | Get pipeline status |
| `orchestrate_checkpoint` | Save/load checkpoint |
| `orchestrate_resume` | Resume from checkpoint |

### Batch MCP (4 tools)
| Tool | Description |
|------|-------------|
| `batch_start` | Start batch scan on multiple targets |
| `batch_status` | Get batch job status |
| `batch_results` | Retrieve batch results |
| `batch_stop` | Stop running batch job |

### Hydration MCP (3 tools)
| Tool | Description |
|------|-------------|
| `hydrate_recon` | Hydrate recon file with vulnerability context |
| `hydrate_endpoint` | Hydrate single endpoint with bug classes |
| `hydrate_batch` | Batch hydrate multiple recon files |

### Auth Tester MCP (5 tools)
| Tool | Description |
|------|-------------|
| `auth_test_jwt` | Test JWT: alg:none, weak secrets, RS256->HS256, kid |
| `auth_test_oauth` | Test OAuth: redirect_uri manipulation, state bypass |
| `auth_test_mfa` | Test MFA/2FA bypass, brute force, session fixation |
| `auth_test_csrf` | Test CSRF protection on sensitive actions |
| `auth_test_session` | Test session handling |

### HTTPS Probe MCP (4 tools)
| Tool | Description |
|------|-------------|
| `https_probe` | Probe HTTPS endpoint and collect SSL/TLS info |
| `https_certificate` | Extract SSL certificate details |
| `https_tls_version` | Check supported TLS versions and ciphers |
| `https_headers` | Analyze HTTPS security headers |

### Evidence MCP (4 tools)
| Tool | Description |
|------|-------------|
| `evidence_create_package` | Create evidence package for finding |
| `evidence_sanitize` | Sanitize: redact tokens, cookies, PII |
| `evidence_validate` | Validate package completeness |
| `evidence_export` | Export to zip/tar.gz/json |

### Validation MCP (5 tools)
| Tool | Description |
|------|-------------|
| `validate_finding` | Full validation: 7-Question + 4-Gate |
| `validate_gate7` | Run only 7-Question Gate |
| `validate_gate4` | Run only 4-Gate Checklist |
| `cvss_score` | Calculate CVSS score from vector |
| `severity_guide` | Get severity guide for bug class |

## Test any server

```bash
python mcp/<server>/server.py --list-tools
```

See each client's README for detailed setup instructions.
