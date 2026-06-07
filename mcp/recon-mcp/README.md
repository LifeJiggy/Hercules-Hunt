# Recon MCP — Multi-Stage Reconnaissance Pipeline

Orchestrates subdomain discovery, live host probing, technology
fingerprinting, and port scanning in one pipeline.

## Tools

| Tool | Description |
|------|-------------|
| `discover_subdomains` | Subdomain discovery via crt.sh certificate transparency |
| `probe_live_hosts` | HTTP probe subdomains (port 80/443) for live hosts |
| `fingerprint` | Tech stack detection via HTTP headers + body signatures |
| `port_scan` | Port scan for 17 common ports (http, db, mail, etc.) |
| `full_recon` | All-in-one: discover -> probe -> fingerprint |

## Setup

```json
{
  "mcpServers": {
    "recon": {
      "command": "python3",
      "args": ["mcp/recon-mcp/server.py"]
    }
  }
}
```

## Usage

```bash
python mcp/recon-mcp/server.py --list-tools
```

### Tech fingerprints detected

- CDN: Cloudflare, CloudFront, Fastly, Akamai
- Web servers: nginx, Apache, IIS
- Frameworks: WordPress, Laravel, Rails, Django, React, Vue, Angular

### Scan notes

- Subdomain discovery is rate-limited by crt.sh (~30 req/min)
- Port scan uses raw sockets (no nmap required)
- Full recon runs all stages sequentially

Depends on: Python standard library (socket, ssl, urllib).
