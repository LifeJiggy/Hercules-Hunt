# DNS Recon MCP — DNS Enumeration & Subdomain Discovery

DNS reconnaissance tools: record lookup, certificate transparency
search, reverse DNS, and subdomain brute-force.

## Tools

| Tool | Description |
|------|-------------|
| `dns_lookup` | Look up A/AAAA/MX/NS/TXT/CNAME/SOA records |
| `crt_sh_search` | Search crt.sh for subdomains via cert transparency |
| `reverse_dns` | Reverse DNS lookup by IP address |
| `dns_bruteforce` | Brute-force common subdomains (30 built-in) |

## Setup

```json
{
  "mcpServers": {
    "dns-recon": {
      "command": "python3",
      "args": ["mcp/dns-recon-mcp/server.py"]
    }
  }
}
```

## Usage

```bash
python mcp/dns-recon-mcp/server.py --list-tools
```

Depends on: Python standard library only (socket, ssl, urllib).
