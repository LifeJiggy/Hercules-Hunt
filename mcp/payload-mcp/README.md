# Payload MCP — Vulnerability Payload Generation

Generates payloads for 7+ vulnerability classes with WAF bypass
variants and encoding transformations (URL, base64, hex, unicode).

## Tools

| Tool | Description |
|------|-------------|
| `generate_xss` | Reflected/stored/DOM XSS variants |
| `generate_sqli` | Error/time/union/boolean SQLi payloads |
| `generate_ssrf` | Cloud metadata, localhost, scheme bypass URLs |
| `generate_xxe` | Classic/OOB/error XXE entity payloads |
| `generate_cmdi` | Command injection (;, |, `, $()) variants |
| `generate_ssti` | Jinja2/Twig/Freemarker/ERB probes |
| `generate_nosqli` | MongoDB NoSQL injection ($gt, $ne, $where) |
| `encode_payload` | Encode payloads: url, base64, hex, double_url, unicode |

## Setup

```json
{
  "mcpServers": {
    "payloads": {
      "command": "python3",
      "args": ["mcp/payload-mcp/server.py"]
    }
  }
}
```

## Usage

```bash
python mcp/payload-mcp/server.py --list-tools
```

Depends on: Python standard library only.
