# Interactsh MCP — OOB Callback Testing

Blind interaction / out-of-band callback testing via interact.sh integration.
Generates unique poll URLs for SSRF, XXE, and blind RCE detection.

## Tools

| Tool | Description |
|------|-------------|
| `generate_callback` | Create a unique OOB callback URL for blind testing |
| `check_callbacks` | Poll all/specific callbacks for received interactions |
| `test_ssrf_blind` | Generate SSRF callback test URLs + payloads |
| `test_xxe_oob` | Generate OOB XXE DTD with callback exfiltration |
| `test_rce_oob` | Generate blind RCE pingback payloads |

## Setup

```json
{
  "mcpServers": {
    "interactsh": {
      "command": "python3",
      "args": ["mcp/interactsh-mcp/server.py"]
    }
  }
}
```

## Usage

```bash
# List tools
python mcp/interactsh-mcp/server.py --list-tools

# Test directly (MCP clients connect via stdio)
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"generate_callback","arguments":{}}}' | python mcp/interactsh-mcp/server.py
```

Depends on: `interact.sh` public API (no API key required).
