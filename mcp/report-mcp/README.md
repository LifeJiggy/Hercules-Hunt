# Report MCP — Findings Management & Report Generation

Stores, manages, and exports hunt findings. Persists to `findings.json`
in the same directory. Generates reports in JSON, CSV, and HTML formats.

## Tools

| Tool | Description |
|------|-------------|
| `add_finding` | Add a new finding (type, severity, detail, url, status) |
| `list_findings` | List findings filtered by status/severity/type |
| `get_finding` | Get detailed finding by its 8-char ID |
| `update_finding` | Update finding status/severity/details |
| `generate_report` | Export all findings as json/csv/html report |
| `get_summary` | Stats: total, by severity, by type, by status |

## Setup

```json
{
  "mcpServers": {
    "reports": {
      "command": "python3",
      "args": ["mcp/report-mcp/server.py"]
    }
  }
}
```

## Usage

```bash
python mcp/report-mcp/server.py --list-tools
```

### Data persistence

Findings are stored in `mcp/report-mcp/findings.json`. This file
is created automatically when the first finding is added.

### Example finding structure

```json
{
  "id": "a1b2c3d4",
  "type": "ssrf_cloud_metadata",
  "severity": "critical",
  "detail": "AWS metadata accessible via 169.254.169.254",
  "url": "https://target.com/fetch?url=",
  "status": "confirmed",
  "timestamp": "2026-06-07T12:00:00"
}
```

Depends on: Python standard library only.
