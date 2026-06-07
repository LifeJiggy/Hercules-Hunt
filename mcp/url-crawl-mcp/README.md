# URL Crawl MCP — Wayback Machine & URL Discovery

Historical URL discovery from Wayback Machine and CommonCrawl.
Extracts endpoints, parameters, and file extensions from crawled URLs.

## Tools

| Tool | Description |
|------|-------------|
| `wayback_urls` | Fetch historical URLs from Wayback Machine CDX API |
| `wayback_request_bodies` | Get status, mime type, timestamp per URL |
| `common_crawl` | Search CommonCrawl index (CC-MAIN-2025-06) |
| `extract_endpoints` | Parse paths, params, extensions from URL list |

## Setup

```json
{
  "mcpServers": {
    "url-crawl": {
      "command": "python3",
      "args": ["mcp/url-crawl-mcp/server.py"]
    }
  }
}
```

## Usage

```bash
python mcp/url-crawl-mcp/server.py --list-tools
```

Depends on: Python standard library (ssl, urllib).
Rate limits: Wayback CDX ~10 req/min, CommonCrawl ~100 req/min.
