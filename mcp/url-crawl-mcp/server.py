#!/usr/bin/env python3
"""
url-crawl-mcp — URL crawling, Wayback Machine, and endpoint discovery MCP server.

Discovers URLs from Wayback Machine, CommonCrawl, and builds
endpoint catalogs for active target testing.

Tools:
  - wayback_urls          Fetch historical URLs from Wayback Machine
  - wayback_request_bodies Get request/response pairs from Wayback
  - common_crawl          Search CommonCrawl index for URLs
  - extract_endpoints     Parse endpoints from URL list (dedup, categorize)
  - url_stats             Statistics on discovered URL catalog
"""

import json
import os
import re
import ssl
import sys
import urllib.parse
import urllib.request
import urllib.error
from collections import Counter
from datetime import datetime
from typing import Any, Dict, List, Optional, Set


def wayback_urls(domain: str, limit: int = 200) -> List[str]:
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&limit={limit}&collapse=urlkey"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "Hercules-Hunt/2.0"})
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            return [entry[0] for entry in data[1:]] if len(data) > 1 else []
    except Exception as e:
        return [{"error": str(e)}]


def wayback_request_bodies(domain: str, limit: int = 50) -> List[Dict[str, Any]]:
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original,statuscode,mimetype,timestamp&limit={limit}"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "Hercules-Hunt/2.0"})
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            results = []
            for entry in data[1:]:
                results.append({"url": entry[0], "status": entry[1], "mime": entry[2], "timestamp": entry[3]})
            return results
    except Exception as e:
        return [{"error": str(e)}]


def common_crawl(domain: str, limit: int = 100) -> List[str]:
    index_url = "https://index.commoncrawl.org/CC-MAIN-2025-06-index"
    search_url = f"{index_url}?url=*.{domain}/*&output=json&limit={limit}&fl=url"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(search_url, headers={"User-Agent": "Hercules-Hunt/2.0"})
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            urls = []
            for line in resp.read().decode().strip().split("\n"):
                if line:
                    try:
                        urls.append(json.loads(line).get("url", ""))
                    except json.JSONDecodeError:
                        pass
            return urls[:limit]
    except Exception as e:
        return [{"error": str(e)}]


def extract_endpoints(urls: List[str]) -> Dict[str, Any]:
    paths: Set[str] = set()
    params: Counter = Counter()
    exts: Counter = Counter()
    methods = set()
    for u in urls:
        parsed = urllib.parse.urlparse(u)
        path = parsed.path.rstrip("/")
        if path:
            paths.add(path)
        if parsed.query:
            for p in urllib.parse.parse_qs(parsed.query):
                params[p] += 1
        ext = os.path.splitext(parsed.path)[1].lower()
        if ext:
            exts[ext] += 1
    return {
        "unique_paths": len(paths),
        "paths": sorted(paths)[:50],
        "parameters": dict(params.most_common(30)),
        "extensions": dict(exts.most_common(20)),
    }


TOOLS = [
    {"name": "wayback_urls", "description": "Fetch historical URLs from Wayback Machine", "inputSchema": {"type": "object", "properties": {"domain": {"type": "string"}, "limit": {"type": "integer", "default": 200}}, "required": ["domain"]}},
    {"name": "wayback_request_bodies", "description": "Get detailed request info from Wayback", "inputSchema": {"type": "object", "properties": {"domain": {"type": "string"}, "limit": {"type": "integer", "default": 50}}, "required": ["domain"]}},
    {"name": "common_crawl", "description": "Search CommonCrawl index for URLs", "inputSchema": {"type": "object", "properties": {"domain": {"type": "string"}, "limit": {"type": "integer", "default": 100}}, "required": ["domain"]}},
    {"name": "extract_endpoints", "description": "Parse endpoints from URL list", "inputSchema": {"type": "object", "properties": {"urls": {"type": "array", "items": {"type": "string"}}}, "required": ["urls"]}},
]

TOOL_EXEC = {
    "wayback_urls": lambda a: wayback_urls(a["domain"], a.get("limit", 200)),
    "wayback_request_bodies": lambda a: wayback_request_bodies(a["domain"], a.get("limit", 50)),
    "common_crawl": lambda a: common_crawl(a["domain"], a.get("limit", 100)),
    "extract_endpoints": lambda a: extract_endpoints(a["urls"]),
}


def handle(request: Dict[str, Any]) -> str:
    rid = request.get("id")
    method = request.get("method", "")
    params = request.get("params", {})
    if method == "initialize":
        return json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}}, "serverInfo": {"name": "url-crawl-mcp", "version": "2.0.0"}}})
    elif method == "tools/list":
        return json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments", {})
        if name not in TOOL_EXEC:
            return json.dumps({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"Unknown: {name}"}})
        try:
            return json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": json.dumps(TOOL_EXEC[name](args), indent=2, default=str)}]}})
        except Exception as e:
            return json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": json.dumps({"error": str(e)})}]}})
    elif method == "notifications/initialized":
        return json.dumps({"jsonrpc": "2.0", "id": rid, "result": {}})
    return json.dumps({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"Unknown: {method}"}})


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--list-tools":
        print(json.dumps({"tools": TOOLS}, indent=2))
        sys.exit(0)
    for line in sys.stdin:
        line = line.strip()
        if line:
            try:
                sys.stdout.write(handle(json.loads(line)) + "\n")
                sys.stdout.flush()
            except json.JSONDecodeError:
                pass
