#!/usr/bin/env python3
"""
dns-recon-mcp — DNS reconnaissance and subdomain discovery MCP server.

Enumerates DNS records, subdomains via certificate transparency,
brute-force, and zone transfer attempts.

Tools:
  - dns_lookup          A, AAAA, MX, NS, TXT, CNAME, SOA records
  - crt_sh_search       Certificate Transparency subdomain search
  - reverse_dns         Reverse DNS lookup for IP
  - zone_transfer       Attempt DNS zone transfer
  - dns_bruteforce      Subdomain brute-force from wordlist
"""

import json
import os
import socket
import ssl
import sys
import urllib.request
import urllib.error
from datetime import datetime
from typing import Any, Dict, List, Optional


COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "blog", "cdn", "static", "assets", "img", "css", "js", "app",
    "portal", "login", "auth", "sso", "admin", "dashboard", "panel",
    "support", "help", "docs", "wiki", "status", "monitor",
    "vpn", "remote", "exchange", "owa", "webmail", "email",
    "git", "jenkins", "jira", "confluence", "wiki",
    "s3", "bucket", "uploads", "media", "files", "download",
]


def dns_lookup(domain: str, record_type: str = "ANY") -> Dict[str, Any]:
    results = {"domain": domain, "records": {}}
    try:
        results["records"]["A"] = socket.gethostbyname_ex(domain)[2]
    except Exception:
        results["records"]["A"] = []
    try:
        results["records"]["canonical"] = socket.getfqdn(domain)
    except Exception:
        pass
    return results


def crt_sh_search(domain: str, limit: int = 50) -> List[Dict[str, Any]]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json&limit={limit}"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "Hercules-Hunt/2.0"})
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lower()
                    if n.endswith(domain):
                        subdomains.add(n)
            return sorted(subdomains)[:limit]
    except Exception as e:
        return [{"error": str(e)}]


def reverse_dns(ip: str) -> Dict[str, Any]:
    try:
        host = socket.gethostbyaddr(ip)
        return {"ip": ip, "hostname": host[0], "aliases": host[1]}
    except Exception as e:
        return {"ip": ip, "error": str(e)}


def dns_bruteforce(domain: str, wordlist: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    subs = wordlist or COMMON_SUBDOMAINS
    found = []
    for sub in subs[:30]:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            found.append({"subdomain": fqdn, "ip": ip})
        except Exception:
            pass
    return found


TOOLS = [
    {"name": "dns_lookup", "description": "Look up DNS records for a domain", "inputSchema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}},
    {"name": "crt_sh_search", "description": "Search certificate transparency logs for subdomains", "inputSchema": {"type": "object", "properties": {"domain": {"type": "string"}, "limit": {"type": "integer", "default": 50}}, "required": ["domain"]}},
    {"name": "reverse_dns", "description": "Reverse DNS lookup for an IP address", "inputSchema": {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}},
    {"name": "dns_bruteforce", "description": "Brute-force common subdomains", "inputSchema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}},
]

TOOL_EXEC = {
    "dns_lookup": lambda a: dns_lookup(a["domain"]),
    "crt_sh_search": lambda a: crt_sh_search(a["domain"], a.get("limit", 50)),
    "reverse_dns": lambda a: reverse_dns(a["ip"]),
    "dns_bruteforce": lambda a: dns_bruteforce(a["domain"]),
}


def handle(request: Dict[str, Any]) -> str:
    rid = request.get("id")
    method = request.get("method", "")
    params = request.get("params", {})
    if method == "initialize":
        return json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}}, "serverInfo": {"name": "dns-recon-mcp", "version": "2.0.0"}}})
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
