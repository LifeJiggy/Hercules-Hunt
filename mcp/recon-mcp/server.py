#!/usr/bin/env python3
"""
recon-mcp — Comprehensive reconnaissance MCP server.

Orchestrates multi-stage recon: subdomain discovery, live host
probing, technology fingerprinting, port scanning, and URL
collection. Integration point for web2-recon workflow.

Tools:
  - discover_subdomains   Multi-source subdomain discovery
  - probe_live_hosts      HTTP probe subdomains for live hosts
  - fingerprint           Technology fingerprinting via HTTP headers
  - port_scan             Targeted port scan on discovered hosts
  - full_recon            Full recon pipeline (all steps)
  - get_recon_status      Check status of recon targets
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


RECON_TARGETS: Dict[str, Dict[str, Any]] = {}

COMMON_PORTS = [80, 443, 8080, 8443, 22, 21, 3306, 5432, 6379, 9200, 27017, 1433, 1521, 25, 110, 993, 995]

TECH_SIGNATURES: Dict[str, List[str]] = {
    "cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
    "nginx": ["Server: nginx", "nginx/"],
    "apache": ["Server: Apache", "Apache/"],
    "iis": ["Server: Microsoft-IIS", "X-AspNet-Version"],
    "cloudfront": ["x-amz-cf-id", "x-amz-cf-pop", "cloudfront"],
    "fastly": ["X-Served-By", "X-Cache-Hits", "Fastly"],
    "akamai": ["X-Akamai-", "Akamai"],
    "wordpress": ["wp-content", "wp-includes", "WordPress"],
    "laravel": ["Laravel", "X-Powered-By: PHP"],
    "rails": ["rails", "X-Powered-By: Phusion"],
    "django": ["csrftoken", "django"],
    "react": ["react", "__NEXT_DATA__", "next.js"],
    "vue": ["vue", "vue.js", "Vue"],
    "angular": ["angular", "ng-app", "ng-version"],
}


def discover_subdomains(domain: str) -> Dict[str, Any]:
    results = {"domain": domain, "sources": {}, "subdomains": set()}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(f"https://crt.sh/?q=%25.{domain}&output=json&limit=100",
                                      headers={"User-Agent": "Hercules-Hunt/2.0"})
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    n = name.strip().lower()
                    if n.endswith(domain) and n != domain:
                        results["subdomains"].add(n)
        results["sources"]["crt.sh"] = len(results["subdomains"])
    except Exception as e:
        results["sources"]["crt.sh"] = str(e)
    results["subdomains"] = sorted(results["subdomains"])[:100]
    results["count"] = len(results["subdomains"])
    RECON_TARGETS[domain] = {"subdomains": results["subdomains"], "updated": datetime.now().isoformat()}
    return results


def probe_live_hosts(domain: str, subdomains: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    if not subdomains:
        if domain in RECON_TARGETS:
            subdomains = RECON_TARGETS[domain].get("subdomains", [])
        else:
            return [{"error": "Run discover_subdomains first or provide subdomains"}]
    live = []
    for sub in subdomains[:30]:
        for port in [80, 443]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((sub, port))
                sock.close()
                if result == 0:
                    scheme = "https" if port == 443 else "http"
                    live.append({"host": sub, "port": port, "url": f"{scheme}://{sub}"})
            except Exception:
                pass
    return live


def fingerprint(urls: List[str]) -> List[Dict[str, Any]]:
    results = []
    for url in urls[:20]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "Hercules-Hunt/2.0"})
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                headers = dict(resp.headers)
                body_sample = resp.read(5000).decode("utf-8", errors="replace").lower()
                detected = []
                for tech, sigs in TECH_SIGNATURES.items():
                    for sig in sigs:
                        if sig.lower() in str(headers).lower() or sig.lower() in body_sample:
                            detected.append(tech)
                            break
                results.append({"url": url, "status": resp.status, "server": headers.get("Server", ""), "tech": detected, "headers": {k: v for k, v in list(headers.items())[:10]}})
        except Exception as e:
            results.append({"url": url, "error": str(e)[:80]})
    return results


def port_scan(host: str, ports: Optional[List[int]] = None) -> List[Dict[str, Any]]:
    if not ports:
        ports = COMMON_PORTS
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                open_ports.append({"port": port, "state": "open"})
        except Exception:
            pass
    return open_ports


def full_recon(domain: str) -> Dict[str, Any]:
    subs = discover_subdomains(domain)
    live = probe_live_hosts(domain, subs.get("subdomains"))
    live_urls = [h["url"] for h in live if "url" in h]
    tech = fingerprint(live_urls)
    return {
        "domain": domain,
        "subdomains": subs,
        "live_hosts": live,
        "fingerprints": tech,
        "timestamp": datetime.now().isoformat(),
    }


TOOLS = [
    {"name": "discover_subdomains", "description": "Multi-source subdomain discovery (crt.sh)", "inputSchema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}},
    {"name": "probe_live_hosts", "description": "HTTP probe subdomains for live hosts", "inputSchema": {"type": "object", "properties": {"domain": {"type": "string"}, "subdomains": {"type": "array", "items": {"type": "string"}}}, "required": ["domain"]}},
    {"name": "fingerprint", "description": "Technology fingerprinting via HTTP", "inputSchema": {"type": "object", "properties": {"urls": {"type": "array", "items": {"type": "string"}}}, "required": ["urls"]}},
    {"name": "port_scan", "description": "Port scan a host for common ports", "inputSchema": {"type": "object", "properties": {"host": {"type": "string"}, "ports": {"type": "array", "items": {"type": "integer"}}}, "required": ["host"]}},
    {"name": "full_recon", "description": "Full recon pipeline: subdomains -> live hosts -> fingerprint", "inputSchema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}},
]

TOOL_EXEC = {
    "discover_subdomains": lambda a: discover_subdomains(a["domain"]),
    "probe_live_hosts": lambda a: probe_live_hosts(a["domain"], a.get("subdomains")),
    "fingerprint": lambda a: fingerprint(a["urls"]),
    "port_scan": lambda a: port_scan(a["host"], a.get("ports")),
    "full_recon": lambda a: full_recon(a["domain"]),
}


def handle(request: Dict[str, Any]) -> str:
    rid = request.get("id")
    method = request.get("method", "")
    params = request.get("params", {})
    if method == "initialize":
        return json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}}, "serverInfo": {"name": "recon-mcp", "version": "2.0.0"}}})
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
