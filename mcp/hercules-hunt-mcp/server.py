#!/usr/bin/env python3
"""
Hercules-Hunt MCP Server — exposes all 7 P1 hunters + core tools as MCP tools.

MCP (Model Context Protocol) server that wraps the Python vulnerability hunting
toolkit into callable tools for AI agents. Runs over stdio JSON-RPC 2.0.

Tools:
  - rce_hunt         RCE/CMDi/SSTI testing
  - sqli_hunt        SQLi/NoSQLi/JSONi testing
  - idor_hunt        IDOR / mass assignment testing
  - auth_hunt        JWT/OAuth/MFA/CSRF testing
  - ssrf_hunt        SSRF / cloud metadata testing
  - xxe_hunt         XXE / OOB / SVG / SOAP testing
  - file_upload_hunt File upload / webshell / XSS testing
  - secret_scan      Regex + entropy secret scanning
  - network_recon    DNS / SSL / port scan / CDN detection

Usage:
  python3 server.py              # Run MCP server over stdio (for Claude/OpenCode)
  python3 server.py --list-tools # Print tool definitions as JSON
  python3 server.py --tool rce_hunt '{"target_url":"https://target.com","cmd":"id"}'
"""

import importlib.util
import json
import os
import sys
import traceback
from datetime import datetime
from typing import Any, Dict, List, Optional


# ─── MCP Protocol Helpers ─────────────────────────────────────────────────────

MCP_VERSION = "2025-03-26"

def mcp_error(id: Any, code: int, message: str) -> str:
    return json.dumps({
        "jsonrpc": "2.0", "id": id,
        "error": {"code": code, "message": message},
    })

def mcp_result(id: Any, result: Any) -> str:
    return json.dumps({"jsonrpc": "2.0", "id": id, "result": result})


# ─── Tool Registry ────────────────────────────────────────────────────────────

TOOLS: List[Dict[str, Any]] = [
    {
        "name": "rce_hunt",
        "description": "Test for RCE, command injection, SSTI, and deserialization vulnerabilities",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "Target URL"},
                "cmd": {"type": "string", "description": "Command to inject", "default": "id"},
            },
            "required": ["target_url"],
        },
    },
    {
        "name": "sqli_hunt",
        "description": "Test for SQL injection, NoSQL injection, and JSON injection",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "Target URL"},
            },
            "required": ["target_url"],
        },
    },
    {
        "name": "idor_hunt",
        "description": "Test for IDOR and mass assignment vulnerabilities",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "Target URL with ID parameter"},
                "param_name": {"type": "string", "description": "ID parameter name", "default": "id"},
            },
            "required": ["target_url"],
        },
    },
    {
        "name": "auth_hunt",
        "description": "Test authentication bypass: JWT, OAuth, MFA, CSRF, rate limiting",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "Target URL"},
                "jwt_token": {"type": "string", "description": "JWT token to test"},
            },
            "required": ["target_url"],
        },
    },
    {
        "name": "ssrf_hunt",
        "description": "Test for SSRF including cloud metadata, localhost bypass, DNS rebinding",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "Target URL with SSRF parameter"},
                "param_name": {"type": "string", "description": "URL parameter name", "default": "url"},
            },
            "required": ["target_url"],
        },
    },
    {
        "name": "xxe_hunt",
        "description": "Test for XXE: classic, OOB, error-based, SVG, SOAP, encoding bypass",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "XML endpoint URL"},
            },
            "required": ["target_url"],
        },
    },
    {
        "name": "file_upload_hunt",
        "description": "Test file upload for webshell, XSS via SVG, XXE via DOCX, ZIP slip",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "Upload endpoint URL"},
            },
            "required": ["target_url"],
        },
    },
    {
        "name": "secret_scan",
        "description": "Scan files/directories for secrets using regex patterns and entropy detection",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File or directory path to scan"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "network_recon",
        "description": "Run network recon: DNS lookup, SSL cert info, port scan, CDN detection",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain"},
            },
            "required": ["domain"],
        },
    },
]

RESOURCES: List[Dict[str, Any]] = [
    {
        "uri": "hercules://findings/latest",
        "name": "Latest Findings",
        "description": "Most recent findings from the last hunt session",
        "mimeType": "application/json",
    },
    {
        "uri": "hercules://tools/inventory",
        "name": "Tool Inventory",
        "description": "Complete inventory of all Python and PowerShell tools",
        "mimeType": "application/json",
    },
    {
        "uri": "hercules://config/profile",
        "name": "Active Hunt Profile",
        "description": "Current active hunt configuration profile",
        "mimeType": "application/json",
    },
]


# ─── Tool Executors ───────────────────────────────────────────────────────────

def _load_module(module_name: str, file_path: str) -> Optional[Any]:
    """Load a Python module from file path."""
    try:
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    except Exception:
        return None
    return None

def _get_hunter_class(module: Any, class_name: str) -> Optional[Any]:
    """Get hunter class from loaded module."""
    return getattr(module, class_name, None) if module else None

HUNTER_BASE = os.path.join(os.path.dirname(__file__), "..", "..", "tools", "python")

def _run_hunter(hunter_file: str, class_name: str, target_url: str, **kwargs) -> Dict[str, Any]:
    """Generic runner for any P1 hunter module."""
    file_path = os.path.normpath(os.path.join(HUNTER_BASE, hunter_file))
    if not os.path.exists(file_path):
        return {"error": f"Hunter file not found: {file_path}", "target": target_url}
    mod = _load_module(hunter_file.replace(".py", ""), file_path)
    cls = _get_hunter_class(mod, class_name) if mod else None
    if not cls:
        return {"error": f"Class {class_name} not found in {hunter_file}", "target": target_url}
    try:
        hunter = cls(target_url=target_url)
        if hasattr(hunter, "test_all") and callable(hunter.test_all):
            hunter.test_all(target_url)
        elif hasattr(hunter, "test_ssrf_all") and callable(hunter.test_ssrf_all):
            getattr(hunter, "run_tests", lambda: None)()
        elif hasattr(hunter, "test_jwt_all") and callable(hunter.test_jwt_all):
            if kwargs.get("jwt_token"):
                hunter.test_jwt_all(kwargs["jwt_token"])
        summary = hunter.get_summary() if hasattr(hunter, "get_summary") else {}
        findings = getattr(hunter, "findings", [])
        return {
            "findings_count": len(findings),
            "summary": summary,
            "findings": findings[:20],
        }
    except Exception as e:
        return {"error": str(e), "traceback": traceback.format_exc(), "target": target_url}

def _exec_rce_hunt(args: Dict[str, Any]) -> Dict[str, Any]:
    url = args.get("target_url", "")
    cmd = args.get("cmd", "id")
    file_path = os.path.normpath(os.path.join(HUNTER_BASE, "rce_hunter.py"))
    mod = _load_module("rce_hunter", file_path)
    if not mod:
        return {"error": "rce_hunter module not found"}
    cls = _get_hunter_class(mod, "RCEHunter")
    if not cls:
        return {"error": "RCEHunter class not found"}
    hunter = cls(target_url=url)
    results = hunter.test_rce_command_injection(url, cmd=cmd)
    return {"findings": [f.get("detail", "") for f in hunter.findings[:20]], "count": len(hunter.findings)}

def _exec_ssrf_hunt(args: Dict[str, Any]) -> Dict[str, Any]:
    url = args.get("target_url", "")
    param = args.get("param_name", "url")
    file_path = os.path.normpath(os.path.join(HUNTER_BASE, "ssrf_hunter.py"))
    mod = _load_module("ssrf_hunter", file_path)
    if not mod:
        return {"error": "ssrf_hunter module not found"}
    cls = _get_hunter_class(mod, "SSRFHunter")
    if not cls:
        return {"error": "SSRFHunter class not found"}
    hunter = cls(target_url=url)
    results = hunter.test_ssrf_all(url, param)
    return {"findings": [f.get("detail", "") for f in hunter.findings[:20]], "count": len(hunter.findings)}

def _exec_secret_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    scan_path = args.get("path", ".")
    file_path = os.path.normpath(os.path.join(HUNTER_BASE, "secret_scanner.py"))
    mod = _load_module("secret_scanner", file_path)
    if not mod or not hasattr(mod, "SecretScanner"):
        return {"error": "secret_scanner module not found"}
    scanner = mod.SecretScanner()
    if hasattr(scanner, "scan_path"):
        scanner.scan_path(scan_path)
    return {
        "secrets_found": len(getattr(scanner, "findings", [])),
        "findings": getattr(scanner, "findings", [])[:20],
    }

TOOL_EXECUTORS = {
    "rce_hunt": _exec_rce_hunt,
    "ssrf_hunt": _exec_ssrf_hunt,
    "secret_scan": _exec_secret_scan,
    "sqli_hunt": lambda a: _run_hunter("sqli_hunter.py", "SQLiHunter", a.get("target_url", "")),
    "idor_hunt": lambda a: _run_hunter("idor_hunter.py", "IDORHunter", a.get("target_url", "")),
    "auth_hunt": lambda a: _run_hunter("auth_hunter.py", "AuthHunter", a.get("target_url", ""), jwt_token=a.get("jwt_token")),
    "xxe_hunt": lambda a: _run_hunter("xxe_hunter.py", "XXEHunter", a.get("target_url", "")),
    "file_upload_hunt": lambda a: _run_hunter("file_upload_hunter.py", "FileUploadHunter", a.get("target_url", "")),
}

def _exec_network_recon(args: Dict[str, Any]) -> Dict[str, Any]:
    domain = args.get("domain", "")
    fn_path = os.path.normpath(os.path.join(HUNTER_BASE, "network_utils.py"))
    spec = importlib.util.spec_from_file_location("network_utils", fn_path)
    if not spec or not spec.loader:
        return {"error": "network_utils module not found"}
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    results = {}
    if hasattr(mod, "dns_lookup"):
        results["dns"] = mod.dns_lookup(domain) if callable(mod.dns_lookup) else None
    if hasattr(mod, "get_cert_info"):
        results["ssl"] = mod.get_cert_info(domain) if callable(mod.get_cert_info) else None
    if hasattr(mod, "scan_ports"):
        results["ports"] = mod.scan_ports(domain) if callable(mod.scan_ports) else None
    return {"domain": domain, "results": results}

TOOL_EXECUTORS["network_recon"] = _exec_network_recon


# ─── MCP Request Handler ──────────────────────────────────────────────────────

def handle_request(request: Dict[str, Any]) -> str:
    req_id = request.get("id")
    method = request.get("method", "")
    params = request.get("params", {})

    if method == "initialize":
        return mcp_result(req_id, {
            "protocolVersion": MCP_VERSION,
            "capabilities": {
                "tools": {},
                "resources": {},
            },
            "serverInfo": {"name": "hercules-hunt-mcp", "version": "2.0.0"},
        })

    elif method == "tools/list":
        return mcp_result(req_id, {"tools": TOOLS})

    elif method == "tools/call":
        tool_name = params.get("name", "")
        args = params.get("arguments", {})
        if tool_name not in TOOL_EXECUTORS:
            return mcp_error(req_id, -32601, f"Unknown tool: {tool_name}")
        try:
            result = TOOL_EXECUTORS[tool_name](args)
            return mcp_result(req_id, {"content": [{"type": "text", "text": json.dumps(result, indent=2, default=str)}]})
        except Exception as e:
            return mcp_result(req_id, {"content": [{"type": "text", "text": json.dumps({"error": str(e), "traceback": traceback.format_exc()}, indent=2)}]})

    elif method == "resources/list":
        return mcp_result(req_id, {"resources": RESOURCES})

    elif method == "resources/read":
        uri = params.get("uri", "")
        if uri == "hercules://findings/latest":
            data = {"findings": [], "timestamp": datetime.now().isoformat(), "note": "Run a tool first to generate findings"}
            return mcp_result(req_id, {"contents": [{"uri": uri, "mimeType": "application/json", "text": json.dumps(data, indent=2)}]})
        elif uri == "hercules://tools/inventory":
            tools_list = [t["name"] for t in TOOLS]
            return mcp_result(req_id, {"contents": [{"uri": uri, "mimeType": "application/json", "text": json.dumps({"tools": tools_list, "count": len(tools_list)}, indent=2)}]})
        elif uri == "hercules://config/profile":
            profile_path = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "config", "profiles.json"))
            if os.path.exists(profile_path):
                with open(profile_path) as f:
                    return mcp_result(req_id, {"contents": [{"uri": uri, "mimeType": "application/json", "text": f.read()}]})
            return mcp_result(req_id, {"contents": [{"uri": uri, "mimeType": "application/json", "text": json.dumps({"profile": "no config found"})}]})
        return mcp_error(req_id, -32602, f"Unknown resource: {uri}")

    elif method == "notifications/initialized":
        return mcp_result(req_id, {})

    return mcp_error(req_id, -32601, f"Method not found: {method}")


# ─── CLI + MCP Server Loop ────────────────────────────────────────────────────

def main():
    if len(sys.argv) > 1:
        if sys.argv[1] == "--list-tools":
            print(json.dumps({"tools": TOOLS, "resources": RESOURCES}, indent=2))
            return
        elif sys.argv[1] == "--tool" and len(sys.argv) > 2:
            tool_name = sys.argv[2]
            args = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
            if tool_name in TOOL_EXECUTORS:
                result = TOOL_EXECUTORS[tool_name](args)
                print(json.dumps(result, indent=2, default=str))
            else:
                print(json.dumps({"error": f"Unknown tool: {tool_name}"}))
            return

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
            response = handle_request(request)
            if response:
                sys.stdout.write(response + "\n")
                sys.stdout.flush()
        except json.JSONDecodeError:
            sys.stdout.write(mcp_error(None, -32700, "Parse error") + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
