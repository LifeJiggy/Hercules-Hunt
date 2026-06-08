#!/usr/bin/env python3
"""
Hercules-Hunt MCP Server — exposes all 7 P1 hunters + core tools as MCP tools.

MCP (Model Context Protocol) server wrapping the Python vulnerability hunting
toolkit into callable tools for AI agents. Runs over stdio JSON-RPC 2.0.

Uses shared mcp_lib.py for standard MCP protocol compliance.

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
  python3 server.py                  # Run MCP server over stdio
  python3 server.py --list-tools     # Print tool definitions as JSON (helper)
  python3 server.py --tool rce_hunt '{"target_url":"https://target.com","cmd":"id"}'
"""

import importlib.util
import json
import os
import sys
import traceback
from datetime import datetime
from typing import Any, Dict, List

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from mcp_lib import (
    MCP_VERSION, MCPErrorCodes, mcp_result, mcp_error, mcp_notification,
    is_notification, get_request_id,
    handle_initialize, handle_tools_list, handle_resources_list,
    handle_completion_complete, handle_mcp_request, run_stdio_server,
    notify_progress,
)

HUNTER_BASE = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "tools", "python"))


# ─── Tool Registry ────────────────────────────────────────────────

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
            "properties": {"target_url": {"type": "string", "description": "Target URL"}},
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
                "target_url": {"type": "string", "description": "Target URL"},
                "param_name": {"type": "string", "description": "Parameter to test", "default": "url"},
            },
            "required": ["target_url"],
        },
    },
    {
        "name": "xxe_hunt",
        "description": "Test for XXE, OOB XXE, SVG XXE, SOAP XXE, DOCX XXE",
        "inputSchema": {
            "type": "object",
            "properties": {"target_url": {"type": "string", "description": "Target URL"}},
            "required": ["target_url"],
        },
    },
    {
        "name": "file_upload_hunt",
        "description": "Test file upload: webshell, XSS via SVG, zip slip, polyglot",
        "inputSchema": {
            "type": "object",
            "properties": {"target_url": {"type": "string", "description": "Upload endpoint URL"}},
            "required": ["target_url"],
        },
    },
    {
        "name": "secret_scan",
        "description": "Scan files/directories for hardcoded secrets and API keys",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Path to scan", "default": "."}},
            "required": [],
        },
    },
    {
        "name": "network_recon",
        "description": "DNS lookup, SSL cert info, port scan, CDN detection",
        "inputSchema": {
            "type": "object",
            "properties": {"domain": {"type": "string", "description": "Domain to recon"}},
            "required": ["domain"],
        },
    },
]

RESOURCES = [
    {"uri": "hercules://findings/latest", "name": "Latest Hunt Findings",
     "description": "Most recent findings from tool execution", "mimeType": "application/json"},
    {"uri": "hercules://tools/inventory", "name": "Tool Inventory",
     "description": "Full list of available hunting tools", "mimeType": "application/json"},
    {"uri": "hercules://config/profile", "name": "Active Profile",
     "description": "Current hunter configuration profile", "mimeType": "application/json"},
]


# ─── Module Loading Helpers ───────────────────────────────────────

def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if not spec or not spec.loader:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


def _get_hunter_class(mod, class_name: str):
    return getattr(mod, class_name, None) if mod else None


def _run_hunter(hunter_file: str, class_name: str, target_url: str, **kwargs) -> Dict:
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


# ─── Tool Executors ───────────────────────────────────────────────

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
    hunter.test_rce_command_injection(url, cmd=cmd)
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
    hunter.test_ssrf_all(url, param)
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


# ─── Resource Readers ─────────────────────────────────────────────

def _read_findings_latest():
    return {"findings": [], "timestamp": datetime.now().isoformat(),
            "note": "Run a tool first to generate findings"}


def _read_tools_inventory():
    return {"tools": [t["name"] for t in TOOLS], "count": len(TOOLS)}


def _read_config_profile():
    profile_path = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "config", "profiles.json"))
    if os.path.exists(profile_path):
        with open(profile_path) as f:
            return json.load(f)
    return {"profile": "default", "note": "No config/profile.json found"}


RESOURCE_READERS = {
    "hercules://findings/latest": _read_findings_latest,
    "hercules://tools/inventory": _read_tools_inventory,
    "hercules://config/profile": _read_config_profile,
}


# ─── Request Handler ──────────────────────────────────────────────

def handle_request(request: Dict[str, Any]) -> str:
    return handle_mcp_request(
        request=request,
        tools=TOOLS,
        tool_executors=TOOL_EXECUTORS,
        resources=RESOURCES,
        resource_readers=RESOURCE_READERS,
        server_name="hercules-hunt-mcp",
        server_version="2.0.0",
        capabilities={"tools": {}, "resources": {}, "logging": {}},
    )


# ─── CLI + MCP Server Loop ────────────────────────────────────────

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

    run_stdio_server(handle_request)


if __name__ == "__main__":
    main()
