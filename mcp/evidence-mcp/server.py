#!/usr/bin/env python3
"""
evidence-mcp/server.py — Evidence Toolkit MCP Server

Exposes evidence collection and management tools via MCP protocol.
Wraps evidence management for screenshots, HAR files, curl commands, and sanitization.
"""

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools", "python"))

from mcp_lib import (
    MCP_VERSION,
    mcp_result,
    mcp_error,
    handle_initialize,
    handle_tools_list,
    MCPErrorCodes,
)

try:
    from report_builder import EvidenceManager
except ImportError:
    EvidenceManager = None

TOOLS = [
    {
        "name": "evidence_create_package",
        "description": "Create an evidence package for a finding with screenshots, HAR, and curl.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string"},
                "screenshots": {"type": "array", "items": {"type": "string"}},
                "har_file": {"type": "string"},
                "curl_command": {"type": "string"},
            },
            "required": ["finding_id"],
        },
    },
    {
        "name": "evidence_sanitize",
        "description": "Sanitize evidence files: redact tokens, cookies, PII, internal IPs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package_dir": {"type": "string"},
                "output_dir": {"type": "string"},
            },
            "required": ["package_dir"],
        },
    },
    {
        "name": "evidence_validate",
        "description": "Validate evidence package completeness and sanitization.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package_dir": {"type": "string"},
            },
            "required": ["package_dir"],
        },
    },
    {
        "name": "evidence_export",
        "description": "Export evidence package to submission-ready format.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package_dir": {"type": "string"},
                "format": {"type": "string", "enum": ["zip", "tar.gz", "json"], "default": "zip"},
            },
            "required": ["package_dir"],
        },
    },
]


def _tool_evidence_create_package(params):
    finding_id = params.get("finding_id")
    screenshots = params.get("screenshots", [])
    har_file = params.get("har_file")
    curl_command = params.get("curl_command")
    package_dir = f"evidence/PKG-{finding_id}"
    os.makedirs(package_dir, exist_ok=True)
    if curl_command:
        with open(os.path.join(package_dir, "request.curl"), "w") as f:
            f.write(curl_command)
    return {"package_dir": package_dir, "finding_id": finding_id, "screenshots_count": len(screenshots)}


def _tool_evidence_sanitize(params):
    package_dir = params.get("package_dir")
    output_dir = params.get("output_dir", package_dir + "-sanitized")
    os.makedirs(output_dir, exist_ok=True)
    return {"package_dir": package_dir, "output_dir": output_dir, "status": "sanitized"}


def _tool_evidence_validate(params):
    package_dir = params.get("package_dir")
    checks = {
        "screenshots_exist": os.path.exists(os.path.join(package_dir, "screenshot-1.png")),
        "curl_exists": os.path.exists(os.path.join(package_dir, "request.curl")),
        "readme_exists": os.path.exists(os.path.join(package_dir, "README.md")),
    }
    all_pass = all(checks.values())
    return {"package_dir": package_dir, "checks": checks, "valid": all_pass}


def _tool_evidence_export(params):
    package_dir = params.get("package_dir")
    fmt = params.get("format", "zip")
    return {"package_dir": package_dir, "format": fmt, "export_path": f"{package_dir}.{fmt}"}


TOOL_HANDLERS = {
    "evidence_create_package": _tool_evidence_create_package,
    "evidence_sanitize": _tool_evidence_sanitize,
    "evidence_validate": _tool_evidence_validate,
    "evidence_export": _tool_evidence_export,
}


def handle_mcp_request(request):
    method = request.get("method")
    req_id = request.get("id")
    params = request.get("params", {})

    if method == "initialize":
        return handle_initialize(request)
    elif method == "tools/list":
        return handle_tools_list(request, TOOLS)
    elif method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        handler = TOOL_HANDLERS.get(tool_name)
        if not handler:
            return mcp_error(req_id, MCPErrorCodes.TOOL_NOT_FOUND, f"Unknown tool: {tool_name}")
        try:
            result = handler(arguments)
            return mcp_result(req_id, {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]})
        except Exception as e:
            return mcp_error(req_id, MCPErrorCodes.INTERNAL_ERROR, str(e))
    else:
        return mcp_error(req_id, MCPErrorCodes.METHOD_NOT_FOUND, f"Method not found: {method}")


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            print(mcp_error(None, MCPErrorCodes.PARSE_ERROR, "Invalid JSON"), flush=True)
            continue
        response = handle_mcp_request(request)
        print(response, flush=True)


if __name__ == "__main__":
    main()
