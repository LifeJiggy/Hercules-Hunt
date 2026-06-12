#!/usr/bin/env python3
"""
https-mcp/server.py — HTTPS Probing MCP Server

Exposes HTTPS probing tools via MCP protocol.
Wraps tools/python/https_probing.py for SSL/TLS analysis, certificate inspection, and protocol testing.
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
    from https_probing import HTTPSProber
except ImportError:
    HTTPSProber = None

TOOLS = [
    {
        "name": "https_probe",
        "description": "Probe HTTPS endpoint and collect SSL/TLS information.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "port": {"type": "number", "default": 443},
            },
            "required": ["target"],
        },
    },
    {
        "name": "https_certificate",
        "description": "Extract SSL certificate details: issuer, subject, SANs, validity, fingerprint.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "port": {"type": "number", "default": 443},
            },
            "required": ["target"],
        },
    },
    {
        "name": "https_tls_version",
        "description": "Check supported TLS versions and cipher suites.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "port": {"type": "number", "default": 443},
            },
            "required": ["target"],
        },
    },
    {
        "name": "https_headers",
        "description": "Analyze HTTPS security headers: HSTS, CSP, X-Frame-Options, etc.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "path": {"type": "string", "default": "/"},
            },
            "required": ["target"],
        },
    },
]


def _tool_https_probe(params):
    if HTTPSProber is None:
        return {"error": "HTTPSProber not available"}
    target = params.get("target")
    port = params.get("port", 443)
    prober = HTTPSProber(target, port=port)
    result = prober.probe()
    return result


def _tool_https_certificate(params):
    if HTTPSProber is None:
        return {"error": "HTTPSProber not available"}
    target = params.get("target")
    port = params.get("port", 443)
    prober = HTTPSProber(target, port=port)
    result = prober.get_certificate()
    return result


def _tool_https_tls_version(params):
    if HTTPSProber is None:
        return {"error": "HTTPSProber not available"}
    target = params.get("target")
    port = params.get("port", 443)
    prober = HTTPSProber(target, port=port)
    result = prober.check_tls()
    return result


def _tool_https_headers(params):
    if HTTPSProber is None:
        return {"error": "HTTPSProber not available"}
    target = params.get("target")
    path = params.get("path", "/")
    prober = HTTPSProber(target)
    result = prober.check_headers(path)
    return result


TOOL_HANDLERS = {
    "https_probe": _tool_https_probe,
    "https_certificate": _tool_https_certificate,
    "https_tls_version": _tool_https_tls_version,
    "https_headers": _tool_https_headers,
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
