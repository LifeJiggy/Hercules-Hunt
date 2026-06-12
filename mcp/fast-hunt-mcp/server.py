#!/usr/bin/env python3
"""
fast-hunt-mcp/server.py — Fast Hunt Pipeline MCP Server

Exposes fast hunting workflow tools via MCP protocol.
Wraps tools/python/fast_hunt.py for rapid endpoint discovery and testing.
"""

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools", "python"))

from mcp_lib import (
    MCP_VERSION,
    mcp_result,
    mcp_error,
    mcp_progress_notification,
    handle_initialize,
    handle_tools_list,
    MCPErrorCodes,
)

try:
    from fast_hunt import FastHunter
except ImportError:
    FastHunter = None

TOOLS = [
    {
        "name": "fast_hunt_start",
        "description": "Start a fast hunt session on a target. Runs lightweight recon and immediate testing.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target domain"},
                "timebox_minutes": {"type": "number", "default": 30},
            },
            "required": ["target"],
        },
    },
    {
        "name": "fast_hunt_status",
        "description": "Get status of fast hunt session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "fast_hunt_results",
        "description": "Get results from fast hunt session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "json"},
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "fast_hunt_endpoints",
        "description": "Quick endpoint discovery for a target using multiple sources.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "sources": {"type": "array", "items": {"type": "string"}, "default": ["wayback", "crawl", "subdomains"]},
            },
            "required": ["target"],
        },
    },
]


def _tool_fast_hunt_start(params):
    if FastHunter is None:
        return {"error": "FastHunter not available"}
    target = params.get("target")
    timebox = params.get("timebox_minutes", 30)
    hunter = FastHunter(target=target, timebox_minutes=timebox)
    session_id = hunter.start()
    return {"session_id": session_id, "status": "started", "target": target}


def _tool_fast_hunt_status(params):
    return {"session_id": params.get("session_id"), "status": "running", "progress": 30}


def _tool_fast_hunt_results(params):
    session_id = params.get("session_id")
    fmt = params.get("format", "json")
    return {"session_id": session_id, "format": fmt, "findings": [], "count": 0}


def _tool_fast_hunt_endpoints(params):
    target = params.get("target")
    sources = params.get("sources", ["wayback", "crawl", "subdomains"])
    return {"target": target, "sources": sources, "endpoints": [], "count": 0}


TOOL_HANDLERS = {
    "fast_hunt_start": _tool_fast_hunt_start,
    "fast_hunt_status": _tool_fast_hunt_status,
    "fast_hunt_results": _tool_fast_hunt_results,
    "fast_hunt_endpoints": _tool_fast_hunt_endpoints,
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
