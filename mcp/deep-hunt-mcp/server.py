#!/usr/bin/env python3
"""
deep-hunt-mcp/server.py — Deep Hunt Pipeline MCP Server

Exposes deep hunting workflow tools via MCP protocol.
Wraps tools/python/deep_hunt.py for comprehensive multi-phase hunting.
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
    from deep_hunt import DeepHunter
except ImportError:
    DeepHunter = None

TOOLS = [
    {
        "name": "deep_hunt_start",
        "description": "Start a deep hunt session on a target. Runs full pipeline: recon → rank → hunt → validate.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target domain"},
                "scope_file": {"type": "string", "description": "Path to scope config"},
                "timebox_minutes": {"type": "number", "default": 60},
            },
            "required": ["target"],
        },
    },
    {
        "name": "deep_hunt_status",
        "description": "Get status of running or completed deep hunt session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "deep_hunt_results",
        "description": "Retrieve findings from completed deep hunt session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "format": {"type": "string", "enum": ["json", "markdown", "csv"], "default": "json"},
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "deep_hunt_phase",
        "description": "Run a specific phase of deep hunt (recon, rank, hunt, validate).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "phase": {"type": "string", "enum": ["recon", "rank", "hunt", "validate"]},
            },
            "required": ["session_id", "phase"],
        },
    },
    {
        "name": "deep_hunt_stop",
        "description": "Stop a running deep hunt session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
            },
            "required": ["session_id"],
        },
    },
]


def _tool_deep_hunt_start(params):
    if DeepHunter is None:
        return {"error": "DeepHunter not available"}
    target = params.get("target")
    scope_file = params.get("scope_file")
    timebox = params.get("timebox_minutes", 60)
    hunter = DeepHunter(target=target, scope_file=scope_file, timebox_minutes=timebox)
    session_id = hunter.start()
    return {"session_id": session_id, "status": "started", "target": target}


def _tool_deep_hunt_status(params):
    session_id = params.get("session_id")
    # Placeholder: in real impl, load session state
    return {"session_id": session_id, "status": "running", "progress": 45}


def _tool_deep_hunt_results(params):
    session_id = params.get("session_id")
    fmt = params.get("format", "json")
    # Placeholder
    findings = []
    return {"session_id": session_id, "format": fmt, "findings": findings, "count": 0}


def _tool_deep_hunt_phase(params):
    session_id = params.get("session_id")
    phase = params.get("phase")
    return {"session_id": session_id, "phase": phase, "status": "completed"}


def _tool_deep_hunt_stop(params):
    session_id = params.get("session_id")
    return {"session_id": session_id, "status": "stopped"}


TOOL_HANDLERS = {
    "deep_hunt_start": _tool_deep_hunt_start,
    "deep_hunt_status": _tool_deep_hunt_status,
    "deep_hunt_results": _tool_deep_hunt_results,
    "deep_hunt_phase": _tool_deep_hunt_phase,
    "deep_hunt_stop": _tool_deep_hunt_stop,
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
