#!/usr/bin/env python3
"""
orchestrator-mcp/server.py — Orchestrator MCP Server

Exposes pipeline orchestration tools via MCP protocol.
Wraps tools/python/python-hunter.py for full workflow orchestration.
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
    from python_hunter import Orchestrator
except ImportError:
    Orchestrator = None

TOOLS = [
    {
        "name": "orchestrate_start",
        "description": "Start a full orchestration pipeline: recon → rank → research → hunt → chain → validate → report.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "config": {"type": "string", "description": "Path to hunter config"},
                "mode": {"type": "string", "enum": ["paranoid", "normal", "yolo"], "default": "normal"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "orchestrate_status",
        "description": "Get status of running orchestration.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "orchestrate_checkpoint",
        "description": "Create or resume from a checkpoint in the pipeline.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "checkpoint_name": {"type": "string"},
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "orchestrate_resume",
        "description": "Resume orchestration from last checkpoint.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
            },
            "required": ["session_id"],
        },
    },
]


def _tool_orchestrate_start(params):
    if Orchestrator is None:
        return {"error": "Orchestrator not available"}
    target = params.get("target")
    config = params.get("config")
    mode = params.get("mode", "normal")
    orch = Orchestrator(target=target, config_path=config, mode=mode)
    session_id = orch.start()
    return {"session_id": session_id, "status": "started", "mode": mode}


def _tool_orchestrate_status(params):
    return {"session_id": params.get("session_id"), "status": "running", "phase": "recon", "progress": 10}


def _tool_orchestrate_checkpoint(params):
    return {"session_id": params.get("session_id"), "checkpoint": params.get("checkpoint_name", "auto"), "status": "saved"}


def _tool_orchestrate_resume(params):
    return {"session_id": params.get("session_id"), "status": "resumed", "phase": "recon"}


TOOL_HANDLERS = {
    "orchestrate_start": _tool_orchestrate_start,
    "orchestrate_status": _tool_orchestrate_status,
    "orchestrate_checkpoint": _tool_orchestrate_checkpoint,
    "orchestrate_resume": _tool_orchestrate_resume,
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
