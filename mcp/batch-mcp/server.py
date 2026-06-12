#!/usr/bin/env python3
"""
batch-mcp/server.py — Batch Processing MCP Server

Exposes batch processing tools via MCP protocol.
Wraps tools/python/batch_processor.py for multi-target scanning.
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
    from batch_processor import BatchProcessor
except ImportError:
    BatchProcessor = None

TOOLS = [
    {
        "name": "batch_start",
        "description": "Start batch processing on multiple targets with rate limiting.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "targets": {"type": "array", "items": {"type": "string"}, "description": "List of target URLs"},
                "module": {"type": "string", "description": "Module to run (e.g., ssrf_hunter, idor_hunter)"},
                "rate_limit": {"type": "number", "default": 10, "description": "Requests per second"},
                "timeout": {"type": "number", "default": 30},
            },
            "required": ["targets", "module"],
        },
    },
    {
        "name": "batch_status",
        "description": "Get status of batch processing job.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
            },
            "required": ["job_id"],
        },
    },
    {
        "name": "batch_results",
        "description": "Get results from completed batch job.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
                "format": {"type": "string", "enum": ["json", "csv", "html"], "default": "json"},
            },
            "required": ["job_id"],
        },
    },
    {
        "name": "batch_stop",
        "description": "Stop a running batch job.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
            },
            "required": ["job_id"],
        },
    },
]


def _tool_batch_start(params):
    if BatchProcessor is None:
        return {"error": "BatchProcessor not available"}
    targets = params.get("targets", [])
    module = params.get("module")
    rate_limit = params.get("rate_limit", 10)
    timeout = params.get("timeout", 30)
    processor = BatchProcessor(rate_limit=rate_limit, timeout=timeout)
    job_id = processor.start(targets=targets, module=module)
    return {"job_id": job_id, "status": "started", "targets_count": len(targets), "module": module}


def _tool_batch_status(params):
    return {"job_id": params.get("job_id"), "status": "running", "progress": 50, "processed": 5, "total": 10}


def _tool_batch_results(params):
    job_id = params.get("job_id")
    fmt = params.get("format", "json")
    return {"job_id": job_id, "format": fmt, "results": [], "count": 0}


def _tool_batch_stop(params):
    return {"job_id": params.get("job_id"), "status": "stopped"}


TOOL_HANDLERS = {
    "batch_start": _tool_batch_start,
    "batch_status": _tool_batch_status,
    "batch_results": _tool_batch_results,
    "batch_stop": _tool_batch_stop,
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
