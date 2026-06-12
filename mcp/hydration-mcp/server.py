#!/usr/bin/env python3
"""
hydration-mcp/server.py — Data Hydration MCP Server

Exposes data hydration tools via MCP protocol.
Wraps tools/python/hydration.py for enriching recon data with vulnerability context.
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
    from hydration import Hydrator
except ImportError:
    Hydrator = None

TOOLS = [
    {
        "name": "hydrate_recon",
        "description": "Hydrate raw recon data with vulnerability context and bug-class assignments.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "recon_file": {"type": "string", "description": "Path to recon JSON file"},
                "output_file": {"type": "string", "description": "Path to output hydrated JSON"},
            },
            "required": ["recon_file"],
        },
    },
    {
        "name": "hydrate_endpoint",
        "description": "Hydrate a single endpoint with potential bug classes and test plans.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "endpoint": {"type": "string"},
                "method": {"type": "string"},
                "parameters": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["endpoint", "method"],
        },
    },
    {
        "name": "hydrate_batch",
        "description": "Hydrate multiple recon files in batch.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "recon_dir": {"type": "string"},
                "output_dir": {"type": "string"},
            },
            "required": ["recon_dir"],
        },
    },
]


def _tool_hydrate_recon(params):
    if Hydrator is None:
        return {"error": "Hydrator not available"}
    recon_file = params.get("recon_file")
    output_file = params.get("output_file", "hydrated-recon.json")
    hydrator = Hydrator()
    result = hydrator.hydrate_file(recon_file)
    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)
    return {"output_file": output_file, "endpoints_hydrated": len(result.get("endpoints", []))}


def _tool_hydrate_endpoint(params):
    endpoint = params.get("endpoint")
    method = params.get("method")
    parameters = params.get("parameters", [])
    if Hydrator is None:
        return {"error": "Hydrator not available"}
    hydrator = Hydrator()
    result = hydrator.hydrate_endpoint(endpoint, method, parameters)
    return result


def _tool_hydrate_batch(params):
    recon_dir = params.get("recon_dir")
    output_dir = params.get("output_dir", "hydrated-output")
    os.makedirs(output_dir, exist_ok=True)
    count = 0
    for fname in os.listdir(recon_dir):
        if fname.endswith(".json"):
            fpath = os.path.join(recon_dir, fname)
            outpath = os.path.join(output_dir, fname)
            try:
                hydrator = Hydrator()
                result = hydrator.hydrate_file(fpath)
                with open(outpath, "w") as f:
                    json.dump(result, f, indent=2)
                count += 1
            except Exception:
                pass
    return {"files_processed": count, "output_dir": output_dir}


TOOL_HANDLERS = {
    "hydrate_recon": _tool_hydrate_recon,
    "hydrate_endpoint": _tool_hydrate_endpoint,
    "hydrate_batch": _tool_hydrate_batch,
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
