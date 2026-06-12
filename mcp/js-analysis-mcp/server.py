#!/usr/bin/env python3
"""
js-analysis-mcp/server.py — JavaScript Bundle Analysis MCP Server

Exposes JS bundle analysis tools via MCP protocol.
Wraps tools/python/js_analyzer.py and tools/python/extract_apis.py
for endpoint extraction, secret scanning, and functionality analysis.
"""

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools", "python"))

from mcp_lib import (
    MCP_VERSION,
    mcp_result,
    mcp_error,
    mcp_notification,
    mcp_progress_notification,
    handle_initialize,
    handle_tools_list,
    MCPErrorCodes,
)

try:
    from js_analyzer import JSAnalyzer
    from extract_apis import extract_apis_from_bundle
    from extract_functionalities import extract_functionalities
    from secret_scanner import SecretScanner
except ImportError:
    JSAnalyzer = None
    extract_apis_from_bundle = None
    extract_functionalities = None
    SecretScanner = None

TOOLS = [
    {
        "name": "analyze_js_bundle",
        "description": "Analyze a JavaScript bundle for endpoints, secrets, and functionality. Returns structured JSON with findings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "bundle_path": {"type": "string", "description": "Path to JS bundle file or directory"},
                "scan_secrets": {"type": "boolean", "description": "Enable secret scanning", "default": True},
                "scan_endpoints": {"type": "boolean", "description": "Enable endpoint extraction", "default": True},
            },
            "required": ["bundle_path"],
        },
    },
    {
        "name": "extract_endpoints",
        "description": "Extract API endpoints from a JS bundle using string and regex analysis.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "bundle_path": {"type": "string"},
                "include_comments": {"type": "boolean", "default": False},
            },
            "required": ["bundle_path"],
        },
    },
    {
        "name": "scan_secrets",
        "description": "Scan JS bundle for hardcoded secrets using regex + entropy detection.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "bundle_path": {"type": "string"},
                "entropy_threshold": {"type": "number", "default": 3.5},
            },
            "required": ["bundle_path"],
        },
    },
    {
        "name": "extract_functionalities",
        "description": "Extract functional modules and features from a JS bundle.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "bundle_path": {"type": "string"},
            },
            "required": ["bundle_path"],
        },
    },
    {
        "name": "batch_analyze_bundles",
        "description": "Analyze multiple JS bundles in a directory and produce a summary report.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "bundle_dir": {"type": "string"},
                "output_file": {"type": "string", "default": "js-analysis-report.json"},
            },
            "required": ["bundle_dir"],
        },
    },
]


def _tool_analyze_js_bundle(params):
    if JSAnalyzer is None:
        return {"error": "JSAnalyzer not available"}
    bundle_path = params.get("bundle_path")
    scan_secrets = params.get("scan_secrets", True)
    scan_endpoints = params.get("scan_endpoints", True)
    analyzer = JSAnalyzer(bundle_path)
    result = analyzer.analyze(scan_secrets=scan_secrets, scan_endpoints=scan_endpoints)
    return result


def _tool_extract_endpoints(params):
    if extract_apis_from_bundle is None:
        return {"error": "extract_apis not available"}
    bundle_path = params.get("bundle_path")
    include_comments = params.get("include_comments", False)
    endpoints = extract_apis_from_bundle(bundle_path, include_comments=include_comments)
    return {"endpoints": endpoints, "count": len(endpoints)}


def _tool_scan_secrets(params):
    if SecretScanner is None:
        return {"error": "SecretScanner not available"}
    bundle_path = params.get("bundle_path")
    entropy_threshold = params.get("entropy_threshold", 3.5)
    scanner = SecretScanner(entropy_threshold=entropy_threshold)
    secrets = scanner.scan_file(bundle_path)
    return {"secrets": secrets, "count": len(secrets)}


def _tool_extract_functionalities(params):
    if extract_functionalities is None:
        return {"error": "extract_functionalities not available"}
    bundle_path = params.get("bundle_path")
    funcs = extract_functionalities(bundle_path)
    return {"functionalities": funcs, "count": len(funcs)}


def _tool_batch_analyze_bundles(params):
    bundle_dir = params.get("bundle_dir")
    output_file = params.get("output_file", "js-analysis-report.json")
    if JSAnalyzer is None:
        return {"error": "JSAnalyzer not available"}
    results = []
    for fname in os.listdir(bundle_dir):
        if fname.endswith(".js"):
            fpath = os.path.join(bundle_dir, fname)
            analyzer = JSAnalyzer(fpath)
            results.append({"file": fname, **analyzer.analyze()})
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    return {"bundles_analyzed": len(results), "output_file": output_file}


TOOL_HANDLERS = {
    "analyze_js_bundle": _tool_analyze_js_bundle,
    "extract_endpoints": _tool_extract_endpoints,
    "scan_secrets": _tool_scan_secrets,
    "extract_functionalities": _tool_extract_functionalities,
    "batch_analyze_bundles": _tool_batch_analyze_bundles,
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
