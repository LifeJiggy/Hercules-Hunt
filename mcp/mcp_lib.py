#!/usr/bin/env python3
"""
mcp_lib.py — Shared MCP Protocol Helpers for Hercules-Hunt

Provides standard JSON-RPC 2.0 / MCP protocol formatting, error codes,
progress notifications, and request/notification routing.

All MCP servers in this project should import from this module to ensure
consistent protocol compliance.

Usage:
    from mcp_lib import (
        MCP_VERSION, mcp_result, mcp_error, mcp_notification,
        is_notification, handle_initialize, handle_tools_list,
        mcp_progress_notification, handle_mcp_request,
        MCPErrorCodes,
    )
"""

import json
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

MCP_VERSION = "2025-03-26"

# ─── MCP Error Codes (JSON-RPC 2.0 + MCP extensions) ────────────

class MCPErrorCodes:
    PARSE_ERROR          = -32700
    INVALID_REQUEST      = -32600
    METHOD_NOT_FOUND     = -32601
    INVALID_PARAMS       = -32602
    INTERNAL_ERROR       = -32603
    # MCP-specific
    TOOL_NOT_FOUND       = -32001
    RESOURCE_NOT_FOUND   = -32002
    COMPLETION_NOT_FOUND = -32003


# ─── Response / Notification Builders ────────────────────────────

def mcp_result(id: Any, result: Any) -> str:
    """Build a JSON-RPC 2.0 success response."""
    return json.dumps({"jsonrpc": "2.0", "id": id, "result": result})


def mcp_error(id: Any, code: int, message: str, data: Any = None) -> str:
    """Build a JSON-RPC 2.0 error response with optional data field."""
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return json.dumps({"jsonrpc": "2.0", "id": id, "error": err})


def mcp_notification(method: str, params: Dict[str, Any] = None) -> str:
    """Build a JSON-RPC 2.0 notification (no id — no response expected)."""
    msg = {"jsonrpc": "2.0", "method": method}
    if params:
        msg["params"] = params
    return json.dumps(msg)


def mcp_progress_notification(
    progress_token: str,
    progress: float,
    total: Optional[float] = None,
    message: Optional[str] = None,
) -> str:
    """Build an MCP progress notification (per spec: notifications/progress)."""
    params = {
        "progressToken": progress_token,
        "progress": progress,
    }
    if total is not None:
        params["total"] = total
    if message:
        params["message"] = message
    return mcp_notification("notifications/progress", params)


def mcp_log_message(level: str, message: str, **extra) -> str:
    """Build a logging/message notification (per MCP spec)."""
    params = {"level": level, "message": message, **extra}
    return mcp_notification("logging/message", params)


# ─── Request / Notification Detection ────────────────────────────

def is_notification(request: Dict[str, Any]) -> bool:
    """A JSON-RPC notification has no 'id' field."""
    return "id" not in request or request["id"] is None


def get_request_id(request: Dict[str, Any]) -> Any:
    """Safely get request id — returns None for notifications."""
    return request.get("id") if "id" in request else None


# ─── Standard MCP Handlers ───────────────────────────────────────

def handle_initialize(req_id: Any, params: Dict = None,
                      server_name: str = "mcp-server",
                      server_version: str = "1.0.0",
                      capabilities: Dict = None) -> str:
    """Handle MCP initialize request."""
    caps = capabilities or {"tools": {}, "resources": {}, "logging": {}}
    return mcp_result(req_id, {
        "protocolVersion": MCP_VERSION,
        "capabilities": caps,
        "serverInfo": {"name": server_name, "version": server_version},
    })


def handle_tools_list(req_id: Any, tools: List[Dict]) -> str:
    """Handle MCP tools/list request."""
    return mcp_result(req_id, {"tools": tools})


def handle_resources_list(req_id: Any, resources: List[Dict]) -> str:
    """Handle MCP resources/list request."""
    return mcp_result(req_id, {"resources": resources})


def handle_completion_complete(req_id: Any, params: Dict) -> str:
    """Handle MCP completion/complete request (stub)."""
    return mcp_result(req_id, {
        "completion": {
            "values": [],
            "total": 0,
        }
    })


def handle_ping(req_id: Any) -> str:
    """Handle MCP ping request."""
    return mcp_result(req_id, {})


# ─── Top-Level Request Router ────────────────────────────────────

def handle_mcp_request(
    request: Dict[str, Any],
    tools: List[Dict],
    tool_executors: Dict[str, callable],
    resources: List[Dict] = None,
    resource_readers: Dict[str, callable] = None,
    server_name: str = "mcp-server",
    server_version: str = "1.0.0",
    capabilities: Dict = None,
) -> Optional[str]:
    """
    Route an MCP request/notification and return the response string,
    or None for notifications (no response expected).

    Callers must:
    - Send notification strings via sys.stdout.write() directly
    - Return response strings via sys.stdout.write()
    """
    req_id = get_request_id(request)
    method = request.get("method", "")
    params = request.get("params", {})

    # ── Requests that expect a response ──
    if not is_notification(request):
        if method == "initialize":
            return handle_initialize(req_id, params, server_name, server_version, capabilities)

        elif method == "ping":
            return handle_ping(req_id)

        elif method == "tools/list":
            return handle_tools_list(req_id, tools)

        elif method == "tools/call":
            tool_name = params.get("name", "")
            args = params.get("arguments", {})
            if tool_name not in tool_executors:
                return mcp_error(req_id, MCPErrorCodes.TOOL_NOT_FOUND,
                                 f"Unknown tool: {tool_name}")
            try:
                result = tool_executors[tool_name](args)
                return mcp_result(req_id, {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2, default=str)}]
                })
            except Exception as e:
                import traceback
                return mcp_result(req_id, {
                    "content": [{"type": "text", "text": json.dumps({
                        "error": str(e),
                        "traceback": traceback.format_exc(),
                    }, indent=2)}]
                })

        elif method == "resources/list":
            resources_list = resources or []
            return handle_resources_list(req_id, resources_list)

        elif method == "resources/read":
            uri = params.get("uri", "")
            if resource_readers and uri in resource_readers:
                try:
                    result = resource_readers[uri]()
                    return mcp_result(req_id, {
                        "contents": [{"uri": uri, "mimeType": "application/json",
                                      "text": json.dumps(result, indent=2, default=str)}]
                    })
                except Exception as e:
                    return mcp_error(req_id, MCPErrorCodes.INTERNAL_ERROR,
                                     f"Error reading resource: {e}")
            return mcp_error(req_id, MCPErrorCodes.RESOURCE_NOT_FOUND,
                             f"Unknown resource: {uri}")

        elif method == "resources/subscribe":
            # Stub — clients may subscribe, server can ignore per spec
            return mcp_result(req_id, {})

        elif method == "resources/unsubscribe":
            return mcp_result(req_id, {})

        elif method == "completion/complete":
            return handle_completion_complete(req_id, params)

        elif method == "sampling/createMessage":
            return mcp_error(req_id, MCPErrorCodes.METHOD_NOT_FOUND,
                             "sampling not supported")

        elif method == "logging/setLevel":
            return mcp_result(req_id, {})

        return mcp_error(req_id, MCPErrorCodes.METHOD_NOT_FOUND,
                         f"Method not found: {method}")

    # ── Notifications (no response) ──
    if method == "notifications/initialized":
        # Per MCP spec: no response expected
        return None

    elif method == "notifications/cancelled":
        return None

    elif method == "notifications/progress":
        return None

    # Unknown notification — per spec, silently ignore
    return None


# ─── Stdio Server Loop ───────────────────────────────────────────

def run_stdio_server(handler_fn: callable, log: bool = False):
    """
    Run a line-delimited JSON-RPC 2.0 server over stdin/stdout.

    handler_fn(request_dict) -> Optional[str]
      - Return a response string for requests
      - Return None for notifications
    """
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
            response = handler_fn(request)
            if response:
                sys.stdout.write(response + "\n")
                sys.stdout.flush()
        except json.JSONDecodeError:
            sys.stdout.write(mcp_error(None, MCPErrorCodes.PARSE_ERROR,
                                       "Parse error") + "\n")
            sys.stdout.flush()
        except Exception as e:
            req_id = request.get("id") if "request" in dir() and isinstance(request, dict) else None
            sys.stdout.write(mcp_error(req_id, MCPErrorCodes.INTERNAL_ERROR,
                                       f"Internal error: {e}") + "\n")
            sys.stdout.flush()


# ─── Progress Notification Helper (for long-running tools) ───────

def notify_progress(progress_token: str, current: float, total: float,
                    message: str = None):
    """Send a progress notification to stdout (for long-running tools)."""
    notification = mcp_progress_notification(progress_token, current, total, message)
    sys.stdout.write(notification + "\n")
    sys.stdout.flush()
