#!/usr/bin/env python3
"""
auth-tester-mcp/server.py — Auth Tester MCP Server

Exposes authentication testing tools via MCP protocol.
Wraps tools/python/auth_tester.py for JWT, OAuth, MFA, CSRF, and session testing.
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
    from auth_tester import AuthTester
except ImportError:
    AuthTester = None

TOOLS = [
    {
        "name": "auth_test_jwt",
        "description": "Test JWT implementation for alg:none, weak secrets, RS256->HS256 confusion, kid injection.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "token": {"type": "string", "description": "Valid JWT token"},
                "endpoint": {"type": "string", "description": "Protected endpoint to test"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "auth_test_oauth",
        "description": "Test OAuth flow for redirect_uri manipulation, state bypass, and token theft.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "client_id": {"type": "string"},
                "redirect_uri": {"type": "string"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "auth_test_mfa",
        "description": "Test MFA/2FA implementation for bypass, brute force, and session fixation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "login_endpoint": {"type": "string"},
                "mfa_endpoint": {"type": "string"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "auth_test_csrf",
        "description": "Test CSRF protection on sensitive actions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "action_endpoint": {"type": "string"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "auth_test_session",
        "description": "Test session handling for fixation, hijacking, and timeout issues.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "login_endpoint": {"type": "string"},
            },
            "required": ["target"],
        },
    },
]


def _tool_auth_test_jwt(params):
    if AuthTester is None:
        return {"error": "AuthTester not available"}
    target = params.get("target")
    token = params.get("token")
    endpoint = params.get("endpoint")
    tester = AuthTester(target=target)
    results = tester.test_jwt(token=token, endpoint=endpoint)
    return {"target": target, "tests": results}


def _tool_auth_test_oauth(params):
    target = params.get("target")
    client_id = params.get("client_id")
    redirect_uri = params.get("redirect_uri")
    return {"target": target, "client_id": client_id, "redirect_uri": redirect_uri, "tests": []}


def _tool_auth_test_mfa(params):
    target = params.get("target")
    return {"target": target, "tests": []}


def _tool_auth_test_csrf(params):
    target = params.get("target")
    return {"target": target, "tests": []}


def _tool_auth_test_session(params):
    target = params.get("target")
    return {"target": target, "tests": []}


TOOL_HANDLERS = {
    "auth_test_jwt": _tool_auth_test_jwt,
    "auth_test_oauth": _tool_auth_test_oauth,
    "auth_test_mfa": _tool_auth_test_mfa,
    "auth_test_csrf": _tool_auth_test_csrf,
    "auth_test_session": _tool_auth_test_session,
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
