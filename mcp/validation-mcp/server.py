#!/usr/bin/env python3
"""
validation-mcp/server.py — Validation MCP Server

Exposes vulnerability validation tools via MCP protocol.
Wraps validation workflows: 7-Question Gate, 4-Gate Checklist, CVSS scoring.
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
    from validation import validate_finding, score_cvss
except ImportError:
    validate_finding = None
    score_cvss = None

TOOLS = [
    {
        "name": "validate_finding",
        "description": "Run full validation on a finding: 7-Question Gate + 4-Gate Checklist.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding": {"type": "object", "description": "Finding object with bug_class, target, endpoint, description"},
                "evidence_ready": {"type": "boolean", "default": False},
            },
            "required": ["finding"],
        },
    },
    {
        "name": "validate_gate7",
        "description": "Run only the 7-Question Gate on a finding.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding": {"type": "object"},
            },
            "required": ["finding"],
        },
    },
    {
        "name": "validate_gate4",
        "description": "Run only the 4-Gate Checklist on a finding (assumes 7-Question passed).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding": {"type": "object"},
                "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low"]},
            },
            "required": ["finding"],
        },
    },
    {
        "name": "cvss_score",
        "description": "Calculate CVSS 3.1 or 4.0 score from vector components.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "vector": {"type": "string", "description": "CVSS vector string, e.g., AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                "version": {"type": "string", "enum": ["3.1", "4.0"], "default": "3.1"},
            },
            "required": ["vector"],
        },
    },
    {
        "name": "severity_guide",
        "description": "Get severity classification guide for a bug class.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "bug_class": {"type": "string", "description": "Bug class (SSRF, IDOR, JWT, XSS, etc.)"},
                "impact": {"type": "string", "description": "Impact level if known (info, low, medium, high, critical)"},
            },
            "required": ["bug_class"],
        },
    },
]


def _tool_validate_finding(params):
    finding = params.get("finding", {})
    evidence_ready = params.get("evidence_ready", False)
    if validate_finding is None:
        return {"error": "Validation module not available", "finding_id": finding.get("id")}
    result = validate_finding(finding, evidence_ready=evidence_ready)
    return {"finding_id": finding.get("id"), "validation": result}


def _tool_validate_gate7(params):
    finding = params.get("finding", {})
    if validate_finding is None:
        return {"error": "Validation module not available"}
    result = validate_finding(finding, gate_only="gate7")
    return {"finding_id": finding.get("id"), "gate7": result}


def _tool_validate_gate4(params):
    finding = params.get("finding", {})
    severity = params.get("severity", "High")
    if validate_finding is None:
        return {"error": "Validation module not available"}
    result = validate_finding(finding, gate_only="gate4", severity=severity)
    return {"finding_id": finding.get("id"), "gate4": result}


def _tool_cvss_score(params):
    vector = params.get("vector")
    version = params.get("version", "3.1")
    if score_cvss is None:
        return {"error": "CVSS scoring module not available", "vector": vector}
    score = score_cvss(vector, version=version)
    return {"vector": vector, "version": version, "score": score}


def _tool_severity_guide(params):
    bug_class = params.get("bug_class")
    impact = params.get("impact", "")
    guides = {
        "SSRF": {"Critical": "Cloud metadata + IAM chain", "High": "Internal service access", "Medium": "Blind SSRF only"},
        "IDOR": {"Critical": "Write IDOR + ATO chain", "High": "Write IDOR or sensitive PII read", "Medium": "Read IDOR limited data"},
        "JWT": {"Critical": "alg:none with admin claims", "High": "Weak secret or RS256->HS256", "Medium": "kid injection without impact"},
        "XSS": {"Critical": "Stored XSS on admin pages", "High": "Stored XSS non-admin", "Medium": "Reflected non-self XSS"},
        "File Upload": {"Critical": "Webshell RCE", "High": "XXE or path traversal", "Medium": "File upload with content restriction bypass"},
    }
    class_guide = guides.get(bug_class.upper(), {})
    if impact and impact in class_guide:
        recommendation = class_guide[impact]
    else:
        recommendation = class_guide.get("High", "Assess based on actual impact demonstrated")
    return {"bug_class": bug_class, "recommendation": recommendation, "guide": class_guide}


TOOL_HANDLERS = {
    "validate_finding": _tool_validate_finding,
    "validate_gate7": _tool_validate_gate7,
    "validate_gate4": _tool_validate_gate4,
    "cvss_score": _tool_cvss_score,
    "severity_guide": _tool_severity_guide,
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
