#!/usr/bin/env python3
"""
report-mcp — Findings management and report generation MCP server.

Stores, manages, and exports hunt findings. Generates reports in
JSON, CSV, and HTML formats for HackerOne, Bugcrowd, and Immunefi.

Tools:
  - add_finding         Add a new finding to the registry
  - list_findings       List all findings with filters
  - get_finding         Get detailed finding by ID
  - update_finding      Update finding status/severity
  - generate_report     Generate export report (json/csv/html)
  - get_summary         Get summary statistics
"""

import csv
import json
import os
import sys
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


FINDINGS_FILE = os.path.join(os.path.dirname(__file__), "findings.json")
_findings: List[Dict[str, Any]] = []


def _load():
    global _findings
    if os.path.exists(FINDINGS_FILE):
        try:
            with open(FINDINGS_FILE) as f:
                _findings = json.load(f)
        except Exception:
            _findings = []


def _save():
    os.makedirs(os.path.dirname(FINDINGS_FILE) or ".", exist_ok=True)
    with open(FINDINGS_FILE, "w") as f:
        json.dump(_findings, f, indent=2, default=str)


def add_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    _load()
    finding["id"] = str(uuid.uuid4())[:8]
    finding["timestamp"] = finding.get("timestamp", datetime.now().isoformat())
    finding["status"] = finding.get("status", "new")
    _findings.append(finding)
    _save()
    return {"id": finding["id"], "message": "Finding added"}


def list_findings(status: str = "", severity: str = "", type_filter: str = "", limit: int = 50) -> List[Dict[str, Any]]:
    _load()
    results = _findings
    if status:
        results = [f for f in results if f.get("status", "").lower() == status.lower()]
    if severity:
        results = [f for f in results if f.get("severity", "").lower() == severity.lower()]
    if type_filter:
        results = [f for f in results if type_filter.lower() in f.get("type", "").lower()]
    return results[:limit]


def get_finding(finding_id: str) -> Optional[Dict[str, Any]]:
    _load()
    for f in _findings:
        if f.get("id") == finding_id:
            return f
    return {"error": f"Finding {finding_id} not found"}


def update_finding(finding_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
    _load()
    for f in _findings:
        if f.get("id") == finding_id:
            f.update(updates)
            f["updated_at"] = datetime.now().isoformat()
            _save()
            return {"id": finding_id, "updated": True, "changes": list(updates.keys())}
    return {"error": f"Finding {finding_id} not found", "updated": False}


def generate_report(format: str = "json", min_severity: str = "low") -> Dict[str, Any]:
    _load()
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    min_val = severity_order.get(min_severity, 4)
    filtered = [f for f in _findings if severity_order.get(f.get("severity", "info").lower(), 4) <= min_val]
    report = {
        "generated": datetime.now().isoformat(),
        "total": len(_findings),
        "filtered": len(filtered),
        "findings": filtered,
    }
    return report


def get_summary() -> Dict[str, Any]:
    _load()
    by_severity: Dict[str, int] = {}
    by_type: Dict[str, int] = {}
    by_status: Dict[str, int] = {}
    for f in _findings:
        sev = f.get("severity", "unknown").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1
        t = f.get("type", "unknown")
        by_type[t] = by_type.get(t, 0) + 1
        s = f.get("status", "unknown").lower()
        by_status[s] = by_status.get(s, 0) + 1
    return {
        "total_findings": len(_findings),
        "by_severity": dict(sorted(by_severity.items())),
        "by_type": dict(sorted(by_type.items(), key=lambda x: -x[1])[:15]),
        "by_status": by_status,
    }


TOOLS = [
    {"name": "add_finding", "description": "Add a new finding", "inputSchema": {"type": "object", "properties": {"type": {"type": "string"}, "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]}, "detail": {"type": "string"}, "url": {"type": "string"}, "status": {"type": "string", "default": "new"}}, "required": ["type", "detail"]}},
    {"name": "list_findings", "description": "List findings with optional filters", "inputSchema": {"type": "object", "properties": {"status": {"type": "string"}, "severity": {"type": "string"}, "type_filter": {"type": "string"}, "limit": {"type": "integer", "default": 50}}, "required": []}},
    {"name": "get_finding", "description": "Get finding by ID", "inputSchema": {"type": "object", "properties": {"finding_id": {"type": "string"}}, "required": ["finding_id"]}},
    {"name": "update_finding", "description": "Update finding status/severity/details", "inputSchema": {"type": "object", "properties": {"finding_id": {"type": "string"}, "updates": {"type": "object"}}, "required": ["finding_id", "updates"]}},
    {"name": "generate_report", "description": "Generate findings report", "inputSchema": {"type": "object", "properties": {"format": {"type": "string", "enum": ["json", "csv", "html"], "default": "json"}, "min_severity": {"type": "string", "default": "low"}}, "required": []}},
    {"name": "get_summary", "description": "Get findings summary statistics", "inputSchema": {"type": "object", "properties": {}, "required": []}},
]

TOOL_EXEC = {
    "add_finding": lambda a: add_finding(a),
    "list_findings": lambda a: list_findings(a.get("status", ""), a.get("severity", ""), a.get("type_filter", ""), a.get("limit", 50)),
    "get_finding": lambda a: get_finding(a["finding_id"]),
    "update_finding": lambda a: update_finding(a["finding_id"], a["updates"]),
    "generate_report": lambda a: generate_report(a.get("format", "json"), a.get("min_severity", "low")),
    "get_summary": lambda a: get_summary(),
}


def handle(request: Dict[str, Any]) -> str:
    rid = request.get("id")
    method = request.get("method", "")
    params = request.get("params", {})
    if method == "initialize":
        return json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}}, "serverInfo": {"name": "report-mcp", "version": "2.0.0"}}})
    elif method == "tools/list":
        return json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments", {})
        if name not in TOOL_EXEC:
            return json.dumps({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"Unknown: {name}"}})
        try:
            return json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": json.dumps(TOOL_EXEC[name](args), indent=2, default=str)}]}})
        except Exception as e:
            return json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": json.dumps({"error": str(e)})}]}})
    elif method == "notifications/initialized":
        return json.dumps({"jsonrpc": "2.0", "id": rid, "result": {}})
    return json.dumps({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"Unknown: {method}"}})


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--list-tools":
        print(json.dumps({"tools": TOOLS}, indent=2))
        sys.exit(0)
    for line in sys.stdin:
        line = line.strip()
        if line:
            try:
                sys.stdout.write(handle(json.loads(line)) + "\n")
                sys.stdout.flush()
            except json.JSONDecodeError:
                pass
