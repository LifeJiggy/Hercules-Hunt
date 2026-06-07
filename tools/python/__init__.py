#!/usr/bin/env python3
"""
Hercules-Hunt Python Vulnerability Hunting Toolkit

Package containing 17 specialized vulnerability-hunting modules,
each with 20+ detection methods for top bug classes.

Modules:
    rce_hunter           — RCE, CMDi, SSTI, deserialization (P1)
    sqli_hunter          — SQL/NoSQL injection detection (P1)
    idor_hunter          — Insecure Direct Object Reference (P1)
    auth_hunter          — Authentication/authorization bypass (P1)
    ssrf_hunter          — Server-Side Request Forgery (P1)
    xxe_hunter           — XML External Entity injection (P1)
    file_upload_hunter   — File upload RCE/XSS/XXE (P1)
    python-hunter        — Orchestrator with pipeline, diff, report
    js_analyzer          — JavaScript bundle analysis & secrets
    url_collector        — URL crawling & parameter extraction
    endpoint_fuzzer      — Directory/file fuzzing & discovery
    base64_utils         — Base64 encoding/decoding utilities
    batch_processor      — Multi-target batch scanning
    report_builder       — HTML/JSON/CSV report generation
    secret_scanner       — 30+ regex pattern & entropy secret scanning
    payload_generator    — XSS/SQLi/SSRF/XXE/LFI/CMDi/SSTI payloads
    network_utils        — DNS, SSL, port scan, CDN/WAF detection

All modules share a common interface:
    export_json()        — Returns/export findings as JSON
    get_summary()        — Returns finding count summary dict
    __main__             — CLI entry point, run module.py --help
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

__version__ = "2.0.0"
__author__ = "Jiggy Security Team"
__description__ = "Vulnerability hunting toolkit — 17 modules, 340+ detection methods"

__all__ = [
    "rce_hunter",
    "sqli_hunter",
    "idor_hunter",
    "auth_hunter",
    "ssrf_hunter",
    "xxe_hunter",
    "file_upload_hunter",
    "js_analyzer",
    "url_collector",
    "endpoint_fuzzer",
    "base64_utils",
    "batch_processor",
    "report_builder",
    "secret_scanner",
    "payload_generator",
    "network_utils",
]
