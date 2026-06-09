#!/usr/bin/env python3
"""
Hercules-Hunt Python Vulnerability Hunting Toolkit

Package containing 27 specialized vulnerability-hunting modules,
each with 20+ detection methods for top bug classes.

Modules:
    extract_apis            — API endpoint discovery (REST/GraphQL/SOAP/gRPC)
    extract_js              — JavaScript extraction, analysis & secret scanning
    deep_hunt               — Multi-pass systematic hunting (IDOR/SSRF/XSS/auth)
    fast_hunt               — Quick surface-level low-hanging fruit probes
    https_probing           — TLS/certificate/security header analysis
    extract_parameters      — URL/body/header/cookie parameter extraction
    extract_functionalities — User interactive element & workflow mapping
    endpoint_fuzzer         — Path/method/extension/parameter fuzzing
    auth_tester             — Auth bypass, JWT analysis, session/rate-limit testing
    report_builder          — Multi-format report generation with CVSS 3.1
    rce_hunter              — RCE, CMDi, SSTI, deserialization (P1)
    sqli_hunter             — SQL/NoSQL injection detection (P1)
    idor_hunter             — Insecure Direct Object Reference (P1)
    auth_hunter             — Authentication/authorization bypass (P1)
    ssrf_hunter             — Server-Side Request Forgery (P1)
    xxe_hunter              — XML External Entity injection (P1)
    file_upload_hunter      — File upload RCE/XSS/XXE (P1)
    python-hunter           — Orchestrator with pipeline, diff, report
    js_analyzer             — JavaScript bundle analysis & secrets
    url_collector           — URL crawling & parameter extraction
    base64_utils            — Base64 encoding/decoding utilities
    batch_processor         — Multi-target batch scanning
    secret_scanner          — 30+ regex pattern & entropy secret scanning
    payload_generator       — XSS/SQLi/SSRF/XXE/LFI/CMDi/SSTI payloads
    network_utils           — DNS, SSL, port scan, CDN/WAF detection

All modules share a common interface:
    export_json()        — Returns/export findings as JSON
    get_summary()        — Returns finding count summary dict
    __main__             — CLI entry point, run module.py --help
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

__version__ = "3.0.0"
__author__ = "Jiggy Security Team"
__description__ = "Vulnerability hunting toolkit — 27 modules, 540+ detection methods"

__all__ = [
    "extract_apis",
    "extract_js",
    "deep_hunt",
    "fast_hunt",
    "https_probing",
    "extract_parameters",
    "extract_functionalities",
    "auth_tester",
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
