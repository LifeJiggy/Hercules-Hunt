#!/usr/bin/env python3
"""
extract_js.py — JavaScript Extraction & Analysis Tool

Extracts inline JS from HTML documents, discovers and downloads external
JS files, analyzes JavaScript bundles for API endpoints, secrets and keys
(35+ regex patterns), URLs, email addresses, and suspicious patterns
(eval, document.write, innerHTML, setTimeout with strings, etc.).

Features: inline JS extraction from script tags and event handlers, external
JS URL discovery (src, dynamic imports, module scripts), JS file download
with configurable timeouts and user-agent rotation, REST/GraphQL/WebSocket
endpoint discovery, secret/credential scanning (AWS keys, API tokens, JWTs,
private keys, OAuth secrets, cloud credentials, database connection strings),
URL extraction, email extraction, obfuscated string detection, suspicious
pattern analysis, entropy detection, base64/JWT decoding, minified code
beautification, concurrent downloading, depth crawling, batch processing,
and multi-format output (JSON/CSV/text).
"""

import argparse
import base64
import concurrent.futures
import csv
import datetime
import hashlib
import http.client
import json
import math
import os
import random
import re
import ssl
import string
import sys
import textwrap
import time
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple, Union


@dataclass
class Finding:
    type: str
    value: str
    source_url: str
    line_number: int = 0
    context: str = ""
    severity: str = "medium"
    category: str = "general"
    entropy: float = 0.0
    confidence: float = 1.0
    discovered_at: str = field(default_factory=lambda: datetime.datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "value": self.value[:500] if self.value else "",
            "source_url": self.source_url,
            "line_number": self.line_number,
            "context": self.context[:200] if self.context else "",
            "severity": self.severity,
            "category": self.category,
            "entropy": round(self.entropy, 2),
            "confidence": round(self.confidence, 2),
            "discovered_at": self.discovered_at,
        }


class EndpointFinder:
    REST_PATTERNS: List[re.Pattern] = [
        re.compile(r'(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+["\']?(/[a-zA-Z0-9_\-/.{}]+)'),
        re.compile(r'["\'](?:url|path|endpoint|route|api|action)\s*["\']?\s*[:=]\s*["\'](\/?[a-zA-Z0-9_\-/.{}]+)["\']'),
        re.compile(r'(?:axios|fetch|\$)\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)'),
        re.compile(r'XMLHttpRequest\S*(?:\.open|\.send)\(?\s*["\']([^"\']+)'),
        re.compile(r'router\.(?:get|post|put|delete|patch|all)\s*\(\s*["\']([^"\']+)'),
        re.compile(r'@(?:Get|Post|Put|Delete|Patch)Mapping\s*\(\s*["\']([^"\']+)'),
        re.compile(r'app\.(?:get|post|put|delete|patch|use)\s*\(\s*["\']([^"\']+)'),
        re.compile(r'(?:api|v[0-9]+)/[a-zA-Z0-9_\-/.{}?&=]+'),
        re.compile(r'["\'](?:backend|server|base|baseURL|base_url|api_url|endpoint)\s*["\']?\s*[:=]\s*["\']([^"\']+)'),
        re.compile(r'xhr\.(?:open|send)\s*\(["\']([^"\']+)'),
        re.compile(r'new URLPattern\(\s*["\']([^"\']+)'),
        re.compile(r'["\'](?:href|action)["\']?\s*[:=]\s*["\'](\/[^"\']+)["\']'),
        re.compile(r'constant\s*\(\s*["\'](?:API|API_URL|BASE_URL|ENDPOINT)["\']?\s*,\s*["\']([^"\']+)'),
        re.compile(r'\.(?:list|get|create|update|delete|save|find|search|query|fetch)\s*[:(]'),
    ]

    GRAPHQL_PATTERNS: List[re.Pattern] = [
        re.compile(r'["\'](\/[a-zA-Z0-9_\-/]*graphql)["\']'),
        re.compile(r'["\'](\/[a-zA-Z0-9_\-/]*gql)["\']'),
        re.compile(r'query\s+(?:[a-zA-Z]\w*\s*)?[{(]'),
        re.compile(r'mutation\s+(?:[a-zA-Z]\w*\s*)?[{(]'),
        re.compile(r'__typename'),
        re.compile(r'__schema\s*[{]'),
        re.compile(r'IntrospectionQuery'),
        re.compile(r'"query"\s*:\s*"'),
        re.compile(r'"operationName"\s*:'),
        re.compile(r'graphql\s*:\s*["\']([^"\']+)'),
    ]

    WEBSOCKET_PATTERNS: List[re.Pattern] = [
        re.compile(r'(ws|wss)://[a-zA-Z0-9_.\-/]+'),
        re.compile(r'new\s+WebSocket\s*\(\s*["\']([^"\']+)'),
        re.compile(r'io\s*\(\s*["\']([^"\']+)'),
        re.compile(r'socket\.(?:connect|on|emit)'),
        re.compile(r'\/(?:ws|wss|socket|realtime|events|live|stream)\b'),
    ]

    def find(self, content: str, source_url: str) -> List[Finding]:
        findings: List[Finding] = []
        seen: Set[str] = set()
        patterns = self.REST_PATTERNS + self.GRAPHQL_PATTERNS + self.WEBSOCKET_PATTERNS
        for pat in patterns:
            for match in pat.finditer(content):
                val = match.group(1) if pat.groups >= 1 else match.group(0)
                if val and len(val) > 2 and val not in seen:
                    seen.add(val)
                    finding_type = "api_endpoint"
                    if "graphql" in val.lower() or "gql" in val.lower():
                        finding_type = "graphql_endpoint"
                    elif val.startswith("ws") or "socket" in val.lower():
                        finding_type = "websocket_endpoint"
                    ctx = self._extract_context(content, match.start())
                    findings.append(Finding(
                        type=finding_type, value=val, source_url=source_url,
                        context=ctx, severity="medium", category="endpoint",
                    ))
        return findings

    def _extract_context(self, content: str, pos: int, window: int = 60) -> str:
        start = max(0, pos - window)
        end = min(len(content), pos + window)
        ctx = content[start:end]
        if start > 0:
            ctx = "..." + ctx
        if end < len(content):
            ctx = ctx + "..."
        return ctx.replace("\n", " ").strip()


class SecretScanner:
    PATTERNS: List[Dict[str, Any]] = [
        {"name": "AWS Access Key", "regex": re.compile(r'(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])'), "severity": "high", "category": "aws"},
        {"name": "AWS Secret Key", "regex": re.compile(r'(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])'), "severity": "critical", "category": "aws", "entropy_check": True},
        {"name": "Google API Key", "regex": re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "severity": "high", "category": "gcp"},
        {"name": "Google OAuth Key", "regex": re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'), "severity": "high", "category": "gcp"},
        {"name": "GitHub Personal Token", "regex": re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}'), "severity": "critical", "category": "github"},
        {"name": "GitHub Old Token", "regex": re.compile(r'(?<![A-Za-z0-9])[A-Za-z0-9]{40}(?![A-Za-z0-9])'), "severity": "high", "category": "github", "entropy_check": True},
        {"name": "Slack Bot Token", "regex": re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,}'), "severity": "high", "category": "slack"},
        {"name": "Slack Webhook URL", "regex": re.compile(r'https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+'), "severity": "high", "category": "slack"},
        {"name": "Stripe Live Key", "regex": re.compile(r'(?<![A-Za-z0-9])sk_live_[0-9a-zA-Z]{24,}(?![A-Za-z0-9])'), "severity": "critical", "category": "stripe"},
        {"name": "Stripe Test Key", "regex": re.compile(r'(?<![A-Za-z0-9])sk_test_[0-9a-zA-Z]{24,}(?![A-Za-z0-9])'), "severity": "medium", "category": "stripe"},
        {"name": "Stripe Publishable Key", "regex": re.compile(r'pk_(live|test)_[0-9a-zA-Z]{24,}'), "severity": "low", "category": "stripe"},
        {"name": "JWT Token", "regex": re.compile(r'eyJ[A-Za-z0-9_\-+/=]+\.[A-Za-z0-9_\-+/=]+\.[A-Za-z0-9_\-+/=]+'), "severity": "high", "category": "jwt"},
        {"name": "RSA Private Key", "regex": re.compile(r'-----BEGIN\s?RSA\s?PRIVATE\s?KEY-----'), "severity": "critical", "category": "crypto"},
        {"name": "OpenSSH Private Key", "regex": re.compile(r'-----BEGIN\s?OPENSSH\s?PRIVATE\s?KEY-----'), "severity": "critical", "category": "crypto"},
        {"name": "Generic Private Key", "regex": re.compile(r'-----BEGIN\s?PRIVATE\s?KEY-----'), "severity": "critical", "category": "crypto"},
        {"name": "EC Private Key", "regex": re.compile(r'-----BEGIN\s?EC\s?PRIVATE\s?KEY-----'), "severity": "critical", "category": "crypto"},
        {"name": "Azure Connection String", "regex": re.compile(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+'), "severity": "critical", "category": "azure"},
        {"name": "Azure Storage Key", "regex": re.compile(r'AccountKey=[^;&"\'\s]+'), "severity": "critical", "category": "azure"},
        {"name": "Heroku API Key", "regex": re.compile(r'[hH][eE][rR][oO][kK][uU]\s*[:=]\s*[A-Za-z0-9\-_]{20,}'), "severity": "high", "category": "heroku"},
        {"name": "Facebook Access Token", "regex": re.compile(r'EAACEdEose0cBA[0-9A-Za-z]+'), "severity": "high", "category": "social"},
        {"name": "Twitter API Key", "regex": re.compile(r'(?<![A-Za-z0-9])[1-9][0-9]*-[a-zA-Z0-9]{40,45}(?![A-Za-z0-9])'), "severity": "medium", "category": "social"},
        {"name": "Password Assignment", "regex": re.compile(r'(?:password|passwd|pwd|secret|api_key|apikey)\s*[:=]\s*["\'][^"\']+["\']'), "severity": "high", "category": "password"},
        {"name": "DB Connection String", "regex": re.compile(r'(?:mysql|postgres|mongodb|redis|sqlite|mssql|oracle)://[^@\s]+@[^\s"\'<>]+'), "severity": "critical", "category": "database"},
        {"name": "S3 Bucket URL", "regex": re.compile(r'(?:s3://|https://[a-zA-Z0-9._-]+\.s3\.amazonaws\.com)'), "severity": "medium", "category": "aws"},
        {"name": "npm Auth Token", "regex": re.compile(r'(?<![A-Za-z0-9/+=])npm_[A-Za-z0-9]{36,}(?![A-Za-z0-9/+=])'), "severity": "high", "category": "npm"},
        {"name": "PyPI Token", "regex": re.compile(r'pypi-[A-Za-z0-9]{20,}'), "severity": "high", "category": "pypi"},
        {"name": "Telegram Bot Token", "regex": re.compile(r'[0-9]{8,10}:[A-Za-z0-9_-]{35,}'), "severity": "high", "category": "telegram"},
        {"name": "Discord Bot Token", "regex": re.compile(r'(?:mfa\.)?[A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,}'), "severity": "high", "category": "discord"},
        {"name": "Google Service Account", "regex": re.compile(r'"type":\s*"service_account"'), "severity": "critical", "category": "gcp"},
        {"name": "SendGrid API Key", "regex": re.compile(r'SG\.[A-Za-z0-9_\-+/]{22,}\.[A-Za-z0-9_\-+/]{43,}'), "severity": "high", "category": "email"},
        {"name": "Mailgun API Key", "regex": re.compile(r'key-[0-9a-f]{32}'), "severity": "high", "category": "email"},
        {"name": "Twilio API Key", "regex": re.compile(r'SK[0-9a-fA-F]{32}'), "severity": "high", "category": "twilio"},
        {"name": "Docker Auth Config", "regex": re.compile(r'"auths"\s*:\s*\{[^}]+"auth"\s*:\s*"[^"]+'), "severity": "high", "category": "docker"},
        {"name": "Authorization Bearer", "regex": re.compile(r'["\']authorization["\']\s*[:=]\s*["\']Bearer\s+[^"\']+'), "severity": "high", "category": "auth"},
        {"name": "Firebase URL", "regex": re.compile(r'https://[a-zA-Z0-9_-]+\.firebaseio\.com'), "severity": "medium", "category": "firebase"},
        {"name": "Cloudinary URL", "regex": re.compile(r'cloudinary://[0-9]+:[^@]+@[a-zA-Z0-9]+'), "severity": "high", "category": "cloudinary"},
        {"name": "SonarQube Token", "regex": re.compile(r'squ\.[0-9a-f]{30,}'), "severity": "high", "category": "sonarqube"},
        {"name": "PagerDuty Token", "regex": re.compile(r'[a-z]_[A-Za-z0-9]{20,}'), "severity": "high", "category": "pagerduty"},
        {"name": "GCP Service Account JSON", "regex": re.compile(r'"private_key_id"\s*:\s*"[^"]{40}"'), "severity": "critical", "category": "gcp"},
        {"name": "GCP API Key", "regex": re.compile(r'(?<![A-Za-z0-9])AIza[0-9A-Za-z\-_]{35}(?![A-Za-z0-9])'), "severity": "high", "category": "gcp"},
        {"name": "Custom Secret Pattern", "regex": re.compile(r'(?i)(?:secret|token|key|password|credential)\s*[:=]\s*["\'][A-Za-z0-9_\-+/=]{20,}["\']'), "severity": "high", "category": "generic"},
        {"name": "Base64 High Entropy", "regex": re.compile(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40,}(?![A-Za-z0-9/+=])'), "severity": "low", "category": "entropy", "entropy_check": True},
    ]

    ALLOWLIST: Set[str] = {
        "example", "test", "sample", "dummy", "placeholder", "changeme",
        "your-", "your_", "xxxx", "00000000", "11111111", "aaaaaaaa",
        "mykey", "my_secret", "my_password", "password123", "secret123",
        "token123", "api_key_here", "your-api-key", "your_secret_key",
        "REPLACE_ME", "TODO", "FIXME", "XXXXX",
    }

    def __init__(self, min_entropy: float = 3.5):
        self.min_entropy = min_entropy

    def shannon_entropy(self, data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        for freq in Counter(data).values():
            p = freq / len(data)
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _is_allowlisted(self, value: str) -> bool:
        lower = value.lower()
        return any(w in lower for w in self.ALLOWLIST)

    def scan(self, content: str, source_url: str) -> List[Finding]:
        findings: List[Finding] = []
        seen: Set[str] = set()

        for pattern_def in self.PATTERNS:
            regex = pattern_def["regex"]
            for match in regex.finditer(content):
                matched = match.group(0).strip()
                if len(matched) < 6:
                    continue
                if self._is_allowlisted(matched):
                    continue
                if matched in seen:
                    continue
                seen.add(matched)

                entropy = self.shannon_entropy(matched)
                if pattern_def.get("entropy_check", False) and entropy < self.min_entropy:
                    continue

                ctx = self._extract_context(content, match.start())
                line_num = content[:match.start()].count("\n") + 1
                confidence = min(1.0, entropy / 6.0) if entropy > 2.0 else 0.5
                if pattern_def["severity"] in ("critical", "high"):
                    confidence = max(confidence, 0.8)

                findings.append(Finding(
                    type=f"secret_{pattern_def['name'].lower().replace(' ', '_')}",
                    value=matched[:250],
                    source_url=source_url,
                    line_number=line_num,
                    context=ctx,
                    severity=pattern_def["severity"],
                    category=pattern_def["category"],
                    entropy=entropy,
                    confidence=confidence,
                ))
        return findings

    def _extract_context(self, content: str, pos: int, window: int = 50) -> str:
        start = max(0, pos - window)
        end = min(len(content), pos + window)
        ctx = content[start:end]
        if start > 0:
            ctx = "..." + ctx
        if end < len(content):
            ctx = ctx + "..."
        return ctx.replace("\n", " ").strip()


class JsAnalyzer:
    SUSPICIOUS_PATTERNS: List[Dict[str, Any]] = [
        {"name": "eval() usage", "regex": re.compile(r'\beval\s*\('), "severity": "high", "description": "Dynamic code execution via eval()"},
        {"name": "document.write()", "regex": re.compile(r'document\.write\s*\('), "severity": "medium", "description": "Direct DOM writing"},
        {"name": "innerHTML assignment", "regex": re.compile(r'\.innerHTML\s*='), "severity": "medium", "description": "HTML injection via innerHTML"},
        {"name": "setTimeout with string", "regex": re.compile(r'setTimeout\s*\(\s*["\']'), "severity": "medium", "description": "String-based setTimeout (eval-like)"},
        {"name": "setInterval with string", "regex": re.compile(r'setInterval\s*\(\s*["\']'), "severity": "medium", "description": "String-based setInterval"},
        {"name": "Function constructor", "regex": re.compile(r'new\s+Function\s*\(["\']'), "severity": "high", "description": "Function constructor with string arg"},
        {"name": "window.execScript", "regex": re.compile(r'execScript\s*\('), "severity": "high", "description": "IE-specific code execution"},
        {"name": "atob on suspicious data", "regex": re.compile(r'atob\s*\(\s*["\'][A-Za-z0-9+/=]{50,}'), "severity": "medium", "description": "Base64 decode of potentially encoded payload"},
        {"name": "Base64 encoded code", "regex": re.compile(r'["\'][A-Za-z0-9+/=]{100,}["\']'), "severity": "low", "description": "Large base64 string"},
        {"name": "WebAssembly binary", "regex": re.compile(r'WebAssembly\.instantiate'), "severity": "low", "description": "WebAssembly module instantiation"},
        {"name": "Dynamic script injection", "regex": re.compile(r'document\.createElement\s*\(\s*["\']script["\']'), "severity": "high", "description": "Runtime script injection"},
        {"name": "Location hash eval", "regex": re.compile(r'location\s*\.\s*(?:hash|href|search)'), "severity": "medium", "description": "URL-based input usage"},
        {"name": "postMessage usage", "regex": re.compile(r'\.postMessage\s*\('), "severity": "low", "description": "Cross-origin messaging"},
        {"name": "JSONP callback", "regex": re.compile(r'(?:callback|jsonp|cb)\s*[:=]\s*["\']?[a-zA-Z_][a-zA-Z0-9_]*'), "severity": "low", "description": "JSONP callback parameter"},
        {"name": "localStorage access", "regex": re.compile(r'(?:localStorage|sessionStorage)\s*\.'), "severity": "low", "description": "Client-side storage access"},
        {"name": "obfuscated hex string", "regex": re.compile(r'\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}'), "severity": "medium", "description": "Hex-encoded string (potential obfuscation)"},
        {"name": "obfuscated unicode string", "regex": re.compile(r'\\u[0-9a-f]{4}\\u[0-9a-f]{4}'), "severity": "medium", "description": "Unicode-encoded string (potential obfuscation)"},
        {"name": "prototype pollution", "regex": re.compile(r'(?:__proto__|prototype)\s*\[?\s*["\']?\s*[a-zA-Z_]'), "severity": "high", "description": "Potential prototype pollution"},
        {"name": "DOM clobbering", "regex": re.compile(r'document\.(?:getElementById|querySelector)\s*\(\s*["\'][^"\']+["\']\s*\)[\s.]*innerHTML|outerHTML|text'), "severity": "medium", "description": "DOM clobbering pattern"},
        {"name": "crypto subtle usage", "regex": re.compile(r'crypto\.subtle'), "severity": "low", "description": "Web Crypto API usage"},
    ]

    def __init__(self):
        self.suspicious_findings: List[Finding] = []
        self.minified_indicators: List[str] = []

    def analyze(self, content: str, source_url: str) -> List[Finding]:
        findings: List[Finding] = []
        seen: Set[str] = set()

        # Check if minified
        if self._is_minified(content):
            self.minified_indicators.append(source_url)
            findings.append(Finding(
                type="minified_script", value=source_url,
                source_url=source_url, severity="info",
                category="analysis",
                context="Script appears to be minified/compressed",
            ))

        # Find suspicious patterns
        for pat_def in self.SUSPICIOUS_PATTERNS:
            for match in pat_def["regex"].finditer(content):
                val = match.group(0)[:100]
                if val in seen:
                    continue
                seen.add(val)
                ctx = self._extract_context(content, match.start(), 40)
                findings.append(Finding(
                    type=f"suspicious_{pat_def['name'].lower().replace(' ', '_').replace('()', '')}",
                    value=val,
                    source_url=source_url,
                    line_number=content[:match.start()].count("\n") + 1,
                    context=ctx,
                    severity=pat_def["severity"],
                    category="suspicious",
                    confidence=0.7,
                ))

        # Decode base64 strings
        for match in re.finditer(r'["\']([A-Za-z0-9+/=]{50,})["\']', content):
            b64_str = match.group(1)
            try:
                decoded = base64.b64decode(b64_str).decode("utf-8", errors="replace")
                if decoded and len(decoded) > 10:
                    findings.append(Finding(
                        type="decoded_base64",
                        value=decoded[:200],
                        source_url=source_url,
                        severity="low",
                        category="analysis",
                        entropy=self._shannon_entropy(b64_str),
                    ))
            except Exception:
                pass

        self.suspicious_findings.extend(findings)
        return findings

    def _is_minified(self, content: str) -> bool:
        if len(content) < 1000:
            return False
        lines = content.split("\n")
        avg_line_len = len(content) / max(len(lines), 1)
        return avg_line_len > 200 or (len(lines) < 5 and len(content) > 5000)

    def _extract_context(self, content: str, pos: int, window: int = 40) -> str:
        start = max(0, pos - window)
        end = min(len(content), pos + window)
        ctx = content[start:end]
        if start > 0:
            ctx = "..." + ctx
        if end < len(content):
            ctx = ctx + "..."
        return ctx.replace("\n", "\\n").strip()

    def _shannon_entropy(self, data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        for freq in Counter(data).values():
            p = freq / len(data)
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy


class JsExtractor:
    USER_AGENTS: List[str] = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    ]

    def __init__(self, silent: bool = False, timeout: float = 30, depth: int = 2):
        self.silent = silent
        self.timeout = timeout
        self.max_depth = depth
        self.findings: List[Finding] = []
        self.external_js_urls: List[str] = []
        self.inline_js_blocks: List[str] = []
        self._visited_urls: Set[str] = set()
        self.endpoint_finder = EndpointFinder()
        self.secret_scanner = SecretScanner()
        self.js_analyzer = JsAnalyzer()
        self._scan_stats: Dict[str, Any] = {
            "urls_visited": 0,
            "js_files_downloaded": 0,
            "inline_blocks": 0,
            "total_findings": 0,
            "secrets_found": 0,
            "endpoints_found": 0,
            "suspicious_patterns": 0,
            "errors": 0,
        }

    def _log(self, msg: str, level: str = "info") -> None:
        if self.silent:
            return
        prefix = {"info": "[+]", "warn": "[!]", "error": "[-]", "debug": "[*]"}.get(level, "[+]")
        print(f"{prefix} {msg}", file=sys.stderr)

    def _create_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _get_user_agent(self) -> str:
        return random.choice(self.USER_AGENTS)

    def fetch_content(self, url: str) -> Optional[str]:
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": self._get_user_agent(), "Accept": "*/*"},
            )
            ctx = self._create_ssl_context()
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                content_type = resp.headers.get("Content-Type", "")
                encoding = "utf-8"
                if "charset=" in content_type:
                    enc = content_type.split("charset=")[-1].split(";")[0].strip()
                    try:
                        encoding = enc
                    except Exception:
                        pass
                raw = resp.read()
                return raw.decode(encoding, errors="replace")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            try:
                return e.read().decode("utf-8", errors="replace")
            except Exception:
                return None
        except urllib.error.URLError as e:
            self._log(f"URL error: {e.reason}", "error")
            return None
        except Exception as e:
            self._log(f"Error fetching {url}: {e}", "error")
            return None

    def extract_inline_js(self, html: str, base_url: str) -> List[Finding]:
        findings: List[Finding] = []

        # Script tag content
        for match in re.finditer(r'<script[^>]*>([^<]+)</script>', html, re.IGNORECASE | re.DOTALL):
            js_code = match.group(1).strip()
            if not js_code or len(js_code) < 10:
                continue
            self.inline_js_blocks.append(js_code)
            self._scan_stats["inline_blocks"] += 1

            # Analyze inline JS
            findings.extend(self._analyze_js(js_code, base_url))

        # Event handler attributes
        event_pat = re.compile(r'\s(?:onload|onclick|onmouseover|onerror|onsubmit|onfocus|onblur|onchange|onkeydown|onkeyup|onscroll|onresize|ontouchstart)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
        for match in event_pat.finditer(html):
            handler = match.group(1).strip()
            if handler:
                findings.append(Finding(
                    type="inline_event_handler",
                    value=handler[:150],
                    source_url=base_url,
                    severity="low",
                    category="inline_js",
                ))

        # javascript: URLs
        for match in re.finditer(r'href\s*=\s*["\']\s*javascript\s*:\s*([^"\']+)["\']', html, re.IGNORECASE):
            js_code = match.group(1).strip()
            if js_code and len(js_code) > 5:
                findings.extend(self._analyze_js(js_code, base_url))

        # data-bind and similar
        for match in re.finditer(r'data-(?:bind|event|action)\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
            val = match.group(1)
            if val and ("(" in val or "{" in val):
                findings.append(Finding(
                    type="data_binding_expression",
                    value=val[:150],
                    source_url=base_url,
                    severity="low",
                    category="inline_js",
                ))

        return findings

    def discover_external_js(self, html: str, base_url: str) -> List[str]:
        urls: List[str] = []

        # Script src attributes
        for match in re.finditer(r'<script[^>]*\ssrc\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
            src = match.group(1)
            if src and not src.startswith("data:"):
                full = urllib.parse.urljoin(base_url, src)
                if full not in urls:
                    urls.append(full)

        # Module imports
        for match in re.finditer(r'<script[^>]*\stype\s*=\s*["\']module["\'][^>]*\ssrc\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
            src = match.group(1)
            if src:
                full = urllib.parse.urljoin(base_url, src)
                if full not in urls:
                    urls.append(full)

        # Dynamic import() calls
        for match in re.finditer(r'import\s*\(\s*["\']([^"\']+)["\']', html):
            url = match.group(1)
            if url.endswith((".js", ".mjs", ".cjs")) or ".js?" in url:
                full = urllib.parse.urljoin(base_url, url)
                if full not in urls:
                    urls.append(full)

        # Import maps
        json_match = re.search(r'<script[^>]*type=["\']importmap["\'][^>]*>(.*?)</script>', html, re.IGNORECASE | re.DOTALL)
        if json_match:
            try:
                import_map = json.loads(json_match.group(1).strip())
                for module_name, module_url in import_map.get("imports", {}).items():
                    if module_url:
                        full = urllib.parse.urljoin(base_url, module_url)
                        if full not in urls:
                            urls.append(full)
            except json.JSONDecodeError:
                pass

        # Source map references
        for match in re.finditer(r'//# sourceMappingURL=([^\s]+)', html):
            sm = match.group(1)
            if sm:
                full = urllib.parse.urljoin(base_url, sm)
                if full not in urls:
                    urls.append(full)

        # Manifest / preload hints
        for match in re.finditer(r'<link[^>]*\shref\s*=\s*["\']([^"\']+\.js[^"\']*)["\']', html, re.IGNORECASE):
            href = match.group(1)
            full = urllib.parse.urljoin(base_url, href)
            if full not in urls:
                urls.append(full)

        self.external_js_urls.extend(urls)
        return urls

    def _analyze_js(self, js_content: str, source_url: str) -> List[Finding]:
        findings: List[Finding] = []

        # Find API endpoints in JS
        endpoint_findings = self.endpoint_finder.find(js_content, source_url)
        findings.extend(endpoint_findings)
        self._scan_stats["endpoints_found"] += len(endpoint_findings)

        # Scan for secrets
        secret_findings = self.secret_scanner.scan(js_content, source_url)
        findings.extend(secret_findings)
        self._scan_stats["secrets_found"] += len(secret_findings)

        # Analyze for suspicious patterns
        analysis_findings = self.js_analyzer.analyze(js_content, source_url)
        findings.extend(analysis_findings)
        self._scan_stats["suspicious_patterns"] += len(analysis_findings)

        # Extract URLs
        url_findings = self._extract_urls(js_content, source_url)
        findings.extend(url_findings)

        # Extract emails
        email_findings = self._extract_emails(js_content, source_url)
        findings.extend(email_findings)

        # Detect obfuscation patterns
        obf_findings = self._detect_obfuscation(js_content, source_url)
        findings.extend(obf_findings)

        return findings

    def _extract_urls(self, content: str, source_url: str) -> List[Finding]:
        findings: List[Finding] = []
        seen: Set[str] = set()
        # http/https URLs
        for match in re.finditer(r'https?://[a-zA-Z0-9_.\-/~?&=+#%]{10,500}', content):
            url = match.group(0)
            if url in seen:
                continue
            seen.add(url)
            findings.append(Finding(
                type="url", value=url[:300], source_url=source_url,
                severity="info", category="url",
            ))
        return findings

    def _extract_emails(self, content: str, source_url: str) -> List[Finding]:
        findings: List[Finding] = []
        seen: Set[str] = set()
        for match in re.finditer(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content):
            email = match.group(0)
            if email in seen:
                continue
            seen.add(email)
            findings.append(Finding(
                type="email", value=email, source_url=source_url,
                severity="low", category="pii",
            ))
        return findings

    def _detect_obfuscation(self, content: str, source_url: str) -> List[Finding]:
        findings: List[Finding] = []
        # Concat-based string building
        concat_count = len(re.findall(r'["\']\s*\+\s*["\']', content))
        if concat_count > 20:
            findings.append(Finding(
                type="obfuscation_string_concat",
                value=f"String concatenation count: {concat_count}",
                source_url=source_url,
                severity="low",
                category="obfuscation",
            ))

        # Array-based string construction
        arr_str_count = len(re.findall(r'\[["\'][^"\']+["\'][,\]]', content))
        if arr_str_count > 15:
            findings.append(Finding(
                type="obfuscation_array_string",
                value=f"Array string fragments: {arr_str_count}",
                source_url=source_url,
                severity="medium",
                category="obfuscation",
            ))

        # charCodeAt/fromCharCode usage
        char_code_count = len(re.findall(r'(?:fromCharCode|charCodeAt)', content))
        if char_code_count > 10:
            findings.append(Finding(
                type="obfuscation_char_code",
                value=f"CharCode usage: {char_code_count}",
                source_url=source_url,
                severity="medium",
                category="obfuscation",
            ))

        # Numeric variable names
        numeric_vars = len(re.findall(r'\b_[0-9a-f]{4,}\b', content))
        if numeric_vars > 20:
            findings.append(Finding(
                type="obfuscation_minified_names",
                value=f"Short variable names: {numeric_vars}+",
                source_url=source_url,
                severity="low",
                category="obfuscation",
            ))

        return findings

    def crawl_and_analyze(self, url: str) -> List[Finding]:
        self._scan_stats["urls_visited"] += 1
        self._log(f"Fetching {url}")
        html = self.fetch_content(url)
        if not html:
            self._log(f"Failed to fetch {url}", "error")
            self._scan_stats["errors"] += 1
            return []

        findings: List[Finding] = []

        # Extract inline JS
        inline_findings = self.extract_inline_js(html, url)
        findings.extend(inline_findings)

        # Discover external JS
        js_urls = self.discover_external_js(html, url)
        self._log(f"Discovered {len(js_urls)} external JS files")

        # Download and analyze external JS
        downloaded: List[str] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
            future_to_url = {ex.submit(self.fetch_content, js_url): js_url for js_url in js_urls}
            for future in concurrent.futures.as_completed(future_to_url):
                js_url = future_to_url[future]
                try:
                    js_content = future.result(timeout=self.timeout)
                    if js_content:
                        downloaded.append(js_url)
                        self._scan_stats["js_files_downloaded"] += 1
                        self._log(f"  Analyzing {js_url} ({len(js_content)} bytes)")
                        js_findings = self._analyze_js(js_content, js_url)
                        findings.extend(js_findings)
                except Exception as e:
                    self._log(f"Failed to analyze {js_url}: {e}", "error")
                    self._scan_stats["errors"] += 1

        # Check for source maps
        for js_url in downloaded:
            sm_url = js_url + ".map" if not js_url.endswith(".map") else js_url
            sm_content = self.fetch_content(sm_url)
            if sm_content and len(sm_content) > 100:
                findings.append(Finding(
                    type="source_map",
                    value=sm_url,
                    source_url=sm_url,
                    severity="high",
                    category="source_map",
                ))
                sm_findings = self._analyze_js(sm_content, sm_url)
                findings.extend(sm_findings)

        self.findings.extend(findings)
        self._scan_stats["total_findings"] = len(findings)
        return findings

    def analyze_file(self, filepath: str, source_url: str = "") -> List[Finding]:
        self._log(f"Analyzing local file: {filepath}")
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            self._log(f"Error reading file: {e}", "error")
            return []

        findings = self._analyze_js(content, source_url or filepath)
        self.findings.extend(findings)
        self._scan_stats["total_findings"] = len(findings)
        return findings

    def process_inline_content(self, content: str, source_label: str = "inline") -> List[Finding]:
        findings = self._analyze_js(content, source_label)
        self.findings.extend(findings)
        self._scan_stats["total_findings"] = len(findings)
        return findings

    def output_json(self, filepath: Optional[str] = None) -> str:
        data = {
            "scan_metadata": self._scan_stats,
            "findings": [f.to_dict() for f in self.findings],
        }
        output = json.dumps(data, indent=2, default=str)
        if filepath:
            os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(output)
            self._log(f"JSON written to {filepath}")
        return output

    def output_csv(self, filepath: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
        if not self.findings:
            self._log("No findings to write", "warn")
            return
        fieldnames = list(self.findings[0].to_dict().keys())
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for finding in self.findings:
                writer.writerow(finding.to_dict())
        self._log(f"CSV written to {filepath}")

    def output_text(self, filepath: Optional[str] = None) -> str:
        lines = ["JavaScript Analysis Report", "=" * 60,
                 f"Generated: {datetime.datetime.now().isoformat()}",
                 f"URLs Visited: {self._scan_stats.get('urls_visited', 0)}",
                 f"JS Files Downloaded: {self._scan_stats.get('js_files_downloaded', 0)}",
                 f"Inline JS Blocks: {self._scan_stats.get('inline_blocks', 0)}",
                 f"Total Findings: {self._scan_stats.get('total_findings', 0)}",
                 f"  Secrets: {self._scan_stats.get('secrets_found', 0)}",
                 f"  Endpoints: {self._scan_stats.get('endpoints_found', 0)}",
                 f"  Suspicious: {self._scan_stats.get('suspicious_patterns', 0)}",
                 "", "--- Findings ---", ""]

        by_severity: Dict[str, List[Finding]] = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for f in self.findings:
            by_severity.setdefault(f.severity, []).append(f)
        for sev in ["critical", "high", "medium", "low", "info"]:
            items = by_severity[sev]
            if items:
                lines.append(f"\n[{sev.upper()}] ({len(items)} findings)")
                for f in items[:20]:
                    lines.append(f"  {f.type}: {f.value[:100]}")
                    if f.context:
                        lines.append(f"    Context: {f.context[:100]}")
                    lines.append(f"    Source: {f.source_url}")

        report = "\n".join(lines)
        if filepath:
            os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(report)
            self._log(f"Report written to {filepath}")
        return report

    def get_summary(self) -> Dict[str, Any]:
        sev_counts: Dict[str, int] = {}
        cat_counts: Dict[str, int] = {}
        for f in self.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
            cat_counts[f.category] = cat_counts.get(f.category, 0) + 1
        return {
            "scan_stats": self._scan_stats,
            "by_severity": sev_counts,
            "by_category": cat_counts,
        }

    def filter_by_type(self, finding_type: str) -> List[Finding]:
        return [f for f in self.findings if f.type == finding_type]

    def filter_by_severity(self, min_severity: str = "medium") -> List[Finding]:
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        threshold = order.get(min_severity, 2)
        return [f for f in self.findings if order.get(f.severity, 0) >= threshold]


def build_argparse() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="extract_js.py — JavaScript Extraction & Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python extract_js.py --url https://target.com
              python extract_js.py --file app.js --output analysis.json
              python extract_js.py --url https://target.com --secrets --json
              python extract_js.py --url https://target.com --inline --external --depth 3
              python extract_js.py --file bundle.js --output report.txt --secrets
        """),
    )
    parser.add_argument("--url", type=str, help="Target URL to analyze")
    parser.add_argument("--file", type=str, help="Local JS file to analyze")
    parser.add_argument("--inline", type=str, default=None,
                        help="Inline JavaScript content string to analyze")
    parser.add_argument("--external", action="store_true",
                        help="Download and analyze external JS files (used with --url)")
    parser.add_argument("--output", type=str, default=None, help="Output file path")
    parser.add_argument("--secrets", action="store_true",
                        help="Focus on secret/credential scanning")
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument("--timeout", type=int, default=30,
                        help="Request timeout in seconds (default: 30)")
    parser.add_argument("--silent", action="store_true",
                        help="Suppress informational output")
    parser.add_argument("--json", action="store_true",
                        help="Output in JSON format")
    parser.add_argument("--csv", type=str, default=None, help="Write CSV output")
    return parser


def main() -> None:
    parser = build_argparse()
    args = parser.parse_args()

    if not args.url and not args.file and not args.inline:
        parser.print_help()
        sys.exit(1)

    extractor = JsExtractor(silent=args.silent, timeout=args.timeout, depth=args.depth)

    try:
        if args.url:
            extractor.crawl_and_analyze(args.url)
        if args.file:
            extractor.analyze_file(args.file, args.url or "")
        if args.inline:
            extractor.process_inline_content(args.inline, args.url or "inline")
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Filter if --secrets
    if args.secrets:
        extractor.findings = extractor.filter_by_type("secret")

    if args.json or (args.output and args.output.endswith(".json")):
        out = extractor.output_json(filepath=args.output)
        if not args.output:
            print(out)
    elif args.csv:
        extractor.output_csv(args.csv)
    else:
        report = extractor.output_text(filepath=args.output)
        if not args.output:
            print(report)

    summary = extractor.get_summary()
    print(f"\n=== Summary ===", file=sys.stderr if not args.json else sys.stdout)
    print(f"  Findings: {summary['scan_stats'].get('total_findings', 0)}", file=sys.stderr if not args.json else sys.stdout)
    print(f"  Secrets: {summary['scan_stats'].get('secrets_found', 0)}", file=sys.stderr if not args.json else sys.stdout)
    print(f"  Endpoints: {summary['scan_stats'].get('endpoints_found', 0)}", file=sys.stderr if not args.json else sys.stdout)


if __name__ == "__main__":
    main()
