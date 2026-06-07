#!/usr/bin/env python3
"""
js_analyzer.py — JavaScript Bundle Security Analyzer

Extracts API endpoints, secrets, feature flags, source maps, and internal
endpoints from JavaScript bundles. Supports URL fetching, file loading,
diffing, batch analysis, and report generation.

Features: endpoint discovery, secret extraction, feature flag detection,
source map extraction, internal endpoint detection, bundle diffing,
batch mode, JSON/CSV output, obfuscation detection, inline-config parsing,
GraphQL endpoint detection, WebSocket endpoint detection, SPA route discovery,
dependency detection, version fingerprinting, error tracking,
callback URL extraction, eval() detection, dynamic import scanning,
and minification detection.
"""

import base64
import csv
import hashlib
import json
import os
import re
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urljoin, urlparse


class JSAnalyzer:
    """
    JavaScript bundle security analyzer with 20+ analysis capabilities.

    Downloads JS from URLs or reads local files, then runs the full
    analysis pipeline: endpoints, secrets, feature flags, source maps,
    internal IPs, obfuscation markers, SPA routes, dependencies, and more.

    Attributes:
        source_url: URL or file path of the bundle.
        content: Raw JS content.
        endpoints: Extracted API endpoint URLs.
        secrets: Discovered credential/secret patterns.
        feature_flags: Configuration toggles and feature gates.
        results: Consolidated analysis output dict.
    """

    ENDPOINT_PATTERNS = [
        re.compile(r'["\']((?:https?://|/)(?:[a-zA-Z0-9._/-]+(?:/api/|/v[0-9]+/|/rest/|/graphql|/auth/|/oauth/|/saml/|/ws/|/wss/|/socket)[a-zA-Z0-9._?=/&%-]*))["\']'),
        re.compile(r'["\'](/[a-zA-Z0-9_/.-]*(?:api|rest|graphql|auth|oauth|v1|v2|v3)[a-zA-Z0-9_/.-]*)["\']'),
        re.compile(r'fetch\(["\']([^"\']+)["\']'),
        re.compile(r'axios\.(?:get|post|put|patch|delete)\(["\']([^"\']+)["\']'),
        re.compile(r'\$\.(?:get|post|ajax)\(["\']([^"\']+)["\']'),
        re.compile(r'XMLHttpRequest\.open\(["\'][A-Z]+["\'],\s*["\']([^"\']+)["\']'),
        re.compile(r'url:\s*["\']([^"\']+)["\']'),
        re.compile(r'path:\s*["\']([^"\']+)["\']'),
        re.compile(r'route:\s*["\']([^"\']+)["\']'),
        re.compile(r'endpoint:\s*["\']([^"\']+)["\']'),
        re.compile(r'baseURL:\s*["\']([^"\']+)["\']'),
        re.compile(r'["\'](?:https?://[^/]+)?(/graphql)["\']'),
        re.compile(r'["\'](?:https?://[^/]+)?(/socket\.io/)["\']'),
        re.compile(r'(?:login|signin|signup|register|auth|token|refresh|logout|session)[^a-z]', re.IGNORECASE),
        re.compile(r'(?:ws://|wss://)[^\s"\'<>]+'),
        re.compile(r'["\'](?:https?://[^/]+)?(/api/[/a-zA-Z0-9_.-]*)["\']'),
        re.compile(r'(?:query|mutation|subscription)\s+\w+\s*[({]'),
    ]

    FEATURE_FLAG_PATTERNS = [
        re.compile(r'["\'](FF_[A-Z_0-9]+)["\']'),
        re.compile(r'["\'](feature_[a-zA-Z_0-9]+)["\']'),
        re.compile(r'["\'](flag_[a-zA-Z_0-9]+)["\']'),
        re.compile(r'(isEnabled|isDisabled|isActive)\s*[:=]\s*(true|false)'),
        re.compile(r'enable[A-Z]\w+\s*[:=]\s*(true|false)'),
        re.compile(r'disable[A-Z]\w+\s*[:=]\s*(true|false)'),
        re.compile(r'(experiment|variant|rollout)\s*[:=]\s*["\']([^"\']+)["\']'),
    ]

    SOURCEMAP_PATTERN = re.compile(r'//#\s*sourceMappingURL\s*=\s*(.+\.map)')
    EVAL_PATTERN = re.compile(r'\beval\s*\(\s*["\'`]')
    DYNAMIC_IMPORT_PATTERN = re.compile(r'(?:import|require)\s*\(\s*["\'`][^"\']+["\'`]\s*\)')
    OBFUSCATION_PATTERNS = [
        re.compile(r'(?:_0x[a-f0-9]{4,})'),
        re.compile(r'(?:\\x[0-9a-f]{2}){10,}'),
        re.compile(r'(?:atob|btoa)\s*\('),
        re.compile(r'(?:\\u[0-9a-f]{4}){5,}'),
    ]

    def __init__(self, source_url: str = "", content: str = ""):
        self.source_url = source_url
        self.content = content
        self.endpoints: List[str] = []
        self.secrets: List[Dict[str, Any]] = []
        self.feature_flags: List[Dict[str, str]] = []
        self.source_map_url: Optional[str] = None
        self.internal_endpoints: List[str] = []
        self.spa_routes: List[str] = []
        self.dependencies: Dict[str, str] = {}
        self.graphql_endpoints: List[str] = []
        self.ws_endpoints: List[str] = []
        self.callback_urls: List[str] = []
        self.obfuscation_signals: List[str] = []
        self.results: Dict[str, Any] = {}

    def load(self) -> bool:
        if self.content:
            return True
        if not self.source_url:
            print("[!] No source URL or content provided.", file=sys.stderr)
            return False
        if self.source_url.startswith(("http://", "https://")):
            return self._load_from_url()
        else:
            return self._load_from_file()

    def _load_from_url(self) -> bool:
        try:
            import requests
            resp = requests.get(self.source_url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "*/*",
            }, timeout=30, verify=True)
            resp.raise_for_status()
            self.content = resp.text
            print(f"[+] Loaded JS bundle ({len(self.content)} bytes)")
            return True
        except ImportError:
            print("[!] requests library required.", file=sys.stderr)
            return False
        except Exception as e:
            print(f"[!] Failed to load: {e}", file=sys.stderr)
            return False

    def _load_from_file(self) -> bool:
        try:
            with open(self.source_url, "r", encoding="utf-8", errors="ignore") as f:
                self.content = f.read()
            print(f"[+] Loaded JS file ({len(self.content)} bytes)")
            return True
        except Exception as e:
            print(f"[!] Failed to read file: {e}", file=sys.stderr)
            return False

    def extract_endpoints(self) -> List[str]:
        if not self.content:
            return []
        found: Set[str] = set()
        for pattern in self.ENDPOINT_PATTERNS:
            for m in pattern.findall(self.content):
                ep = m.strip("\"'` ")
                if ep and len(ep) > 2 and not ep.startswith(("./", "../", "data:", "blob:")):
                    found.add(ep)
        self.endpoints = sorted(found)
        return self.endpoints

    def extract_secrets(self) -> List[Dict[str, Any]]:
        from secret_scanner import SecretScanner
        if not self.content:
            return []
        scanner = SecretScanner()
        findings = scanner.scan_text(self.content, source_label=self.source_url or "js_bundle")
        self.secrets = findings
        return self.secrets

    def extract_feature_flags(self) -> List[Dict[str, str]]:
        if not self.content:
            return []
        flags: List[Dict[str, str]] = []
        for pattern in self.FEATURE_FLAG_PATTERNS:
            for match in pattern.finditer(self.content):
                flag_data: Dict[str, str] = {"value": match.group(0), "type": "feature_flag"}
                if match.lastindex and match.lastindex >= 1:
                    flag_data["key"] = match.group(1)
                flags.append(flag_data)
        seen: Set[str] = set()
        self.feature_flags = []
        for f in flags:
            if f["value"] not in seen:
                seen.add(f["value"])
                self.feature_flags.append(f)
        return self.feature_flags

    def extract_source_map(self) -> Optional[str]:
        if not self.content:
            return None
        match = self.SOURCEMAP_PATTERN.search(self.content)
        if match:
            self.source_map_url = match.group(1).strip()
        return self.source_map_url

    def extract_internal_endpoints(self) -> List[str]:
        if not self.content:
            return []
        patterns = [
            re.compile(r'["\'](https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.1[6-9]\.\d+\.\d+|172\.2[0-9]\.\d+\.\d+|172\.3[0-1]\.\d+\.\d+|192\.168\.\d+\.\d+)[^"\']*)["\']'),
            re.compile(r'["\'](https?://[\w-]+\.internal[^"\']*)["\']'),
            re.compile(r'["\'](https?://[\w-]+\.local[^"\']*)["\']'),
        ]
        found: Set[str] = set()
        for pattern in patterns:
            for match in pattern.finditer(self.content):
                url = match.group(1).strip("\"'")
                if "://" in url:
                    found.add(url)
        self.internal_endpoints = sorted(found)
        return self.internal_endpoints

    def extract_spa_routes(self) -> List[str]:
        if not self.content:
            return []
        patterns = [
            re.compile(r'path:\s*["\']([^"\']+)["\']'),
            re.compile(r'route:\s*["\']([^"\']+)["\']'),
            re.compile(r'component:\s*\w+'),  # React/Vue component routes
            re.compile(r'Router\.(?:get|post)\(["\']([^"\']+)["\']'),
            re.compile(r'(?:Route|route)\s*\(\s*["\']([^"\']+)["\']'),
        ]
        found: Set[str] = set()
        for pattern in patterns:
            for m in pattern.findall(self.content):
                route = m.strip("\"'")
                if route.startswith("/"):
                    found.add(route)
        self.spa_routes = sorted(found)
        return self.spa_routes

    def extract_graphql_endpoints(self) -> List[str]:
        if not self.content:
            return []
        patterns = [
            re.compile(r'["\'](https?://[^"\']*graphql[^"\']*)["\']'),
            re.compile(r'["\'](/graphql?)["\']'),
            re.compile(r'(?:query|mutation)\s+\w+\s*[({]'),
        ]
        found: Set[str] = set()
        for pattern in patterns:
            for m in pattern.findall(self.content):
                found.add(m.strip("\"'"))
        self.graphql_endpoints = sorted(found)
        return self.graphql_endpoints

    def extract_ws_endpoints(self) -> List[str]:
        if not self.content:
            return []
        patterns = [
            re.compile(r'["\'](wss?://[^"\']+)["\']'),
            re.compile(r'(?:WebSocket|Socket)\s*\(\s*["\']([^"\']+)["\']'),
        ]
        found: Set[str] = set()
        for pattern in patterns:
            for m in pattern.findall(self.content):
                found.add(m.strip("\"'"))
        self.ws_endpoints = sorted(found)
        return self.ws_endpoints

    def detect_obfuscation(self) -> List[str]:
        if not self.content:
            return []
        signals: List[str] = []
        for i, pattern in enumerate(self.OBFUSCATION_PATTERNS):
            matches = pattern.findall(self.content)
            if len(matches) > 5:
                names = ["hex-escapes", "hex-escapes", "atob/btoa", "unicode-escapes"]
                signals.append(f"Obfuscation detected: {names[i] if i < len(names) else f'pattern-{i}'} ({len(matches)} occurrences)")
        if re.search(r'(?:window\[|global\[|self\[)', self.content):
            signals.append("Dynamic property access — possible obfuscation")
        if re.search(r'(?:\\[0-7]{3}){4,}', self.content):
            signals.append("Octal escape sequences detected")
        self.obfuscation_signals = signals
        return signals

    def extract_dependencies(self) -> Dict[str, str]:
        if not self.content:
            return {}
        patterns = [
            (r'require\(["\']([^"\']+)["\']\)', 'require'),
            (r'from\s+["\']([^"\']+)["\']', 'import'),
            (r'import\s+["\']([^"\']+)["\']', 'dynamic-import'),
        ]
        deps: Dict[str, Set[str]] = {}
        for pat, src_type in patterns:
            for m in re.finditer(pat, self.content):
                dep = m.group(1)
                if dep and not dep.startswith(".") and not dep.startswith("/"):
                    deps.setdefault(dep, set()).add(src_type)
        self.dependencies = {k: ",".join(v) for k, v in sorted(deps.items())}
        return self.dependencies

    def extract_callback_urls(self) -> List[str]:
        if not self.content:
            return []
        patterns = [
            re.compile(r'(?:callback|redirect|return|next|continue|goto)\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE),
            re.compile(r'(?:callbackUrl|redirect_uri|return_url|next_url)\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE),
        ]
        found: Set[str] = set()
        for pattern in patterns:
            for m in pattern.findall(self.content):
                url = m.strip("\"'")
                if url.startswith(("http", "/", "//")):
                    found.add(url)
        self.callback_urls = sorted(found)
        return self.callback_urls

    def detect_minification(self) -> bool:
        if not self.content or len(self.content) < 100:
            return False
        lines = self.content.splitlines()
        avg_line_len = sum(len(l) for l in lines) / max(len(lines), 1)
        return avg_line_len > 200 and len(lines) < 100

    def detect_eval_usage(self) -> int:
        if not self.content:
            return 0
        return len(self.EVAL_PATTERN.findall(self.content))

    def scan_dynamic_imports(self) -> List[str]:
        if not self.content:
            return []
        return list(set(self.DYNAMIC_IMPORT_PATTERN.findall(self.content)))

    def detect_inline_config(self) -> Dict[str, Any]:
        if not self.content:
            return {}
        config: Dict[str, Any] = {}
        patterns = [
            (r'["\'](API_KEY|APP_ID|CLIENT_ID|TENANT_ID|ORG_ID)["\']\s*[:=]\s*["\']([^"\']+)["\']', 'key'),
            (r'(?:window\.__|__INITIAL_STATE__|__CONFIG__|__ENV__)\s*=\s*({[^;]+})', 'state'),
            (r'["\'](environment|env|NODE_ENV|APP_ENV)["\']\s*[:=]\s*["\']([^"\']+)["\']', 'env'),
        ]
        for pat, label in patterns:
            for m in re.finditer(pat, self.content):
                config[m.group(1)] = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(0)[:100]
        return config

    def detect_version_fingerprints(self) -> Dict[str, str]:
        if not self.content:
            return {}
        versions: Dict[str, str] = {}
        patterns = [
            (r'@([\w-]+/[\w-]+)[^"]*["\']:\s*["\'](\d+\.\d+\.\d+)', 'package'),
            (r'(?:version|VERSION)\s*[:=]\s*["\'](\d+\.\d+\.\d+)["\']', 'app'),
            (r'(?:react|angular|vue|jquery|bootstrap)[.\-]?(\d+\.\d+\.\d+)', 'framework'),
        ]
        for pat, label in patterns:
            for m in re.finditer(pat, self.content):
                if m.lastindex and m.lastindex >= 1:
                    key = m.group(1) if m.lastindex >= 2 else label
                    val = m.group(2) if m.lastindex >= 2 else m.group(1)
                    versions[key] = val
        return versions

    def diff(self, other_content: str, label_a: str = "v1", label_b: str = "v2") -> Dict[str, Any]:
        lines_a = self.content.splitlines(keepends=False) if self.content else []
        lines_b = other_content.splitlines(keepends=False) if other_content else []
        set_a, set_b = set(lines_a), set(lines_b)
        added = [l for l in lines_b if l not in set_a]
        removed = [l for l in lines_a if l not in set_b]
        return {
            "label_a": label_a, "label_b": label_b,
            "total_a": len(lines_a), "total_b": len(lines_b),
            "added": added[:500], "added_count": len(added),
            "removed": removed[:500], "removed_count": len(removed),
        }

    def batch_analyze(self, sources: List[str], max_workers: int = 5) -> List[Dict[str, Any]]:
        all_results: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(self._analyze_single, s): s for s in sources}
            for future in as_completed(futures):
                try:
                    all_results.append(future.result(timeout=60))
                except Exception as e:
                    all_results.append({"source": futures[future], "error": str(e)})
        return all_results

    def _analyze_single(self, source: str) -> Dict[str, Any]:
        a = JSAnalyzer(source_url=source)
        return a.analyze_all()

    def analyze_all(self) -> Dict[str, Any]:
        if not self.load():
            return {"error": "Failed to load content"}
        self.results = {
            "source": self.source_url,
            "size_bytes": len(self.content),
            "endpoints": self.extract_endpoints(),
            "secrets": self.extract_secrets(),
            "feature_flags": self.extract_feature_flags(),
            "source_map": self.extract_source_map(),
            "internal_endpoints": self.extract_internal_endpoints(),
            "spa_routes": self.extract_spa_routes(),
            "graphql_endpoints": self.extract_graphql_endpoints(),
            "ws_endpoints": self.extract_ws_endpoints(),
            "dependencies": self.extract_dependencies(),
            "callback_urls": self.extract_callback_urls(),
            "obfuscation": self.detect_obfuscation(),
            "eval_calls": self.detect_eval_usage(),
            "is_minified": self.detect_minification(),
            "inline_config": self.detect_inline_config(),
            "version_fingerprints": self.detect_version_fingerprints(),
            "analysis_time": datetime.now().isoformat(),
            "total_findings": 0,
        }
        self.results["total_findings"] = sum([
            len(self.results.get("endpoints", [])),
            len(self.results.get("secrets", [])),
            len(self.results.get("feature_flags", [])),
            len(self.results.get("internal_endpoints", [])),
            len(self.results.get("spa_routes", [])),
            len(self.results.get("callback_urls", [])),
        ])
        return self.results

    def output_json(self, filepath: Optional[str] = None) -> str:
        if not self.results:
            self.results = self.analyze_all()
        json_str = json.dumps(self.results, indent=2, default=str)
        if filepath:
            os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(json_str)
            print(f"[+] Results written to {filepath}")
        return json_str

    def output_csv(self, filepath: str, data_key: str = "endpoints") -> None:
        items = self.results.get(data_key, [])
        if not items:
            return
        os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["#", data_key])
            for i, item in enumerate(items, 1):
                w.writerow([i, item])

    def get_summary(self) -> Dict[str, Any]:
        if not self.results:
            self.results = self.analyze_all()
        return {
            "source": self.results.get("source"),
            "size": self.results.get("size_bytes"),
            "endpoints": len(self.results.get("endpoints", [])),
            "secrets": len(self.results.get("secrets", [])),
            "internal": len(self.results.get("internal_endpoints", [])),
            "spa_routes": len(self.results.get("spa_routes", [])),
            "graphql": len(self.results.get("graphql_endpoints", [])),
            "ws": len(self.results.get("ws_endpoints", [])),
            "dependencies": len(self.results.get("dependencies", {})),
            "obfuscated": len(self.results.get("obfuscation", [])) > 0,
            "minified": self.results.get("is_minified", False),
            "total": self.results.get("total_findings", 0),
        }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python js_analyzer.py <url|file> [--output <path>]")
        sys.exit(1)
    source = sys.argv[1]
    out = sys.argv[3] if len(sys.argv) > 3 and sys.argv[2] == "--output" else None
    analyzer = JSAnalyzer(source_url=source)
    results = analyzer.analyze_all()
    print(json.dumps(analyzer.get_summary(), indent=2))
    if out:
        analyzer.output_json(out)
