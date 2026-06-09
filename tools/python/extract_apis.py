#!/usr/bin/env python3
"""
extract_apis.py — API Endpoint Discovery & Extraction Tool

Discovers REST, GraphQL, SOAP, WebSocket, and gRPC API endpoints from
HTML pages, JavaScript files, and HTTP responses. Detects HTTP methods,
extracts query/path/body parameters, identifies authentication requirements,
and produces sorted, deduplicated output with contextual metadata.

Features: REST endpoint discovery (25+ patterns), GraphQL introspection
detection, SOAP WSDL discovery, WebSocket endpoint detection, gRPC
reflection probe, method fingerprinting (GET/POST/PUT/DELETE/PATCH/OPTIONS/HEAD),
parameter extraction from URLs, forms, and JSON bodies, auth requirement
detection (Bearer, Basic, OAuth, API key, cookie), depth crawling,
batch URL/file processing, multi-format output (JSON/CSV/text),
concurrent scanning, path normalization, endpoint deduplication,
path variable identification, query parameter aggregation, and
severity scoring based on endpoint sensitivity.
"""

import argparse
import base64
import concurrent.futures
import csv
import datetime
import hashlib
import http.client
import json
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
class Endpoint:
    path: str
    method: str = "GET"
    params: Dict[str, List[str]] = field(default_factory=dict)
    body_params: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    auth_type: Optional[str] = None
    auth_required: bool = False
    content_type: Optional[str] = None
    source_url: Optional[str] = None
    response_status: Optional[int] = None
    response_body_sample: Optional[str] = None
    is_graphql: bool = False
    is_websocket: bool = False
    is_grpc: bool = False
    is_soap: bool = False
    discovered_at: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    severity: str = "info"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "method": self.method,
            "params": self.params,
            "body_params": self.body_params,
            "headers": self.headers,
            "auth_type": self.auth_type,
            "auth_required": self.auth_required,
            "content_type": self.content_type,
            "source_url": self.source_url,
            "response_status": self.response_status,
            "is_graphql": self.is_graphql,
            "is_websocket": self.is_websocket,
            "is_grpc": self.is_grpc,
            "is_soap": self.is_soap,
            "discovered_at": self.discovered_at,
            "severity": self.severity,
        }


class EndpointDatabase:
    def __init__(self) -> None:
        self._endpoints: Dict[str, Endpoint] = {}
        self._method_index: Dict[str, List[str]] = {m: [] for m in
            ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]}
        self._auth_index: Dict[str, List[str]] = {}
        self._graphql_endpoints: List[str] = []
        self._websocket_endpoints: List[str] = []
        self._soap_endpoints: List[str] = []
        self._grpc_endpoints: List[str] = []

    def _key(self, path: str, method: str) -> str:
        return f"{method.upper()}:{path}"

    def add(self, endpoint: Endpoint) -> None:
        k = self._key(endpoint.path, endpoint.method)
        if k in self._endpoints:
            existing = self._endpoints[k]
            if endpoint.params:
                for p, vals in endpoint.params.items():
                    if p not in existing.params:
                        existing.params[p] = vals
                    else:
                        existing.params[p] = list(set(existing.params[p] + vals))
            if endpoint.body_params:
                existing.body_params.update(endpoint.body_params)
            if endpoint.auth_type and not existing.auth_type:
                existing.auth_type = endpoint.auth_type
                existing.auth_required = endpoint.auth_required
            return
        self._endpoints[k] = endpoint
        m = endpoint.method.upper()
        if m in self._method_index:
            self._method_index[m].append(endpoint.path)
        if endpoint.auth_type:
            if endpoint.auth_type not in self._auth_index:
                self._auth_index[endpoint.auth_type] = []
            self._auth_index[endpoint.auth_type].append(endpoint.path)
        if endpoint.is_graphql:
            self._graphql_endpoints.append(endpoint.path)
        if endpoint.is_websocket:
            self._websocket_endpoints.append(endpoint.path)
        if endpoint.is_soap:
            self._soap_endpoints.append(endpoint.path)
        if endpoint.is_grpc:
            self._grpc_endpoints.append(endpoint.path)

    def get_by_method(self, method: str) -> List[Endpoint]:
        paths = self._method_index.get(method.upper(), [])
        return [self._endpoints[self._key(p, method)] for p in paths if self._key(p, method) in self._endpoints]

    def get_by_auth(self, auth_type: str) -> List[Endpoint]:
        paths = self._auth_index.get(auth_type, [])
        result: List[Endpoint] = []
        seen: Set[str] = set()
        for p in paths:
            for m in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]:
                k = self._key(p, m)
                if k in self._endpoints and k not in seen:
                    result.append(self._endpoints[k])
                    seen.add(k)
        return result

    def get_all(self) -> List[Endpoint]:
        return list(self._endpoints.values())

    def get_graphql(self) -> List[Endpoint]:
        return [self._endpoints[self._key(p, "POST")] for p in self._graphql_endpoints if self._key(p, "POST") in self._endpoints]

    def get_websocket(self) -> List[Endpoint]:
        return [e for e in self._endpoints.values() if e.is_websocket]

    def get_soap(self) -> List[Endpoint]:
        return [e for e in self._endpoints.values() if e.is_soap]

    def get_grpc(self) -> List[Endpoint]:
        return [e for e in self._endpoints.values() if e.is_grpc]

    def deduplicate(self) -> int:
        before = len(self._endpoints)
        seen: Set[str] = set()
        deduped: Dict[str, Endpoint] = {}
        for k, ep in self._endpoints.items():
            norm = f"{ep.method}:{ep.path}"
            if norm not in seen:
                seen.add(norm)
                deduped[k] = ep
        self._endpoints = deduped
        return before - len(self._endpoints)

    def stats(self) -> Dict[str, Any]:
        return {
            "total_endpoints": len(self._endpoints),
            "by_method": {m: len(paths) for m, paths in self._method_index.items()},
            "by_auth": {a: len(p) for a, p in self._auth_index.items()},
            "graphql_count": len(self._graphql_endpoints),
            "websocket_count": len(self._websocket_endpoints),
            "soap_count": len(self._soap_endpoints),
            "grpc_count": len(self._grpc_endpoints),
        }

    def sort_by_path(self) -> List[Endpoint]:
        return sorted(self._endpoints.values(), key=lambda e: e.path)

    def sort_by_severity(self) -> List[Endpoint]:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return sorted(self._endpoints.values(), key=lambda e: order.get(e.severity, 4))


class ApiExtractor:
    REST_PATTERNS: List[re.Pattern] = [
        re.compile(r'(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+["\']?(/[a-zA-Z0-9_\-/.{}]+)'),
        re.compile(r'["\'](?:url|path|endpoint|route|api|action)\s*["\']?\s*[:=]\s*["\'](/?[a-zA-Z0-9_\-/.{}]+)["\']'),
        re.compile(r'axios\.(?:get|post|put|delete|patch)\s*\(\s*["\'](/?[a-zA-Z0-9_\-/.{}?&=]+)'),
        re.compile(r'fetch\s*\(\s*["\'](/?[a-zA-Z0-9_\-/.{}?&=]+)'),
        re.compile(r'\$\.(?:get|post|put|delete|ajax)\s*\(\s*["\'](/?[a-zA-Z0-9_\-/.{}?&=]+)'),
        re.compile(r'XMLHttpRequest\S+\s*(?:\.open|\.send)\(?\s*["\'](GET|POST|PUT|DELETE|PATCH)?["\']?,?\s*["\'](/?[a-zA-Z0-9_\-/.{}?&=]+)'),
        re.compile(r'router\.(?:get|post|put|delete|patch|all)\s*\(\s*["\'](/?[a-zA-Z0-9_\-/.{}]+)'),
        re.compile(r'@(?:Get|Post|Put|Delete|Patch)Mapping\s*\(\s*["\'](/?[a-zA-Z0-9_\-/.{}]+)'),
        re.compile(r'app\.(?:get|post|put|delete|patch|use)\s*\(\s*["\'](/?[a-zA-Z0-9_\-/.{}]+)'),
        re.compile(r'api/v[0-9]+/[a-zA-Z0-9_\-/.{}]+'),
        re.compile(r'/api/[a-zA-Z0-9_\-/.{}?&=]+'),
        re.compile(r'/rest/[a-zA-Z0-9_\-/.{}]+'),
        re.compile(r'/v[0-9]+/[a-zA-Z0-9_\-/.{}]+'),
        re.compile(r'["\'](?:backend|server|base|baseURL|base_url)\s*["\']?\s*[:=]\s*["\']([^"\']+)'),
        re.compile(r'endpoint\s*[:=]\s*["\']([^"\']+)'),
        re.compile(r'(?:api|service|client)\.([a-zA-Z]+)\(["\']([^"\']+)'),
        re.compile(r'xhr\.(?:open|send)\s*\(["\'](GET|POST|PUT|DELETE|PATCH)?["\']?,?\s*["\']([^"\']+)'),
        re.compile(r'ng-controller=["\']([^"\']+)'),
        re.compile(r'ui-sref=["\']([^"\']+)'),
        re.compile(r'route\.(?:path|name|pattern)\s*[:=]\s*["\']([^"\']+)'),
        re.compile(r'new URLPattern\(\s*["\']([^"\']+)'),
        re.compile(r'["\'](?:href|action)\s*["\']?\s*[:=]\s*["\'](/?api/[^"\']+)'),
        re.compile(r'constant\s*\(\s*["\'](?:API|API_URL|BASE_URL|ENDPOINT)["\']?\s*,\s*["\']([^"\']+)'),
        re.compile(r'["\'](?:uri|resource)["\']?\s*[:=]\s*["\'](/?[a-zA-Z0-9_\-/.{}]+)'),
        re.compile(r'@RequestMapping\s*\(\s*["\'](/?[a-zA-Z0-9_\-/.{}]+)'),
        re.compile(r'\.(?:list|get|create|update|delete|save|find|search|query|fetch)\s*[:(]'),
        re.compile(r'["\']rest/([a-zA-Z0-9_\-/.{}]+)'),
        re.compile(r'["\']/[\w\-]+/[\w\-]+/[\w\-]+\.[\w]+(?:\?[^"\']*)?["\']'),
    ]

    GRAPHQL_PATTERNS: List[re.Pattern] = [
        re.compile(r'["\'](?:/[a-zA-Z0-9_\-/]*graphql)["\']'),
        re.compile(r'["\'](?:/[a-zA-Z0-9_\-/]*gql)["\']'),
        re.compile(r'query\s+(?:[a-zA-Z]\w*\s*)?[{(]'),
        re.compile(r'mutation\s+(?:[a-zA-Z]\w*\s*)?[{(]'),
        re.compile(r'__typename'),
        re.compile(r'IntrospectionQuery'),
        re.compile(r'__schema\s*[{]'),
        re.compile(r'graphql\s*:\s*["\']([^"\']+)'),
        re.compile(r'GraphQL'),
        re.compile(r'"query"\s*:\s*"'),
        re.compile(r'"operationName"\s*:'),
        re.compile(r'"variables"\s*:'),
        re.compile(r'/graphql\b'),
        re.compile(r'/v1/graphql\b'),
        re.compile(r'/v2/graphql\b'),
        re.compile(r'/gql\b'),
    ]

    WEBSOCKET_PATTERNS: List[re.Pattern] = [
        re.compile(r'(?:ws|wss)://[a-zA-Z0-9_.\-/]+'),
        re.compile(r'new\s+WebSocket\s*\(\s*["\']([^"\']+)'),
        re.compile(r'SockJS\s*\(\s*["\']([^"\']+)'),
        re.compile(r'io\s*\(\s*["\']([^"\']+)'),
        re.compile(r'socket\.(?:connect|on|emit)'),
        re.compile(r'/(?:ws|wss|socket|realtime|events|live|stream)'),
        re.compile(r'["\']websocket["\']\s*[:=]\s*["\']([^"\']+)'),
        re.compile(r'new\s+WebSocket\b'),
        re.compile(r'Socket\.IO'),
        re.compile(r'engine\.io'),
        re.compile(r'socket\.io'),
    ]

    SOAP_PATTERNS: List[re.Pattern] = [
        re.compile(r'(?:/wsdl|\.wsdl|/soap|\.soap|/asmx|\.asmx)'),
        re.compile(r'<wsdl:definitions'),
        re.compile(r'<soap:Body'),
        re.compile(r'<soap:Envelope'),
        re.compile(r'WSDL'),
        re.compile(r'SOAPAction'),
        re.compile(r'xmlns:soap'),
        re.compile(r'<message\s+name'),
        re.compile(r'<portType\s+name'),
        re.compile(r'<binding\s+type'),
        re.compile(r'<service\s+name'),
        re.compile(r'/Service\.asmx'),
        re.compile(r'\.svc\b'),
        re.compile(r'/WcfService'),
        re.compile(r'/Service1\.svc'),
    ]

    GRPC_PATTERNS: List[re.Pattern] = [
        re.compile(r'proto\s+(?:package|service|rpc)\s+\w+'),
        re.compile(r'grpc\.(?:web|client)'),
        re.compile(r'(?:unary|serverStreaming|clientStreaming|bidiStreaming)'),
        re.compile(r'protobuf'),
        re.compile(r'/grpc'),
        re.compile(r'/grpc.reflection'),
        re.compile(r'\.pb\b'),
        re.compile(r'service\s+\w+\s*[{]\s*rpc'),
        re.compile(r'npm.*@grpc'),
        re.compile(r'proto3'),
        re.compile(r'google\.protobuf'),
        re.compile(r'import\s+"[a-zA-Z0-9_]+\.proto'),
        re.compile(r'option\s+\(google\.api'),
        re.compile(r'/v1/protos/'),
        re.compile(r'grpc-web:'),
    ]

    AUTH_PATTERNS: List[Dict[str, Any]] = [
        {"name": "bearer", "regex": re.compile(r'(?:bearer|Bearer|BEARER)\s+[A-Za-z0-9_\-+=./]+'), "type": "Bearer"},
        {"name": "basic_auth", "regex": re.compile(r'(?:basic|Basic|BASIC)\s+[A-Za-z0-9+/=]+'), "type": "Basic"},
        {"name": "oauth", "regex": re.compile(r'(?:oauth|OAuth|OAUTH)\s*[:=]\s*["\'][^"\']+'), "type": "OAuth"},
        {"name": "api_key_header", "regex": re.compile(r'(?:x-api-key|X-Api-Key|X-API-Key|api[_-]?key)\s*[:=]\s*["\'][^"\']+'), "type": "API Key"},
        {"name": "jwt_pattern", "regex": re.compile(r'eyJ[A-Za-z0-9_\-+/=]+\.[A-Za-z0-9_\-+/=]+\.[A-Za-z0-9_\-+/=]+'), "type": "JWT"},
        {"name": "session_cookie", "regex": re.compile(r'(?:session|token|sid|auth|jwt)\s*[:=]\s*["\'][A-Za-z0-9_\-]+'), "type": "Session Cookie"},
        {"name": "api_key_url", "regex": re.compile(r'[?&](?:api[_-]?key|apikey|key|token|auth)=[^&\s]+'), "type": "API Key (URL)"},
        {"name": "authorization_header", "regex": re.compile(r'["\']authorization["\']\s*[:=]\s*["\'][^"\']+'), "type": "Authorization Header"},
    ]

    PARAM_PATTERNS: List[re.Pattern] = [
        re.compile(r'\?([a-zA-Z0-9_\-]+)=([^&\s"\']+)'),
        re.compile(r'(?:params|parameters|query|data|body)\s*[:=]\s*\{([^}]+)\}'),
        re.compile(r'["\']([a-zA-Z]\w*)["\']\s*:\s*["\'][^"\']+["\']'),
        re.compile(r'\{([a-zA-Z_]\w*)\}'),
        re.compile(r':([a-zA-Z_]\w*)'),
    ]

    METHOD_PATTERNS: Dict[str, List[re.Pattern]] = {
        "GET": [re.compile(r'\.(?:get|fetch|list|search|query|find|index|show)\s*[:(]'), re.compile(r'method:\s*["\']?GET["\']?')],
        "POST": [re.compile(r'\.(?:post|create|add|insert|store|save|submit|upload)\s*[:(]'), re.compile(r'method:\s*["\']?POST["\']?')],
        "PUT": [re.compile(r'\.(?:put|update|edit|modify|replace)\s*[:(]'), re.compile(r'method:\s*["\']?PUT["\']?')],
        "DELETE": [re.compile(r'\.(?:delete|remove|destroy|erase|del)\s*[:(]'), re.compile(r'method:\s*["\']?DELETE["\']?')],
        "PATCH": [re.compile(r'\.(?:patch)\s*[:(]'), re.compile(r'method:\s*["\']?PATCH["\']?')],
    }

    SENSITIVE_PATHS: List[str] = [
        "/admin", "/administrator", "/manage", "/management", "/dashboard",
        "/config", "/configuration", "/settings", "/setup", "/install",
        "/debug", "/test", "/health", "/status", "/monitor", "/metrics",
        "/swagger", "/api-docs", "/docs", "/openapi", "/v2/api-docs",
        "/actuator", "/env", "/heapdump", "/threaddump", "/trace",
        "/log", "/logging", "/audit", "/backup", "/export", "/import",
        "/secret", "/credentials", "/token", "/password", "/reset",
        "/payment", "/billing", "/invoice", "/order", "/checkout",
        "/user", "/users", "/account", "/profile", "/admin/users",
        "/.git", "/.env", "/.aws", "/.ssh", "/composer.json",
        "/node_modules", "/package.json", "/web.config", "/.htaccess",
        "/wp-admin", "/phpinfo.php", "/server-status", "/server-info",
    ]

    def __init__(self, silent: bool = False, depth: int = 2):
        self.db = EndpointDatabase()
        self.silent = silent
        self.max_depth = depth
        self._visited_urls: Set[str] = set()
        self._scan_stats: Dict[str, Any] = {
            "urls_scanned": 0, "js_files_analyzed": 0,
            "endpoints_found": 0, "graphql_found": 0,
            "websocket_found": 0, "auth_endpoints": 0,
            "errors": 0, "start_time": None, "end_time": None,
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

    def fetch_url(self, url: str, timeout: float = 15) -> Optional[str]:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "*/*",
                    "Accept-Language": "en-US,en;q=0.5",
                },
            )
            ctx = self._create_ssl_context()
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                content_type = resp.headers.get("Content-Type", "")
                encoding = "utf-8"
                if "charset=" in content_type:
                    encoding = content_type.split("charset=")[-1].split(";")[0].strip()
                raw = resp.read()
                try:
                    return raw.decode(encoding, errors="replace")
                except (LookupError, UnicodeDecodeError):
                    return raw.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            try:
                return e.read().decode("utf-8", errors="replace")
            except Exception:
                return None
        except urllib.error.URLError as e:
            self._log(f"URL error for {url}: {e.reason}", "error")
            return None
        except Exception as e:
            self._log(f"Error fetching {url}: {e}", "error")
            return None

    def extract_from_html(self, html: str, base_url: str = "") -> List[Endpoint]:
        endpoints: List[Endpoint] = []
        if not html:
            return endpoints

        # Extract form actions
        for match in re.finditer(r'<form[^>]*\saction\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
            action = match.group(1)
            if action and not action.startswith("#") and not action.startswith("javascript:"):
                full_url = urllib.parse.urljoin(base_url, action)
                ep = Endpoint(path=full_url, method="POST", source_url=base_url)
                method_m = re.search(r'method\s*=\s*["\'](get|post|put|delete|patch)["\']', html, re.IGNORECASE)
                if method_m:
                    ep.method = method_m.group(1).upper()
                # Extract form fields
                for fm in re.finditer(r'<input[^>]*\sname\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
                    ep.params.setdefault(fm.group(1), ["<form_field>"])
                endpoints.append(ep)

        # Extract links with API patterns
        for match in re.finditer(r'<a[^>]*\shref\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
            href = match.group(1)
            if not href or href.startswith("#") or href.startswith("javascript:"):
                continue
            full_url = urllib.parse.urljoin(base_url, href)
            if self._is_api_path(full_url):
                ep = Endpoint(path=full_url, method="GET", source_url=base_url)
                # Extract query params
                parsed = urllib.parse.urlparse(full_url)
                qs = urllib.parse.parse_qs(parsed.query)
                if qs:
                    ep.params = {k: v for k, v in qs.items()}
                endpoints.append(ep)

        # Extract from script tags containing JSON/config
        for match in re.finditer(r'<script[^>]*>([^<]+)</script>', html, re.IGNORECASE):
            js_content = match.group(1)
            if any(kw in js_content for kw in ["api", "API", "endpoint", "url", "fetch", "axios", "ajax"]):
                endpoints.extend(self.extract_from_js(js_content, base_url))

        # Extract from data- attributes
        for match in re.finditer(r'data-(?:url|endpoint|api|href)\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
            val = match.group(1)
            if val and not val.startswith("#"):
                full_url = urllib.parse.urljoin(base_url, val)
                endpoints.append(Endpoint(path=full_url, method="GET", source_url=base_url))

        return endpoints

    def extract_from_js(self, js_content: str, source_url: str = "") -> List[Endpoint]:
        endpoints: List[Endpoint] = []
        if not js_content:
            return endpoints

        # REST endpoint extraction
        for pat in self.REST_PATTERNS:
            for match in pat.finditer(js_content):
                url_str = match.group(1) if pat.groups >= 1 else match.group(0)
                if not url_str or len(url_str) < 3:
                    continue
                if url_str.startswith("/") or "://" in url_str or url_str.startswith("."):
                    full_url = urllib.parse.urljoin(source_url, url_str) if source_url else url_str
                    method = self._detect_method(js_content, match.start())
                    ep = Endpoint(path=full_url, method=method, source_url=source_url)
                    # Extract params from URL
                    parsed = urllib.parse.urlparse(full_url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    if qs:
                        ep.params = qs
                    # Check for auth
                    ctx_before = js_content[max(0, match.start() - 200):match.start()]
                    ctx_after = js_content[match.end():match.end() + 200]
                    auth_info = self._detect_auth(ctx_before + ctx_after)
                    if auth_info:
                        ep.auth_type = auth_info
                        ep.auth_required = True
                    endpoints.append(ep)

        # GraphQL detection
        for pat in self.GRAPHQL_PATTERNS:
            for match in pat.finditer(js_content):
                full_url = urllib.parse.urljoin(source_url, match.group(0)) if source_url else match.group(0)
                ep = Endpoint(path=full_url, method="POST", source_url=source_url, is_graphql=True)
                endpoints.append(ep)

        # WebSocket detection
        for pat in self.WEBSOCKET_PATTERNS:
            for match in pat.finditer(js_content):
                url_str = match.group(1) if pat.groups >= 1 else match.group(0)
                if url_str:
                    full_url = urllib.parse.urljoin(source_url, url_str) if source_url else url_str
                    ep = Endpoint(path=full_url, method="WS", source_url=source_url, is_websocket=True)
                    endpoints.append(ep)

        # SOAP detection
        for pat in self.SOAP_PATTERNS:
            for match in pat.finditer(js_content):
                full_url = urllib.parse.urljoin(source_url, match.group(0)) if source_url else match.group(0)
                ep = Endpoint(path=full_url, method="POST", source_url=source_url, is_soap=True)
                endpoints.append(ep)

        # gRPC detection
        for pat in self.GRPC_PATTERNS:
            for match in pat.finditer(js_content):
                full_url = urllib.parse.urljoin(source_url, match.group(0)) if source_url else match.group(0)
                ep = Endpoint(path=full_url, method="POST", source_url=source_url, is_grpc=True)
                endpoints.append(ep)

        return endpoints

    def _is_api_path(self, path: str) -> bool:
        lower = path.lower()
        api_keywords = ["api", "rest", "v1/", "v2/", "v3/", "graphql", "soap", "wsdl",
                        "service", "endpoint", "auth", "login", "logout", "token",
                        "oauth", "callback", "webhook", "swagger", "openapi",
                        "actuator", "health", "metrics", "status"]
        return any(kw in lower for kw in api_keywords)

    def _detect_method(self, content: str, near_pos: int) -> str:
        window = content[max(0, near_pos - 100):near_pos + 100].lower()
        for method, patterns in self.METHOD_PATTERNS.items():
            for pat in patterns:
                if pat.search(window):
                    return method
        ctx = content[max(0, near_pos - 50):near_pos + 50]
        method_keywords = {"get": "GET", "post": "POST", "put": "PUT", "delete": "DELETE",
                           "patch": "PATCH", "fetch": "GET", "list": "GET", "create": "POST",
                           "update": "PUT", "remove": "DELETE", "save": "POST", "search": "GET"}
        for kw, m in method_keywords.items():
            if kw in ctx.lower():
                return m
        return "GET"

    def _detect_auth(self, content: str) -> Optional[str]:
        for pat_def in self.AUTH_PATTERNS:
            if pat_def["regex"].search(content):
                return pat_def["type"]
        return None

    def detect_graphql_introspection(self, url: str) -> bool:
        introspection_query = '{"query":"query { __schema { types { name fields { name } } } }"}'
        try:
            req = urllib.request.Request(
                url,
                data=introspection_query.encode(),
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                },
            )
            ctx = self._create_ssl_context()
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return "__schema" in body or "types" in body
        except Exception:
            return False

    def detect_wsdl(self, url: str) -> bool:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            ctx = self._create_ssl_context()
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return "<wsdl:definitions" in body or "<definitions" in body
        except Exception:
            return False

    def crawl_page(self, url: str, current_depth: int = 0) -> None:
        if current_depth > self.max_depth:
            return
        if url in self._visited_urls:
            return
        self._visited_urls.add(url)
        self._scan_stats["urls_scanned"] += 1
        self._log(f"Crawling {url} (depth {current_depth})")

        html = self.fetch_url(url)
        if not html:
            return

        # Extract from HTML
        html_endpoints = self.extract_from_html(html, url)
        for ep in html_endpoints:
            self.db.add(ep)

        # Find JS files
        js_urls = self._find_js_urls(html, url)
        for js_url in js_urls:
            if js_url not in self._visited_urls:
                self._visited_urls.add(js_url)
                self._scan_stats["js_files_analyzed"] += 1
                js_content = self.fetch_url(js_url)
                if js_content:
                    js_endpoints = self.extract_from_js(js_content, js_url)
                    for ep in js_endpoints:
                        self.db.add(ep)

        # Find linked pages for further crawling
        if current_depth < self.max_depth:
            for match in re.finditer(r'<a[^>]*\shref\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
                href = match.group(1)
                if href and not href.startswith("#") and not href.startswith("javascript:"):
                    full_url = urllib.parse.urljoin(url, href)
                    if self._is_api_path(full_url) or current_depth == 0:
                        self.crawl_page(full_url, current_depth + 1)

    def _find_js_urls(self, html: str, base_url: str) -> List[str]:
        urls: List[str] = []
        for match in re.finditer(r'<script[^>]*\ssrc\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
            src = match.group(1)
            if src:
                full_url = urllib.parse.urljoin(base_url, src)
                urls.append(full_url)
        for match in re.finditer(r'import\s*[({]\s*["\']([^"\']+)["\']', html):
            url = match.group(1)
            if url.endswith(".js") or ".js?" in url:
                full_url = urllib.parse.urljoin(base_url, url)
                urls.append(full_url)
        for match in re.finditer(r'(?:src|href)\s*=\s*["\']([^"\']+\.js[^"\']*)["\']', html, re.IGNORECASE):
            url = match.group(1)
            full_url = urllib.parse.urljoin(base_url, url)
            if full_url not in urls:
                urls.append(full_url)
        return urls

    def probe_methods(self, base_url: str, methods: Optional[List[str]] = None) -> List[Endpoint]:
        if methods is None:
            methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
        results: List[Endpoint] = []
        for method in methods:
            try:
                req = urllib.request.Request(
                    base_url, method=method,
                    headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*"},
                )
                ctx = self._create_ssl_context()
                with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                    body_sample = resp.read(1024).decode("utf-8", errors="replace")
                    ep = Endpoint(
                        path=base_url, method=method,
                        source_url=base_url,
                        response_status=resp.status,
                        response_body_sample=body_sample,
                        content_type=resp.headers.get("Content-Type"),
                    )
                    self.db.add(ep)
                    results.append(ep)
                    self._log(f"  {method} {base_url} -> {resp.status}")
            except urllib.error.HTTPError as e:
                body_sample = ""
                try:
                    body_sample = e.read(1024).decode("utf-8", errors="replace")
                except Exception:
                    pass
                ep = Endpoint(
                    path=base_url, method=method,
                    source_url=base_url,
                    response_status=e.code,
                    response_body_sample=body_sample,
                    content_type=e.headers.get("Content-Type"),
                )
                self.db.add(ep)
                results.append(ep)
            except Exception as e:
                self._log(f"  {method} {base_url} -> {e}", "error")
        return results

    def classify_severity(self, endpoint: Endpoint) -> str:
        path_lower = endpoint.path.lower()
        sensitive_keywords = {
            "critical": ["admin", "config", "secret", "credential", "password", "token", "backup",
                         "export", "import", "payment", "billing", "invoice", "order", "sudo"],
            "high": ["user", "account", "profile", "auth", "login", "oauth", "reset", "role",
                     "permission", "group", "manage", "setting", "api-key"],
            "medium": ["api", "v1", "v2", "service", "data", "search", "query", "report",
                       "notification", "webhook", "callback"],
            "low": ["health", "status", "metrics", "version", "ping", "info", "docs", "swagger"],
        }
        for sev, keywords in sensitive_keywords.items():
            if any(kw in path_lower for kw in keywords):
                return sev
        if endpoint.auth_required:
            return "medium"
        if endpoint.is_graphql or endpoint.is_websocket:
            return "medium"
        if endpoint.is_soap or endpoint.is_grpc:
            return "medium"
        return "info"

    def scan_url(self, url: str, methods: Optional[List[str]] = None) -> EndpointDatabase:
        self._scan_stats["start_time"] = datetime.datetime.now().isoformat()
        self._log(f"Scanning URL: {url}")
        self.crawl_page(url)
        if methods:
            self.probe_methods(url, methods)
        for ep in self.db.get_all():
            ep.severity = self.classify_severity(ep)
        self._scan_stats["endpoints_found"] = len(self.db.get_all())
        self._scan_stats["graphql_found"] = len(self.db.get_graphql())
        self._scan_stats["websocket_found"] = len(self.db.get_websocket())
        self._scan_stats["auth_endpoints"] = len([e for e in self.db.get_all() if e.auth_required])
        self._scan_stats["end_time"] = datetime.datetime.now().isoformat()
        self._log(f"Scan complete: {self._scan_stats['endpoints_found']} endpoints found")
        return self.db

    def scan_file(self, filepath: str, base_url: str = "") -> EndpointDatabase:
        self._scan_stats["start_time"] = datetime.datetime.now().isoformat()
        self._log(f"Scanning file: {filepath}")
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            self._log(f"Error reading file {filepath}: {e}", "error")
            return self.db

        if filepath.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
            endpoints = self.extract_from_js(content, base_url)
        else:
            endpoints = self.extract_from_html(content, base_url)
            js_urls = self._find_js_urls(content, base_url)
            for js_url in js_urls:
                js_content = self.fetch_url(js_url)
                if js_content:
                    self._scan_stats["js_files_analyzed"] += 1
                    endpoints.extend(self.extract_from_js(js_content, js_url))

        for ep in endpoints:
            ep.severity = self.classify_severity(ep)
            self.db.add(ep)

        self._scan_stats["endpoints_found"] = len(endpoints)
        self._scan_stats["end_time"] = datetime.datetime.now().isoformat()
        self._log(f"File scan complete: {len(endpoints)} endpoints found")
        return self.db

    def output_json(self, filepath: Optional[str] = None) -> str:
        data = {
            "scan_metadata": self._scan_stats,
            "db_stats": self.db.stats(),
            "endpoints": [e.to_dict() for e in self.db.sort_by_path()],
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
        endpoints = self.db.sort_by_path()
        if not endpoints:
            self._log("No endpoints to write to CSV", "warn")
            return
        fieldnames = list(endpoints[0].to_dict().keys())
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for ep in endpoints:
                writer.writerow(ep.to_dict())
        self._log(f"CSV output written to {filepath}")

    def output_text(self, filepath: Optional[str] = None) -> str:
        lines = [f"API Endpoint Discovery Report", "=" * 60,
                 f"Generated: {datetime.datetime.now().isoformat()}",
                 f"URLs Scanned: {self._scan_stats.get('urls_scanned', 0)}",
                 f"JS Files Analyzed: {self._scan_stats.get('js_files_analyzed', 0)}",
                 f"Total Endpoints Found: {len(self.db.get_all())}",
                 f"GraphQL: {len(self.db.get_graphql())}",
                 f"WebSocket: {len(self.db.get_websocket())}",
                 f"SOAP: {len(self.db.get_soap())}",
                 f"gRPC: {len(self.db.get_grpc())}",
                 f"Auth-Protected: {self._scan_stats.get('auth_endpoints', 0)}",
                 "", "--- Endpoints ---", ""]

        for ep in self.db.sort_by_path():
            lines.append(f"[{ep.severity.upper()}] {ep.method} {ep.path}")
            if ep.params:
                lines.append(f"  Params: {list(ep.params.keys())}")
            if ep.body_params:
                lines.append(f"  Body: {list(ep.body_params.keys())}")
            if ep.auth_type:
                lines.append(f"  Auth: {ep.auth_type}")
            if ep.content_type:
                lines.append(f"  Content-Type: {ep.content_type}")
            if ep.response_status:
                lines.append(f"  Status: {ep.response_status}")
            if ep.is_graphql:
                lines.append("  [GraphQL]")
            if ep.is_websocket:
                lines.append("  [WebSocket]")
            if ep.is_soap:
                lines.append("  [SOAP]")
            if ep.is_grpc:
                lines.append("  [gRPC]")
            lines.append("")

        report = "\n".join(lines)
        if filepath:
            os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(report)
            self._log(f"Text report written to {filepath}")
        return report

    def get_summary(self) -> Dict[str, Any]:
        return {
            "scan_stats": self._scan_stats,
            "db_stats": self.db.stats(),
        }

    def merge_databases(self, other: "ApiExtractor") -> int:
        before = len(self.db.get_all())
        for ep in other.db.get_all():
            self.db.add(ep)
        return len(self.db.get_all()) - before


def build_argparse() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="extract_apis.py — API Endpoint Discovery & Extraction Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python extract_apis.py --url https://target.com/api
              python extract_apis.py --file app.js
              python extract_apis.py --url https://target.com --output endpoints.json --depth 3
              python extract_apis.py --url https://target.com --methods GET,POST
              python extract_apis.py --url https://target.com --silent --json
        """),
    )
    parser.add_argument("--url", type=str, help="Target URL to scan for API endpoints")
    parser.add_argument("--file", type=str, help="Local file to analyze (HTML or JS)")
    parser.add_argument("--output", type=str, default=None, help="Output file path for results")
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth for URL scanning (default: 2)")
    parser.add_argument("--silent", action="store_true", help="Suppress informational output")
    parser.add_argument("--json", action="store_true", help="Output in JSON format (to stdout or file)")
    parser.add_argument("--csv", type=str, default=None, help="Write CSV output to specified file")
    parser.add_argument("--methods", type=str, default=None,
                        help="Comma-separated HTTP methods to probe (e.g., GET,POST,PUT,DELETE)")
    parser.add_argument("--probe", action="store_true", help="Probe discovered endpoints for method support")
    return parser


def main() -> None:
    parser = build_argparse()
    args = parser.parse_args()

    extractor = ApiExtractor(silent=args.silent, depth=args.depth)

    if not args.url and not args.file:
        parser.print_help()
        sys.exit(1)

    methods: Optional[List[str]] = None
    if args.methods:
        methods = [m.strip().upper() for m in args.methods.split(",") if m.strip()]

    try:
        if args.url:
            extractor.scan_url(args.url, methods=methods)
        if args.file:
            extractor.scan_file(args.file, base_url=args.url or "")
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user", file=sys.stderr)
    except Exception as e:
        print(f"[!] Fatal error: {e}", file=sys.stderr)
        sys.exit(1)

    summary = extractor.get_summary()
    db_stats = summary.get("db_stats", {})

    if args.json or (args.output and args.output.endswith(".json")):
        out_path = args.output if args.output else None
        json_output = extractor.output_json(filepath=out_path)
        if not out_path:
            print(json_output)
    elif args.csv:
        extractor.output_csv(args.csv)
    else:
        report = extractor.output_text(filepath=args.output)
        if not args.output:
            print(report)

    print(f"\n=== Summary ===", file=sys.stderr if not args.json else sys.stdout)
    print(f"  Total Endpoints: {db_stats.get('total_endpoints', 0)}", file=sys.stderr if not args.json else sys.stdout)
    print(f"  GraphQL: {db_stats.get('graphql_count', 0)}", file=sys.stderr if not args.json else sys.stdout)
    print(f"  WebSocket: {db_stats.get('websocket_count', 0)}", file=sys.stderr if not args.json else sys.stdout)
    print(f"  SOAP: {db_stats.get('soap_count', 0)}", file=sys.stderr if not args.json else sys.stdout)
    print(f"  gRPC: {db_stats.get('grpc_count', 0)}", file=sys.stderr if not args.json else sys.stdout)


if __name__ == "__main__":
    main()
