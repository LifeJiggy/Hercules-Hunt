#!/usr/bin/env python3
"""
endpoint_fuzzer.py — Endpoint Fuzzing Tool

Performs comprehensive endpoint fuzzing including path discovery, HTTP method
testing, extension enumeration, parameter fuzzing, response analysis, baseline
comparison, access control testing, and recursive discovery. Designed for
bug bounty recon and API security assessment.

Features:
    - Path fuzzing with built-in dictionary-based wordlists
    - HTTP method fuzzing (GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD, TRACE)
    - Extension fuzzing (.php, .asp, .aspx, .jsp, .json, .xml, .bak, etc.)
    - Parameter fuzzing with common API parameter names
    - Response analysis (status codes, body size, response time, content-type)
    - Baseline comparison against known-good responses
    - Access control testing across different auth states
    - Recursive discovery of newly found paths
    - Multi-threaded execution with configurable concurrency
    - JSON, CSV, and text output formats

Classes:
    FuzzResult: Dataclass for storing individual fuzz test results
    ResponseAnalyzer: Analyzes HTTP responses for anomalies
    WordlistManager: Manages built-in and custom wordlists
    BaselineComparator: Compares responses against a baseline
    EndpointFuzzer: Main fuzzer orchestrator
"""

import argparse
import base64
import collections
import concurrent.futures
import csv
import datetime
import hashlib
import http.client
import json
import logging
import os
import random
import re
import ssl
import sys
import textwrap
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

_MAX_URL_LENGTH = 8192


def _validate_output_path(filepath: str) -> str:
    normalized = os.path.normpath(filepath)
    if ".." in normalized.split(os.sep):
        raise ValueError(f"Invalid output path: {filepath}")
    return normalized

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("endpoint_fuzzer")


@dataclass
class FuzzResult:
    """Represents the result of a single fuzz test request.

    Stores the target, request parameters, response metadata, and
    anomaly detection results for a single fuzzing operation.

    Attributes:
        description: Human-readable description of this test case
        url: The target URL that was tested
        method: HTTP method used (GET, POST, etc.)
        params: Query parameters sent with the request
        headers: HTTP headers sent with the request
        data: Request body data
        path: Fuzzed path component
        extension: File extension tested
        status: HTTP response status code
        size: Response body size in bytes
        body_hash: MD5 hash of response body
        elapsed: Request duration in seconds
        content_type: Content-Type header from response
        error: Error message if request failed
        anomalous: Whether this response is considered anomalous
        anomaly_reason: Explanation of why it is anomalous
    """
    description: str = ""
    url: str = ""
    method: str = "GET"
    params: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    data: Optional[Dict[str, str]] = None
    path: str = ""
    extension: str = ""
    status: Optional[int] = None
    size: Optional[int] = None
    body_hash: Optional[str] = None
    elapsed: float = 0.0
    content_type: str = ""
    error: Optional[str] = None
    anomalous: bool = False
    anomaly_reason: str = ""
    patterns: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize result to dictionary for JSON export."""
        return {
            "description": self.description,
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "path": self.path,
            "extension": self.extension,
            "status": self.status,
            "size": self.size,
            "elapsed": round(self.elapsed, 4),
            "content_type": self.content_type,
            "error": self.error,
            "anomalous": self.anomalous,
            "anomaly_reason": self.anomaly_reason,
        }


class ResponseAnalyzer:
    """Analyzes HTTP responses to detect anomalies and classify behaviors.

    Performs status code classification, size comparison, response time
    analysis, content-type inspection, and pattern matching against
    response bodies to identify interesting or anomalous results.

    Attributes:
        classifications: Reference dictionary of status code ranges
        anomaly_thresholds: Dict of threshold values for anomaly detection
    """

    STATUS_CLASSIFICATIONS: Dict[str, Tuple[int, int]] = {
        "success": (200, 299),
        "redirect": (300, 399),
        "client_error": (400, 499),
        "server_error": (500, 599),
    }

    INTERESTING_STATUSES: Set[int] = {
        200, 201, 202, 204, 301, 302, 303, 307, 308,
        400, 401, 403, 404, 405, 500, 502, 503,
    }

    def __init__(self, size_threshold: float = 0.3, time_threshold: float = 3.0):
        """Initialize the response analyzer.

        Args:
            size_threshold: Fractional size difference threshold (0.0-1.0)
            time_threshold: Time difference threshold in seconds
        """
        self.size_threshold = size_threshold
        self.time_threshold = time_threshold

    def classify_status(self, status: int) -> str:
        """Categorize HTTP status code into a named range.

        Args:
            status: HTTP status code

        Returns:
            Classification string: success, redirect, client_error,
                server_error, or unknown
        """
        for name, (low, high) in self.STATUS_CLASSIFICATIONS.items():
            if low <= status <= high:
                return name
        return "unknown"

    def is_interesting_status(self, status: int) -> bool:
        """Determine if a status code is worth investigating.

        Args:
            status: HTTP status code

        Returns:
            True if the status is in the interesting set
        """
        return status in self.INTERESTING_STATUSES

    def detect_anomaly(
        self,
        status: Optional[int],
        size: Optional[int],
        elapsed: float,
        baseline_status: Optional[int] = None,
        baseline_size: Optional[int] = None,
        baseline_elapsed: float = 0.0,
    ) -> Tuple[bool, str]:
        """Detect anomalies by comparing response attributes against baseline.

        Args:
            status: Current response status code
            size: Current response body size
            elapsed: Current response time in seconds
            baseline_status: Baseline status code for comparison
            baseline_size: Baseline response body size
            baseline_elapsed: Baseline response time in seconds

        Returns:
            Tuple of (is_anomalous, reason_string)
        """
        reasons: List[str] = []

        if status is not None and baseline_status is not None:
            if status != baseline_status:
                if self.is_interesting_status(status):
                    reasons.append(f"status_changed:{baseline_status}->{status}")

        if size is not None and baseline_size is not None and baseline_size > 0:
            size_diff = abs(size - baseline_size)
            size_ratio = size_diff / max(baseline_size, 1)
            if size_ratio > self.size_threshold:
                reasons.append(f"size_delta:{size_diff}b({size_ratio:.1%})")

        if elapsed > 0 and baseline_elapsed > 0:
            time_diff = elapsed - baseline_elapsed
            if time_diff > self.time_threshold:
                reasons.append(f"time_delta:{time_diff:.1f}s")
            elif elapsed > 10 and baseline_elapsed < 1:
                reasons.append(f"slow_response:{elapsed:.1f}s")

        is_anomalous = len(reasons) > 0
        reason = "; ".join(reasons) if reasons else ""
        return is_anomalous, reason

    def find_patterns(self, body: str) -> List[str]:
        """Search response body for interesting security patterns.

        Looks for common indicators like error messages, stack traces,
        debug output, and configuration disclosures.

        Args:
            body: Response body text

        Returns:
            List of matched pattern descriptions
        """
        patterns: List[str] = []
        checks: Dict[str, str] = {
            "stack_trace": r"(?:Traceback|at\s+\w+\.\w+|in\s+[/\w]+\.\w+:\d+)",
            "sql_error": r"(?:SQL syntax|ORA-\d{5}|MySQL error|PostgreSQL|SQLite)",
            "debug_enabled": r"(?:DEBUG\s*=\s*True|debug_mode|APP_DEBUG)",
            "path_disclosure": r"(?:Warning:\s+include\(|Fatal error.*?on line \d+)",
            "internal_ip": r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)",
            "api_key_leak": r"(?:api[_-]?key['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,})",
            "jwt_token": r"eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+",
            "cloud_metadata": r"(?:s3\.amazonaws|storage\.googleapis|blob\.core\.windows)",
        }
        for name, pattern in checks.items():
            if re.search(pattern, body, re.IGNORECASE):
                patterns.append(name)
        return patterns


class WordlistManager:
    """Manages built-in and custom wordlists for endpoint fuzzing.

    Provides dictionary-based wordlists for paths, admin endpoints, backup
    files, API endpoints, parameters, and extensions. Supports loading
    custom wordlists from external files and combining multiple sources.

    Attributes:
        custom_wordlist: Optional path to a custom wordlist file
        loaded_words: Set of words loaded from custom file
    """

    COMMON_PATHS: List[str] = [
        "admin", "api", "v1", "v2", "v3", "test", "dev", "uat", "staging",
        "backup", "temp", "tmp", "logs", "log", "debug", "internal",
        "private", "restricted", "secure", "hidden", "secret", "config",
        "configuration", "settings", "setup", "install", "installer",
        "docs", "documentation", "swagger", "api-docs", "api/v1", "api/v2",
        "graphql", "gql", "rest", "soap", "xmlrpc", "webhook", "callback",
        "health", "healthz", "status", "ping", "metrics", "info",
        "version", "version.txt", "robots.txt", "sitemap.xml", "crossdomain.xml",
        ".well-known", ".well-known/security.txt", ".env", ".git/config",
        "wp-admin", "wp-content", "wp-includes", "administrator",
        "cgi-bin", "cgi-bin/status", "cgi-bin/test.cgi",
        "phpmyadmin", "phpinfo.php", "info.php", "test.php",
        "server-status", "server-info",
    ]

    ADMIN_PATHS: List[str] = [
        "admin", "administrator", "admincp", "adminarea", "adminportal",
        "admin/login", "admin/login.php", "admin/index.php",
        "admin/dashboard", "admin/users", "admin/settings", "admin/config",
        "admin/panel", "admin/console", "admin/backup",
        "admin/export", "admin/import", "admin/logs",
        "manage", "manager", "management", "management/console",
        "dashboard", "panel", "controlpanel", "cpanel",
        "backend", "backoffice", "back-office",
        "operator", "operations",
        "sysadmin", "system", "system/admin",
        "root", "super", "superadmin",
        "cp", "control", "controls",
        "moderator", "mod", "modcp",
    ]

    BACKUP_PATHS: List[str] = [
        "backup", "backups", "dump", "dumps", "export", "exports",
        "db_backup", "database_backup", "db-export",
        "backup.sql", "backup.tar.gz", "backup.zip",
        "database.sql", "db.sql", "data.sql",
        "dump.sql", "export.sql", "export.json", "export.xml",
        "backup.db", "data.db", "storage.db",
        "old", "bak", "backup.old", "backup.bak",
        "www.tar.gz", "www.zip", "htdocs.tar.gz",
        "site.tar.gz", "site-backup.tar.gz",
    ]

    API_PATHS: List[str] = [
        "api", "api/v1", "api/v2", "api/v3", "api/rest",
        "api/graphql", "api/soap", "api/xmlrpc",
        "api/users", "api/user", "api/admin", "api/auth",
        "api/login", "api/logout", "api/register",
        "api/token", "api/refresh", "api/verify",
        "api/upload", "api/upload.php",
        "api/download", "api/export", "api/import",
        "api/config", "api/settings", "api/health",
        "api/status", "api/metrics", "api/info",
        "api/search", "api/query", "api/filter",
        "swagger", "swagger.json", "swagger/ui",
        "api-docs", "api-docs.json", "docs/api",
        "openapi.json", "openapi.yaml",
        "graphql", "graphiql", "graphql/console",
    ]

    EXTENSIONS: List[str] = [
        ".php", ".php3", ".php4", ".php5", ".phtml",
        ".asp", ".aspx", ".ashx", ".asmx", ".svc",
        ".jsp", ".jspx", ".do", ".action",
        ".json", ".xml", ".yaml", ".yml",
        ".config", ".conf", ".ini", ".cfg",
        ".bak", ".old", ".swp", ".save", ".orig",
        ".tar.gz", ".zip", ".rar", ".7z", ".gz",
        ".txt", ".log", ".inc", ".sql", ".db",
        ".sqlite", ".sqlite3", ".mdb", ".accdb",
        ".env", ".htaccess", ".htpasswd",
        ".git", ".svn", ".DS_Store",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx",
        ".csv", ".tsv", ".md", ".rst",
        ".js", ".css", ".map", ".min.js",
    ]

    COMMON_PARAMS: List[str] = [
        "id", "user_id", "userId", "uid", "username", "email",
        "token", "api_key", "apiKey", "secret", "auth", "session",
        "page", "limit", "offset", "sort", "order", "dir",
        "q", "query", "search", "term", "debug", "verbose",
        "callback", "redirect", "url", "next", "return",
        "format", "type", "lang", "locale", "admin", "test",
        "timestamp", "nonce", "sig", "signature", "hmac",
        "access_token", "refresh_token", "accessToken",
        "include", "exclude", "fields", "expand", "embed",
        "role", "permission", "group", "org", "organization",
        "file", "filename", "path", "dir", "template",
        "command", "exec", "run", "system", "shell",
        "action", "method", "func", "function", "mode",
        "view", "display", "show", "index", "list",
        "create", "update", "delete", "remove", "edit",
        "upload", "download", "import", "export", "backup",
    ]

    PARAM_VALUES: List[str] = [
        "", "1", "0", "true", "false", "null", "undefined",
        "admin", "root", "test", "demo", "guest",
        "../../etc/passwd", "..\\windows\\win.ini",
        "<script>alert(1)</script>", "' OR 1=1--",
        "http://localhost", "https://127.0.0.1",
        "{{7*7}}", "${7*7}",
        '{"$gt": ""}', '{"$ne": ""}',
    ]

    def __init__(self, custom_wordlist_path: Optional[str] = None):
        """Initialize the wordlist manager.

        Args:
            custom_wordlist_path: Optional path to custom wordlist file
        """
        self.custom_wordlist_path = custom_wordlist_path
        self.loaded_words: Set[str] = set()
        if custom_wordlist_path:
            self._load_custom_wordlist()

    def _load_custom_wordlist(self) -> None:
        """Load words from custom wordlist file.

        Reads each non-empty, non-comment line from the file.

        Raises:
            FileNotFoundError: If the wordlist file does not exist
            PermissionError: If the wordlist file cannot be read
        """
        try:
            with open(self.custom_wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    word = line.strip()
                    if word and not word.startswith("#"):
                        self.loaded_words.add(word)
            logger.info("Loaded %d words from %s", len(self.loaded_words), self.custom_wordlist_path)
        except FileNotFoundError:
            logger.warning("Custom wordlist not found: %s", self.custom_wordlist_path)
        except PermissionError:
            logger.error("Permission denied reading wordlist: %s", self.custom_wordlist_path)
        except Exception as e:
            logger.error("Error loading wordlist %s: %s", self.custom_wordlist_path, e)

    def get_paths(self, include_custom: bool = True) -> List[str]:
        """Return combined path wordlist.

        Args:
            include_custom: Whether to include custom wordlist entries

        Returns:
            List of path strings
        """
        paths: List[str] = list(set(self.COMMON_PATHS + self.ADMIN_PATHS + self.BACKUP_PATHS + self.API_PATHS))
        if include_custom and self.loaded_words:
            paths.extend(w for w in self.loaded_words if w not in paths)
        return paths

    def get_admin_paths(self) -> List[str]:
        """Return admin-specific path wordlist."""
        return list(self.ADMIN_PATHS)

    def get_extensions(self, include_custom: bool = True) -> List[str]:
        """Return file extension wordlist.

        Args:
            include_custom: Whether to include custom wordlist entries

        Returns:
            List of extension strings (including leading dot)
        """
        exts = list(self.EXTENSIONS)
        if include_custom and self.loaded_words:
            exts.extend(w for w in self.loaded_words if w.startswith(".") and w not in exts)
        return exts

    def get_params(self) -> List[str]:
        """Return common parameter name wordlist."""
        return list(self.COMMON_PARAMS)

    def get_param_values(self) -> List[str]:
        """Return parameter value wordlist for injection testing."""
        return list(self.PARAM_VALUES)


class BaselineComparator:
    """Compares fuzz responses against a baseline response reference.

    Establishes a baseline by requesting the target with default parameters,
    then compares subsequent responses to detect meaningful differences
    that may indicate vulnerabilities or interesting behavior.

    Attributes:
        baseline: Dictionary of baseline response attributes
        analyzer: ResponseAnalyzer instance for anomaly detection
    """

    def __init__(self, analyzer: Optional[ResponseAnalyzer] = None):
        """Initialize the baseline comparator.

        Args:
            analyzer: ResponseAnalyzer instance (creates default if None)
        """
        self.baseline: Dict[str, Any] = {}
        self.analyzer = analyzer or ResponseAnalyzer()

    def establish(self, result: FuzzResult) -> Dict[str, Any]:
        """Set the baseline from a fuzz result.

        Args:
            result: FuzzResult to use as baseline

        Returns:
            Baseline dictionary with status, size, body_hash, elapsed
        """
        self.baseline = {
            "status": result.status,
            "size": result.size,
            "body_hash": result.body_hash,
            "elapsed": result.elapsed,
            "content_type": result.content_type,
            "url": result.url,
        }
        logger.debug("Baseline established: status=%s, size=%s", result.status, result.size)
        return self.baseline

    def is_established(self) -> bool:
        """Check whether a baseline has been established.

        Returns:
            True if baseline exists
        """
        return bool(self.baseline)

    def compare(self, result: FuzzResult) -> Tuple[bool, str]:
        """Compare a fuzz result against the current baseline.

        Args:
            result: FuzzResult to compare

        Returns:
            Tuple of (is_anomalous, reason_string)
        """
        if not self.baseline:
            return False, "no_baseline"
        return self.analyzer.detect_anomaly(
            status=result.status,
            size=result.size,
            elapsed=result.elapsed,
            baseline_status=self.baseline.get("status"),
            baseline_size=self.baseline.get("size"),
            baseline_elapsed=self.baseline.get("elapsed", 0.0),
        )

    def compare_body_hash(self, result: FuzzResult) -> bool:
        """Compare body hash against baseline.

        Args:
            result: FuzzResult with body_hash to compare

        Returns:
            True if body hash differs from baseline (may indicate different content)
        """
        if not self.baseline or not result.body_hash:
            return False
        baseline_hash = self.baseline.get("body_hash")
        if not baseline_hash:
            return False
        return result.body_hash != baseline_hash

    def compare_content_type(self, result: FuzzResult) -> bool:
        """Compare content type against baseline.

        Args:
            result: FuzzResult with content_type to compare

        Returns:
            True if content type differs from baseline
        """
        if not self.baseline:
            return False
        return result.content_type != self.baseline.get("content_type", "")

    def reset(self) -> None:
        """Clear the baseline."""
        self.baseline = {}
        logger.debug("Baseline reset")


class EndpointFuzzer:
    """Main endpoint fuzzer orchestrator with complete fuzzing pipeline.

    Coordinates wordlist generation, request execution, response analysis,
    baseline comparison, and recursive discovery. Supports multi-threaded
    execution with configurable delay and output in multiple formats.

    Attributes:
        base_url: Target base URL
        wordlist_manager: WordlistManager for path/param/extension lists
        response_analyzer: ResponseAnalyzer for anomaly detection
        baseline_comparator: BaselineComparator for baseline comparison
        results: List of completed FuzzResult objects
        discovered_paths: Set of discovered paths for recursive fuzzing
        threads: Number of concurrent threads
        delay: Delay between requests in seconds
        timeout: Request timeout in seconds
        session: HTTP session (requests library or None)
    """

    METHODS: List[str] = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"]

    AUTH_BYPASS_HEADERS: Dict[str, str] = {
        "X-Forwarded-For": "127.0.0.1",
        "X-Real-IP": "127.0.0.1",
        "X-Originating-IP": "127.0.0.1",
        "X-Remote-IP": "127.0.0.1",
        "X-Client-IP": "127.0.0.1",
        "X-Host": "localhost",
        "X-Forwarded-Host": "localhost",
        "X-Role": "admin",
        "X-Admin": "true",
        "X-Is-Admin": "true",
        "X-Privilege": "admin",
        "X-Auth-Roles": "admin",
    }

    def __init__(
        self,
        base_url: str,
        wordlist_path: Optional[str] = None,
        threads: int = 5,
        delay: float = 0.0,
        timeout: int = 15,
        filter_size: Optional[int] = None,
        filter_code: Optional[Set[int]] = None,
        allow_insecure: bool = False,
    ):
        """Initialize the endpoint fuzzer.

        Args:
            base_url: Target base URL
            wordlist_path: Optional custom wordlist file path
            threads: Number of concurrent threads
            delay: Delay between requests in seconds
            timeout: Request timeout in seconds
            filter_size: Response bodies of this exact size will be filtered out
            filter_code: Set of status codes to filter out
        """
        self.base_url = base_url.rstrip("/")
        self.wordlist_path = wordlist_path
        self.threads = max(1, threads)
        self.delay = max(0.0, delay)
        self.timeout = max(1, timeout)
        self.filter_size = filter_size
        self.filter_code = filter_code or set()
        self.allow_insecure = allow_insecure

        self.wordlist_manager = WordlistManager(wordlist_path)
        self.response_analyzer = ResponseAnalyzer()
        self.baseline_comparator = BaselineComparator(self.response_analyzer)
        self.results: List[FuzzResult] = []
        self.discovered_paths: Set[str] = set()
        self.session: Optional[Any] = None
        self._init_session()

    def _init_session(self) -> None:
        """Initialize HTTP session with default headers.

        Uses the requests library if available; falls back gracefully.
        Sets common browser-like User-Agent and default Accept header.
        """
        try:
            import requests as req
            self.session = req.Session()
            self.session.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.5",
            })
            self.session.verify = False
            logger.debug("HTTP session initialized with requests library")
        except ImportError:
            logger.warning("requests library not available; using urllib fallback")
            self.session = None

    def _request(
        self,
        url: str,
        method: str = "GET",
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
    ) -> Optional[FuzzResult]:
        """Execute a single HTTP request and return the result.

        Args:
            url: Full target URL
            method: HTTP method
            params: Query string parameters
            headers: Additional HTTP headers
            data: Request body data (for POST/PUT/PATCH)

        Returns:
            FuzzResult with response data, or None on critical failure
        """
        result = FuzzResult(url=url, method=method.upper(), params=params or {})

        if self.delay > 0:
            time.sleep(self.delay)

        all_headers: Dict[str, str] = {}
        if headers:
            all_headers.update(headers)

        if params:
            query_string = urllib.parse.urlencode(params, doseq=True)
            full_url = f"{url}?{query_string}"
        else:
            full_url = url

        result.url = full_url

        try:
            if self.session is not None:
                start = time.time()
                resp = self.session.request(
                    method.upper(),
                    full_url,
                    headers=all_headers or None,
                    data=data,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                elapsed = time.time() - start
                result.status = resp.status_code
                result.size = len(resp.content)
                result.body_hash = hashlib.md5(resp.content).hexdigest()
                result.elapsed = elapsed
                result.content_type = resp.headers.get("Content-Type", "")
            else:
                result = self._urllib_request(full_url, method, all_headers, data)
        except Exception as e:
            result.error = str(e)
            logger.debug("Request failed: %s %s - %s", method, full_url, e)

        return result

    def _urllib_request(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        data: Optional[Dict[str, str]] = None,
    ) -> FuzzResult:
        """Fallback HTTP request using urllib (no requests library).

        Args:
            url: Full target URL
            method: HTTP method
            headers: HTTP headers
            data: Request body data

        Returns:
            FuzzResult with response data
        """
        result = FuzzResult(url=url, method=method.upper())
        if len(url) > _MAX_URL_LENGTH:
            result.error = f"URL exceeds max length ({len(url)} > {_MAX_URL_LENGTH})"
            return result
        try:
            ctx = ssl.create_default_context()
            if self.allow_insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(url, headers=headers, method=method.upper())

            if data:
                encoded = urllib.parse.urlencode(data).encode("utf-8")
                req.data = encoded

            start = time.time()
            resp = urllib.request.urlopen(req, timeout=self.timeout, context=ctx)
            elapsed = time.time() - start

            body = resp.read()
            result.status = resp.status
            result.size = len(body)
            result.body_hash = hashlib.md5(body).hexdigest()
            result.elapsed = elapsed
            result.content_type = resp.headers.get("Content-Type", "")
            resp.close()
        except urllib.error.HTTPError as e:
            elapsed = time.time() - start  # type: ignore
            result.status = e.code
            result.elapsed = elapsed
            try:
                body = e.read()
                result.size = len(body)
                result.body_hash = hashlib.md5(body).hexdigest()
            except Exception:
                pass
        except Exception as e:
            result.error = str(e)
        return result

    def _should_filter(self, result: FuzzResult) -> bool:
        """Determine if a result should be filtered out.

        Args:
            result: FuzzResult to check

        Returns:
            True if the result should be excluded from output
        """
        if result.error:
            return False
        if self.filter_size is not None and result.size == self.filter_size:
            return True
        if result.status in self.filter_code:
            return True
        return False

    def fuzz_paths(
        self,
        paths: Optional[List[str]] = None,
        extensions: Optional[List[str]] = None,
        methods: Optional[List[str]] = None,
    ) -> List[FuzzResult]:
        """Fuzz endpoints by combining paths with extensions and methods.

        Tests each path with each extension and each HTTP method.

        Args:
            paths: List of path segments to test (uses wordlist if None)
            extensions: List of extensions to append (uses wordlist if None)
            methods: List of HTTP methods to test (defaults to GET, POST)

        Returns:
            List of FuzzResult objects
        """
        path_list = paths or self.wordlist_manager.get_paths()
        ext_list = extensions or [""]
        method_list = methods or ["GET", "POST"]
        generated: List[FuzzResult] = []

        for path in path_list:
            for ext in ext_list:
                full_path = f"{path}{ext}"
                url = f"{self.base_url}/{full_path.lstrip('/')}"
                for method in method_list:
                    result = FuzzResult(
                        description=f"path_fuzz:{full_path}",
                        url=url,
                        method=method,
                        path=full_path,
                        extension=ext,
                    )
                    generated.append(result)

        logger.info("Generated %d path fuzz variants", len(generated))
        return generated

    def fuzz_extensions(
        self,
        base_paths: Optional[List[str]] = None,
        extensions: Optional[List[str]] = None,
    ) -> List[FuzzResult]:
        """Fuzz file extensions on given base paths.

        Args:
            base_paths: List of base paths (uses wordlist if None)
            extensions: List of extensions to try (uses wordlist if None)

        Returns:
            List of FuzzResult objects
        """
        base_list = base_paths or ["index", "config", "admin", "backup", "api", "app", "main", "test"]
        ext_list = extensions or self.wordlist_manager.get_extensions()
        generated: List[FuzzResult] = []

        for base in base_list:
            for ext in ext_list:
                path = f"{base}{ext}"
                url = f"{self.base_url}/{path}"
                result = FuzzResult(
                    description=f"ext_fuzz:{path}",
                    url=url,
                    method="GET",
                    path=path,
                    extension=ext,
                )
                generated.append(result)

        logger.info("Generated %d extension fuzz variants", len(generated))
        return generated

    def fuzz_methods(
        self,
        target_path: str = "",
        methods: Optional[List[str]] = None,
    ) -> List[FuzzResult]:
        """Fuzz HTTP methods on a specific path.

        Tests each HTTP method to discover alternative method support.

        Args:
            target_path: Path to test (uses base URL root if empty)
            methods: List of methods to test (all methods if None)

        Returns:
            List of FuzzResult objects
        """
        method_list = methods or self.METHODS
        url = f"{self.base_url}/{target_path.lstrip('/')}" if target_path else self.base_url
        generated: List[FuzzResult] = []

        for method in method_list:
            result = FuzzResult(
                description=f"method_fuzz:{method}",
                url=url,
                method=method,
            )
            generated.append(result)

        logger.info("Generated %d method fuzz variants", len(generated))
        return generated

    def fuzz_params(
        self,
        target_path: str = "",
        params: Optional[List[str]] = None,
        values: Optional[List[str]] = None,
        method: str = "GET",
    ) -> List[FuzzResult]:
        """Fuzz query parameters on a target path.

        Tests adding common parameters with various values to discover
        hidden functionality or parameter-based vulnerabilities.

        Args:
            target_path: Path to target
            params: List of parameter names (uses wordlist if None)
            values: List of values to try (uses wordlist if None)
            method: HTTP method to use

        Returns:
            List of FuzzResult objects
        """
        param_list = params or self.wordlist_manager.get_params()
        value_list = values or self.wordlist_manager.get_param_values()
        url = f"{self.base_url}/{target_path.lstrip('/')}" if target_path else self.base_url
        generated: List[FuzzResult] = []

        for param_name in param_list:
            for val in value_list[:5]:
                result = FuzzResult(
                    description=f"param_fuzz:{param_name}={val}",
                    url=url,
                    method=method,
                    params={param_name: val},
                )
                generated.append(result)

        logger.info("Generated %d parameter fuzz variants", len(generated))
        return generated

    def fuzz_access_control(
        self,
        paths: Optional[List[str]] = None,
    ) -> List[FuzzResult]:
        """Test access control by sending auth bypass headers.

        For each target path, sends requests with common auth bypass
        headers (X-Forwarded-For, X-Role, etc.) to detect access
        control vulnerabilities.

        Args:
            paths: List of paths to test (uses admin wordlist if None)

        Returns:
            List of FuzzResult objects
        """
        path_list = paths or self.wordlist_manager.get_admin_paths()
        generated: List[FuzzResult] = []

        for path in path_list:
            url = f"{self.base_url}/{path.lstrip('/')}"
            for header_name, header_value in self.AUTH_BYPASS_HEADERS.items():
                result = FuzzResult(
                    description=f"ac_test:{path}:{header_name}",
                    url=url,
                    method="GET",
                    headers={header_name: header_value},
                    path=path,
                )
                generated.append(result)

        logger.info("Generated %d access control test variants", len(generated))
        return generated

    def execute(
        self,
        variants: List[FuzzResult],
        establish_baseline: bool = True,
    ) -> List[FuzzResult]:
        """Execute fuzz variants and analyze responses.

        Runs the given variants (sequentially or concurrently based on
        thread count), optionally establishes a baseline, analyzes
        responses, and stores results.

        Args:
            variants: List of FuzzResult objects to execute
            establish_baseline: Whether to establish baseline before fuzzing

        Returns:
            List of completed FuzzResult objects with response data
        """
        if not variants:
            logger.warning("No variants to execute")
            return []

        if establish_baseline:
            baseline_result = self._request(self.base_url, "GET")
            if baseline_result:
                self.baseline_comparator.establish(baseline_result)
                logger.info("Baseline: status=%s, size=%s, time=%.2fs",
                           baseline_result.status, baseline_result.size, baseline_result.elapsed)

        executed: List[FuzzResult] = []

        if self.threads > 1 and len(variants) > 1:
            executed = self._execute_concurrent(variants)
        else:
            executed = self._execute_sequential(variants)

        self.results.extend(executed)
        return executed

    def _execute_sequential(self, variants: List[FuzzResult]) -> List[FuzzResult]:
        """Execute variants sequentially.

        Args:
            variants: List of FuzzResult objects

        Returns:
            List of completed results
        """
        completed: List[FuzzResult] = []
        total = len(variants)
        for idx, variant in enumerate(variants, 1):
            result = self._request(
                variant.url,
                variant.method,
                variant.params,
                variant.headers,
                variant.data,
            )
            if result and variant.description:
                result.description = variant.description
                result.path = variant.path
                result.extension = variant.extension

            if result and self.baseline_comparator.is_established():
                is_anom, reason = self.baseline_comparator.compare(result or variant)
                if result:
                    result.anomalous = is_anom
                    result.anomaly_reason = reason

            if result and self._should_filter(result):
                logger.debug("Filtered: %s %s", variant.method, variant.url)
            elif result:
                completed.append(result)

            if idx % 50 == 0:
                logger.info("Progress: %d/%d", idx, total)

        return completed

    def _execute_concurrent(self, variants: List[FuzzResult]) -> List[FuzzResult]:
        """Execute variants concurrently using thread pool.

        Args:
            variants: List of FuzzResult objects

        Returns:
            List of completed results
        """
        completed: List[Optional[FuzzResult]] = [None] * len(variants)

        def _worker(idx: int, variant: FuzzResult) -> Tuple[int, Optional[FuzzResult]]:
            result = self._request(
                variant.url,
                variant.method,
                variant.params,
                variant.headers,
                variant.data,
            )
            if result and variant.description:
                result.description = variant.description
                result.path = variant.path
                result.extension = variant.extension

            if result and self.baseline_comparator.is_established():
                is_anom, reason = self.baseline_comparator.compare(result or variant)
                if result:
                    result.anomalous = is_anom
                    result.anomaly_reason = reason

            if result and self._should_filter(result):
                return idx, None
            return idx, result

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(_worker, idx, variant): idx
                for idx, variant in enumerate(variants)
            }
            for future in concurrent.futures.as_completed(futures):
                try:
                    idx, result = future.result(timeout=self.timeout + 10)
                    completed[idx] = result
                except Exception as e:
                    idx = futures[future]
                    logger.debug("Concurrent task %d failed: %s", idx, e)

        return [r for r in completed if r is not None]

    def recursive_fuzz(
        self,
        initial_paths: Optional[List[str]] = None,
        max_depth: int = 2,
    ) -> List[FuzzResult]:
        """Perform recursive path discovery.

        Starts with initial paths, fuzzes them, extracts any new paths
        from responses, and fuzzes those as well up to max_depth.

        Args:
            initial_paths: Starting paths (uses wordlist if None)
            max_depth: Maximum recursion depth (default 2)

        Returns:
            All FuzzResult objects from all depths
        """
        all_results: List[FuzzResult] = []
        paths_to_fuzz: Set[str] = set(initial_paths or self.wordlist_manager.get_paths()[:20])
        already_fuzzed: Set[str] = set()
        depth = 0

        while paths_to_fuzz and depth < max_depth:
            current_paths = list(paths_to_fuzz - already_fuzzed)
            if not current_paths:
                break

            already_fuzzed.update(current_paths)
            logger.info("Recursive depth %d: fuzzing %d paths", depth + 1, len(current_paths))

            variants = self.fuzz_paths(paths=current_paths, methods=["GET"])
            results = self.execute(variants, establish_baseline=(depth == 0))
            all_results.extend(results)

            new_paths = self._extract_paths_from_results(results)
            paths_to_fuzz.update(new_paths)

            depth += 1

        self.discovered_paths.update(paths_to_fuzz)
        logger.info("Recursive fuzzing complete. Total unique paths: %d", len(self.discovered_paths))
        return all_results

    def _extract_paths_from_results(self, results: List[FuzzResult]) -> Set[str]:
        """Extract new paths from successful response URLs.

        Looks at redirect locations and response body for discoverable paths.

        Args:
            results: List of completed FuzzResult objects

        Returns:
            Set of newly discovered path strings
        """
        new_paths: Set[str] = set()
        for r in results:
            if r.status in (301, 302, 307, 308) and r.headers.get("Location"):
                loc = r.headers["Location"]
                parsed = urllib.parse.urlparse(loc)
                path = parsed.path.strip("/")
                if path and path not in new_paths:
                    new_paths.add(path)
        return new_paths

    def get_anomalies(self) -> List[FuzzResult]:
        """Return all results flagged as anomalous.

        Returns:
            List of anomalous FuzzResult objects
        """
        return [r for r in self.results if r.anomalous]

    def get_summary(self) -> Dict[str, Any]:
        """Generate a summary dictionary of fuzzing results.

        Returns:
            Dictionary with counts, status distribution, and timing
        """
        total = len(self.results)
        anomalies = self.get_anomalies()
        status_dist: Dict[str, int] = collections.Counter(
            self.response_analyzer.classify_status(r.status) if r.status else "unknown"
            for r in self.results
        )
        status_raw: Dict[str, int] = collections.Counter(
            str(r.status) if r.status else "error" for r in self.results
        )
        total_time = sum(r.elapsed for r in self.results)
        avg_time = total_time / max(total, 1)

        return {
            "target": self.base_url,
            "total_requests": total,
            "anomalies": len(anomalies),
            "status_distribution": dict(status_dist),
            "status_codes": dict(sorted(status_raw.items())),
            "average_time_s": round(avg_time, 3),
            "total_time_s": round(total_time, 3),
            "paths_discovered": len(self.discovered_paths),
            "threads": self.threads,
        }

    def export_json(self, filepath: str) -> None:
        """Export results to JSON file.

        Args:
            filepath: Output file path

        Raises:
            OSError: If the file cannot be written
        """
        filepath = _validate_output_path(filepath)
        try:
            os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
        except OSError:
            pass
        data = {
            "summary": self.get_summary(),
            "results": [r.to_dict() for r in self.results],
            "anomalies": [r.to_dict() for r in self.get_anomalies()],
            "discovered_paths": sorted(self.discovered_paths),
        }
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            logger.info("Results exported to %s", filepath)
        except OSError as e:
            logger.error("Failed to export JSON: %s", e)
            raise

    def export_csv(self, filepath: str) -> None:
        """Export results to CSV file.

        Args:
            filepath: Output file path

        Raises:
            OSError: If the file cannot be written
        """
        filepath = _validate_output_path(filepath)
        try:
            os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
        except OSError:
            pass
        try:
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Description", "Method", "URL", "Status", "Size",
                    "Elapsed", "ContentType", "Anomalous", "Reason",
                ])
                for r in self.results:
                    writer.writerow([
                        r.description, r.method, r.url, r.status, r.size,
                        round(r.elapsed, 4), r.content_type, r.anomalous, r.anomaly_reason,
                    ])
            logger.info("Results exported to %s", filepath)
        except OSError as e:
            logger.error("Failed to export CSV: %s", e)
            raise


def setup_argparse() -> argparse.ArgumentParser:
    """Configure and return the argument parser for CLI usage.

    Returns:
        Configured ArgumentParser with all command-line options
    """
    parser = argparse.ArgumentParser(
        prog="endpoint_fuzzer.py",
        description="Endpoint Fuzzing Tool — Path discovery, method fuzzing, "
                    "extension enumeration, parameter fuzzing, and access control testing.",
        epilog=textwrap.dedent("""
            Examples:
              %(prog)s --target https://example.com
              %(prog)s --target https://example.com/api --extensions --threads 10
              %(prog)s --target https://example.com --wordlist custom.txt --methods GET,POST
              %(prog)s --target https://example.com/admin --recursive --delay 0.5
              %(prog)s --target https://example.com --filter-code 404 --json results.json
        """),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        type=str,
        help="Target base URL (e.g., https://example.com)",
    )
    parser.add_argument(
        "--wordlist", "-w",
        type=str,
        default=None,
        help="Custom wordlist file (one entry per line)",
    )
    parser.add_argument(
        "--methods", "-m",
        type=str,
        default="GET,POST",
        help="Comma-separated HTTP methods to test (default: GET,POST)",
    )
    parser.add_argument(
        "--extensions", "-e",
        action="store_true",
        help="Enable extension fuzzing (.php, .asp, .bak, etc.)",
    )
    parser.add_argument(
        "--params",
        action="store_true",
        help="Enable parameter fuzzing",
    )
    parser.add_argument(
        "--ac-test",
        action="store_true",
        help="Enable access control bypass testing",
    )
    parser.add_argument(
        "--recursive", "-r",
        type=int,
        default=0,
        const=2,
        nargs="?",
        help="Enable recursive discovery (optional depth, default: 2)",
    )
    parser.add_argument(
        "--threads", "-T",
        type=int,
        default=5,
        help="Number of concurrent threads (default: 5)",
    )
    parser.add_argument(
        "--delay", "-d",
        type=float,
        default=0.0,
        help="Delay between requests in seconds (default: 0)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="Request timeout in seconds (default: 15)",
    )
    parser.add_argument(
        "--filter-size",
        type=int,
        default=None,
        help="Filter out responses with exact body size",
    )
    parser.add_argument(
        "--filter-code",
        type=str,
        default=None,
        help="Comma-separated status codes to filter (e.g., 404,403)",
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Output file path (auto-detects format from extension)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Force JSON output format",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose (debug) logging",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 2.0.0",
        help="Show version and exit",
    )
    parser.add_argument(
        "--allow-insecure", action="store_true",
        help="Allow insecure SSL connections (skip certificate verification)",
    )
    return parser


def parse_filter_code(value: Optional[str]) -> Set[int]:
    """Parse comma-separated filter codes string into a set of integers.

    Args:
        value: Comma-separated status codes (e.g., "404,403,500")

    Returns:
        Set of integer status codes
    """
    if not value:
        return set()
    codes: Set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if part.isdigit():
            codes.add(int(part))
    return codes


def main() -> None:
    """Main entry point for the endpoint fuzzer CLI.

    Parses arguments, configures logging, initializes the fuzzer,
    runs the selected fuzzing modes, and exports results.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    filter_codes = parse_filter_code(args.filter_code)
    method_list = [m.strip().upper() for m in args.methods.split(",") if m.strip().upper() in EndpointFuzzer.METHODS]
    if not method_list:
        method_list = ["GET"]

    logger.info("Target: %s", args.target)
    logger.info("Methods: %s", ", ".join(method_list))
    logger.info("Threads: %d, Delay: %.1fs", args.threads, args.delay)

    fuzzer = EndpointFuzzer(
        base_url=args.target,
        wordlist_path=args.wordlist,
        threads=args.threads,
        delay=args.delay,
        timeout=args.timeout,
        filter_size=args.filter_size,
        filter_code=filter_codes,
        allow_insecure=args.allow_insecure,
    )

    all_variants: List[FuzzResult] = []

    try:
        path_variants = fuzzer.fuzz_paths(methods=method_list)
        all_variants.extend(path_variants)
        logger.info("Path fuzzing: %d variants", len(path_variants))

        if args.extensions:
            ext_variants = fuzzer.fuzz_extensions()
            all_variants.extend(ext_variants)
            logger.info("Extension fuzzing: %d variants", len(ext_variants))

        if args.params:
            param_variants = fuzzer.fuzz_params()
            all_variants.extend(param_variants)
            logger.info("Parameter fuzzing: %d variants", len(param_variants))

        if args.ac_test:
            ac_variants = fuzzer.fuzz_access_control()
            all_variants.extend(ac_variants)
            logger.info("Access control tests: %d variants", len(ac_variants))

        if args.recursive and args.recursive > 0:
            logger.info("Running recursive fuzzing (depth: %d)", args.recursive)
            results = fuzzer.recursive_fuzz(max_depth=args.recursive)
        else:
            results = fuzzer.execute(all_variants, establish_baseline=True)

        summary = fuzzer.get_summary()
        anomalies = fuzzer.get_anomalies()

        print("\n" + "=" * 60)
        print("ENDPOINT FUZZER RESULTS")
        print("=" * 60)
        print(f"Target:            {summary['target']}")
        print(f"Total Requests:    {summary['total_requests']}")
        print(f"Anomalies Found:   {summary['anomalies']}")
        print(f"Avg Response Time: {summary['average_time_s']:.3f}s")
        print(f"Status Distribution:")
        for cls, count in sorted(summary['status_distribution'].items()):
            print(f"  {cls}: {count}")
        print(f"Paths Discovered:  {summary['paths_discovered']}")
        print("-" * 60)

        if anomalies:
            print(f"\nTop Anomalies ({len(anomalies)} total):")
            for a in anomalies[:20]:
                print(f"  [{a.status}] {a.method} {a.url}")
                if a.anomaly_reason:
                    print(f"    Reason: {a.anomaly_reason}")
                if a.anomaly_reason:
                    print(f"    Patterns: {a.anomaly_reason}")

        if args.output:
            output_path = args.output
            if args.json or output_path.endswith(".json"):
                fuzzer.export_json(output_path)
            elif output_path.endswith(".csv"):
                fuzzer.export_csv(output_path)
            else:
                fuzzer.export_json(f"{output_path}.json")
                logger.info("No recognized format; saved as JSON")

        elif anomalies:
            default_output = f"fuzz_results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            fuzzer.export_json(default_output)
            logger.info("Results saved to %s", default_output)

    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        print("\n[!] Fuzzing interrupted. Partial results may be available.")
        if fuzzer.results:
            partial = f"fuzz_partial_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            fuzzer.export_json(partial)
            print(f"[!] Partial results saved to {partial}")
        sys.exit(130)
    except Exception as e:
        logger.error("Fuzzing failed: %s", e)
        print(f"\n[!] Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        logger.info("Endpoint fuzzing completed")


if __name__ == "__main__":
    main()
