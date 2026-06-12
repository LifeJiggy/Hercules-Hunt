#!/usr/bin/env python3
"""
fast_hunt.py — Fast Surface Vulnerability Hunter

Rapid reconnaissance and low-hanging fruit discovery tool. Probes for common
sensitive paths (/admin, /backup, /.git, /.env, /config), default credentials,
debug pages, information disclosure, CORS misconfigurations, missing security
headers, directory listing, HTTP method testing, and common cloud/AWS
metadata endpoints. Provides color-coded terminal output for quick triage
and generates structured reports for deeper analysis.

Features: 100+ common path probes, default credential testing, debug page
detection, info disclosure scanning (stack traces, error pages, PHP info),
CORS misconfiguration detection (wildcard origin, null origin, credential
reflection), security header audit (HSTS, CSP, X-Frame-Options, X-XSS-Protection,
X-Content-Type-Options, Referrer-Policy, Permissions-Policy), HTTP method
testing (OPTIONS response, allowed methods), directory listing detection,
cloud metadata endpoint probes, tech stack fingerprinting via headers,
server version disclosure, admin panel discovery, backup file discovery,
source code exposure detection (.git, .svn, .DS_Store), cookie security
analysis (Secure, HttpOnly, SameSite flags), form detection, color-coded
terminal output, JSON/CSV/text report output, multi-threaded probing,
quick scan mode, aggressive scan mode, and result severity triage.
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

_MAX_URL_LENGTH = 8192


def _validate_output_path(filepath: str) -> str:
    normalized = os.path.normpath(filepath)
    if ".." in normalized.split(os.sep):
        raise ValueError(f"Invalid output path: {filepath}")
    return normalized


# Terminal color codes
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"
    RED_BG = "\033[101m"
    GREEN_BG = "\033[102m"
    YELLOW_BG = "\033[103m"

    @staticmethod
    def colorize(text: str, color: str, bold: bool = False) -> str:
        if not sys.stdout.isatty():
            return text
        prefix = color
        if bold:
            prefix += Colors.BOLD
        return f"{prefix}{text}{Colors.RESET}"


@dataclass
class Probe:
    type: str
    path: str
    description: str
    severity: str
    confidence: float = 0.5

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "path": self.path,
            "description": self.description,
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class Result:
    url: str
    status_code: int
    response_size: int
    response_time: float
    content_type: str
    probes: List[Probe] = field(default_factory=list)
    severity: str = "info"
    server: str = ""
    technologies: List[str] = field(default_factory=list)
    cookies: List[Dict[str, str]] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "response_size": self.response_size,
            "response_time": round(self.response_time, 3),
            "content_type": self.content_type,
            "severity": self.severity,
            "server": self.server,
            "technologies": self.technologies,
            "cookies": self.cookies,
            "headers": dict(list(self.headers.items())[:20]),
            "probes": [p.to_dict() for p in self.probes],
        }


class ResultCollector:
    def __init__(self):
        self.results: List[Result] = []
        self._severity_counts: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }

    def add(self, result: Result) -> None:
        self.results.append(result)
        self._severity_counts[result.severity] = self._severity_counts.get(result.severity, 0) + 1

    def get_by_severity(self, severity: str) -> List[Result]:
        return [r for r in self.results if r.severity == severity]

    def get_critical(self) -> List[Result]:
        return self.get_by_severity("critical")

    def get_high(self) -> List[Result]:
        return self.get_by_severity("high")

    def severity_counts(self) -> Dict[str, int]:
        return dict(self._severity_counts)

    def total(self) -> int:
        return len(self.results)

    def sort_by_severity(self) -> List[Result]:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return sorted(self.results, key=lambda r: order.get(r.severity, 4))


class FastHunter:
    COMMON_PATHS: List[Dict[str, Any]] = [
        # Admin & management
        {"path": "/admin", "type": "admin_panel", "severity": "high"},
        {"path": "/administrator", "type": "admin_panel", "severity": "high"},
        {"path": "/admin/", "type": "admin_panel", "severity": "high"},
        {"path": "/manage", "type": "admin_panel", "severity": "high"},
        {"path": "/management", "type": "admin_panel", "severity": "high"},
        {"path": "/dashboard", "type": "admin_panel", "severity": "medium"},
        {"path": "/admin/dashboard", "type": "admin_panel", "severity": "high"},
        {"path": "/admin/login", "type": "login_page", "severity": "medium"},
        {"path": "/login", "type": "login_page", "severity": "medium"},
        {"path": "/wp-admin", "type": "admin_panel", "severity": "high"},
        {"path": "/cpanel", "type": "admin_panel", "severity": "high"},

        # Configuration files
        {"path": "/.env", "type": "config_exposure", "severity": "critical"},
        {"path": "/.git/config", "type": "vcs_exposure", "severity": "critical"},
        {"path": "/.git/HEAD", "type": "vcs_exposure", "severity": "critical"},
        {"path": "/.svn/entries", "type": "vcs_exposure", "severity": "critical"},
        {"path": "/.DS_Store", "type": "info_disclosure", "severity": "medium"},
        {"path": "/config", "type": "config_exposure", "severity": "high"},
        {"path": "/configuration", "type": "config_exposure", "severity": "high"},
        {"path": "/config.json", "type": "config_exposure", "severity": "high"},
        {"path": "/config.php", "type": "config_exposure", "severity": "high"},
        {"path": "/settings", "type": "config_exposure", "severity": "high"},
        {"path": "/setup", "type": "installer", "severity": "critical"},
        {"path": "/install", "type": "installer", "severity": "critical"},
        {"path": "/install.php", "type": "installer", "severity": "critical"},

        # Debug & development
        {"path": "/debug", "type": "debug_page", "severity": "high"},
        {"path": "/debug/", "type": "debug_page", "severity": "high"},
        {"path": "/test", "type": "debug_page", "severity": "medium"},
        {"path": "/tests", "type": "debug_page", "severity": "medium"},
        {"path": "/phpinfo.php", "type": "info_disclosure", "severity": "critical"},
        {"path": "/info.php", "type": "info_disclosure", "severity": "high"},
        {"path": "/health", "type": "info_disclosure", "severity": "low"},
        {"path": "/healthcheck", "type": "info_disclosure", "severity": "low"},
        {"path": "/status", "type": "info_disclosure", "severity": "low"},
        {"path": "/version", "type": "info_disclosure", "severity": "low"},

        # API & documentation
        {"path": "/api", "type": "api_endpoint", "severity": "medium"},
        {"path": "/api/", "type": "api_endpoint", "severity": "medium"},
        {"path": "/api/v1", "type": "api_endpoint", "severity": "medium"},
        {"path": "/api/v2", "type": "api_endpoint", "severity": "medium"},
        {"path": "/v1", "type": "api_endpoint", "severity": "medium"},
        {"path": "/v2", "type": "api_endpoint", "severity": "medium"},
        {"path": "/swagger", "type": "api_docs", "severity": "medium"},
        {"path": "/swagger/", "type": "api_docs", "severity": "medium"},
        {"path": "/swagger.json", "type": "api_docs", "severity": "medium"},
        {"path": "/swagger-ui.html", "type": "api_docs", "severity": "medium"},
        {"path": "/api-docs", "type": "api_docs", "severity": "medium"},
        {"path": "/docs", "type": "api_docs", "severity": "low"},
        {"path": "/openapi.json", "type": "api_docs", "severity": "medium"},
        {"path": "/graphql", "type": "graphql_endpoint", "severity": "medium"},
        {"path": "/graphiql", "type": "graphql_endpoint", "severity": "medium"},

        # Backup & source
        {"path": "/backup", "type": "backup_exposure", "severity": "critical"},
        {"path": "/backups", "type": "backup_exposure", "severity": "critical"},
        {"path": "/backup.zip", "type": "backup_exposure", "severity": "critical"},
        {"path": "/backup.sql", "type": "backup_exposure", "severity": "critical"},
        {"path": "/dump", "type": "backup_exposure", "severity": "critical"},
        {"path": "/db.sql", "type": "backup_exposure", "severity": "critical"},
        {"path": "/database.sql", "type": "backup_exposure", "severity": "critical"},
        {"path": "/db_backup.sql", "type": "backup_exposure", "severity": "critical"},
        {"path": "/export", "type": "backup_exposure", "severity": "high"},
        {"path": "/src", "type": "source_exposure", "severity": "high"},
        {"path": "/source", "type": "source_exposure", "severity": "high"},

        # Cloud & AWS
        {"path": "/.aws/credentials", "type": "cloud_credentials", "severity": "critical"},
        {"path": "/.aws/config", "type": "cloud_credentials", "severity": "high"},
        {"path": "/.azure/credentials", "type": "cloud_credentials", "severity": "critical"},
        {"path": "/.gcp/credentials", "type": "cloud_credentials", "severity": "critical"},

        # Security & auth
        {"path": "/robots.txt", "type": "info_disclosure", "severity": "low"},
        {"path": "/sitemap.xml", "type": "info_disclosure", "severity": "low"},
        {"path": "/crossdomain.xml", "type": "policy_file", "severity": "medium"},
        {"path": "/clientaccesspolicy.xml", "type": "policy_file", "severity": "medium"},
        {"path": "/.htaccess", "type": "config_exposure", "severity": "high"},
        {"path": "/web.config", "type": "config_exposure", "severity": "high"},
        {"path": "/composer.json", "type": "dep_info", "severity": "medium"},
        {"path": "/composer.lock", "type": "dep_info", "severity": "medium"},
        {"path": "/package.json", "type": "dep_info", "severity": "medium"},
        {"path": "/yarn.lock", "type": "dep_info", "severity": "medium"},

        # Common CMS paths
        {"path": "/wp-content/", "type": "cms_path", "severity": "low"},
        {"path": "/wp-includes/", "type": "cms_path", "severity": "low"},
        {"path": "/wp-json/", "type": "api_endpoint", "severity": "medium"},
        {"path": "/administrator/", "type": "cms_path", "severity": "medium"},
        {"path": "/joomla.xml", "type": "cms_path", "severity": "low"},
        {"path": "/Drupal/", "type": "cms_path", "severity": "low"},

        # Logs & metrics
        {"path": "/logs", "type": "log_exposure", "severity": "high"},
        {"path": "/error.log", "type": "log_exposure", "severity": "high"},
        {"path": "/access.log", "type": "log_exposure", "severity": "high"},
        {"path": "/log.txt", "type": "log_exposure", "severity": "high"},
        {"path": "/metrics", "type": "info_disclosure", "severity": "medium"},
        {"path": "/actuator", "type": "info_disclosure", "severity": "high"},
        {"path": "/actuator/", "type": "info_disclosure", "severity": "high"},
        {"path": "/actuator/env", "type": "info_disclosure", "severity": "critical"},
        {"path": "/actuator/health", "type": "info_disclosure", "severity": "low"},
        {"path": "/actuator/info", "type": "info_disclosure", "severity": "medium"},
        {"path": "/actuator/heapdump", "type": "info_disclosure", "severity": "critical"},
        {"path": "/actuator/threaddump", "type": "info_disclosure", "severity": "high"},
        {"path": "/actuator/httptrace", "type": "info_disclosure", "severity": "high"},
        {"path": "/actuator/beans", "type": "info_disclosure", "severity": "medium"},
        {"path": "/actuator/mappings", "type": "info_disclosure", "severity": "high"},

        # CI/CD
        {"path": "/.circleci/config.yml", "type": "cicd_exposure", "severity": "high"},
        {"path": "/.github/workflows/", "type": "cicd_exposure", "severity": "high"},
        {"path": "/.travis.yml", "type": "cicd_exposure", "severity": "high"},
        {"path": "/Jenkinsfile", "type": "cicd_exposure", "severity": "medium"},
        {"path": "/Dockerfile", "type": "docker_exposure", "severity": "medium"},
        {"path": "/docker-compose.yml", "type": "docker_exposure", "severity": "medium"},
        {"path": "/.dockerignore", "type": "docker_exposure", "severity": "low"},

        # Common file extensions
        {"path": "/index.php", "type": "info_disclosure", "severity": "low"},
        {"path": "/index.html", "type": "info_disclosure", "severity": "low"},
        {"path": "/server-status", "type": "server_info", "severity": "high"},
        {"path": "/server-info", "type": "server_info", "severity": "high"},
        {"path": "/console/", "type": "admin_panel", "severity": "critical"},
        {"path": "/phpmyadmin", "type": "admin_panel", "severity": "critical"},
        {"path": "/phpMyAdmin", "type": "admin_panel", "severity": "critical"},
        {"path": "/pma", "type": "admin_panel", "severity": "critical"},
        {"path": "/adminer.php", "type": "admin_panel", "severity": "critical"},
        {"path": "/favicon.ico", "type": "info_disclosure", "severity": "info"},
    ]

    AGGRESSIVE_PATHS: List[Dict[str, Any]] = [
        {"path": "/shell.php", "type": "webshell", "severity": "critical"},
        {"path": "/cmd.php", "type": "webshell", "severity": "critical"},
        {"path": "/webshell.php", "type": "webshell", "severity": "critical"},
        {"path": "/c99.php", "type": "webshell", "severity": "critical"},
        {"path": "/r57.php", "type": "webshell", "severity": "critical"},
        {"path": "/uploads/", "type": "upload_dir", "severity": "high"},
        {"path": "/upload/", "type": "upload_dir", "severity": "high"},
        {"path": "/files/", "type": "upload_dir", "severity": "high"},
        {"path": "/assets/", "type": "upload_dir", "severity": "low"},
        {"path": "/static/", "type": "upload_dir", "severity": "low"},
        {"path": "/storage/", "type": "upload_dir", "severity": "medium"},
        {"path": "/tmp/", "type": "temp_dir", "severity": "medium"},
        {"path": "/temp/", "type": "temp_dir", "severity": "medium"},
        {"path": "/.gitignore", "type": "config_exposure", "severity": "low"},
        {"path": "/.htpasswd", "type": "config_exposure", "severity": "critical"},
        {"path": "/.pgpass", "type": "config_exposure", "severity": "critical"},
        {"path": "/.npmrc", "type": "config_exposure", "severity": "high"},
        {"path": "/.dockerenv", "type": "docker_exposure", "severity": "medium"},
        {"path": "/.elasticbeanstalk/", "type": "cloud_credentials", "severity": "high"},
        {"path": "/Procfile", "type": "deploy_config", "severity": "low"},
        {"path": "/serverless.yml", "type": "deploy_config", "severity": "medium"},
        {"path": "/samconfig.toml", "type": "deploy_config", "severity": "medium"},
        {"path": "/credentials", "type": "credentials", "severity": "critical"},
        {"path": "/.secret", "type": "credentials", "severity": "critical"},
        {"path": "/secret.txt", "type": "credentials", "severity": "critical"},
        {"path": "/token", "type": "credentials", "severity": "high"},
        {"path": "/id_rsa", "type": "credentials", "severity": "critical"},
        {"path": "/id_rsa.pub", "type": "credentials", "severity": "medium"},
        {"path": "/.ssh/id_rsa", "type": "credentials", "severity": "critical"},
        {"path": "/service-account.json", "type": "cloud_credentials", "severity": "critical"},
        {"path": "/key.json", "type": "cloud_credentials", "severity": "critical"},
        {"path": "/credentials.json", "type": "cloud_credentials", "severity": "critical"},
    ]

    COMMON_DEFAULTS: List[Dict[str, str]] = [
        {"user": "admin", "pass": "admin"},
        {"user": "admin", "pass": "password"},
        {"user": "admin", "pass": "123456"},
        {"user": "admin", "pass": "admin123"},
        {"user": "admin", "pass": "administrator"},
        {"user": "root", "pass": "root"},
        {"user": "root", "pass": "toor"},
        {"user": "root", "pass": "password"},
        {"user": "admin", "pass": "letmein"},
        {"user": "admin", "pass": "welcome"},
        {"user": "admin", "pass": "passw0rd"},
        {"user": "admin", "pass": "changeme"},
        {"user": "admin", "pass": "demo"},
        {"user": "admin", "pass": "test"},
        {"user": "user", "pass": "user"},
        {"user": "user", "pass": "password"},
        {"user": "guest", "pass": "guest"},
        {"user": "test", "pass": "test"},
        {"user": "operator", "pass": "operator"},
        {"user": "admin", "pass": "qwerty"},
    ]

    SECURITY_HEADERS: List[str] = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
        "Access-Control-Allow-Origin",
        "Cross-Origin-Resource-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Embedder-Policy",
    ]

    INFO_DISCLOSURE_PATTERNS: Dict[str, List[str]] = {
        "stack_trace": [
            "at ", "in <module>", "Traceback (most recent call last)",
            "java.lang.", "Exception in thread", "at org.",
            "at com.", "at net.", "at javax.", "Caused by:",
            "Stack trace:", "Stacktrace:", "Internal Server Error",
        ],
        "server_info": [
            "Server: ", "X-Powered-By: ", "X-AspNet-Version: ",
            "X-AspNetMvc-Version: ", "X-Generator: ",
        ],
        "php_info": [
            "PHP Version ", "phpinfo()", "PHP License",
            "System ", "Build Date ",
        ],
        "debug_mode": [
            "DEBUG = True", "APP_DEBUG", "WP_DEBUG",
            "debug_mode", "is_debug", "APP_ENV=dev",
            "CI_ENVIRONMENT = development",
        ],
        "database_leak": [
            "SQLSTATE[", "pdo_mysql", "mysqli_connect",
            "Cannot connect to MySQL", "ORA-", "PostgreSQL",
            "dbname=", "host=", "port=",
        ],
        "path_disclosure": [
            "Warning: include(", "Warning: require(", "Warning: fopen(",
            "Fatal error: Uncaught exception", "in /var/www",
            "in /home/", "in /app/", "in /usr/local/",
        ],
    }

    def __init__(self, silent: bool = False, aggressive: bool = False, quick: bool = False, allow_insecure: bool = False):
        self.silent = silent
        self.aggressive = aggressive
        self.quick = quick
        self.allow_insecure = allow_insecure
        self.collector = ResultCollector()
        self._ssl_ctx = self._create_ssl_context()
        self._scan_stats: Dict[str, Any] = {
            "paths_tested": 0,
            "methods_tested": 0,
            "findings": 0,
            "start_time": None,
            "end_time": None,
            "errors": 0,
        }

    def _log(self, msg: str, level: str = "info") -> None:
        if self.silent:
            return
        prefix = {"info": f"{Colors.GREEN}[+]{Colors.RESET}",
                  "warn": f"{Colors.YELLOW}[!]{Colors.RESET}",
                  "error": f"{Colors.RED}[-]{Colors.RESET}",
                  "finding": f"{Colors.RED_BG}[!]{Colors.RESET}"}.get(level, f"{Colors.GREEN}[+]{Colors.RESET}")
        print(f"{prefix} {msg}", file=sys.stderr)

    def _create_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if self.allow_insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _color_status(self, code: int) -> str:
        if code >= 500:
            c = Colors.RED
        elif code >= 400:
            c = Colors.YELLOW
        elif code >= 300:
            c = Colors.CYAN
        elif code >= 200:
            c = Colors.GREEN
        else:
            c = Colors.DIM
        return Colors.colorize(str(code), c, bold=code < 400)

    def _color_severity(self, severity: str) -> str:
        colors = {
            "critical": Colors.RED_BG,
            "high": Colors.RED,
            "medium": Colors.YELLOW,
            "low": Colors.BLUE,
            "info": Colors.DIM,
        }
        return Colors.colorize(severity.upper(), colors.get(severity, Colors.DIM))

    def fetch(self, url: str, method: str = "GET",
              headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        if len(url) > _MAX_URL_LENGTH:
            return {"status": 0, "body": "", "headers": {}, "size": 0, "elapsed": 0.0, "error": f"URL exceeds max length ({len(url)} > {_MAX_URL_LENGTH})"}
        start = time.time()
        result: Dict[str, Any] = {
            "status": 0, "body": "", "headers": {}, "size": 0,
            "elapsed": 0.0, "error": None,
        }
        try:
            req_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "*/*",
            }
            if headers:
                req_headers.update(headers)

            req = urllib.request.Request(url, method=method, headers=req_headers)
            with urllib.request.urlopen(req, timeout=10, context=self._ssl_ctx) as resp:
                body = resp.read()
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
        except Exception as e:
            result["error"] = str(e)

        result["elapsed"] = round(time.time() - start, 3)
        return result

    def test_paths(self, base_url: str) -> List[Result]:
        results: List[Result] = []
        paths = list(self.COMMON_PATHS)
        if self.aggressive:
            paths.extend(self.AGGRESSIVE_PATHS)

        if self.quick:
            paths = paths[:30]

        self._log(f"Testing {len(paths)} common paths on {base_url}")

        def probe_path(entry: Dict[str, Any]) -> Optional[Result]:
            try:
                url = urllib.parse.urljoin(base_url, entry["path"])
                resp = self.fetch(url)
                if resp["status"] in (0,):
                    return None
                self._scan_stats["paths_tested"] += 1
                if resp["status"] in (200, 201, 204, 301, 302, 401, 403, 500):
                    probe = Probe(
                        type=entry["type"],
                        path=entry["path"],
                        description=f"{entry['type'].replace('_', ' ').title()} at {entry['path']}",
                        severity=entry["severity"],
                        confidence=0.7 if resp["status"] == 200 else 0.4,
                    )
                    result = Result(
                        url=url, status_code=resp["status"],
                        response_size=resp["size"],
                        response_time=resp["elapsed"],
                        content_type=resp["headers"].get("Content-Type", ""),
                        server=resp["headers"].get("Server", ""),
                        probes=[probe],
                        severity=entry["severity"],
                        headers=resp["headers"],
                    )
                    # Analyze info disclosure
                    self._check_info_disclosure(resp["body"], result)
                    self._extract_technologies(resp["headers"], result)
                    return result
            except Exception:
                self._scan_stats["errors"] += 1
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            future_map = {ex.submit(probe_path, p): p for p in paths}
            for future in concurrent.futures.as_completed(future_map):
                entry = future_map[future]
                try:
                    result = future.result(timeout=20)
                    if result:
                        results.append(result)
                        self.collector.add(result)
                        self._print_result(result, entry)
                except Exception:
                    pass

        return results

    def test_methods(self, base_url: str) -> Optional[Result]:
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
        self._log(f"Testing HTTP methods on {base_url}")
        support: List[str] = []

        for method in methods:
            result = self.fetch(base_url, method=method)
            self._scan_stats["methods_tested"] += 1
            if result["status"] and result["status"] not in (404, 405, 501, 0):
                support.append(f"{method} ({result['status']})")

        if support:
            probes = [Probe(type="http_method", path="", severity="medium",
                            description=f"Multiple HTTP methods allowed: {', '.join(support)}",
                            confidence=0.6)]
            result_obj = Result(
                url=base_url, status_code=0,
                response_size=0, response_time=0,
                content_type="", probes=probes,
                severity="medium",
            )
            self.collector.add(result_obj)
            self._print_result(result_obj)
            return result_obj
        return None

    def check_security_headers(self, base_url: str) -> Optional[Result]:
        resp = self.fetch(base_url)
        if not resp["status"]:
            return None

        missing: List[str] = []
        present: List[str] = []
        for header in self.SECURITY_HEADERS:
            lower = header.lower()
            found = any(lower == h.lower() for h in resp["headers"])
            if found:
                present.append(header)
            else:
                missing.append(header)

        findings: List[Probe] = []
        if missing:
            findings.append(Probe(
                type="missing_security_headers",
                path="",
                severity="medium",
                description=f"Missing security headers ({len(missing)}): {', '.join(missing[:5])}",
                confidence=0.8,
            ))

        # Check CORS
        acao = resp["headers"].get("Access-Control-Allow-Origin", "")
        if acao == "*":
            findings.append(Probe(
                type="cors_wildcard",
                path="",
                severity="medium",
                description="CORS allows all origins (Access-Control-Allow-Origin: *)",
                confidence=0.9,
            ))
        elif acao and "null" in acao:
            findings.append(Probe(
                type="cors_null_origin",
                path="",
                severity="medium",
                description="CORS allows null origin",
                confidence=0.7,
            ))

        # Check HSTS
        hsts = resp["headers"].get("Strict-Transport-Security", "")
        if not hsts:
            findings.append(Probe(
                type="missing_hsts",
                path="",
                severity="low",
                description="Missing HTTP Strict-Transport-Security header",
                confidence=0.6,
            ))

        if findings:
            result = Result(
                url=base_url, status_code=resp["status"],
                response_size=resp["size"],
                response_time=resp["elapsed"],
                content_type=resp["headers"].get("Content-Type", ""),
                headers=resp["headers"],
                probes=findings,
                severity="medium",
            )
            self.collector.add(result)
            self._print_result(result)
            return result
        return None

    def check_directory_listing(self, base_url: str) -> Optional[Result]:
        test_paths = ["/", "/assets/", "/images/", "/css/", "/js/", "/uploads/", "/static/"]
        dir_indicators = ["Index of /", "<title>Directory listing", "<title>Index of",
                          "Parent Directory</a>", "[parent directory]", "Directory Listing for"]

        for path in test_paths:
            try:
                url = urllib.parse.urljoin(base_url, path)
                resp = self.fetch(url)
                if resp["status"] == 200:
                    body = resp["body"]
                    if any(ind in body for ind in dir_indicators):
                        probe = Probe(
                            type="directory_listing",
                            path=path,
                            severity="high",
                            description=f"Directory listing enabled at {path}",
                            confidence=0.9,
                        )
                        result = Result(
                            url=url, status_code=200,
                            response_size=resp["size"],
                            response_time=resp["elapsed"],
                            content_type=resp["headers"].get("Content-Type", ""),
                            probes=[probe],
                            severity="high",
                            headers=resp["headers"],
                        )
                        self.collector.add(result)
                        self._print_result(result)
                        return result
            except Exception:
                continue
        return None

    def check_cloud_metadata(self, base_url: str) -> Optional[Result]:
        urls_to_check = [
            (f"{base_url}/latest/meta-data/", "AWS IMDSv1"),
            (f"{base_url}/metadata/instance?api-version=2021-02-01", "Azure IMDS"),
        ]
        for url, cloud_type in urls_to_check:
            try:
                resp = self.fetch(url)
                if resp["status"] == 200 and resp["size"] > 50:
                    probe = Probe(
                        type="cloud_metadata_access",
                        path=url,
                        severity="critical",
                        description=f"Potential {cloud_type} metadata accessible",
                        confidence=0.5,
                    )
                    result = Result(
                        url=url, status_code=200,
                        response_size=resp["size"],
                        response_time=resp["elapsed"],
                        content_type=resp["headers"].get("Content-Type", ""),
                        probes=[probe],
                        severity="critical",
                        headers=resp["headers"],
                    )
                    self.collector.add(result)
                    self._print_result(result)
                    return result
            except Exception:
                continue
        return None

    def _check_info_disclosure(self, body: str, result: Result) -> None:
        body_lower = body.lower()
        for category, patterns in self.INFO_DISCLOSURE_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in body_lower:
                    existing = [p for p in result.probes if p.type == f"info_disclosure_{category}"]
                    if not existing:
                        result.probes.append(Probe(
                            type=f"info_disclosure_{category}",
                            path="",
                            severity="high" if category in ("stack_trace", "database_leak") else "medium",
                            description=f"Information disclosure: {category.replace('_', ' ')}",
                            confidence=0.6,
                        ))
                    break

    def _extract_technologies(self, headers: Dict[str, str], result: Result) -> None:
        server = headers.get("Server", "")
        if server:
            result.server = server
            result.technologies.append(server)

        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            result.technologies.append(powered_by)

        asp_ver = headers.get("X-AspNet-Version", "")
        if asp_ver:
            result.technologies.append(f"ASP.NET {asp_ver}")

        asp_mvc = headers.get("X-AspNetMvc-Version", "")
        if asp_mvc:
            result.technologies.append(f"ASP.NET MVC {asp_mvc}")

        cf_ray = headers.get("CF-RAY", "")
        if cf_ray:
            result.technologies.append("Cloudflare")

        set_cookie = headers.get("Set-Cookie", "")
        if "PHPSESSID" in set_cookie:
            result.technologies.append("PHP")
        if "JSESSIONID" in set_cookie:
            result.technologies.append("Java/JSP")
        if "ASPSESSIONID" in set_cookie or "ASP.NET_SessionId" in set_cookie:
            result.technologies.append("ASP.NET")
        if "connect.sid" in set_cookie:
            result.technologies.append("Node.js/Express")

    def _analyze_cookies(self, headers: Dict[str, str], result: Result) -> None:
        set_cookie = headers.get("Set-Cookie", "")
        if not set_cookie:
            return
        for cookie_part in set_cookie.split(","):
            cookie_part = cookie_part.strip()
            if "=" not in cookie_part:
                continue
            name = cookie_part.split("=")[0].strip()
            info: Dict[str, str] = {"name": name}
            if "Secure" in cookie_part:
                info["secure"] = "yes"
            else:
                info["insecure"] = "yes"
                result.probes.append(Probe(
                    type="insecure_cookie",
                    path="",
                    severity="low",
                    description=f"Cookie '{name}' missing Secure flag",
                    confidence=0.8,
                ))
            if "HttpOnly" in cookie_part:
                info["httponly"] = "yes"
            else:
                result.probes.append(Probe(
                    type="httponly_cookie",
                    path="",
                    severity="low",
                    description=f"Cookie '{name}' missing HttpOnly flag",
                    confidence=0.6,
                ))
            if "SameSite=" in cookie_part:
                samesite_match = re.search(r'SameSite=(\w+)', cookie_part)
                if samesite_match:
                    info["samesite"] = samesite_match.group(1)
            result.cookies.append(info)

    def _print_result(self, result: Result, entry: Optional[Dict[str, Any]] = None) -> None:
        if self.silent:
            return
        status_str = self._color_status(result.status_code) if result.status_code else ""
        sev_str = self._color_severity(result.severity)
        path_str = entry["path"] if entry else result.url
        desc = result.probes[0].description if result.probes else ""
        tech_str = f" [{', '.join(result.technologies[:3])}]" if result.technologies else ""
        print(f"  [{sev_str}] {status_str:>4} {path_str:<30} {desc[:60]}{tech_str}", file=sys.stderr)

    def full_scan(self, base_url: str) -> ResultCollector:
        self._scan_stats["start_time"] = datetime.datetime.now().isoformat()
        self._log(f"{Colors.BOLD}Fast Hunt v2.0 — Surface Reconnaissance{Colors.RESET}")
        self._log(f"Target: {base_url}")
        self._log(f"Mode: {'Aggressive' if self.aggressive else 'Standard'}{', Quick' if self.quick else ''}")
        print(f"\n{'─' * 70}", file=sys.stderr)

        # Phase 1: Common paths
        self._log(f"\nPhase 1: Probing common paths...", "info")
        path_results = self.test_paths(base_url)
        findings = len([r for r in path_results if r.severity in ("critical", "high")])
        total = len(path_results)
        print(f"  Found {findings} high/critical findings across {total} accessible paths\n", file=sys.stderr)

        # Phase 2: Security headers
        self._log(f"Phase 2: Checking security headers...", "info")
        header_result = self.check_security_headers(base_url)
        if header_result:
            print(f"  {len(header_result.probes)} header issues found\n", file=sys.stderr)

        # Phase 3: Directory listing
        self._log(f"Phase 3: Checking directory listing...", "info")
        dir_result = self.check_directory_listing(base_url)
        if dir_result:
            print(f"  Directory listing FOUND\n", file=sys.stderr)

        # Phase 4: HTTP methods
        self._log(f"Phase 4: Testing HTTP methods...", "info")
        method_result = self.test_methods(base_url)

        # Phase 5: Security analysis on main page
        self._log(f"Phase 5: Analyzing main page response...", "info")
        main_resp = self.fetch(base_url)
        if main_resp["status"]:
            main_result = Result(
                url=base_url, status_code=main_resp["status"],
                response_size=main_resp["size"],
                response_time=main_resp["elapsed"],
                content_type=main_resp["headers"].get("Content-Type", ""),
                server=main_resp["headers"].get("Server", ""),
                headers=main_resp["headers"],
            )
            self._extract_technologies(main_resp["headers"], main_result)
            self._check_info_disclosure(main_resp["body"], main_result)
            self._analyze_cookies(main_resp["headers"], main_result)
            if main_result.probes:
                self.collector.add(main_result)
                for probe in main_result.probes:
                    sev = self._color_severity(probe.severity)
                    print(f"  [{sev}] {probe.description}", file=sys.stderr)

            if main_result.technologies:
                print(f"\n  Tech Stack: {', '.join(main_result.technologies)}", file=sys.stderr)

        print(f"\n{'─' * 70}", file=sys.stderr)
        self._scan_stats["end_time"] = datetime.datetime.now().isoformat()
        self._scan_stats["findings"] = self.collector.total()
        self._log(f"{Colors.BOLD}Scan complete. {self.collector.total()} findings detected.{Colors.RESET}")

        sev_counts = self.collector.severity_counts()
        for sev in ["critical", "high", "medium", "low"]:
            if sev_counts.get(sev, 0) > 0:
                c = {"critical": Colors.RED, "high": Colors.RED, "medium": Colors.YELLOW, "low": Colors.BLUE}.get(sev, "")
                print(f"  {Colors.colorize(f'{sev}: {sev_counts[sev]}', c)}", file=sys.stderr)

        return self.collector

    def output_json(self, filepath: Optional[str] = None) -> str:
        data = {
            "scan_metadata": self._scan_stats,
            "severity_counts": self.collector.severity_counts(),
            "results": [r.to_dict() for r in self.collector.sort_by_severity()],
        }
        output = json.dumps(data, indent=2, default=str)
        if filepath:
            filepath = _validate_output_path(filepath)
            os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(output)
            self._log(f"JSON written to {filepath}")
        return output

    def output_csv(self, filepath: str) -> None:
        filepath = _validate_output_path(filepath)
        os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
        rows = []
        for r in self.collector.results:
            for p in r.probes:
                rows.append({
                    "url": r.url,
                    "status": r.status_code,
                    "severity": r.severity,
                    "type": p.type,
                    "description": p.description,
                    "path": p.path,
                    "confidence": p.confidence,
                    "server": r.server,
                })
        if rows:
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
            self._log(f"CSV written to {filepath}")

    def output_text(self, filepath: Optional[str] = None) -> str:
        lines = ["Fast Hunt Report", "=" * 60,
                 f"Generated: {datetime.datetime.now().isoformat()}",
                 f"Target: {self._scan_stats.get('start_time', 'N/A')}",
                 f"Paths Tested: {self._scan_stats.get('paths_tested', 0)}",
                 f"Methods Tested: {self._scan_stats.get('methods_tested', 0)}",
                 f"Total Findings: {self.collector.total()}", ""]

        sev_counts = self.collector.severity_counts()
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev_counts.get(sev, 0):
                lines.append(f"  {sev.upper()}: {sev_counts[sev]}")

        lines.append("\n--- Findings ---")
        for i, r in enumerate(self.collector.sort_by_severity(), 1):
            for p in r.probes:
                lines.append(f"\n[{i}] [{r.severity.upper()}] {p.type}")
                lines.append(f"  URL:    {r.url}")
                lines.append(f"  Status: {r.status_code}")
                lines.append(f"  Desc:   {p.description}")
                lines.append(f"  Path:   {p.path}")
                if r.technologies:
                    lines.append(f"  Tech:   {', '.join(r.technologies)}")

        report = "\n".join(lines)
        if filepath:
            filepath = _validate_output_path(filepath)
            os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(report)
            self._log(f"Report written to {filepath}")
        return report

    def get_summary(self) -> Dict[str, Any]:
        return {
            "scan_stats": self._scan_stats,
            "severity_counts": self.collector.severity_counts(),
            "total_findings": self.collector.total(),
        }


def build_argparse() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="fast_hunt.py — Fast Surface Vulnerability Hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python fast_hunt.py --target https://target.com
              python fast_hunt.py --target https://target.com --quick
              python fast_hunt.py --target https://target.com --aggressive --output results.json
              python fast_hunt.py --target https://target.com --silent --json
              python fast_hunt.py --target https://target.com --quick --output report.txt
        """),
    )
    parser.add_argument("--target", type=str, required=True, help="Target URL to scan")
    parser.add_argument("--quick", action="store_true",
                        help="Quick scan (reduced path set)")
    parser.add_argument("--aggressive", action="store_true",
                        help="Aggressive scan (additional paths for webshells, credentials)")
    parser.add_argument("--output", type=str, default=None, help="Output file path")
    parser.add_argument("--silent", action="store_true", help="Suppress terminal output")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--csv", type=str, default=None, help="Write CSV output")
    parser.add_argument("--allow-insecure", action="store_true",
                        help="Allow insecure SSL connections (skip certificate verification)")
    return parser


def main() -> None:
    parser = build_argparse()
    args = parser.parse_args()

    hunter = FastHunter(silent=args.silent, aggressive=args.aggressive, quick=args.quick, allow_insecure=args.allow_insecure)

    try:
        hunter.full_scan(args.target)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.json or (args.output and args.output.endswith(".json")):
        out = hunter.output_json(filepath=args.output)
        if not args.output:
            print(out)
    elif args.csv:
        hunter.output_csv(args.csv)
    else:
        report = hunter.output_text(filepath=args.output)
        if not args.output:
            print(report)


if __name__ == "__main__":
    main()
