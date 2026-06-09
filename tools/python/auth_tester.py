#!/usr/bin/env python3
"""
auth_tester.py — Authentication Testing Tool

Performs comprehensive authentication security testing including login form
detection, session cookie analysis, JWT decoding and inspection, auth bypass
header testing, HTTP verb tampering, parameter tampering, and rate limit
detection. Designed for bug bounty recon and web application security
assessment.

Features:
    - Login form detection (username/password fields, remember-me, CSRF tokens)
    - Session cookie analysis (HttpOnly, Secure, SameSite, Domain, Path, Expires)
    - JWT decoding and inspection (header/payload decode, alg detection, expiry)
    - Auth bypass header testing (X-Forwarded-For, X-Role, X-Admin, etc.)
    - HTTP verb tampering (access POST-only via GET, PUT, etc.)
    - Parameter tampering (admin=true, role=admin, is_admin=1)
    - Rate limit detection (count requests, detect 429/Retry-After)
    - Multi-threaded execution
    - JSON, CSV, and text output

Classes:
    JwtAnalyzer: JWT token decoding and security analysis
    SessionAnalyzer: HTTP cookie and session analysis
    LoginDetector: Login form field detection
    BypassTester: Auth bypass technique testing
    RateLimitDetector: Rate limiting detection
    AuthTester: Main auth testing orchestrator
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
import re
import ssl
import sys
import textwrap
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("auth_tester")


@dataclass
class AuthTestResult:
    """Represents the result of a single auth test operation.

    Stores the test configuration, response metadata, and any
    findings detected during the test.

    Attributes:
        test_name: Name of the test performed
        url: URL that was tested
        method: HTTP method used
        headers: Headers sent with the request
        data: Request body data
        status: HTTP response status code
        size: Response body size in bytes
        elapsed: Request duration in seconds
        error: Error message if request failed
        finding: Description of any security finding
        finding_type: Classification of the finding
        severity: Severity level of the finding
    """
    test_name: str = ""
    url: str = ""
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    data: Optional[Dict[str, str]] = None
    status: Optional[int] = None
    size: Optional[int] = None
    elapsed: float = 0.0
    error: Optional[str] = None
    finding: str = ""
    finding_type: str = ""
    severity: str = "info"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize result to dictionary for JSON export."""
        return {
            "test_name": self.test_name,
            "url": self.url,
            "method": self.method,
            "headers": self.headers,
            "status": self.status,
            "size": self.size,
            "elapsed": round(self.elapsed, 4),
            "error": self.error,
            "finding": self.finding,
            "finding_type": self.finding_type,
            "severity": self.severity,
        }


class JwtAnalyzer:
    """Decodes, inspects, and analyzes JWT tokens for security issues.

    Performs base64 decoding of JWT header and payload, identifies the
    signing algorithm, checks for common weaknesses (alg=none, weak HMAC,
    expired tokens), and extracts claims for review.

    Attributes:
        token: The raw JWT token string
        header: Decoded JWT header dict
        payload: Decoded JWT payload dict
        algorithm: Identified signing algorithm
        signature: Raw signature bytes
        findings: List of security findings about the token
    """

    WEAK_ALGORITHMS: Set[str] = {"none", "none", "NONE"}
    KNOWN_ALGORITHMS: Set[str] = {
        "HS256", "HS384", "HS512",
        "RS256", "RS384", "RS512",
        "ES256", "ES384", "ES512",
        "PS256", "PS384", "PS512",
        "EdDSA", "none",
    }

    def __init__(self, token: str):
        """Initialize the JWT analyzer with a token.

        Args:
            token: JWT token string (three base64 parts separated by dots)
        """
        self.raw_token = token
        self.header: Dict[str, Any] = {}
        self.payload: Dict[str, Any] = {}
        self.algorithm: str = "unknown"
        self.signature: bytes = b""
        self.findings: List[Dict[str, str]] = []
        self._is_valid_format: bool = False
        self._parse()

    def _parse(self) -> None:
        """Parse the JWT token into header, payload, and signature.

        Splits the token on dots, base64-decodes header and payload,
        and extracts the algorithm and signature.

        Side effects:
            Sets header, payload, algorithm, signature, _is_valid_format
        """
        parts = self.raw_token.strip().split(".")
        if len(parts) != 3:
            logger.warning("Invalid JWT format: expected 3 parts, got %d", len(parts))
            self.findings.append({
                "issue": "Invalid format",
                "detail": "JWT must have exactly 3 dot-separated segments",
                "severity": "low",
            })
            return

        try:
            header_b64 = self._pad_base64(parts[0])
            self.header = json.loads(base64.urlsafe_b64decode(header_b64).decode("utf-8"))
            self.algorithm = self.header.get("alg", "unknown")
            self._is_valid_format = True
        except Exception as e:
            logger.debug("Failed to decode JWT header: %s", e)
            self.findings.append({
                "issue": "Header decode failed",
                "detail": str(e),
                "severity": "low",
            })
            return

        try:
            payload_b64 = self._pad_base64(parts[1])
            decoded = base64.urlsafe_b64decode(payload_b64)
            self.payload = json.loads(decoded.decode("utf-8"))
        except json.JSONDecodeError:
            self.findings.append({
                "issue": "Payload decode warning",
                "detail": "Payload is not valid JSON after base64 decode",
                "severity": "low",
            })
        except Exception as e:
            logger.debug("Failed to decode JWT payload: %s", e)
            self.findings.append({
                "issue": "Payload decode failed",
                "detail": str(e),
                "severity": "low",
            })

        try:
            sig_b64 = self._pad_base64(parts[2])
            self.signature = base64.urlsafe_b64decode(sig_b64)
        except Exception as e:
            logger.debug("Failed to decode JWT signature: %s", e)

        self._analyze()

    def _pad_base64(self, data: str) -> str:
        """Add base64 padding if missing.

        Args:
            data: Base64 string without padding

        Returns:
            Properly padded base64 string
        """
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return data

    def _analyze(self) -> None:
        """Run security analysis on the parsed JWT.

        Checks for algorithm none, weak HMAC keys, token expiry,
        missing claims, and unusual algorithm types.
        """
        if self.algorithm in self.WEAK_ALGORITHMS:
            self.findings.append({
                "issue": "Algorithm 'none' accepted",
                "detail": "Token uses alg=none which allows signature bypass",
                "severity": "critical",
            })

        if self.algorithm not in self.KNOWN_ALGORITHMS:
            self.findings.append({
                "issue": "Unknown algorithm",
                "detail": f"Algorithm '{self.algorithm}' is not in known JWT algorithms",
                "severity": "medium",
            })

        if self.algorithm and self.algorithm.startswith("HS"):
            self.findings.append({
                "issue": "Symmetric algorithm",
                "detail": f"Token uses {self.algorithm} (symmetric). If weak key, can be brute-forced.",
                "severity": "medium",
            })

        exp = self.payload.get("exp")
        if exp is not None:
            try:
                exp_time = datetime.datetime.fromtimestamp(int(exp), tz=datetime.timezone.utc)
                now = datetime.datetime.now(datetime.timezone.utc)
                if exp_time < now:
                    self.findings.append({
                        "issue": "Token expired",
                        "detail": f"Token expired at {exp_time.isoformat()}",
                        "severity": "info",
                    })
                else:
                    remaining = exp_time - now
                    if remaining < datetime.timedelta(hours=1):
                        self.findings.append({
                            "issue": "Token expiring soon",
                            "detail": f"Token expires in {remaining}",
                            "severity": "low",
                        })
            except (ValueError, TypeError):
                self.findings.append({
                    "issue": "Invalid exp claim",
                    "detail": "exp claim is not a valid timestamp",
                    "severity": "low",
                })
        else:
            self.findings.append({
                "issue": "No expiration",
                "detail": "Token has no 'exp' claim (never expires)",
                "severity": "medium",
            })

        iat = self.payload.get("iat")
        if iat is not None:
            try:
                iat_time = datetime.datetime.fromtimestamp(int(iat), tz=datetime.timezone.utc)
                age = datetime.datetime.now(datetime.timezone.utc) - iat_time
                if age > datetime.timedelta(days=30):
                    self.findings.append({
                        "issue": "Old token",
                        "detail": f"Token issued {age.days} days ago",
                        "severity": "low",
                    })
            except (ValueError, TypeError):
                pass

        for required_claim in ["iss", "sub", "aud", "iat"]:
            if required_claim not in self.payload:
                self.findings.append({
                    "issue": f"Missing claim: {required_claim}",
                    "detail": f"Token does not contain the '{required_claim}' claim",
                    "severity": "low",
                })

        if "admin" in str(self.payload).lower() or "role" in str(self.payload).lower():
            roles = self.payload.get("role") or self.payload.get("roles") or self.payload.get("user_role")
            if roles:
                self.findings.append({
                    "issue": "Role claim found",
                    "detail": f"Token contains role information: {roles}",
                    "severity": "medium",
                })

    def get_summary(self) -> Dict[str, Any]:
        """Return a summary of the JWT analysis.

        Returns:
            Dictionary with token info, decoded data, and findings
        """
        return {
            "algorithm": self.algorithm,
            "header": self.header,
            "payload": self.payload,
            "signature_length": len(self.signature),
            "findings": self.findings,
            "finding_count": len(self.findings),
        }


class SessionAnalyzer:
    """Analyzes HTTP cookies and session management configuration.

    Parses Set-Cookie headers, checks security flags (HttpOnly, Secure,
    SameSite), evaluates cookie scope (Domain, Path), checks expiration,
    and identifies session-related security issues.

    Attributes:
        cookies: List of parsed cookie dictionaries
        findings: List of security findings about session handling
    """

    def __init__(self):
        """Initialize the session analyzer."""
        self.cookies: List[Dict[str, Any]] = []
        self.findings: List[Dict[str, str]] = []

    def parse_set_cookie(self, set_cookie_header: str, source_url: str = "") -> Dict[str, Any]:
        """Parse a single Set-Cookie header into structured data.

        Args:
            set_cookie_header: Raw Set-Cookie header value
            source_url: URL that set the cookie (for relative path analysis)

        Returns:
            Dictionary with parsed cookie attributes
        """
        cookie: Dict[str, Any] = {
            "name": "",
            "value": "",
            "httponly": False,
            "secure": False,
            "samesite": "",
            "domain": "",
            "path": "",
            "max_age": None,
            "expires": None,
            "source_url": source_url,
        }

        parts = [p.strip() for p in set_cookie_header.split(";")]
        if not parts:
            return cookie

        first = parts[0]
        if "=" in first:
            cookie["name"], cookie["value"] = first.split("=", 1)

        for part in parts[1:]:
            lower = part.lower()
            if lower == "httponly":
                cookie["httponly"] = True
            elif lower == "secure":
                cookie["secure"] = True
            elif lower.startswith("samesite="):
                cookie["samesite"] = part.split("=", 1)[1].strip()
            elif lower.startswith("domain="):
                cookie["domain"] = part.split("=", 1)[1].strip().lower()
            elif lower.startswith("path="):
                cookie["path"] = part.split("=", 1)[1].strip()
            elif lower.startswith("max-age="):
                try:
                    cookie["max_age"] = int(part.split("=", 1)[1].strip())
                except (ValueError, IndexError):
                    pass
            elif lower.startswith("expires="):
                cookie["expires"] = part.split("=", 1)[1].strip()

        return cookie

    def analyze_cookies(self, set_cookie_headers: List[str], source_url: str = "") -> List[Dict[str, Any]]:
        """Analyze multiple Set-Cookie headers for security issues.

        Args:
            set_cookie_headers: List of raw Set-Cookie header values
            source_url: URL that set the cookies

        Returns:
            List of parsed cookie dictionaries
        """
        self.cookies = []
        self.findings = []

        for header in set_cookie_headers:
            cookie = self.parse_set_cookie(header, source_url)
            self.cookies.append(cookie)
            self._analyze_cookie(cookie)

        return self.cookies

    def _analyze_cookie(self, cookie: Dict[str, Any]) -> None:
        """Analyze a single cookie for security issues.

        Args:
            cookie: Parsed cookie dictionary
        """
        if not cookie["name"]:
            return

        if not cookie["httponly"]:
            self.findings.append({
                "issue": f"Cookie '{cookie['name']}' missing HttpOnly flag",
                "detail": "Session cookie accessible via JavaScript (XSS risk)",
                "severity": "high",
            })

        if not cookie["secure"]:
            self.findings.append({
                "issue": f"Cookie '{cookie['name']}' missing Secure flag",
                "detail": "Cookie sent over unencrypted HTTP connections",
                "severity": "high",
            })

        samesite = cookie.get("samesite", "").lower()
        if not samesite:
            self.findings.append({
                "issue": f"Cookie '{cookie['name']}' missing SameSite attribute",
                "detail": "CSRF protection not enforced at cookie level",
                "severity": "medium",
            })
        elif samesite == "none":
            self.findings.append({
                "issue": f"Cookie '{cookie['name']}' has SameSite=None",
                "detail": "Cookie sent on cross-site requests (requires Secure flag)",
                "severity": "medium",
            })

        domain = cookie.get("domain", "")
        if domain and not domain.startswith("."):
            self.findings.append({
                "issue": f"Cookie '{cookie['name']}' domain scope",
                "detail": f"Domain set to '{domain}' (not starting with dot). May limit subdomain scope.",
                "severity": "low",
            })

        if not cookie.get("path"):
            self.findings.append({
                "issue": f"Cookie '{cookie['name']}' missing Path attribute",
                "detail": "Cookie scope is not explicitly limited",
                "severity": "low",
            })

        max_age = cookie.get("max_age")
        if max_age is not None and max_age <= 0:
            self.findings.append({
                "issue": f"Cookie '{cookie['name']}' deletion signal",
                "detail": f"Max-Age={max_age} indicates cookie deletion",
                "severity": "info",
            })
        elif max_age is not None and max_age > 86400 * 365:
            self.findings.append({
                "issue": f"Cookie '{cookie['name']}' long-lived",
                "detail": f"Max-Age={max_age}s ({max_age // 86400} days) - persistent session",
                "severity": "medium",
            })

        name = cookie.get("name", "").lower()
        if any(kw in name for kw in ["session", "token", "auth", "sid", "jwt"]):
            if not cookie.get("httponly") or not cookie.get("secure"):
                self.findings.append({
                    "issue": f"Session cookie '{cookie['name']}' insecure",
                    "detail": "Session cookie lacks HttpOnly or Secure flag",
                    "severity": "high",
                })

    def get_summary(self) -> Dict[str, Any]:
        """Return summary of session analysis.

        Returns:
            Dictionary with cookie count and findings
        """
        return {
            "total_cookies": len(self.cookies),
            "finding_count": len(self.findings),
            "findings": self.findings,
            "cookie_names": [c["name"] for c in self.cookies if c["name"]],
        }


class LoginDetector:
    """Detects and analyzes login forms in HTML responses.

    Scans HTML for password fields, username/email inputs, CSRF tokens,
    remember-me checkboxes, and multi-factor authentication indicators.

    Attributes:
        findings: List of detected login-related elements
    """

    PASSWORD_FIELD_PATTERNS: List[str] = [
        r'<input[^>]*type=["\']password["\']',
        r'<input[^>]*name=["\'](?:password|passwd|pwd|pass|pin|passcode)["\']',
        r'type=["\']password["\']',
    ]

    USERNAME_FIELD_PATTERNS: List[str] = [
        r'<input[^>]*name=["\'](?:username|user|email|login|userid|login_id|user_name)["\']',
        r'type=["\'](?:email|text)["\'][^>]*autocomplete=["\']username["\']',
        r'autocomplete=["\']username["\']',
    ]

    CSRF_TOKEN_PATTERNS: List[str] = [
        r'name=["\'](?:csrf[_\-]?token|csrfmiddlewaretoken|_csrf|csrf_token|authenticity_token)["\']',
        r'name=["\'](?:__RequestVerificationToken|_token|token|xsrf|xsrf-token)["\']',
        r'meta[^>]*name=["\']csrf-token["\']',
        r'meta[^>]*name=["\']_csrf["\']',
    ]

    REMEMBER_ME_PATTERNS: List[str] = [
        r'name=["\'](?:remember|remember_me|rememberMe|keep_login)["\']',
        r'type=["\']checkbox["\'][^>]*remember',
    ]

    MFA_INDICATORS: List[str] = [
        r'(?:two.factor|2fa|mfa|otp|totp|authenticator|verification.code|security.code)',
        r'(?:multi.factor|second.factor|one.time.code|authy|google.authenticator)',
    ]

    def __init__(self):
        """Initialize the login detector."""
        self.findings: Dict[str, List[str]] = {
            "password_fields": [],
            "username_fields": [],
            "csrf_tokens": [],
            "remember_me": [],
            "mfa_indicators": [],
        }

    def analyze_html(self, html: str, url: str = "") -> Dict[str, List[str]]:
        """Scan HTML content for login form elements.

        Args:
            html: HTML content to scan
            url: Source URL (for logging)

        Returns:
            Dictionary with lists of matched patterns by category
        """
        self.findings = {
            "password_fields": [],
            "username_fields": [],
            "csrf_tokens": [],
            "remember_me": [],
            "mfa_indicators": [],
        }

        for pattern in self.PASSWORD_FIELD_PATTERNS:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                self.findings["password_fields"].extend(matches)

        for pattern in self.USERNAME_FIELD_PATTERNS:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                self.findings["username_fields"].extend(matches)

        for pattern in self.CSRF_TOKEN_PATTERNS:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                self.findings["csrf_tokens"].extend(matches)

        for pattern in self.REMEMBER_ME_PATTERNS:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                self.findings["remember_me"].extend(matches)

        for pattern in self.MFA_INDICATORS:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                self.findings["mfa_indicators"].extend(matches)

        unique_counts = {k: len(set(v)) for k, v in self.findings.items()}
        logger.debug("Login form analysis for %s: %s", url, unique_counts)
        return self.findings

    def has_login_form(self) -> bool:
        """Check if a login form was detected.

        Returns:
            True if password fields or CSRF tokens were found
        """
        return bool(self.findings["password_fields"]) or bool(self.findings["csrf_tokens"])

    def has_mfa(self) -> bool:
        """Check if MFA indicators were found.

        Returns:
            True if MFA-related patterns matched
        """
        return bool(self.findings["mfa_indicators"])

    def get_summary(self) -> Dict[str, Any]:
        """Return summary of login detection results.

        Returns:
            Dictionary with detection counts and indicators
        """
        return {
            "has_login_form": self.has_login_form(),
            "has_mfa": self.has_mfa(),
            "password_fields": len(set(self.findings["password_fields"])),
            "username_fields": len(set(self.findings["username_fields"])),
            "csrf_tokens": len(set(self.findings["csrf_tokens"])),
            "remember_me": len(set(self.findings["remember_me"])),
            "mfa_indicators": len(set(self.findings["mfa_indicators"])),
        }


class BypassTester:
    """Tests authentication bypass techniques against target endpoints.

    Executes a battery of auth bypass tests including header injection,
    HTTP verb tampering, parameter tampering, and path traversal
    techniques designed to bypass authentication and access controls.

    Attributes:
        results: List of AuthTestResult objects
        finding_types: Set of detected bypass finding types
    """

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
        "X-Mod-Rewrite": "true",
        "X-Original-URL": "/admin",
        "X-Rewrite-URL": "/admin",
        "X-HTTP-Method-Override": "POST",
        "X-Custom-Auth": "true",
        "X-Auth-Type": "admin",
        "X-Access-Level": "admin",
        "X-Permissions": "*",
        "X-User-Role": "administrator",
    }

    VERB_TAMPERING_TARGETS: List[str] = ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

    PARAM_TAMPERING: List[Dict[str, str]] = [
        {"admin": "true"},
        {"admin": "1"},
        {"is_admin": "true"},
        {"is_admin": "1"},
        {"role": "admin"},
        {"role": "administrator"},
        {"user_role": "admin"},
        {"account_type": "admin"},
        {"access_level": "admin"},
        {"permissions": "admin"},
        {"privilege": "admin"},
        {"authenticated": "true"},
        {"logged_in": "true"},
        {"verified": "true"},
        {"bypass": "true"},
        {"override": "true"},
        {"sudo": "true"},
        {"su": "true"},
        {"debug": "true"},
        {"disable_auth": "true"},
        {"auth": "false"},
        {"_debug": "true"},
        {"__debug": "true"},
        {"X-Debug": "true"},
    ]

    def __init__(self, session: Optional[Any] = None):
        """Initialize the bypass tester.

        Args:
            session: Optional HTTP session for request execution
        """
        self.results: List[AuthTestResult] = []
        self.finding_types: Set[str] = set()
        self._session = session

    def _request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
        timeout: int = 15,
    ) -> Optional[AuthTestResult]:
        """Execute a single HTTP request for bypass testing.

        Args:
            url: Target URL
            method: HTTP method
            headers: Request headers
            data: Request body
            timeout: Request timeout in seconds

        Returns:
            AuthTestResult with response data
        """
        result = AuthTestResult(url=url, method=method.upper(), headers=headers or {}, data=data)

        try:
            if self._session is not None:
                start = time.time()
                resp = self._session.request(
                    method.upper(), url, headers=headers or {},
                    data=data, timeout=timeout, allow_redirects=False,
                )
                result.elapsed = time.time() - start
                result.status = resp.status_code
                result.size = len(resp.content)
            else:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(url, headers=headers or {}, method=method.upper())
                if data:
                    req.data = urllib.parse.urlencode(data).encode("utf-8")
                start = time.time()
                resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
                result.elapsed = time.time() - start
                result.status = resp.status
                body = resp.read()
                result.size = len(body)
                resp.close()
        except urllib.error.HTTPError as e:
            result.elapsed = time.time() - start  # type: ignore
            result.status = e.code
            try:
                result.size = len(e.read())
            except Exception:
                pass
        except Exception as e:
            result.error = str(e)

        return result

    def test_auth_bypass_headers(
        self,
        url: str,
        baseline_status: int = 403,
        timeout: int = 15,
    ) -> List[AuthTestResult]:
        """Test auth bypass headers against a protected endpoint.

        Sends requests with various auth bypass headers and checks for
        status code changes indicating bypass success.

        Args:
            url: Protected endpoint URL
            baseline_status: Expected status for unauthenticated requests
            timeout: Request timeout

        Returns:
            List of AuthTestResult objects
        """
        self.results = []
        logger.info("Testing %d auth bypass headers on %s", len(self.AUTH_BYPASS_HEADERS), url)

        for header_name, header_value in self.AUTH_BYPASS_HEADERS.items():
            headers = {header_name: header_value}
            result = self._request(url, "GET", headers=headers, timeout=timeout)
            if result:
                result.test_name = f"auth_bypass_header:{header_name}"
                if result.status and result.status != baseline_status and result.status < 400:
                    result.finding = f"Auth bypass via {header_name}: {header_value}"
                    result.finding_type = "auth_bypass_header"
                    result.severity = "critical" if result.status == 200 else "high"
                    self.finding_types.add("auth_bypass_header")
                self.results.append(result)

        return self.results

    def test_verb_tampering(
        self,
        url: str,
        known_method: str = "POST",
        known_status: int = 200,
        timeout: int = 15,
    ) -> List[AuthTestResult]:
        """Test HTTP verb tampering on a target endpoint.

        Attempts alternative HTTP methods on an endpoint that normally
        requires a specific method, looking for access control bypasses.

        Args:
            url: Target URL
            known_method: The expected/allowed HTTP method
            known_status: Expected status for the allowed method
            timeout: Request timeout

        Returns:
            List of AuthTestResult objects
        """
        self.results = []
        logger.info("Testing %d HTTP verb tampering variants on %s", len(self.VERB_TAMPERING_TARGETS), url)

        for method in self.VERB_TAMPERING_TARGETS:
            if method == known_method:
                continue
            result = self._request(url, method, timeout=timeout)
            if result:
                result.test_name = f"verb_tampering:{method}"
                if result.status and result.status in (200, 201, 202, 204, 302, 301):
                    result.finding = f"Verb tampering: {method} returned {result.status}"
                    result.finding_type = "verb_tampering"
                    result.severity = "high" if result.status in (200, 201) else "medium"
                    self.finding_types.add("verb_tampering")
                self.results.append(result)

        return self.results

    def test_param_tampering(
        self,
        url: str,
        method: str = "POST",
        timeout: int = 15,
    ) -> List[AuthTestResult]:
        """Test parameter tampering for privilege escalation.

        Sends requests with common admin/privilege escalation parameters
        to detect mass assignment or access control bypasses.

        Args:
            url: Target URL
            method: HTTP method to use
            timeout: Request timeout

        Returns:
            List of AuthTestResult objects
        """
        self.results = []
        logger.info("Testing %d parameter tampering variants on %s", len(self.PARAM_TAMPERING), url)

        for params in self.PARAM_TAMPERING:
            result = self._request(url, method, data=params, timeout=timeout)
            if result:
                param_desc = ";".join(f"{k}={v}" for k, v in params.items())
                result.test_name = f"param_tampering:{param_desc}"
                if result.status and result.status in (200, 201, 202, 302):
                    result.finding = f"Parameter tampering: {param_desc} returned {result.status}"
                    result.finding_type = "param_tampering"
                    result.severity = "high"
                    self.finding_types.add("param_tampering")
                self.results.append(result)

        return self.results

    def test_path_traversal_auth(
        self,
        base_url: str,
        protected_path: str = "/admin",
        timeout: int = 15,
    ) -> List[AuthTestResult]:
        """Test path traversal-based auth bypass techniques.

        Attempts to access protected paths using traversal techniques
        like URL encoding, double encoding, and alternative paths.

        Args:
            base_url: Base URL of the target
            protected_path: Path to the protected resource
            timeout: Request timeout

        Returns:
            List of AuthTestResult objects
        """
        traversal_payloads = [
            f"/{protected_path.lstrip('/')}",
            f"/./{protected_path.lstrip('/')}",
            f"//{protected_path.lstrip('/')}",
            f"/%2f{protected_path.lstrip('/')}",
            f"/./{protected_path.lstrip('/')}/.",
            f"/{protected_path.lstrip('/')}%00",
            f"/.{protected_path.lstrip('/')}",
            f"/..;/{protected_path.lstrip('/')}",
            f"/../{protected_path.lstrip('/')}",
            f"/%2e%2e/{protected_path.lstrip('/')}",
        ]

        self.results = []
        logger.info("Testing %d path traversal variants on %s", len(traversal_payloads), base_url)

        for payload in traversal_payloads:
            url = f"{base_url.rstrip('/')}{payload}" if payload.startswith("/") else f"{base_url.rstrip('/')}/{payload}"
            result = self._request(url, "GET", timeout=timeout)
            if result:
                result.test_name = f"path_traversal:{payload}"
                if result.status and result.status < 400:
                    result.finding = f"Path traversal bypass: {payload} returned {result.status}"
                    result.finding_type = "path_traversal_auth"
                    result.severity = "high"
                    self.finding_types.add("path_traversal_auth")
                self.results.append(result)

        return self.results

    def get_summary(self) -> Dict[str, Any]:
        """Return summary of bypass testing results.

        Returns:
            Dictionary with counts and finding types
        """
        bypass_count = sum(1 for r in self.results if r.finding)
        return {
            "total_tests": len(self.results),
            "bypasses_found": bypass_count,
            "finding_types": sorted(self.finding_types),
            "severity_counts": dict(collections.Counter(
                r.severity for r in self.results if r.finding
            )),
        }


class RateLimitDetector:
    """Detects rate limiting and brute-force protection mechanisms.

    Sends rapid successive requests to target endpoints and analyzes
    responses for rate limiting indicators (429 status, Retry-After
    headers, CAPTCHA challenges, progressive delays).

    Attributes:
        results: List of rate limit test results
        rate_limited: Whether rate limiting was detected
        rate_limit_type: Type of rate limiting detected
    """

    RATE_LIMIT_INDICATORS: Dict[str, List[str]] = {
        "status_429": ["429"],
        "retry_after": ["Retry-After", "retry-after"],
        "rate_limit_headers": ["X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"],
        "error_messages": [
            "rate limit", "rate_limit", "too many requests", "slow down",
            "try again later", "request limit", "throttled", "blocked",
            "temporarily disabled", "too many attempts",
        ],
    }

    def __init__(self, request_func: Optional[Callable] = None):
        """Initialize the rate limit detector.

        Args:
            request_func: Optional request function for custom transport
        """
        self.results: List[Dict[str, Any]] = []
        self.rate_limited: bool = False
        self.rate_limit_type: str = "none"
        self.request_limit: Optional[int] = None
        self.window_seconds: Optional[int] = None
        self._request_func = request_func or self._default_request

    def _default_request(self, url: str, timeout: int = 10) -> Tuple[int, Dict[str, str], str]:
        """Default request function for rate limit testing.

        Args:
            url: Target URL
            timeout: Request timeout

        Returns:
            Tuple of (status_code, headers_dict, response_body)
        """
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, method="GET")
            start = time.time()
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            elapsed = time.time() - start
            body = resp.read().decode("utf-8", errors="ignore")
            headers = dict(resp.headers)
            resp.close()
            return resp.status, headers, body
        except urllib.error.HTTPError as e:
            elapsed = time.time() - start  # type: ignore
            headers = dict(e.headers)
            body = e.read().decode("utf-8", errors="ignore") if e.fp else ""
            return e.code, headers, body
        except Exception as e:
            logger.debug("Rate limit request failed: %s", e)
            return 0, {}, str(e)

    def test_rate_limit(
        self,
        url: str,
        request_count: int = 20,
        interval: float = 0.1,
        timeout: int = 10,
    ) -> List[Dict[str, Any]]:
        """Test for rate limiting by sending rapid requests.

        Sends a burst of requests and monitors for 429 responses,
        Retry-After headers, and other rate limiting signals.

        Args:
            url: Target URL
            request_count: Number of requests to send
            interval: Delay between requests in seconds
            timeout: Per-request timeout

        Returns:
            List of result dictionaries for each request
        """
        self.results = []
        logger.info("Rate limit testing: %d requests with %.2fs interval", request_count, interval)

        for i in range(request_count):
            if i > 0 and interval > 0:
                time.sleep(interval)

            status, headers, body = self._request_func(url, timeout)
            result: Dict[str, Any] = {
                "request_num": i + 1,
                "status": status,
                "headers": headers,
                "body_sample": body[:200] if body else "",
                "rate_limited": False,
            }

            if status == 429:
                result["rate_limited"] = True
                retry_after = headers.get("Retry-After") or headers.get("retry-after")
                if retry_after:
                    result["retry_after"] = retry_after
                self._detected("status_429")
                logger.info("Rate limit detected via 429 at request %d", i + 1)

            if not result["rate_limited"]:
                for header_name in self.RATE_LIMIT_INDICATORS["rate_limit_headers"]:
                    if header_name in headers or header_name.lower() in headers:
                        result["rate_limited"] = True
                        result["rate_limit_header"] = header_name
                        result["rate_limit_value"] = headers.get(header_name) or headers.get(header_name.lower(), "")
                        self._detected(f"header:{header_name}")

            if not result["rate_limited"]:
                body_lower = body.lower() if body else ""
                for msg in self.RATE_LIMIT_INDICATORS["error_messages"]:
                    if msg in body_lower:
                        result["rate_limited"] = True
                        result["rate_limit_message"] = msg
                        self._detected(f"message:{msg}")
                        break

            if i > 0 and not result["rate_limited"] and self.results:
                prev_status = self.results[-1].get("status")
                if status != prev_status and status in (403, 401, 400):
                    result["rate_limited"] = True
                    self._detected(f"status_change:{prev_status}->{status}")

            self.results.append(result)

        self._finalize()
        return self.results

    def _detected(self, indicator: str) -> None:
        """Record a rate limiting detection indicator.

        Args:
            indicator: Description of the rate limit indicator
        """
        self.rate_limited = True
        if self.rate_limit_type == "none":
            self.rate_limit_type = indicator

    def _finalize(self) -> None:
        """Finalize analysis after all requests complete.

        Calculates the request count before rate limiting kicked in
        and estimates the rate limit window.
        """
        if not self.rate_limited:
            return

        for i, r in enumerate(self.results):
            if r.get("rate_limited"):
                self.request_limit = i + 1
                self.window_seconds = (i + 1) * 0.1  # rough estimate
                break

        logger.info("Rate limiting detected: type=%s, limit=~%d", self.rate_limit_type, self.request_limit or 0)

    def get_summary(self) -> Dict[str, Any]:
        """Return summary of rate limit testing.

        Returns:
            Dictionary with detection status and details
        """
        status_counts = dict(collections.Counter(r["status"] for r in self.results))
        return {
            "rate_limited": self.rate_limited,
            "rate_limit_type": self.rate_limit_type,
            "estimated_limit": self.request_limit,
            "total_requests": len(self.results),
            "status_distribution": status_counts,
            "requests_until_limit": self.request_limit,
        }


class AuthTester:
    """Main authentication testing orchestrator.

    Coordinates all auth testing modules including login detection,
    session analysis, JWT analysis, bypass testing, and rate limit
    detection. Provides a unified interface for comprehensive auth
    security assessment.

    Attributes:
        target_url: Base URL of the target
        login_detector: LoginDetector instance
        session_analyzer: SessionAnalyzer instance
        bypass_tester: BypassTester instance
        rate_limit_detector: RateLimitDetector instance
        results: All collected test results
        session: HTTP session for requests
        timeout: Request timeout in seconds
    """

    def __init__(
        self,
        target_url: str,
        timeout: int = 15,
        threads: int = 5,
    ):
        """Initialize the auth tester.

        Args:
            target_url: Target base URL
            timeout: Request timeout in seconds
            threads: Number of concurrent threads
        """
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.threads = max(1, threads)

        self.login_detector = LoginDetector()
        self.session_analyzer = SessionAnalyzer()
        self.bypass_tester = BypassTester()
        self.rate_limit_detector = RateLimitDetector()
        self.jwt_analyzers: List[JwtAnalyzer] = []

        self.results: List[AuthTestResult] = []
        self.findings: List[Dict[str, Any]] = []
        self.session: Optional[Any] = None
        self._init_session()

    def _init_session(self) -> None:
        """Initialize HTTP session with default headers."""
        try:
            import requests as req
            self.session = req.Session()
            self.session.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.5",
            })
            self.session.verify = False
        except ImportError:
            logger.warning("requests library not available")
            self.session = None

        self.bypass_tester = BypassTester(self.session)
        self.rate_limit_detector = RateLimitDetector()

    def detect_login_form(self, login_url: str = "") -> Dict[str, Any]:
        """Detect and analyze login forms on the target.

        Args:
            login_url: Optional specific login page URL

        Returns:
            Login detection summary
        """
        url = login_url or f"{self.target_url}/login"
        logger.info("Analyzing login form at %s", url)

        try:
            if self.session:
                resp = self.session.get(url, timeout=self.timeout, verify=False)
                html = resp.text
                set_cookies = resp.headers.get_all("Set-Cookie") or [resp.headers.get("Set-Cookie", "")] if hasattr(resp.headers, "get_all") else [resp.headers.get("Set-Cookie", "")]
            else:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(url)
                resp = urllib.request.urlopen(req, timeout=self.timeout, context=ctx)
                html = resp.read().decode("utf-8", errors="ignore")
                set_cookie_header = resp.headers.get("Set-Cookie", "")
                set_cookies = [set_cookie_header] if set_cookie_header else []
                resp.close()

            login_findings = self.login_detector.analyze_html(html, url)

            if set_cookies:
                self.session_analyzer.analyze_cookies(set_cookies, url)

            return {
                "url": url,
                "login_detected": self.login_detector.has_login_form(),
                "mfa_detected": self.login_detector.has_mfa(),
                "fields": self.login_detector.get_summary(),
                "session_issues": self.session_analyzer.get_summary(),
            }

        except Exception as e:
            logger.error("Login form detection failed: %s", e)
            return {"url": url, "error": str(e), "login_detected": False}

    def analyze_jwt(self, token: str) -> Dict[str, Any]:
        """Analyze a JWT token for security issues.

        Args:
            token: JWT token string

        Returns:
            JWT analysis summary with findings
        """
        analyzer = JwtAnalyzer(token)
        self.jwt_analyzers.append(analyzer)
        summary = analyzer.get_summary()

        for finding in summary.get("findings", []):
            self.findings.append({
                "type": "jwt_issue",
                "detail": finding.get("issue", ""),
                "severity": finding.get("severity", "info"),
                "token_summary": {
                    "alg": summary["algorithm"],
                    "claims": list(summary["payload"].keys()),
                },
            })

        return summary

    def run_bypass_tests(
        self,
        protected_url: str = "",
        baseline_status: int = 403,
    ) -> Dict[str, Any]:
        """Run all bypass tests against a protected endpoint.

        Args:
            protected_url: URL of the protected endpoint
            baseline_status: Expected status for blocked requests

        Returns:
            Bypass test summary
        """
        url = protected_url or f"{self.target_url}/admin"

        logger.info("Running bypass tests on %s", url)

        header_results = self.bypass_tester.test_auth_bypass_headers(url, baseline_status, self.timeout)
        self.results.extend(header_results)

        verb_results = self.bypass_tester.test_verb_tampering(url, timeout=self.timeout)
        self.results.extend(verb_results)

        param_results = self.bypass_tester.test_param_tampering(url, "POST", self.timeout)
        self.results.extend(param_results)

        traversal_results = self.bypass_tester.test_path_traversal_auth(self.target_url, protected_path=urllib.parse.urlparse(url).path or "/admin", timeout=self.timeout)
        self.results.extend(traversal_results)

        bypass_summary = self.bypass_tester.get_summary()
        for r in self.results:
            if r.finding:
                self.findings.append({
                    "type": r.finding_type,
                    "detail": r.finding,
                    "severity": r.severity,
                    "url": r.url,
                    "method": r.method,
                    "status": r.status,
                })

        return bypass_summary

    def run_rate_limit_test(
        self,
        target_url: str = "",
        request_count: int = 30,
    ) -> Dict[str, Any]:
        """Run rate limit detection test.

        Args:
            target_url: URL to test for rate limiting
            request_count: Number of requests to send

        Returns:
            Rate limit test summary
        """
        url = target_url or f"{self.target_url}/login"
        logger.info("Running rate limit test on %s (%d requests)", url, request_count)

        self.rate_limit_detector.test_rate_limit(url, request_count=request_count)
        summary = self.rate_limit_detector.get_summary()

        if summary["rate_limited"]:
            self.findings.append({
                "type": "rate_limiting",
                "detail": f"Rate limiting detected via {summary['rate_limit_type']}",
                "severity": "info",
                "estimated_limit": summary["estimated_limit"],
            })

        return summary

    def get_summary(self) -> Dict[str, Any]:
        """Return complete summary of all auth testing.

        Returns:
            Dictionary with all findings and results
        """
        finding_severities = dict(collections.Counter(
            f.get("severity", "info") for f in self.findings
        ))
        return {
            "target": self.target_url,
            "total_findings": len(self.findings),
            "finding_severities": finding_severities,
            "finding_types": list(set(f["type"] for f in self.findings)),
            "total_tests": len(self.results),
        }

    def export_json(self, filepath: str) -> None:
        """Export all results to a JSON file.

        Args:
            filepath: Output file path

        Raises:
            OSError: If the file cannot be written
        """
        try:
            os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
        except OSError:
            pass
        data = {
            "summary": self.get_summary(),
            "findings": self.findings,
            "results": [r.to_dict() for r in self.results],
            "jwt_tokens": [a.get_summary() for a in self.jwt_analyzers],
        }
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            logger.info("Results exported to %s", filepath)
        except OSError as e:
            logger.error("Failed to export JSON: %s", e)
            raise

    def export_csv(self, filepath: str) -> None:
        """Export results to a CSV file.

        Args:
            filepath: Output file path

        Raises:
            OSError: If the file cannot be written
        """
        try:
            os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
        except OSError:
            pass
        try:
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "TestName", "URL", "Method", "Status", "Size",
                    "Elapsed", "Finding", "Type", "Severity",
                ])
                for r in self.results:
                    writer.writerow([
                        r.test_name, r.url, r.method, r.status, r.size,
                        round(r.elapsed, 4), r.finding, r.finding_type, r.severity,
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
        prog="auth_tester.py",
        description="Authentication Testing Tool — Login detection, session analysis, "
                    "JWT inspection, auth bypass testing, verb tampering, and rate limiting.",
        epilog=textwrap.dedent("""
            Examples:
              %(prog)s --target https://example.com
              %(prog)s --target https://example.com --login-url https://example.com/login
              %(prog)s --target https://example.com --test-bypasses
              %(prog)s --target https://example.com --analyze-jwt eyJhbGciOiJI...
              %(prog)s --target https://example.com --rate-limit --credentials admin:test
              %(prog)s --target https://example.com --output results.json
        """),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )
    parser.add_argument(
        "--target", "-t",
        type=str,
        required=True,
        help="Target base URL (e.g., https://example.com)",
    )
    parser.add_argument(
        "--login-url", "-l",
        type=str,
        default=None,
        help="Specific login page URL (default: /login)",
    )
    parser.add_argument(
        "--credentials", "-c",
        type=str,
        default=None,
        help="Credentials for authenticated tests (format: username:password)",
    )
    parser.add_argument(
        "--method", "-m",
        type=str,
        default="POST",
        help="HTTP method for login/param tests (default: POST)",
    )
    parser.add_argument(
        "--test-bypasses", "-b",
        action="store_true",
        help="Run auth bypass header, verb, and parameter tests",
    )
    parser.add_argument(
        "--analyze-jwt", "-j",
        type=str,
        default=None,
        help="Analyze a JWT token (base64 string)",
    )
    parser.add_argument(
        "--rate-limit", "-r",
        action="store_true",
        help="Run rate limit detection test",
    )
    parser.add_argument(
        "--requests",
        type=int,
        default=30,
        help="Number of requests for rate limit test (default: 30)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="Request timeout in seconds (default: 15)",
    )
    parser.add_argument(
        "--threads", "-T",
        type=int,
        default=5,
        help="Number of concurrent threads (default: 5)",
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
    return parser


def main() -> None:
    """Main entry point for the auth tester CLI.

    Parses arguments, configures logging, initializes the tester,
    runs the selected testing modules, and exports results.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    logger.info("Auth tester starting for target: %s", args.target)

    tester = AuthTester(
        target_url=args.target,
        timeout=args.timeout,
        threads=args.threads,
    )

    print("\n" + "=" * 60)
    print("AUTHENTICATION TESTING TOOL")
    print("=" * 60)
    print(f"Target:    {args.target}")
    print(f"Timeout:   {args.timeout}s")
    print(f"Threads:   {args.threads}")
    print("-" * 60)

    try:
        login_url = args.login_url or f"{args.target}/login"

        print(f"\n[1/4] Login form detection at {login_url}...")
        login_result = tester.detect_login_form(login_url)
        if login_result.get("login_detected"):
            print(f"  [+] Login form detected")
            if login_result.get("mfa_detected"):
                print(f"  [+] MFA indicators found")
            ld_summary = login_result.get("fields", {})
            if ld_summary.get("password_fields", 0) > 0:
                print(f"  [+] Password fields: {ld_summary['password_fields']}")
            if ld_summary.get("csrf_tokens", 0) > 0:
                print(f"  [+] CSRF tokens found: {ld_summary['csrf_tokens']}")
        else:
            print(f"  [-] No login form detected")

        session_issues = login_result.get("session_issues", {})
        if session_issues.get("finding_count", 0) > 0:
            print(f"\n  Session Cookie Issues:")
            for sf in session_issues.get("findings", []):
                print(f"    [!] {sf.get('issue', '')}")

        if args.analyze_jwt:
            print(f"\n[2/4] JWT Analysis...")
            jwt_result = tester.analyze_jwt(args.analyze_jwt)
            print(f"  Algorithm: {jwt_result.get('algorithm', 'unknown')}")
            print(f"  Payload claims: {list(jwt_result.get('payload', {}).keys())}")
            jwt_findings = jwt_result.get("findings", [])
            if jwt_findings:
                for f in jwt_findings:
                    print(f"  [{f.get('severity', '?').upper()}] {f.get('issue', '')}")
            else:
                print(f"  No JWT security issues found")

        if args.test_bypasses:
            print(f"\n[3/4] Auth bypass testing...")
            protected = f"{args.target}/admin"
            bypass_result = tester.run_bypass_tests(protected_url=protected)
            if bypass_result.get("bypasses_found", 0) > 0:
                print(f"  [!] Found {bypass_result['bypasses_found']} bypasses!")
                print(f"  Types: {', '.join(bypass_result.get('finding_types', []))}")
                for r in tester.results:
                    if r.finding:
                        print(f"    [{r.severity.upper()}] {r.finding}")
            else:
                print(f"  No bypasses found")

        if args.rate_limit:
            print(f"\n[4/4] Rate limit testing ({args.requests} requests)...")
            rate_result = tester.run_rate_limit_test(request_count=args.requests)
            if rate_result.get("rate_limited"):
                print(f"  [!] Rate limiting detected!")
                print(f"  Type: {rate_result.get('rate_limit_type', 'unknown')}")
                print(f"  Estimated limit: ~{rate_result.get('estimated_limit', '?')} requests")
            else:
                print(f"  No rate limiting detected within {args.requests} requests")

        print("\n" + "=" * 60)
        summary = tester.get_summary()
        print(f"Total Findings: {summary.get('total_findings', 0)}")
        if summary.get("finding_severities"):
            for sev, count in sorted(summary["finding_severities"].items()):
                print(f"  {sev}: {count}")

        if args.output:
            output_path = args.output
            if args.json or output_path.endswith(".json"):
                tester.export_json(output_path)
            elif output_path.endswith(".csv"):
                tester.export_csv(output_path)
            else:
                tester.export_json(f"{output_path}.json")
        else:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            default_output = f"auth_results_{timestamp}.json"
            tester.export_json(default_output)
            print(f"\nResults saved to {default_output}")

    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        print("\n[!] Auth testing interrupted.")
        if tester.results:
            partial = f"auth_partial_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            tester.export_json(partial)
            print(f"[!] Partial results saved to {partial}")
        sys.exit(130)
    except Exception as e:
        logger.error("Auth testing failed: %s", e)
        print(f"\n[!] Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        logger.info("Auth testing completed")


if __name__ == "__main__":
    main()
