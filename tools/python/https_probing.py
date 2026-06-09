#!/usr/bin/env python3
"""
https_probing.py — HTTPS/TLS Probing Tool (P1)

Probes HTTPS endpoints for TLS configuration weaknesses, certificate chain
issues, cipher suite strength, and missing security headers. Produces a
ranked security report suitable for bug-bounty and red-team engagements.

Features:
  - TLS protocol version detection (1.0 / 1.1 / 1.2 / 1.3)
  - Certificate chain analysis (expiry, issuer, subject, SAN, self-signed)
  - Cipher suite enumeration via OpenSSL subprocess
  - Security header analysis (HSTS, CSP, XFO, XCTO, XXSS, RP, PP)
  - Weak certificate detection (SHA1, short keys, expired, not-yet-valid)
  - JSON / human-readable report generation
  - Configurable timeouts, verbose logging, output to file
"""

import argparse
import base64
import collections
import datetime
import hashlib
import html.parser
import http.client
import json
import logging
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger("https_probing")
LOG_FMT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(LOG_FMT))
    logger.setLevel(level)
    logger.addHandler(handler)
    logger.propagate = False


_SECURITY_HEADERS: Dict[str, str] = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "CSP",
    "X-Frame-Options": "XFO",
    "X-Content-Type-Options": "XCTO",
    "X-XSS-Protection": "XXSS",
    "Referrer-Policy": "RP",
    "Permissions-Policy": "PP",
}

_WEAK_SIGNATURE_ALGOS: Set[str] = {"sha1", "sha1withrsaencryption", "md2", "md4", "md5"}
_WEAK_KEY_SIZES: Set[int] = {512, 1024, 2048}
_PROTOCOL_VERSIONS: List[str] = [
    "tls1_3", "tls1_2", "tls1_1", "tls1",
]
_PROTOCOL_LABELS: Dict[str, str] = {
    "tls1_3": "TLS 1.3", "tls1_2": "TLS 1.2",
    "tls1_1": "TLS 1.1", "tls1": "TLS 1.0",
}

_KNOWN_WEAK_CIPHERS: Set[str] = {
    "rc4", "des", "3des", "md5", "export", "null", "anon",
    "e_null", "aecdh", "aedh",
}

_DEFAULT_TIMEOUT: float = 10.0
_DEFAULT_USER_AGENT: str = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class CertificateInfo:
    subject: str = ""
    issuer: str = ""
    serial_number: str = ""
    not_before: Optional[datetime.datetime] = None
    not_after: Optional[datetime.datetime] = None
    san_list: List[str] = field(default_factory=list)
    is_self_signed: bool = False
    signature_algorithm: str = ""
    key_size: int = 0
    fingerprint_sha256: str = ""
    fingerprint_sha1: str = ""
    ocsp_must_staple: bool = False
    is_expired: bool = False
    is_not_yet_valid: bool = False
    days_remaining: int = 0
    weaknesses: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "san_list": self.san_list,
            "is_self_signed": self.is_self_signed,
            "signature_algorithm": self.signature_algorithm,
            "key_size": self.key_size,
            "fingerprint_sha256": self.fingerprint_sha256,
            "fingerprint_sha1": self.fingerprint_sha1,
            "ocsp_must_staple": self.ocsp_must_staple,
            "is_expired": self.is_expired,
            "is_not_yet_valid": self.is_not_yet_valid,
            "days_remaining": self.days_remaining,
            "weaknesses": self.weaknesses,
        }
        return d


@dataclass
class CipherSuite:
    name: str = ""
    protocol: str = ""
    key_exchange: str = ""
    authentication: str = ""
    encryption: str = ""
    mac: str = ""
    is_weak: bool = False
    weakness_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityHeaderResult:
    name: str = ""
    short_name: str = ""
    present: bool = False
    value: str = ""
    issues: List[str] = field(default_factory=list)
    severity: str = "info"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TlsProbeResult:
    host: str = ""
    port: int = 443
    supports_tls_1_0: bool = False
    supports_tls_1_1: bool = False
    supports_tls_1_2: bool = False
    supports_tls_1_3: bool = False
    preferred_protocol: str = ""
    certificates: List[CertificateInfo] = field(default_factory=list)
    cipher_suites: List[CipherSuite] = field(default_factory=list)
    security_headers: Dict[str, SecurityHeaderResult] = field(default_factory=dict)
    total_weaknesses: int = 0
    score: int = 100
    scan_errors: List[str] = field(default_factory=list)
    scan_time: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "supports_tls_1_0": self.supports_tls_1_0,
            "supports_tls_1_1": self.supports_tls_1_1,
            "supports_tls_1_2": self.supports_tls_1_2,
            "supports_tls_1_3": self.supports_tls_1_3,
            "preferred_protocol": self.preferred_protocol,
            "certificates": [c.to_dict() for c in self.certificates],
            "cipher_suites": [c.to_dict() for c in self.cipher_suites],
            "security_headers": {k: v.to_dict() for k, v in self.security_headers.items()},
            "total_weaknesses": self.total_weaknesses,
            "score": self.score,
            "scan_errors": self.scan_errors,
            "scan_time": self.scan_time,
        }


# ---------------------------------------------------------------------------
# CertificateAnalyzer
# ---------------------------------------------------------------------------

class CertificateAnalyzer:
    """Parses and analyzes X.509 SSL/TLS certificate chains."""

    def __init__(self, timeout: float = _DEFAULT_TIMEOUT):
        self.timeout = timeout
        self.logger = logging.getLogger(f"{__name__}.CertificateAnalyzer")

    def analyze(self, host: str, port: int = 443) -> List[CertificateInfo]:
        """Connect to host:port, retrieve certificate chain, return analyzed list."""
        results: List[CertificateInfo] = []
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.load_default_certs()
            raw_sock = socket.create_connection((host, port), timeout=self.timeout)
            with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
                der_certs = ssock.getpeercert(binary_form=True)
                chain = ssock.get_extra_info("socket") if hasattr(ssock, "get_extra_info") else None
                all_certs: List[bytes] = [der_certs] if der_certs else []
                try:
                    alt_certs = []
                    if hasattr(ssock, "get_unverified_chain"):
                        alt_certs = list(ssock.get_unverified_chain())
                    elif hasattr(ssock, "_sslobj"):
                        obj = ssock._sslobj
                        if hasattr(obj, "get_unverified_chain"):
                            alt_certs = list(obj.get_unverified_chain())
                    for c in alt_certs:
                        if isinstance(c, bytes):
                            all_certs.append(c)
                except Exception:
                    pass
                for idx, der in enumerate(all_certs):
                    try:
                        info = self._parse_der_certificate(der, idx)
                        results.append(info)
                    except Exception as exc:
                        self.logger.warning("Failed to parse cert %d: %s", idx, exc)
            raw_sock.close()
        except socket.timeout:
            self.logger.error("Connection timeout to %s:%d", host, port)
        except socket.gaierror as exc:
            self.logger.error("DNS resolution failed for %s: %s", host, exc)
        except ConnectionRefusedError:
            self.logger.error("Connection refused %s:%d", host, port)
        except ssl.SSLError as exc:
            self.logger.error("SSL error for %s:%d — %s", host, port, exc)
        except OSError as exc:
            self.logger.error("OS error for %s:%d — %s", host, port, exc)
        except Exception as exc:
            self.logger.error("Unexpected error analyzing %s:%d — %s", host, port, exc)
        if not results:
            self.logger.warning("No certificates retrieved from %s:%d", host, port)
        return results

    def _parse_der_certificate(self, der_bytes: bytes, index: int = 0) -> CertificateInfo:
        """Parse a DER-encoded X.509 certificate and return CertificateInfo."""
        info = CertificateInfo()
        try:
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False, suffix=".der") as tmp:
                tmp.write(der_bytes)
                tmp_path = tmp.name
            try:
                pem = subprocess.check_output(
                    ["openssl", "x509", "-inform", "DER", "-in", tmp_path],
                    stderr=subprocess.DEVNULL,
                    timeout=self.timeout,
                )
                text = subprocess.check_output(
                    ["openssl", "x509", "-inform", "DER", "-in", tmp_path, "-text", "-noout"],
                    stderr=subprocess.DEVNULL,
                    timeout=self.timeout,
                ).decode("utf-8", errors="replace")
                info = self._parse_openssl_text(text, pem.decode("utf-8", errors="replace"), der_bytes)
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
        except subprocess.TimeoutExpired:
            self.logger.warning("openssl timeout parsing cert %d", index)
        except FileNotFoundError:
            self.logger.warning("openssl not found — using minimal DER parsing for cert %d", index)
            info = self._parse_der_minimal(der_bytes, index)
        except subprocess.CalledProcessError as exc:
            self.logger.warning("openssl error parsing cert %d: %s", index, exc)
        except Exception as exc:
            self.logger.warning("Error parsing cert %d: %s", index, exc)
        return info

    def _parse_openssl_text(self, text: str, pem: str, der: bytes) -> CertificateInfo:
        """Parse openssl x509 -text output into CertificateInfo."""
        info = CertificateInfo()
        try:
            m_subj = re.search(r"Subject:\s*(.+?)(?:\n|$)", text)
            if m_subj:
                info.subject = m_subj.group(1).strip()

            m_issuer = re.search(r"Issuer:\s*(.+?)(?:\n|$)", text)
            if m_issuer:
                info.issuer = m_issuer.group(1).strip()

            m_serial = re.search(r"Serial Number:\s*(.+?)(?:\n|$)", text, re.IGNORECASE)
            if m_serial:
                info.serial_number = m_serial.group(1).strip()

            m_not_before = re.search(r"Not Before:\s*(.+?)(?:\n|$)", text)
            if m_not_before:
                try:
                    info.not_before = self._parse_openssl_date(m_not_before.group(1).strip())
                except Exception:
                    pass

            m_not_after = re.search(r"Not After\s*:\s*(.+?)(?:\n|$)", text)
            if not m_not_after:
                m_not_after = re.search(r"Not After:\s*(.+?)(?:\n|$)", text)
            if m_not_after:
                try:
                    info.not_after = self._parse_openssl_date(m_not_after.group(1).strip())
                except Exception:
                    pass

            m_sig = re.search(r"Signature Algorithm:\s*(.+?)(?:\n|$)", text)
            if m_sig:
                info.signature_algorithm = m_sig.group(1).strip().lower()

            m_san = re.search(r"X509v3 Subject Alternative Name:\s*\n\s*(.+?)(?:\n\S|\n\n|\Z)", text, re.DOTALL)
            if m_san:
                raw = m_san.group(1).strip()
                parts = re.findall(r"(?:DNS|IP|email|URI):([^\s,]+)", raw)
                info.san_list = [p.strip() for p in parts if p.strip()]

            m_key = re.search(r"Public-Key:\s*\((\d+)\s*bit", text)
            if m_key:
                info.key_size = int(m_key.group(1))

            m_ocsp = re.search(r"1\.3\.6\.1\.5\.5\.7\.1\.1|OCSP", text)
            if m_ocsp:
                info.ocsp_must_staple = True

            info.fingerprint_sha256 = self._compute_fingerprint(der, "sha256")
            info.fingerprint_sha1 = self._compute_fingerprint(der, "sha1")

            if info.subject and info.issuer and (
                info.subject == info.issuer or
                re.sub(r"\s+", "", info.subject) == re.sub(r"\s+", "", info.issuer)
            ):
                info.is_self_signed = True

            now = datetime.datetime.utcnow()
            if info.not_before and info.not_after:
                if info.not_after < now:
                    info.is_expired = True
                    info.weaknesses.append("certificate_expired")
                if info.not_before > now:
                    info.is_not_yet_valid = True
                    info.weaknesses.append("certificate_not_yet_valid")
                delta = info.not_after - now
                info.days_remaining = delta.days if delta.days >= 0 else 0

            if info.signature_algorithm:
                for weak_algo in _WEAK_SIGNATURE_ALGOS:
                    if weak_algo in info.signature_algorithm:
                        info.weaknesses.append(f"weak_signature_algorithm:{info.signature_algorithm}")
                        break

            if info.key_size in _WEAK_KEY_SIZES:
                info.weaknesses.append(f"short_key_size:{info.key_size}")
        except Exception as exc:
            self.logger.warning("Error parsing openssl text: %s", exc)
        return info

    @staticmethod
    def _parse_openssl_date(date_str: str) -> Optional[datetime.datetime]:
        """Parse various date formats from OpenSSL output."""
        for fmt in [
            "%b %d %H:%M:%S %Y %Z",
            "%b %d %H:%M:%S %Y GMT",
            "%b %d %H:%M:%S %Y",
            "%Y-%m-%d %H:%M:%S %Z",
            "%Y-%m-%d %H:%M:%S",
        ]:
            try:
                return datetime.datetime.strptime(date_str.strip(), fmt)
            except ValueError:
                continue
        try:
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(date_str.strip())
            return dt.replace(tzinfo=None)
        except Exception:
            pass
        return None

    @staticmethod
    def _compute_fingerprint(der: bytes, algo: str = "sha256") -> str:
        h = hashlib.new(algo, der)
        return h.hexdigest().upper()

    def _parse_der_minimal(self, der: bytes, index: int) -> CertificateInfo:
        """Fallback minimal parsing when openssl is unavailable."""
        info = CertificateInfo()
        try:
            import struct
            # attempt to extract a few bytes from ASN.1 structure
            info.subject = f"<der cert #{index}>"
            info.fingerprint_sha256 = self._compute_fingerprint(der, "sha256")
            info.fingerprint_sha1 = self._compute_fingerprint(der, "sha1")
            info.key_size = len(der) * 4  # rough estimate
        except Exception:
            pass
        return info

    def check_weaknesses(self, info: CertificateInfo) -> List[str]:
        """Run additional weakness checks on a certificate."""
        issues: List[str] = []
        if info.is_self_signed:
            issues.append("self_signed_certificate")
        if info.is_expired:
            issues.append("certificate_expired")
        if info.is_not_yet_valid:
            issues.append("certificate_not_yet_valid")
        if info.days_remaining < 30:
            issues.append("certificate_expiring_soon")
        for w in info.weaknesses:
            if w not in issues:
                issues.append(w)
        return issues


# ---------------------------------------------------------------------------
# CipherScanner
# ---------------------------------------------------------------------------

class CipherScanner:
    """Enumerates supported cipher suites for a given host:port using OpenSSL."""

    def __init__(self, timeout: float = _DEFAULT_TIMEOUT):
        self.timeout = timeout
        self.logger = logging.getLogger(f"{__name__}.CipherScanner")

    def scan_all(self, host: str, port: int = 443) -> List[CipherSuite]:
        """Scan all TLS protocol versions for supported cipher suites."""
        all_ciphers: List[CipherSuite] = []
        for proto_key in _PROTOCOL_VERSIONS:
            try:
                suites = self._scan_protocol(host, port, proto_key)
                all_ciphers.extend(suites)
            except Exception as exc:
                self.logger.debug("Cipher scan failed for %s/%s: %s", proto_key, host, exc)
        return all_ciphers

    def _scan_protocol(self, host: str, port: int, proto: str) -> List[CipherSuite]:
        """Run openssl s_client for a specific protocol version."""
        results: List[CipherSuite] = []
        try:
            cipher_list = self._get_cipher_list_for_protocol(proto)
            if not cipher_list:
                self.logger.debug("No cipher list found for %s", proto)
                return results
            batch_size = 50
            for i in range(0, len(cipher_list), batch_size):
                batch = cipher_list[i:i + batch_size]
                test_cipher = ":".join(batch) if batch else "ALL"
                cmd = [
                    "openssl", "s_client",
                    "-connect", f"{host}:{port}",
                    "-cipher", test_cipher,
                    "-servername", host,
                ]
                if proto == "tls1_3":
                    cmd.extend(["-tls1_3"])
                elif proto == "tls1_2":
                    cmd.extend(["-tls1_2"])
                elif proto == "tls1_1":
                    cmd.extend(["-tls1_1"])
                elif proto == "tls1":
                    cmd.extend(["-tls1"])
                cmd.extend(["-no_alt_chains", "-verify_return_error"])
                try:
                    proc = subprocess.run(
                        cmd,
                        capture_output=True,
                        timeout=self.timeout,
                        text=True,
                    )
                    stdout = proc.stdout or ""
                    stderr = proc.stderr or ""
                    if "BEGIN CERTIFICATE" in stdout:
                        for cipher in batch:
                            cs = CipherSuite(
                                name=cipher,
                                protocol=_PROTOCOL_LABELS.get(proto, proto),
                            )
                            self._classify_cipher(cs)
                            results.append(cs)
                except subprocess.TimeoutExpired:
                    self.logger.debug("Timeout scanning %s ciphers for %s", proto, host)
                except FileNotFoundError:
                    self.logger.error("openssl not found — cannot scan ciphers")
                    return results
                except Exception as exc:
                    self.logger.debug("Error scanning %s ciphers: %s", proto, exc)
        except Exception as exc:
            self.logger.debug("Error in _scan_protocol(%s): %s", proto, exc)
        return results

    def _get_cipher_list_for_protocol(self, proto: str) -> List[str]:
        """Return a list of cipher names for a given protocol version."""
        try:
            cmd = ["openssl", "ciphers", "-v"]
            if proto == "tls1_3":
                cmd.append("-tls1_3")
            elif proto == "tls1_2":
                cmd.append("-tls1_2")
            elif proto == "tls1_1":
                cmd.append("-tls1_1")
            elif proto == "tls1":
                cmd.append("-tls1")
            else:
                cmd.append("-tls1_2")
            proc = subprocess.run(cmd, capture_output=True, timeout=self.timeout, text=True)
            lines = proc.stdout.strip().split("\n") if proc.stdout else []
            ciphers: List[str] = []
            for line in lines:
                parts = line.split()
                if parts:
                    ciphers.append(parts[0])
            return ciphers
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            self.logger.debug("Could not get cipher list: %s", exc)
            return []

    def _classify_cipher(self, cs: CipherSuite) -> None:
        """Determine if a cipher suite is weak based on its name."""
        name_lower = cs.name.lower()
        for weak_kw in _KNOWN_WEAK_CIPHERS:
            if weak_kw in name_lower:
                cs.is_weak = True
                cs.weakness_reason = f"uses {weak_kw.upper()}"
                break
        if cs.is_weak and not cs.weakness_reason:
            cs.weakness_reason = "known weak cipher suite"

    def detect_protocol_support(self, host: str, port: int = 443) -> Dict[str, bool]:
        """Detect which TLS protocol versions a server supports via openssl."""
        support: Dict[str, bool] = {
            "tls1_3": False, "tls1_2": False,
            "tls1_1": False, "tls1": False,
        }
        for proto_key in _PROTOCOL_VERSIONS:
            try:
                label = _PROTOCOL_LABELS.get(proto_key, proto_key)
                cmd = [
                    "openssl", "s_client",
                    "-connect", f"{host}:{port}",
                    "-servername", host,
                    "-no_alt_chains",
                ]
                if proto_key == "tls1_3":
                    cmd.extend(["-tls1_3"])
                elif proto_key == "tls1_2":
                    cmd.extend(["-tls1_2"])
                elif proto_key == "tls1_1":
                    cmd.extend(["-tls1_1"])
                elif proto_key == "tls1":
                    cmd.extend(["-tls1"])
                cmd.extend(["-verify_return_error", "-brief"])
                proc = subprocess.run(
                    cmd, capture_output=True, timeout=self.timeout,
                    input=b"Q\n", text=True,
                )
                support[proto_key] = "BEGIN CERTIFICATE" in (proc.stdout or "")
            except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
                self.logger.debug("Protocol detection for %s failed: %s", proto_key, exc)
            except Exception as exc:
                self.logger.debug("Unexpected error detecting %s: %s", proto_key, exc)
        return support


# ---------------------------------------------------------------------------
# HeaderAnalyzer
# ---------------------------------------------------------------------------

class HeaderAnalyzer:
    """Analyzes HTTP response security headers."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.HeaderAnalyzer")

    def analyze(self, host: str, port: int = 443, timeout: float = _DEFAULT_TIMEOUT) -> Dict[str, SecurityHeaderResult]:
        """Fetch the HTTPS response and analyze security headers."""
        results: Dict[str, SecurityHeaderResult] = {}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
            conn.request("GET", "/", headers={
                "User-Agent": _DEFAULT_USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            })
            resp = conn.getresponse()
            headers = dict(resp.getheaders())
            for header_name, short_name in _SECURITY_HEADERS.items():
                result = SecurityHeaderResult(
                    name=header_name, short_name=short_name,
                )
                raw_value = headers.get(header_name) or headers.get(header_name.lower(), "")
                if raw_value:
                    result.present = True
                    result.value = raw_value
                    self._analyze_header_value(result)
                else:
                    result.present = False
                    result.issues.append(f"missing_{short_name.lower()}_header")
                    result.severity = "medium"
                results[header_name] = result
            conn.close()
        except ssl.SSLError as exc:
            self.logger.error("SSL error fetching headers from %s: %s", host, exc)
        except http.client.HTTPException as exc:
            self.logger.error("HTTP error fetching headers from %s: %s", host, exc)
        except socket.timeout:
            self.logger.error("Timeout fetching headers from %s", host)
        except ConnectionRefusedError:
            self.logger.error("Connection refused fetching headers from %s", host)
        except Exception as exc:
            self.logger.error("Unexpected error fetching headers from %s: %s", host, exc)
        return results

    def _analyze_header_value(self, result: SecurityHeaderResult) -> None:
        """Analyze a single security header value for weaknesses."""
        name_lower = result.name.lower()
        val_lower = result.value.lower()

        if "strict-transport-security" in name_lower:
            if "max-age=" not in val_lower:
                result.issues.append("hsts_missing_max_age")
                result.severity = "high"
            else:
                m = re.search(r"max-age=(\d+)", val_lower)
                if m:
                    max_age = int(m.group(1))
                    if max_age < 31536000:
                        result.issues.append(f"hsts_max_age_too_short:{max_age}")
                        result.severity = "low"
                    else:
                        result.severity = "info"
                if "includesubdomains" not in val_lower:
                    result.issues.append("hsts_missing_include_subdomains")
                    result.severity = "low"
                if "preload" in val_lower:
                    result.severity = "info"

        elif "content-security-policy" in name_lower:
            if "default-src" not in val_lower and "default-src" not in val_lower:
                result.issues.append("csp_missing_default_src")
                result.severity = "medium"
            if "'unsafe-inline'" in val_lower:
                result.issues.append("csp_unsafe_inline_allowed")
                result.severity = "medium"
            if "'unsafe-eval'" in val_lower:
                result.issues.append("csp_unsafe_eval_allowed")
                result.severity = "low"
            if "*" in val_lower and "default-src" in val_lower:
                result.issues.append("csp_wildcard_default_src")
                result.severity = "high"
            result.severity = "info"

        elif "x-frame-options" in name_lower:
            if val_lower not in ("deny", "sameorigin"):
                result.issues.append(f"xfo_not_restrictive:{result.value}")
                result.severity = "high"
            elif "allow-from" in val_lower:
                result.issues.append("xfo_uses_deprecated_allow_from")
                result.severity = "low"
            else:
                result.severity = "info"

        elif "x-content-type-options" in name_lower:
            if "nosniff" not in val_lower:
                result.issues.append("xcto_not_nosniff")
                result.severity = "high"
            else:
                result.severity = "info"

        elif "x-xss-protection" in name_lower:
            if "0" in val_lower:
                result.severity = "info"
            elif "1" in val_lower:
                result.issues.append("xxss_deprecated_header")
                result.severity = "low"
            else:
                result.issues.append("xxss_unexpected_value")
                result.severity = "low"

        elif "referrer-policy" in name_lower:
            strict_policies = {
                "no-referrer", "same-origin", "strict-origin",
                "strict-origin-when-cross-origin", "no-referrer-when-downgrade",
            }
            if val_lower.strip() not in strict_policies:
                result.issues.append(f"rp_not_strict:{result.value}")
                result.severity = "low"
            else:
                result.severity = "info"

        elif "permissions-policy" in name_lower:
            if not val_lower.strip():
                result.issues.append("pp_empty_policy")
                result.severity = "medium"
            else:
                dangerous_features = ["camera", "microphone", "geolocation", "usb"]
                for feat in dangerous_features:
                    if f"({feat} *=" not in val_lower and f"({feat}=" not in val_lower:
                        if f"({feat})" not in val_lower and feat not in val_lower:
                            continue
                result.severity = "info"

    def analyze_from_raw_headers(self, raw_headers: Dict[str, str]) -> Dict[str, SecurityHeaderResult]:
        """Analyze security headers from a raw header dictionary."""
        results: Dict[str, SecurityHeaderResult] = {}
        for header_name, short_name in _SECURITY_HEADERS.items():
            result = SecurityHeaderResult(name=header_name, short_name=short_name)
            raw_value = ""
            for k, v in raw_headers.items():
                if k.lower() == header_name.lower():
                    raw_value = v
                    break
            if raw_value:
                result.present = True
                result.value = raw_value
                self._analyze_header_value(result)
            else:
                result.present = False
                result.issues.append(f"missing_{short_name.lower()}_header")
                result.severity = "medium"
            results[header_name] = result
        return results


# ---------------------------------------------------------------------------
# TlsProber
# ---------------------------------------------------------------------------

class TlsProber:
    """Master orchestrator that runs all TLS checks against a target."""

    def __init__(
        self,
        timeout: float = _DEFAULT_TIMEOUT,
        verbose: bool = False,
    ):
        self.timeout = timeout
        self.verbose = verbose
        self.cert_analyzer = CertificateAnalyzer(timeout=timeout)
        self.cipher_scanner = CipherScanner(timeout=timeout)
        self.header_analyzer = HeaderAnalyzer()
        self.logger = logging.getLogger(f"{__name__}.TlsProber")

    def probe(
        self,
        host: str,
        port: int = 443,
        check_cert: bool = True,
        cipher_scan: bool = True,
    ) -> TlsProbeResult:
        """
        Run a full TLS probe against host:port.

        Returns a TlsProbeResult containing certificates, cipher suites,
        protocol support, security headers, and a numeric score.
        """
        result = TlsProbeResult(host=host, port=port)
        result.scan_time = datetime.datetime.utcnow().isoformat()
        self.logger.info("Probing %s:%d", host, port)

        # Protocol support detection
        try:
            proto_support = self.cipher_scanner.detect_protocol_support(host, port)
            result.supports_tls_1_0 = proto_support.get("tls1", False)
            result.supports_tls_1_1 = proto_support.get("tls1_1", False)
            result.supports_tls_1_2 = proto_support.get("tls1_2", False)
            result.supports_tls_1_3 = proto_support.get("tls1_3", False)
            if result.supports_tls_1_3:
                result.preferred_protocol = "TLS 1.3"
            elif result.supports_tls_1_2:
                result.preferred_protocol = "TLS 1.2"
            elif result.supports_tls_1_1:
                result.preferred_protocol = "TLS 1.1"
            elif result.supports_tls_1_0:
                result.preferred_protocol = "TLS 1.0"
        except Exception as exc:
            self.logger.error("Protocol detection failed: %s", exc)
            result.scan_errors.append(f"protocol_detection:{exc}")

        # Certificate chain analysis
        if check_cert:
            try:
                certs = self.cert_analyzer.analyze(host, port)
                if certs:
                    result.certificates = certs
                    for cert in certs:
                        if cert.is_expired:
                            result.total_weaknesses += 1
                        if cert.is_self_signed:
                            result.total_weaknesses += 2
                        if cert.is_not_yet_valid:
                            result.total_weaknesses += 2
                        for w in cert.weaknesses:
                            if "weak_signature" in w:
                                result.total_weaknesses += 2
                            elif "short_key" in w:
                                result.total_weaknesses += 1
                else:
                    result.scan_errors.append("no_certificates_retrieved")
            except Exception as exc:
                self.logger.error("Certificate analysis failed: %s", exc)
                result.scan_errors.append(f"certificate_analysis:{exc}")

        # Cipher suite enumeration
        if cipher_scan:
            try:
                ciphers = self.cipher_scanner.scan_all(host, port)
                if ciphers:
                    result.cipher_suites = ciphers
                    weak_count = sum(1 for c in ciphers if c.is_weak)
                    result.total_weaknesses += weak_count
                else:
                    self.logger.warning("No cipher suites enumerated — may indicate openssl is unavailable")
            except Exception as exc:
                self.logger.error("Cipher scan failed: %s", exc)
                result.scan_errors.append(f"cipher_scan:{exc}")

        # Security header analysis
        try:
            headers = self.header_analyzer.analyze(host, port, self.timeout)
            result.security_headers = headers
            missing_count = sum(1 for h in headers.values() if not h.present)
            result.total_weaknesses += missing_count
            for hdr in headers.values():
                if hdr.severity == "high":
                    result.total_weaknesses += 2
                elif hdr.severity == "medium":
                    result.total_weaknesses += 1
        except Exception as exc:
            self.logger.error("Header analysis failed: %s", exc)
            result.scan_errors.append(f"header_analysis:{exc}")

        # Compute final score
        result.score = max(0, 100 - result.total_weaknesses * 5)
        return result

    def probe_from_url(self, url: str, **kwargs) -> TlsProbeResult:
        """Parse a URL and probe the host:port."""
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return self.probe(host, port, **kwargs)


# ---------------------------------------------------------------------------
# SecurityReport
# ---------------------------------------------------------------------------

class SecurityReport:
    """Generates human-readable and JSON reports from TlsProbeResult."""

    def __init__(self, result: TlsProbeResult):
        self.result = result
        self.logger = logging.getLogger(f"{__name__}.SecurityReport")

    def to_dict(self) -> Dict[str, Any]:
        return self.result.to_dict()

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_text(self) -> str:
        """Generate a human-readable text report."""
        r = self.result
        lines: List[str] = []
        lines.append("=" * 70)
        lines.append(f"TLS Security Report — {r.host}:{r.port}")
        lines.append("=" * 70)
        lines.append(f"Scan time:           {r.scan_time}")
        lines.append(f"Score:               {r.score}/100")
        lines.append(f"Total weaknesses:    {r.total_weaknesses}")
        lines.append(f"Preferred protocol:  {r.preferred_protocol}")
        lines.append("")

        lines.append("--- Protocol Support ---")
        lines.append(f"  TLS 1.3:  {'YES' if r.supports_tls_1_3 else 'NO'}")
        lines.append(f"  TLS 1.2:  {'YES' if r.supports_tls_1_2 else 'NO'}")
        lines.append(f"  TLS 1.1:  {'YES' if r.supports_tls_1_1 else 'NO'}")
        lines.append(f"  TLS 1.0:  {'YES' if r.supports_tls_1_0 else 'NO'}")
        lines.append("")

        lines.append("--- Certificate Chain ---")
        if r.certificates:
            for i, cert in enumerate(r.certificates):
                lines.append(f"  Certificate #{i + 1}:")
                lines.append(f"    Subject:      {cert.subject}")
                lines.append(f"    Issuer:       {cert.issuer}")
                lines.append(f"    Signature:    {cert.signature_algorithm}")
                lines.append(f"    Key size:     {cert.key_size} bit")
                not_after_str = cert.not_after.isoformat() if cert.not_after else "N/A"
                lines.append(f"    Expires:      {not_after_str} ({cert.days_remaining} days)")
                lines.append(f"    Self-signed:  {cert.is_self_signed}")
                lines.append(f"    SAN count:    {len(cert.san_list)}")
                if cert.weaknesses:
                    for w in cert.weaknesses:
                        lines.append(f"    [!] Weakness: {w}")
        else:
            lines.append("  (no certificates retrieved)")
        lines.append("")

        lines.append("--- Cipher Suites ---")
        if r.cipher_suites:
            weak_ciphers = [c for c in r.cipher_suites if c.is_weak]
            strong_ciphers = [c for c in r.cipher_suites if not c.is_weak]
            lines.append(f"  Total:     {len(r.cipher_suites)}")
            lines.append(f"  Strong:    {len(strong_ciphers)}")
            lines.append(f"  Weak:      {len(weak_ciphers)}")
            if weak_ciphers:
                lines.append("  Weak ciphers:")
                for c in weak_ciphers:
                    lines.append(f"    - {c.name} ({c.protocol}) [{c.weakness_reason}]")
            lines.append("  First 20 strong ciphers:")
            for c in strong_ciphers[:20]:
                lines.append(f"    - {c.name} ({c.protocol})")
        else:
            lines.append("  (cipher scan not available)")
        lines.append("")

        lines.append("--- Security Headers ---")
        for hdr_name, hdr_result in r.security_headers.items():
            status = "PRESENT" if hdr_result.present else "MISSING"
            lines.append(f"  {hdr_name}: {status}")
            if hdr_result.present and hdr_result.value:
                lines.append(f"    Value: {hdr_result.value}")
            for issue in hdr_result.issues:
                lines.append(f"    [!] {issue}")
        lines.append("")

        if r.scan_errors:
            lines.append("--- Errors ---")
            for err in r.scan_errors:
                lines.append(f"  [!] {err}")
            lines.append("")

        lines.append("--- Recommendations ---")
        recs = self._generate_recommendations()
        for rec in recs:
            lines.append(f"  * {rec}")
        lines.append("")

        return "\n".join(lines)

    def _generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations based on findings."""
        recs: List[str] = []
        r = self.result
        if r.supports_tls_1_0:
            recs.append("Disable TLS 1.0 — it is deprecated and vulnerable to protocol downgrade attacks.")
        if r.supports_tls_1_1:
            recs.append("Disable TLS 1.1 — it is deprecated and should be replaced by TLS 1.2+.")
        if r.certificates:
            for cert in r.certificates:
                if cert.is_expired:
                    recs.append(f"Renew expired certificate for {cert.subject} immediately.")
                if cert.is_self_signed:
                    recs.append("Replace self-signed certificate with a CA-issued certificate.")
                if cert.days_remaining < 30:
                    recs.append(f"Certificate for {cert.subject} expires in {cert.days_remaining} days — renew soon.")
        weak_ciphers = [c for c in r.cipher_suites if c.is_weak]
        if weak_ciphers:
            recs.append(f"Disable {len(weak_ciphers)} weak cipher suites: {', '.join(c.name for c in weak_ciphers[:5])}.")
        for hdr_name, hdr_result in r.security_headers.items():
            if not hdr_result.present:
                short = hdr_result.short_name
                recs.append(f"Implement the {hdr_name} ({short}) header.")
        return recs

    def export_json(self, filepath: str) -> None:
        """Write JSON report to a file."""
        try:
            dirname = os.path.dirname(os.path.abspath(filepath))
            if dirname:
                os.makedirs(dirname, exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(self.to_json())
            self.logger.info("JSON report written to %s", filepath)
        except OSError as exc:
            self.logger.error("Failed to write JSON report to %s: %s", filepath, exc)

    def export_text(self, filepath: str) -> None:
        """Write text report to a file."""
        try:
            dirname = os.path.dirname(os.path.abspath(filepath))
            if dirname:
                os.makedirs(dirname, exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(self.to_text())
            self.logger.info("Text report written to %s", filepath)
        except OSError as exc:
            self.logger.error("Failed to write text report to %s: %s", filepath, exc)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="https_probing",
        description="HTTPS/TLS Probing Tool — probes endpoints for TLS configuration, "
                    "certificate issues, cipher strength, and security header gaps.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python https_probing.py --target example.com\n"
            "  python https_probing.py --url https://example.com:8443 --check-cert --cipher-scan\n"
            "  python https_probing.py --target example.com --json --output report.json\n"
            "  python https_probing.py --target example.com --timeout 15 --verbose\n"
        ),
    )
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--target", "-t", type=str, default="",
        help="Target hostname (default port 443)",
    )
    target_group.add_argument(
        "--url", "-u", type=str, default="",
        help="Full URL (e.g. https://example.com:8443)",
    )
    parser.add_argument("--port", "-p", type=int, default=443, help="Target port (default: 443)")
    parser.add_argument(
        "--output", "-o", type=str, default="",
        help="Write report to file (appends .json or .txt based on --json flag)",
    )
    parser.add_argument(
        "--check-cert", "-c", action="store_true", default=True,
        help="Perform certificate chain analysis (default: True)",
    )
    parser.add_argument(
        "--no-check-cert", action="store_true", dest="no_check_cert",
        help="Skip certificate chain analysis",
    )
    parser.add_argument(
        "--cipher-scan", action="store_true", default=True,
        help="Enumerate cipher suites via OpenSSL (default: True)",
    )
    parser.add_argument(
        "--no-cipher-scan", action="store_true", dest="no_cipher_scan",
        help="Skip cipher suite enumeration",
    )
    parser.add_argument(
        "--timeout", type=float, default=_DEFAULT_TIMEOUT,
        help=f"Connection timeout in seconds (default: {_DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--json", "-j", action="store_true", default=False,
        help="Output JSON (default: human-readable text)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", default=False,
        help="Enable verbose debug logging",
    )
    return parser.parse_args(argv)


def main() -> None:
    args = parse_args()
    _setup_logging(verbose=args.verbose)

    host: str = args.target
    port: int = args.port
    if args.url:
        parsed = urllib.parse.urlparse(args.url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if not host:
        logger.error("No target host specified")
        sys.exit(1)

    check_cert = args.check_cert and not args.no_check_cert
    cipher_scan = args.cipher_scan and not args.no_cipher_scan

    logger.info("Starting TLS probe — %s:%d (cert=%s, cipher=%s)", host, port, check_cert, cipher_scan)

    prober = TlsProber(timeout=args.timeout, verbose=args.verbose)
    result = prober.probe(host, port, check_cert=check_cert, cipher_scan=cipher_scan)
    report = SecurityReport(result)

    if args.json:
        output = report.to_json()
        print(output)
    else:
        output = report.to_text()
        print(output)

    if args.output:
        if args.json:
            report.export_json(args.output)
        else:
            report.export_text(args.output)

    # Non-zero exit if weaknesses found
    if result.total_weaknesses > 0:
        logger.warning("Found %d weaknesses — score: %d/100", result.total_weaknesses, result.score)
    else:
        logger.info("No weaknesses found — score: %d/100", result.score)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(130)
    except Exception as exc:
        logger.error("Unhandled exception: %s", exc)
        if logger.isEnabledFor(logging.DEBUG):
            import traceback
            traceback.print_exc()
        sys.exit(1)
