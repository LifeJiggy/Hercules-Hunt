#!/usr/bin/env python3
"""
network_utils.py — Network utility functions for Hercules-Hunt.

Provides SSL context building, HTTP fetching with retries, URL parsing and
validation, DNS resolution, TCP port checks, file downloads with progress
tracking, and redirect-chain following.  All functions include type hints,
proper error handling, and logging.
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_TIMEOUT = 30
_DEFAULT_MAX_REDIRECTS = 10
_DOWNLOAD_CHUNK_SIZE = 64 * 1024  # 64 KiB
_MAX_URL_LENGTH = 8192
_MAX_RETRIES = 3
_RETRY_BACKOFF = 1.0  # seconds

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) "
    "Gecko/20100101 Firefox/128.0"
)

# IP address validation regexes
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_IPV6_RE = re.compile(
    r"^\[?([0-9a-fA-F:]{2,39})\]?$"
)

# Valid schemes for HTTP client functions
_VALID_SCHEMES = frozenset({"http", "https"})


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class UrlComponents:
    """Structured breakdown of a parsed URL."""

    scheme: str
    hostname: str
    port: Optional[int]
    path: str
    query: str
    fragment: str
    username: Optional[str]
    password: Optional[str]

    @property
    def netloc(self) -> str:
        """Reconstruct the ``hostname:port`` portion."""
        if self.port is not None:
            return f"{self.hostname}:{self.port}"
        return self.hostname

    @property
    def full_path(self) -> str:
        """Reconstruct ``path?query#fragment``."""
        result = self.path or "/"
        if self.query:
            result = f"{result}?{self.query}"
        if self.fragment:
            result = f"{result}#{self.fragment}"
        return result

    def __str__(self) -> str:
        creds = ""
        if self.username:
            pw = f":{self.password}" if self.password else ""
            creds = f"{self.username}{pw}@"
        return f"{self.scheme}://{creds}{self.netloc}{self.full_path}"


@dataclass
class RedirectStep:
    """A single hop in a redirect chain."""

    url: str
    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"<RedirectStep {self.status_code} -> {self.url}>"


# ---------------------------------------------------------------------------
# SSL context
# ---------------------------------------------------------------------------


def build_ssl_context(
    allow_insecure: bool = False,
    protocol: Optional[int] = None,
    ciphers: Optional[str] = None,
) -> ssl.SSLContext:
    """Create a hardened SSL/TLS context.

    When *allow_insecure* is ``True``, certificate verification is disabled
    — use **only** for testing against hosts with self-signed certificates.

    Args:
        allow_insecure: Skip certificate verification (default ``False``).
        protocol: SSL protocol constant (defaults to
            :data:`ssl.PROTOCOL_TLS_CLIENT`).
        ciphers: OpenSSL cipher string.  If ``None``, a secure subset is used.

    Returns:
        Configured :class:`ssl.SSLContext`.

    Example:
        >>> ctx = build_ssl_context(allow_insecure=True)
        >>> isinstance(ctx, ssl.SSLContext)
        True
    """
    if protocol is None:
        protocol = ssl.PROTOCOL_TLS_CLIENT

    ctx = ssl.SSLContext(protocol=protocol)

    # Enforce modern TLS — disable SSLv2, SSLv3, TLSv1, TLSv1.1
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    if ciphers:
        ctx.set_ciphers(ciphers)
    else:
        # Restrict to strong ciphers
        ctx.set_ciphers(
            "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!MD5:!DSS"
        )

    if allow_insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        logger.warning("SSL certificate verification is DISABLED")
    else:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            ctx.load_default_certs()
        except ssl.SSLError as exc:
            logger.warning("Could not load default CA certs: %s", exc)

    return ctx


# ---------------------------------------------------------------------------
# HTTP client factory
# ---------------------------------------------------------------------------


def build_http_client(
    timeout: int = _DEFAULT_TIMEOUT,
    allow_insecure: bool = False,
    headers: Optional[Dict[str, str]] = None,
) -> "_HttpClient":
    """Create a reusable HTTP client with the given configuration.

    The returned :class:`_HttpClient` instance can be used for multiple
    requests while reusing the same SSL context and connection-pool settings.

    Args:
        timeout: Request timeout in seconds (default 30).
        allow_insecure: Disable SSL verification (default ``False``).
        headers: Default headers sent with every request.

    Returns:
        A configured :class:`_HttpClient` instance.
    """
    ssl_ctx = build_ssl_context(allow_insecure=allow_insecure)
    req_headers = dict(headers or {})
    req_headers.setdefault("User-Agent", _USER_AGENT)
    return _HttpClient(timeout=timeout, ssl_context=ssl_ctx, headers=req_headers)


class _HttpClient:
    """Lightweight HTTP client wrapping :mod:`urllib.request`.

    This is intentionally kept dependency-free so no third-party libraries
    (``requests``, ``httpx``) are required.
    """

    def __init__(
        self,
        timeout: int,
        ssl_context: ssl.SSLContext,
        headers: Dict[str, str],
    ) -> None:
        self._timeout = timeout
        self._ssl_context = ssl_context
        self._headers = headers

    @property
    def timeout(self) -> int:
        return self._timeout

    def _request(
        self,
        method: str,
        url: str,
        body: Optional[bytes] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> "urllib.request.Request":
        # Import here to avoid top-level side effects
        import urllib.request

        merged = dict(self._headers)
        if extra_headers:
            merged.update(extra_headers)
        req = urllib.request.Request(url, data=body, headers=merged, method=method)
        return req

    def _open(
        self, req: "urllib.request.Request"
    ) -> Tuple["http.client.HTTPResponse", str]:
        import urllib.request

        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self._ssl_context)
        )
        response = opener.open(req, timeout=self._timeout)
        final_url = response.geturl()
        return response, final_url  # type: ignore[return-value]

    def request(
        self,
        method: str,
        url: str,
        body: Optional[bytes] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[bytes, int, Dict[str, str]]:
        """Execute an HTTP request and return ``(body, status, headers)``."""
        req = self._request(method, url, body=body, extra_headers=extra_headers)
        response, final_url = self._open(req)
        data = response.read()
        status = response.status
        headers = dict(response.headers)
        response.close()
        return data, status, headers


# ---------------------------------------------------------------------------
# URL fetching
# ---------------------------------------------------------------------------


def fetch_url(
    url: str,
    timeout: int = _DEFAULT_TIMEOUT,
    headers: Optional[Dict[str, str]] = None,
    allow_insecure: bool = False,
    retries: int = _MAX_RETRIES,
) -> Tuple[bytes, int, Dict[str, str]]:
    """Fetch a URL and return ``(content, status_code, response_headers)``.

    Implements automatic retries with exponential backoff for transient
    errors (connection resets, DNS failures, timeouts).  Non-transient HTTP
    status codes (4xx, 5xx) are returned immediately without retry.

    Args:
        url: Target URL.
        timeout: Request timeout in seconds (default 30).
        headers: Additional request headers.
        allow_insecure: Disable SSL verification (default ``False``).
        retries: Max retries on transient errors (default 3).

    Returns:
        Tuple of ``(bytes_content, status_code, headers_dict)``.

    Raises:
        ValueError: If *url* is invalid or exceeds max length.
        ssl.SSLError: On SSL negotiation failure.
        urllib.error.URLError: On unrecoverable network errors.
    """
    validate_url(url)
    client = build_http_client(
        timeout=timeout, allow_insecure=allow_insecure, headers=headers
    )

    last_exc: Optional[Exception] = None
    attempt = 0

    while attempt <= retries:
        try:
            data, status, resp_headers = client.request("GET", url)
        except Exception as exc:
            last_exc = exc
            # Only retry on transient (connection-level) errors
            if _is_transient_error(exc):
                attempt += 1
                if attempt > retries:
                    logger.error(
                        "fetch_url failed after %d retries: %s", retries, exc
                    )
                    raise
                backoff = _RETRY_BACKOFF * (2 ** (attempt - 1))
                logger.warning(
                    "Retry %d/%d for %s after %s (%.1fs)",
                    attempt,
                    retries,
                    url,
                    exc,
                    backoff,
                )
                time.sleep(backoff)
                continue
            raise

        logger.debug("GET %s -> %d (%d bytes)", url, status, len(data))
        return data, status, resp_headers

    # Should never reach here — re-raise last exception as fallback
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("Unreachable: fetch_url retry exhausted with no exception")


def _is_transient_error(exc: Exception) -> bool:
    """Return ``True`` if *exc* is likely a transient network error."""
    exc_name = type(exc).__name__
    exc_str = str(exc).lower()

    # urllib wraps socket/SSL errors in URLError — check the inner cause
    inner = getattr(exc, "reason", None) or getattr(exc, "args", (None,))[0]
    if inner is not None and not isinstance(inner, str):
        return _is_transient_error(inner)

    transient_patterns = (
        "timeout",
        "connection reset",
        "connection refused",
        "connection aborted",
        "connection closed",
        "name or service not known",
        "temporary failure",
        "no route to host",
        "network is unreachable",
        "eof occurred",
        "broken pipe",
        "ssl: certificate_verify_failed",
    )
    return any(p in exc_str for p in transient_patterns)


def fetch_json(
    url: str,
    timeout: int = _DEFAULT_TIMEOUT,
    headers: Optional[Dict[str, str]] = None,
    allow_insecure: bool = False,
) -> Any:
    """Fetch a URL and deserialise the response body as JSON.

    Args:
        url: Target URL.
        timeout: Request timeout (default 30).
        headers: Additional request headers.
        allow_insecure: Disable SSL verification (default ``False``).

    Returns:
        The deserialised Python object.

    Raises:
        ValueError: If *url* is invalid or response is not valid JSON.
        urllib.error.URLError: On network errors.
    """
    content, status, _ = fetch_url(
        url, timeout=timeout, headers=headers, allow_insecure=allow_insecure
    )

    if status >= 400:
        raise ValueError(
            f"fetch_json received HTTP {status} for {url}: "
            f"{content.decode('utf-8', errors='replace')[:500]}"
        )

    import json

    try:
        return json.loads(content.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(
            f"Response from {url} is not valid JSON: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# URL parsing and validation
# ---------------------------------------------------------------------------


def _normalize_port(scheme: str, port: Optional[int]) -> Optional[int]:
    """Return ``None`` when *port* matches the default for *scheme*."""
    if port is None:
        return None
    defaults = {"http": 80, "https": 443}
    if defaults.get(scheme) == port:
        return None
    return port


def parse_url(url: str) -> UrlComponents:
    """Parse a URL string into structured :class:`UrlComponents`.

    Validates that the URL is well-formed and uses a recognised scheme.

    Args:
        url: URL string (e.g. ``https://example.com:8080/path?a=1#sec``).

    Returns:
        A :class:`UrlComponents` instance.

    Raises:
        ValueError: If the URL is malformed, too long, or uses an unsupported
            scheme.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL must be a non-empty string")

    if len(url) > _MAX_URL_LENGTH:
        raise ValueError(
            f"URL exceeds maximum length of {_MAX_URL_LENGTH} characters "
            f"({len(url)} given)"
        )

    parsed = urlparse(url.strip())

    if not parsed.scheme:
        raise ValueError(f"URL is missing a scheme: {url!r}")
    if parsed.scheme not in _VALID_SCHEMES:
        raise ValueError(
            f"Unsupported URL scheme {parsed.scheme!r} in {url!r}. "
            f"Only {sorted(_VALID_SCHEMES)} are supported."
        )
    if not parsed.hostname:
        raise ValueError(f"URL has no hostname: {url!r}")

    port = _normalize_port(parsed.scheme, parsed.port)

    return UrlComponents(
        scheme=parsed.scheme,
        hostname=parsed.hostname,
        port=port,
        path=parsed.path or "/",
        query=parsed.query,
        fragment=parsed.fragment,
        username=parsed.username,
        password=parsed.password,
    )


def validate_url(url: str) -> bool:
    """Validate that a URL is well-formed, has a recognised scheme, and is
    under the length limit.

    This is a lighter-weight check than :func:`parse_url` — it returns a
    boolean suitable for guards and assertions.

    Args:
        url: URL string to validate.

    Returns:
        ``True`` if the URL is valid.

    Raises:
        ValueError: With a descriptive message when the URL is invalid.
    """
    parse_url(url)  # raises ValueError on any problem
    return True


# ---------------------------------------------------------------------------
# DNS resolution
# ---------------------------------------------------------------------------


def resolve_hostname(hostname: str, family: int = socket.AF_INET) -> List[str]:
    """Resolve a hostname to a list of IP addresses.

    By default only IPv4 addresses are returned.  Pass
    ``family=socket.AF_INET6`` for IPv6 or ``family=socket.AF_UNSPEC`` for
    both.

    Args:
        hostname: Hostname or IP literal to resolve.
        family: Address family (default :data:`socket.AF_INET`).

    Returns:
        List of IP address strings.

    Raises:
        ValueError: If *hostname* is empty.
        socket.gaierror: On resolution failure.
    """
    if not hostname or not hostname.strip():
        raise ValueError("hostname must be a non-empty string")

    hostname = hostname.strip()
    try:
        info = socket.getaddrinfo(hostname, None, family=family)
    except socket.gaierror as exc:
        logger.error("DNS resolution failed for %s: %s", hostname, exc)
        raise

    seen: set = set()
    results: List[str] = []
    for entry in info:
        ip = entry[4][0]
        if ip not in seen:
            seen.add(ip)
            results.append(ip)

    logger.debug("resolve_hostname(%s) -> %s", hostname, results)
    return results


# ---------------------------------------------------------------------------
# Port checking
# ---------------------------------------------------------------------------


def check_port(
    host: str,
    port: int,
    timeout: int = 5,
    family: int = socket.AF_INET,
) -> bool:
    """Check if a TCP port is open on the given host.

    Attempts a TCP connection and returns ``True`` if it succeeds.

    Args:
        host: Hostname or IP.
        port: TCP port number (1–65535).
        timeout: Connection timeout in seconds (default 5).
        family: Address family (default :data:`socket.AF_INET`).

    Returns:
        ``True`` if the port is open, ``False`` otherwise.

    Raises:
        ValueError: If *port* is out of range or *host* is empty.
    """
    if not host:
        raise ValueError("host must be a non-empty string")
    if not 1 <= port <= 65535:
        raise ValueError(f"port must be in 1–65535, got {port}")

    try:
        resolved = resolve_hostname(host, family=family)
    except socket.gaierror:
        logger.warning("check_port: could not resolve %s", host)
        return False

    for ip in resolved:
        try:
            sock = socket.create_connection(
                (ip, port), timeout=timeout
            )
            sock.close()
            logger.debug("Port %d is open on %s (%s)", port, host, ip)
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            continue

    logger.debug("Port %d is closed on %s", port, host)
    return False


# ---------------------------------------------------------------------------
# File download
# ---------------------------------------------------------------------------


def download_file(
    url: str,
    dest_path: Union[str, Path],
    timeout: int = 60,
    allow_insecure: bool = False,
    headers: Optional[Dict[str, str]] = None,
) -> Path:
    """Download a file from *url* to *dest_path* with progress logging.

    The download streams data in chunks so it can handle arbitrarily large
    files without exhausting memory.

    Args:
        url: Source URL.
        dest_path: Local destination path.
        timeout: Request timeout in seconds (default 60).
        allow_insecure: Disable SSL verification (default ``False``).
        headers: Additional request headers.

    Returns:
        The :class:`Path` of the downloaded file.

    Raises:
        ValueError: If *url* is invalid.
        urllib.error.URLError: On network errors.
        OSError: On local write failures.
    """
    validate_url(url)
    dest = Path(dest_path)

    # Ensure parent directory exists
    dest.parent.mkdir(parents=True, exist_ok=True)

    client = build_http_client(
        timeout=timeout, allow_insecure=allow_insecure, headers=headers
    )
    req = client._request("GET", url)
    response, final_url = client._open(req)

    total_bytes = 0
    try:
        with open(str(dest), mode="wb") as fh:
            while True:
                chunk = response.read(_DOWNLOAD_CHUNK_SIZE)
                if not chunk:
                    break
                fh.write(chunk)
                total_bytes += len(chunk)
    except OSError as exc:
        logger.error("Failed to write download to %s: %s", dest, exc)
        response.close()
        raise
    except Exception:
        response.close()
        raise

    response.close()
    logger.info("Downloaded %s (%d bytes) -> %s", url, total_bytes, dest)
    return dest


# ---------------------------------------------------------------------------
# Redirect-chain follower
# ---------------------------------------------------------------------------


def _resolve_redirect(
    client: _HttpClient,
    step: RedirectStep,
    max_hops: int,
    seen: set,
) -> List[RedirectStep]:
    """Recursive helper for :func:`get_redirect_chain`."""
    if len(seen) >= max_hops:
        logger.warning("Redirect chain exceeded %d hops, stopping", max_hops)
        return [step]

    location = step.headers.get("Location") or step.headers.get("location")
    if not location:
        return [step]

    # Resolve relative redirects
    resolved = urllib.parse.urljoin(step.url, location)
    if resolved in seen:
        logger.warning("Redirect cycle detected at %s", resolved)
        return [step]

    seen.add(resolved)
    try:
        data, status, headers = client.request("GET", resolved)
        new_step = RedirectStep(url=resolved, status_code=status, headers=headers)
    except Exception as exc:
        logger.warning("Redirect follow failed at %s: %s", resolved, exc)
        return [step]

    # Return current step + recursion (to build full chain)
    return [step] + _resolve_redirect(client, new_step, max_hops, seen)


def get_redirect_chain(
    url: str,
    max_hops: int = _DEFAULT_MAX_REDIRECTS,
    timeout: int = _DEFAULT_TIMEOUT,
    allow_insecure: bool = False,
) -> List[RedirectStep]:
    """Follow the redirect chain starting from *url*.

    Each hop is recorded as a :class:`RedirectStep` with the URL, status
    code, and response headers.  Result includes the initial request as the
    first element.

    Args:
        url: Starting URL.
        max_hops: Maximum redirects to follow (default 10).
        timeout: Request timeout (default 30).
        allow_insecure: Disable SSL verification (default ``False``).

    Returns:
        List of :class:`RedirectStep` instances, starting with the original
        request and ending with the terminal (non-redirect) response.

    Raises:
        ValueError: If *url* is invalid.
    """
    validate_url(url)
    client = build_http_client(
        timeout=timeout, allow_insecure=allow_insecure
    )

    # Initial request
    data, status, headers = client.request("GET", url)
    first = RedirectStep(url=url, status_code=status, headers=headers)

    if status not in (301, 302, 303, 307, 308):
        return [first]

    seen: set = {url}
    chain = _resolve_redirect(client, first, max_hops, seen)

    if len(chain) > 1:
        logger.info(
            "Redirect chain: %s", " -> ".join(s.url for s in chain)
        )
    return chain


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------


def is_ip_address(value: str) -> bool:
    """Check if *value* is a valid IPv4 or IPv6 address string.

    Args:
        value: String to test.

    Returns:
        ``True`` if *value* is an IP address.
    """
    return bool(_IPV4_RE.match(value) or _IPV6_RE.match(value))


def is_reachable(
    host: str,
    port: int = 443,
    timeout: int = 5,
) -> bool:
    """Quick reachability check — resolves hostname and tests TCP port.

    This is a convenience function combining :func:`resolve_hostname` and
    :func:`check_port`.

    Args:
        host: Hostname or IP.
        port: TCP port (default 443).
        timeout: Connection timeout (default 5).

    Returns:
        ``True`` if the host is reachable on the given port.
    """
    return check_port(host, port, timeout=timeout)


def extract_domain(url: str) -> str:
    """Extract the domain (hostname) from a URL string.

    This is a lightweight alternative to :func:`parse_url` when only the
    hostname is needed.

    Args:
        url: URL string.

    Returns:
        The hostname portion (e.g. ``example.com``).

    Raises:
        ValueError: If the URL is invalid.
    """
    return parse_url(url).hostname
