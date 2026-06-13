#!/usr/bin/env python3
"""Input validation and sanitization utilities for bug bounty hunting workflows.

Provides comprehensive validation for URLs, domains, IPs, emails, ports,
file paths, HTTP methods, status codes, and sanitization for filenames,
HTML, and shell arguments. All functions include proper type hints,
error handling, and docstrings.
"""

import json
import re
import os
import socket
import string
from typing import Optional, Tuple, Union
from urllib.parse import urlparse, quote


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_HTTP_METHODS = frozenset({
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS",
    "TRACE", "PATCH",
})

VALID_HTTP_STATUS_RANGES = {
    "1xx": range(100, 200),
    "2xx": range(200, 300),
    "3xx": range(300, 400),
    "4xx": range(400, 500),
    "5xx": range(500, 600),
}

SAFE_FILENAME_CHARS = frozenset(
    string.ascii_letters + string.digits + "._-"
)

MAX_URL_LENGTH = 8192
MAX_PARAM_VALUE_LENGTH = 4096
MAX_TRUNCATE_LENGTH = 100

# RFC 3986 unreserved characters
URL_UNRESERVED = string.ascii_letters + string.digits + "-._~"

# Regex patterns (compiled once at module load)
_RE_IPV4 = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
)

_RE_IPV6 = re.compile(
    r"^("
    r"([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
    r"([0-9a-fA-F]{1,4}:){1,7}:|"
    r"([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
    r"([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
    r"([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
    r"([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
    r"([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
    r"[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
    r":((:[0-9a-fA-F]{1,4}){1,7}|:)|"
    r"fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|"
    r"::(ffff(:0{1,4}){0,1}:){0,1}"
    r"((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}"
    r"(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|"
    r"([0-9a-fA-F]{1,4}:){1,4}:"
    r"((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}"
    r"(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])"
    r")$"
)

_RE_DOMAIN = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}$"
)

_RE_EMAIL = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)

_RE_HEADER_NAME = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]*$")

_RE_PARAM_NAME = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_\[\]]*$")

_RE_HTML_TAG = re.compile(r"<[^>]*>")

_RE_PATH_TRAVERSAL = re.compile(
    r"(?:^|[/\\])\.\.[/\\]"
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ValidationError(ValueError):
    """Raised when a validation check fails."""
    pass


class SanitizationError(ValueError):
    """Raised when a sanitization operation fails."""
    pass


# ---------------------------------------------------------------------------
# URL validation
# ---------------------------------------------------------------------------

def validate_url(
    url: str, max_length: int = MAX_URL_LENGTH
) -> Tuple[bool, Optional[str]]:
    """Validate a URL string format, scheme, and length.

    Args:
        url: The URL string to validate.
        max_length: Maximum allowed URL length (default 8192).

    Returns:
        Tuple of (is_valid, error_message). If valid, error_message is None.

    Example:
        >>> validate_url("https://example.com/path?q=1")
        (True, None)
        >>> validate_url("ftp://bad")
        (False, "Invalid URL scheme: ftp")
    """
    if not url or not isinstance(url, str):
        return False, "URL must be a non-empty string"

    if len(url) > max_length:
        return (
            False,
            f"URL exceeds maximum length of {max_length} characters",
        )

    try:
        parsed = urlparse(url)
    except Exception as exc:
        return False, f"Failed to parse URL: {exc}"

    if not parsed.scheme:
        return False, "URL must have a scheme (http/https)"

    if parsed.scheme not in ("http", "https"):
        return False, f"Invalid URL scheme: {parsed.scheme}"

    if not parsed.netloc:
        return False, "URL must have a network location (host)"

    netloc = parsed.netloc
    at_index = netloc.find("@")
    if at_index != -1:
        netloc = netloc[at_index + 1:]

    colon_index = netloc.find(":")
    host = netloc[:colon_index] if colon_index != -1 else netloc

    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
        ip_valid, _ = validate_ip(host)
        if not ip_valid:
            return False, "Invalid IPv6 address in URL"
    else:
        domain_valid, _ = validate_domain(host)
        ip_valid, _ = validate_ip(host)
        if not domain_valid and not ip_valid:
            return False, f"Invalid host in URL: {host}"

    return True, None


def is_valid_url(url: str) -> bool:
    """Boolean check if a string is a valid URL.

    Args:
        url: The URL string to check.

    Returns:
        True if valid, False otherwise.
    """
    valid, _ = validate_url(url)
    return valid


# ---------------------------------------------------------------------------
# Domain validation
# ---------------------------------------------------------------------------

def validate_domain(
    domain: str,
) -> Tuple[bool, Optional[str]]:
    """Validate a domain name string according to RFC 1035.

    Args:
        domain: The domain name to validate.

    Returns:
        Tuple of (is_valid, error_message).

    Example:
        >>> validate_domain("example.com")
        (True, None)
        >>> validate_domain("-bad.com")
        (False, "Domain name format is invalid")
    """
    if not domain or not isinstance(domain, str):
        return False, "Domain must be a non-empty string"

    if len(domain) > 253:
        return False, "Domain name exceeds maximum length of 253 characters"

    if domain.endswith("."):
        domain = domain[:-1]

    if not _RE_DOMAIN.match(domain):
        return False, "Domain name format is invalid"

    return True, None


def is_valid_domain(domain: str) -> bool:
    """Boolean check if a string is a valid domain name.

    Args:
        domain: The domain string to check.

    Returns:
        True if valid, False otherwise.
    """
    valid, _ = validate_domain(domain)
    return valid


# ---------------------------------------------------------------------------
# IP validation
# ---------------------------------------------------------------------------

def validate_ip(ip: str) -> Tuple[bool, Optional[str]]:
    """Validate an IPv4 or IPv6 address string.

    Uses socket layer for IPv6, regex + range check for IPv4.

    Args:
        ip: The IP address string to validate.

    Returns:
        Tuple of (is_valid, error_message).

    Example:
        >>> validate_ip("192.168.1.1")
        (True, None)
        >>> validate_ip("::1")
        (True, None)
        >>> validate_ip("999.999.999.999")
        (False, "IPv4 octet out of range: 999")
    """
    if not ip or not isinstance(ip, str):
        return False, "IP must be a non-empty string"

    # Try IPv4 first
    match = _RE_IPV4.match(ip)
    if match:
        for octet_str in match.groups():
            octet = int(octet_str)
            if octet > 255:
                return (
                    False,
                    f"IPv4 octet out of range: {octet}",
                )
        return True, None

    # Try IPv6
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True, None
    except (socket.error, OSError):
        pass

    if _RE_IPV6.match(ip):
        return True, None

    return False, "Invalid IP address format"


def is_valid_ip(ip: str) -> bool:
    """Boolean check if a string is a valid IP address.

    Args:
        ip: The IP string to check.

    Returns:
        True if valid, False otherwise.
    """
    valid, _ = validate_ip(ip)
    return valid


# ---------------------------------------------------------------------------
# Email validation
# ---------------------------------------------------------------------------

def validate_email(
    email: str,
) -> Tuple[bool, Optional[str]]:
    """Validate an email address format.

    Validates structure per RFC 5321 simplified rules. Does NOT
    verify that the domain exists or that the mailbox is deliverable.

    Args:
        email: The email address to validate.

    Returns:
        Tuple of (is_valid, error_message).

    Example:
        >>> validate_email("user@example.com")
        (True, None)
        >>> validate_email("not-an-email")
        (False, "Email format is invalid")
    """
    if not email or not isinstance(email, str):
        return False, "Email must be a non-empty string"

    if len(email) > 254:
        return False, "Email exceeds maximum length of 254 characters"

    if not _RE_EMAIL.match(email):
        return False, "Email format is invalid"

    local_part, domain_part = email.rsplit("@", 1)

    if len(local_part) > 64:
        return False, "Email local part exceeds 64 characters"

    if local_part.startswith(".") or local_part.endswith("."):
        return False, "Email local part cannot start or end with a dot"

    if ".." in local_part:
        return False, "Email local part cannot contain consecutive dots"

    domain_valid, domain_err = validate_domain(domain_part)
    if not domain_valid:
        return False, f"Invalid email domain: {domain_err}"

    return True, None


# ---------------------------------------------------------------------------
# Port validation
# ---------------------------------------------------------------------------

def validate_port(port: int) -> Tuple[bool, Optional[str]]:
    """Validate a TCP/UDP port number.

    Args:
        port: The port number to validate (1-65535).

    Returns:
        Tuple of (is_valid, error_message).

    Example:
        >>> validate_port(80)
        (True, None)
        >>> validate_port(0)
        (False, "Port must be between 1 and 65535")
    """
    if not isinstance(port, int):
        return False, "Port must be an integer"

    if port < 1 or port > 65535:
        return False, "Port must be between 1 and 65535"

    return True, None


# ---------------------------------------------------------------------------
# File path validation
# ---------------------------------------------------------------------------

def validate_file_path(
    path: str, project_root: Optional[str] = None
) -> Tuple[bool, Optional[str]]:
    """Validate a file path for safety (no path traversal, within project).

    Checks for path traversal sequences (``..``) and ensures the
    resolved path stays within the project root directory.

    Args:
        path: The file path to validate.
        project_root: Project root directory. If None, auto-detected
            from the current file's location.

    Returns:
        Tuple of (is_valid, error_message).

    Example:
        >>> validate_file_path("data/output.txt")
        (True, None)
        >>> validate_file_path("../../../etc/passwd")
        (False, "Path traversal detected")
    """
    if not path or not isinstance(path, str):
        return False, "Path must be a non-empty string"

    if _RE_PATH_TRAVERSAL.search(path):
        return False, "Path traversal detected"

    if os.path.isabs(path):
        return False, "Absolute paths are not allowed"

    if project_root is None:
        project_root = os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )

    resolved = os.path.normpath(os.path.join(project_root, path))
    resolved_real = os.path.realpath(resolved)

    project_real = os.path.realpath(project_root)

    if not resolved_real.startswith(project_real + os.sep):
        if resolved_real != project_real:
            return False, "Path escapes project root directory"

    return True, None


# ---------------------------------------------------------------------------
# HTTP method / status validation
# ---------------------------------------------------------------------------

def validate_http_method(
    method: str,
) -> Tuple[bool, Optional[str]]:
    """Validate an HTTP method string.

    Accepts standard methods from RFC 7231 and RFC 5789.

    Args:
        method: The HTTP method to validate (case-sensitive, uppercase).

    Returns:
        Tuple of (is_valid, error_message).

    Example:
        >>> validate_http_method("GET")
        (True, None)
        >>> validate_http_method("INVALID")
        (False, "Invalid HTTP method: INVALID")
    """
    if not method or not isinstance(method, str):
        return False, "HTTP method must be a non-empty string"

    if method in VALID_HTTP_METHODS:
        return True, None

    return False, f"Invalid HTTP method: {method}"


def validate_http_status(
    status: int,
) -> Tuple[bool, Optional[str]]:
    """Validate an HTTP status code.

    Args:
        status: The HTTP status code to validate (100-599).

    Returns:
        Tuple of (is_valid, error_message).

    Example:
        >>> validate_http_status(200)
        (True, None)
        >>> validate_http_status(99)
        (False, "HTTP status code must be between 100 and 599")
    """
    if not isinstance(status, int):
        return False, "HTTP status must be an integer"

    if status < 100 or status > 599:
        return False, "HTTP status code must be between 100 and 599"

    for label, codes in VALID_HTTP_STATUS_RANGES.items():
        if status in codes:
            return True, None

    return True, None


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------

def sanitize_filename(filename: str) -> str:
    """Remove dangerous or invalid characters from a filename.

    Retains only alphanumerics, dots, underscores, and hyphens.
    Strips leading/trailing dots and spaces.

    Args:
        filename: The filename to sanitize.

    Returns:
        Sanitized filename string.

    Raises:
        SanitizationError: If the result is an empty string.

    Example:
        >>> sanitize_filename("hello<world>:*.txt")
        'helloworld.txt'
    """
    if not filename or not isinstance(filename, str):
        raise SanitizationError("Filename must be a non-empty string")

    sanitized = "".join(
        ch for ch in filename if ch in SAFE_FILENAME_CHARS
    )

    sanitized = sanitized.strip(". ")

    if not sanitized:
        raise SanitizationError(
            "Filename is empty after sanitization"
        )

    return sanitized


def sanitize_html(text: str) -> str:
    """Strip all HTML tags from a string.

    Reuses compiled regex for performance. Does not decode HTML entities.

    Args:
        text: The text to sanitize.

    Returns:
        Text with all HTML tags removed.

    Example:
        >>> sanitize_html("<p>Hello <b>world</b></p>")
        'Hello world'
    """
    if not text or not isinstance(text, str):
        return ""

    return _RE_HTML_TAG.sub("", text)


def sanitize_shell_arg(arg: str) -> str:
    """Sanitize a shell argument to prevent command injection.

    Uses a whitelist approach: only allows alphanumeric characters,
    underscores, hyphens, dots, forward slashes, and colons. All other
    characters are removed.

    Args:
        arg: The shell argument to sanitize.

    Returns:
        Sanitized shell argument string.

    Raises:
        SanitizationError: If the result is empty after sanitization.

    Example:
        >>> sanitize_shell_arg("example.com")
        'example.com'
        >>> sanitize_shell_arg("foo; rm -rf /")
        'foorm-rf'
    """
    if not arg or not isinstance(arg, str):
        raise SanitizationError("Shell argument must be a non-empty string")

    safe_chars = set(string.ascii_letters + string.digits + "_-./:@")
    sanitized = "".join(ch for ch in arg if ch in safe_chars)

    if not sanitized:
        raise SanitizationError(
            "Shell argument is empty after sanitization"
        )

    return sanitized


# ---------------------------------------------------------------------------
# JSON validation
# ---------------------------------------------------------------------------

def is_valid_json(text: str) -> bool:
    """Check if a string is valid JSON.

    Args:
        text: The string to check.

    Returns:
        True if the string is valid JSON, False otherwise.

    Example:
        >>> is_valid_json('{"key": "value"}')
        True
        >>> is_valid_json('not json')
        False
    """
    if not isinstance(text, str):
        return False

    try:
        json.loads(text)
        return True
    except (json.JSONDecodeError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Parameter validation
# ---------------------------------------------------------------------------

def validate_param_name(
    name: str,
) -> Tuple[bool, Optional[str]]:
    """Validate an HTTP parameter name.

    Allowed pattern: starts with a letter or underscore, followed by
    letters, digits, underscores, or square brackets (for array params).

    Args:
        name: The parameter name to validate.

    Returns:
        Tuple of (is_valid, error_message).

    Example:
        >>> validate_param_name("user_id")
        (True, None)
        >>> validate_param_name("123invalid")
        (False, "Invalid parameter name format")
    """
    if not name or not isinstance(name, str):
        return False, "Parameter name must be a non-empty string"

    if not _RE_PARAM_NAME.match(name):
        return False, "Invalid parameter name format"

    return True, None


def validate_param_value(
    value: str, max_length: int = MAX_PARAM_VALUE_LENGTH
) -> Tuple[bool, Optional[str]]:
    """Validate an HTTP parameter value.

    Checks length and character safety. Allows URL-encoded values.

    Args:
        value: The parameter value to validate.
        max_length: Maximum allowed length (default 4096).

    Returns:
        Tuple of (is_valid, error_message).

    Example:
        >>> validate_param_value("test_value")
        (True, None)
    """
    if not isinstance(value, str):
        return False, "Parameter value must be a string"

    if len(value) > max_length:
        return (
            False,
            f"Parameter value exceeds max length of {max_length}",
        )

    for char in value:
        if ord(char) < 32 and char not in ("\t", "\n", "\r"):
            return False, "Parameter value contains control characters"

    return True, None


# ---------------------------------------------------------------------------
# Header validation
# ---------------------------------------------------------------------------

def validate_header_name(
    name: str,
) -> Tuple[bool, Optional[str]]:
    """Validate an HTTP header name.

    Headers must start with a letter and contain only letters,
    digits, hyphens, and underscores.

    Args:
        name: The header name to validate.

    Returns:
        Tuple of (is_valid, error_message).

    Example:
        >>> validate_header_name("Content-Type")
        (True, None)
        >>> validate_header_name(" header")
        (False, "Invalid header name format")
    """
    if not name or not isinstance(name, str):
        return False, "Header name must be a non-empty string"

    if not _RE_HEADER_NAME.match(name):
        return False, "Invalid header name format"

    return True, None


# ---------------------------------------------------------------------------
# Positive integer validation
# ---------------------------------------------------------------------------

def validate_positive_int(
    value: int, name: str = "value"
) -> Tuple[bool, Optional[str]]:
    """Validate that a value is a positive integer.

    Args:
        value: The value to validate.
        name: The name of the value for error messages (default 'value').

    Returns:
        Tuple of (is_valid, error_message).

    Example:
        >>> validate_positive_int(5)
        (True, None)
        >>> validate_positive_int(-1)
        (False, "value must be a positive integer")
    """
    if not isinstance(value, int) or isinstance(value, bool):
        return False, f"{name} must be a positive integer"

    if value <= 0:
        return False, f"{name} must be a positive integer"

    return True, None


# ---------------------------------------------------------------------------
# Text truncation
# ---------------------------------------------------------------------------

def truncate(
    text: str, max_length: int = MAX_TRUNCATE_LENGTH
) -> str:
    """Truncate text to a maximum length, appending an ellipsis.

    If the text is shorter than max_length, it is returned unchanged.
    If truncated, the last 3 characters are replaced with '...' so the
    total length does not exceed max_length.

    Args:
        text: The text to truncate.
        max_length: Maximum length of the result (default 100).

    Returns:
        Truncated string with ellipsis if needed.

    Example:
        >>> truncate("Hello world", 8)
        'Hello...'
        >>> truncate("Hi", 10)
        'Hi'
    """
    if not isinstance(text, str):
        text = str(text)

    if max_length < 3:
        return text[:max_length]

    if len(text) <= max_length:
        return text

    return text[: max_length - 3] + "..."


# ---------------------------------------------------------------------------
# URL encoding helper (additional utility)
# ---------------------------------------------------------------------------

def url_encode_component(component: str) -> str:
    """URL-encode a string component safely.

    Uses urllib.parse.quote with safe characters per RFC 3986.

    Args:
        component: The string to encode.

    Returns:
        URL-encoded string.
    """
    if not isinstance(component, str):
        component = str(component)

    return quote(component, safe=URL_UNRESERVED)


def url_decode_component(component: str) -> str:
    """URL-decode a string component.

    Args:
        component: The URL-encoded string.

    Returns:
        Decoded string.
    """
    from urllib.parse import unquote

    if not isinstance(component, str):
        component = str(component)

    return unquote(component, encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Composite validators
# ---------------------------------------------------------------------------

def validate_host(
    host: str,
) -> Tuple[bool, Optional[str]]:
    """Validate a host string that can be a domain name or IP address.

    Args:
        host: The host string to validate.

    Returns:
        Tuple of (is_valid, error_message).

    Example:
        >>> validate_host("example.com")
        (True, None)
        >>> validate_host("192.168.1.1")
        (True, None)
        >>> validate_host("invalid!")
        (False, "Host must be a valid domain or IP address")
    """
    if not host or not isinstance(host, str):
        return False, "Host must be a non-empty string"

    if is_valid_domain(host):
        return True, None

    if is_valid_ip(host):
        return True, None

    return False, "Host must be a valid domain or IP address"


def validate_authority(
    authority: str,
) -> Tuple[bool, Optional[str]]:
    """Validate a URL authority string (host[:port]).

    Args:
        authority: The authority string (e.g., 'example.com:8080').

    Returns:
        Tuple of (is_valid, error_message).
    """
    if not authority or not isinstance(authority, str):
        return False, "Authority must be a non-empty string"

    if authority.count(":") > 1:
        if authority.startswith("["):
            bracket_end = authority.find("]")
            if bracket_end == -1:
                return False, "Unclosed bracket in IPv6 authority"
            host_part = authority[1:bracket_end]
            port_part = authority[bracket_end + 1:]
            if port_part.startswith(":"):
                port_part = port_part[1:]
            else:
                port_part = None
        else:
            return False, "Invalid authority format"
    elif ":" in authority:
        host_part, port_part = authority.rsplit(":", 1)
    else:
        host_part = authority
        port_part = None

    host_valid, host_err = validate_host(host_part)
    if not host_valid:
        return False, host_err

    if port_part is not None:
        try:
            port = int(port_part)
        except (ValueError, TypeError):
            return False, f"Invalid port in authority: {port_part}"
        port_valid, port_err = validate_port(port)
        if not port_valid:
            return False, port_err

    return True, None


# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------

__all__ = [
    "validate_url",
    "validate_domain",
    "validate_ip",
    "validate_email",
    "validate_port",
    "validate_file_path",
    "validate_http_method",
    "validate_http_status",
    "sanitize_filename",
    "sanitize_html",
    "sanitize_shell_arg",
    "is_valid_json",
    "is_valid_ip",
    "is_valid_domain",
    "is_valid_url",
    "validate_param_name",
    "validate_param_value",
    "validate_header_name",
    "validate_positive_int",
    "truncate",
    "validate_host",
    "validate_authority",
    "url_encode_component",
    "url_decode_component",
    "ValidationError",
    "SanitizationError",
]
