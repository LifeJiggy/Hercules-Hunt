#!/usr/bin/env python3
"""
extract_parameters.py — Parameter Extraction Tool (P2)

Extracts all parameters from HTTP requests across methods (GET, POST, PUT,
PATCH, DELETE), parses URL path parameters, request bodies (JSON, form data,
multipart), headers, and cookies. Supports parameter name fuzzing, schema
extraction from JSON bodies, and reflection detection.

Features:
  - GET: URL query string parsing
  - POST/PUT/PATCH: form data, JSON body, multipart form parsing
  - DELETE: query string + body
  - URL path parameter extraction (/api/users/:id, /api/users/{id})
  - JSON body schema extraction (nested objects, arrays, all field names)
  - Header and cookie parameter extraction
  - Parameter name fuzzing (common names, IDOR-relevant names)
  - Parameter reflection detection
  - JSON / human-readable output
"""

import argparse
import base64
import collections
import copy
import datetime
import hashlib
import html.parser
import http.client
import io
import json
import logging
import mimetypes
import os
import random
import re
import socket
import ssl
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlencode, urlparse, parse_qs, quote, unquote_plus

logger = logging.getLogger("extract_parameters")
LOG_FMT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(LOG_FMT))
    logger.setLevel(level)
    logger.addHandler(handler)
    logger.propagate = False


_DEFAULT_TIMEOUT: float = 15.0
_DEFAULT_USER_AGENT: str = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

_COMMON_PARAM_NAMES: List[str] = [
    "id", "uuid", "uid", "user_id", "userId", "account_id", "accountId",
    "token", "api_key", "apiKey", "secret", "key", "pass", "password",
    "pwd", "email", "username", "name", "full_name", "firstName",
    "lastName", "phone", "phone_number", "address", "zip", "country",
    "role", "type", "status", "state", "action", "method", "format",
    "callback", "redirect", "next", "return", "continue", "url", "link",
    "file", "path", "page", "limit", "offset", "pageSize", "per_page",
    "sort", "order", "filter", "search", "q", "query", "term", "keyword",
    "category", "tag", "group", "org", "organization", "company",
    "is_admin", "isAdmin", "admin", "debug", "test", "mode", "env",
    "locale", "lang", "language", "tz", "timezone", "timestamp",
    "signature", "hmac", "nonce", "csrf", "xsrf", "csrf_token",
    "X-CSRF-Token", "X-Requested-With", "Authorization", "Bearer",
    "Content-Type", "Accept", "X-Forwarded-For", "X-Real-IP",
    "X-API-Key", "X-Auth-Token", "X-Session-Id",
]

_IDOR_PARAM_NAMES: List[str] = [
    "id", "uuid", "uid", "user_id", "userId", "account_id", "accountId",
    "profile_id", "customer_id", "order_id", "invoice_id", "transaction_id",
    "payment_id", "subscription_id", "document_id", "file_id", "photo_id",
    "image_id", "attachment_id", "message_id", "thread_id", "ticket_id",
    "report_id", "project_id", "task_id", "team_id", "org_id", "company_id",
    "role_id", "group_id", "permission_id", "asset_id", "resource_id",
    "reference_id", "external_id", "token_id", "session_id",
]


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class ExtractedParameter:
    source: str = ""       # "url_query", "form_body", "json_body", "multipart", "header", "cookie", "path"
    name: str = ""
    value: str = ""
    method: str = "GET"
    content_type: str = ""
    is_reflected: bool = False
    reflection_location: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PathParameter:
    name: str = ""
    pattern: str = ""       # ":id" or "{id}" or "{param}"
    position: int = 0
    sample_value: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class JsonSchema:
    field_name: str = ""
    field_type: str = ""
    required: bool = False
    nested: List["JsonSchema"] = field(default_factory=list)
    array_item_type: Optional[str] = None
    sample_value: Optional[Any] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field_name": self.field_name,
            "field_type": self.field_type,
            "required": self.required,
            "nested": [n.to_dict() for n in self.nested],
            "array_item_type": self.array_item_type,
            "sample_value": str(self.sample_value) if self.sample_value is not None else None,
        }


@dataclass
class ExtractionReport:
    target_url: str = ""
    method: str = "GET"
    parameters: List[ExtractedParameter] = field(default_factory=list)
    path_parameters: List[PathParameter] = field(default_factory=list)
    json_schemas: List[JsonSchema] = field(default_factory=list)
    headers_found: Dict[str, str] = field(default_factory=dict)
    cookies_found: Dict[str, str] = field(default_factory=dict)
    reflected_parameters: List[ExtractedParameter] = field(default_factory=list)
    fuzzed_parameters: List[ExtractedParameter] = field(default_factory=list)
    extraction_time: str = ""
    total_parameters: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "method": self.method,
            "parameters": [p.to_dict() for p in self.parameters],
            "path_parameters": [p.to_dict() for p in self.path_parameters],
            "json_schemas": [s.to_dict() for s in self.json_schemas],
            "headers_found": self.headers_found,
            "cookies_found": self.cookies_found,
            "reflected_parameters": [p.to_dict() for p in self.reflected_parameters],
            "fuzzed_parameters": [p.to_dict() for p in self.fuzzed_parameters],
            "extraction_time": self.extraction_time,
            "total_parameters": self.total_parameters,
        }


# ---------------------------------------------------------------------------
# UrlParser
# ---------------------------------------------------------------------------

class UrlParser:
    """Parses URLs to extract query parameters, path parameters, and fragments."""

    def __init__(self, url: str = ""):
        self.url = url
        self.parsed = urllib.parse.urlparse(url) if url else None
        self.logger = logging.getLogger(f"{__name__}.UrlParser")

    def set_url(self, url: str) -> None:
        self.url = url
        self.parsed = urllib.parse.urlparse(url)

    def extract_query_params(self, method: str = "GET") -> List[ExtractedParameter]:
        """Extract all query string parameters from the URL."""
        params: List[ExtractedParameter] = []
        if not self.parsed or not self.parsed.query:
            return params
        try:
            parsed_qs = urllib.parse.parse_qs(self.parsed.query, keep_blank_values=True)
            for name, values in parsed_qs.items():
                for val in values:
                    ep = ExtractedParameter(
                        source="url_query",
                        name=name,
                        value=val,
                        method=method,
                        content_type="application/x-www-form-urlencoded",
                    )
                    params.append(ep)
        except Exception as exc:
            self.logger.error("Failed to parse query parameters: %s", exc)
        return params

    def extract_path_params(self) -> List[PathParameter]:
        """Extract path parameters from URL patterns like :id or {id}."""
        params: List[PathParameter] = []
        if not self.parsed:
            return params
        try:
            path = self.parsed.path
            segments = path.strip("/").split("/")
            for idx, seg in enumerate(segments):
                if seg.startswith(":") or seg.startswith("{"):
                    name = seg.lstrip(":{")
                    name = name.rstrip("}")
                    pattern = seg
                    pp = PathParameter(
                        name=name,
                        pattern=pattern,
                        position=idx,
                        sample_value=seg,
                    )
                    params.append(pp)
        except Exception as exc:
            self.logger.error("Failed to extract path parameters: %s", exc)
        return params

    def extract_fragment_params(self) -> Dict[str, str]:
        """Extract parameters from URL fragment (#key=value)."""
        result: Dict[str, str] = {}
        if not self.parsed or not self.parsed.fragment:
            return result
        try:
            frag = self.parsed.fragment
            if "=" in frag:
                parsed_frag = urllib.parse.parse_qs(frag, keep_blank_values=True)
                for k, v in parsed_frag.items():
                    result[k] = v[0] if v else ""
        except Exception as exc:
            self.logger.error("Failed to parse fragment: %s", exc)
        return result

    def get_full_url_with_params(self, params: Dict[str, str]) -> str:
        """Generate a full URL with replaced query parameters."""
        if not self.parsed:
            return self.url
        new_query = urllib.parse.urlencode(params, doseq=True)
        return f"{self.parsed.scheme}://{self.parsed.netloc}{self.parsed.path}?{new_query}"

    def rebuild_url(self, params: Dict[str, str]) -> str:
        return self.get_full_url_with_params(params)

    def parse_multiple_urls(self, urls: List[str]) -> List[List[ExtractedParameter]]:
        """Parse query params from multiple URLs."""
        results: List[List[ExtractedParameter]] = []
        for url in urls:
            parser = UrlParser(url)
            params = parser.extract_query_params()
            if params:
                results.append(params)
        return results


# ---------------------------------------------------------------------------
# BodyParser
# ---------------------------------------------------------------------------

class BodyParser:
    """Parses request body content from various content-types."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.BodyParser")

    def parse(self, body: str, content_type: str = "", method: str = "POST") -> List[ExtractedParameter]:
        """Route body parsing based on content type."""
        ct_lower = content_type.lower().strip() if content_type else ""
        if "application/json" in ct_lower:
            return self.parse_json_body(body, method, content_type)
        elif "multipart/form-data" in ct_lower:
            return self.parse_multipart_body(body, content_type, method)
        elif "application/x-www-form-urlencoded" in ct_lower or "form" in ct_lower:
            return self.parse_form_body(body, method, content_type)
        elif "application/xml" in ct_lower or "text/xml" in ct_lower:
            return self.parse_xml_body(body, method, content_type)
        else:
            # try to auto-detect
            if body.strip().startswith("{"):
                return self.parse_json_body(body, method, content_type or "application/json")
            elif body.strip().startswith("<"):
                return self.parse_xml_body(body, method, content_type or "text/xml")
            elif "=" in body:
                return self.parse_form_body(body, method, content_type or "application/x-www-form-urlencoded")
            return []

    def parse_form_body(self, body: str, method: str = "POST", content_type: str = "") -> List[ExtractedParameter]:
        """Parse application/x-www-form-urlencoded body."""
        params: List[ExtractedParameter] = []
        if not body or not body.strip():
            return params
        try:
            parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
            for name, values in parsed.items():
                for val in values:
                    ep = ExtractedParameter(
                        source="form_body",
                        name=name,
                        value=val,
                        method=method,
                        content_type=content_type or "application/x-www-form-urlencoded",
                    )
                    params.append(ep)
        except Exception as exc:
            self.logger.error("Failed to parse form body: %s", exc)
        return params

    def parse_json_body(self, body: str, method: str = "POST", content_type: str = "application/json") -> List[ExtractedParameter]:
        """Parse JSON body and extract all parameters."""
        params: List[ExtractedParameter] = []
        if not body or not body.strip():
            return params
        try:
            data = json.loads(body)
            self._extract_json_params(data, params, method, content_type, prefix="")
        except json.JSONDecodeError as exc:
            self.logger.warning("Invalid JSON body: %s", exc)
        except Exception as exc:
            self.logger.error("Failed to parse JSON body: %s", exc)
        return params

    def _extract_json_params(
        self, data: Any, params: List[ExtractedParameter],
        method: str, content_type: str, prefix: str,
    ) -> None:
        """Recursively extract parameters from nested JSON."""
        if isinstance(data, dict):
            for key, val in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                if isinstance(val, (dict, list)):
                    self._extract_json_params(val, params, method, content_type, full_key)
                else:
                    ep = ExtractedParameter(
                        source="json_body",
                        name=full_key,
                        value=str(val) if val is not None else "",
                        method=method,
                        content_type=content_type,
                    )
                    params.append(ep)
        elif isinstance(data, list):
            for idx, item in enumerate(data):
                nested_prefix = f"{prefix}[{idx}]"
                if isinstance(item, (dict, list)):
                    self._extract_json_params(item, params, method, content_type, nested_prefix)
                else:
                    ep = ExtractedParameter(
                        source="json_body",
                        name=nested_prefix,
                        value=str(item) if item is not None else "",
                        method=method,
                        content_type=content_type,
                    )
                    params.append(ep)

    def parse_multipart_body(self, body: str, content_type: str, method: str = "POST") -> List[ExtractedParameter]:
        """Parse multipart/form-data body (simplified — extracts field names from raw body)."""
        params: List[ExtractedParameter] = []
        if not body or not body.strip():
            return params
        try:
            boundary = self._extract_boundary(content_type)
            if not boundary:
                self.logger.warning("No boundary found in multipart content-type")
                return params
            parts = body.split(f"--{boundary}".encode() if isinstance(body, str) else f"--{boundary}")
            for part in parts:
                if isinstance(part, bytes):
                    part_str = part.decode("utf-8", errors="replace")
                else:
                    part_str = part
                name_match = re.search(r'name="([^"]+)"', part_str)
                if name_match:
                    field_name = name_match.group(1)
                    # Extract value after headers
                    value = ""
                    val_match = re.search(r'\r\n\r\n(.+?)(?:\r\n--|\s*$)', part_str, re.DOTALL)
                    if val_match:
                        value = val_match.group(1).strip()
                    ep = ExtractedParameter(
                        source="multipart",
                        name=field_name,
                        value=value,
                        method=method,
                        content_type=content_type,
                        extra={"has_file": "filename=" in part_str.lower()},
                    )
                    params.append(ep)
        except Exception as exc:
            self.logger.error("Failed to parse multipart body: %s", exc)
        return params

    def parse_xml_body(self, body: str, method: str = "POST", content_type: str = "text/xml") -> List[ExtractedParameter]:
        """Parse XML body and extract element parameters."""
        params: List[ExtractedParameter] = []
        if not body or not body.strip():
            return params
        try:
            root = xml.etree.ElementTree.fromstring(body)
            self._extract_xml_params(root, params, method, content_type, prefix="")
        except xml.etree.ElementTree.ParseError as exc:
            self.logger.warning("Invalid XML body: %s", exc)
        except Exception as exc:
            self.logger.error("Failed to parse XML body: %s", exc)
        return params

    def _extract_xml_params(
        self, element: xml.etree.ElementTree.Element,
        params: List[ExtractedParameter], method: str, content_type: str, prefix: str,
    ) -> None:
        """Recursively extract parameters from XML elements."""
        tag = element.tag.split("}")[-1] if "}" in element.tag else element.tag
        full_key = f"{prefix}.{tag}" if prefix else tag
        if element.text and element.text.strip():
            ep = ExtractedParameter(
                source="xml_body",
                name=full_key,
                value=element.text.strip(),
                method=method,
                content_type=content_type,
            )
            params.append(ep)
        for child in element:
            self._extract_xml_params(child, params, method, content_type, full_key)
        for attr_name, attr_val in element.attrib.items():
            attr_key = f"{full_key}@{attr_name}"
            ep = ExtractedParameter(
                source="xml_body",
                name=attr_key,
                value=attr_val,
                method=method,
                content_type=content_type,
            )
            params.append(ep)

    @staticmethod
    def _extract_boundary(content_type: str) -> Optional[str]:
        """Extract the boundary string from a multipart content-type header."""
        m = re.search(r'boundary=([^;\s]+)', content_type, re.IGNORECASE)
        if m:
            return m.group(1).strip('"')
        return None

    def extract_json_schema(self, body: str) -> List[JsonSchema]:
        """Extract a JSON schema from a JSON body string."""
        schemas: List[JsonSchema] = []
        if not body or not body.strip():
            return schemas
        try:
            data = json.loads(body)
            schemas = self._build_json_schema(data)
        except json.JSONDecodeError:
            pass
        except Exception as exc:
            self.logger.error("Failed to extract JSON schema: %s", exc)
        return schemas

    def _build_json_schema(self, data: Any, prefix: str = "") -> List[JsonSchema]:
        """Recursively build a schema from JSON data."""
        schemas: List[JsonSchema] = []
        if isinstance(data, dict):
            for key, val in data.items():
                field_name = f"{prefix}.{key}" if prefix else key
                js = JsonSchema(field_name=field_name, sample_value=val)
                if val is None:
                    js.field_type = "null"
                elif isinstance(val, bool):
                    js.field_type = "boolean"
                elif isinstance(val, int):
                    js.field_type = "integer"
                elif isinstance(val, float):
                    js.field_type = "float"
                elif isinstance(val, str):
                    js.field_type = "string"
                elif isinstance(val, list):
                    js.field_type = "array"
                    if val:
                        item = val[0]
                        if isinstance(item, dict):
                            js.nested = self._build_json_schema(item, f"{field_name}[]")
                            js.array_item_type = "object"
                        else:
                            js.array_item_type = type(item).__name__
                    else:
                        js.array_item_type = "unknown"
                elif isinstance(val, dict):
                    js.field_type = "object"
                    js.nested = self._build_json_schema(val, field_name)
                else:
                    js.field_type = type(val).__name__
                schemas.append(js)
        return schemas


# ---------------------------------------------------------------------------
# HeaderParser
# ---------------------------------------------------------------------------

class HeaderParser:
    """Parses HTTP headers and cookies to extract parameters."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.HeaderParser")

    def parse_headers(self, headers: Dict[str, str], method: str = "GET") -> List[ExtractedParameter]:
        """Extract parameters from a dictionary of HTTP headers."""
        params: List[ExtractedParameter] = []
        if not headers:
            return params
        try:
            for name, value in headers.items():
                ep = ExtractedParameter(
                    source="header",
                    name=name,
                    value=value,
                    method=method,
                    content_type="application/octet-stream",
                )
                params.append(ep)
        except Exception as exc:
            self.logger.error("Failed to parse headers: %s", exc)
        return params

    def parse_auth_header(self, auth_value: str) -> Dict[str, str]:
        """Parse an Authorization header into components."""
        result: Dict[str, str] = {}
        try:
            if not auth_value:
                return result
            parts = auth_value.split(None, 1)
            if len(parts) == 2:
                scheme = parts[0].lower()
                credentials = parts[1]
                result["auth_scheme"] = scheme
                if scheme == "basic":
                    try:
                        decoded = base64.b64decode(credentials).decode("utf-8", errors="replace")
                        if ":" in decoded:
                            user, pw = decoded.split(":", 1)
                            result["auth_username"] = user
                            result["auth_password"] = pw
                    except Exception:
                        pass
                    result["auth_credentials"] = credentials
                elif scheme == "bearer":
                    result["auth_token"] = credentials
                elif scheme == "digest":
                    for attr_match in re.finditer(r'(\w+)=("[^"]*"|[^, ]+)', credentials):
                        key = attr_match.group(1).lower()
                        val = attr_match.group(2).strip('"')
                        result[f"digest_{key}"] = val
                else:
                    result["auth_credentials"] = credentials
            else:
                result["auth_raw"] = auth_value
        except Exception as exc:
            self.logger.error("Failed to parse auth header: %s", exc)
        return result

    def parse_cookies(self, cookie_header: str, method: str = "GET") -> List[ExtractedParameter]:
        """Parse a Cookie header string into individual cookie parameters."""
        params: List[ExtractedParameter] = []
        if not cookie_header:
            return params
        try:
            cookie_pairs = cookie_header.split(";")
            for pair in cookie_pairs:
                pair = pair.strip()
                if "=" in pair:
                    name, _, value = pair.partition("=")
                    ep = ExtractedParameter(
                        source="cookie",
                        name=name.strip(),
                        value=value.strip(),
                        method=method,
                        content_type="application/x-www-form-urlencoded",
                    )
                    params.append(ep)
                elif pair:
                    ep = ExtractedParameter(
                        source="cookie",
                        name=pair,
                        value="",
                        method=method,
                        content_type="application/x-www-form-urlencoded",
                    )
                    params.append(ep)
        except Exception as exc:
            self.logger.error("Failed to parse cookies: %s", exc)
        return params

    def parse_set_cookie(self, set_cookie_value: str) -> Dict[str, str]:
        """Parse a Set-Cookie header into its attributes."""
        result: Dict[str, str] = {}
        try:
            parts = set_cookie_value.split(";")
            if parts and "=" in parts[0]:
                name, value = parts[0].split("=", 1)
                result["name"] = name.strip()
                result["value"] = value.strip()
            for part in parts[1:]:
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    result[k.strip().lower()] = v.strip()
                else:
                    result[part.lower()] = "true"
        except Exception as exc:
            self.logger.error("Failed to parse Set-Cookie: %s", exc)
        return result

    def extract_content_type_info(self, content_type: str) -> Dict[str, str]:
        """Extract information from a Content-Type header."""
        info: Dict[str, str] = {}
        if not content_type:
            return info
        try:
            parts = content_type.split(";")
            if parts:
                info["mime_type"] = parts[0].strip().lower()
            for part in parts[1:]:
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    info[k.strip().lower()] = v.strip().strip('"')
        except Exception as exc:
            self.logger.error("Failed to parse content-type: %s", exc)
        return info


# ---------------------------------------------------------------------------
# Fuzzer
# ---------------------------------------------------------------------------

class Fuzzer:
    """Generates fuzzed parameter names from common patterns and mutations."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.Fuzzer")

    def generate_fuzz_params(
        self,
        existing_params: Optional[List[str]] = None,
        include_idor: bool = True,
        include_common: bool = True,
        max_params: int = 100,
    ) -> List[ExtractedParameter]:
        """Generate a list of fuzzed parameter names."""
        param_names: Set[str] = set()
        if include_common:
            param_names.update(_COMMON_PARAM_NAMES)
        if include_idor:
            param_names.update(_IDOR_PARAM_NAMES)
        if existing_params:
            param_names.update(existing_params)
            for p in existing_params:
                param_names.update(self._mutate_param_name(p))
        limited = list(param_names)[:max_params]
        return [
            ExtractedParameter(
                source="fuzzed",
                name=name,
                value="FUZZ_VALUE",
                method="GET",
                extra={"fuzz_type": "generated"},
            )
            for name in limited
        ]

    def _mutate_param_name(self, name: str) -> Set[str]:
        """Generate mutations of a given parameter name."""
        mutations: Set[str] = set()
        try:
            # case variations
            mutations.add(name.lower())
            mutations.add(name.upper())
            mutations.add(name.capitalize())
            # common prefix/suffix
            mutations.add(f"_{name}")
            mutations.add(f"{name}_")
            mutations.add(f"__{name}")
            mutations.add(f"{name}__")
            # nested path style
            mutations.add(f"data[{name}]")
            mutations.add(f"{name}[]")
            mutations.add(f"attributes[{name}]")
            # camelCase / snake_case
            if "_" in name:
                parts = name.split("_")
                camel = parts[0] + "".join(p.capitalize() for p in parts[1:])
                mutations.add(camel)
            else:
                snake = re.sub(r'([A-Z])', r'_\1', name).lower().lstrip("_")
                mutations.add(snake)
        except Exception as exc:
            self.logger.debug("Error mutating param name '%s': %s", name, exc)
        return mutations

    def generate_idor_fuzz_params(self, base_id: str = "100") -> List[ExtractedParameter]:
        """Generate parameters specifically for IDOR testing with common IDs."""
        params: List[ExtractedParameter] = []
        try:
            for name in _IDOR_PARAM_NAMES[:30]:
                ep = ExtractedParameter(
                    source="fuzzed",
                    name=name,
                    value=base_id,
                    method="GET",
                    extra={"fuzz_type": "idor", "base_id": base_id},
                )
                params.append(ep)
            # Also add with encoded versions
            encoded_variants = [
                base_id,
                str(int(base_id) + 1),
                str(int(base_id) - 1),
                base_id * 2,
                base_id[::-1],
                urllib.parse.quote(base_id),
                base64.b64encode(base_id.encode()).decode(),
                f"000{base_id}",
                f"{base_id}.0",
            ]
            for name in _IDOR_PARAM_NAMES[:10]:
                for variant in encoded_variants:
                    ep = ExtractedParameter(
                        source="fuzzed",
                        name=name,
                        value=variant,
                        method="GET",
                        extra={"fuzz_type": "idor_encoded", "original": base_id},
                    )
                    params.append(ep)
        except Exception as exc:
            self.logger.error("Failed to generate IDOR fuzz params: %s", exc)
        return params

    def generate_json_fuzz_params(self) -> List[Dict[str, Any]]:
        """Generate JSON bodies with common mass-assignment / injection keys."""
        bodies: List[Dict[str, Any]] = []
        payload_keys = [
            "is_admin", "isAdmin", "admin", "role", "user_role",
            "permissions", "access_level", "verified", "is_verified",
            "email_verified", "phone_verified", "active", "enabled",
            "is_active", "status", "account_status", "membership",
            "plan", "subscription", "tier", "level", "balance", "credit",
            "debug", "test_mode", "bypass", "skip_validation",
        ]
        for key in payload_keys:
            body = {key: True, "_debug": True, "test": True}
            bodies.append(body)
            body2 = {key: "admin", "role": "admin", "access": "full"}
            bodies.append(body2)
        return bodies

    def guess_param_types(self, params: List[ExtractedParameter]) -> Dict[str, str]:
        """Guess the data type of each parameter based on its name."""
        type_guesses: Dict[str, str] = {}
        id_patterns = re.compile(r"(id|uuid|uid|_id)$", re.IGNORECASE)
        bool_patterns = re.compile(r"^(is_|has_|can_|should_|was_|allow|enable|disable|active)", re.IGNORECASE)
        email_patterns = re.compile(r"email|mail", re.IGNORECASE)
        url_patterns = re.compile(r"^(url|link|href|redirect|callback|return)", re.IGNORECASE)
        numeric_patterns = re.compile(r"(limit|offset|page|count|total|index|number|amount|price)", re.IGNORECASE)
        for p in params:
            name = p.name
            if id_patterns.search(name):
                type_guesses[name] = "identifier"
            elif bool_patterns.search(name):
                type_guesses[name] = "boolean"
            elif email_patterns.search(name):
                type_guesses[name] = "email"
            elif url_patterns.search(name):
                type_guesses[name] = "url"
            elif numeric_patterns.search(name):
                type_guesses[name] = "numeric"
            elif "token" in name.lower() or "secret" in name.lower() or "key" in name.lower() or "pass" in name.lower():
                type_guesses[name] = "sensitive"
            elif "date" in name.lower() or "time" in name.lower() or "timestamp" in name.lower():
                type_guesses[name] = "datetime"
            else:
                type_guesses[name] = "string"
        return type_guesses


# ---------------------------------------------------------------------------
# ReflectionDetector
# ---------------------------------------------------------------------------

class ReflectionDetector:
    """Detects if parameter values are reflected in the server response."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.ReflectionDetector")

    def check_reflection(
        self,
        param: ExtractedParameter,
        response_body: str,
        response_headers: Optional[Dict[str, str]] = None,
    ) -> bool:
        """Check if a parameter value is reflected anywhere in the response."""
        try:
            value = param.value
            if not value or value in ("FUZZ_VALUE", ""):
                return False
            # Direct reflection in body
            if value in response_body:
                param.is_reflected = True
                param.reflection_location = self._find_reflection_location(value, response_body)
                return True
            # HTML-encoded reflection
            html_encoded = html.escape(value)
            if html_encoded in response_body:
                param.is_reflected = True
                param.reflection_location = "html_encoded"
                return True
            # URL-encoded reflection
            url_encoded = urllib.parse.quote(value)
            if url_encoded in response_body:
                param.is_reflected = True
                param.reflection_location = "url_encoded"
                return True
            # Script context reflection
            if f'"{value}"' in response_body or f"'{value}'" in response_body:
                param.is_reflected = True
                param.reflection_location = "javascript_string"
                return True
            # Reflection in headers
            if response_headers:
                for header_val in response_headers.values():
                    if value in header_val:
                        param.is_reflected = True
                        param.reflection_location = "response_header"
                        return True
        except Exception as exc:
            self.logger.debug("Error checking reflection for '%s': %s", param.name, exc)
        return False

    def _find_reflection_location(self, value: str, body: str) -> str:
        """Try to determine where in the HTML the value is reflected."""
        try:
            # Check script tag
            script_pattern = re.compile(rf'<script[^>]*>[^<]*{re.escape(value)}[^<]*</script>', re.IGNORECASE | re.DOTALL)
            if script_pattern.search(body):
                return "script_tag"
            # Check input value
            input_pattern = re.compile(rf'<input[^>]*value=["\']?{re.escape(value)}["\']?', re.IGNORECASE)
            if input_pattern.search(body):
                return "input_value"
            # Check meta tag
            meta_pattern = re.compile(rf'<meta[^>]*content=["\']?{re.escape(value)}["\']?', re.IGNORECASE)
            if meta_pattern.search(body):
                return "meta_tag"
            # Check JSON response
            json_pattern = re.compile(rf'"{re.escape(value)}"', re.IGNORECASE)
            if json_pattern.search(body):
                return "json_response"
            # Check generic text
            text_pattern = re.compile(re.escape(value), re.IGNORECASE)
            if text_pattern.search(body):
                return "response_body"
        except Exception:
            pass
        return "response_body (generic)"

    def check_mass_reflection(
        self,
        params: List[ExtractedParameter],
        response_body: str,
        response_headers: Optional[Dict[str, str]] = None,
    ) -> List[ExtractedParameter]:
        """Check multiple parameters for reflection at once."""
        reflected: List[ExtractedParameter] = []
        for param in params:
            if self.check_reflection(param, response_body, response_headers):
                reflected.append(param)
        return reflected

    def generate_reflection_probe(self, param_name: str) -> str:
        """Generate a unique probe value for reflection testing."""
        rand_part = random.randint(100000, 999999)
        return f"RFL{rand_part}{param_name}{rand_part}"

    def get_reflection_context(self, value: str, body: str, context_size: int = 50) -> str:
        """Get surrounding context of a reflected value in the body."""
        try:
            idx = body.find(value)
            if idx >= 0:
                start = max(0, idx - context_size)
                end = min(len(body), idx + len(value) + context_size)
                context = body[start:end]
                return f"...{context}..."
        except Exception:
            pass
        return ""


# ---------------------------------------------------------------------------
# ParameterExtractor
# ---------------------------------------------------------------------------

class ParameterExtractor:
    """
    Master orchestrator that extracts all parameters from a target URL or file.

    Combines URL parsing, body parsing, header parsing, cookie parsing,
    fuzzing, and reflection detection into a single ExtractionReport.
    """

    def __init__(self, timeout: float = _DEFAULT_TIMEOUT, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self.url_parser = UrlParser()
        self.body_parser = BodyParser()
        self.header_parser = HeaderParser()
        self.fuzzer = Fuzzer()
        self.reflection_detector = ReflectionDetector()
        self.logger = logging.getLogger(f"{__name__}.ParameterExtractor")

    def extract_from_url(
        self,
        url: str,
        method: str = "GET",
        body: str = "",
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        content_type: str = "",
        fuzz: bool = False,
        depth: int = 1,
    ) -> ExtractionReport:
        """Extract all parameters from a single URL request specification."""
        report = ExtractionReport(target_url=url, method=method)
        report.extraction_time = datetime.datetime.utcnow().isoformat()
        self.url_parser.set_url(url)

        # Path parameters
        path_params = self.url_parser.extract_path_params()
        report.path_parameters = path_params

        # Query parameters (all methods can have them)
        query_params = self.url_parser.extract_query_params(method)
        report.parameters.extend(query_params)

        # Body parameters (for non-GET methods)
        if method.upper() in ("POST", "PUT", "PATCH", "DELETE") and body:
            body_params = self.body_parser.parse(body, content_type, method)
            report.parameters.extend(body_params)
            # JSON schema extraction
            if "json" in content_type.lower() or body.strip().startswith("{"):
                schemas = self.body_parser.extract_json_schema(body)
                report.json_schemas = schemas

        # Header parameters
        if headers:
            header_params = self.header_parser.parse_headers(headers, method)
            report.parameters.extend(header_params)
            report.headers_found = headers.copy()
            # Parse Authorization header
            auth_val = headers.get("Authorization") or headers.get("authorization", "")
            if auth_val:
                auth_info = self.header_parser.parse_auth_header(auth_val)
                for k, v in auth_info.items():
                    ep = ExtractedParameter(
                        source="header",
                        name=k,
                        value=v,
                        method=method,
                        extra={"auth_component": True},
                    )
                    report.parameters.append(ep)

        # Cookie parameters
        cookie_str = ""
        if cookies:
            cookie_params = []
            for cname, cvalue in cookies.items():
                ep = ExtractedParameter(
                    source="cookie",
                    name=cname,
                    value=cvalue,
                    method=method,
                )
                cookie_params.append(ep)
                report.parameters.append(ep)
            report.cookies_found = cookies
            # Build cookie string
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        elif headers:
            ch = headers.get("Cookie") or headers.get("cookie", "")
            if ch:
                cookie_params = self.header_parser.parse_cookies(ch, method)
                report.parameters.extend(cookie_params)
                cookie_str = ch

        # Fuzzing
        if fuzz:
            existing_names = [p.name for p in report.parameters]
            fuzz_params = self.fuzzer.generate_fuzz_params(
                existing_params=existing_names,
                max_params=depth * 50,
            )
            report.fuzzed_parameters = fuzz_params
            report.parameters.extend(fuzz_params)

        report.total_parameters = len(report.parameters)
        return report

    def extract_from_file(self, filepath: str) -> ExtractionReport:
        """Extract parameters from a file containing raw HTTP request data."""
        report = ExtractionReport()
        report.extraction_time = datetime.datetime.utcnow().isoformat()
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            report = self._parse_raw_http(content)
        except FileNotFoundError:
            self.logger.error("File not found: %s", filepath)
        except PermissionError:
            self.logger.error("Permission denied: %s", filepath)
        except Exception as exc:
            self.logger.error("Failed to read file %s: %s", filepath, exc)
        return report

    def _parse_raw_http(self, raw: str) -> ExtractionReport:
        """Parse a raw HTTP request string into an ExtractionReport."""
        report = ExtractionReport()
        try:
            lines = raw.strip().split("\n")
            if not lines:
                return report
            # Parse request line
            request_line = lines[0].strip()
            parts = request_line.split()
            if len(parts) >= 2:
                method = parts[0].upper()
                url_path = parts[1]
                report.method = method
                report.target_url = url_path
                self.url_parser.set_url(url_path)
                query_params = self.url_parser.extract_query_params(method)
                report.parameters.extend(query_params)
            # Parse headers
            headers: Dict[str, str] = {}
            body_start = 0
            for i in range(1, len(lines)):
                line = lines[i].strip()
                if not line:
                    body_start = i + 1
                    break
                if ":" in line:
                    hname, _, hvalue = line.partition(":")
                    headers[hname.strip()] = hvalue.strip()
            if headers:
                header_params = self.header_parser.parse_headers(headers, method)
                report.parameters.extend(header_params)
                report.headers_found = headers
            # Parse body
            if body_start and body_start < len(lines):
                body = "\n".join(lines[body_start:]).strip()
                if body:
                    content_type = headers.get("Content-Type", headers.get("content-type", ""))
                    body_params = self.body_parser.parse(body, content_type, method)
                    report.parameters.extend(body_params)
            # Parse cookies from header
            cookie_h = headers.get("Cookie", headers.get("cookie", ""))
            if cookie_h:
                cookie_params = self.header_parser.parse_cookies(cookie_h, method)
                report.parameters.extend(cookie_params)
            report.total_parameters = len(report.parameters)
        except Exception as exc:
            self.logger.error("Failed to parse raw HTTP: %s", exc)
        return report

    def run_reflection_detection(
        self,
        report: ExtractionReport,
        response_body: str,
        response_headers: Optional[Dict[str, str]] = None,
    ) -> List[ExtractedParameter]:
        """Run reflection detection on all extracted parameters."""
        reflected = self.reflection_detector.check_mass_reflection(
            report.parameters, response_body, response_headers,
        )
        report.reflected_parameters = reflected
        return reflected

    def compute_param_stats(self, report: ExtractionReport) -> Dict[str, Any]:
        """Compute statistics about the extracted parameters."""
        stats: Dict[str, Any] = {
            "total": report.total_parameters,
            "by_source": defaultdict(int),
            "by_method": defaultdict(int),
            "unique_names": len(set(p.name for p in report.parameters)),
            "reflected_count": len(report.reflected_parameters),
            "path_params": len(report.path_parameters),
            "fuzzed_params": len(report.fuzzed_parameters),
        }
        for p in report.parameters:
            stats["by_source"][p.source] += 1
            stats["by_method"][p.method] += 1
        stats["by_source"] = dict(stats["by_source"])
        stats["by_method"] = dict(stats["by_method"])
        return stats


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="extract_parameters",
        description="Parameter Extraction Tool — extracts all parameters from HTTP "
                    "requests across methods, bodies, headers, cookies, and URLs. "
                    "Supports fuzzing, JSON schema extraction, and reflection detection.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python extract_parameters.py --url 'https://api.example.com/users?id=1'\n"
            "  python extract_parameters.py --url 'https://example.com/login' --method POST "
            "--body '{\"user\":\"admin\",\"pass\":\"test\"}' --content-type application/json\n"
            "  python extract_parameters.py --file request.txt\n"
            "  python extract_parameters.py --url 'https://example.com/api' --fuzz --depth 3\n"
            "  python extract_parameters.py --url 'https://example.com/page' --method POST "
            "--body 'user=admin&pass=test' --output params.json --json\n"
        ),
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", "-u", type=str, default="", help="Target URL to extract parameters from")
    group.add_argument("--file", "-f", type=str, default="", help="File containing raw HTTP request")

    parser.add_argument("--method", "-m", type=str, default="GET", choices=["GET", "POST", "PUT", "PATCH", "DELETE"],
                        help="HTTP method (default: GET)")
    parser.add_argument("--body", "-b", type=str, default="", help="Request body string")
    parser.add_argument("--content-type", "-c", type=str, default="",
                        help="Content-Type of the request body")
    parser.add_argument("--headers", "-H", type=str, default="",
                        help="Headers as JSON string (e.g. '{\"Authorization\":\"Bearer xyz\"}')")
    parser.add_argument("--cookies", "-C", type=str, default="",
                        help="Cookies as JSON string (e.g. '{\"session\":\"abc123\"}')")
    parser.add_argument("--output", "-o", type=str, default="", help="Output file path")
    parser.add_argument("--fuzz", action="store_true", default=False,
                        help="Generate fuzzed parameter names from common and IDOR patterns")
    parser.add_argument("--depth", "-d", type=int, default=1,
                        help="Fuzzing depth / max parameter count multiplier (default: 1)")
    parser.add_argument("--json", "-j", action="store_true", default=False,
                        help="Output as JSON (default: human-readable text)")
    parser.add_argument("--verbose", "-v", action="store_true", default=False,
                        help="Enable verbose debug logging")
    return parser.parse_args(argv)


def _format_report_text(report: ExtractionReport, stats: Dict[str, Any]) -> str:
    """Format the extraction report as human-readable text."""
    lines: List[str] = []
    lines.append("=" * 70)
    lines.append(f"Parameter Extraction Report — {report.target_url}")
    lines.append("=" * 70)
    lines.append(f"Method:          {report.method}")
    lines.append(f"Total params:    {stats['total']}")
    lines.append(f"Unique names:    {stats['unique_names']}")
    lines.append(f"Reflected:       {stats['reflected_count']}")
    lines.append(f"Path params:     {stats['path_params']}")
    lines.append(f"Scanned at:      {report.extraction_time}")
    lines.append("")

    if report.path_parameters:
        lines.append("--- Path Parameters ---")
        for pp in report.path_parameters:
            lines.append(f"  [{pp.position}] {pp.pattern} -> {pp.name}")
        lines.append("")

    lines.append("--- Parameters by Source ---")
    for source, count in stats["by_source"].items():
        lines.append(f"  {source}: {count}")
    lines.append("")

    lines.append("--- All Extracted Parameters ---")
    for i, p in enumerate(report.parameters, 1):
        reflected = " [REFLECTED]" if p.is_reflected else ""
        lines.append(f"  {i:3d}. [{p.source:>10}] {p.name}={p.value[:80]}{reflected}")
    lines.append("")

    if report.json_schemas:
        lines.append("--- JSON Schema ---")
        for js in report.json_schemas:
            lines.append(f"  {js.field_name}: {js.field_type}")
            if js.array_item_type:
                lines.append(f"    -> array of {js.array_item_type}")
            if js.nested:
                for n in js.nested:
                    lines.append(f"      {n.field_name}: {n.field_type}")
        lines.append("")

    if report.fuzzed_parameters:
        lines.append("--- Fuzzed Parameters (first 30) ---")
        for p in report.fuzzed_parameters[:30]:
            fuzz_type = p.extra.get("fuzz_type", "")
            lines.append(f"  {p.name}={p.value} [{fuzz_type}]")
        lines.append("")

    if report.reflected_parameters:
        lines.append("--- Reflected Parameters ---")
        for p in report.reflected_parameters:
            lines.append(f"  {p.name}={p.value[:60]} -> {p.reflection_location}")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    args = parse_args()
    _setup_logging(verbose=args.verbose)

    extractor = ParameterExtractor(timeout=_DEFAULT_TIMEOUT, verbose=args.verbose)

    if args.file:
        logger.info("Extracting parameters from file: %s", args.file)
        report = extractor.extract_from_file(args.file)
    else:
        headers: Dict[str, str] = {}
        if args.headers:
            try:
                headers = json.loads(args.headers)
            except json.JSONDecodeError:
                logger.error("Invalid headers JSON: %s", args.headers)
                sys.exit(1)

        cookies: Dict[str, str] = {}
        if args.cookies:
            try:
                cookies = json.loads(args.cookies)
            except json.JSONDecodeError:
                logger.error("Invalid cookies JSON: %s", args.cookies)
                sys.exit(1)

        logger.info("Extracting parameters from URL: %s [%s]", args.url, args.method)
        report = extractor.extract_from_url(
            url=args.url,
            method=args.method,
            body=args.body,
            headers=headers,
            cookies=cookies,
            content_type=args.content_type,
            fuzz=args.fuzz,
            depth=args.depth,
        )

    stats = extractor.compute_param_stats(report)

    if args.json:
        output = json.dumps(report.to_dict(), indent=2, default=str)
        print(output)
    else:
        output = _format_report_text(report, stats)
        print(output)

    if args.output:
        try:
            dirname = os.path.dirname(os.path.abspath(args.output))
            if dirname:
                os.makedirs(dirname, exist_ok=True)
            with open(args.output, "w", encoding="utf-8") as f:
                if args.json:
                    f.write(output)
                else:
                    f.write(output)
            logger.info("Report written to %s", args.output)
        except OSError as exc:
            logger.error("Failed to write output: %s", exc)

    logger.info("Extraction complete — %d total parameters", stats["total"])


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
