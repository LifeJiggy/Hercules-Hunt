#!/usr/bin/env python3
"""
extract_functionalities.py — User Functionality Extraction Tool (P2)

Discovers all user-interactive elements from HTML pages: forms, links, buttons,
inputs, selects, textareas, and JavaScript event handlers. Maps user workflows
(form submission targets, redirect chains, navigation paths) and detects
client-side frameworks (React, Angular, Vue, jQuery).

Features:
  - Form analysis: action, method, all input types, textareas, selects, buttons
  - Link analysis: href, onclick, target, rel
  - Button analysis: type, onclick, form, value, formaction
  - Input field analysis: type, name, value, placeholder, pattern, required, min/max
  - Select and option extraction
  - Textarea extraction
  - JavaScript event handler scanning (onclick, onsubmit, onchange, etc.)
  - User workflow mapping (form targets, redirect chains, navigation paths)
  - Framework-specific detection (React, Angular, Vue, jQuery)
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
import os
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

_MAX_URL_LENGTH = 8192
_MAX_FILE_SIZE = 100 * 1024 * 1024


def _validate_output_path(filepath: str) -> str:
    normalized = os.path.normpath(filepath)
    if ".." in normalized.split(os.sep):
        raise ValueError(f"Invalid output path: {filepath}")
    return normalized
from urllib.parse import urljoin, urlparse

logger = logging.getLogger("extract_functionalities")
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

_MAX_REDIRECTS: int = 5
_MAX_DEPTH: int = 3

_EVENT_HANDLERS: List[str] = [
    "onclick", "ondblclick", "onmousedown", "onmouseup",
    "onmouseover", "onmouseout", "onmousemove",
    "onkeydown", "onkeypress", "onkeyup",
    "onsubmit", "onreset", "onchange", "onfocus",
    "onblur", "onselect", "oninput",
    "onload", "onunload", "onpageshow", "onpagehide",
    "onscroll", "onresize",
    "oncontextmenu", "onerror", "onabort",
    "ontouchstart", "ontouchend", "ontouchmove",
    "ondrag", "ondrop", "ondragstart", "ondragend",
    "onplay", "onpause", "onended", "onvolumechange",
    "onwheel", "onpointerdown", "onpointerup", "onpointermove",
]

_FRAMEWORK_PATTERNS: Dict[str, List[str]] = {
    "react": [
        r"data-reactroot",
        r"data-reactid",
        r"__reactFiber",
        r"__reactProps",
        r"react\.production\.min\.js",
        r"react\.development\.js",
        r"/static/js/main\.[a-f0-9]+\.js",
        r"_reactRootContainer",
    ],
    "angular": [
        r"ng-app",
        r"ng-controller",
        r"ng-model",
        r"ng-repeat",
        r"ng-click",
        r"ng-submit",
        r"ng-if",
        r"ng-show",
        r"ng-hide",
        r"ng-bind",
        r"_ngcontent",
        r"angular\.js",
        r"angular\.min\.js",
        r"zone\.js",
    ],
    "vue": [
        r"v-if",
        r"v-for",
        r"v-model",
        r"v-bind",
        r"v-on:",
        r"v-show",
        r"v-else",
        r"v-html",
        r"v-text",
        r"v-cloak",
        r"vue\.js",
        r"vue\.min\.js",
        r"__vue__",
        r"data-v-",
        r"app\.mount",
        r"createApp",
    ],
    "jquery": [
        r"jquery(-[0-9.]+)?(\.min)?\.js$",
        r"\$\(document\)\.ready",
        r"\$\.ajax",
        r"\$\.getJSON",
        r"\$\.post",
        r"\$\(function",
        r"jQuery\(function",
    ],
    "nextjs": [
        r"/_next/static",
        r"__NEXT_DATA__",
        r"next\.js",
        r"next\.min\.js",
        r"data-next-page",
    ],
    "nuxt": [
        r"__NUXT__",
        r"_nuxt/",
        r"nuxt-link",
    ],
}


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class FormField:
    field_type: str = ""       # "input", "select", "textarea", "button"
    name: str = ""
    value: str = ""
    input_type: str = ""
    placeholder: str = ""
    pattern: str = ""
    required: bool = False
    readonly: bool = False
    disabled: bool = False
    min_value: Optional[str] = None
    max_value: Optional[str] = None
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    autocomplete: str = ""
    options: List[Dict[str, str]] = field(default_factory=list)
    rows: Optional[int] = None
    cols: Optional[int] = None
    extra_attrs: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Form:
    action: str = ""
    method: str = "GET"
    name: str = ""
    form_id: str = ""
    enctype: str = ""
    target: str = ""
    autocomplete: str = ""
    novalidate: bool = False
    fields: List[FormField] = field(default_factory=list)
    has_submit_button: bool = False
    requires_auth: bool = False
    url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "method": self.method,
            "name": self.name,
            "form_id": self.form_id,
            "enctype": self.enctype,
            "target": self.target,
            "autocomplete": self.autocomplete,
            "novalidate": self.novalidate,
            "fields": [f.to_dict() for f in self.fields],
            "has_submit_button": self.has_submit_button,
            "requires_auth": self.requires_auth,
            "url": self.url,
        }


@dataclass
class Link:
    href: str = ""
    text: str = ""
    onclick: str = ""
    target: str = ""
    rel: str = ""
    link_id: str = ""
    link_class: str = ""
    title: str = ""
    is_external: bool = False
    is_javascript: bool = False
    is_empty: bool = False
    url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Button:
    button_type: str = ""      # "submit", "reset", "button", "menu"
    name: str = ""
    value: str = ""
    onclick: str = ""
    form: str = ""
    formaction: str = ""
    formmethod: str = ""
    formtarget: str = ""
    text: str = ""
    disabled: bool = False
    button_id: str = ""
    button_class: str = ""
    url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EventHandler:
    event: str = ""
    handler_code: str = ""
    element_tag: str = ""
    element_id: str = ""
    element_class: str = ""
    element_name: str = ""
    url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WorkflowStep:
    step_type: str = ""        # "form_submit", "link_click", "redirect", "navigation", "api_call"
    source_url: str = ""
    target_url: str = ""
    trigger_element: str = ""
    trigger_value: str = ""
    method: str = "GET"
    depth: int = 0
    requires_auth: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FrameworkDetection:
    framework: str = ""
    detected: bool = False
    evidence: List[str] = field(default_factory=list)
    version: str = ""
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FunctionalityReport:
    url: str = ""
    title: str = ""
    forms: List[Form] = field(default_factory=list)
    links: List[Link] = field(default_factory=list)
    buttons: List[Button] = field(default_factory=list)
    event_handlers: List[EventHandler] = field(default_factory=list)
    workflows: List[WorkflowStep] = field(default_factory=list)
    frameworks: List[FrameworkDetection] = field(default_factory=list)
    total_interactive_elements: int = 0
    extraction_time: str = ""
    depth_reached: int = 0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "title": self.title,
            "forms": [f.to_dict() for f in self.forms],
            "links": self._links_to_dicts(),
            "buttons": [b.to_dict() for b in self.buttons],
            "event_handlers": [e.to_dict() for e in self.event_handlers],
            "workflows": [w.to_dict() for w in self.workflows],
            "frameworks": [f.to_dict() for f in self.frameworks],
            "total_interactive_elements": self.total_interactive_elements,
            "extraction_time": self.extraction_time,
            "depth_reached": self.depth_reached,
            "errors": self.errors,
        }

    def _links_to_dicts(self) -> List[Dict[str, Any]]:
        return [l.to_dict() for l in self.links]


# ---------------------------------------------------------------------------
# FormAnalyzer
# ---------------------------------------------------------------------------

class FormAnalyzer:
    """Parses HTML forms and extracts all form fields, types, and metadata."""

    def __init__(self, base_url: str = ""):
        self.base_url = base_url
        self.logger = logging.getLogger(f"{__name__}.FormAnalyzer")

    def parse_forms(self, html_content: str, source_url: str = "") -> List[Form]:
        """Parse all <form> elements from HTML and extract their details."""
        forms: List[Form] = []
        if not html_content:
            return forms
        try:
            form_pattern = re.compile(
                r'<form\s([^>]*)>(.*?)</form\s*>',
                re.IGNORECASE | re.DOTALL,
            )
            for form_match in form_pattern.finditer(html_content):
                try:
                    form_attrs = form_match.group(1)
                    inner_html = form_match.group(2)
                    form = self._parse_form_attrs(form_attrs, source_url)
                    form.fields = self._parse_form_fields(inner_html)
                    form.has_submit_button = any(
                        f.field_type == "button" or
                        (f.input_type and f.input_type in ("submit", "image"))
                        for f in form.fields
                    )
                    forms.append(form)
                except Exception as exc:
                    self.logger.debug("Error parsing a form element: %s", exc)
        except Exception as exc:
            self.logger.error("Failed to parse forms from HTML: %s", exc)
        return forms

    def _parse_form_attrs(self, attrs_str: str, source_url: str = "") -> Form:
        """Parse form element attributes into a Form dataclass."""
        form = Form()
        try:
            attrs = self._parse_attrs(attrs_str)
            form.action = self._resolve_url(attrs.get("action", ""), source_url)
            form.method = attrs.get("method", "GET").upper()
            form.name = attrs.get("name", "")
            form.form_id = attrs.get("id", "")
            form.enctype = attrs.get("enctype", attrs.get("encoding", ""))
            form.target = attrs.get("target", "")
            form.autocomplete = attrs.get("autocomplete", "")
            form.novalidate = "novalidate" in attrs_str.lower()
            form.url = source_url
        except Exception as exc:
            self.logger.debug("Error parsing form attrs: %s", exc)
        return form

    def _parse_form_fields(self, inner_html: str) -> List[FormField]:
        """Extract all input, select, textarea, and button fields from form inner HTML."""
        fields: List[FormField] = []
        try:
            # <input> elements
            input_pattern = re.compile(r'<input\s([^>]*?)/?\s*>', re.IGNORECASE | re.DOTALL)
            for match in input_pattern.finditer(inner_html):
                try:
                    field = self._parse_input(match.group(1))
                    if field.name or field.input_type:
                        fields.append(field)
                except Exception:
                    continue

            # <select> elements
            select_pattern = re.compile(
                r'<select\s([^>]*)>(.*?)</select\s*>',
                re.IGNORECASE | re.DOTALL,
            )
            for match in select_pattern.finditer(inner_html):
                try:
                    field = self._parse_select(match.group(1), match.group(2))
                    fields.append(field)
                except Exception:
                    continue

            # <textarea> elements
            textarea_pattern = re.compile(
                r'<textarea\s([^>]*)>(.*?)</textarea\s*>',
                re.IGNORECASE | re.DOTALL,
            )
            for match in textarea_pattern.finditer(inner_html):
                try:
                    field = self._parse_textarea(match.group(1), match.group(2))
                    fields.append(field)
                except Exception:
                    continue

            # <button> elements
            button_pattern = re.compile(
                r'<button\s([^>]*)>(.*?)</button\s*>',
                re.IGNORECASE | re.DOTALL,
            )
            for match in button_pattern.finditer(inner_html):
                try:
                    field = self._parse_button_field(match.group(1), match.group(2))
                    fields.append(field)
                except Exception:
                    continue

        except Exception as exc:
            self.logger.debug("Error parsing form fields: %s", exc)
        return fields

    def _parse_attrs(self, attrs_str: str) -> Dict[str, str]:
        """Parse HTML attribute string into a dictionary."""
        attrs: Dict[str, str] = {}
        try:
            pattern = re.compile(
                r'''([\w:-]+)\s*=\s*["']([^"']*)["']|([\w:-]+)\s*=\s*([^\s"'>]+)|([\w:-]+)(?=\s|>)''',
                re.IGNORECASE,
            )
            for match in pattern.finditer(attrs_str):
                if match.group(1) and match.group(2) is not None:
                    attrs[match.group(1).lower()] = match.group(2)
                elif match.group(3) and match.group(4) is not None:
                    attrs[match.group(3).lower()] = match.group(4)
                elif match.group(5):
                    attrs[match.group(5).lower()] = ""
        except Exception as exc:
            self.logger.debug("Error parsing attrs: %s", exc)
        return attrs

    def _parse_input(self, attrs_str: str) -> FormField:
        """Parse an <input> element."""
        field = FormField(field_type="input")
        try:
            attrs = self._parse_attrs(attrs_str)
            field.input_type = attrs.get("type", "text").lower()
            field.name = attrs.get("name", "")
            field.value = attrs.get("value", "")
            field.placeholder = attrs.get("placeholder", "")
            field.pattern = attrs.get("pattern", "")
            field.required = "required" in attrs or "required" in attrs_str.lower()
            field.readonly = "readonly" in attrs or "readonly" in attrs_str.lower()
            field.disabled = "disabled" in attrs or "disabled" in attrs_str.lower()
            field.min_value = attrs.get("min", "")
            field.max_value = attrs.get("max", "")
            ml = attrs.get("maxlength", "")
            field.max_length = int(ml) if ml.isdigit() else None
            mnl = attrs.get("minlength", "")
            field.min_length = int(mnl) if mnl.isdigit() else None
            field.autocomplete = attrs.get("autocomplete", "")
            for k, v in attrs.items():
                if k not in ("type", "name", "value", "placeholder", "pattern",
                             "required", "readonly", "disabled", "min", "max",
                             "maxlength", "minlength", "autocomplete"):
                    field.extra_attrs[k] = v
        except Exception as exc:
            self.logger.debug("Error parsing input element: %s", exc)
        return field

    def _parse_select(self, attrs_str: str, inner_html: str) -> FormField:
        """Parse a <select> element and its <option> children."""
        field = FormField(field_type="select")
        try:
            attrs = self._parse_attrs(attrs_str)
            field.name = attrs.get("name", "")
            field.required = "required" in attrs_str.lower()
            field.disabled = "disabled" in attrs_str.lower()
            option_pattern = re.compile(
                r'<option\s([^>]*)>(.*?)</option\s*>',
                re.IGNORECASE | re.DOTALL,
            )
            for option_match in option_pattern.finditer(inner_html):
                opt_attrs = option_match.group(1)
                opt_text = option_match.group(2).strip()
                oa = self._parse_attrs(opt_attrs)
                opt_value = oa.get("value", opt_text)
                field.options.append({
                    "value": opt_value,
                    "text": opt_text,
                    "selected": "selected" in opt_attrs.lower() or "selected" in opt_attrs,
                    "disabled": "disabled" in opt_attrs.lower(),
                })
            # Also handle single-tag options
            option_single = re.compile(
                r'<option\s([^>]*?)/?\s*>',
                re.IGNORECASE,
            )
            for osm in option_single.finditer(inner_html):
                oa = self._parse_attrs(osm.group(1))
                if oa.get("value") and not any(o["value"] == oa["value"] for o in field.options):
                    field.options.append({
                        "value": oa["value"],
                        "text": oa.get("label", oa["value"]),
                        "selected": "selected" in osm.group(1).lower(),
                        "disabled": "disabled" in osm.group(1).lower(),
                    })
        except Exception as exc:
            self.logger.debug("Error parsing select element: %s", exc)
        return field

    def _parse_textarea(self, attrs_str: str, content: str) -> FormField:
        """Parse a <textarea> element."""
        field = FormField(field_type="textarea")
        try:
            attrs = self._parse_attrs(attrs_str)
            field.name = attrs.get("name", "")
            field.placeholder = attrs.get("placeholder", "")
            field.required = "required" in attrs_str.lower()
            field.readonly = "readonly" in attrs_str.lower()
            field.disabled = "disabled" in attrs_str.lower()
            field.value = content.strip()
            rows = attrs.get("rows", "")
            field.rows = int(rows) if rows.isdigit() else None
            cols = attrs.get("cols", "")
            field.cols = int(cols) if cols.isdigit() else None
            ml = attrs.get("maxlength", "")
            field.max_length = int(ml) if ml.isdigit() else None
            field.autocomplete = attrs.get("autocomplete", "")
            for k, v in attrs.items():
                if k not in ("name", "placeholder", "required", "readonly",
                             "disabled", "rows", "cols", "maxlength", "autocomplete"):
                    field.extra_attrs[k] = v
        except Exception as exc:
            self.logger.debug("Error parsing textarea element: %s", exc)
        return field

    def _parse_button_field(self, attrs_str: str, content: str) -> FormField:
        """Parse a <button> element as a form field."""
        field = FormField(field_type="button")
        try:
            attrs = self._parse_attrs(attrs_str)
            field.input_type = attrs.get("type", "submit").lower()
            field.name = attrs.get("name", "")
            field.value = attrs.get("value", content.strip())
            field.disabled = "disabled" in attrs_str.lower()
            if "onclick" in attrs:
                field.placeholder = attrs.get("onclick", "")
            for k, v in attrs.items():
                if k not in ("type", "name", "value", "disabled", "onclick"):
                    field.extra_attrs[k] = v
        except Exception as exc:
            self.logger.debug("Error parsing button field: %s", exc)
        return field

    def _resolve_url(self, href: str, base_url: str) -> str:
        """Resolve a potentially relative URL against a base URL."""
        if not href or href.startswith("#") or href.startswith("javascript:"):
            return href
        if base_url:
            try:
                return urljoin(base_url, href)
            except Exception:
                pass
        return href


# ---------------------------------------------------------------------------
# LinkAnalyzer
# ---------------------------------------------------------------------------

class LinkAnalyzer:
    """Extracts and categorizes all <a> links from HTML."""

    def __init__(self, base_url: str = ""):
        self.base_url = base_url
        self.logger = logging.getLogger(f"{__name__}.LinkAnalyzer")

    def parse_links(self, html_content: str, source_url: str = "") -> List[Link]:
        """Parse all <a> elements from HTML."""
        links: List[Link] = []
        if not html_content:
            return links
        try:
            pattern = re.compile(
                r'<a\s([^>]*)>(.*?)</a\s*>',
                re.IGNORECASE | re.DOTALL,
            )
            for match in pattern.finditer(html_content):
                try:
                    attrs_str = match.group(1)
                    text = match.group(2).strip()
                    link = self._parse_link(attrs_str, text, source_url)
                    links.append(link)
                except Exception:
                    continue

            # Self-closing anchors
            self_close = re.compile(
                r'<a\s([^>]*?)/?\s*>',
                re.IGNORECASE,
            )
            for match in self_close.finditer(html_content):
                attrs_str = match.group(1)
                if "href" in attrs_str.lower():
                    link = self._parse_link(attrs_str, "", source_url)
                    if not any(l.href == link.href for l in links):
                        links.append(link)
        except Exception as exc:
            self.logger.error("Failed to parse links from HTML: %s", exc)
        return links

    def _parse_link(self, attrs_str: str, text: str, source_url: str = "") -> Link:
        """Parse a single <a> element attributes into a Link dataclass."""
        link = Link()
        try:
            attrs = self._parse_attrs(attrs_str)
            raw_href = attrs.get("href", "")
            link.href = self._resolve_url(raw_href, source_url or self.base_url)
            link.text = text[:200] if text else ""
            link.onclick = attrs.get("onclick", "")
            link.target = attrs.get("target", "")
            link.rel = attrs.get("rel", "")
            link.link_id = attrs.get("id", "")
            link.link_class = attrs.get("class", "")
            link.title = attrs.get("title", "")
            link.url = source_url or self.base_url

            link.is_javascript = raw_href.lower().startswith("javascript:")
            link.is_empty = raw_href in ("", "#")
            if link.href:
                parsed = urlparse(link.href)
                if parsed.netloc and parsed.netloc != urlparse(source_url).netloc:
                    link.is_external = True
        except Exception as exc:
            self.logger.debug("Error parsing link: %s", exc)
        return link

    def _parse_attrs(self, attrs_str: str) -> Dict[str, str]:
        """Parse HTML attribute string into a dictionary."""
        attrs: Dict[str, str] = {}
        try:
            pattern = re.compile(
                r'''([\w:-]+)\s*=\s*["']([^"']*)["']|([\w:-]+)\s*=\s*([^\s"'>]+)|([\w:-]+)(?=\s|>)''',
                re.IGNORECASE,
            )
            for match in pattern.finditer(attrs_str):
                if match.group(1) and match.group(2) is not None:
                    attrs[match.group(1).lower()] = match.group(2)
                elif match.group(3) and match.group(4) is not None:
                    attrs[match.group(3).lower()] = match.group(4)
                elif match.group(5):
                    attrs[match.group(5).lower()] = ""
        except Exception as exc:
            self.logger.debug("Error parsing link attrs: %s", exc)
        return attrs

    def _resolve_url(self, href: str, base_url: str) -> str:
        """Resolve a potentially relative URL against a base URL."""
        if not href or href.startswith("#") or href.startswith("javascript:"):
            return href
        if base_url:
            try:
                return urljoin(base_url, href)
            except Exception:
                pass
        return href

    def categorize_links(self, links: List[Link]) -> Dict[str, List[Link]]:
        """Categorize links by type."""
        categories: Dict[str, List[Link]] = {
            "internal": [],
            "external": [],
            "javascript": [],
            "empty": [],
            "mailto": [],
            "tel": [],
        }
        for link in links:
            if link.is_javascript:
                categories["javascript"].append(link)
            elif link.is_empty:
                categories["empty"].append(link)
            elif link.href.startswith("mailto:"):
                categories["mailto"].append(link)
            elif link.href.startswith("tel:"):
                categories["tel"].append(link)
            elif link.is_external:
                categories["external"].append(link)
            else:
                categories["internal"].append(link)
        return categories


# ---------------------------------------------------------------------------
# ButtonAnalyzer
# ---------------------------------------------------------------------------

class ButtonAnalyzer:
    """Extracts all <button> elements and <input type=button/submit> from HTML."""

    def __init__(self, base_url: str = ""):
        self.base_url = base_url
        self.logger = logging.getLogger(f"{__name__}.ButtonAnalyzer")

    def parse_buttons(self, html_content: str, source_url: str = "") -> List[Button]:
        """Parse all <button> and <input type=submit|button|reset|image> elements."""
        buttons: List[Button] = []
        if not html_content:
            return buttons
        try:
            # <button> elements
            btn_pattern = re.compile(
                r'<button\s([^>]*)>(.*?)</button\s*>',
                re.IGNORECASE | re.DOTALL,
            )
            for match in btn_pattern.finditer(html_content):
                try:
                    btn = self._parse_button_tag(match.group(1), match.group(2), source_url)
                    buttons.append(btn)
                except Exception:
                    continue

            # <input type=submit|button|reset|image>
            input_btn_pattern = re.compile(
                r'''<input\s([^>]*?type\s*=\s*["'](?:submit|button|reset|image)["'][^>]*?)/?\s*>''',
                re.IGNORECASE | re.DOTALL,
            )
            for match in input_btn_pattern.finditer(html_content):
                try:
                    attrs_str = match.group(1)
                    btn = self._parse_input_button(attrs_str, source_url)
                    buttons.append(btn)
                except Exception:
                    continue

        except Exception as exc:
            self.logger.error("Failed to parse buttons from HTML: %s", exc)
        return buttons

    def _parse_button_tag(self, attrs_str: str, content: str, source_url: str) -> Button:
        """Parse a <button> element."""
        btn = Button()
        try:
            attrs = self._parse_attrs(attrs_str)
            btn.button_type = attrs.get("type", "submit").lower()
            btn.name = attrs.get("name", "")
            btn.value = attrs.get("value", content.strip())
            btn.onclick = attrs.get("onclick", "")
            btn.form = attrs.get("form", "")
            btn.formaction = attrs.get("formaction", "")
            if btn.formaction and source_url:
                btn.formaction = urljoin(source_url, btn.formaction)
            btn.formmethod = attrs.get("formmethod", "")
            btn.formtarget = attrs.get("formtarget", "")
            btn.text = content.strip()[:100]
            btn.disabled = "disabled" in attrs_str.lower()
            btn.button_id = attrs.get("id", "")
            btn.button_class = attrs.get("class", "")
            btn.url = source_url or self.base_url
        except Exception as exc:
            self.logger.debug("Error parsing button tag: %s", exc)
        return btn

    def _parse_input_button(self, attrs_str: str, source_url: str) -> Button:
        """Parse an <input type=submit|button|reset|image> element."""
        btn = Button()
        try:
            attrs = self._parse_attrs(attrs_str)
            btn.button_type = attrs.get("type", "submit").lower()
            btn.name = attrs.get("name", "")
            btn.value = attrs.get("value", "")
            btn.onclick = attrs.get("onclick", "")
            btn.form = attrs.get("form", "")
            btn.formaction = attrs.get("formaction", "")
            if btn.formaction and source_url:
                btn.formaction = urljoin(source_url, btn.formaction)
            btn.formmethod = attrs.get("formmethod", "")
            btn.formtarget = attrs.get("formtarget", "")
            btn.text = attrs.get("value", "")
            btn.disabled = "disabled" in attrs_str.lower()
            btn.button_id = attrs.get("id", "")
            btn.button_class = attrs.get("class", "")
            btn.url = source_url or self.base_url
        except Exception as exc:
            self.logger.debug("Error parsing input button: %s", exc)
        return btn

    def _parse_attrs(self, attrs_str: str) -> Dict[str, str]:
        """Parse HTML attribute string into a dictionary."""
        attrs: Dict[str, str] = {}
        try:
            pattern = re.compile(
                r'''([\w:-]+)\s*=\s*["']([^"']*)["']|([\w:-]+)\s*=\s*([^\s"'>]+)|([\w:-]+)(?=\s|>)''',
                re.IGNORECASE,
            )
            for match in pattern.finditer(attrs_str):
                if match.group(1) and match.group(2) is not None:
                    attrs[match.group(1).lower()] = match.group(2)
                elif match.group(3) and match.group(4) is not None:
                    attrs[match.group(3).lower()] = match.group(4)
                elif match.group(5):
                    attrs[match.group(5).lower()] = ""
        except Exception as exc:
            self.logger.debug("Error parsing attrs: %s", exc)
        return attrs


# ---------------------------------------------------------------------------
# EventHandlerScanner
# ---------------------------------------------------------------------------

class EventHandlerScanner:
    """Scans HTML and inline JavaScript for event handler declarations."""

    def __init__(self, base_url: str = ""):
        self.base_url = base_url
        self.logger = logging.getLogger(f"{__name__}.EventHandlerScanner")

    def scan_html(self, html_content: str, source_url: str = "") -> List[EventHandler]:
        """Scan HTML for inline event handler attributes."""
        handlers: List[EventHandler] = []
        if not html_content:
            return handlers
        try:
            for event in _EVENT_HANDLERS:
                pattern = re.compile(
                    rf'{event}\s*=\s*"([^"]*)"',
                    re.IGNORECASE,
                )
                for match in pattern.finditer(html_content):
                    handler_code = match.group(1).strip()
                    if handler_code:
                        eh = EventHandler(
                            event=event,
                            handler_code=handler_code[:500],
                            url=source_url or self.base_url,
                        )
                        handlers.append(eh)

                # Single-quoted handlers
                pattern2 = re.compile(
                    rf"{event}\s*=\s*'([^']*)'",
                    re.IGNORECASE,
                )
                for match in pattern2.finditer(html_content):
                    handler_code = match.group(1).strip()
                    if handler_code:
                        eh = EventHandler(
                            event=event,
                            handler_code=handler_code[:500],
                            url=source_url or self.base_url,
                        )
                        handlers.append(eh)

                # Event handler without quotes (rare but possible)
                pattern3 = re.compile(
                    rf'{event}\s*=\s*([^\s"\'/>]+)',
                    re.IGNORECASE,
                )
                for match in pattern3.finditer(html_content):
                    handler_code = match.group(1).strip()
                    if handler_code:
                        eh = EventHandler(
                            event=event,
                            handler_code=handler_code[:500],
                            url=source_url or self.base_url,
                        )
                        handlers.append(eh)
        except Exception as exc:
            self.logger.error("Failed to scan HTML for event handlers: %s", exc)
        return handlers

    def scan_script_tags(self, html_content: str, source_url: str = "") -> List[EventHandler]:
        """Scan <script> tag content for event handler registrations."""
        handlers: List[EventHandler] = []
        if not html_content:
            return handlers
        try:
            script_pattern = re.compile(
                r'<script[^>]*>(.*?)</script\s*>',
                re.IGNORECASE | re.DOTALL,
            )
            for script_match in script_pattern.finditer(html_content):
                script_content = script_match.group(1)
                # addEventListener patterns
                listener_pattern = re.compile(
                    r'''\.addEventListener\s*\(\s*['"]([^'"]+)['"]\s*,\s*(function\s*\([^)]*\)\s*\{[^}]*\})''',
                    re.IGNORECASE | re.DOTALL,
                )
                for listener_match in listener_pattern.finditer(script_content):
                    event_name = listener_match.group(1).strip()
                    handler_code = listener_match.group(2).strip()[:500]
                    eh = EventHandler(
                        event=f"addEventListener:{event_name}",
                        handler_code=handler_code,
                        element_tag="script",
                        url=source_url or self.base_url,
                    )
                    handlers.append(eh)

                # jQuery .on() patterns
                jquery_pattern = re.compile(
                    r'''\.(?:on|bind|live|delegate)\s*\(\s*['"]([^'"]+)['"]\s*,\s*(function\s*\([^)]*\)\s*\{[^}]*\})''',
                    re.IGNORECASE | re.DOTALL,
                )
                for jq_match in jquery_pattern.finditer(script_content):
                    event_name = jq_match.group(1).strip()
                    handler_code = jq_match.group(2).strip()[:500]
                    eh = EventHandler(
                        event=f"jquery:{event_name}",
                        handler_code=handler_code,
                        element_tag="script",
                        url=source_url or self.base_url,
                    )
                    handlers.append(eh)

                # jQuery .click(), .submit(), etc. shorthand
                shorthand_pattern = re.compile(
                    r'''\.(click|submit|change|focus|blur|hover|keyup|keydown|load|scroll|resize)\s*\(\s*(function\s*\([^)]*\)\s*\{[^}]*\})''',
                    re.IGNORECASE | re.DOTALL,
                )
                for sh_match in shorthand_pattern.finditer(script_content):
                    event_name = sh_match.group(1).strip()
                    handler_code = sh_match.group(2).strip()[:500]
                    eh = EventHandler(
                        event=f"jquery_shorthand:{event_name}",
                        handler_code=handler_code,
                        element_tag="script",
                        url=source_url or self.base_url,
                    )
                    handlers.append(eh)

                # on* = function() patterns in script
                inline_fn = re.compile(
                    r'''(window\.onload|document\.onclick|document\.onsubmit|element\.on\w+)\s*=\s*(function\s*\([^)]*\)\s*\{[^}]*\})''',
                    re.IGNORECASE | re.DOTALL,
                )
                for fn_match in inline_fn.finditer(script_content):
                    event_name = fn_match.group(1).strip()
                    handler_code = fn_match.group(2).strip()[:500]
                    eh = EventHandler(
                        event=event_name,
                        handler_code=handler_code,
                        element_tag="script",
                        url=source_url or self.base_url,
                    )
                    handlers.append(eh)
        except Exception as exc:
            self.logger.debug("Error scanning script tags: %s", exc)
        return handlers

    def scan_all(self, html_content: str, source_url: str = "") -> List[EventHandler]:
        """Run all scanning methods and return combined results."""
        handlers: List[EventHandler] = []
        try:
            handlers.extend(self.scan_html(html_content, source_url))
            handlers.extend(self.scan_script_tags(html_content, source_url))
        except Exception as exc:
            self.logger.error("Event handler scan failed: %s", exc)
        return handlers

    def deduplicate(self, handlers: List[EventHandler]) -> List[EventHandler]:
        """Remove duplicate event handlers."""
        seen: Set[Tuple[str, str]] = set()
        unique: List[EventHandler] = []
        for h in handlers:
            key = (h.event, h.handler_code[:100])
            if key not in seen:
                seen.add(key)
                unique.append(h)
        return unique


# ---------------------------------------------------------------------------
# FrameworkDetector
# ---------------------------------------------------------------------------

class FrameworkDetector:
    """Detects client-side frameworks from HTML and script references."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.FrameworkDetector")

    def detect(self, html_content: str) -> List[FrameworkDetection]:
        """Detect all known client-side frameworks in the HTML."""
        detections: List[FrameworkDetection] = []
        if not html_content:
            return detections
        try:
            for framework, patterns in _FRAMEWORK_PATTERNS.items():
                fd = FrameworkDetection(framework=framework)
                evidence: List[str] = []
                for pattern in patterns:
                    matches = re.findall(pattern, html_content, re.IGNORECASE)
                    if matches:
                        evidence.append(f"matched: {pattern}")
                        for m in matches[:3]:
                            if isinstance(m, str) and m:
                                fd.version = m if re.match(r'^[\d.]+', m) else fd.version
                if evidence:
                    fd.detected = True
                    fd.evidence = evidence[:5]
                    fd.confidence = min(1.0, len(evidence) * 0.25)
                detections.append(fd)
        except Exception as exc:
            self.logger.error("Framework detection failed: %s", exc)
        return detections

    def detect_from_body_attrs(self, html_content: str) -> List[FrameworkDetection]:
        """Detect frameworks by looking at specific body/root element attributes."""
        detections: List[FrameworkDetection] = []
        if not html_content:
            return detections
        try:
            # React root detection
            if 'id="root"' in html_content or 'id="app"' in html_content or 'id="__next"' in html_content:
                fd = FrameworkDetection(
                    framework="react_root",
                    detected=True,
                    evidence=["standard root div found (react/nextjs)"],
                    confidence=0.5,
                )
                detections.append(fd)

            # Angular root detection
            root_match = re.search(r'<app-root[^>]*>', html_content, re.IGNORECASE)
            if root_match:
                fd = FrameworkDetection(
                    framework="angular_root",
                    detected=True,
                    evidence=["<app-root> element found"],
                    confidence=0.6,
                )
                detections.append(fd)

            # Vue app mount
            if 'id="app"' in html_content:
                fd = FrameworkDetection(
                    framework="vue_mount",
                    detected=True,
                    evidence=['id="app" mount point'],
                    confidence=0.4,
                )
                detections.append(fd)
        except Exception as exc:
            self.logger.debug("Error detecting body attrs: %s", exc)
        return detections


# ---------------------------------------------------------------------------
# WorkflowMapper
# ---------------------------------------------------------------------------

class WorkflowMapper:
    """Maps user workflows from form targets, links, and navigation paths."""

    def __init__(self, base_url: str = ""):
        self.base_url = base_url
        self.logger = logging.getLogger(f"{__name__}.WorkflowMapper")

    def map_form_workflows(self, forms: List[Form], source_url: str = "") -> List[WorkflowStep]:
        """Map form submission workflows."""
        steps: List[WorkflowStep] = []
        try:
            for form in forms:
                step = WorkflowStep(
                    step_type="form_submit",
                    source_url=source_url or self.base_url,
                    target_url=form.action,
                    trigger_element=f"form[name={form.name}]" if form.name else f"form[action={form.action}]",
                    trigger_value=form.method,
                    method=form.method,
                )
                # Determine if form likely requires auth (look for password fields)
                for field in form.fields:
                    if field.input_type == "password":
                        step.requires_auth = True
                        break
                    if field.name and any(kw in field.name.lower() for kw in ["pass", "token", "secret"]):
                        step.requires_auth = True
                        break
                # Check for login forms
                if form.action and any(kw in form.action.lower() for kw in ["login", "signin", "auth"]):
                    step.requires_auth = True
                steps.append(step)
        except Exception as exc:
            self.logger.error("Failed to map form workflows: %s", exc)
        return steps

    def map_link_workflows(self, links: List[Link], source_url: str = "") -> List[WorkflowStep]:
        """Map navigation workflows from links."""
        steps: List[WorkflowStep] = []
        try:
            for link in links:
                if link.href and not link.is_javascript and not link.is_empty:
                    step = WorkflowStep(
                        step_type="link_click",
                        source_url=source_url or self.base_url,
                        target_url=link.href,
                        trigger_element=f"a[href={link.href[:80]}]",
                        trigger_value=link.text[:80],
                        method="GET",
                    )
                    steps.append(step)
        except Exception as exc:
            self.logger.error("Failed to map link workflows: %s", exc)
        return steps

    def map_workflows(self, forms: List[Form], links: List[Link],
                      buttons: List[Button], source_url: str = "") -> List[WorkflowStep]:
        """Combine all workflow mappings."""
        steps: List[WorkflowStep] = []
        try:
            steps.extend(self.map_form_workflows(forms, source_url))
            steps.extend(self.map_link_workflows(links, source_url))

            for btn in buttons:
                if btn.formaction:
                    step = WorkflowStep(
                        step_type="form_submit",
                        source_url=source_url or self.base_url,
                        target_url=btn.formaction,
                        trigger_element=f"button[name={btn.name}]" if btn.name else "button[formaction]",
                        trigger_value=btn.text[:80],
                        method=btn.formmethod.upper() if btn.formmethod else "POST",
                    )
                    steps.append(step)
                if btn.onclick:
                    step = WorkflowStep(
                        step_type="api_call",
                        source_url=source_url or self.base_url,
                        target_url=btn.onclick[:200],
                        trigger_element=f"button[onclick]" if not btn.name else f"button[name={btn.name}]",
                        trigger_value=btn.text[:80],
                        method="GET",
                    )
                    steps.append(step)
        except Exception as exc:
            self.logger.error("Failed to map workflows: %s", exc)
        return steps

    def find_auth_workflows(self, steps: List[WorkflowStep]) -> List[WorkflowStep]:
        """Filter workflow steps that are related to authentication."""
        auth_steps: List[WorkflowStep] = []
        auth_keywords = ["login", "signin", "sign-in", "log-in", "auth",
                         "password", "forgot", "reset", "register", "signup",
                         "sign-up", "oauth", "saml", "callback"]
        for step in steps:
            target_lower = step.target_url.lower()
            source_lower = step.source_url.lower()
            if any(kw in target_lower for kw in auth_keywords):
                auth_steps.append(step)
            elif any(kw in source_lower for kw in auth_keywords):
                auth_steps.append(step)
            elif step.requires_auth:
                auth_steps.append(step)
        return auth_steps


# ---------------------------------------------------------------------------
# FunctionalityExtractor
# ---------------------------------------------------------------------------

class FunctionalityExtractor:
    """
    Master orchestrator that extracts all user-interactive elements from HTML.

    Combines form analysis, link analysis, button analysis, event handler
    scanning, framework detection, and workflow mapping into a single report.
    """

    def __init__(self, timeout: float = _DEFAULT_TIMEOUT, verbose: bool = False, allow_insecure: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self.allow_insecure = allow_insecure
        self.logger = logging.getLogger(f"{__name__}.FunctionalityExtractor")

    def extract_from_url(
        self,
        url: str,
        depth: int = 1,
        include_hidden: bool = False,
        follow_redirects: bool = True,
    ) -> FunctionalityReport:
        """Fetch a URL and extract all interactive elements."""
        report = FunctionalityReport(url=url)
        report.extraction_time = datetime.datetime.utcnow().isoformat()

        html_content = self._fetch_url(url, follow_redirects)
        if not html_content:
            report.errors.append(f"Failed to fetch URL: {url}")
            return report

        self._parse_html(html_content, url, report, include_hidden)

        # Crawl linked pages up to depth
        if depth > 1:
            visited: Set[str] = {url}
            current_depth = 1
            current_urls: List[str] = [url]

            while current_depth < depth and current_urls:
                next_urls: List[str] = []
                for current_url in current_urls:
                    inner_html = self._fetch_url(current_url, follow_redirects)
                    if not inner_html:
                        continue
                    inner_report = FunctionalityReport(url=current_url)
                    self._parse_html(inner_html, current_url, inner_report, include_hidden)
                    report.forms.extend(inner_report.forms)
                    report.links.extend(inner_report.links)
                    report.buttons.extend(inner_report.buttons)
                    report.event_handlers.extend(inner_report.event_handlers)
                    report.workflows.extend(inner_report.workflows)

                    for link in inner_report.links:
                        if (link.href and not link.is_external and not link.is_javascript
                                and not link.is_empty and link.href not in visited):
                            visited.add(link.href)
                            if len(next_urls) < 10:
                                next_urls.append(link.href)
                current_urls = next_urls
                current_depth += 1
                report.depth_reached = current_depth

        report.total_interactive_elements = (
            len(report.forms) + len(report.links) + len(report.buttons)
            + len(report.event_handlers)
        )
        return report

    def extract_from_file(self, filepath: str, base_url: str = "",
                          include_hidden: bool = False) -> FunctionalityReport:
        """Extract interactive elements from an HTML file."""
        report = FunctionalityReport(url=filepath)
        report.extraction_time = datetime.datetime.utcnow().isoformat()
        try:
            file_size = os.path.getsize(filepath)
            if file_size > _MAX_FILE_SIZE:
                report.errors.append(f"File too large ({file_size} > {_MAX_FILE_SIZE}): {filepath}")
                self.logger.error("File too large: %s", filepath)
                return report
            with open(filepath, "r", encoding="utf-8") as f:
                html_content = f.read()
            self._parse_html(html_content, base_url or filepath, report, include_hidden)
            report.total_interactive_elements = (
                len(report.forms) + len(report.links) + len(report.buttons)
                + len(report.event_handlers)
            )
        except FileNotFoundError:
            report.errors.append(f"File not found: {filepath}")
            self.logger.error("File not found: %s", filepath)
        except PermissionError:
            report.errors.append(f"Permission denied: {filepath}")
            self.logger.error("Permission denied: %s", filepath)
        except Exception as exc:
            report.errors.append(f"Error reading file: {exc}")
            self.logger.error("Failed to read file %s: %s", filepath, exc)
        return report

    def extract_from_html(self, html_content: str, source_url: str = "",
                          include_hidden: bool = False) -> FunctionalityReport:
        """Extract interactive elements directly from HTML string."""
        report = FunctionalityReport(url=source_url)
        report.extraction_time = datetime.datetime.utcnow().isoformat()
        self._parse_html(html_content, source_url, report, include_hidden)
        report.total_interactive_elements = (
            len(report.forms) + len(report.links) + len(report.buttons)
            + len(report.event_handlers)
        )
        return report

    def _fetch_url(self, url: str, follow_redirects: bool = True) -> Optional[str]:
        """Fetch a URL and return the HTML content."""
        if len(url) > _MAX_URL_LENGTH:
            self.logger.warning("URL exceeds max length (%d > %d): %s...", len(url), _MAX_URL_LENGTH, url[:100])
            return None
        try:
            ctx = ssl.create_default_context()
            if self.allow_insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            max_redirs = _MAX_REDIRECTS if follow_redirects else 0
            redirect_count = 0
            current_url = url

            while redirect_count <= max_redirs:
                try:
                    req = urllib.request.Request(
                        current_url,
                        headers={"User-Agent": _DEFAULT_USER_AGENT},
                        unverifiable=True,
                    )
                    with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                        content_type = resp.headers.get("Content-Type", "")
                        if "text/html" in content_type or "application/xhtml" in content_type:
                            html = resp.read().decode("utf-8", errors="replace")
                            return html
                        elif "json" in content_type:
                            html = resp.read().decode("utf-8", errors="replace")
                            return f"<pre>{html}</pre>"
                        else:
                            raw = resp.read()
                            try:
                                return raw.decode("utf-8", errors="replace")
                            except Exception:
                                return f"<pre>[binary content: {len(raw)} bytes]</pre>"
                except urllib.request.HTTPError as exc:
                    if exc.code in (301, 302, 303, 307, 308) and follow_redirects:
                        current_url = exc.headers.get("Location", "")
                        if current_url:
                            current_url = urljoin(url, current_url)
                            redirect_count += 1
                            continue
                    return None
                except urllib.request.URLError as exc:
                    self.logger.error("URL error fetching %s: %s", current_url, exc)
                    return None
        except ssl.SSLError as exc:
            self.logger.error("SSL error fetching %s: %s", url, exc)
        except socket.timeout:
            self.logger.error("Timeout fetching %s", url)
        except Exception as exc:
            self.logger.error("Failed to fetch %s: %s", url, exc)
        return None

    def _parse_html(self, html_content: str, source_url: str,
                    report: FunctionalityReport, include_hidden: bool) -> None:
        """Parse HTML content and populate a report with all findings."""
        try:
            # Title
            title_match = re.search(r'<title[^>]*>(.*?)</title\s*>', html_content, re.IGNORECASE | re.DOTALL)
            if title_match:
                report.title = title_match.group(1).strip()

            # Remove hidden elements if not included
            if not include_hidden:
                html_content = re.sub(
                    r'<[^>]*style=["\']display:\s*none["\'][^>]*>.*?</[^>]+>',
                    '', html_content, flags=re.IGNORECASE | re.DOTALL,
                )
                html_content = re.sub(
                    r'<[^>]*hidden[^>]*>.*?</[^>]+>',
                    '', html_content, flags=re.IGNORECASE | re.DOTALL,
                )

            # Form analysis
            form_analyzer = FormAnalyzer(base_url=source_url)
            report.forms = form_analyzer.parse_forms(html_content, source_url)

            # Link analysis
            link_analyzer = LinkAnalyzer(base_url=source_url)
            report.links = link_analyzer.parse_links(html_content, source_url)

            # Button analysis
            button_analyzer = ButtonAnalyzer(base_url=source_url)
            report.buttons = button_analyzer.parse_buttons(html_content, source_url)

            # Event handler scanning
            event_scanner = EventHandlerScanner(base_url=source_url)
            raw_handlers = event_scanner.scan_all(html_content, source_url)
            report.event_handlers = event_scanner.deduplicate(raw_handlers)

            # Framework detection
            framework_detector = FrameworkDetector()
            report.frameworks = framework_detector.detect(html_content)
            report.frameworks.extend(framework_detector.detect_from_body_attrs(html_content))

            # Workflow mapping
            workflow_mapper = WorkflowMapper(base_url=source_url)
            report.workflows = workflow_mapper.map_workflows(
                report.forms, report.links, report.buttons, source_url,
            )
        except Exception as exc:
            self.logger.error("Failed to parse HTML: %s", exc)
            report.errors.append(f"HTML parsing error: {exc}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="extract_functionalities",
        description="User Functionality Extraction Tool — discovers all user-interactive "
                    "elements from HTML pages: forms, links, buttons, inputs, event "
                    "handlers, and workflows. Detects client-side frameworks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python extract_functionalities.py --url https://example.com\n"
            "  python extract_functionalities.py --url https://example.com --depth 2\n"
            "  python extract_functionalities.py --file page.html\n"
            "  python extract_functionalities.py --url https://example.com --include-hidden\n"
            "  python extract_functionalities.py --url https://example.com --json --output report.json\n"
            "  python extract_functionalities.py --url https://example.com --verbose\n"
        ),
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", "-u", type=str, default="", help="Target URL to extract from")
    group.add_argument("--file", "-f", type=str, default="", help="HTML file to extract from")

    parser.add_argument("--output", "-o", type=str, default="", help="Output file path")
    parser.add_argument("--depth", "-d", type=int, default=1,
                        help="Crawl depth for linked pages (default: 1)")
    parser.add_argument("--include-hidden", action="store_true", default=False,
                        help="Include hidden form fields and elements")
    parser.add_argument("--follow-redirects", action="store_true", default=True,
                        help="Follow HTTP redirects (default: True)")
    parser.add_argument("--no-follow-redirects", action="store_false", dest="follow_redirects",
                        help="Do not follow HTTP redirects")
    parser.add_argument("--json", "-j", action="store_true", default=False,
                        help="Output as JSON (default: human-readable text)")
    parser.add_argument("--verbose", "-v", action="store_true", default=False,
                        help="Enable verbose debug logging")
    parser.add_argument("--allow-insecure", action="store_true",
                        help="Allow insecure SSL connections (skip certificate verification)")
    return parser.parse_args(argv)


def _format_report_text(report: FunctionalityReport) -> str:
    """Format the functionality report as human-readable text."""
    lines: List[str] = []
    lines.append("=" * 70)
    lines.append(f"Functionality Extraction Report — {report.url}")
    lines.append("=" * 70)
    lines.append(f"Title:       {report.title}")
    lines.append(f"Depth:       {report.depth_reached}")
    lines.append(f"Forms:       {len(report.forms)}")
    lines.append(f"Links:       {len(report.links)}")
    lines.append(f"Buttons:     {len(report.buttons)}")
    lines.append(f"Event Hndl:  {len(report.event_handlers)}")
    lines.append(f"Workflows:   {len(report.workflows)}")
    lines.append(f"Total elem:  {report.total_interactive_elements}")
    lines.append(f"Extracted:   {report.extraction_time}")
    lines.append("")

    if report.frameworks:
        lines.append("--- Detected Frameworks ---")
        for fd in report.frameworks:
            status = "YES" if fd.detected else "no"
            lines.append(f"  {fd.framework:>12}: {status}  (conf: {fd.confidence:.1f})")
            if fd.detected and fd.evidence:
                for ev in fd.evidence[:2]:
                    lines.append(f"           -> {ev}")
        lines.append("")

    lines.append("--- Forms ---")
    if report.forms:
        for i, form in enumerate(report.forms, 1):
            lines.append(f"  Form #{i}:")
            lines.append(f"    Action:    {form.action}")
            lines.append(f"    Method:    {form.method}")
            lines.append(f"    Enctype:   {form.enctype}")
            lines.append(f"    Name/ID:   {form.name}/{form.form_id}")
            lines.append(f"    Target:    {form.target}")
            lines.append(f"    Fields:    {len(form.fields)}")
            for field in form.fields:
                req = " [REQ]" if field.required else ""
                dis = " [DIS]" if field.disabled else ""
                opts = f" ({len(field.options)} options)" if field.options else ""
                lines.append(f"      - {field.field_type:>8}:{field.input_type:>10} "
                             f"name={field.name} value={field.value[:50]}{req}{dis}{opts}")
            lines.append("")
    else:
        lines.append("  (no forms found)")
        lines.append("")

    lines.append("--- Links (first 30) ---")
    for i, link in enumerate(report.links[:30], 1):
        ext = " [EXT]" if link.is_external else ""
        js = " [JS]" if link.is_javascript else ""
        lines.append(f"  {i:3d}. {link.href[:90]}{ext}{js}")
        if link.text:
            lines.append(f"       text: {link.text[:60]}")
    if len(report.links) > 30:
        lines.append(f"  ... and {len(report.links) - 30} more")
    lines.append("")

    lines.append("--- Buttons (first 20) ---")
    for i, btn in enumerate(report.buttons[:20], 1):
        dis = " [DIS]" if btn.disabled else ""
        lines.append(f"  {i:3d}. [{btn.button_type:>6}] name={btn.name} value={btn.value[:40]}{dis}")
        if btn.formaction:
            lines.append(f"       formaction: {btn.formaction}")
        if btn.onclick:
            lines.append(f"       onclick: {btn.onclick[:60]}")
    if len(report.buttons) > 20:
        lines.append(f"  ... and {len(report.buttons) - 20} more")
    lines.append("")

    lines.append("--- Event Handlers (first 20) ---")
    for i, eh in enumerate(report.event_handlers[:20], 1):
        lines.append(f"  {i:3d}. {eh.event}")
        lines.append(f"       code: {eh.handler_code[:80]}")
    if len(report.event_handlers) > 20:
        lines.append(f"  ... and {len(report.event_handlers) - 20} more")
    lines.append("")

    lines.append("--- Workflow Steps (first 20) ---")
    for i, ws in enumerate(report.workflows[:20], 1):
        auth = " [AUTH]" if ws.requires_auth else ""
        lines.append(f"  {i:3d}. [{ws.step_type:>14}] {ws.method:>4} -> {ws.target_url[:80]}{auth}")
    if len(report.workflows) > 20:
        lines.append(f"  ... and {len(report.workflows) - 20} more")
    lines.append("")

    if report.errors:
        lines.append("--- Errors ---")
        for err in report.errors:
            lines.append(f"  [!] {err}")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    args = parse_args()
    _setup_logging(verbose=args.verbose)

    extractor = FunctionalityExtractor(timeout=_DEFAULT_TIMEOUT, verbose=args.verbose, allow_insecure=args.allow_insecure)

    if args.file:
        logger.info("Extracting from file: %s", args.file)
        report = extractor.extract_from_file(
            args.file,
            include_hidden=args.include_hidden,
        )
    else:
        logger.info("Extracting from URL: %s (depth=%d)", args.url, args.depth)
        report = extractor.extract_from_url(
            args.url,
            depth=args.depth,
            include_hidden=args.include_hidden,
            follow_redirects=args.follow_redirects,
        )

    if args.json:
        output = json.dumps(report.to_dict(), indent=2, default=str)
        print(output)
    else:
        output = _format_report_text(report)
        print(output)

    if args.output:
        try:
            output_path = _validate_output_path(args.output)
            dirname = os.path.dirname(os.path.abspath(output_path))
            if dirname:
                os.makedirs(dirname, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(output)
            logger.info("Report written to %s", output_path)
        except OSError as exc:
            logger.error("Failed to write output: %s", exc)

    logger.info("Extraction complete — %d total interactive elements", report.total_interactive_elements)


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
