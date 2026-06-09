#!/usr/bin/env python3
"""
report_builder.py — Finding Report Builder & CVSS 3.1 Calculator

Generates professional bug bounty and security finding reports with CVSS 3.1
scoring, platform-specific templates (HackerOne, Bugcrowd, Intigriti),
custom template support, and batch processing. Designed for security
researchers and penetration testers.

Features:
    - Reads findings from JSON input files
    - Generates reports in HackerOne, Bugcrowd, Intigriti, and generic markdown
    - CVSS 3.1 scoring calculator with all 8 base metrics
    - CVSS vector string generation and severity rating
    - Template system for custom report formats
    - Batch processing of multiple finding files
    - JSON export for programmatic use
    - Author metadata and report branding

Classes:
    Finding: Dataclass representing a single security finding
    Cvss31Calculator: CVSS 3.1 base score computation
    TemplateEngine: Custom report template rendering
    BatchProcessor: Multi-file batch processing
    ReportBuilder: Main report generation orchestrator
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
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("report_builder")


@dataclass
class Finding:
    """Represents a single security finding for report generation.

    Attributes:
        title: Finding title
        severity: Severity rating (critical, high, medium, low, info, none)
        description: Detailed description of the vulnerability
        impact: Business/security impact statement
        reproduction_steps: Step-by-step reproduction instructions
        evidence: PoC evidence (HTTP requests, screenshots, etc.)
        remediation: Fix recommendation
        cvss_vector: CVSS 3.1 vector string
        cwe_id: CWE identifier (e.g., CWE-79)
        references: List of reference URLs
        vulnerable_url: URL where the vulnerability was found
        parameter: Affected parameter name
        payload: Payload used for exploitation
        tags: List of tags/categories for the finding
    """
    title: str = ""
    severity: str = "medium"
    description: str = ""
    impact: str = ""
    reproduction_steps: str = ""
    evidence: str = ""
    remediation: str = ""
    cvss_vector: str = ""
    cwe_id: str = ""
    references: List[str] = field(default_factory=list)
    vulnerable_url: str = ""
    parameter: str = ""
    payload: str = ""
    tags: List[str] = field(default_factory=list)

    def validate(self) -> List[str]:
        """Validate the finding has all required fields.

        Returns:
            List of missing field descriptions
        """
        missing: List[str] = []
        if not self.title:
            missing.append("title")
        if not self.description:
            missing.append("description")
        if not self.severity:
            missing.append("severity")
        valid_severities = {"critical", "high", "medium", "low", "info", "none"}
        if self.severity.lower() not in valid_severities:
            missing.append(f"valid severity (one of: {', '.join(sorted(valid_severities))})")
        return missing

    def is_valid(self) -> bool:
        """Check if the finding has all required fields.

        Returns:
            True if all required fields are present
        """
        return len(self.validate()) == 0


class Cvss31Calculator:
    """CVSS 3.1 Base Score calculator with full metric support.

    Computes CVSS 3.1 base scores from the 8 base metrics (AV, AC, PR,
    UI, S, C, I, A), generates vector strings, and provides severity
    ratings. Supports all valid metric values per the CVSS 3.1 spec.

    Attributes:
        METRICS: Dict of metric groups and their valid values
        SEVERITY_RANGES: Dict mapping severity to score ranges
    """

    METRICS: Dict[str, Dict[str, float]] = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
        "AC": {"L": 0.77, "H": 0.44},
        "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
        "UI": {"N": 0.85, "R": 0.62},
        "S": {"U": 0.0, "C": 1.0},
        "C": {"H": 0.56, "L": 0.22, "N": 0.0},
        "I": {"H": 0.56, "L": 0.22, "N": 0.0},
        "A": {"H": 0.56, "L": 0.22, "N": 0.0},
    }

    METRIC_LABELS: Dict[str, Dict[str, str]] = {
        "AV": {
            "N": "Network",
            "A": "Adjacent Network",
            "L": "Local",
            "P": "Physical",
        },
        "AC": {"L": "Low", "H": "High"},
        "PR": {
            "N": "None",
            "L": "Low",
            "H": "High",
        },
        "UI": {"N": "None", "R": "Required"},
        "S": {"U": "Unchanged", "C": "Changed"},
        "C": {"H": "High", "L": "Low", "N": "None"},
        "I": {"H": "High", "L": "Low", "N": "None"},
        "A": {"H": "High", "L": "Low", "N": "None"},
    }

    SEVERITY_RANGES: List[Tuple[str, float, float]] = [
        ("none", 0.0, 0.0),
        ("low", 0.1, 3.9),
        ("medium", 4.0, 6.9),
        ("high", 7.0, 8.9),
        ("critical", 9.0, 10.0),
    ]

    PR_CHANGED_MAP: Dict[str, float] = {
        "N": 0.85, "L": 0.68, "H": 0.50,
    }

    def __init__(self):
        """Initialize the CVSS calculator."""
        self.metrics: Dict[str, str] = {}
        self.base_score: float = 0.0
        self.vector_string: str = ""
        self.severity: str = "none"

    def set_metric(self, name: str, value: str) -> bool:
        """Set a single CVSS metric value.

        Args:
            name: Metric name (AV, AC, PR, UI, S, C, I, A)
            value: Metric value (N, L, H, etc.)

        Returns:
            True if the metric was valid and set
        """
        if name not in self.METRICS:
            logger.warning("Unknown metric: %s", name)
            return False
        if value not in self.METRICS[name]:
            logger.warning("Invalid value %s for metric %s", value, name)
            return False
        self.metrics[name] = value
        return True

    def set_metrics(self, metrics: Dict[str, str]) -> List[str]:
        """Set multiple CVSS metrics at once.

        Args:
            metrics: Dict of metric name to value

        Returns:
            List of any error messages
        """
        errors: List[str] = []
        for name, value in metrics.items():
            if not self.set_metric(name, value):
                errors.append(f"Invalid {name}={value}")
        return errors

    def parse_vector(self, vector: str) -> List[str]:
        """Parse a CVSS vector string and set metrics.

        Args:
            vector: CVSS vector string (e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

        Returns:
            List of parse errors (empty if successful)
        """
        self.metrics = {}
        errors: List[str] = []

        cleaned = vector.strip()
        if cleaned.startswith("CVSS:3.1/"):
            cleaned = cleaned[9:]
        elif cleaned.startswith("CVSS:3.0/"):
            cleaned = cleaned[9:]

        parts = cleaned.split("/")
        for part in parts:
            if ":" not in part:
                continue
            name, value = part.split(":", 1)
            if not self.set_metric(name.strip(), value.strip()):
                errors.append(f"Invalid metric: {part}")

        if not errors:
            self.compute_score()

        return errors

    def compute_score(self) -> float:
        """Compute the CVSS 3.1 base score from set metrics.

        Implements the CVSS 3.1 base score formula:
        If Scope is Unchanged:
            Base = min(ISS + Exploitability, 10) * Impact
        If Scope is Changed:
            Base = min(1.08 * (ISS + Exploitability), 10) * Impact

        Returns:
            Computed base score (0.0 - 10.0)
        """
        required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
        missing = [m for m in required if m not in self.metrics]
        if missing:
            logger.warning("Cannot compute score, missing metrics: %s", ", ".join(missing))
            return 0.0

        av = self.METRICS["AV"][self.metrics["AV"]]
        ac = self.METRICS["AC"][self.metrics["AC"]]
        pr_base = self.metrics["PR"]
        if self.metrics["S"] == "C":
            pr = self.PR_CHANGED_MAP.get(pr_base, 0.68)
        else:
            pr = self.METRICS["PR"][pr_base]
        ui = self.METRICS["UI"][self.metrics["UI"]]
        s = self.metrics["S"]
        c = self.METRICS["C"][self.metrics["C"]]
        i = self.METRICS["I"][self.metrics["I"]]
        a = self.METRICS["A"][self.metrics["A"]]

        exploitability = 8.22 * av * ac * pr * ui
        impact = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

        if s == "U":
            if impact <= 0.0:
                self.base_score = 0.0
            else:
                self.base_score = min(exploitability + impact, 10.0) * impact
                self.base_score = min(self.base_score, 10.0)
        else:
            impact_changed = 1.0 - ((1.0 - c * 1.0) * (1.0 - i * 1.0) * (1.0 - a * 1.0))
            if impact_changed <= 0.0:
                self.base_score = 0.0
            else:
                self.base_score = min(1.08 * (exploitability + impact_changed), 10.0) * impact_changed
                self.base_score = min(self.base_score, 10.0)

        self.base_score = round(self.base_score * 10.0) / 10.0
        self.severity = self.rating_from_score(self.base_score)
        self.vector_string = self.build_vector()

        return self.base_score

    def build_vector(self) -> str:
        """Build the CVSS vector string from current metrics.

        Returns:
            CVSS 3.1 vector string
        """
        required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
        parts = [f"{m}:{self.metrics.get(m, 'X')}" for m in required]
        return "CVSS:3.1/" + "/".join(parts)

    def rating_from_score(self, score: float) -> str:
        """Convert a numeric score to a severity rating.

        Args:
            score: CVSS base score (0.0 - 10.0)

        Returns:
            Severity string: none, low, medium, high, critical
        """
        for severity, low, high in self.SEVERITY_RANGES:
            if low <= score <= high:
                return severity
        return "none"

    def explain_vector(self, vector: str) -> List[str]:
        """Generate human-readable explanation of a CVSS vector.

        Args:
            vector: CVSS 3.1 vector string

        Returns:
            List of explanation strings for each metric
        """
        explanations: List[str] = []
        cleaned = vector.strip()
        if cleaned.startswith("CVSS:3."):
            cleaned = cleaned.split("/", 1)[1] if "/" in cleaned else ""

        parts = cleaned.split("/")
        for part in parts:
            if ":" not in part:
                continue
            name, value = part.split(":", 1)
            if name in self.METRIC_LABELS and value in self.METRIC_LABELS[name]:
                label = self.METRIC_LABELS[name][value]
                explanations.append(f"{name}: {label}")
            else:
                explanations.append(f"{name}: {value}")

        return explanations

    def get_suggested_severity(self, vuln_type: str = "") -> str:
        """Get a suggested severity for common vulnerability types.

        Args:
            vuln_type: Type of vulnerability

        Returns:
            Suggested severity string
        """
        suggestions: Dict[str, str] = {
            "rce": "critical",
            "sql_injection": "critical",
            "command_injection": "critical",
            "idor": "high",
            "ssrf": "high",
            "xss": "medium",
            "csrf": "medium",
            "open_redirect": "low",
            "information_disclosure": "low",
            "xxe": "high",
            "file_upload": "critical",
            "auth_bypass": "critical",
            "privilege_escalation": "high",
            "business_logic": "medium",
            "race_condition": "medium",
            "ssti": "high",
            "deserialization": "critical",
            "path_traversal": "high",
            "subdomain_takeover": "high",
            "misconfiguration": "medium",
        }
        return suggestions.get(vuln_type.lower(), "medium")

    def get_summary(self) -> Dict[str, Any]:
        """Return a summary of the CVSS computation.

        Returns:
            Dictionary with score, severity, vector, and metric labels
        """
        labels: Dict[str, str] = {}
        for name, value in self.metrics.items():
            if name in self.METRIC_LABELS and value in self.METRIC_LABELS[name]:
                labels[name] = self.METRIC_LABELS[name][value]
            else:
                labels[name] = value

        return {
            "base_score": self.base_score,
            "severity": self.severity,
            "vector_string": self.vector_string,
            "metrics": dict(self.metrics),
            "metric_labels": labels,
        }


class TemplateEngine:
    """Custom report template rendering engine.

    Provides a Jinja2-inspired template system with variable substitution,
    conditional blocks, loops over findings, and date formatting. Supports
    custom template files with {{ variable }} syntax.

    Attributes:
        template_dir: Directory containing template files
        builtin_templates: Dict of built-in template strings
    """

    BUILTIN_TEMPLATES: Dict[str, str] = {
        "hackerone": textwrap.dedent("""\
            ## Summary

            {{ description }}

            ## Severity

            {{ severity|upper }}

            {% if cvss_vector %}
            **CVSS Vector:** `{{ cvss_vector }}`
            {% endif %}

            ## Steps To Reproduce

            {{ reproduction_steps }}

            ## Impact

            {{ impact }}

            ## Supporting Material / Evidence

            ```
            {{ evidence }}
            ```

            {% if vulnerable_url %}
            **Affected URL:** {{ vulnerable_url }}
            {% endif %}

            {% if parameter %}
            **Affected Parameter:** {{ parameter }}
            {% endif %}

            {% if payload %}
            **Payload:** `{{ payload }}`
            {% endif %}

            {% if references %}
            ## References
            {% for ref in references %}
            - {{ ref }}
            {% endfor %}
            {% endif %}
        """),
        "bugcrowd": textwrap.dedent("""\
            ## Vulnerability Description

            {{ description }}

            ## Severity Justification

            {{ severity_justification }}

            {% if cvss_vector %}
            **CVSS Vector:** `{{ cvss_vector }}`
            {% endif %}

            ## Steps to Reproduce

            {{ reproduction_steps }}

            ## Proof of Concept / Evidence

            ```
            {{ evidence }}
            ```

            ## Impact

            {{ impact }}

            ## Remediation Recommendation

            {{ remediation }}

            {% if vulnerable_url %}
            **Affected URL:** {{ vulnerable_url }}
            {% endif %}
        """),
        "intigriti": textwrap.dedent("""\
            ## Vulnerability Title

            {{ title }}

            ## Vulnerability Type

            {{ cwe_id }}

            ## Vulnerability Description

            {{ description }}

            ## Steps to Reproduce

            {{ reproduction_steps }}

            ## Proof of Concept

            ```
            {{ evidence }}
            ```

            ## Impact

            {{ impact }}

            ## Remediation

            {{ remediation }}

            ## References

            {% for ref in references %}
            - {{ ref }}
            {% endfor %}
        """),
        "generic": textwrap.dedent("""\
            # {{ title }}

            **Severity:** {{ severity|upper }}
            **Date:** {{ date }}
            **CWE:** {{ cwe_id|default('N/A') }}

            {% if cvss_vector %}
            **CVSS Vector:** `{{ cvss_vector }}`
            **CVSS Score:** {{ cvss_score }}
            {% endif %}

            ---

            ## Description

            {{ description }}

            ## Impact

            {{ impact }}

            ## Steps to Reproduce

            {{ reproduction_steps }}

            ## Evidence

            ```
            {{ evidence }}
            ```

            ## Remediation

            {{ remediation }}

            {% if references %}
            ## References
            {% for ref in references %}
            - {{ ref }}
            {% endfor %}
            {% endif %}

            {% if tags %}
            ## Tags
            {{ tags|join(', ') }}
            {% endif %}
        """),
    }

    SEVERITY_JUSTIFICATIONS: Dict[str, str] = {
        "critical": "This vulnerability allows direct compromise of the target "
                    "system without user interaction, leading to complete loss of "
                    "confidentiality, integrity, and availability.",
        "high": "This vulnerability allows significant compromise of data "
                "confidentiality or integrity, requiring minimal user interaction "
                "or preconditions.",
        "medium": "This vulnerability has limited but meaningful security impact, "
                  "requiring specific conditions or user interaction to exploit.",
        "low": "This vulnerability has minimal direct impact but represents a "
               "best-practice violation or information leak.",
        "info": "This is an informational finding with no direct security impact.",
    }

    def __init__(self, template_dir: Optional[str] = None):
        """Initialize the template engine.

        Args:
            template_dir: Optional directory containing custom template files
        """
        self.template_dir = template_dir
        self.custom_templates: Dict[str, str] = {}
        if template_dir:
            self._load_templates()

    def _load_templates(self) -> None:
        """Load custom template files from the template directory.

        Reads all .md and .txt files from the template directory.
        """
        if not self.template_dir or not os.path.isdir(self.template_dir):
            return

        for filename in os.listdir(self.template_dir):
            if filename.endswith((".md", ".txt")):
                path = os.path.join(self.template_dir, filename)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        name = os.path.splitext(filename)[0]
                        self.custom_templates[name] = f.read()
                        logger.debug("Loaded template: %s", name)
                except Exception as e:
                    logger.warning("Failed to load template %s: %s", filename, e)

    def render(
        self,
        template_name: str,
        finding: Finding,
        extra_vars: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Render a finding using the specified template.

        Supports {{ variable }} substitution, {% if condition %} blocks,
        {% for item in list %} loops, and filters like |upper, |lower, |default.

        Args:
            template_name: Name of the template (builtin or custom)
            finding: Finding object with data to render
            extra_vars: Additional variables for the template

        Returns:
            Rendered template string

        Raises:
            ValueError: If the template is not found
        """
        template = self._get_template(template_name)
        if not template:
            raise ValueError(f"Template not found: {template_name}")

        vars: Dict[str, Any] = {
            "title": finding.title,
            "severity": finding.severity,
            "description": finding.description,
            "impact": finding.impact,
            "reproduction_steps": finding.reproduction_steps,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
            "cvss_vector": finding.cvss_vector,
            "cvss_score": "",
            "cwe_id": finding.cwe_id,
            "references": finding.references,
            "vulnerable_url": finding.vulnerable_url,
            "parameter": finding.parameter,
            "payload": finding.payload,
            "tags": finding.tags,
            "severity_justification": self.SEVERITY_JUSTIFICATIONS.get(
                finding.severity.lower(), ""
            ),
            "date": datetime.datetime.now().strftime("%Y-%m-%d"),
        }

        if extra_vars:
            vars.update(extra_vars)

        if finding.cvss_vector:
            calc = Cvss31Calculator()
            errors = calc.parse_vector(finding.cvss_vector)
            if not errors:
                vars["cvss_score"] = str(calc.base_score)

        return self._render_template(template, vars)

    def _get_template(self, name: str) -> Optional[str]:
        """Get template content by name.

        Args:
            name: Template name (checks custom first, then builtin)

        Returns:
            Template string or None
        """
        if name in self.custom_templates:
            return self.custom_templates[name]
        return self.BUILTIN_TEMPLATES.get(name)

    def _render_template(self, template: str, vars: Dict[str, Any]) -> str:
        """Render a template string with variable substitution.

        Implements:
            - {{ variable }} substitution
            - {{ variable|filter }} filters (upper, lower, default)
            - {% if condition %}...{% endif %} blocks
            - {% for item in list %}...{% endfor %} loops

        Args:
            template: Template string
            vars: Variables dictionary

        Returns:
            Rendered string
        """
        result = template

        result = self._render_for_loops(result, vars)
        result = self._render_conditionals(result, vars)
        result = self._render_variables(result, vars)

        return result

    def _render_variables(self, template: str, vars: Dict[str, Any]) -> str:
        """Replace {{ variable }} and {{ variable|filter }} placeholders.

        Args:
            template: Template string with variable placeholders
            vars: Variables dictionary

        Returns:
            Template with variables substituted
        """
        def _replace_var(match: re.Match) -> str:
            expr = match.group(1).strip()

            if "|" in expr:
                parts = expr.split("|")
                var_name = parts[0].strip()
                filters = [p.strip() for p in parts[1:]]
            else:
                var_name = expr
                filters = []

            value = self._resolve_var(var_name, vars)

            for f in filters:
                if f == "upper" and isinstance(value, str):
                    value = value.upper()
                elif f == "lower" and isinstance(value, str):
                    value = value.lower()
                elif f.startswith("default:") and not value:
                    value = f.split(":", 1)[1]
                elif f == "default" and not value:
                    value = ""

            if isinstance(value, list):
                return ", ".join(str(v) for v in value)
            return str(value) if value is not None else ""

        pattern = r'\{\{\s*(.+?)\s*\}\}'
        return re.sub(pattern, _replace_var, template)

    def _resolve_var(self, name: str, vars: Dict[str, Any]) -> Any:
        """Resolve a variable name, supporting dotted access.

        Args:
            name: Variable name (e.g., "finding.title")
            vars: Variables dictionary

        Returns:
            Resolved value or empty string
        """
        parts = name.split(".")
        value = vars
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part, "")
            elif hasattr(value, part):
                value = getattr(value, part, "")
            else:
                return ""
        return value

    def _render_conditionals(self, template: str, vars: Dict[str, Any]) -> str:
        """Process {% if condition %}...{% endif %} blocks.

        Args:
            template: Template string with conditionals
            vars: Variables dictionary

        Returns:
            Template with conditionals evaluated
        """
        pattern = r'\{%\s*if\s+(.+?)\s*%\}(.*?)\{%\s*endif\s*%\}'

        def _replace_if(match: re.Match) -> str:
            condition = match.group(1).strip()
            content = match.group(2)

            negate = condition.startswith("not ")
            if negate:
                condition = condition[4:].strip()

            value = self._resolve_var(condition, vars)
            truthy = bool(value)

            if (negate and not truthy) or (not negate and truthy):
                return content
            return ""

        return re.sub(pattern, _replace_if, template, flags=re.DOTALL)

    def _render_for_loops(self, template: str, vars: Dict[str, Any]) -> str:
        """Process {% for item in list %}...{% endfor %} loops.

        Args:
            template: Template string with for loops
            vars: Variables dictionary

        Returns:
            Template with loops rendered
        """
        pattern = r'\{%\s+for\s+(\w+)\s+in\s+(\w+)\s*%\}(.*?)\{%\s+endfor\s*%\}'

        def _replace_for(match: re.Match) -> str:
            item_var = match.group(1)
            list_var = match.group(2)
            content = match.group(3)

            items = self._resolve_var(list_var, vars)
            if not isinstance(items, list):
                return ""

            rendered_parts: List[str] = []
            for item in items:
                loop_vars = dict(vars)
                loop_vars[item_var] = item
                rendered = self._render_template(content, loop_vars)
                rendered_parts.append(rendered)

            return "".join(rendered_parts)

        return re.sub(pattern, _replace_for, template, flags=re.DOTALL)

    def list_templates(self) -> List[str]:
        """List all available template names.

        Returns:
            Sorted list of template names
        """
        names = list(self.BUILTIN_TEMPLATES.keys())
        names.extend(self.custom_templates.keys())
        return sorted(set(names))


class BatchProcessor:
    """Processes multiple finding files in batch mode.

    Reads multiple JSON finding files, validates each, and generates
    combined reports. Supports directory scanning for finding files,
    filtering by severity, and parallel processing.

    Attributes:
        input_files: List of finding file paths
        findings: All loaded Finding objects
        errors: List of processing errors
    """

    def __init__(self, input_paths: Optional[List[str]] = None):
        """Initialize the batch processor.

        Args:
            input_paths: Optional list of input file paths
        """
        self.input_paths: List[str] = input_paths or []
        self.findings: List[Finding] = []
        self.errors: List[str] = []

    def add_input(self, path: str) -> None:
        """Add an input file or directory for processing.

        Args:
            path: File path or directory path
        """
        self.input_paths.append(path)

    def load_all(self) -> int:
        """Load findings from all input paths.

        Scans directories for *.json files and loads findings from
        each file. Validates loaded findings.

        Returns:
            Total number of findings loaded
        """
        self.findings = []
        self.errors = []

        resolved_paths: List[str] = []
        for path in self.input_paths:
            if os.path.isdir(path):
                for root, _dirs, files in os.walk(path):
                    for fname in files:
                        if fname.endswith(".json"):
                            resolved_paths.append(os.path.join(root, fname))
            elif os.path.isfile(path):
                resolved_paths.append(path)
            else:
                self.errors.append(f"Path not found: {path}")

        for filepath in resolved_paths:
            try:
                count = self._load_file(filepath)
                logger.info("Loaded %d findings from %s", count, filepath)
            except Exception as e:
                self.errors.append(f"Error loading {filepath}: {e}")

        logger.info("Total loaded: %d findings from %d files", len(self.findings), len(resolved_paths))
        return len(self.findings)

    def _load_file(self, filepath: str) -> int:
        """Load findings from a single JSON file.

        Supports both single findings and arrays of findings.

        Args:
            filepath: Path to JSON file

        Returns:
            Number of findings loaded from this file
        """
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, list):
            findings_data = data
        elif isinstance(data, dict):
            findings_data = data.get("findings", data.get("results", [data]))
        else:
            self.errors.append(f"Unexpected JSON structure in {filepath}")
            return 0

        count = 0
        for item in findings_data:
            if isinstance(item, dict):
                finding = Finding(**{
                    k: v for k, v in item.items()
                    if k in Finding.__dataclass_fields__
                })
                validation_errors = finding.validate()
                if not validation_errors:
                    self.findings.append(finding)
                    count += 1
                else:
                    self.errors.append(
                        f"Invalid finding in {filepath}: missing {', '.join(validation_errors)}"
                    )
        return count

    def filter_by_severity(self, min_severity: str) -> None:
        """Filter findings by minimum severity level.

        Args:
            min_severity: Minimum severity (critical, high, medium, low, info)
        """
        severity_order = {
            "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "none": -1,
        }
        min_level = severity_order.get(min_severity.lower(), 0)
        self.findings = [
            f for f in self.findings
            if severity_order.get(f.severity.lower(), 0) >= min_level
        ]

    def sort_by_severity(self) -> None:
        """Sort findings by severity (highest first)."""
        severity_order = {
            "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "none": -1,
        }
        self.findings.sort(
            key=lambda f: severity_order.get(f.severity.lower(), 0),
            reverse=True,
        )

    def get_summary(self) -> Dict[str, Any]:
        """Return summary of batch processing results.

        Returns:
            Dictionary with counts, severity distribution, and errors
        """
        sev_counts: Dict[str, int] = {}
        for f in self.findings:
            s = f.severity.lower()
            sev_counts[s] = sev_counts.get(s, 0) + 1

        return {
            "total_findings": len(self.findings),
            "total_files": len(self.input_paths),
            "severity_distribution": dict(sorted(sev_counts.items())),
            "errors_count": len(self.errors),
            "errors": self.errors[:10],
        }


class ReportBuilder:
    """Main report builder orchestrator for security finding reports.

    Coordinates CVSS scoring, template rendering, and report generation
    across multiple platforms and formats. Supports single and batch
    report generation with metadata and branding.

    Attributes:
        platform: Target platform name (hackerone, bugcrowd, intigriti, generic)
        findings: List of Finding objects
        metadata: Dict of report metadata (author, date, etc.)
        template_engine: TemplateEngine instance for rendering
        calculator: Cvss31Calculator instance
    """

    PLATFORM_TEMPLATES: Dict[str, str] = {
        "hackerone": "hackerone",
        "h1": "hackerone",
        "bugcrowd": "bugcrowd",
        "bc": "bugcrowd",
        "intigriti": "intigriti",
        "generic": "generic",
        "markdown": "generic",
    }

    def __init__(self, platform: str = "generic", title: str = "Security Finding Report"):
        """Initialize the report builder.

        Args:
            platform: Target platform (hackerone, bugcrowd, intigriti, generic)
            title: Report title
        """
        self.platform = platform.lower()
        self.title = title
        self.findings: List[Finding] = []
        self.metadata: Dict[str, str] = {
            "author": "",
            "date": datetime.datetime.now().strftime("%Y-%m-%d"),
            "version": "1.0",
        }
        self.template_engine = TemplateEngine()
        self.calculator = Cvss31Calculator()

    def set_metadata(self, key: str, value: str) -> None:
        """Set a metadata field for the report.

        Args:
            key: Metadata key
            value: Metadata value
        """
        self.metadata[key] = value

    def set_author(self, author: str) -> None:
        """Set the report author name.

        Args:
            author: Author name or handle
        """
        self.metadata["author"] = author

    def add_finding(self, finding: Finding) -> None:
        """Add a single finding to the report.

        Args:
            finding: Finding object
        """
        self.findings.append(finding)

    def add_finding_from_dict(self, data: Dict[str, Any]) -> None:
        """Add a finding from a dictionary.

        Args:
            data: Dictionary with finding fields
        """
        finding = Finding(**{
            k: v for k, v in data.items()
            if k in Finding.__dataclass_fields__
        })
        self.findings.append(finding)

    def add_findings(self, findings: List[Finding]) -> None:
        """Add multiple findings to the report.

        Args:
            findings: List of Finding objects
        """
        self.findings.extend(findings)

    def remove_finding(self, index: int) -> None:
        """Remove a finding by index.

        Args:
            index: Zero-based index of the finding

        Raises:
            IndexError: If index is out of range
        """
        if 0 <= index < len(self.findings):
            self.findings.pop(index)
        else:
            raise IndexError(f"Finding index {index} out of range (0-{len(self.findings) - 1})")

    def generate_report(
        self,
        format: str = "markdown",
        template: str = "",
        extra_vars: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Generate a report in the specified format.

        Args:
            format: Output format (markdown, json)
            template: Optional custom template name
            extra_vars: Additional template variables

        Returns:
            Report as a string
        """
        if format == "json":
            return self._generate_json()

        if template:
            template_name = template
        else:
            template_name = self.PLATFORM_TEMPLATES.get(self.platform, "generic")

        if len(self.findings) == 1:
            return self.template_engine.render(
                template_name, self.findings[0], extra_vars
            )

        return self._generate_multi_finding_report(template_name, extra_vars)

    def _generate_multi_finding_report(
        self,
        template_name: str,
        extra_vars: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Generate a report with multiple findings.

        Creates a document with a summary table followed by individual
        finding sections rendered with the specified template.

        Args:
            template_name: Template name for individual findings
            extra_vars: Additional template variables

        Returns:
            Rendered multi-finding report
        """
        sections: List[str] = []

        sections.append(f"# {self.title}")
        sections.append("")
        sections.append(f"**Platform:** {self.platform.title()}")
        sections.append(f"**Date:** {self.metadata.get('date', '')}")
        if self.metadata.get("author"):
            sections.append(f"**Author:** {self.metadata['author']}")
        sections.append(f"**Total Findings:** {len(self.findings)}")
        sections.append("")

        sev_counts: Dict[str, int] = collections.Counter(
            f.severity.lower() for f in self.findings
        )
        sections.append("## Summary")
        sections.append("")
        sections.append("| Severity | Count |")
        sections.append("|----------|-------|")
        for sev in ["critical", "high", "medium", "low", "info", "none"]:
            c = sev_counts.get(sev, 0)
            if c > 0:
                sections.append(f"| {sev.title()} | {c} |")
        sections.append("")
        sections.append("---")
        sections.append("")

        sections.append("## Findings")
        sections.append("")

        for i, finding in enumerate(self.findings, 1):
            rendered = self.template_engine.render(
                template_name, finding, extra_vars
            )
            sections.append(f"### Finding {i}: {finding.title}")
            sections.append("")
            sections.append(rendered)
            sections.append("")
            sections.append("---")
            sections.append("")

        return "\n".join(sections)

    def _generate_json(self) -> str:
        """Generate the report as JSON.

        Returns:
            JSON string with all findings and metadata
        """
        data = {
            "report_metadata": {
                "title": self.title,
                "platform": self.platform,
                **self.metadata,
                "generated_at": datetime.datetime.now().isoformat(),
            },
            "findings": [asdict(f) for f in self.findings],
            "statistics": self.get_statistics(),
        }
        return json.dumps(data, indent=2, default=str)

    def get_statistics(self) -> Dict[str, Any]:
        """Generate statistics about the findings.

        Returns:
            Dictionary with severity distribution, CWE counts, etc.
        """
        sev_counts: Dict[str, int] = collections.Counter(
            f.severity.lower() for f in self.findings
        )
        cwe_counts: Dict[str, int] = collections.Counter(
            f.cwe_id for f in self.findings if f.cwe_id
        )
        tag_counts: Dict[str, int] = collections.Counter(
            tag for f in self.findings for tag in f.tags
        )
        cvss_count = sum(1 for f in self.findings if f.cvss_vector)

        return {
            "total_findings": len(self.findings),
            "severity_distribution": dict(sorted(sev_counts.items())),
            "cwe_distribution": dict(cwe_counts.most_common(10)),
            "tag_distribution": dict(tag_counts.most_common(10)),
            "findings_with_cvss": cvss_count,
        }

    def save_report(
        self,
        filepath: str,
        format: str = "",
        template: str = "",
        extra_vars: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Generate and save a report to a file.

        Args:
            filepath: Output file path
            format: Output format (auto-detected from extension if empty)
            template: Optional custom template name
            extra_vars: Additional template variables

        Returns:
            Generated report content

        Raises:
            OSError: If the file cannot be written
        """
        if not format:
            if filepath.endswith(".json"):
                format = "json"
            else:
                format = "markdown"

        content = self.generate_report(format=format, template=template, extra_vars=extra_vars)

        try:
            os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
        except OSError:
            pass

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            logger.info("Report saved to %s", filepath)
        except OSError as e:
            logger.error("Failed to save report: %s", e)
            raise

        return content

    def load_findings_from_json(self, filepath: str) -> int:
        """Load findings from a JSON file.

        Args:
            filepath: Path to JSON file

        Returns:
            Number of findings loaded
        """
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError, OSError) as e:
            logger.error("Failed to load findings from %s: %s", filepath, e)
            return 0

        if isinstance(data, list):
            findings_data = data
        elif isinstance(data, dict):
            findings_data = data.get("findings", [data])
        else:
            logger.warning("Unexpected JSON structure in %s", filepath)
            return 0

        count = 0
        for item in findings_data:
            if isinstance(item, dict):
                self.add_finding_from_dict(item)
                count += 1

        logger.info("Loaded %d findings from %s", count, filepath)
        return count


def setup_argparse() -> argparse.ArgumentParser:
    """Configure and return the argument parser for CLI usage.

    Returns:
        Configured ArgumentParser with all command-line options
    """
    parser = argparse.ArgumentParser(
        prog="report_builder.py",
        description="Finding Report Builder — Generate professional security finding "
                    "reports with CVSS 3.1 scoring and platform-specific templates.",
        epilog=textwrap.dedent("""
            Examples:
              %(prog)s --input findings.json
              %(prog)s --input findings.json --format hackerone --output report.md
              %(prog)s --input findings.json --format bugcrowd --severity high
              %(prog)s --input findings.json --template custom_template --author researcher
              %(prog)s --batch findings_dir/ --format json --output combined.json
              %(prog)s --input finding.json --format markdown --json
        """),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )
    parser.add_argument(
        "--input", "-i",
        type=str,
        required=True,
        help="Input JSON file containing finding(s)",
    )
    parser.add_argument(
        "--format", "-f",
        type=str,
        default="markdown",
        choices=["markdown", "json", "hackerone", "h1", "bugcrowd", "bc", "intigriti", "generic"],
        help="Output format (default: markdown)",
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Output file path (default: stdout)",
    )
    parser.add_argument(
        "--severity", "-s",
        type=str,
        default=None,
        choices=["critical", "high", "medium", "low", "info"],
        help="Minimum severity filter for batch processing",
    )
    parser.add_argument(
        "--template", "-t",
        type=str,
        default=None,
        help="Custom template name or file path",
    )
    parser.add_argument(
        "--batch", "-b",
        type=str,
        default=None,
        help="Directory or file pattern for batch processing (overrides --input)",
    )
    parser.add_argument(
        "--author", "-a",
        type=str,
        default=None,
        help="Report author name/handle",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format (overrides --format)",
    )
    parser.add_argument(
        "--title",
        type=str,
        default="Security Finding Report",
        help="Report title (default: Security Finding Report)",
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
    """Main entry point for the report builder CLI.

    Parses arguments, configures logging, loads findings, generates
    the report, and writes output to the specified location.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    report_builder = ReportBuilder(
        platform=args.format,
        title=args.title,
    )

    if args.author:
        report_builder.set_author(args.author)

    try:
        if args.batch:
            processor = BatchProcessor()
            processor.add_input(args.batch)
            total = processor.load_all()

            if args.severity:
                processor.filter_by_severity(args.severity)
                logger.info("Filtered to %d findings with severity >= %s",
                           len(processor.findings), args.severity)

            if processor.errors:
                logger.warning("Batch processing had %d errors", len(processor.errors))
                for err in processor.errors[:5]:
                    logger.warning("  Error: %s", err)

            report_builder.add_findings(processor.findings)

            if total == 0:
                print("[!] No valid findings loaded from batch input", file=sys.stderr)
                sys.exit(1)

            summary = processor.get_summary()
            print(f"\nBatch Processing Summary:")
            print(f"  Total files: {summary['total_files']}")
            print(f"  Valid findings: {summary['total_findings']}")
            print(f"  Errors: {summary['errors_count']}")
            print(f"  Severity distribution: {summary['severity_distribution']}")

        else:
            count = report_builder.load_findings_from_json(args.input)
            if count == 0:
                print(f"[!] No findings loaded from {args.input}", file=sys.stderr)
                sys.exit(1)
            print(f"Loaded {count} finding(s) from {args.input}")

        if args.json:
            output_format = "json"
        else:
            output_format = args.format

        extra_vars: Dict[str, Any] = {}
        if args.template:
            extra_vars["_template"] = args.template

        if args.output:
            report_builder.save_report(
                args.output,
                format=output_format,
                template=args.template or "",
                extra_vars=extra_vars,
            )
            print(f"Report saved to {args.output}")

        else:
            content = report_builder.generate_report(
                format=output_format,
                template=args.template or "",
                extra_vars=extra_vars,
            )
            print("\n" + "=" * 60)
            print("REPORT OUTPUT")
            print("=" * 60)
            print(content)

        stats = report_builder.get_statistics()
        print(f"\nStatistics:")
        print(f"  Total findings: {stats['total_findings']}")
        print(f"  Severity: {stats['severity_distribution']}")
        if stats["findings_with_cvss"] > 0:
            print(f"  Findings with CVSS: {stats['findings_with_cvss']}")

    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error("Report generation failed: %s", e)
        print(f"\n[!] Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        logger.info("Report generation completed")


if __name__ == "__main__":
    main()
