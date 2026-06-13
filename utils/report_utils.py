#!/usr/bin/env python3
"""CVSS scoring, severity calculation, and finding report formatting utilities.

Provides functions for parsing CVSS 3.1 vectors, calculating base scores,
converting severity levels, formatting findings for bug bounty platforms
(HackerOne, Bugcrowd), and organizing vulnerability data for reporting.

Typical usage:
    >>> from utils.report_utils import (
    ...     calculate_cvss_score, cvss_severity,
    ...     findings_to_markdown, format_finding_title
    ... )
    >>> score = calculate_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    >>> print(cvss_severity(score))
    Critical
"""

import json
import math
import re
from typing import Any, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field, asdict


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """Represents a single security vulnerability finding.

    Attributes:
        vuln_type: Vulnerability class (e.g. "IDOR", "XSS", "SSRF").
        endpoint: Affected URL or endpoint path.
        severity: Severity rating ("None", "Low", "Medium", "High", "Critical").
        title: Human-readable finding title.
        description: Detailed description of the vulnerability.
        impact: Business/security impact statement.
        remediation: Recommendation for fixing the vulnerability.
        cvss_vector: CVSS 3.1 vector string.
        cvss_score: Computed CVSS base score.
        poc: Proof-of-concept description or steps.
        references: List of reference URLs.
    """
    vuln_type: str = ""
    endpoint: str = ""
    severity: str = "Medium"
    title: str = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""
    cvss_vector: str = ""
    cvss_score: float = 0.0
    poc: str = ""
    references: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# CVSS 3.1 vector parsing and scoring
# ---------------------------------------------------------------------------

_CVSS_METRICS: Dict[str, Tuple[str, List[str], List[float]]] = {
    "AV": ("Attack Vector", ["N", "A", "L", "P"], [0.85, 0.62, 0.55, 0.20]),
    "AC": ("Attack Complexity", ["L", "H"], [0.77, 0.44]),
    "PR": (
        "Privileges Required",
        ["N", "L", "H"],
        [0.85, 0.62, 0.27],
    ),
    "UI": ("User Interaction", ["N", "R"], [0.85, 0.62]),
    "S": ("Scope", ["U", "C"], [6.42, 7.52]),
    "C": ("Confidentiality", ["H", "L", "N"], [0.56, 0.22, 0.0]),
    "I": ("Integrity", ["H", "L", "N"], [0.56, 0.22, 0.0]),
    "A": ("Availability", ["H", "L", "N"], [0.56, 0.22, 0.0]),
}

_VALID_SEVERITIES = frozenset({"None", "Low", "Medium", "High", "Critical"})
_SEVERITY_ORDER = {"None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def parse_cvss_vector(vector: str) -> Dict[str, str]:
    """Parse a CVSS 3.1 vector string into its component metrics.

    Accepts vectors with or without the "CVSS:3.1/" prefix.

    Args:
        vector: CVSS 3.1 vector string, e.g.
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    Returns:
        Dictionary mapping metric abbreviations to their values,
        e.g. {"AV": "N", "AC": "L", "PR": "N", ...}.

    Raises:
        TypeError: If vector is not a string.
        ValueError: If the vector is malformed or contains unknown metrics.

    Examples:
        >>> parsed = parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        >>> parsed["AV"]
        'N'
    """
    if not isinstance(vector, str):
        raise TypeError(f"Expected string, got {type(vector).__name__}")

    vector = vector.strip()
    if not vector:
        raise ValueError("CVSS vector string is empty")

    parts = vector.split("/")
    result: Dict[str, str] = {}

    start_idx = 0
    if parts[0].startswith("CVSS:"):
        result["_version"] = parts[0]
        start_idx = 1

    for part in parts[start_idx:]:
        part = part.strip()
        if not part:
            continue

        if ":" not in part:
            raise ValueError(
                f"Malformed CVSS metric component: {part!r}. "
                "Expected format 'METRIC:VALUE'"
            )

        metric, value = part.split(":", 1)

        if metric not in _CVSS_METRICS:
            raise ValueError(
                f"Unknown CVSS metric: {metric!r}. "
                f"Valid metrics: {', '.join(sorted(_CVSS_METRICS.keys()))}"
            )

        valid_values = [v.upper() for v in _CVSS_METRICS[metric][1]]
        if value.upper() not in valid_values:
            raise ValueError(
                f"Invalid value {value!r} for metric {metric}. "
                f"Valid values: {', '.join(_CVSS_METRICS[metric][1])}"
            )

        result[metric] = value.upper()

    required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    missing = [m for m in required if m not in result]
    if missing:
        raise ValueError(
            f"CVSS vector is missing required metrics: {', '.join(missing)}"
        )

    return result


def _roundup(value: float) -> float:
    """Round up to 1 decimal place per CVSS 3.1 spec.

    The CVSS specification uses a specific rounding approach that rounds up
    for the first decimal place rather than standard rounding.

    Args:
        value: Float to round.

    Returns:
        Rounded value to 1 decimal place (ceiling-based).
    """
    int_part = int(math.floor(value))
    fraction = value - int_part
    if fraction == 0.0:
        return float(int_part)
    return int_part + 1.0


def calculate_cvss_score(vector: str) -> float:
    """Calculate the CVSS 3.1 base score from a vector string.

    Implements the CVSS 3.1 base score formula per the specification:
        - Impact Sub-Score (ISS) = 1 - (1 - C) * (1 - I) * (1 - A)
        - Impact = 6.42 * ISS if Scope is Unchanged
        - Impact = 7.52 * (ISS - 0.029) - 3.25 * (ISS - 0.02)^15 if Scope Changed
        - Exploitability = 8.22 * AV * AC * PR * UI
        - Base = Impact + Exploitability if Impact <= 0
        - Base = min(Impact + Exploitability, 10) if Scope Unchanged
        - Base = min(1.08 * (Impact + Exploitability), 10) if Scope Changed

    Args:
        vector: CVSS 3.1 vector string.

    Returns:
        Base score as a float rounded to 1 decimal place.

    Raises:
        TypeError: If vector is not a string.
        ValueError: If vector is malformed or contains invalid metrics.

    Examples:
        >>> calculate_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        9.8
        >>> calculate_cvss_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L")
        4.5
    """
    metrics = parse_cvss_vector(vector)

    _metric_lookup: Dict[str, Dict[str, float]] = {}
    for key, (_, values, scores) in _CVSS_METRICS.items():
        _metric_lookup[key] = {v.upper(): s for v, s in zip(values, scores)}

    av = _metric_lookup["AV"][metrics["AV"]]
    ac = _metric_lookup["AC"][metrics["AC"]]
    pr_uns = _metric_lookup["PR"][metrics["PR"]]
    ui = _metric_lookup["UI"][metrics["UI"]]
    scope_changed = metrics["S"] == "C"
    c = _metric_lookup["C"][metrics["C"]]
    i = _metric_lookup["I"][metrics["I"]]
    a = _metric_lookup["A"][metrics["A"]]

    if scope_changed:
        pr_values = {"N": 0.85, "L": 0.68, "H": 0.50}
        pr = pr_values[metrics["PR"]]
    else:
        pr = pr_uns

    exploitability = 8.22 * av * ac * pr * ui

    iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    if impact <= 0.0:
        return 0.0

    if scope_changed:
        base_score = min(1.08 * (impact + exploitability), 10.0)
    else:
        base_score = min(impact + exploitability, 10.0)

    rounded = _roundup(base_score * 10.0) / 10.0
    return min(rounded, 10.0)


def cvss_severity(score: Optional[Union[float, int]]) -> str:
    """Convert a CVSS score to a severity rating string.

    Mapping per CVSS 3.1:
        - 0.0       -> "None"
        - 0.1 - 3.9 -> "Low"
        - 4.0 - 6.9 -> "Medium"
        - 7.0 - 8.9 -> "High"
        - 9.0 - 10.0 -> "Critical"

    Args:
        score: CVSS base score (0.0 - 10.0) or None.

    Returns:
        Severity rating as a string.

    Raises:
        TypeError: If score is not a number or None.
        ValueError: If score is outside the valid 0.0-10.0 range.

    Examples:
        >>> cvss_severity(9.8)
        'Critical'
        >>> cvss_severity(4.5)
        'Medium'
        >>> cvss_severity(None)
        'None'
    """
    if score is None:
        return "None"

    if not isinstance(score, (int, float)):
        raise TypeError(f"Expected numeric or None, got {type(score).__name__}")

    if score < 0.0 or score > 10.0:
        raise ValueError(
            f"CVSS score must be between 0.0 and 10.0, got {score}"
        )

    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


# ---------------------------------------------------------------------------
# Finding formatting
# ---------------------------------------------------------------------------

def format_finding_title(
    vuln_type: str, endpoint: str, severity: str
) -> str:
    """Generate a standardized bug bounty finding title.

    Format: "[{severity}] {vuln_type} at {endpoint}"

    Args:
        vuln_type: Vulnerability type (e.g. "IDOR", "XSS", "SSRF").
        endpoint: The affected URL or endpoint.
        severity: Severity level ("None", "Low", "Medium", "High", "Critical").

    Returns:
        Formatted finding title string.

    Raises:
        TypeError: If any argument is not a string.
        ValueError: If severity is invalid.

    Examples:
        >>> format_finding_title("IDOR", "/api/users/123", "High")
        '[High] IDOR at /api/users/123'
    """
    if not isinstance(vuln_type, str):
        raise TypeError(f"vuln_type must be str, got {type(vuln_type).__name__}")
    if not isinstance(endpoint, str):
        raise TypeError(f"endpoint must be str, got {type(endpoint).__name__}")
    if not isinstance(severity, str):
        raise TypeError(f"severity must be str, got {type(severity).__name__}")

    validate_finding_severity(severity)

    cleaned_endpoint = endpoint.strip().rstrip("/")
    return f"[{severity}] {vuln_type.strip()} at {cleaned_endpoint}"


def format_finding_summary(finding: Finding) -> str:
    """Format a Finding dataclass as a concise markdown summary.

    Args:
        finding: Finding dataclass to format.

    Returns:
        Markdown-formatted finding summary string.

    Raises:
        TypeError: If finding is not a Finding instance.

    Examples:
        >>> f = Finding(vuln_type="IDOR", endpoint="/api/users",
        ...             severity="High", title="IDOR at /api/users")
        >>> print(format_finding_summary(f))
        ### [High] IDOR at /api/users
        ...
    """
    if not isinstance(finding, Finding):
        raise TypeError(f"Expected Finding, got {type(finding).__name__}")

    lines: List[str] = []
    title = finding.title or format_finding_title(
        finding.vuln_type, finding.endpoint, finding.severity
    )
    lines.append(f"### {title}")
    lines.append("")

    score_str = f" ({finding.cvss_score})" if finding.cvss_score else ""
    lines.append(f"- **Severity:** {finding.severity}{score_str}")
    lines.append(f"- **Type:** {finding.vuln_type}")
    lines.append(f"- **Endpoint:** `{finding.endpoint}`")

    if finding.cvss_vector:
        lines.append(f"- **CVSS Vector:** `{finding.cvss_vector}`")

    if finding.description:
        lines.append("")
        lines.append("**Description:**")
        lines.append(finding.description)

    if finding.impact:
        lines.append("")
        lines.append("**Impact:**")
        lines.append(finding.impact)

    if finding.poc:
        lines.append("")
        lines.append("**Proof of Concept:**")
        lines.append(finding.poc)

    if finding.remediation:
        lines.append("")
        lines.append("**Remediation:**")
        lines.append(finding.remediation)

    if finding.references:
        lines.append("")
        lines.append("**References:**")
        for ref in finding.references:
            lines.append(f"- {ref}")

    lines.append("")
    lines.append("---")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Severity colors and emoji
# ---------------------------------------------------------------------------

_SEVERITY_ANSI_COLORS = {
    "Critical": "\033[91m",
    "High": "\033[91m",
    "Medium": "\033[93m",
    "Low": "\033[94m",
    "None": "\033[90m",
}
_ANSI_RESET = "\033[0m"

_SEVERITY_EMOJI_MAP = {
    "Critical": "CRITICAL",
    "High": "HIGH",
    "Medium": "MEDIUM",
    "Low": "LOW",
    "None": "NONE",
}


def severity_color(severity: str) -> str:
    """Return the ANSI escape code color for a severity level.

    Colors:
        - Critical/High: Red
        - Medium: Yellow
        - Low: Blue
        - None: Gray

    Args:
        severity: Severity string.

    Returns:
        ANSI escape code string for coloring terminal output.

    Raises:
        TypeError: If severity is not a string.
        ValueError: If severity is not a valid severity level.

    Examples:
        >>> severity_color("Critical")
        '\\033[91m'
    """
    if not isinstance(severity, str):
        raise TypeError(f"Expected string, got {type(severity).__name__}")

    validate_finding_severity(severity)

    return _SEVERITY_ANSI_COLORS.get(severity, _ANSI_RESET)


def severity_emoji(severity: str) -> str:
    """Return a text label representing the severity for use in text reports.

    Returns uppercase severity label for use in text-based contexts.

    Args:
        severity: Severity string.

    Returns:
        Uppercase severity label string.

    Raises:
        TypeError: If severity is not a string.
        ValueError: If severity is not a valid severity level.

    Examples:
        >>> severity_emoji("Critical")
        'CRITICAL'
    """
    if not isinstance(severity, str):
        raise TypeError(f"Expected string, got {type(severity).__name__}")

    validate_finding_severity(severity)

    return _SEVERITY_EMOJI_MAP.get(severity, severity.upper())


# ---------------------------------------------------------------------------
# Finding sorting and grouping
# ---------------------------------------------------------------------------

def sort_findings_by_severity(findings: List[Finding]) -> List[Finding]:
    """Sort a list of findings by severity (Critical first).

    Sorting order: Critical > High > Medium > Low > None.

    Args:
        findings: List of Finding objects to sort.

    Returns:
        New list sorted by severity descending.

    Raises:
        TypeError: If findings is not a list or contains non-Finding items.

    Examples:
        >>> low = Finding(vuln_type="XSS", severity="Low")
        >>> high = Finding(vuln_type="IDOR", severity="High")
        >>> sorted_list = sort_findings_by_severity([low, high])
        >>> sorted_list[0].severity
        'High'
    """
    if not isinstance(findings, list):
        raise TypeError(
            f"Expected list of Findings, got {type(findings).__name__}"
        )

    filtered: List[Finding] = []
    for i, f in enumerate(findings):
        if not isinstance(f, Finding):
            raise TypeError(
                f"Item at index {i} is not a Finding: {type(f).__name__}"
            )
        filtered.append(f)

    return sorted(
        filtered,
        key=lambda f: (_SEVERITY_ORDER.get(f.severity, -1), f.vuln_type),
        reverse=True,
    )


def group_findings_by_type(findings: List[Finding]) -> Dict[str, List[Finding]]:
    """Group a list of findings by their vulnerability type.

    Args:
        findings: List of Finding objects to group.

    Returns:
        Dictionary mapping vuln_type to list of Findings of that type.

    Raises:
        TypeError: If findings is not a list or contains non-Finding items.

    Examples:
        >>> f1 = Finding(vuln_type="IDOR", severity="High")
        >>> f2 = Finding(vuln_type="XSS", severity="Medium")
        >>> f3 = Finding(vuln_type="IDOR", severity="Critical")
        >>> grouped = group_findings_by_type([f1, f2, f3])
        >>> list(grouped.keys())
        ['IDOR', 'XSS']
    """
    if not isinstance(findings, list):
        raise TypeError(
            f"Expected list of Findings, got {type(findings).__name__}"
        )

    groups: Dict[str, List[Finding]] = {}
    for i, f in enumerate(findings):
        if not isinstance(f, Finding):
            raise TypeError(
                f"Item at index {i} is not a Finding: {type(f).__name__}"
            )
        f_type = f.vuln_type if f.vuln_type else "Unknown"
        if f_type not in groups:
            groups[f_type] = []
        groups[f_type].append(f)

    return dict(sorted(groups.items()))


# ---------------------------------------------------------------------------
# Report generation (markdown, JSON, platform formats)
# ---------------------------------------------------------------------------

def findings_to_markdown(findings: List[Finding]) -> str:
    """Convert a list of findings to a full markdown vulnerability report.

    Generates a markdown document with a severity summary table and
    detailed sections for each finding, grouped by type and sorted
    by severity.

    Args:
        findings: List of Finding objects.

    Returns:
        Full markdown report string.

    Raises:
        TypeError: If findings is not a list or contains non-Finding items.
    """
    if not isinstance(findings, list):
        raise TypeError(
            f"Expected list of Findings, got {type(findings).__name__}"
        )

    if not findings:
        return "# Vulnerability Report\n\nNo findings to report.\n"

    validated: List[Finding] = []
    for i, f in enumerate(findings):
        if not isinstance(f, Finding):
            raise TypeError(
                f"Item at index {i} is not a Finding: {type(f).__name__}"
            )
        validated.append(f)

    sorted_findings = sort_findings_by_severity(validated)
    grouped = group_findings_by_type(sorted_findings)

    lines: List[str] = []
    lines.append("# Vulnerability Report")
    lines.append("")
    lines.append(f"**Total Findings:** {len(sorted_findings)}")
    lines.append("")

    severity_counts: Dict[str, int] = {s: 0 for s in _VALID_SEVERITIES}
    for f in sorted_findings:
        sev = f.severity if f.severity in _VALID_SEVERITIES else "None"
        severity_counts[sev] += 1

    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ("Critical", "High", "Medium", "Low", "None"):
        count = severity_counts[sev]
        if count > 0:
            lines.append(f"| {sev} | {count} |")

    lines.append("")
    lines.append("---")
    lines.append("")

    for vuln_type, type_findings in grouped.items():
        for f in type_findings:
            lines.append(format_finding_summary(f))
            lines.append("")

    return "\n".join(lines)


def findings_to_json(
    findings: List[Finding], indent: int = 2
) -> str:
    """Serialize a list of findings to a JSON string.

    Args:
        findings: List of Finding objects.
        indent: JSON indentation level (default 2).

    Returns:
        Pretty-printed JSON string.

    Raises:
        TypeError: If findings is not a list or contains non-Finding items.
        ValueError: If indent is negative.
    """
    if not isinstance(findings, list):
        raise TypeError(
            f"Expected list of Findings, got {type(findings).__name__}"
        )

    if not isinstance(indent, int):
        raise TypeError(f"indent must be int, got {type(indent).__name__}")

    if indent < 0:
        raise ValueError(f"indent must be non-negative, got {indent}")

    validated: List[Finding] = []
    for i, f in enumerate(findings):
        if not isinstance(f, Finding):
            raise TypeError(
                f"Item at index {i} is not a Finding: {type(f).__name__}"
            )
        validated.append(f)

    data: List[Dict[str, Any]] = []
    for f in validated:
        d = asdict(f)
        d["cvss_score"] = round(d["cvss_score"], 1)
        data.append(d)

    return json.dumps(data, indent=indent, ensure_ascii=False, default=str)


def _build_platform_finding(
    finding: Finding,
    platform: str,
) -> Dict[str, str]:
    """Build a platform-specific finding dictionary.

    Args:
        finding: Finding object.
        platform: Target platform name.

    Returns:
        Dictionary of platform-specific fields.

    Raises:
        TypeError: If finding is not a Finding.
        ValueError: If platform is unknown.
    """
    if not isinstance(finding, Finding):
        raise TypeError(f"Expected Finding, got {type(finding).__name__}")

    title = finding.title or format_finding_title(
        finding.vuln_type, finding.endpoint, finding.severity
    )

    body_parts: List[str] = []

    if finding.description:
        body_parts.append("## Description")
        body_parts.append(finding.description)
        body_parts.append("")

    if finding.impact:
        body_parts.append("## Impact")
        body_parts.append(finding.impact)
        body_parts.append("")

    if finding.cvss_vector:
        body_parts.append(f"**CVSS Vector:** `{finding.cvss_vector}`")
        if finding.cvss_score:
            body_parts.append(
                f"**CVSS Score:** {finding.cvss_score} "
                f"({cvss_severity(finding.cvss_score)})"
            )
        body_parts.append("")

    if finding.poc:
        body_parts.append("## Proof of Concept")
        body_parts.append(finding.poc)
        body_parts.append("")

    if finding.remediation:
        body_parts.append("## Remediation")
        body_parts.append(finding.remediation)
        body_parts.append("")

    if finding.references:
        body_parts.append("## References")
        for ref in finding.references:
            body_parts.append(f"- {ref}")

    body = "\n".join(body_parts).strip()

    severity_value = finding.severity
    if severity_value not in _VALID_SEVERITIES:
        severity_value = "Medium"

    return {
        "title": title,
        "body": body,
        "severity": severity_value,
        "vulnerability_type": finding.vuln_type,
        "endpoint": finding.endpoint,
    }


def finding_to_hackerone_format(finding: Finding) -> str:
    """Format a finding for HackerOne submission.

    Generates a structured report suitable for the HackerOne platform
    with markdown body sections.

    Args:
        finding: Finding object.

    Returns:
        Formatted HackerOne report string containing title line,
        severity tag, and body.

    Raises:
        TypeError: If finding is not a Finding.

    Examples:
        >>> f = Finding(vuln_type="IDOR", endpoint="/api/users/123",
        ...             severity="High", description="Direct object reference")
        >>> print(finding_to_hackerone_format(f))
    """
    if not isinstance(finding, Finding):
        raise TypeError(f"Expected Finding, got {type(finding).__name__}")

    data = _build_platform_finding(finding, "hackerone")

    body = data["body"] if data["body"] else "No additional details provided."

    lines: List[str] = []
    lines.append(data["title"])
    lines.append("")
    lines.append(f"**Severity:** {data['severity']}")
    lines.append("")
    lines.append(body)

    return "\n".join(lines)


def finding_to_bugcrowd_format(finding: Finding) -> str:
    """Format a finding for Bugcrowd submission.

    Generates a structured report suitable for Bugcrowd with
    severity, title, vulnerability type, and body sections.

    Args:
        finding: Finding object.

    Returns:
        Formatted Bugcrowd report string.

    Raises:
        TypeError: If finding is not a Finding.

    Examples:
        >>> f = Finding(vuln_type="XSS", endpoint="/search",
        ...             severity="Medium", description="Reflected XSS")
        >>> print(finding_to_bugcrowd_format(f))
    """
    if not isinstance(finding, Finding):
        raise TypeError(f"Expected Finding, got {type(finding).__name__}")

    data = _build_platform_finding(finding, "bugcrowd")

    lines: List[str] = []
    lines.append(f"# {data['title']}")
    lines.append("")
    lines.append(f"**Severity:** {data['severity']}")
    lines.append(f"**Type:** {data['vulnerability_type']}")
    lines.append(f"**Endpoint:** `{data['endpoint']}`")
    lines.append("")

    if data["body"]:
        lines.append(data["body"])

    lines.append("")
    lines.append("---")
    lines.append("*This report was generated automatically.*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Validation and helpers
# ---------------------------------------------------------------------------

def validate_finding_severity(severity: str) -> None:
    """Validate that a severity string is one of the recognized values.

    Valid values: "None", "Low", "Medium", "High", "Critical".

    Args:
        severity: Severity string to validate.

    Raises:
        TypeError: If severity is not a string.
        ValueError: If severity is not a valid severity level.

    Examples:
        >>> validate_finding_severity("High")
        >>> validate_finding_severity("Invalid")
        Traceback (most recent call last):
            ...
        ValueError: Invalid severity: 'Invalid'. Must be one of: None, Low, Medium, High, Critical
    """
    if not isinstance(severity, str):
        raise TypeError(f"Expected string, got {type(severity).__name__}")

    if severity not in _VALID_SEVERITIES:
        raise ValueError(
            f"Invalid severity: {severity!r}. "
            f"Must be one of: {', '.join(sorted(_VALID_SEVERITIES))}"
        )


# ---------------------------------------------------------------------------
# CVSS metric description helpers
# ---------------------------------------------------------------------------

_CVSS_ATTACK_VECTOR_DESCRIPTIONS = {
    "N": "Network: The vulnerable component is remotely exploitable "
         "from across the network stack (e.g. exploitable via HTTP/S).",
    "A": "Adjacent Network: The vulnerable component is bound to the "
         "network stack and cannot be exploited remotely, only from "
         "a logically adjacent network (same local network segment).",
    "L": "Local: The vulnerable component is not network-accessible. "
         "The attacker requires local filesystem or terminal access.",
    "P": "Physical: The attacker requires physical access to the "
         "vulnerable component (e.g. USB-based attacks).",
}

_CVSS_ATTACK_COMPLEXITY_DESCRIPTIONS = {
    "L": "Low: No special conditions exist for exploitation. "
         "Attacker can consistently succeed against the target.",
    "H": "High: Successful attack requires special conditions or "
         "race conditions that must be won. Exploitability requires "
         "careful preparation or repeated attempts.",
}


def cvss_attack_vector_description(av: str) -> str:
    """Describe a CVSS attack vector metric value.

    Args:
        av: Attack Vector value ("N", "A", "L", "P").

    Returns:
        Human-readable description of the attack vector.

    Raises:
        TypeError: If av is not a string.
        ValueError: If av is not a valid attack vector value.

    Examples:
        >>> cvss_attack_vector_description("N")
        'Network: The vulnerable component is remotely exploitable...'
    """
    if not isinstance(av, str):
        raise TypeError(f"Expected string, got {type(av).__name__}")

    av_upper = av.upper()
    if av_upper not in _CVSS_ATTACK_VECTOR_DESCRIPTIONS:
        raise ValueError(
            f"Invalid Attack Vector value: {av!r}. "
            "Must be one of: N, A, L, P"
        )

    return _CVSS_ATTACK_VECTOR_DESCRIPTIONS[av_upper]


def cvss_attack_complexity_description(ac: str) -> str:
    """Describe a CVSS attack complexity metric value.

    Args:
        ac: Attack Complexity value ("L" or "H").

    Returns:
        Human-readable description of the attack complexity.

    Raises:
        TypeError: If ac is not a string.
        ValueError: If ac is not a valid attack complexity value.

    Examples:
        >>> cvss_attack_complexity_description("L")
        'Low: No special conditions exist for exploitation...'
    """
    if not isinstance(ac, str):
        raise TypeError(f"Expected string, got {type(ac).__name__}")

    ac_upper = ac.upper()
    if ac_upper not in _CVSS_ATTACK_COMPLEXITY_DESCRIPTIONS:
        raise ValueError(
            f"Invalid Attack Complexity value: {ac!r}. "
            "Must be one of: L, H"
        )

    return _CVSS_ATTACK_COMPLEXITY_DESCRIPTIONS[ac_upper]


if __name__ == "__main__":
    test_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    score = calculate_cvss_score(test_vector)
    sev = cvss_severity(score)
    print(f"CVSS Score: {score} ({sev})")
    print(f"Severity color: {severity_color(sev)}colored{_ANSI_RESET}")
    print(f"Severity label: {severity_emoji(sev)}")
    print()

    f1 = Finding(
        vuln_type="IDOR",
        endpoint="/api/v1/users/12345",
        severity="High",
        description="Direct object reference allows accessing other users' data.",
        impact="Unauthorized access to all user personal data.",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        cvss_score=calculate_cvss_score(
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
        ),
        poc="1. Log in as user A\n2. GET /api/v1/users/12346\n3. See user B's data",
        remediation="Implement proper authorization checks on all user endpoints.",
        references=["https://example.com/idor-guidance"],
    )

    f2 = Finding(
        vuln_type="XSS",
        endpoint="/search?q=",
        severity="Medium",
        description="Reflected XSS in search query parameter.",
        impact="Session hijacking and data theft via script injection.",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        cvss_score=calculate_cvss_score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
        ),
        poc="Visit /search?q=<script>alert(1)</script>",
    )

    print(findings_to_markdown([f1, f2]))
    print()
    print("HackerOne format:")
    print(finding_to_hackerone_format(f1))
    print()
    print("Bugcrowd format:")
    print(finding_to_bugcrowd_format(f2))
    print()
    print("JSON format:")
    print(findings_to_json([f1, f2]))
    print()
    print("CVSS descriptions:")
    print(cvss_attack_vector_description("N"))
    print(cvss_attack_complexity_description("L"))
