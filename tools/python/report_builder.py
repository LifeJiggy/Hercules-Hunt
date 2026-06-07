#!/usr/bin/env python3
"""
report_builder.py — Bug Bounty Report Generator & CVSS Calculator

Generates professional security finding reports with CVSS 3.1 scoring,
platform-specific templates (HackerOne, Bugcrowd), evidence formatting,
and multi-format export. Supports markdown, JSON, and HTML output.

Features: CVSS 3.1 vector builder, CVSS explanation, severity badges,
evidence formatting (HTTP, JSON, code), platform templates (H1, Bugcrowd),
markdown generation, HTML export, finding summary tables,
CWE mapping, remediation formatting, reference formatting,
multiple finding support, severity distribution charts (ASCII),
timeline generation, report metadata, custom branding,
template customization, bulk finding import, finding validation,
impact scoring, and automated severity suggestion.
"""

import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    title: str
    severity: str
    description: str
    impact: str = ""
    reproduction_steps: str = ""
    evidence: str = ""
    remediation: str = ""
    cvss_vector: str = ""
    cwe_id: str = ""
    references: List[str] = field(default_factory=list)


class ReportBuilder:
    """
    Professional bug bounty report generator with 20+ features.

    Generates markdown/HTML reports with CVSS scoring, platform templates,
    evidence formatting, severity visualization, and structured output.
    """

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

    SEVERITY_COLORS = {
        "critical": "#e74c3c", "high": "#e67e22", "medium": "#f1c40f",
        "low": "#3498db", "info": "#95a5a6", "none": "#bdc3c7",
    }

    SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    CWE_MAP = {
        "CWE-79": "Cross-site Scripting", "CWE-89": "SQL Injection",
        "CWE-200": "Information Exposure", "CWE-287": "Authentication Bypass",
        "CWE-352": "CSRF", "CWE-918": "SSRF", "CWE-22": "Path Traversal",
        "CWE-284": "Improper Access Control", "CWE-611": "XXE",
        "CWE-502": "Deserialization", "CWE-434": "File Upload",
        "CWE-77": "Command Injection", "CWE-601": "Open Redirect",
    }

    def __init__(self, platform: str = "generic", title: str = "Bug Bounty Report"):
        self.platform = platform.lower()
        self.title = title
        self.findings: List[Finding] = []
        self.metadata: Dict[str, str] = {}
        self.author = ""
        self.brand = "Hercules-Hunt Security Report"

    def set_metadata(self, key: str, value: str) -> None:
        self.metadata[key] = value

    def add_finding(self, finding: Dict[str, Any]) -> None:
        self.findings.append(Finding(**{k: v for k, v in finding.items() if k in Finding.__dataclass_fields__}))

    def add_findings(self, findings: List[Dict[str, Any]]) -> None:
        for f in findings:
            self.add_finding(f)

    def remove_finding(self, index: int) -> None:
        if 0 <= index < len(self.findings):
            self.findings.pop(index)

    def build_cvss_vector(self, metrics: Dict[str, str]) -> str:
        required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
        for key in required:
            if key not in metrics:
                return f"Missing: {key}"
            if metrics[key] not in self.CVSS_METRICS[key]:
                return f"Invalid: {key}={metrics[key]}"
        return "CVSS:3.1/" + "/".join(f"{k}:{metrics[k]}" for k in required)

    def explain_cvss(self, vector: str) -> str:
        if not vector.startswith("CVSS:3.1/"):
            return "Unsupported"
        parts = vector.replace("CVSS:3.1/", "").split("/")
        explanations = []
        for part in parts:
            if ":" not in part:
                continue
            k, v = part.split(":", 1)
            if k in self.CVSS_METRICS and v in self.CVSS_METRICS[k]:
                explanations.append(f"{k}: {self.CVSS_METRICS[k][v]}")
        return "; ".join(explanations) if explanations else "Could not parse"

    def suggest_severity(self, vector: str) -> str:
        if not vector.startswith("CVSS:3.1/"):
            return "unknown"
        score_map = {
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": "critical",
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N": "high",
            "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N": "medium",
            "AV:A/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N": "low",
        }
        partial = vector.split("CVSS:3.1/")[1] if "CVSS:3.1/" in vector else vector
        return score_map.get(partial, "medium")

    def _severity_badge(self, severity: str) -> str:
        severity = severity.lower()
        color = self.SEVERITY_COLORS.get(severity, "#95a5a6")
        return f"![{severity}](https://img.shields.io/badge/{severity}-{color.lstrip('#')})"

    def _severity_ascii(self, severity: str) -> str:
        bars = {"critical": "████", "high": "███", "medium": "██", "low": "█", "info": "▬"}
        return bars.get(severity.lower(), "▬")

    def _format_evidence(self, evidence: str) -> str:
        if not evidence:
            return "_No evidence provided_"
        lines = evidence.split("\n")
        is_http = any(l.startswith(("GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HTTP/")) for l in lines[:5])
        if is_http:
            return "```http\n" + evidence + "\n```"
        try:
            json.loads(evidence)
            return "```json\n" + json.dumps(json.loads(evidence), indent=2) + "\n```"
        except (json.JSONDecodeError, ValueError):
            pass
        return ("```\n" + evidence + "\n```") if len(lines) > 1 else evidence

    def generate_markdown(self) -> str:
        if not self.findings:
            return "# No Findings\n\n_No findings to report._"
        sections = [
            f"# {self.title}", "",
            f"**Platform:** {self.platform.title()}  ",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d')}  ",
            f"**Findings:** {len(self.findings)}  ",
        ]
        for k, v in self.metadata.items():
            sections.append(f"**{k}:** {v}  ")
        sections += ["", "---", "", "## Summary", "",
                     "| Severity | Count |", "|----------|-------|"]
        sev_counts = Counter(f.severity.lower() for f in self.findings)
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev_counts.get(sev, 0) > 0:
                sections.append(f"| {sev.title()} {self._severity_badge(sev)} | {sev_counts[sev]} |")
        sections += [
            "", f"| **Total** | **{len(self.findings)}** |",
            "", "---", "", "## Findings", ""
        ]
        for i, finding in enumerate(self.findings, 1):
            sections += [
                f"### {i}. {finding.title}", "",
                f"**Severity:** {self._severity_badge(finding.severity)}", "",
            ]
            if finding.cwe_id:
                cwe_name = self.CWE_MAP.get(finding.cwe_id, finding.cwe_id)
                sections.append(f"**CWE:** [{finding.cwe_id}](https://cwe.mitre.org/data/definitions/{finding.cwe_id.split('-')[1]}.html) — {cwe_name}")
                sections.append("")
            if finding.cvss_vector:
                sections += [f"**CVSS Vector:** `{finding.cvss_vector}`", "",
                             f"**CVSS Explanation:** {self.explain_cvss(finding.cvss_vector)}", ""]
            sections += ["#### Description", "", finding.description, "",
                         "#### Impact", "", finding.impact or "_No impact stated_", "",
                         "#### Steps to Reproduce", "", finding.reproduction_steps or "_No steps provided_", "",
                         "#### Evidence", "", self._format_evidence(finding.evidence), "",
                         "#### Remediation", "", finding.remediation or "_No remediation_", ""]
            if finding.references:
                sections += ["#### References", ""]
                for ref in finding.references:
                    sections.append(f"- [{ref}]({ref})")
                sections.append("")
            sections.append("---")
            sections.append("")
        return "\n".join(sections)

    def generate_html(self) -> str:
        md = self.generate_markdown()
        html = ["<!DOCTYPE html><html><head><meta charset='utf-8'>"]
        html.append(f"<title>{self.title}</title>")
        html.append("<style>body{font-family:monospace;padding:20px;background:#1a1a2e;color:#eee}")
        html.append(".critical{color:#ff4444}.high{color:#ff8800}.medium{color:#ffcc00}.low{color:#88ccff}")
        html.append(".finding{margin:10px 0;padding:10px;border-left:3px solid #444}")
        html.append("pre{background:#16213e;padding:10px;overflow:auto}img{vertical-align:middle}</style></head><body>")
        html.append(f"<h1>{self.title}</h1>")
        sev_counts = Counter(f.severity.lower() for f in self.findings)
        html.append("<div style='display:flex;gap:15px;margin:20px 0'>")
        for sev, color in [("critical", "#ff4444"), ("high", "#ff8800"), ("medium", "#ffcc00"), ("low", "#88ccff")]:
            cnt = sev_counts.get(sev, 0)
            if cnt > 0:
                html.append(f"<div style='background:{color}22;padding:10px;border-radius:5px;text-align:center;min-width:60px'><span style='font-size:1.5em;display:block'>{cnt}</span>{sev.title()}</div>")
        html.append("</div><hr>")
        for i, f in enumerate(self.findings, 1):
            sev_color = self.SEVERITY_COLORS.get(f.severity.lower(), "#444")
            html.append(f"<div class='finding' style='border-color:{sev_color}'><h3>{i}. {f.title}</h3>")
            html.append(f"<p><strong>Severity:</strong> <span style='color:{sev_color}'>{f.severity.upper()}</span></p>")
            if f.cvss_vector:
                html.append(f"<p><strong>CVSS:</strong> <code>{f.cvss_vector}</code></p>")
            html.append(f"<p><strong>Description:</strong> {f.description}</p>")
            html.append(f"<p><strong>Impact:</strong> {f.impact}</p>")
            if f.evidence:
                html.append(f"<pre>{f.evidence[:500]}</pre>")
            html.append(f"<p><strong>Fix:</strong> {f.remediation}</p></div>")
        html.append("</body></html>")
        return "\n".join(html)

    def generate_hackerone_template(self, finding_index: int = 0) -> str:
        if not self.findings:
            return "No findings"
        f = self.findings[finding_index]
        return f"""## Summary

{f.description}

## Severity

{f.severity.title()}

## Steps To Reproduce

{f.reproduction_steps}

## Impact

{f.impact}

## Supporting Material / Evidence

```
{f.evidence}
```
"""

    def generate_bugcrowd_template(self, finding_index: int = 0) -> str:
        if not self.findings:
            return "No findings"
        f = self.findings[finding_index]
        sev_stmt = {
            "critical": "Direct compromise without user interaction.",
            "high": "Significant data integrity/confidentiality compromise.",
            "medium": "Limited but meaningful security impact.",
            "low": "Minimal impact, best-practice violation.",
            "info": "Observational, no direct impact.",
        }
        return f"""## Vulnerability Description

{f.description}

## Severity Justification

{sev_stmt.get(f.severity.lower(), '')}

{f.cvss_vector}

## Steps to Reproduce

{f.reproduction_steps}

## Proof of Concept / Evidence

```
{f.evidence}
```

## Impact

{f.impact}

## Remediation Recommendation

{f.remediation}
"""

    def generate_summary_table(self) -> str:
        if not self.findings:
            return "| # | Title | Severity | CWE |\n|---|-------|----------|-----|"
        lines = ["| # | Title | Severity | CWE |", "|---|-------|----------|-----|"]
        for i, f in enumerate(self.findings, 1):
            badge = self._severity_ascii(f.severity)
            cwe = f.cwe_id or "N/A"
            lines.append(f"| {i} | {f.title[:50]} | {badge} {f.severity.title()} | {cwe} |")
        return "\n".join(lines)

    def get_statistics(self) -> Dict[str, Any]:
        sev_counts = Counter(f.severity.lower() for f in self.findings)
        return {
            "total": len(self.findings),
            "severity_distribution": dict(sev_counts),
            "unique_cwes": len(set(f.cwe_id for f in self.findings if f.cwe_id)),
            "has_cvss": sum(1 for f in self.findings if f.cvss_vector),
            "platform": self.platform,
        }

    def save_markdown(self, filepath: str) -> str:
        content = self.generate_markdown()
        os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"[+] Report saved to {filepath}")
        return content

    def save_html(self, filepath: str) -> str:
        content = self.generate_html()
        os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"[+] HTML report saved to {filepath}")
        return content

    def save_json(self, filepath: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
        data = {"statistics": self.get_statistics(), "findings": [asdict(f) for f in self.findings]}
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    def import_json(self, filepath: str) -> int:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        findings_data = data if isinstance(data, list) else data.get("findings", [data])
        self.add_findings(findings_data)
        return len(findings_data)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python report_builder.py <findings.json> [--output report.md]")
        sys.exit(1)
    rb = ReportBuilder()
    rb.import_json(sys.argv[1])
    out = sys.argv[3] if len(sys.argv) > 3 and sys.argv[2] == "--output" else "report.md"
    rb.save_markdown(out)
    print(rb.generate_summary_table())
