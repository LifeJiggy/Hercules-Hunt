# Reconnaissance Module

This directory contains the recon methodology and tool reference for Hercules-Hunt.

## Files

- `SKILL.md` — Reconnaissance skill definition: subdomain enumeration, live host discovery, URL crawling, technology fingerprinting, directory fuzzing, JS analysis, and continuous monitoring.
- `critical-bug-recon.md` — Recon methodology mapped to critical/high bug classes (IDOR, SSRF, auth bypass, RCE, XSS, race conditions, API misconfigs, SSTI). Asset prioritization and quick-win recon commands.
- `output-parser.md` — Recon output parsing, deduplication, and structuring methodology. Covers parsing subfinder, httpx, nuclei, katana, ffuf, dnsx outputs into canonical `target/` directory format.
- `windows-recon-workflow.md` — Windows-native recon workflow. PowerShell equivalents, curl.exe mastery, Scoop/WSL setup, Burp Suite on Windows, batch scripting patterns, and common Windows gotchas.
- `scope-validator.md` — Recon scope validation and out-of-scope filtering. Covers wildcard matching, regex scope enforcement, CIDR validation, asset type filtering (CDN/WAF/acquisition), and automated OOS removal pipelines.
- `recon-chaining.md` — Recon methodology for exploit chain building. Maps recon outputs to chainable bug pairs (IDOR→ATO, SSRF→cloud metadata, XSS→ATO, file upload→RCE, subdomain takeover→OAuth theft). Co-location signals and chain verification workflow.
- `quick-recon-cheatsheet.md` — One-page quick reference. Essential one-liners, common commands, bug class signal patterns, rate limiting flags, npm-install troubleshooting, and the recon→hunt decision tree.
- `recon-methodology.md` — Detailed recon methodology and pipeline steps (passive first, then active).
- `recon-arsenal.md` — Tool commands and techniques for recon (nuclei, httpx, subfinder, curl, dig).
- `recon-arsenal.md` — Tool commands and techniques for recon (nuclei, httpx, subfinder, curl, dig).
- `README` — This file.

## Usage

Source the recon skill in any AI agent:
```
load skill recon/SKILL.md
```

For executable tools, see `tools/bash/recon-toolkit.sh` (Linux/macOS) or `tools/powershell/recon-toolkit.ps1` (Windows).
