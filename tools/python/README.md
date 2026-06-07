# Python Vulnerability Hunting Toolkit

17 specialized modules with 340+ detection methods for P1 bug classes.

## Installation

```bash
pip install requests
```

## P1 Server-Side Tools (7 modules, 20+ methods each)

| Module | Class | Bug Classes | Key Methods |
|--------|-------|-------------|-------------|
| `rce_hunter.py` | `RCEHunter` | RCE, CMDi, SSTI, deserialization | Blind timing, OOB callback, reverse shell gen, WAF bypass, batch scan |
| `sqli_hunter.py` | `SQLiHunter` | SQLi, NoSQLi, JSONi | Error/time/boolean/union/OOB detection, DB fingerprint, data extraction |
| `idor_hunter.py` | `IDORHunter` | IDOR, mass assignment | Sequential/parallel UUID/hash/wildcard/array IDOR, JWT HMAC bypass |
| `auth_hunter.py` | `AuthHunter` | JWT, OAuth, MFA, CSRF, SSO | JWT alg=none/weak-kid, password reset, OTP brute force, session fixation |
| `ssrf_hunter.py` | `SSRFHunter` | SSRF, cloud metadata | IP encoding (dec/oct/hex/IPv6), DNS rebinding, gopher SSRF, IMDSv2 |
| `xxe_hunter.py` | `XXEHunter` | XXE, OOB XXE, SVG/SOAP/DOCX | Classic/OOB/error-based, XInclude, UTF-7/16 bypass, DOCX injection |
| `file_upload_hunter.py` | `FileUploadHunter` | RCE, XSS, XXE, path traversal | Webshell (PHP/ASP/JSP), magic byte spoof, .htaccess, SVG XSS, ZIP slip |

## Core Modules (10 modules)

| Module | Class / Entry | Purpose |
|--------|---------------|---------|
| `python-hunter.py` | `Orchestrator` | Pipeline orchestration, checkpoint/resume, diff, interactive menu |
| `js_analyzer.py` | `JSAnalyzer` | JS bundle analysis, endpoint extraction, secrets grep |
| `url_collector.py` | `URLCollector` | URL crawling, parameter extraction, wayback integration |
| `endpoint_fuzzer.py` | `EndpointFuzzer` | Directory/file fuzzing, extension discovery |
| `base64_utils.py` | functions | Base64 encode/decode, hex/octal conversion |
| `batch_processor.py` | `BatchProcessor` | Multi-target batch scanning, rate limiting |
| `report_builder.py` | `ReportBuilder` | HTML/JSON/CSV report generation |
| `secret_scanner.py` | `SecretScanner` | 30+ regex patterns, entropy detection |
| `payload_generator.py` | `PayloadGenerator` | XSS/SQLi/SSRF/XXE/LFI/CMDi/SSTI/NoSQLi payloads |
| `network_utils.py` | functions | DNS, SSL cert, port scan, CDN/WAF detection |

## Common Interface

Every module follows the same pattern:

```python
from tools.python import rce_hunter
hunter = rce_hunter.RCEHunter(target_url="https://target.com")
hunter.test_rce_command_injection("https://target.com/api/exec?cmd=ls")
hunter.export_json("results.json")
print(hunter.get_summary())
```

## CLI Usage

```bash
# Single module
python tools/python/rce_hunter.py https://target.com/api/exec --cmd "id"

# All tests
python tools/python/ssrf_hunter.py https://target.com/fetch --param url

# With output
python tools/python/xxe_hunter.py https://target.com/api/xml --output results.json
```

## Scoring

- **P1** (7 modules): Server-side bug classes — RCE, SQLi, IDOR, auth bypass, SSRF, XXE, file upload
- **Core** (10 modules): Recon, analysis, orchestration, reporting, payloads

## Requirements

- Python 3.8+
- `requests` library
