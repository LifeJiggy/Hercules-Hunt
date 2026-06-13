# Utilities

Shared Python utility library (6,768 lines) used across all Hercules-Hunt modules. Zero external dependencies — standard library only.

## Files

| File | Lines | Description |
|------|-------|-------------|
| `file_utils.py` | 623 | Safe file I/O, path validation, JSON read/write, glob, checksum, temp files |
| `network_utils.py` | 798 | HTTP client, SSL contexts, URL validation, DNS resolution, port checks, download |
| `crypto_utils.py` | 829 | Shannon entropy, base64/hex encode-decode, JWT parse, hash, token generation, XOR |
| `logging_utils.py` | 789 | Color logging, progress bars, table printing, banner, timer context manager |
| `validation_utils.py` | 944 | URL/domain/IP/email/port/path/HTTP validation, sanitization, param checks |
| `config_utils.py` | 1,013 | JSON/env config loading, deep merge, dot-path access, schema validation, CLI conversion |
| `date_utils.py` | 765 | Timestamp formatting, ISO 8601, relative time, SSL/HTTP date parsing, duration |
| `report_utils.py` | 1,007 | CVSS 3.1 scoring, severity, HackerOne/Bugcrowd formatting, markdown/JSON reports |

## Usage

```python
from utils.file_utils import safe_read_file, read_json
from utils.network_utils import fetch_json, validate_url
from utils.crypto_utils import jwt_decode, shannon_entropy
from utils.logging_utils import print_success, print_error, setup_logger
from utils.validation_utils import validate_url, validate_domain
from utils.config_utils import ConfigManager
from utils.date_utils import format_timestamp, time_ago
from utils.report_utils import calculate_cvss_score, cvss_severity
```
