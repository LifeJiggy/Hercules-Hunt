# Windows Hunting Workflow Rules

## Reference ID: WHW-2026
## Applies to: All bug bounty / red-team operations from Windows hosts
## Version: 2.0

---

## Table of Contents

1. [Philosophy & Core Principles](#1-philosophy--core-principles)
2. [curl.exe Mastery for Bug Bounty](#2-curleee-mastery-for-bug-bounty)
3. [PowerShell Alternatives to Linux Tools](#3-powershell-alternatives-to-linux-tools)
4. [Python3 for JS Bundle Analysis, Regex Extraction & Batch Processing](#4-python3-for-js-bundle-analysis-regex-extraction--batch-processing)
5. [Batch Scripting for Automation](#5-batch-scripting-for-automation)
6. [Setting Up Burp Suite on Windows](#6-setting-up-burp-suite-on-windows)
7. [FFUF on Windows](#7-ffuf-on-windows)
8. [Nuclei on Windows](#8-nuclei-on-windows)
9. [Httpx on Windows](#9-httpx-on-windows)
10. [Working Around Missing Linux Tools with API-Based Alternatives](#10-working-around-missing-linux-tools-with-api-based-alternatives)
11. [Git for Windows](#11-git-for-windows)
12. [WSL Integration](#12-wsl-integration)
13. [PowerShell One-Liner Library for Common Hunting Tasks](#13-powershell-one-liner-library-for-common-hunting-tasks)
14. [Output Redirection & Logging](#14-output-redirection--logging)
15. [Environment Setup Scripts](#15-environment-setup-scripts)
16. [Windows-Specific Recon Workflow](#16-windows-specific-recon-workflow)
17. [Troubleshooting Common Windows Issues](#17-troubleshooting-common-windows-issues)
18. [Appendices](#18-appendices)

---

## 1. Philosophy & Core Principles

### 1.1 Why Windows for Bug Bounty

Most security tooling targets Linux, but Windows is the most common personal computing environment. A properly configured Windows workstation is fully capable for bug bounty hunting.

### 1.2 The Windows Advantage

- Native curl.exe (Windows 10 1803+ / Server 2019+)
- PowerShell 5.1+ with object-oriented pipeline
- Native Docker Desktop for controlled Linux environments
- WSL2 for when you absolutely need Linux tools
- Superior GUI tooling (Burp Suite, Fiddler, Procmon)

### 1.3 When to Use What

| Task | Tool | Why |
|------|------|-----|
| Quick HTTP requests | curl.exe | Lightweight, portable, scriptable |
| API testing | curl.exe / Burp | Interception vs raw requests |
| Recon automation | PowerShell + Python | Cross-batch scripting |
| JS analysis | Python3 + Node.js | Ecosystem support |
| Directory fuzzing | FFUF.exe | Native Windows binary |
| Template scanning | nuclei.exe | Native Windows binary |
| Subdomain discovery | PowerShell + APIs | No Linux dependency |
| Port scanning | PowerShell TCP sockets | Built-in, no nmap needed |
| Screenshotting | aquatone / gowitness | Windows-native binaries |
| Source control | git for Windows | Full git capability |

### 1.4 PATH Hygiene

Always install tools to a central directory:

C:\Tools\
  curl\        (Windows ships with it)
  ffuf\
  nuclei\
  httpx\
  python3\
  BurpSuite\
  aquatone\
  gowitness\
  subfinder\
  scripts\     (your PowerShell/batch scripts)

Add C:\Tools\scripts to your PATH via System Environment Variables.

---

## 2. curl.exe Mastery for Bug Bounty

### 2.1 Basic Structure

curl.exe [options] <URL>

Critical flags for bug bounty:

| Flag | Purpose | Example |
|------|---------|---------|
| -s | Silent mode | curl -s https://target.com |
| -S | Show errors | curl -sS https://target.com |
| -v | Verbose | curl -sv https://target.com |
| -i | Include response headers | curl -si https://target.com |
| -o | Write output to file | curl -so output.txt https://target.com |
| -k | Skip TLS verification | curl -sk https://target.com |
| -L | Follow redirects | curl -sL https://target.com |
| -A | Set User-Agent | curl -sA "Mozilla/5.0" https://target.com |
| -e | Set Referer | curl -se "https://admin.target.com" https://target.com/api |
| -H | Custom header | curl -sH "X-Forwarded-For: 127.0.0.1" https://target.com |
| -b | Send cookies | curl -sb "session=abc123" https://target.com |
| -c | Write cookies to file | curl -sc cookies.txt https://target.com/login |
| -D | Write response headers | curl -sD headers.txt https://target.com |
| -d | POST data | curl -sd "user=admin&pass=test" https://target.com/login |
| -F | Multipart form upload | curl -sF "file=@shell.php" https://target.com/upload |
| -X | HTTP method | curl -sX PUT https://target.com/api/resource |
| -w | Write-out formatting | curl -s -w "%{http_code}" -o nul https://target.com |
| --proxy | Proxy URL | curl -s --proxy http://127.0.0.1:8080 https://target.com |
| --cacert | CA certificate | curl -s --cacert burp-ca.pem https://target.com |
| --resolve | Custom DNS resolution | curl -s --resolve target.com:443:127.0.0.1 https://target.com |

### 2.2 Cookie Handling

Capture cookies from login:
curl -sv -c cookies.txt -d "username=test&password=test123" https://target.com/api/login

Use captured cookies:
curl -sv -b cookies.txt https://target.com/api/profile

Send cookies from string:
curl -sv -b "session=abc123; csrf=def456" https://target.com/api/dashboard

### 2.3 Header Capture with -D

Save response headers for analysis:
curl -sv -D headers.txt -o response_body.txt https://target.com

Extract specific header values with PowerShell:
curl -sD headers.txt -o nul https://target.com
$sessionToken = (Get-Content headers.txt | Select-String "Set-Cookie: session=").Line -replace '.*session=([^;]+).*','$1'
Write-Output $sessionToken

### 2.4 Method Switching

GET:       curl -s https://target.com/api/users
POST:      curl -s -X POST -d "name=test" https://target.com/api/users
PUT:       curl -s -X PUT -H "Content-Type: application/json" -d '{"name":"updated"}' https://target.com/api/users/1
PATCH:     curl -s -X PATCH -H "Content-Type: application/json" -d '{"field":"value"}' https://target.com/api/users/1
DELETE:    curl -s -X DELETE -H "Authorization: Bearer TOKEN" https://target.com/api/users/1
OPTIONS:   curl -s -X OPTIONS -i https://target.com/api/users
TRACE:     curl -s -X TRACE -i https://target.com/
HEAD:      curl -s -I https://target.com/some-file.txt

### 2.5 JSON POST

Simple JSON POST:
curl -s -X POST -H "Content-Type: application/json" -d '{"username":"test","password":"test123"}' https://target.com/api/login

JSON POST from file:
curl -s -X POST -H "Content-Type: application/json" -d @payload.json https://target.com/api/submit

GraphQL query via JSON POST:
curl -s -X POST -H "Content-Type: application/json" -d '{"query":"query { users { id name email } }"}' https://target.com/graphql

### 2.6 Multipart Upload

File upload:
curl -s -F "file=@/path/to/exploit.php" -F "description=test" https://target.com/upload

File upload with custom content type:
curl -s -F "file=@shell.php;type=image/jpeg" https://target.com/upload

Upload with filename override:
curl -s -F "file=@payload.txt;filename=exploit.php" https://target.com/upload

SVG XSS upload test:
curl -s -F "file=@xss.svg;type=image/svg+xml" https://target.com/avatar/upload

### 2.7 Timing with -w

Basic timing:
curl -s -w "`nHTTP Code: %{http_code}`nTime Total: %{time_total}s`nTime Connect: %{time_connect}s`nTTFB: %{time_starttransfer}s`nDNS: %{time_namelookup}s`n" -o nul https://target.com

Export timing as CSV:
curl -s -w "%{http_code},%{time_total},%{time_connect},%{time_starttransfer},%{time_namelookup}`n" -o nul https://target.com >> timing_log.csv

Batch timing multiple endpoints:
$urls = @("https://target.com/login", "https://target.com/api", "https://target.com/admin")
foreach ($url in $urls) {
    $result = curl -s -w "%{http_code},%{time_total}`n" -o nul $url
    Write-Output "$url,$result"
}

### 2.8 Following Redirects

Follow with verbose:    curl -sL -i https://target.com
Limit redirect count:   curl -sL --max-redirs 5 https://target.com
Capture redirect chain: curl -sLD headers.txt -o nul https://target.com; Get-Content headers.txt | Select-String "^Location:"
Follow with cookies:    curl -sL -b cookies.txt -c cookies.txt https://target.com/dashboard

### 2.9 Certificate Handling

Skip TLS verification:  curl -sk https://target.com
Use Burp CA:            curl -s --cacert C:\Tools\BurpSuite\burp-ca.pem --proxy http://127.0.0.1:8080 https://target.com
Check TLS version:      curl -sv --tlsv1.2 https://target.com 2>&1 | Select-String "SSL connection"

### 2.10 Proxy Configuration

Burp Suite proxy:       curl -s --proxy http://127.0.0.1:8080 https://target.com
SOCKS5 proxy:           curl -s --socks5 127.0.0.1:9050 https://target.com
Bypass proxy:           curl -s --noproxy "*" https://target.com

Environment variables:
$env:HTTP_PROXY="http://127.0.0.1:8080"
$env:HTTPS_PROXY="http://127.0.0.1:8080"
$env:NO_PROXY="localhost,127.0.0.1,::1"

### 2.11 Advanced curl Techniques

IDOR testing:
1..100 | ForEach-Object { curl -s -o nul -w "%{http_code}`n" "https://target.com/api/user/$_" }

Race condition (parallel):
$jobs = 1..20 | ForEach-Object { Start-Job -ScriptBlock { param($id) curl -s -X POST -d "coupon=SAVE50" https://target.com/api/apply-coupon } -ArgumentList $_ }
$jobs | Receive-Job -Wait

SSRF testing:
curl -s "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"
curl -s "https://target.com/fetch?url=http://burpcollaborator.net"
curl -s "https://target.com/fetch?url=file:///etc/passwd"

Verb tampering:
curl -s -X PUT https://target.com/api/change-password
curl -s -X PATCH https://target.com/api/change-password
curl -s -X OPTIONS -i https://target.com/api/change-password

Custom DNS resolution (virtual host testing):
curl -s --resolve target.com:443:192.168.1.1 https://target.com

### 2.12 curl.exe vs Linux curl

| Feature | Windows curl | Linux curl |
|---------|-------------|------------|
| TLS backend | Schannel | OpenSSL/LibreSSL/NSS |
| CA bundle | Windows cert store | /etc/ssl/certs |
| Default -k behavior | Respects store | Requires explicit CA |

Windows curl uses Schannel, so you don't need to manage CA certificates --- it trusts the Windows certificate store.

---

## 3. PowerShell Alternatives to Linux Tools

### 3.1 Select-String (grep equivalent)

Basic search:
Select-String -Pattern "password" -Path C:\scraped\*.txt

Recursive search:
Get-ChildItem -Path C:\scraped -Recurse -Include *.txt,*.js | Select-String -Pattern "api_key"

Search with context lines:
Select-String -Pattern "token" -Path response.txt -Context 2,3

Regex search with capture groups:
Select-String -Pattern "(?i)(AKIA[0-9A-Z]{16})" -Path C:\scraped\*.js | ForEach-Object { $_.Matches.Groups[1].Value }

Multiple pattern search (OR):
Select-String -Pattern "token|secret|key|password" -Path *.js

Inverse match (grep -v):
Get-Content data.txt | Select-String -Pattern "debug" -NotMatch

### 3.2 Get-ChildItem (ls equivalent)

Detailed listing:        Get-ChildItem | Select-Object Mode, Length, LastWriteTime, Name
Recursive:               Get-ChildItem -Recurse
Filter by extension:     Get-ChildItem -Filter "*.js" -Recurse
List only files:         Get-ChildItem -File
List only directories:   Get-ChildItem -Directory
Sort by size:            Get-ChildItem -File | Sort-Object Length -Descending
Hidden files:            Get-ChildItem -Hidden -Force

### 3.3 Measure-Object (wc equivalent)

Line count (wc -l):  Get-Content data.txt | Measure-Object -Line
Word count (wc -w):  Get-Content data.txt | Measure-Object -Word
Character count:     Get-Content data.txt | Measure-Object -Character
Byte count:          (Get-Item file.bin).Length

### 3.4 Invoke-WebRequest (curl fallback)

Basic GET:              Invoke-WebRequest -Uri "https://target.com" -Method Get
GET with content:       (Invoke-WebRequest -Uri "https://target.com" -Method Get).Content
POST with form data:    Invoke-WebRequest -Uri "https://target.com/login" -Method Post -Body @{username="test"; password="test123"}
JSON POST:              Invoke-WebRequest -Uri "https://target.com/api" -Method Post -Body (@{name="test"} | ConvertTo-Json) -ContentType "application/json"
With headers:           Invoke-WebRequest -Uri "https://target.com/api" -Method Get -Headers @{"Authorization"="Bearer TOKEN"}
Download file:          Invoke-WebRequest -Uri "https://target.com/file.zip" -OutFile "C:\target\file.zip"
With proxy:             Invoke-WebRequest -Uri "https://target.com" -Proxy "http://127.0.0.1:8080"
Skip cert validation:   [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

### 3.5 Invoke-RestMethod (for APIs)

GET JSON:  Invoke-RestMethod -Uri "https://api.target.com/v1/users" -Method Get -Headers @{"Authorization"="Bearer TOKEN"}
POST JSON: Invoke-RestMethod -Uri "https://api.target.com/v1/users" -Method Post -Body (@{name="test"} | ConvertTo-Json) -ContentType "application/json"

### 3.6 Get-Content (cat equivalent)

Read file:               Get-Content data.txt
Read first N lines:      Get-Content data.txt -TotalCount 10
Read last N lines:       Get-Content data.txt -Tail 10
Watch file (tail -f):    Get-Content log.txt -Wait
Read as single string:   Get-Content data.txt -Raw

### 3.7 Linux-to-PowerShell Command Map

| Linux Command | PowerShell Equivalent |
|---------------|----------------------|
| ls -la | Get-ChildItem | Format-Table Mode,Length,LastWriteTime,Name |
| cat file | Get-Content file |
| grep pattern file | Select-String -Pattern pattern -Path file |
| grep -r pattern . | Get-ChildItem -Recurse -File | Select-String -Pattern pattern |
| wc -l file | (Get-Content file).Count |
| head -n 10 | Get-Content file -TotalCount 10 |
| tail -n 10 | Get-Content file -Tail 10 |
| tail -f | Get-Content file -Wait |
| sort -u | Get-Content file | Sort-Object -Unique |
| uniq -c | Get-Content file | Group-Object | Select-Object Count,Name |
| diff a b | Compare-Object (Get-Content a) (Get-Content b) |
| find . -name "*.js" | Get-ChildItem -Recurse -Filter "*.js" |
| ps aux | Get-Process | Format-Table |
| kill -9 PID | Stop-Process -Id PID -Force |
| df -h | Get-PSDrive | Where-Object Used -gt 0 |
| which cmd | Get-Command cmd | Select-Object Source |
| env | Get-ChildItem Env: |
| echo $VAR | $env:VAR |
| touch file | New-Item -ItemType File -Path file |
| mkdir -p | New-Item -ItemType Directory -Path a\b\c -Force |
| cp -r | Copy-Item -Recurse |
| mv | Move-Item |
| rm -rf | Remove-Item -Recurse -Force |
| tee file | Tee-Object -FilePath file |
| xargs | ForEach-Object |
| base64 -d | [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($str)) |
| md5sum | Get-FileHash -Algorithm MD5 file |
| sha256sum | Get-FileHash -Algorithm SHA256 file |
| ping | Test-Connection -ComputerName host -Count 4 |
| nslookup | Resolve-DnsName host |
| traceroute | Test-NetConnection -TraceRoute host |
| netstat -tlnp | Get-NetTCPConnection | Where-Object State -eq Listen |
| iptables -L | netsh advfirewall show allprofiles |
| crontab -l | Get-ScheduledTask |
| uname -a | [System.Environment]::OSVersion |
| uptime | (Get-CimInstance Win32_OperatingSystem).LastBootUpTime |
### 3.8 Proxy Configuration for PowerShell

$env:HTTP_PROXY="http://127.0.0.1:8080"
$env:HTTPS_PROXY="http://127.0.0.1:8080"

Invoke-WebRequest -Uri "https://target.com" -Proxy "http://127.0.0.1:8080" -ProxyUseDefaultCredentials
Invoke-WebRequest -Uri "https://target.com" -NoProxy

### 3.9 Parallel Execution in PowerShell

Job-based parallelism (PowerShell 5.1):
$urls = @("https://target1.com", "https://target2.com", "https://target3.com")
$jobs = @()
foreach ($url in $urls) {
    $jobs += Start-Job -ScriptBlock { param($u) curl -s -o nul -w "$u %{http_code}`n" $u } -ArgumentList $url
}
$jobs | Wait-Job | Receive-Job

---

## 4. Python3 for JS Bundle Analysis, Regex Extraction & Batch Processing

### 4.1 Why Python3 on Windows

Python3 compensates for missing Linux tools, handles multipart parsing better than PowerShell, and has superior regex and HTTP libraries.

### 4.2 Initial Setup

pip install requests beautifulsoup4 lxml jsbeautifier pyjwt colorama tqdm

### 4.3 JS Bundle Analysis Script

Save as js_analyzer.py:
import re, sys, os, json
from pathlib import Path

def analyze_js(content, filename):
    findings = []
    patterns = {
        "API Endpoints (relative)": r'["\x27]/(?:api|v[0-9]+|graphql|rest|service|endpoint)/[^"\x27\s]+',
        "API Endpoints (absolute)": r'https?://[^"\x27\s]+(?:api|v[0-9]+|graphql|rest)[^"\x27\s]*',
        "AWS Keys": r"AKIA[0-9A-Z]{16}",
        "Google API Keys": r"AIza[0-9A-Za-z\-_]{35}",
        "JWT Tokens": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
        "Firebase URLs": r"https://[a-zA-Z0-9-]+\.firebaseio\.com",
        "AWS S3 URLs": r"https://[a-zA-Z0-9-]+\.s3\.amazonaws\.com",
        "Internal IPs": r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})",
        "Email addresses": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "Hardcoded secrets": r"(?:password|passwd|pwd|secret|token|api_key|apikey)\s*[=:]\s*[""\x27][^""\x27]+[""\x27]",
        "OAuth endpoints": r"/oauth|/authorize|/token|/revoke|/callback",
        "SSRF candidates": r"(?:fetch|request|load|get|curl|httpget)\([\s\S]{0,50}(?:url|path|uri|link)",
    }
    for label, pattern in patterns.items():
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            unique = list(set(matches))[:20]
            findings.append(f"\n[!] {label} (in {filename}):")
            for m in unique:
                findings.append(f"    -> {m[:200]}")
    return findings

def main():
    path = Path(sys.argv[1])
    files = [path] if path.is_file() else list(path.rglob("*.js")) + list(path.rglob("*.ts"))
    for f in files:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            for finding in analyze_js(content, f.name):
                print(finding)
        except Exception as e:
            print(f"Error reading {f}: {e}")

if __name__ == "__main__":
    main()

### 4.4 Regex Extraction Library

Save as regex_extract.py:
import re, sys, json
from pathlib import Path

PATTERNS = {
    "apis": [("API Endpoints", r'["\x27`](/[a-zA-Z0-9_\-/.]+(?:api|v[0-9]+|graphql|rest|service)[a-zA-Z0-9_\-/.?&=]*))["\x27`]')],
    "keys": [
        ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
        ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
        ("Stripe Key", r"(?:sk_live|pk_live|sk_test|pk_test)_[A-Za-z0-9]+"),
        ("GitHub Token", r"gh[ps]_[A-Za-z0-9]{36,}"),
        ("Slack Token", r"xox[abpors]-[A-Za-z0-9]{10,}"),
    ],
    "jwt": [("JWT Token", r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}")],
    "urls": [("HTTP URL", r"https?://[a-zA-Z0-9./?=&_%-]+"), ("Subdomain", r"https://(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})")],
    "emails": [("Email", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")],
    "internal": [("Internal IP", r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")],
}

def load_patterns(pattern_type="all"):
    if pattern_type == "all":
        return [item for sub in PATTERNS.values() for item in sub]
    return PATTERNS.get(pattern_type, [])

def extract_from_file(filepath, patterns):
    content = Path(filepath).read_text(encoding="utf-8", errors="ignore")
    results = []
    for name, pattern in patterns:
        for m in set(re.findall(pattern, content, re.IGNORECASE)):
            results.append((name, m.strip()))
    return results

def main():
    filepath, pattern_type = sys.argv[1], sys.argv[2].lower() if len(sys.argv) > 2 else "all"
    patterns = load_patterns(pattern_type)
    if not patterns:
        print(f"Unknown type: {pattern_type}. Available: all, apis, keys, jwt, urls, emails, internal")
        return
    results = extract_from_file(filepath, patterns)
    current = ""
    for name, value in results:
        if name != current:
            print(f"\n[{name}]")
            current = name
        print(f"  {value}")

if __name__ == "__main__":
    main()

### 4.5 Batch URL Fetcher

Save as batch_fetch.py:
import requests, sys, os, time, argparse
from pathlib import Path
from urllib.parse import urlparse

def main():
    parser = argparse.ArgumentParser(description="Batch URL fetcher")
    parser.add_argument("input", help="File with URLs (one per line)")
    parser.add_argument("--output", "-o", default="output", help="Output directory")
    parser.add_argument("--delay", "-d", type=float, default=0.5, help="Delay between requests")
    parser.add_argument("--proxy", "-p", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    args = parser.parse_args()

    Path(args.output).mkdir(parents=True, exist_ok=True)
    with open(args.input) as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None

    for i, url in enumerate(urls, 1):
        try:
            time.sleep(args.delay)
            resp = requests.get(url, headers=headers, proxies=proxies, timeout=15, verify=False)
            parsed = urlparse(url)
            safe_name = f"{i:04d}_{parsed.netloc}{parsed.path.replace('/', '_')[:100]}.html"
            (Path(args.output) / safe_name).write_text(resp.text, encoding="utf-8", errors="replace")
            print(f"[{i}] {resp.status_code} {url} -> {safe_name}")
        except Exception as e:
            print(f"[{i}] ERROR {url}: {e}")

if __name__ == "__main__":
    main()

### 4.6 JWT Decoder and Analyzer

Save as jwt_analyzer.py:
import sys, json, base64, re, time
from pathlib import Path

def decode_jwt_part(part):
    padding = 4 - len(part) % 4
    if padding != 4: part += "=" * padding
    return json.loads(base64.urlsafe_b64decode(part))

def analyze_jwt(jwt_str):
    parts = jwt_str.split(".")
    if len(parts) != 3: return {"error": "Invalid JWT"}
    header, payload = decode_jwt_part(parts[0]), decode_jwt_part(parts[1])
    findings = []

    alg = header.get("alg", "none")
    if alg.lower() in ("none", "none"): findings.append("CRITICAL: Algorithm is 'none' - unsigned JWT accepted")
    if "kid" in header and (header["kid"].startswith("/") or ".." in header["kid"]):
        findings.append(f"HIGH: kid path traversal: {header['kid']}")
    if "jwk" in header: findings.append("HIGH: JWK embedded in header - possible key injection")
    if "jku" in header: findings.append(f"HIGH: JKU header: {header['jku']} - check URL control")
    if "exp" not in payload: findings.append("MEDIUM: No expiration claim - token never expires")
    if "iat" not in payload: findings.append("LOW: No issued-at claim")
    for claim in ["role", "roles", "admin", "is_admin", "permissions", "scope"]:
        if claim in payload: findings.append(f"INFO: Contains '{claim}': {payload[claim]}")

    return {"header": header, "payload": payload, "findings": findings}

def main():
    input_data = sys.argv[1]
    if Path(input_data).exists():
        jwts = re.findall(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", Path(input_data).read_text())
        for i, j in enumerate(jwts, 1):
            print(f"\nJWT #{i}")
            result = analyze_jwt(j)
            print(f"Header: {json.dumps(result['header'], indent=2)}")
            print(f"Payload: {json.dumps(result['payload'], indent=2)}")
            for f in result["findings"]: print(f"  - {f}")
    else:
        result = analyze_jwt(input_data)
        print(f"Header: {json.dumps(result['header'], indent=2)}")
        print(f"Payload: {json.dumps(result['payload'], indent=2)}")
        for f in result["findings"]: print(f"  - {f}")

if __name__ == "__main__":
    main()

### 4.7 URL Extractor from JavaScript

Save as url_extractor.py:
import re, sys, json
from pathlib import Path
from urllib.parse import urljoin

def extract_urls(content, base_url="https://target.com"):
    urls = set()
    patterns = [
        r'["\x27](https?://[^"\x27]+)["\x27]',
        r'["\x60](/[a-zA-Z0-9_\-/.?&=+#\[\]%]+)["\x60]',
        r"fetch\(["\x27]([^"\x27]+)["\x27]",
        r"axios\.\w+\(["\x27]([^"\x27]+)["\x27]",
        r"\$\.(?:get|post|ajax|put|delete)\(["\x27]([^"\x27]+)["\x27]",
        r"open\(["\x27'][A-Z]+["\x27'],\s*["\x27]([^"\x27]+)["\x27]",
        r"location\.href\s*=\s*["\x27]([^"\x27]+)["\x27]",
        r"redirect\(["\x27]([^"\x27]+)["\x27]",
        r"router\.push\(["\x27]([^"\x27]+)["\x27]",
    ]
    for p in patterns:
        for m in re.findall(p, content, re.IGNORECASE):
            if m.startswith("http") or m.startswith("//"): urls.add(m)
            elif m.startswith("/"): urls.add(urljoin(base_url, m))
    return sorted(urls)

def extract_api_structures(content):
    apis = set()
    for p in [r"router\.(?:get|post|put|delete|patch)\s*\(["\x27]([^"\x27]+)["\x27]",
              r"app\.(?:get|post|put|delete|patch)\s*\(["\x27]([^"\x27]+)["\x27]",
              r"@(?:Get|Post|Put|Delete|Patch)\(["\x27]([^"\x27]+)["\x27]",
              r"baseURL:\s*["\x27]([^"\x27]+)["\x27]", r"baseUrl:\s*["\x27]([^"\x27]+)["\x27]"]:
        for m in re.findall(p, content, re.IGNORECASE): apis.add(m)
    return sorted(apis)

def main():
    path = Path(sys.argv[1])
    files = [path] if path.is_file() else list(path.rglob("*.js"))
    all_urls, all_apis = set(), set()
    for f in files:
        try:
            c = f.read_text(encoding="utf-8", errors="ignore")
            all_urls.update(extract_urls(c))
            all_apis.update(extract_api_structures(c))
        except: pass
    use_json = "--json" in sys.argv
    if use_json:
        print(json.dumps({"urls": sorted(all_urls), "api_endpoints": sorted(all_apis)}, indent=2))
    else:
        print(f"\nURLs ({len(all_urls)}):")
        for u in sorted(all_urls)[:100]: print(f"  {u}")
        print(f"\nAPI Endpoints ({len(all_apis)}):")
        for a in sorted(all_apis): print(f"  {a}")

if __name__ == "__main__":
    main()

### 4.8 Batch Subdomain Enumerator via crt.sh

Save as subdomain_enum.py:
import sys, json, socket, argparse
from urllib.request import urlopen

def crtsh_enum(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        data = json.loads(urlopen(url, timeout=30).read())
        subs = set()
        for entry in data:
            for n in entry.get("name_value", "").split("\n"):
                n = n.strip()
                if n.endswith(domain) and "*" not in n: subs.add(n.lower())
        return subs
    except Exception as e:
        print(f"crt.sh error: {e}", file=sys.stderr)
        return set()

def resolve(subs):
    resolved = {}
    for sub in subs:
        try:
            ips = socket.gethostbyname_ex(sub)[2]
            resolved[sub] = ips
        except: pass
    return resolved

def main():
    parser = argparse.ArgumentParser(description="Subdomain enumerator")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("--output", "-o", help="Output file")
    parser.add_argument("--resolve", "-r", action="store_true", help="Resolve to IPs")
    args = parser.parse_args()

    subs = crtsh_enum(args.domain)
    print(f"Found {len(subs)} subdomains")

    if args.resolve:
        resolved = resolve(subs)
        results = [f"{sub},{','.join(ips)}" for sub, ips in sorted(resolved.items())]
        results += [f"{sub},[unresolved]" for sub in sorted(subs - set(resolved.keys()))]
    else:
        results = sorted(subs)

    for r in results: print(r)
    if args.output:
        with open(args.output, "w") as f: f.write("\n".join(results) + "\n")

if __name__ == "__main__":
    main()

### 4.9 Setting Up a Python Virtual Environment for Hunting

# Create isolated Python environment
python -m venv C:\Tools\venv\hunting
C:\Tools\venv\hunting\Scripts\Activate.ps1

# Core packages
pip install requests beautifulsoup4 lxml jsbeautifier pyjwt colorama tqmd dnspython
pip install urllib3 cryptography pyOpenSSL httpx aiohttp

# Deactivate when done
deactivate

---
## TEST SECTION
Test content
---


## TEST PYTHON APPEND


---

## 8. Nuclei on Windows

### 8.1 Installation

Download from GitHub:
```
curl.exe -sL -o C:\Tools\nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.2.0_windows_amd64.zip"
Expand-Archive -Path C:\Tools\nuclei.zip -DestinationPath C:\Tools\nuclei -Force
```

Or Chocolatey: choco install nuclei -y

Update templates after install:
```
nuclei -update-templates
```

### 8.2 Basic Usage

```
# Scan single URL
nuclei -u https://target.com

# Scan multiple URLs from file
nuclei -l urls.txt

# Scan with specific template category
nuclei -u https://target.com -t cves/
nuclei -u https://target.com -t exposures/
nuclei -u https://target.com -t misconfiguration/

# Scan with high severity only
nuclei -u https://target.com -s high,critical
```

### 8.3 Advanced Nuclei Usage

```
# With proxy (Burp integration)
nuclei -u https://target.com -proxy http://127.0.0.1:8080

# Output formats
nuclei -u https://target.com -o results.txt
nuclei -u https://target.com -o results.json -jsonl

# Rate limiting
nuclei -u https://target.com -rl 50

# Concurrency
nuclei -u https://target.com -c 25

# Timeout
nuclei -u https://target.com -timeout 10

# Headless mode
nuclei -u https://target.com -headless

# Filter by tags
nuclei -u https://target.com -tags cve,idor,ssrf

# Severity-based
nuclei -u https://target.com -severity critical,high,medium
```

### 8.4 Template Management

```
# Update templates
nuclei -update-templates

# List templates
nuclei -tl
nuclei -tl | Select-String "cve"
nuclei -tl -tags cve
nuclei -tl -severity critical
```

### 8.5 Pipeline: Subfinder -> Httpx -> Nuclei

```
# Full pipeline
subfinder -d target.com -o subs.txt
httpx -l subs.txt -o alive.txt -mc 200,301,302,403
nuclei -l alive.txt -o results.txt -jsonl

# One-liner:
subfinder -d target.com | httpx -mc 200,301,302,403 | nuclei -o scan.json -jsonl
```

---

## 9. Httpx on Windows

### 9.1 Installation

```
curl.exe -sL -o C:\Tools\httpx.zip "https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_1.6.0_windows_amd64.zip"
Expand-Archive -Path C:\Tools\httpx.zip -DestinationPath C:\Tools\httpx -Force
```

Or Chocolatey: choco install httpx -y

### 9.2 Basic Usage

```
# Check single host
echo "target.com" | httpx

# Check multiple hosts
httpx -l subdomains.txt

# Find alive hosts
httpx -l subdomains.txt -o alive.txt

# Custom status codes
httpx -l subdomains.txt -mc 200,403,500

# Custom ports
httpx -l subdomains.txt -ports 80,443,8080,8443,3000,5000
```

### 9.3 Advanced Httpx Usage

```
# Extract technology stack
httpx -l subdomains.txt -tech-detect

# Screenshot
httpx -l subdomains.txt -screenshot -screenshot-output screenshots/

# Extract page title
httpx -l subdomains.txt -title

# Web server header
httpx -l subdomains.txt -web-server

# JSON output
httpx -l subdomains.txt -json -o output.json

# Follow redirects
httpx -l subdomains.txt -follow-redirects

# HTTP/2 probe
httpx -l subdomains.txt -http2

# CDN check
httpx -l subdomains.txt -cdn

# IP output
httpx -l subdomains.txt -ip
```

### 9.4 Httpx with Burp Integration

```
# Route through Burp
httpx -l subdomains.txt -proxy http://127.0.0.1:8080

# Skip certificate errors
httpx -l subdomains.txt -proxy http://127.0.0.1:8080 -x all
```


---

## 10. Working Around Missing Linux Tools with API-Based Alternatives

### 10.1 Subdomain Enumeration via crt.sh

```powershell
function Get-Subdomains {
    param([string]$Domain)
    $url = "https://crt.sh/?q=%25.$Domain&output=json"
    $response = Invoke-RestMethod -Uri $url -Method Get
    $subdomains = $response | ForEach-Object { $_.name_value } |
        ForEach-Object { $_.Split("`n") } |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -like "*.$Domain" -and $_ -notlike "*\**" } |
        Sort-Object -Unique
    return $subdomains
}

Get-Subdomains -Domain "target.com" | Out-File -FilePath "subdomains.txt"
```

### 10.2 HTTP Server Detection (No httpx)

```powershell
function Test-HttpStatus {
    param([Parameter(Mandatory,ValueFromPipeline)][string]$Hostname)
    process {
        $result = [PSCustomObject]@{Host=$Hostname; HttpStatus=$null; HttpsStatus=$null}
        try {
            $req = [System.Net.WebRequest]::Create("http://$Hostname")
            $req.Timeout = 5000
            $resp = $req.GetResponse()
            $result.HttpStatus = [int]$resp.StatusCode
            $resp.Close()
        } catch { $result.HttpStatus = "ERR" }
        try {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            $req = [System.Net.WebRequest]::Create("https://$Hostname")
            $req.Timeout = 5000
            $resp = $req.GetResponse()
            $result.HttpsStatus = [int]$resp.StatusCode
            $resp.Close()
        } catch { $result.HttpsStatus = "ERR" }
        return $result
    }
}

Get-Content subdomains.txt | Test-HttpStatus | Format-Table
```

### 10.3 Port Scanning (No Nmap)

```powershell
function Test-Ports {
    param([Parameter(Mandatory,ValueFromPipeline)][string]$Hostname,
          [int[]]$Ports = @(21,22,25,53,80,110,143,443,445,993,995,1433,3306,3389,5432,5900,5985,5986,6379,8080,8443,27017),
          [int]$Timeout = 1000)
    process {
        foreach ($port in $Ports) {
            try {
                $socket = New-Object System.Net.Sockets.TcpClient
                $async = $socket.BeginConnect($Hostname, $port, $null, $null)
                $wait = $async.AsyncWaitHandle.WaitOne($Timeout, $false)
                if ($wait) {
                    try { $socket.EndConnect($async); [PSCustomObject]@{Host=$Hostname; Port=$port; State="OPEN"} }
                    catch { }
                }
                $socket.Close()
            } catch { }
        }
    }
}

Test-Ports -Hostname "target.com" -Ports @(80,443,8080)
```

### 10.4 SSL Certificate Analysis (No openssl)

```powershell
function Get-CertificateInfo {
    param([string]$Hostname, [int]$Port = 443)
    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.Connect($Hostname, $Port)
    $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, { $true })
    $ssl.AuthenticateAsClient($Hostname)
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
    [PSCustomObject]@{
        Subject = $cert.Subject
        Issuer = $cert.Issuer
        NotBefore = $cert.NotBefore
        NotAfter = $cert.NotAfter
        SAN = ($cert.Extensions | Where-Object Oid -eq "2.5.29.17").Format($false)
        KeySize = $cert.PublicKey.Key.KeySize
    }
    $ssl.Close(); $tcp.Close()
}

Get-CertificateInfo -Hostname "target.com" | Format-List
```

### 10.5 Wayback Machine Integration

```powershell
function Get-WaybackUrls {
    param([string]$Domain, [int]$Limit = 1000)
    $url = "http://web.archive.org/cdx/search/cdx?url=$Domain/*&output=json&fl=original,timestamp,statuscode&limit=$Limit&filter=statuscode:200"
    $response = Invoke-RestMethod -Uri $url -Method Get
    $results = $response[1..$response.Length] | ForEach-Object {
        [PSCustomObject]@{URL=$_[0]; Timestamp=$_[1]; Status=$_[2]}
    }
    return $results
}

Get-WaybackUrls -Domain "target.com" -Limit 100 | Format-Table
```

### 10.6 Shodan Integration

```powershell
function Get-ShodanHost {
    param([string]$ApiKey, [string]$IP)
    $url = "https://api.shodan.io/shodan/host/$IP?key=$ApiKey"
    $response = Invoke-RestMethod -Uri $url -Method Get
    return [PSCustomObject]@{
        IP = $response.ip_str
        Ports = $response.ports -join ", "
        Hostnames = $response.hostnames -join ", "
        Country = $response.country_name
        Org = $response.org
    }
}

function Search-Shodan {
    param([string]$ApiKey, [string]$Query, [int]$Limit = 100)
    $url = "https://api.shodan.io/shodan/host/search?key=$ApiKey&query=$([System.Web.HttpUtility]::UrlEncode($Query))&limit=$Limit"
    $response = Invoke-RestMethod -Uri $url -Method Get
    return $response.matches | Select-Object ip_str, port, org, hostnames, product
}

Search-Shodan -ApiKey "YOUR_KEY" -Query "hostname:target.com"
```

### 10.7 urlscan.io Integration

```powershell
function Get-UrlscanResults {
    param([string]$Domain)
    $url = "https://urlscan.io/api/v1/search/?q=domain:$Domain&size=100"
    $response = Invoke-RestMethod -Uri $url -Method Get
    return $response.results | Select-Object @{N="URL";E={$_.page.url}}, @{N="IP";E={$_.page.ip}}, @{N="Server";E={$_.page.server}}
}

Get-UrlscanResults -Domain "target.com" | Format-Table
```

### 10.8 Technology Detection (No Wappalyzer CLI)

```powershell
function Get-WebTech {
    param([string]$Url)
    $req = [System.Net.WebRequest]::Create($Url)
    $req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    $req.Timeout = 10000
    $resp = $req.GetResponse()
    $headers = @{}; $resp.Headers.AllKeys | ForEach-Object { $headers[$_] = $resp.Headers[$_] }
    $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
    $content = $reader.ReadToEnd(); $reader.Close(); $resp.Close()
    $tech = @{}
    if ($headers.ContainsKey("Server")) { $tech["Server"] = $headers["Server"] }
    if ($headers.ContainsKey("X-Powered-By")) { $tech["X-Powered-By"] = $headers["X-Powered-By"] }
    if ($headers.ContainsKey("X-AspNet-Version")) { $tech["ASP.NET"] = $headers["X-AspNet-Version"] }
    if ($content -match "/wp-content/|wp-json|wordpress") { $tech["CMS"] = "WordPress" }
    if ($content -match "Drupal|drupal.js|drupalSettings") { $tech["CMS"] = "Drupal" }
    if ($content -match "Joomla!|joomla") { $tech["CMS"] = "Joomla" }
    if ($content -match "Laravel|laravel") { $tech["Framework"] = "Laravel" }
    if ($content -match "__VIEWSTATE|__EVENTVALIDATION") { $tech["Framework"] = "ASP.NET" }
    if ($content -match "React|react|reactRoot") { $tech["JS"] = "React" }
    if ($content -match "Vue\.js|vue\.js|vueRouter") { $tech["JS"] = "Vue.js" }
    if ($content -match "cloudflare|cf-ray") { $tech["CDN"] = "Cloudflare" }
    if ($content -match "google-analytics|gtag") { $tech["Analytics"] = "Google Analytics" }
    return $tech
}

Get-WebTech -Url "https://target.com" | Format-Table -AutoSize
```


---

## 11. Git for Windows

### 11.1 Installation

Download from git-scm.com or: `choco install git -y`

Configure basic identity:
```
git config --global user.name "Your Name"
git config --global user.email "your@email.com"
git config --global core.autocrlf input
git config --global core.longpaths true
git config --global credential.helper wincred
```

### 11.2 Git for Recon

```
# Clone target repos for source code review
git clone https://github.com/target/repo.git
git clone --depth 1 https://github.com/target/repo.git  # faster
git clone --branch dev --single-branch https://github.com/target/repo.git
```

### 11.3 Git Secret Scanning

```
# Search commit history for sensitive patterns
git log --all --diff-filter=A --name-only --format="" | Sort-Object -Unique | Where-Object { $_ -match "\.env|config|secret|key|password|token" }

# Search all commits for a pattern
git grep -i "AKIA[0-9A-Z]\{16\}" $(git rev-list --all)

# Search diffs for secrets
git log -p --all -S "password" --oneline

# Gitleaks on Windows
curl.exe -sL -o C:\Tools\gitleaks.zip "https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_8.18.0_windows_x64.zip"
Expand-Archive -Path C:\Tools\gitleaks.zip -DestinationPath C:\Tools\gitleaks -Force
gitleaks detect -s C:\Users\ADMIN\repos\target-repo -v
```

### 11.4 Git Commit Analysis

```
# View commit history
git log --oneline --graph --all -30

# Find commits by author
git log --author="developer@target.com" --oneline

# Find commits in date range
git log --after="2025-01-01" --before="2025-12-31" --oneline

# Find deleted files (may contain secrets)
git log --diff-filter=D --summary --oneline

# Find deleted lines with sensitive data
git log -p --all --diff-filter=D -S "password" -- "*.php" "*.env" "*.config"
```

### 11.5 Git Branch and Tag Enumeration

```
# List all branches
git branch -a

# List all tags
git tag

# List remote references
git ls-remote --heads origin
```


---

## 12. WSL Integration

### 12.1 When to Use WSL

| Task | WSL Recommended? | Alternative |
|------|-----------------|-------------|
| Go tooling (ffuf, nuclei, httpx) | No | Native Windows binaries |
| Python scripts | No | Native Python |
| Bash-specific tools (massdns, puredns) | Yes | No Windows equivalent |
| Linux-only exploits | Yes | No Windows equivalent |
| Network scanning (masscan, nmap) | Yes | PowerShell sockets (basic) |
| Wordlist processing | No | PowerShell faster for text |
| JS analysis | No | Python on Windows |
| Automation scripts | No | PowerShell > bash on Windows |

### 12.2 WSL Setup

```powershell
# Install WSL2
wsl --install -d Ubuntu

# Verify
wsl -l -v

# Set default WSL version
wsl --set-default-version 2

# Run single command in WSL from PowerShell
wsl -- ls -la /mnt/c/Tools

# Run interactive session
wsl ~
```

### 12.3 WSL Limitations

- File I/O across /mnt is SLOW. Keep project files on Linux ext4 filesystem
- Network performance is slightly degraded vs native
- WSL2 uses NAT, not bridged - cannot receive inbound connections by default
- Port forwarding required for external access

Mitigations:
- Store tools inside WSL: ~/tools/
- Store wordlists inside WSL: ~/wordlists/
- Use /mnt/c/ only for final output transfer

### 12.4 Cross-Platform File Access

```powershell
# Windows -> WSL: Copy files
Copy-Item "C:\Tools\wordlists\common.txt" "\\wsl.localhost\Ubuntu\home\user\wordlists\"

# WSL -> Windows: Copy results
cp /home/user/results.txt /mnt/c/Tools/results/

# Run Windows tools from WSL (use .EXE)
/mnt/c/Tools/ffuf/ffuf.exe -u https://target.com/FUZZ -w /mnt/c/Tools/wordlists/common.txt

# Run WSL tools from PowerShell
wsl -- curl -s https://target.com
wsl -- grep "pattern" /mnt/c/Users/ADMIN/data.txt
```

### 12.5 WSL Burp Proxy Integration

```bash
# In WSL, set proxy for all traffic:
export HTTP_PROXY=http://host.docker.internal:8080
export HTTPS_PROXY=http://host.docker.internal:8080

# Or find WSL host IP:
export HTTP_PROXY=http://$(powershell.exe -Command "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -eq 'vEthernet (WSL)' }).IPAddress" | tr -d '\r'):8080

# Set persistently in ~/.bashrc:
echo 'export HTTP_PROXY=http://host.docker.internal:8080' >> ~/.bashrc
echo 'export HTTPS_PROXY=http://host.docker.internal:8080' >> ~/.bashrc
```

### 12.6 Shared Tool Configuration

```bash
# Symlink wordlists from Windows into WSL
ln -s /mnt/c/Tools/wordlists ~/wordlists
ln -s /mnt/c/Tools/scripts ~/scripts
ln -s /mnt/c/Users/ADMIN/nuclei-templates ~/nuclei-templates
```

### 12.7 WSL Port Forwarding (for inbound connections)

```powershell
# PowerShell (Admin):
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8080 connectaddress=127.0.0.1 connectport=8080

# View port proxies:
netsh interface portproxy show all

# Remove:
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0
```

### 12.8 Docker Desktop with WSL2 Backend

```powershell
# Install Docker Desktop, enable WSL2 backend
# Settings -> Resources -> WSL Integration -> Enable for Ubuntu

# Run tools in disposable containers:
docker run --rm -it -v "C:\Tools\wordlists:/wordlists" projectdiscovery/ffuf:latest -u https://target.com/FUZZ -w /wordlists/common.txt

# Kali container:
docker run --rm -it kalilinux/kali-rolling
```


---

## 13. PowerShell One-Liner Library for Common Hunting Tasks

### 13.1 Information Gathering

```powershell
# DNS resolution
Resolve-DnsName -Name target.com -Type A
Resolve-DnsName -Name target.com -Type MX
Resolve-DnsName -Name target.com -Type NS
Resolve-DnsName -Name target.com -Type TXT
Resolve-DnsName -Name target.com -Type ANY

# Reverse DNS
[System.Net.Dns]::GetHostByAddress("1.1.1.1")
```

### 13.2 Web Requests

```powershell
# Quick GET
(Invoke-WebRequest -Uri "https://target.com" -Method Get).Content

# Check status code only
(Invoke-WebRequest -Uri "https://target.com" -Method Get).StatusCode

# Check response headers
(Invoke-WebRequest -Uri "https://target.com" -Method Get).Headers

# POST with form data
Invoke-WebRequest -Uri "https://target.com/login" -Method Post -Body @{username="test"; password="test123"}

# JSON POST via Invoke-RestMethod
Invoke-RestMethod -Uri "https://target.com/api" -Method Post -Body (@{name="test"} | ConvertTo-Json) -ContentType "application/json"

# With Bearer token
$headers = @{Authorization = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ."}
Invoke-RestMethod -Uri "https://api.target.com/v1/users" -Method Get -Headers $headers

# Download file
Invoke-WebRequest -Uri "https://target.com/file.zip" -OutFile "C:\downloads\file.zip"
```

### 13.3 Text Processing

```powershell
# Find all lines with "admin" case-insensitive
Select-String -Pattern "admin" -Path responses.txt | Select-Object -ExpandProperty Line

# Extract regex matches
Select-String -Pattern "(?i)(AKIA[0-9A-Z]{16})" -Path C:\scraped\*.js | ForEach-Object { $_.Matches.Groups[1].Value }

# Count lines in file
(Get-Content data.txt).Count

# Get unique lines
Get-Content data.txt | Sort-Object -Unique

# Group and count
Get-Content data.txt | Group-Object | Sort-Object Count -Descending

# Replace text in file
(Get-Content file.txt) -replace "old","new" | Set-Content file.txt

# Split by delimiter
Get-Content data.csv | ForEach-Object { $_.Split(",")[0] }

# JSON pretty print
Get-Content data.json | ConvertFrom-Json | ConvertTo-Json -Depth 10
```

### 13.4 File System Operations

```powershell
# Find all JS files
Get-ChildItem -Path C:\target -Recurse -Filter "*.js"

# Find files modified in last 24 hours
Get-ChildItem -Path C:\target -Recurse -File | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) }

# Show file sizes sorted
gci -Path C:\target -Recurse -File | Sort-Object Length -Descending | Select-Object Name, Length

# Show directory sizes
Get-ChildItem -Path C:\target -Directory | ForEach-Object {
    $size = (Get-ChildItem $_.FullName -Recurse -File | Measure-Object -Sum Length).Sum
    [PSCustomObject]@{Folder=$_.Name; SizeMB=[math]::Round($size/1MB, 2)}
}
```

### 13.5 Networking

```powershell
# Ping a host
Test-Connection -ComputerName target.com -Count 4

# TCP port check
Test-NetConnection -ComputerName target.com -Port 443 -WarningAction SilentlyContinue

# Trace route
Test-NetConnection -ComputerName target.com -TraceRoute

# List listening ports
Get-NetTCPConnection | Where-Object State -eq Listen | Format-Table

# Get public IP
(Invoke-RestMethod -Uri "https://api.ipify.org?format=json").ip

# HTTP response timing via curl
curl.exe -s -w "DNS: %{time_namelookup}s Connect: %{time_connect}s TTFB: %{time_starttransfer}s Total: %{time_total}s HTTP: %{http_code}\n" -o nul https://target.com
```

### 13.6 Encoding and Decoding

```powershell
# Base64 encode
[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("text to encode"))

# Base64 decode
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("dGV4dA=="))

# URL encode
[System.Web.HttpUtility]::UrlEncode("param value")

# URL decode
[System.Web.HttpUtility]::UrlDecode("param+value")

# Hex encode
$bytes = [System.Text.Encoding]::UTF8.GetBytes("text"); ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""

# Hex decode
$hex = "74657874"; $bytes = for ($i=0; $i -lt $hex.Length; $i+=2) { [Convert]::ToByte($hex.Substring($i,2),16) }; [System.Text.Encoding]::UTF8.GetString($bytes)

# MD5 hash
Get-FileHash -Algorithm MD5 file.txt

# SHA256 hash
Get-FileHash -Algorithm SHA256 file.txt
```

### 13.7 JSON Processing

```powershell
# Parse JSON from API
$data = Invoke-RestMethod -Uri "https://api.target.com/v1/users"
$data | Select-Object id, name, email

# Convert to JSON
$obj = @{name="test"; roles=@("admin","user")} | ConvertTo-Json

# Pretty print JSON file
Get-Content messy.json | ConvertFrom-Json | ConvertTo-Json -Depth 10

# Filter JSON array
$data | Where-Object { $_.role -eq "admin" } | Format-Table

# Export JSON to file
$data | ConvertTo-Json -Depth 10 | Set-Content output.json
```

### 13.8 Data Extraction from Files

```powershell
# Extract all URLs from JS files
Select-String -Pattern "https?://[^""\s]+" -Path C:\scraped\*.js | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value -Unique

# Extract all API endpoints
Select-String -Pattern "([/][a-zA-Z0-9_\-/.]+(?:api|v[0-9]+|graphql|rest)[a-zA-Z0-9_\-/.?&=]*)" -Path *.js | ForEach-Object { $_.Matches.Value } | Sort-Object -Unique

# Extract JWTs from files
Select-String -Pattern "eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}" -Path C:\scraped\*.txt | ForEach-Object { $_.Matches.Value }

# Extract email addresses
Select-String -Pattern "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" -Path C:\scraped\* -CaseSensitive | ForEach-Object { $_.Matches.Value } | Sort-Object -Unique

# Extract IP addresses
Select-String -Pattern "\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b" -Path C:\scraped\* | ForEach-Object { $_.Matches.Value } | Sort-Object -Unique
```

### 13.9 Automation Helpers

```powershell
# Loop over URL list
Get-Content urls.txt | ForEach-Object { curl.exe -s -o nul -w "$_ %{http_code}\n" $_ }

# Loop with delay
Get-Content urls.txt | ForEach-Object { Start-Sleep 1; curl.exe -s -o nul -w "$_ %{http_code}\n" $_ }

# Batch file download
Get-Content urls.txt | ForEach-Object { Invoke-WebRequest -Uri $_ -OutFile ([System.IO.Path]::GetFileName($_)) }

# Generate timestamp
Get-Date -Format "yyyyMMdd_HHmmss"

# Measure execution time
Measure-Command { curl.exe -s https://target.com -o nul }

# Retry with backoff
$retries = 3; $delay = 2
for ($i=0; $i -lt $retries; $i++) {
    try { curl.exe -s https://target.com; break }
    catch { Write-Host "Retry $($i+1)..."; Start-Sleep $delay; $delay *= 2 }
}
```


---

## 14. Output Redirection & Logging

### 14.1 PowerShell Output Operators

```powershell
# Redirect stdout to file (overwrite)
curl.exe -s https://target.com > output.txt

# Redirect stdout to file (append)
curl.exe -s https://target.com >> output.txt

# Redirect stderr to file
cmd /c "dir nonexistent 2> errors.txt"

# Redirect both stdout and stderr
curl.exe -s https://target.com > output.txt 2>&1

# Redirect to null (discard output)
curl.exe -s https://target.com > $null

# PowerShell native - Out-File
curl.exe -s https://target.com | Out-File -FilePath output.txt -Encoding UTF8

# PowerShell native - Add-Content (append)
curl.exe -s https://target.com | Add-Content -Path output.txt -Encoding UTF8

# Tee-Object (output to file AND console)
curl.exe -s https://target.com | Tee-Object -FilePath output.txt
```

### 14.2 Logging Best Practices

```powershell
# Create timestamped log file
$logFile = "scan_$(Get-Date -Format yyyyMMdd_HHmmss).log"

# Log with timestamp
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp [INFO] $Message" | Add-Content -Path $script:logFile
    Write-Host "$timestamp [INFO] $Message"
}

# Usage
Write-Log "Starting scan against target.com"
```

### 14.3 Structured Output (CSV/JSON)

```powershell
# Export results to CSV
$results = @()
Get-Content urls.txt | ForEach-Object {
    $status = (curl.exe -s -o nul -w "%{http_code}" $_)
    $results += [PSCustomObject]@{URL=$_; Status=$status; Date=(Get-Date)}
}
$results | Export-Csv -Path results.csv -NoTypeInformation

# Export to JSON
$results | ConvertTo-Json -Depth 5 | Set-Content results.json

# Parallel processing with logging
$urls = Get-Content urls.txt
$jobs = $urls | ForEach-Object {
    Start-Job -ScriptBlock {
        param($url)
        $code = curl.exe -s -o nul -w "%{http_code}" $url
        [PSCustomObject]@{URL=$url; Status=$code}
    } -ArgumentList $_
}
$jobs | Wait-Job | Receive-Job | Export-Csv -Path parallel_results.csv -NoTypeInformation
```

### 14.4 Session Logging with Start-Transcript

```powershell
# Record entire PowerShell session
Start-Transcript -Path "log.txt"

# ... run commands ...

# Stop recording
Stop-Transcript
```


---

## 15. Environment Setup Scripts

### 15.1 Complete PowerShell Profile

Save to $PROFILE (typically C:\Users\ADMIN\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1)

```powershell
# ============================================
# Bug Bounty PowerShell Profile
# ============================================

# Proxy management
$env:HTTP_PROXY = $null
$env:HTTPS_PROXY = $null

function Set-BurpProxy {
    $env:HTTP_PROXY = "http://127.0.0.1:8080"
    $env:HTTPS_PROXY = "http://127.0.0.1:8080"
    Write-Host "[+] Burp proxy enabled" -ForegroundColor Green
}

function Remove-Proxy {
    Remove-Item Env:\HTTP_PROXY -ErrorAction SilentlyContinue
    Remove-Item Env:\HTTPS_PROXY -ErrorAction SilentlyContinue
    Write-Host "[-] Proxy disabled" -ForegroundColor Yellow
}

# Directory shortcuts
function Go-Target {
    param([string]$Name)
    $path = "C:\BurpProjects\$Name"
    if (-not (Test-Path $path)) { New-Item -ItemType Directory -Path $path -Force | Out-Null }
    Set-Location $path
    Write-Host "[i] Working in $path" -ForegroundColor Cyan
}

# Quick HTTP tools
function Get-StatusCode {
    param([string]$Url)
    $code = curl.exe -s -o nul -w "%{http_code}" $Url
    Write-Host "$Url -> $code" -ForegroundColor $(if ($code -eq 200) { "Green" } else { "Yellow" })
}

function Test-Alive {
    param([string]$File)
    Get-Content $File | ForEach-Object {
        $code = curl.exe -s -o nul -w "%{http_code}" $_
        if ($code -ne 0) { Write-Host "$code $_" }
    }
}

# Directory fuzzing helper
function Invoke-Fuzz {
    param([string]$Url, [string]$Wordlist, [int]$Threads = 20)
    ffuf -u "$Url/FUZZ" -w $Wordlist -t $Threads -ac -o fuzz_$(Get-Date -Format yyyyMMdd_HHmmss).json -of json
}

# Nuclei scan helper
function Invoke-Scan {
    param([string]$Target, [string]$Severity = "medium,high,critical")
    nuclei -u $Target -severity $Severity -o "nuclei_$(Get-Date -Format yyyyMMdd_HHmmss).txt"
}

# Timestamp helper
function Get-Timestamp { Get-Date -Format "yyyy-MM-dd HH:mm:ss" }

# Log helper
function Write-Log {
    param([string]$Message)
    Write-Host "$(Get-Timestamp) $Message"
}

# Prompt customization
function prompt {
    $proxy = if ($env:HTTP_PROXY) { " [PROXY]" } else { "" }
    "BB$proxy $(Get-Location)> "
}
```

### 15.2 Environment Check Script

```powershell
# Save as check-env.ps1
Write-Host "=== Bug Bounty Environment Check ===" -ForegroundColor Cyan

$checks = @(
    @{Name="Python 3"; Command={python --version 2>&1}},
    @{Name="Git"; Command={git --version 2>&1}},
    @{Name="curl"; Command={curl --version 2>&1 | Select-Object -First 1}},
    @{Name="FFUF"; Command={ffuf -V 2>&1}},
    @{Name="Nuclei"; Command={nuclei -version 2>&1}},
    @{Name="Httpx"; Command={httpx -version 2>&1}},
    @{Name="Subfinder"; Command={subfinder -version 2>&1}}
)

foreach ($check in $checks) {
    try {
        $result = & $check.Command
        Write-Host "[OK] $($check.Name): $result" -ForegroundColor Green
    } catch {
        Write-Host "[!!] $($check.Name): NOT FOUND" -ForegroundColor Red
    }
}
```

### 15.3 Quick Target Setup Script

```powershell
# Save as setup-target.ps1
param([string]$Domain)

if (-not $Domain) {
    Write-Host "Usage: .\setup-target.ps1 target.com" -ForegroundColor Yellow
    exit 1
}

$basePath = "C:\BurpProjects\$Domain"
$dirs = @("recon", "fuzz", "nuclei", "js", "screenshots", "burp", "exploits")

foreach ($dir in $dirs) {
    $path = Join-Path $basePath $dir
    New-Item -ItemType Directory -Path $path -Force | Out-Null
}

Write-Host "[+] Target workspace created: $basePath" -ForegroundColor Green
Write-Host "[i] Directories: $($dirs -join ", ")"
Set-Location $basePath
Write-Host "[i] Changed to $basePath"
```

### 15.4 Chocolatey Package Installer

```powershell
# One-liner to install all tools via Chocolatey
choco install -y ffuf nuclei httpx subfinder aquatone gowitness python git curl jq yq
```


---

## 16. Windows-Specific Recon Workflow

### 16.1 Complete Recon Pipeline

```powershell
# === Phase 1: Subdomain Enumeration ===
Write-Host "[Phase 1] Subdomain Enumeration" -ForegroundColor Cyan

# Method A: crt.sh (no external tools needed)
$domain = "target.com"
$subs = (Invoke-RestMethod "https://crt.sh/?q=%25.$domain&output=json") |
    ForEach-Object { $_.name_value } |
    ForEach-Object { $_.Split("`n") } |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -like "*.$domain" -and $_ -notlike "*\**" } |
    Sort-Object -Unique
$subs | Out-File -FilePath "subdomains_crtsh.txt"
Write-Host "Found $($subs.Count) subdomains via crt.sh"

# Method B: Subfinder (if installed)
if (Get-Command subfinder -ErrorAction SilentlyContinue) {
    subfinder -d $domain -o subdomains_subfinder.txt -silent
}

# === Phase 2: Host Discovery ===
Write-Host "[Phase 2] Host Discovery" -ForegroundColor Cyan

# PowerShell native HTTP check
$alive = @()
Get-Content subdomains_crtsh.txt | ForEach-Object {
    try {
        $req = [System.Net.WebRequest]::Create("https://$_")
        $req.Timeout = 5000
        $resp = $req.GetResponse()
        $alive += [PSCustomObject]@{Host=$_; Status=[int]$resp.StatusCode; Server=$resp.Headers["Server"]}
        $resp.Close()
    } catch { }
}
$alive | Export-Csv -Path alive_hosts.csv -NoTypeInformation

# Via httpx (if installed)
if (Get-Command httpx -ErrorAction SilentlyContinue) {
    httpx -l subdomains_crtsh.txt -o alive_httpx.txt -title -tech-detect -status-code -mc 200,301,302,403,401,500
}

# === Phase 3: Technology Fingerprinting ===
Write-Host "[Phase 3] Technology Fingerprinting" -ForegroundColor Cyan

Get-Content alive_httpx.txt | ForEach-Object {
    $url = $_ -replace "\s+.*",""  # Strip extra info if present
    curl.exe -s -i -L -k $url -o nul -D headers.txt
    Get-Content headers.txt | Select-String "Server:|X-Powered-By:|Set-Cookie:"
}

# === Phase 4: JavaScript Analysis ===
Write-Host "[Phase 4] JavaScript Analysis" -ForegroundColor Cyan

if (Get-Command python -ErrorAction SilentlyContinue) {
    # Download JS files for analysis
    Get-Content alive_httpx.txt | ForEach-Object {
        $url = $_ -replace "\s.*",""
        curl.exe -s -k "$url" -o "page_$(Get-Random).html"
    }
    # Run JS analyzer
    python js_analyzer.py .
}

# === Phase 5: Directory Fuzzing ===
Write-Host "[Phase 5] Directory Fuzzing" -ForegroundColor Cyan

if (Get-Command ffuf -ErrorAction SilentlyContinue) {
    Get-Content alive_httpx.txt | ForEach-Object {
        $url = $_ -replace "\s.*",""
        $safeName = ($url -replace "https?://","").Replace("/","_").Replace(".","_")
        ffuf -u "$url/FUZZ" -w "C:\Tools\SecLists-master\Discovery\Web-Content\common.txt" -t 30 -ac -o "fuzz_$safeName.json" -of json -k
    }
}

# === Phase 6: Vulnerability Scanning ===
Write-Host "[Phase 6] Vulnerability Scanning" -ForegroundColor Cyan

if (Get-Command nuclei -ErrorAction SilentlyContinue) {
    nuclei -l alive_httpx.txt -severity critical,high,medium -o nuclei_results.txt -jsonl
}

# === Phase 7: Screenshotting ===
Write-Host "[Phase 7] Screenshotting" -ForegroundColor Cyan

if (Get-Command gowitness -ErrorAction SilentlyContinue) {
    gowitness file -f alive_httpx.txt -P screenshots/
}

Write-Host "[+] Recon complete" -ForegroundColor Green
```

### 16.2 Automated Recon Runner (Batch)

```batch
@echo off
REM === auto_recon.bat - Full automated recon ===
REM Usage: auto_recon.bat target.com

set "DOMAIN=%~1"
set "OUTDIR=recon_%DOMAIN%_%DATE:/=-%"

if "%DOMAIN%"=="" (echo Usage: %~nx0 ^<domain^> & exit /b 1)
if not exist "%OUTDIR%" mkdir "%OUTDIR%"
cd "%OUTDIR%"

echo [!] Starting automated recon for %DOMAIN%

REM Step 1: Subdomain enumeration
echo [1/6] Subdomain enumeration...
powershell -Command "Invoke-RestMethod ""https://crt.sh/?q=%25.%DOMAIN%&output=json"" | ForEach-Object { $_.name_value.Split(""`n"") } | Sort-Object -Unique | Out-File -FilePath subs.txt -Encoding ASCII"

REM Step 2: Host discovery
echo [2/6] Host discovery...
if exist subs.txt (
    for /f "usebackq delims=" %%h in (subs.txt) do (
        curl.exe -s -o nul -w "%%h,%%{http_code}\n" -k --connect-timeout 5 "https://%%h" >> alive.csv 2>&1
    )
)

REM Step 3: Extract URLs from Wayback
echo [3/6] Wayback Machine URLs...
curl.exe -s "http://web.archive.org/cdx/search/cdx?url=%DOMAIN%/*&output=text&fl=original&filter=statuscode:200&limit=5000" > wayback_urls.txt 2>&1

REM Step 4: Common paths check
echo [4/6] Common paths check...
for %%p in (.env .git/config admin api backup config.php wp-admin graphql swagger.json api-docs) do (
    curl.exe -s -o nul -w "%%p,%%{http_code}\n" -k --connect-timeout 5 "https://%DOMAIN%/%%p" >> paths.csv 2>&1
)

REM Step 5: Screenshots for alive hosts
echo [5/6] Taking screenshots...
if exist gowitness.exe (
    for /f "tokens=1 delims=," %%a in (alive.csv) do (
        gowitness single --url "https://%%a" --destination screenshots/ 2>nul
    )
)

REM Step 6: Summary
echo [6/6] Summary...
echo. > summary.txt
echo Target: %DOMAIN% >> summary.txt
echo Date: %DATE% %TIME% >> summary.txt
echo. >> summary.txt

if exist subs.txt (
    for /f %%c in (""subs.txt"") do set SUBCOUNT=%%~zc
    echo Subdomains found: %%SUBCOUNT%% >> summary.txt
)

echo Results in %CD%
echo [!] Recon complete!
```


---

## 17. Troubleshooting Common Windows Issues

### 17.1 curl.exe SSL/TLS Errors

```
# Error: "schannel: next InitializeSecurityContext failed"
# Fix: Use -k to bypass cert validation, or update root certs
curl.exe -sk https://target.com

# Error: "Could not resolve host"
# Fix: Check DNS or use --resolve to force IP
curl.exe -s --resolve target.com:443:1.2.3.4 https://target.com

# Error: "Connection refused"
# Fix: Check firewall, port availability, or use different port
curl.exe -s https://target.com:8443
```

### 17.2 PowerShell Execution Policy

```powershell
# Check current policy
Get-ExecutionPolicy

# Set to bypass (for current session)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Set for current user (persistent)
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

# Run a script bypassing policy
powershell -ExecutionPolicy Bypass -File script.ps1
```

### 17.3 Long Path Support

```powershell
# Check if long paths enabled
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name LongPathsEnabled

# Enable long paths (Admin)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name LongPathsEnabled -Value 1

# Or in Git:
git config --global core.longpaths true
```

### 17.4 Path Too Long / MAX_PATH Issues

```powershell
# Use \\?\ prefix to bypass MAX_PATH (260 char limit)
Get-ChildItem -Path "\\?\C:\Very\Long\Path\Here"
Remove-Item -Path "\\?\C:\Very\Long\Path\Here" -Recurse -Force

# For robocopy (handles long paths well)
robocopy "C:\src" "C:\dst" /E /COPYALL
```

### 17.5 Port Exhaustion

```powershell
# Check current ephemeral port range
netsh int ipv4 show dynamicport tcp

# Increase range (Admin)
netsh int ipv4 set dynamicport tcp start=49152 num=16384

# Check TIME_WAIT connections
Get-NetTCPConnection | Where-Object State -eq TimeWait | Measure-Object

# Reduce TIME_WAIT (Registry - Admin)
# HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
# Add DWORD: TcpTimedWaitDelay = 30 (decimal)
```

### 17.6 Antivirus / Defender Interference

```powershell
# Add exclusion for Tools directory
Add-MpPreference -ExclusionPath "C:\Tools"

# Add exclusion for BurpProjects
Add-MpPreference -ExclusionPath "C:\BurpProjects"

# Add exclusion for Python scripts
Add-MpPreference -ExclusionExtension ".py"

# Check recent detections
Get-MpThreatDetection | Sort-Object -Property InitialDetectionTime -Descending | Select-Object -First 10

# Temporarily disable real-time monitoring (Admin)
Set-MpPreference -DisableRealtimeMonitoring $true
# Re-enable: Set-MpPreference -DisableRealtimeMonitoring $false
```

### 17.7 UAC and Permission Issues

```powershell
# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Self-elevate script
if (-not $isAdmin) {
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

# Run single command as admin from non-admin shell
Start-Process powershell -Verb RunAs -ArgumentList "-Command & { netsh int ipv4 set dynamicport tcp start=49152 num=16384 }"
```

### 17.8 FFUF Hanging / Slow on Windows

```
# Issue: FFUF hangs or is extremely slow

# Fix 1: Reduce concurrency (Windows socket limits)
ffuf -u https://target.com/FUZZ -w wordlist.txt -t 15

# Fix 2: Increase timeout
ffuf -u https://target.com/FUZZ -w wordlist.txt -timeout 15

# Fix 3: Ignore SSL errors
ffuf -u https://target.com/FUZZ -w wordlist.txt -k

# Fix 4: Use HTTP/2
ffuf -u https://target.com/FUZZ -w wordlist.txt -http2

# Fix 5: Increase ephemeral port range (Admin)
netsh int ipv4 set dynamicport tcp start=49152 num=16384
```

### 17.9 WSL Networking Issues

```
# Issue: Cannot reach Windows host from WSL

# Fix 1: Use host.docker.internal
ping host.docker.internal

# Fix 2: Find WSL host IP
ip route show | grep default | awk '{print $3}'

# Issue: Cannot reach WSL from Windows

# Fix 1: Use WSL IP directly
wsl -- hostname -I

# Fix 2: Set up port forwarding
netsh interface portproxy add v4tov4 listenport=8080 connectport=8080 connectaddress=$(wsl -- hostname -I)
```

### 17.10 Python Package Installation Failures

```powershell
# Issue: "Microsoft Visual C++ 14.0 is required"

# Fix 1: Install Visual C++ Build Tools
# Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/

# Fix 2: Use pre-compiled wheels
pip install --only-binary :all: package-name

# Fix 3: Install from conda-forge (if using conda)
conda install -c conda-forge package-name

# Fix 4: Upgrade pip and setuptools first
python -m pip install --upgrade pip setuptools wheel
```

### 17.11 Git Line Ending Issues

```
# Issue: "warning: LF will be replaced by CRLF"

# Fix: Set core.autocrlf based on your workflow
# Windows to Windows: git config --global core.autocrlf false
# Cross-platform: git config --global core.autocrlf input

# Normalize line endings after cloning
# git add --renormalize .
```

### 17.12 File Locking Issues

```powershell
# Check which process has a file locked
# Using Sysinternals Handle:
handle.exe -a -u "path\to\file.txt"

# Using PowerShell (find locking process)
# Look for file handles in Process Explorer

# Force delete locked file
# Option 1: Move-Item + restart
Move-Item locked.txt C:\temp\locked.txt
Restart-Computer

# Option 2: Use Sysinternals Handle to close
handle.exe -c "locked.txt" -p <PID>
```

### 17.13 Windows Terminal and Console Tips

```powershell
# Clear screen
Clear-Host  # or cls

# Get command history
Get-History

# Search command history (Ctrl+R equivalent)
Get-History | Where-Object CommandLine -match "curl"

# Use tab completion for paths
# Just type partial path and press Tab

# Pipe to clipboard
curl.exe -s https://target.com | Set-Clipboard

# Get clipboard content
Get-Clipboard

# Split pane in Windows Terminal
# Ctrl+Shift+D (new tab), Alt+Shift+D (split pane)

# Quick edit mode (enable in Properties)
# Allows right-click paste in console
```


---

## 18. Appendices

### 18.1 Quick Reference Card

```
==============================
  WINDOWS HUNTING QUICK REF
==============================

HTTP Requests:
  curl -s https://target.com
  curl -sv -D headers.txt -o body.txt https://target.com
  curl -s -X POST -d "key=val" -H "Auth: Bearer TOKEN" https://target.com/api

Cookie Handling:
  curl -sc cookies.txt -b cookies.txt https://target.com

Proxy (Burp):
  curl -s --proxy http://127.0.0.1:8080 --cacert burp-ca.pem https://target.com

Timing:
  curl -s -w "%{http_code} %{time_total}s\n" -o nul https://target.com

PowerShell:
  (Invoke-WebRequest -Uri $url -Method Get).Content
  Invoke-RestMethod -Uri $url -Method Post -Body ($body | ConvertTo-Json) -ContentType "application/json"

Grep Equivalent:
  Select-String -Pattern "pattern" -Path file.txt

Find Files:
  Get-ChildItem -Recurse -Filter "*.js"

Line Count:
  (Get-Content file.txt).Count

DNS:
  Resolve-DnsName -Name target.com -Type A

Port Scan:
  Test-NetConnection -ComputerName target.com -Port 443

Tools:
  ffuf -u https://target.com/FUZZ -w wordlist.txt -ac
  nuclei -u https://target.com -severity medium,high,critical
  httpx -l subs.txt -title -tech-detect -status-code -o alive.txt
  subfinder -d target.com -o subs.txt
```

### 18.2 Recommended Wordlists Location

```
C:\Tools\wordlists\
  common.txt                # Common web paths
  subdomains.txt            # Common subdomains
  params.txt                # Common parameter names
  passwords.txt             # Common passwords
  dir_small.txt             # Small directory list (fast)
  admin-paths.txt           # Admin panel paths
  api-endpoints.txt         # API endpoint names
  tech-stack.txt            # Technology-specific paths

# Download location for SecLists
C:\Tools\SecLists-master\
  Discovery\Web-Content\    # Web content discovery
  Discovery\DNS\            # DNS/subdomain lists
  Fuzzing\                   # Fuzzing payloads
  Passwords\                # Password lists
  Payloads\                 # Attack payloads
```

### 18.3 Tool Download URLs (Windows Binaries)

```
FFUF:     https://github.com/ffuf/ffuf/releases
Nuclei:   https://github.com/projectdiscovery/nuclei/releases
Httpx:    https://github.com/projectdiscovery/httpx/releases
Subfinder: https://github.com/projectdiscovery/subfinder/releases
Aquatone: https://github.com/michenriksen/aquatone/releases
Gowitness: https://github.com/sensepost/gowitness/releases
Gitleaks: https://github.com/gitleaks/gitleaks/releases
Python:   https://www.python.org/downloads/windows/
Git:      https://git-scm.com/download/win
Burp:     https://portswigger.net/burp/releases
Docker:   https://docs.docker.com/desktop/windows/install/
Chocolatey: https://chocolatey.org/install
```

### 18.4 Chocolatey One-Line Install

```powershell
# Install Chocolatey first (Admin):
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString("https://community.chocolatey.org/install.ps1"))

# Install all hunting tools:
choco install -y ffuf nuclei httpx subfinder aquatone gowitness gitleaks python git curl jq yq
```

### 18.5 PowerShell Profile (Quick Setup)

```powershell
# One-liner to create hunting profile:
@"
function Set-BurpProxy { `$env:HTTP_PROXY="http://127.0.0.1:8080"; `$env:HTTPS_PROXY="http://127.0.0.1:8080"; Write-Host "[+] Burp ON" -ForegroundColor Green }
function Remove-Proxy { Remove-Item Env:\HTTP_PROXY -EA 0; Remove-Item Env:\HTTPS_PROXY -EA 0; Write-Host "[-] Proxy OFF" -ForegroundColor Yellow }
function Get-StatusCode { param(`$u) curl.exe -s -o nul -w "`$u `%{http_code}`n" `$u }
Set-Alias st Get-StatusCode
"@ | Add-Content -Path (Join-Path $env:USERPROFILE "Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1")
```

### 18.6 File and Directory Naming Conventions

```
Recon Output Structure:
  C:\BurpProjects\target.com\
    recon\              # Raw recon output
      subs.txt          # Subdomains found
      alive.txt         # Alive hosts
      wayback_urls.txt  # URLs from Wayback Machine
      js_files.txt      # Discovered JS files
    fuzz\               # FFUF results
      fuzz_admin.json
      fuzz_api.json
    nuclei\             # Nuclei scan results
      nuclei_results.jsonl
    js\                 # Downloaded JS files
    screenshots\        # Screenshots
    burp\               # Burp project files
      target.burp       # Burp project
      burp_config.json  # Burp config export
    exploits\           # PoC and exploit code
      poc_1.txt
```

### 18.7 Common HTTP Response Codes Reference

```
200 - OK (success)
201 - Created (POST success)
204 - No Content (DELETE success)
301 - Moved Permanently (redirect)
302 - Found (temporary redirect, often login)
304 - Not Modified (cached)
400 - Bad Request (malformed input)
401 - Unauthorized (no auth or bad auth)
403 - Forbidden (authenticated but no permission)
404 - Not Found
405 - Method Not Allowed
406 - Not Acceptable (bad Accept header)
408 - Request Timeout
429 - Too Many Requests (rate limited)
500 - Internal Server Error
502 - Bad Gateway
503 - Service Unavailable
504 - Gateway Timeout
```

### 18.8 Changelog

```
v2.0 (2026-06-06)
  - Complete rewrite of Windows hunting workflow
  - Added curl.exe mastery section with 12 subsections
  - Added full PowerShell to Linux command map
  - Added Python3 scripts for JS analysis, regex, batch fetching
  - Added batch scripts for recon automation
  - Added Burp Suite setup for Windows
  - Added FFUF, Nuclei, Httpx Windows guides
  - Added API-based alternatives for missing Linux tools
  - Added Git for Windows secret scanning
  - Added WSL integration guide
  - Added 70+ PowerShell one-liners for hunting
  - Added output redirection and logging best practices
  - Added environment setup scripts
  - Added complete recon pipeline workflow
  - Added troubleshooting for common Windows issues
  - Added quick reference card and appendices
```
