# Tasks — Recon Tasks

Reconnaissance task definitions. Each recon task is a specific set of
operations to discover assets, enumerate attack surface, and map the
target's infrastructure.

---

## Table of Contents

1. [Recon Overview](#1-recon-overview)
2. [Subdomain Enumeration](#2-subdomain-enumeration)
3. [Live Host Discovery](#3-live-host-discovery)
4. [URL Crawling](#4-url-crawling)
5. [Technology Fingerprinting](#5-technology-fingerprinting)
6. [Directory Fuzzing](#6-directory-fuzzing)
7. [JS Bundle Discovery](#7-js-bundle-discovery)
8. [Certificate Transparency](#8-certificate-transparency)
9. [DNS Enumeration](#9-dns-enumeration)
10. [Port Scanning](#10-port-scanning)
11. [Cloud Asset Enumeration](#11-cloud-asset-enumeration)
12. [Recon Task History](#12-recon-task-history)
13. [Recon Templates](#13-recon-templates)
14. [Maintenance](#14-maintenance)

---

## 1. Recon Overview

### 1.1 Summary

```
COMPLETED RECON TASKS: [N]
DOMAINS ENUMERATED: [N]
SUBDOMAINS DISCOVERED: [N]
LIVE HOSTS FOUND: [N]
ENDPOINTS DISCOVERED: [N]
JS BUNDLES ANALYZED: [N]
SECRETS FOUND IN JS: [N]
```

### 1.2 Task ID Format

```
RECON TASK ID: RTASK-{type}-{YYMMDD}-{XXX}
  type: SUB (subdomains), LIVE (live hosts), URL (URL crawl),
        TECH (fingerprinting), DIR (directory fuzz), JS (JS analysis),
        CRT (certificate), DNS (DNS enum), PORT (port scan),
        CLOUD (cloud assets)

Example: RTASK-SUB-240607-001
```

---

## 2. Subdomain Enumeration

### 2.1 Task: Full Subdomain Enumeration

```
RTASK ID: RTASK-SUB-240607-001
TARGET:  example.com
STATUS:  Planned
TOOLS:   subfinder, chaos, assetfinder, amass

PASSIVE:
  subfinder -d example.com -o subdomains-passive.txt
  chaos -d example.com -o subdomains-chaos.txt
  assetfinder --subs-only example.com > subdomains-assetfinder.txt

CERTIFICATE TRANSPARENCY:
  curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u > subdomains-crtsh.txt

ACTIVE:
  subfinder -d example.com -recursive -o subdomains-all.txt
  # Amass (if installed):
  # amass enum -d example.com -o subdomains-amass.txt

COMBINE:
  Get-Content subdomains-*.txt | Sort-Object -Unique > subdomains-total.txt
  Write-Host "Total subdomains: $(@(Get-Content subdomains-total.txt).Count)"
```

### 2.2 Subdomain Discovery Log

```
| Target | Source | Subdomains Found | Date | Status |
|--------|--------|-----------------|------|--------|
| example.com | subfinder | 45 | 2026-06-02 | Complete |
| example.com | chaos | 32 | 2026-06-02 | Complete |
| example.com | assetfinder | 28 | 2026-06-02 | Complete |
| example.com | crt.sh | 67 | 2026-06-02 | Complete |
| example.com | Combined unique | 98 | 2026-06-02 | Complete |
| example.com | Recursive subfinder | 15 new | 2026-06-02 | Complete |
```

### 2.3 Interesting Subdomains

```
INTERESTING SUBDOMAINS (example.com):
  app.example.com — Main application
  api.example.com — API server
  admin.example.com — Admin panel
  dev.example.com — Development environment
  staging.example.com — Staging environment
  cdn.example.com — CDN
  mail.example.com — Mail server
  docs.example.com — Documentation
  status.example.com — Status page
  static.example.com — Static assets
  vpn.example.com — VPN gateway
  remote.example.com — Remote access
  support.example.com — Support portal
  chat.example.com — Chat system
  blog.example.com — Blog (OOS)
```

---

## 3. Live Host Discovery

### 3.1 Task: Live Host Probing

```
RTASK ID: RTASK-LIVE-240607-001
TARGET:  subdomains-total.txt (from subdomain enum)
STATUS:  Planned
TOOLS:   httpx, dnsx

HTTPX:
  httpx -l subdomains-total.txt -o live-http.txt \
        -title -tech-detect -status-code -follow-redirects
  httpx -l subdomains-total.txt -o live-all.txt \
        -ports 80,443,8080,8443,3000 -x HEAD,GET

DNSX:
  dnsx -l subdomains-total.txt -a -aaaa -cname -ns -mx -soa \
       -o dns-records.txt

COMBINE:
  Get-Content live-http.txt | ForEach-Object {
    $parts = $_ -split ' '
    [PSCustomObject]@{
      URL = $parts[0]
      Status = $parts[1]
      Title = $parts[2]
      Tech = $parts[3]
    }
  } | Sort-Object Status > live-hosts-summary.txt
```

### 3.2 Live Host Summary

```
| Host | Status | Title | Tech | Screenshot |
|------|--------|-------|------|------------|
| app.example.com | 200 | App Name | React 18, Node.js | ✅ |
| api.example.com | 200 | — | Express, Node.js | ✅ |
| admin.example.com | 302 | Redirect | — | ✅ |
| www.example.com | 200 | App Name | React 18 | ✅ |
| cdn.example.com | 403 | Forbidden | Cloudflare | ✅ |
| blog.example.com | 200 | Blog | WordPress | ❌ OOS |
| docs.example.com | 200 | Docs | MDX, Next.js | ✅ |
```

### 3.3 Status Code Distribution

```
| Status Code | Count | Meaning |
|-------------|-------|---------|
| 200 | 5 | Active web server |
| 302 | 2 | Redirect (login portal?) |
| 403 | 3 | Forbidden (possibly admin) |
| 401 | 1 | Unauthorized (requires auth) |
| 404 | 2 | Not found (dead subdomain) |
| 503 | 0 | Service unavailable |
| No response | 3 | Blocked or no web server |
```

---

## 4. URL Crawling

### 4.1 Task: URL Collection

```
RTASK ID: RTASK-URL-240607-001
TARGET:  example.com (live hosts)
STATUS:  Planned
TOOLS:   katana, waybackurls, gau

WAYBACK MACHINE:
  waybackurls example.com > urls-wayback.txt
  gau --subs example.com > urls-gau.txt

KATANA CRAWL:
  katana -u https://app.example.com -d 3 -o urls-katana.txt
  katana -u https://api.example.com -d 3 -o urls-api.txt
  katana -u https://admin.example.com -d 2 -o urls-admin.txt

COMBINE:
  Get-Content urls-*.txt | Sort-Object -Unique > urls-total.txt
  Write-Host "Total URLs: $(@(Get-Content urls-total.txt).Count)"
```

### 4.2 URL Breakdown

```
ENDPOINTS BY TYPE:
  REST API endpoints: [N]
  Web pages: [N]
  Static files: [N]
  Admin panels: [N]
  API docs: [N]
  Login pages: [N]
  File upload endpoints: [N]
  Redirects: [N]
  GraphQL endpoints: [N]
```

### 4.3 Interesting Endpoints

```
API ENDPOINTS:
  POST /api/auth/login
  POST /api/auth/register
  POST /api/auth/refresh
  GET /api/v2/users/{id}
  PUT /api/v2/users/{id}/profile
  POST /api/avatar
  GET /api/v2/orders
  GET /api/v2/invoices
  POST /api/forgot-password
  POST /api/reset-password

ADMIN ENDPOINTS:
  GET /admin
  GET /admin/dashboard
  GET /admin/users
  GET /admin/settings

FILE UPLOAD:
  POST /api/avatar
  POST /api/upload
  POST /api/attachments

POSSIBLE VULNERABLE PARAMETERS:
  ?url= (SSRF)
  ?file= (Path traversal)
  ?redirect= (Open redirect)
  ?id= (IDOR)
  ?next= (Open redirect)
  ?return= (Open redirect)
```

---

## 5. Technology Fingerprinting

### 5.1 Task: Tech Stack Identification

```
RTASK ID: RTASK-TECH-240607-001
TARGET:  live hosts (from live host discovery)
STATUS:  Planned
TOOLS:   httpx, wappalyzer, whatweb

FINGERPRINT:
  httpx -l live-http.txt -tech-detect -o tech-stack.txt
  # wappalyzer (if installed):
  # wappalyzer -u https://app.example.com -o tech-wappalyzer.json

HEADER ANALYSIS:
  curl -sI https://app.example.com | Select-String -Pattern "Server:|X-Powered-By:|X-Framework:"
  curl -sI https://api.example.com | Select-String -Pattern "Server:|X-Powered-By:|X-Framework:"
```

### 5.2 Technology Summary

```
| Host | Tech Stack | Server | Notes |
|------|-----------|--------|-------|
| app.example.com | React 18, Node.js, Express 4 | nginx 1.24 | SPA |
| api.example.com | Node.js, Express 4, JWT auth | nginx 1.24 | REST API |
| admin.example.com | React 18, Node.js | nginx 1.24 | Protected |
| cdn.example.com | — | Cloudflare | CDN |
| docs.example.com | Next.js | Vercel | Static docs |
| status.example.com | — | Statuspage.io | Third-party |
```

### 5.3 Version-Based Attack Surface

```
NGINX 1.24:
  - CVE-2023-44487 (HTTP/2 rapid reset) — Medium
  - No known critical CVEs for 1.24

NODE.JS / EXPRESS 4:
  - Prototype pollution via __proto__
  - Express 4 known default vulnerabilities:
    - Open redirect via res.redirect()
    - X-Powered-By header disclosure
    - No CSRF protection by default

REACT 18:
  - Client-side rendering, API keys in JS bundles
  - SPA routing — API endpoints exposed in JS

JWT AUTH:
  - Common JWT implementation flaws (alg:none, weak secret)
  - Check /.well-known/jwks.json
```

---

## 6. Directory Fuzzing

### 6.1 Task: Directory Discovery

```
RTASK ID: RTASK-DIR-240607-001
TARGET:  example.com (all live hosts)
STATUS:  Planned
TOOLS:   ffuf

FFUF DIRECTORIES:
  ffuf -u https://app.example.com/FUZZ -w wordlists/common.txt \
       -o fuzz-app.txt
  ffuf -u https://api.example.com/FUZZ -w wordlists/api.txt \
       -o fuzz-api.txt
  ffuf -u https://admin.example.com/FUZZ -w wordlists/admin.txt \
       -o fuzz-admin.txt
  ffuf -u https://app.example.com/FUZZ -w wordlists/params.txt \
       -o fuzz-params.txt

WORDLISTS USED:
  wordlists/common.txt — 5,000 common paths
  wordlists/api.txt — 1,500 API paths
  wordlists/admin.txt — 2,000 admin paths
  wordlists/params.txt — 500 parameter names
  wordlists/tech-specific.txt — Tech-specific paths
```

### 6.2 Fuzzing Results

```
APPLICATION DIRECTORIES (app.example.com):
  /api — API endpoints
  /static — Static assets
  /assets — Assets directory
  /images — Images
  /uploads — Uploaded files
  /sw.js — Service worker
  /sitemap.xml — Sitemap

API ENDPOINTS (api.example.com):
  /v1 — API v1 endpoints
  /v2 — API v2 endpoints
  /health — Health check
  /docs — API documentation
  /swagger.json — Swagger spec

ADMIN PATHS (admin.example.com):
  /login — Admin login
  /dashboard — Admin dashboard (redirect to login)
  /users — User management
  /config — Configuration (403)
  /logs — Logs (403)
```

---

## 7. JS Bundle Discovery

### 7.1 Task: JavaScript Analysis

```
RTASK ID: RTASK-JS-240607-001
TARGET:  app.example.com
STATUS:  Planned
TOOLS:   js-analyzer.ps1, python-hunter.py

JS DISCOVERY:
  Get-Content urls-total.txt | Where-Object {$_ -match '\.js'} > js-files.txt
  # Or use LinkFinder:
  # python linkfinder.py -i https://app.example.com -o cli

JS DOWNLOAD:
  foreach ($js in Get-Content js-files.txt) {
    $filename = [System.IO.Path]::GetFileName($js)
    curl -s "$js" -o "storage/js-bundles/$filename"
  }

JS ANALYSIS:
  . .\tools\powershell\js-analyzer.ps1
  Invoke-FullJsScan -BundlePath "storage/js-bundles"

  python .\tools\python\python-hunter.py scan --dir storage/js-bundles

SECRET SCANNING:
  . .\tools\powershell\recon-toolkit.ps1
  Invoke-SecretScan -Path "storage/js-bundles"
```

### 7.2 Bundle Summary

```
| Bundle | Size | Endpoints Found | Secrets Found | Has Map |
|--------|------|----------------|---------------|---------|
| main.abc123.js | 2.3MB | 45 | 3 | Yes |
| vendor.def456.js | 1.8MB | 12 | 1 | Yes |
| admin.ghi789.js | 890KB | 28 | 2 | No |
| chunk.jkl012.js | 450KB | 8 | 0 | No |
```

### 7.3 Secrets Found

```
SECRETS IN JS BUNDLES:
  Type: Stripe publishable key
  Value: pk_live_XXXXXXXXXXXXXXXXXXXXXXXX
  File: vendor.def456.js:2391
  Severity: Low (publishable key, but hardcoded)
  Action: Check for test/live key, report if live key

  Type: Internal API endpoint
  Value: https://internal-api.example.com/v2/
  File: main.abc123.js:4521
  Severity: Medium (internal endpoint exposed)
  Action: Check if internal API is accessible from external
```

---

## 8. Certificate Transparency

### 8.1 Task: CT Log Analysis

```
RTASK ID: RTASK-CRT-240607-001
TARGET:  example.com
STATUS:  Planned
TOOLS:   crt.sh, certspotter

CRT.SH:
  curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u > crtsh-results.txt

CERTSPOTTER:
  curl -s "https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' | sort -u > certspotter-results.txt

COMBINE:
  Get-Content crtsh-results.txt, certspotter-results.txt | Sort-Object -Unique
```

### 8.2 CT Results

```
UNIQUE SUBDOMAINS FROM CT LOGS: [N]
NEW SUBDOMAINS NOT FOUND BY OTHER METHODS: [N]

EXAMPLES:
  *.blog.example.com (found in CT, matched OOS)
  *.staging.example.com (found in CT, not in subfinder)
  *.dev.example.com (found in CT)
  *.vpn.example.com (found in CT, high value target)
```

---

## 9. DNS Enumeration

### 9.1 Task: DNS Record Collection

```
RTASK ID: RTASK-DNS-240607-001
TARGET:  example.com
STATUS:  Planned
TOOLS:   dnsx, nslookup, dig (if available)

A RECORDS:
  nslookup example.com
  ForEach ($sub in Get-Content subdomains-total.txt) {
    nslookup $sub
  }

CNAME RECORDS:
  dnsx -l subdomains-total.txt -cname -o dns-cname.txt
  # Check for takeovers
  Get-Content dns-cname.txt | Where-Object {$_ -match 's3|cloudfront|azure|github|heroku|shopify'}

MX RECORDS:
  dnsx -l subdomains-total.txt -mx -o dns-mx.txt

TXT RECORDS:
  dnsx -l subdomains-total.txt -txt -o dns-txt.txt
```

### 9.2 DNS Findings

```
POTENTIAL SUBDOMAIN TAKEOVERS:
  staging.example.com → staging-bucket.s3.amazonaws.com
    Status: S3 bucket exists, but not owned by example.com
    Check: Try to claim the bucket

  docs.example.com → example.github.io
    Status: GitHub Pages, 404 not found
    Check: Takeover possible

INTERESTING TXT RECORDS:
  example.com → "v=spf1 include:_spf.google.com ~all"
    Notes: Using Google Workspace

  _dmarc.example.com → "v=DMARC1; p=reject;"
    Notes: DMARC reject policy
```

---

## 10. Port Scanning

### 10.1 Task: Port Scan

```
RTASK ID: RTASK-PORT-240607-001
TARGET:  example.com (key hosts)
STATUS:  Planned
TOOLS:   naabu (if installed), telnet, Test-NetConnection

LIGHT SCAN:
  naabu -host app.example.com -top-ports 1000 -o ports-app.txt
  naabu -host api.example.com -top-ports 1000 -o ports-api.txt
  naabu -host admin.example.com -top-ports 1000 -o ports-admin.txt

POWERSHELL:
  $ports = @(80,443,22,21,3306,5432,27017,6379,9200,8080,8443,3000,5000,8000,9000,9090)
  ForEach ($hostname in @("app.example.com","api.example.com","admin.example.com")) {
    ForEach ($port in $ports) {
      $result = Test-NetConnection -ComputerName $hostname -Port $port -WarningAction SilentlyContinue
      if ($result.TcpTestSucceeded) {
        Write-Host "$hostname`:$port OPEN"
      }
    }
  }
```

### 10.2 Open Ports Summary

```
app.example.com:
  [OPEN] 80/tcp — HTTP (redirects to 443)
  [OPEN] 443/tcp — HTTPS
  [OPEN] 8080/tcp — HTTP (possible dev server)

api.example.com:
  [OPEN] 443/tcp — HTTPS
  [CLOSED] 3306 — MySQL (not exposed)
  [CLOSED] 6379 — Redis (not exposed)

admin.example.com:
  [OPEN] 443/tcp — HTTPS
  [OPEN] 22/tcp — SSH (locked down, key-only)
```

---

## 11. Cloud Asset Enumeration

### 11.1 Task: Cloud Asset Discovery

```
RTASK ID: RTASK-CLOUD-240607-001
TARGET:  example.com
STATUS:  Planned
TOOLS:   curl, aws cli (if available)

S3 BUCKET ENUMERATION:
  ForEach ($bucket in Get-Content wordlists/s3-bucket-names.txt) {
    $url = "https://$bucket.s3.amazonaws.com"
    try {
      $req = [System.Net.WebRequest]::Create($url)
      $req.Method = "GET"
      $resp = $req.GetResponse()
      if ($resp.StatusCode -eq 200) {
        Write-Host "PUBLIC S3: $url"
      }
    } catch {
      # 403 or 404 — not public
    }
  }

CLOUDFRONT:
  curl -sI https://cdn.example.com | Select-String "X-Amz-Cf-Id|X-CloudFront-ID"
  # Check if CloudFront origin is exposed
  # Try accessing origin directly
```

### 11.2 Cloud Assets Found

```
S3 BUCKETS:
  example-assets.s3.amazonaws.com — PUBLIC (read-only)
  example-backups.s3.amazonaws.com — 403 (maybe restricted)
  example-media.s3.amazonaws.com — PUBLIC (readable)

CLOUDFRONT:
  d123.cloudfront.net — CDN distribution
  Origin: app.example.com (good — origin isn't directly exposed)
```

---

## 12. Recon Task History

### 12.1 Completed Recon Tasks

```
| Task ID | Description | Target | Date | Results |
|---------|-------------|--------|------|---------|
| RTASK-SUB-240602-001 | Subdomain enumeration | example.com | 2026-06-02 | 98 subdomains |
| RTASK-LIVE-240602-001 | Live host probing | example.com | 2026-06-02 | 8 live hosts |
| RTASK-URL-240602-001 | URL crawling | example.com | 2026-06-02 | 2,450 URLs |
| RTASK-TECH-240602-001 | Tech fingerprinting | example.com | 2026-06-02 | 6 tech stacks |
| RTASK-DIR-240603-001 | Directory fuzzing | example.com | 2026-06-03 | 42 paths |
| RTASK-JS-240603-001 | JS bundle analysis | example.com | 2026-06-03 | 4 bundles, 3 secrets |
| RTASK-CRT-240602-001 | CT log analysis | example.com | 2026-06-02 | 112 entries |
| RTASK-DNS-240603-001 | DNS enumeration | example.com | 2026-06-03 | 2 potential takeovers |
| RTASK-PORT-240603-001 | Port scanning | example.com | 2026-06-03 | 3 open ports |
| RTASK-CLOUD-240604-001 | Cloud asset enumeration | example.com | 2026-06-04 | 3 S3 buckets |
```

### 12.2 Recon Findings Summary

```
CRITICAL:
  - 3 public S3 buckets (data exposure risk)
  - 2 potential subdomain takeovers

HIGH:
  - 3 secrets found in JS bundles
  - Internal API endpoint exposed in JS
  - Dev server running on port 8080

MEDIUM:
  - CMS admin panel exposed (blog — OOS)
  - API documentation public (swagger)
  - Stack trace errors visible on some endpoints (TODO: check)
```

---

## 13. Recon Templates

### 13.1 Full Recon Pipeline Template

```
# Full Recon Pipeline

## Phase 1: Subdomain Enumeration
[ ] Passive: subfinder, chaos, assetfinder
[ ] Certificate: crt.sh, certspotter
[ ] Active: recursive subfinder
[ ] Combine & deduplicate

## Phase 2: Live Host Discovery
[ ] HTTP probing (httpx)
[ ] DNS records (dnsx)
[ ] Status code classification

## Phase 3: URL Collection
[ ] Wayback machine (waybackurls)
[ ] Crawl (katana)
[ ] API endpoint extraction

## Phase 4: Technology Fingerprinting
[ ] Tech detection (httpx, wappalyzer)
[ ] Header analysis
[ ] Version-based CVE mapping

## Phase 5: Directory Fuzzing
[ ] Common paths
[ ] API paths
[ ] Admin paths
[ ] Parameter discovery

## Phase 6: JavaScript Analysis
[ ] JS bundle download
[ ] Secret scanning
[ ] Endpoint extraction
[ ] Deobfuscation if needed

## Phase 7: Infrastructure
[ ] DNS record analysis
[ ] Certificate transparency
[ ] Port scanning
[ ] Cloud asset enumeration

## Phase 8: Output
[ ] Compile all findings
[ ] Prioritize attack surface
[ ] Create target-registry entry
[ ] Set hunting priorities
```

### 13.2 Quick Recon Template

```
# Quick Recon (30 min)

[ ] subfinder -d example.com | httpx | tee recon-quick.txt
[ ] waybackurls example.com | sort -u > urls.txt
[ ] curl -sI https://app.example.com
[ ] open https://app.example.com (manual review)
[ ] Check for /.well-known/ paths
[ ] Check for JS bundles in page source
[ ] Initial endpoint list compiled
```

---

## 14. Maintenance

```
DAILY:
  [ ] Process any new subdomains found during hunting
  [ ] Check new JS bundle alerts
  [ ] Verify CT logs for new subdomains

WEEKLY:
  [ ] Run full recon pipeline for active targets
  [ ] Check subdomain takeover candidates
  [ ] Review new JS bundles for secrets
  [ ] Update recon-results in target-registry

MONTHLY:
  [ ] Full infrastructure reassessment
  [ ] Update wordlists with new patterns
  [ ] Review disclosed reports for recon techniques
  [ ] Test new recon tools
```

---

*End of recon-tasks.md*
