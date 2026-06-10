# Tasks — Threat Modeling for Target

Pre-hunt target analysis and attack surface mapping. Produces a target brief that focuses hunting effort on high-value areas and likely bug classes before any active testing begins.

---

## Table of Contents

1. [Threat Modeling Overview](#1-threat-modeling-overview)
2. [Target Reconnaissance](#2-target-reconnaissance)
3. [Scope Definition](#3-scope-definition)
4. [Technology Stack Analysis](#4-technology-stack-analysis)
5. [Trust Boundary Mapping](#5-trust-boundary-mapping)
6. [High-Value Feature Identification](#6-high-value-feature-identification)
7. [Past Report Research](#7-past-report-research)
8. [Attack Surface Summary](#8-attack-surface-summary)
9. [Hunting Strategy](#9-hunting-strategy)
10. [Threat Model Templates](#10-threat-model-templates)
11. [Maintenance](#11-maintenance)

---

## 1. Threat Modeling Overview

### 1.1 Summary

```
TARGETS MODELED: [N]
ATTACK SURFACES MAPPED: [N]
HIGH-VALUE TARGETS IDENTIFIED: [N]
RECOMMENDED BUG CLASSES: [N]

MODEL ACCURACY:
  Predictions correct: [N]%
  Unexpected findings: [N]
  Missed attack surface: [N]
```

### 1.2 Task ID Format

```
THREAT MODEL TASK ID: TTMODEL-{target_hash}-{YYMMDD}
  target_hash: First 3 chars of target domain
  YYMMDD: Date of model creation

Example: TTMODEL-exa-240607
```

### 1.3 Threat Model Lifecycle

```
TARGET IDENTIFIED → PASSIVE RECON → TECH STACK ANALYSIS
    → TRUST BOUNDARY MAPPING → HIGH-VALUE FEATURE ID
    → PAST REPORT RESEARCH → ATTACK SURFACE SUMMARY
    → HUNTING STRATEGY → ACTIVE HUNTING
```

---

## 2. Target Reconnaissance

### 2.1 Task: Passive Reconnaissance

```
TASK ID: TTMODEL-RECON-001
TARGET: example.com
STATUS: Planned
TOOLS: subfinder, chaos, crt.sh, waybackurls, gau

PASSIVE RECON STEPS:
  [ ] Subdomain enumeration (passive only)
  [ ] Certificate transparency logs
  [ ] Wayback Machine historical URLs
  [ ] GitHub code search for target mentions
  [ ] Public API documentation
  [ ] Technology stack from public sources

RECON COMMANDS:
  # Subdomains
  subfinder -d example.com -o subdomains-passive.txt
  chaos -d example.com -o subdomains-chaos.txt
  curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u > subdomains-crtsh.txt

  # Historical URLs
  waybackurls example.com > urls-wayback.txt
  gau --subs example.com > urls-gau.txt

  # GitHub search
  gh search code "example.com" --limit 100 | cut -d' ' -f1 > github-mentions.txt

  # Technology detection
  httpx -l subdomains-passive.txt -tech-detect -o tech-detected.txt
```

### 2.2 Recon Data Collection

```
SUBDOMAIN DISCOVERY:
  Total subdomains: [N]
  Interesting subdomains:
    - app.example.com (main application)
    - api.example.com (API server)
    - admin.example.com (admin panel)
    - dev.example.com (development)
    - staging.example.com (staging)
    - cdn.example.com (CDN)
    - mail.example.com (mail server)

HISTORICAL URL DISCOVERY:
  Total URLs: [N]
  Interesting endpoints:
    - /api/v2/users/{id} (IDOR candidate)
    - /api/avatar (SSRF candidate)
    - /api/auth/login (auth testing)
    - /api/upload (file upload)
    - /graphql (GraphQL testing)

GITHUB FINDINGS:
  Repositories mentioning example.com: [N]
  Interesting findings:
    - API keys in old commits
    - Internal endpoints exposed
    - Configuration files
```

---

## 3. Scope Definition

### 3.1 Task: Define Testing Scope

```
TASK ID: TTMODEL-SCOPE-001
INPUT: Passive recon results + program rules
OUTPUT: recon/scope-definition.json

SCOPE DEFINITION:
  [ ] Read program rules and scope
  [ ] Identify in-scope domains/subdomains
  [ ] Identify out-of-scope domains/subdomains
  [ ] Identify excluded paths
  [ ] Identify excluded bug classes
  [ ] Document testing authorization

SCOPE DOCUMENTATION:
  In-scope:
    - *.example.com (wildcard)
    - api.example.com (explicit)
    - app.example.com (explicit)

  Out-of-scope:
    - *.staging.example.com
    - *.dev.example.com
    - blog.example.com
    - status.example.com (third-party)

  Excluded paths:
    - /logout
    - /static/*
    - /assets/*
    - /api/admin/test*

  Excluded bug classes:
    - CSRF (explicitly excluded by program)
    - Rate limiting (without ATO)
```

### 3.2 Scope Validation Commands

```powershell
# Validate scope before hunting
$config = Get-Content config/hunter-config.json | ConvertFrom-Json
$target = "example.com"

$inScope = $false
foreach ($pattern in $config.in_scope) {
  if ($target -like $pattern) {
    $inScope = $true
    break
  }
}

if (-not $inScope) {
  Write-Error "Target $target is OUT OF SCOPE"
  exit 1
}

Write-Host "Target $target is IN SCOPE"
Write-Host "Excluded bug classes: $($config.excluded_bug_classes -join ', ')"
Write-Host "Excluded paths: $($config.excluded_paths -join ', ')"
```

---

## 4. Technology Stack Analysis

### 4.1 Task: Identify Technology Stack

```
TASK ID: TTMODEL-TECH-001
TARGET: example.com (all subdomains)
STATUS: Planned
TOOLS: httpx, wappalyzer, whatweb, manual inspection

TECH STACK IDENTIFICATION:
  [ ] Web server detection (nginx, Apache, IIS)
  [ ] Framework detection (Express, Django, Rails)
  [ ] Language detection (Node.js, Python, PHP)
  [ ] Frontend framework (React, Angular, Vue)
  [ ] Database indicators
  [ ] CDN/WAF detection
  [ ] Authentication mechanism (JWT, session, OAuth)
  [ ] API style (REST, GraphQL, SOAP)

TECH STACK OUTPUT:
  | Host | Server | Framework | Language | Frontend | Auth | API |
  |------|--------|-----------|----------|----------|------|-----|
  | app.example.com | nginx 1.24 | Express 4 | Node.js | React 18 | JWT | REST |
  | api.example.com | nginx 1.24 | Express 4 | Node.js | — | JWT | REST |
  | admin.example.com | nginx 1.24 | Express 4 | Node.js | React 18 | JWT | REST |
```

### 4.2 Tech Stack Commands

```powershell
# Technology fingerprinting
$subdomains = Get-Content subdomains-passive.txt

foreach ($sub in $subdomains) {
  $url = "https://$sub"
  $tech = httpx -u $url -tech-detect -silent
  $headers = curl -sI $url | Select-String "Server:|X-Powered-By:|X-Framework:"
  
  Write-Host "$sub : $tech"
  Write-Host "  Headers: $headers"
}

# WAF detection
foreach ($sub in $subdomains) {
  $url = "https://$sub/<script>test"
  $response = curl -s -o NUL -w "%{http_code}" $url
  if ($response -eq "406" -or $response -eq "999") {
    Write-Host "$sub: Possible WAF detected (response: $response)"
  }
}
```

### 4.3 Version-Based Attack Surface

```
NGINX 1.24:
  Known CVEs:
    - CVE-2023-44487 (HTTP/2 rapid reset) - Medium
    - No critical CVEs for 1.24.x

NODE.JS / EXPRESS 4:
  Known issues:
    - Prototype pollution via __proto__
    - Open redirect via res.redirect()
    - X-Powered-By disclosure
    - No CSRF protection by default
    - Default CORS headers

REACT 18:
  Client-side rendering
  API keys potentially in JS bundles
  SPA routing exposes API endpoints

JWT AUTH:
  Common flaws:
    - alg:none acceptance
    - Weak HMAC secrets
    - RS256/HS256 confusion
    - kid path traversal
    - No expiration validation

RECOMMENDED TESTING:
  [ ] Check /.well-known/jwks.json
  [ ] Test JWT with alg:none
  [ ] Enumerate API endpoints from JS bundles
  [ ] Test prototype pollution
```

---

## 5. Trust Boundary Mapping

### 5.1 Task: Map Trust Boundaries

```
TASK ID: TTMODEL-TRUST-001
INPUT: Tech stack + architecture understanding
OUTPUT: recon/trust-boundaries.md

TRUST BOUNDARY ANALYSIS:
  [ ] Identify user roles and permissions
  [ ] Map internal vs external APIs
  [ ] Map data flows between services
  [ ] Identify authentication boundaries
  [ ] Identify authorization boundaries
  [ ] Map network segments (if discoverable)

TRUST ZONES:
  Zone 1: External (Internet)
    - Unauthenticated users
    - Public APIs
    - Static assets

  Zone 2: Authenticated (User)
    - Regular user accounts
    - User-specific data access
    - Profile management

  Zone 3: Privileged (Admin)
    - Admin accounts
    - Admin panel
    - User management
    - System configuration

  Zone 4: Internal (Services)
    - Internal APIs
    - Database access
    - Cloud metadata
    - Internal services (Redis, Elasticsearch)
```

### 5.2 Trust Boundary Diagram

```
┌─────────────────────────────────────────┐
│         EXTERNAL (Internet)              │
│  ┌─────────────┐    ┌───────────────┐  │
│  │ app.example │    │ api.example   │  │
│  │    .com     │    │   .com        │  │
│  └──────┬──────┘    └───────┬───────┘  │
│         │                   │           │
│         └─────────┬─────────┘           │
│                   ▼                     │
│  ┌──────────────────────────────────┐  │
│  │      AUTH BOUNDARY               │  │
│  │  (JWT validation, session check) │  │
│  └──────────────────────────────────┘  │
│                   │                     │
│         ┌─────────┴─────────┐           │
│         ▼                   ▼           │
│  ┌─────────────┐    ┌───────────────┐  │
│  │    USER     │    │     ADMIN     │  │
│  │   ZONE      │    │     ZONE      │  │
│  └──────┬──────┘    └───────┬───────┘  │
│         │                   │           │
│         └─────────┬─────────┘           │
│                   ▼                     │
│  ┌──────────────────────────────────┐  │
│  │      INTERNAL ZONE               │  │
│  │  (DB, Redis, internal APIs)      │  │
│  └──────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

---

## 6. High-Value Feature Identification

### 6.1 Task: Identify High-Value Features

```
TASK ID: TTMODEL-HVALUE-001
INPUT: URLs + tech stack + trust boundaries
OUTPUT: recon/high-value-features.md

HIGH-VALUE FEATURE CATEGORIES:
  [ ] Payment processing
  [ ] File uploads
  [ ] User management (CRUD)
  [ ] Password reset flows
  [ ] Email change flows
  [ ] Two-factor authentication
  [ ] Admin panels
  [ ] API key management
  [ ] Database access
  [ ] Internal service communication

FEATURE RANKING:
  P0 (Critical):
    - Payment processing endpoints
    - Admin panel
    - User management with role changes

  P1 (High):
    - File upload functionality
    - Password reset flows
    - Email/phone change flows

  P2 (Medium):
    - Profile updates
    - Search functionality
    - Comment/review systems

  P3 (Low):
    - Static content
    - Public documentation
    - Status pages
```

### 6.2 High-Value Feature Template

```markdown
# High-Value Feature: File Upload

## Feature Location
- Endpoint: POST /api/avatar
- Subdomain: api.example.com
- Authentication: Required (user role)

## Why High Value
- Direct file write to server
- Potential for RCE via webshell
- XXE via DOCX/SVG upload
- Path traversal via filename
- Storage of malicious content

## Attack Surface
- File type validation
- File content validation
- Filename sanitization
- Storage location
- Execution permissions on upload directory

## Recommended Tests
1. Webshell upload (PHP, ASP, JSP)
2. XXE in DOCX/SVG
3. Path traversal in filename
4. .htaccess upload
5. Polyglot files

## Tools
- tools/python/file_upload_hunter.py
- tools/bash/fuzzer-toolkit.sh
```

---

## 7. Past Report Research

### 7.1 Task: Research Past Disclosed Reports

```
TASK ID: TTMODEL-RESEARCH-001
TARGET: example.com
STATUS: Planned
SOURCES: HackerOne, Bugcrowd, Intigriti, GitHub Advisories

RESEARCH STEPS:
  [ ] Search HackerOne for example.com reports
  [ ] Search Bugcrowd for example.com reports
  [ ] Search CVE databases for used technologies
  [ ] Search GitHub for example.com issues
  [ ] Search Exploit-DB for example.com exploits
  [ ] Document known bug classes and fixed endpoints

RESEARCH COMMANDS:
  # HackerOne
  curl -s "https://hackerone.com/programs?query=example.com" | findstr "disclosed"

  # Bugcrowd
  curl -s "https://bugcrowd.com/programs?query=example.com" | findstr "disclosed"

  # CVE search for tech stack
  searchsploit nginx 1.24
  searchsploit express 4

RESEARCH OUTPUT:
  | Date | Platform | Bug Class | Endpoint | Status | Notes |
  |------|----------|-----------|----------|--------|-------|
  | 2025-12-15 | HackerOne | XSS | /search?q= | Fixed | Reflected XSS |
  | 2025-10-03 | HackerOne | IDOR | /api/v2/users/{id} | Fixed | Read IDOR |
  | 2025-08-20 | Bugcrowd | SSRF | /api/fetch | Fixed | Basic SSRF |
```

### 7.2 Research Summary

```
PAST FINDINGS FOR example.com:
  Total disclosed: [N]
  By bug class:
    XSS: [N]
    IDOR: [N]
    SSRF: [N]
    Auth Bypass: [N]
    File Upload: [N]

FIXED ENDPOINTS (avoid duplicates):
  - GET /search?q= (XSS - fixed)
  - GET /api/v2/users/{id} (IDOR read - fixed)
  - POST /api/fetch (SSRF - fixed)

STILL VULNERABLE? (check these):
  - PUT /api/v2/users/{id}/profile (IDOR write - not reported)
  - POST /api/avatar (SSRF - new parameter)
  - POST /api/auth/register (mass assignment - not reported)

NEW TECHNIQUES TO TRY:
  - SSRF with cloud metadata (new parameter)
  - IDOR write with email change (new impact)
  - JWT alg:none with new endpoints
```

---

## 8. Attack Surface Summary

### 8.1 Task: Generate Attack Surface Summary

```
TASK ID: TTMODEL-SUMMARY-001
INPUT: All threat model data
OUTPUT: recon/attack-surface-summary.md

ATTACK SURFACE SUMMARY:
  Total endpoints discovered: [N]
  High-value endpoints: [N]
  P1 targets: [N]
  P2 targets: [N]
  P3 targets: [N]

TOP 10 ENDPOINTS TO TEST:
  | Rank | Endpoint | Reason | Bug Class | Tool |
  |------|----------|--------|-----------|------|
  | 1 | POST /api/avatar | SSRF sink | SSRF | ssrf_hunter.py |
  | 2 | GET /api/v2/users/{id} | IDOR candidate | IDOR | idor_hunter.py |
  | 3 | PUT /api/v2/users/{id}/profile | IDOR write | IDOR | idor_hunter.py |
  | 4 | POST /api/auth/register | Mass assignment | IDOR | idor_hunter.py |
  | 5 | POST /api/auth/forgot-password | Auth bypass | auth_hunter.py |
  | 6 | /graphql | GraphQL | GraphQL | Manual |
  | 7 | GET /api/search?q= | XSS candidate | XSS | Manual |
  | 8 | POST /api/upload | File upload | FileUploadHunter | file_upload_hunter.py |
  | 9 | GET /admin/dashboard | Auth bypass | AuthBypassHunter | auth_hunter.py |
  | 10 | POST /api/auth/login | JWT testing | JWT | auth_hunter.py |
```

### 8.2 Attack Surface Commands

```powershell
# Generate attack surface summary
$assignments = Get-Content recon/bug-class-assignments.json | ConvertFrom-Json
$ranked = $assignments | Sort-Object score -Descending | Select-Object -First 10

Write-Host "TOP 10 ENDPOINTS TO TEST:"
Write-Host ""

$i = 1
foreach ($ep in $ranked) {
  Write-Host "$i. $($ep.method) $($ep.endpoint)"
  Write-Host "   Score: $($ep.score) | Priority: $($ep.priority)"
  Write-Host "   Bug Classes: $($ep.bug_classes)"
  Write-Host "   Agent: $($ep.agent)"
  Write-Host ""
  $i++
}
```

---

## 9. Hunting Strategy

### 9.1 Task: Develop Hunting Strategy

```
TASK ID: TTMODEL-STRATEGY-001
INPUT: Attack surface summary
OUTPUT: recon/hunting-strategy.md

HUNTING STRATEGY:
  Phase 1: P1 Targets (Day 1)
    - SSRF on /api/avatar
    - IDOR on /api/v2/users/{id}
    - IDOR write on profile update
    - Mass assignment on registration

  Phase 2: P2 Targets (Day 2-3)
    - Auth bypass on admin panel
    - File upload on /api/upload
    - GraphQL introspection
    - XSS on search

  Phase 3: P3 Targets (Day 4-5)
    - Business logic flaws
    - Race conditions
    - Subdomain takeover
    - Additional IDOR enumeration

TIME ALLOCATION:
  P1: 60% of hunting time
  P2: 30% of hunting time
  P3: 10% of hunting time

RECOMMENDED AGENT EXECUTION ORDER:
  1. ssrf-hunter (P1 SSRF)
  2. idor-hunter (P1 IDOR)
  3. auth-bypass-hunter (P1 auth)
  4. file-upload-hunter (P2 uploads)
  5. graphql-hunter (P2 GraphQL)
  6. xss-hunter (P2 XSS)
  7. business-logic-hunter (P3 logic)
  8. race-condition-hunter (P3 race)
```

---

## 10. Threat Model Templates

### 10.1 New Target Onboarding Template

```
THREAT MODEL: TTMODEL-{domain}-{date}

STEP 1: PASSIVE RECON
  [ ] Subdomain enumeration (passive)
  [ ] Certificate transparency
  [ ] Wayback Machine URLs
  [ ] GitHub code search
  [ ] Technology fingerprinting

STEP 2: SCOPE DEFINITION
  [ ] Read program rules
  [ ] Define in-scope assets
  [ ] Define out-of-scope assets
  [ ] Document exclusions

STEP 3: TECH STACK ANALYSIS
  [ ] Identify web server
  [ ] Identify framework
  [ ] Identify language
  [ ] Identify auth mechanism
  [ ] Identify API style

STEP 4: TRUST BOUNDARY MAPPING
  [ ] Map user roles
  [ ] Map internal/external APIs
  [ ] Map data flows
  [ ] Identify network segments

STEP 5: HIGH-VALUE FEATURE ID
  [ ] Payment processing
  [ ] File uploads
  [ ] User management
  [ ] Admin panels
  [ ] Password reset flows

STEP 6: PAST REPORT RESEARCH
  [ ] Search HackerOne
  [ ] Search Bugcrowd
  [ ] Search CVE databases
  [ ] Document findings

STEP 7: ATTACK SURFACE SUMMARY
  [ ] Rank all endpoints
  [ ] Assign bug classes
  [ ] Generate hunt plans
  [ ] Set timeboxes

OUTPUT: recon/attack-surface-summary.md
```

### 10.2 Threat Model Document Template

```markdown
# Threat Model: example.com

## Executive Summary
- Target: example.com
- Scope: *.example.com
- Technologies: Node.js, Express, React, JWT
- Top Risk: SSRF on /api/avatar, IDOR on user endpoints

## Attack Surface
- Total endpoints: 45
- High-value: 12
- P1: 8, P2: 25, P3: 12

## Recommended Hunt Order
1. SSRF (PLAN-SSRF-001)
2. IDOR (PLAN-IDOR-001)
3. JWT (PLAN-JWT-001)
4. File Upload (PLAN-UPLOAD-001)
5. Auth Bypass (PLAN-AUTH-001)

## Known Issues
- 3 XSS findings (fixed)
- 1 IDOR read (fixed)
- 1 SSRF (fixed)

## New Techniques to Try
- SSRF with cloud metadata
- IDOR write with email change
- JWT alg:none with new endpoints
```

---

## 11. Maintenance

### 11.1 Threat Model Updates

```
DAILY:
  [ ] Update if new subdomains discovered
  [ ] Update if new endpoints found
  [ ] Adjust attack surface rankings

WEEKLY:
  [ ] Re-run passive recon
  [ ] Check for new disclosed reports
  [ ] Update tech stack if changed
  [ ] Review hunting strategy effectiveness

MONTHLY:
  [ ] Full threat model refresh
  [ ] Re-research past reports
  [ ] Update high-value feature list
  [ ] Archive old threat models
```

### 11.2 Threat Model Accuracy Tracking

```
| Target | Predicted P1 | Actual P1 | Accuracy | Missed |
|--------|-------------|-----------|----------|--------|
| example.com | 3 | 3 | 100% | 0 |
| test.com | 2 | 3 | 67% | 1 |
| demo.com | 1 | 1 | 100% | 0 |
```

---

*End of threat-modeling.md*
