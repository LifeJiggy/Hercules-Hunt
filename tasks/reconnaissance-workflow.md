# Tasks — Reconnaissance to Hunt Workflow

Bridge recon output into actionable hunt plans with ranked targets and attack paths. Converts raw recon data into structured bug-class assignments and timeboxed hunt plans.

---

## Table of Contents

1. [Workflow Overview](#1-workflow-overview)
2. [Recon Input Processing](#2-recon-input-processing)
3. [Scope Validation](#3-scope-validation)
4. [Attack Surface Ranking](#4-attack-surface-ranking)
5. [Bug Class Assignment](#5-bug-class-assignment)
6. [Hunt Plan Generation](#6-hunt-plan-generation)
7. [Timeboxing Strategy](#7-timeboxing-strategy)
8. [Output Formats](#8-output-formats)
9. [Workflow Templates](#9-workflow-templates)
10. [Maintenance](#10-maintenance)

---

## 1. Workflow Overview

### 1.1 Summary

```
RECON WORKFLOWS COMPLETED: [N]
TARGETS PROCESSED: [N]
ENDPOINTS ANALYZED: [N]
HUNT PLANS GENERATED: [N]
BUG CLASSES ASSIGNED: [N]

ASSIGNMENTS BY BUG CLASS:
  SSRF: [N]
  IDOR: [N]
  JWT: [N]
  XSS: [N]
  Auth Bypass: [N]
  File Upload: [N]
  GraphQL: [N]
  Business Logic: [N]
  Race Condition: [N]
```

### 1.2 Workflow ID Format

```
WORKFLOW ID: WF-RECON-{YYMMDD}-{XXX}
  YYMMDD: Date of execution
  XXX:    Sequential number

Example: WF-RECON-240607-001
```

### 1.3 Workflow Lifecycle

```
RECON OUTPUT → SCOPE FILTER → ATTACK SURFACE RANK
    → BUG CLASS ASSIGN → HUNT PLAN GENERATE
    → TIMEBOX → ACTIVE HUNT PLAN
```

---

## 2. Recon Input Processing

### 2.1 Task: Load Recon Results

```
WF ID: WF-RECON-240607-001
TARGET: example.com
STATUS: Planned
INPUT: recon/output/

FILES TO LOAD:
  recon/output/subdomains-total.txt
  recon/output/live-http.txt
  recon/output/urls-total.txt
  recon/output/tech-stack.txt
  recon/output/js-bundles/
  recon/output/dns-records.txt

PROCESSING STEPS:
  [ ] Load subdomain list
  [ ] Load live hosts with tech stack
  [ ] Load discovered URLs
  [ ] Load JS bundle paths
  [ ] Load DNS records (CNAME, MX, TXT)
  [ ] Merge into unified attack surface map
```

### 2.2 Recon Data Validation

```
VALIDATION CHECKS:
  [ ] Subdomains count matches expected range
  [ ] Live hosts have status codes
  [ ] URLs have HTTP methods identified
  [ ] Tech stack populated for each host
  [ ] No duplicate entries
  [ ] Out-of-scope items flagged

COMMON ISSUES:
  - Subdomains without DNS resolution → skip
  - URLs from Wayback that are dead → mark as historical
  - JS bundles that failed to download → retry or skip
  - Tech stack missing for CDN hosts → acceptable
```

### 2.3 Recon Quality Metrics

```
RECON QUALITY SCORE:
  Subdomain coverage: [N] passive + [N] active sources
  Live host detection: [N] confirmed alive
  URL discovery: [N] unique endpoints
  JS analysis: [N] bundles, [N] secrets found
  DNS coverage: [N] record types checked

MINIMUM QUALITY THRESHOLD:
  - At least 3 subdomain sources used
  - Live host detection rate > 60%
  - URL discovery from 2+ sources (crawl + wayback)
  - Tech stack identified for 80%+ of live hosts
```

---

## 3. Scope Validation

### 3.1 Task: Filter In-Scope Assets

```
WF ID: WF-RECON-240607-002
INPUT: recon/output/ + config/hunter-config.json
OUTPUT: recon/attack-surface-scoped.json

SCOPE RULES FROM CONFIG:
  {
    "in_scope": [
      "*.example.com",
      "api.example.com",
      "app.example.com"
    ],
    "out_of_scope": [
      "blog.example.com",
      "status.example.com",
      "*.staging.example.com"
    ],
    "excluded_paths": [
      "/logout",
      "/static/*",
      "/assets/*"
    ]
  }

FILTERING LOGIC:
  [ ] Remove out-of-scope subdomains
  [ ] Flag excluded paths in URL list
  [ ] Keep wildcard in-scope domains
  [ ] Preserve sub-subdomains under in-scope wildcards
  [ ] Mark uncertain entries for manual review
```

### 3.2 Scope Validation Commands

```powershell
# Load config and filter subdomains
$config = Get-Content config/hunter-config.json | ConvertFrom-Json
$scope = $config.in_scope
$oos = $config.out_of_scope

$subdomains = Get-Content recon/output/subdomains-total.txt
$inScope = $subdomains | Where-Object {
  $sub = $_
  $in = $false
  foreach ($pattern in $scope) {
    if ($sub -like $pattern) { $in = $true; break }
  }
  $in
}

$outOfScope = $subdomains | Where-Object {
  $sub = $_
  $out = $false
  foreach ($pattern in $oos) {
    if ($sub -like $pattern) { $out = $true; break }
  }
  $out
}

Write-Host "In-scope: $($inScope.Count)"
Write-Host "Out-of-scope: $($outOfScope.Count)"
$inScope | Set-Content recon/attack-surface-scoped.json
```

### 3.3 Scope Decision Log

```
| Subdomain | Scope Decision | Reason |
|-----------|----------------|--------|
| app.example.com | In | Matches *.example.com |
| api.example.com | In | Explicitly listed |
| blog.example.com | Out | Explicitly OOS |
| dev.example.com | Uncertain | Not in OOS, not in wildcard |
| status.example.com | Out | Third-party service |
```

---

## 4. Attack Surface Ranking

### 4.1 Task: Rank Endpoints by Risk

```
WF ID: WF-RECON-240607-003
INPUT: recon/attack-surface-scoped.json
OUTPUT: recon/attack-surface-ranked.json

RANKING FACTORS:
  1. Authentication required (higher rank if unauthenticated)
  2. Sensitive operations (user management, payments, file uploads)
  3. Input parameters (URL params, file uploads, JSON bodies)
  4. Technology indicators (JWT, GraphQL, REST API)
  5. Historical vulnerability patterns (known bug classes)

SCORING MATRIX:
  Endpoint Type:
    - File upload: +30 points
    - Auth/register/reset: +25 points
    - User management (IDOR prone): +20 points
    - API with URL params: +15 points
    - GraphQL: +15 points
    - Admin panel: +15 points
    - Static/read-only: +5 points

  Auth Requirement:
    - Unauthenticated: +20 points
    - Low-privilege auth: +10 points
    - Admin-only: +5 points
```

### 4.2 Ranking Commands

```powershell
# Score each endpoint
$endpoints = Get-Content recon/attack-surface-scoped.json | ConvertFrom-Json
$ranked = $endpoints | ForEach-Object {
  $score = 0
  $path = $_.path
  $method = $_.method
  $auth = $_.auth_required

  if ($path -match 'upload|avatar|attachment') { $score += 30 }
  if ($path -match 'login|register|reset|password') { $score += 25 }
  if ($path -match 'user|profile|account') { $score += 20 }
  if ($path -match '\?') { $score += 15 }
  if ($path -match 'graphql') { $score += 15 }
  if ($path -match 'admin') { $score += 15 }
  if ($path -match 'static|css|js|image') { $score += 5 }

  if (-not $auth) { $score += 20 }
  elseif ($auth -eq 'user') { $score += 10 }
  elseif ($auth -eq 'admin') { $score += 5 }

  $_ | Add-Member -NotePropertyName score -NotePropertyValue $score
  $_
}

$ranked | Sort-Object score -Descending | ConvertTo-Json | Set-Content recon/attack-surface-ranked.json
```

### 4.3 Ranked Attack Surface

```
TOP 20 ENDPOINTS (example.com):

| Rank | Endpoint | Method | Score | Bug Class Candidates |
|------|----------|--------|-------|---------------------|
| 1 | POST /api/avatar | POST | 50 | SSRF, File Upload |
| 2 | POST /api/auth/register | POST | 45 | Mass Assignment, JWT |
| 3 | GET /api/v2/users/{id} | GET | 40 | IDOR |
| 4 | PUT /api/v2/users/{id}/profile | PUT | 40 | IDOR, Mass Assignment |
| 5 | POST /api/auth/forgot-password | POST | 35 | Auth Bypass, Rate Limit |
| 6 | POST /api/upload | POST | 35 | File Upload, XXE |
| 7 | /graphql | POST | 35 | GraphQL Introspection, IDOR |
| 8 | GET /api/v2/orders/{id} | GET | 30 | IDOR |
| 9 | GET /api/v2/invoices/{id} | GET | 30 | IDOR |
| 10 | GET /admin/dashboard | GET | 30 | Auth Bypass |
| 11 | POST /api/auth/reset-password | POST | 30 | Auth Bypass |
| 12 | GET /api/v2/documents/{id} | GET | 25 | IDOR, Path Traversal |
| 13 | GET /api/search?q={input} | GET | 25 | XSS, SSRF |
| 14 | POST /api/comments | POST | 20 | XSS, CSRF |
| 15 | GET /api/v2/users/me/settings | GET | 20 | IDOR |
| 16 | GET /api/health | GET | 10 | Info Disclosure |
| 17 | GET /api/version | GET | 10 | Info Disclosure |
| 18 | GET /static/{file} | GET | 5 | Path Traversal |
| 19 | GET /assets/{file} | GET | 5 | Path Traversal |
| 20 | GET /api/docs | GET | 5 | Info Disclosure |
```

---

## 5. Bug Class Assignment

### 5.1 Task: Assign Bug Classes to Endpoints

```
WF ID: WF-RECON-240607-004
INPUT: recon/attack-surface-ranked.json
OUTPUT: recon/bug-class-assignments.json

ASSIGNMENT RULES:
  URL parameters (url=, uri=, link=, image=) → SSRF
  File upload endpoints → File Upload Hunter
  User/account/document IDs in paths → IDOR Hunter
  Login/register/reset endpoints → Auth Bypass Hunter
  Search/error endpoints with user input → XSS Hunter
  GraphQL endpoints → GraphQL Hunter
  Cart/checkout/transfer endpoints → Business Logic Hunter
  Coupon/stock/balance endpoints → Race Condition Hunter
  JWT in headers or JWK endpoints → JWT Attack Suite
  XML/SOAP endpoints → XXE Hunter

AGENT MAPPING:
  SSRF → tools/python/ssrf_hunter.py
  IDOR → tools/python/idor_hunter.py
  JWT → tools/python/auth_hunter.py
  XSS → tools/python/payload_generator.py (XSS payloads)
  Auth Bypass → tools/python/auth_hunter.py
  File Upload → tools/python/file_upload_hunter.py
  GraphQL → manual testing (no dedicated tool yet)
  Business Logic → manual workflow testing
  Race Condition → tools/bash/fuzzer-toolkit.sh (turbo intruder)
```

### 5.2 Assignment Commands

```powershell
# Auto-assign based on endpoint patterns
$ranked = Get-Content recon/attack-surface-ranked.json | ConvertFrom-Json
$assignments = @()

foreach ($endpoint in $ranked) {
  $path = $endpoint.path
  $classes = @()

  if ($path -match 'upload|avatar|attachment') { $classes += 'File Upload' }
  if ($path -match '\?(.*&)?(url|uri|link|image|fetch|avatar)=') { $classes += 'SSRF' }
  if ($path -match '/users/\d|/orders/\d|/documents/\d|/invoices/\d') { $classes += 'IDOR' }
  if ($path -match 'login|register|reset|password|forgot') { $classes += 'Auth Bypass' }
  if ($path -match 'search|error|message') { $classes += 'XSS' }
  if ($path -match 'graphql') { $classes += 'GraphQL' }
  if ($path -match 'cart|checkout|transfer|payment') { $classes += 'Business Logic' }
  if ($path -match 'coupon|stock|like|withdraw') { $classes += 'Race Condition' }

  if ($classes.Count -eq 0) { $classes = @('Manual Review') }

  $assignments += [PSCustomObject]@{
    endpoint = $endpoint.path
    method = $endpoint.method
    score = $endpoint.score
    bug_classes = $classes -join ', '
    agent = $classes[0]
    priority = if ($endpoint.score -ge 40) { 'P1' } elseif ($endpoint.score -ge 25) { 'P2' } else { 'P3' }
  }
}

$assignments | ConvertTo-Json | Set-Content recon/bug-class-assignments.json
```

### 5.3 Assignment Summary

```
| Endpoint | Priority | Bug Classes | Assigned Agent |
|----------|----------|-------------|----------------|
| POST /api/avatar | P1 | SSRF, File Upload | ssrf-hunter, file-upload-hunter |
| POST /api/auth/register | P1 | Mass Assignment, JWT | idor-hunter, auth-hunter |
| GET /api/v2/users/{id} | P1 | IDOR | idor-hunter |
| PUT /api/v2/users/{id}/profile | P1 | IDOR, Mass Assignment | idor-hunter |
| POST /api/auth/forgot-password | P2 | Auth Bypass | auth-bypass-hunter |
| POST /api/upload | P2 | File Upload | file-upload-hunter |
| /graphql | P2 | GraphQL | graphql-hunter |
| GET /api/v2/orders/{id} | P2 | IDOR | idor-hunter |
| GET /api/v2/invoices/{id} | P2 | IDOR | idor-hunter |
| GET /admin/dashboard | P2 | Auth Bypass | auth-bypass-hunter |
```

---

## 6. Hunt Plan Generation

### 6.1 Task: Generate Hunt Plans from Assignments

```
WF ID: WF-RECON-240607-005
INPUT: recon/bug-class-assignments.json
OUTPUT: tasks/hunt-plans.md (new entries)

GENERATION RULES:
  [ ] Group endpoints by bug class
  [ ] Create one plan per bug class per target
  [ ] Plan ID format: PLAN-{CLASS}-{YYMMDD}-{XXX}
  [ ] Include all ranked endpoints in the plan
  [ ] Copy relevant payloads from payload_generator
  [ ] Reference tool scripts for each bug class
  [ ] Set estimated duration based on endpoint count

PLAN STRUCTURE:
  PLAN ID:
  TARGET:
  STATUS: Active
  PRIORITY:
  CREATED:
  ESTIMATED DURATION:
  DESCRIPTION:
  PHASES:
  TEST CASES:
  PAYLOADS:
  EXPECTED RESULTS:
  VALIDATION CRITERIA:
```

### 6.2 Plan Generation Commands

```powershell
# Generate plan entries from assignments
$assignments = Get-Content recon/bug-class-assignments.json | ConvertFrom-Json
$groups = $assignments | Group-Object agent

foreach ($group in $groups) {
  $bugClass = $group.Name
  $endpoints = $group.Group
  $priority = ($endpoints | Measure-Object -Property score -Maximum).Maximum
  $priorityLabel = if ($priority -ge 40) { 'P1' } elseif ($priority -ge 25) { 'P2' } else { 'P3' }
  $duration = [Math]::Ceiling($endpoints.Count * 5)
  $planId = "PLAN-$($bugClass.ToUpper())-$(Get-Date -Format 'yyMMdd')-001"

  Write-Host "Generated plan: $planId for $bugClass ($($endpoints.Count) endpoints, $duration min)"
}
```

### 6.3 Generated Plan Example

```
PLAN ID: PLAN-SSRF-240607-001
TARGET:  api.example.com
STATUS:  Active
CREATED: 2026-06-07
PRIORITY: P1
ESTIMATED DURATION: 25 min

DESCRIPTION:
  Test SSRF on POST /api/avatar endpoint. The endpoint
  accepts a URL parameter and downloads content as avatar.
  Ranked #1 with score 50 (unauthenticated, file upload sink).

PHASES:
  Phase 1 (15 min): Cloud metadata testing
    - AWS: 169.254.169.254/latest/meta-data/
    - GCP: metadata.google.internal/computeMetadata/v1/
    - Azure: 169.254.169.254/metadata/instance

  Phase 2 (10 min): Internal service probing
    - Elasticsearch: 127.0.0.1:9200
    - Redis: 127.0.0.1:6379
    - MySQL: 127.0.0.1:3306

TOOL: tools/python/ssrf_hunter.py
AGENT: ssrf-hunter
```

---

## 7. Timeboxing Strategy

### 7.1 Task: Timebox Hunt Plans

```
WF ID: WF-RECON-240607-006
INPUT: recon/bug-class-assignments.json
OUTPUT: Updated tasks/hunt-plans.md with durations

TIMEBOX RULES:
  P1 endpoint: 10 min per endpoint
  P2 endpoint: 5 min per endpoint
  P3 endpoint: 3 min per endpoint

  Minimum plan duration: 15 min
  Maximum plan duration: 60 min
  Buffer time: 20% added to estimate

CALCULATION:
  total_minutes = sum(endpoint_time for each endpoint)
  buffered = total_minutes * 1.2
  final = max(15, min(60, buffered))

EXAMPLE:
  3 P1 endpoints = 3 * 10 = 30 min
  2 P2 endpoints = 2 * 5 = 10 min
  Total = 40 min
  Buffered = 48 min → 50 min (rounded)
```

### 7.2 Timebox Commands

```powershell
$assignments = Get-Content recon/bug-class-assignments.json | ConvertFrom-Json
$groups = $assignments | Group-Object agent

foreach ($group in $groups) {
  $endpoints = $group.Group
  $total = 0
  foreach ($ep in $endpoints) {
    if ($ep.priority -eq 'P1') { $total += 10 }
    elseif ($ep.priority -eq 'P2') { $total += 5 }
    else { $total += 3 }
  }
  $buffered = [Math]::Ceiling($total * 1.2)
  $final = [Math]::Max(15, [Math]::Min(60, $buffered))
  Write-Host "$($group.Name): $total min base, $final min final"
}
```

---

## 8. Output Formats

### 8.1 Attack Surface Map JSON

```json
{
  "target": "example.com",
  "generated": "2026-06-07T10:00:00Z",
  "summary": {
    "total_endpoints": 45,
    "p1_endpoints": 12,
    "p2_endpoints": 20,
    "p3_endpoints": 13
  },
  "endpoints": [
    {
      "path": "/api/avatar",
      "method": "POST",
      "score": 50,
      "priority": "P1",
      "bug_classes": ["SSRF", "File Upload"],
      "assigned_agent": "ssrf-hunter",
      "parameters": ["url"],
      "auth_required": false,
      "tech_stack": ["Node.js", "Express"]
    }
  ],
  "plans_generated": [
    "PLAN-SSRF-240607-001",
    "PLAN-IDOR-240607-001",
    "PLAN-JWT-240607-001"
  ]
}
```

### 8.2 Hunt Plans Markdown Update

```markdown
## 3. Plan: SSRF Testing

### 3.1 Plan Overview

PLAN ID: PLAN-SSRF-240607-001
TARGET:  api.example.com
STATUS:  Active
CREATED: 2026-06-07
PRIORITY: P1
ESTIMATED DURATION: 50 min

DESCRIPTION:
  [Generated from recon workflow]
  Endpoints: POST /api/avatar

PHASES:
  Phase 1 (15 min): Cloud metadata
  Phase 2 (10 min): Internal services

TEST CASES:
  [Populated from ssrf_hunter.py methods]

PAYLOADS:
  [Populated from payload_generator.py SSRF payloads]
```

---

## 9. Workflow Templates

### 9.1 New Target Workflow Template

```
TASK: Onboard new target
WF ID: WF-RECON-{DATE}-001

STEP 1: Run recon
  - Subdomain enumeration
  - Live host discovery
  - URL crawling
  - JS bundle analysis

STEP 2: Process recon output
  - Load all recon files
  - Validate data quality
  - Filter in-scope assets

STEP 3: Rank attack surface
  - Score endpoints
  - Identify high-value targets

STEP 4: Assign bug classes
  - Map endpoints to agents
  - Generate hunt plans

STEP 5: Begin hunting
  - Execute P1 plans first
  - Timebox each session
  - Update plan progress
```

### 9.2 Continuous Workflow Template

```
DAILY LOOP:
  Morning:
    [ ] Run recon-toolkit.sh on target
    [ ] Process new recon output
    [ ] Update attack surface map
    [ ] Check for new endpoints

  Hunting:
    [ ] Execute active hunt plans
    [ ] Document findings in real-time
    [ ] Update plan progress percentages

  Evening:
    [ ] Run validation on new findings
    [ ] Generate reports for validated findings
    [ ] Update task-registry.md
    [ ] Commit all changes
```

---

## 10. Maintenance

### 10.1 Workflow Quality Checks

```
DAILY:
  [ ] Verify recon output is fresh (not stale)
  [ ] Check attack surface map for new endpoints
  [ ] Review plan progress and update statuses
  [ ] Validate bug class assignments are still accurate

WEEKLY:
  [ ] Re-run full recon to catch new assets
  [ ] Review assignment accuracy based on findings
  [ ] Update timebox estimates based on actual duration
  [ ] Add new endpoint patterns to assignment rules

MONTHLY:
  [ ] Full workflow review
  [ ] Update ranking algorithm weights
  [ ] Add new bug classes to assignment matrix
  [ ] Archive old recon output
```

### 10.2 Workflow History Log

```
| Date | Target | Endpoints | Plans Generated | Duration |
|------|--------|-----------|-----------------|----------|
| 2026-06-07 | example.com | 45 | 6 | 45 min |
| 2026-06-06 | test.com | 32 | 5 | 35 min |
| 2026-06-05 | demo.com | 28 | 4 | 30 min |
```

### 10.3 Troubleshooting

```
COMMON ISSUES:
  - No live hosts found: Check DNS resolution, try different tools
  - Low URL count: Increase crawl depth, add more sources
  - Missing tech stack: Use multiple fingerprinting tools
  - Scope conflicts: Review hunter-config.json rules
  - Timebox too short: Increase endpoint time allocation
  - Plans not generating: Check JSON syntax in assignments file
```

---

*End of reconnaissance-workflow.md*
