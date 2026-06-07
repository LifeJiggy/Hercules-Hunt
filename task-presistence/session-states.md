# Task Persistence — Session States

Cross-session state management. This file tracks the state of each hunting
session, including what tools were loaded, what accounts were active,
what payloads were being tested, and what data needs to be carried forward.

---

## Table of Contents

1. [State Overview](#1-state-overview)
2. [Current Session State](#2-current-session-state)
3. [Previous Session States](#3-previous-session-states)
4. [Tools State](#4-tools-state)
5. [Accounts State](#5-accounts-state)
6. [Payload State](#6-payload-state)
7. [Response State](#7-response-state)
8. [Evidence State](#8-evidence-state)
9. [State Restoration](#9-state-restoration)
10. [Maintenance](#10-maintenance)

---

## 1. State Overview

### 1.1 Summary

```
CURRENT SESSION: 2026-06-07 example.com
PREVIOUS SESSION: 2026-06-06 example.com
SESSION COUNT: 6

STATE TRACKING:
  [x] Tools state saved
  [x] Accounts state saved
  [x] Payload state saved
  [x] Response state saved
  [x] Evidence state saved
  [x] Findings state saved
```

### 1.2 State Components

```
Each session state saves:
  1. SESSION METADATA — Date, target, duration, focus
  2. TOOLS STATE — What tools were loaded, Burp project
  3. ACCOUNTS STATE — Which accounts used, token expiry
  4. PAYLOAD STATE — Last payloads sent, pending tests
  5. RESPONSE STATE — Interesting responses received
  6. EVIDENCE STATE — What evidence was captured
  7. FINDINGS STATE — Current findings and their status
```

---

## 2. Current Session State

### 2.1 Session Metadata

```
SESSION: 2026-06-07
TARGET:  example.com
PROGRAM: HackerOne
START:   10:00
ELAPSED: 45 min
REMAINING: 1h 15min
STATUS:  Active

FOCUS:
  [x] SSRF cloud metadata testing
  [ ] JWT HS256 confusion testing
  [ ] IDOR write operations testing
```

### 2.2 Complete State Dump

```
=== STATE DUMP: 2026-06-07 10:45 ===

TOOLS:
  Burp Suite: Running on 8080, project: example-com-20260607.burp
  Collaborator: xxxxxx.oastify.com (active, 2 callbacks received)
  interact.sh: yyyyyy.interact.sh (active, 0 callbacks)
  PowerShell: powershell-lib.ps1 v2.3 loaded
  curl-hunter: v2.1 loaded

ACCOUNTS:
  attacker+1@test.com: Active, token valid until 10:45 (will refresh)
  victim+1@test.com: Active, token valid until 10:45 (will refresh)
  admin+1@test.com: Token expired — needs rotation

ACTIVE PAYLOADS:
  Current SSRF test: http://169.254.169.254/latest/meta-data/iam/security-credentials/
  Last response status: 200 OK
  Last response: Contains IAM role name + credential endpoint

PENDING TESTS:
  GCP metadata: metadata.google.internal (not yet tested)
  Azure metadata: 169.254.169.254/metadata/instance (not yet tested)
  Hex bypass: 0x7f.0x0.0x0.0x1 (not yet tested)
  Decimal bypass: 2130706433 (not yet tested)
  Internal Elasticsearch: 127.0.0.1:9200 (not yet tested)

FINDINGS IN PROGRESS:
  FIND-001: SSRF cloud metadata (HIGH) — 40% complete
  FIND-002: JWT alg:none (CRITICAL) — needs evidence capture
  FIND-003: IDOR write -> ATO (HIGH) — submitted H1-XXXXX

EVIDENCE CAPTURED:
  PKG-20260607-001: SSRF screenshots (2 of 4)
  PKG-20260606-001: IDOR screenshots (4 of 4 — submitted)
  PKG-20260605-001: JWT alg:none screenshots (1 of 4)
```

---

## 3. Previous Session States

### 3.1 Session 2026-06-06

```
=== STATE DUMP: 2026-06-06 12:00 (END OF SESSION) ===

TOOLS:
  Burp Suite: Running on 8080, project: example-com-20260606.burp
  Collaborator: aaaaaa.oastify.com (closed at session end)
  interact.sh: bbbbbb.interact.sh (closed at session end)

ACCOUNTS:
  attacker+1@test.com: Active, token valid (just refreshed)
  victim+1@test.com: Active, token valid (just refreshed)
  admin+1@test.com: Token valid until 2026-06-07

ACTIVE PAYLOADS (last of session):
  SSRF: {"url":"http://169.254.169.254/latest/meta-data/"} — returned data
  JWT: eyJhbGciOiJub25l... — returned admin access
  IDOR: PUT {"email":"attacker@evil.com"} — returned 200

PENDING TESTS:
  SSRF cloud metadata: AWS endpoint confirmed working
  JWT RS256/HS256 confusion: Not tested yet
  IDOR additional endpoints: Some endpoints not fuzzed

FINDINGS:
  FIND-001: SSRF — confirmed, needs cloud metadata testing
  FIND-002: JWT alg:none — confirmed, needs evidence
  FIND-003: IDOR write — confirmed, submitted to H1

EVIDENCE:
  IDOR: 4 screenshots captured, submitted with report
  SSRF: 1 screenshot captured (need more)
  JWT: 0 screenshots captured (need all)

CARRY FORWARD:
  1. Refresh tokens next session
  2. Continue SSRF with cloud metadata focus
  3. Test JWT RS256/HS256 confusion
  4. Capture JWT evidence
  5. Test more IDOR endpoints
```

### 3.2 Session 2026-06-05

```
=== STATE DUMP: 2026-06-05 12:00 (END OF SESSION) ===

TOOLS:
  Burp Suite: Running on 8080, project: example-com-20260605.burp
  Collaborator: cccccc.oastify.com (closed)

ACCOUNTS:
  attacker+1@test.com: Active
  victim+1@test.com: Active

ACTIVE PAYLOADS (last of session):
  SSRF: {"url":"http://169.254.169.254/"} — returned connection refused
  SSRF callback: collaborator URL in X-Forwarded-For — CALLBACK RECEIVED
  JWT: alg:none test — 200 OK

PENDING TESTS:
  SSRF: Try different metadata endpoints
  JWT: Document alg:none finding, test more algorithms

FINDINGS:
  FIND-001: SSRF (blind) — confirmed via collaborator callback
  FIND-002: JWT alg:none (tentative) — need to reproduce

CARRY FORWARD:
  1. Continue SSRF cloud metadata testing
  2. Confirm JWT alg:none with different payloads
  3. Start testing IDOR
```

### 3.3 Session 2026-06-04

```
=== STATE DUMP: 2026-06-04 11:00 (END OF SESSION) ===

TOOLS:
  Burp Suite: Running, project: other-com-20260604.burp

ACCOUNTS:
  attacker@testcorp.com: Active

FINDINGS: None
  - Heavy WAF prevented effective testing
  - All payloads blocked or rate-limited

CARRY FORWARD:
  1. Consider different target
  2. Research WAF bypass techniques
  3. Target not viable without bypass
```

---

## 4. Tools State

### 4.1 Current Tools State

```
TOOL STATE: 2026-06-07 10:45

PROCESSES RUNNING:
  [x] Burp Suite (PID: 12345) — Port 8080
  [x] PowerShell session
  [ ] Python (not running)
  [x] Browser (Firefox hunt profile)
  [ ] Browser (Chrome hunt profile)

TOOLS LOADED:
  [x] tools/powershell-lib.ps1
  [x] tools/curl-hunter.ps1
  [ ] tools/recon-toolkit.ps1 (not needed)
  [ ] tools/fuzzer-toolkit.ps1 (not needed)
  [ ] tools/js-analyzer.ps1 (not needed)
  [ ] tools/evidence-toolkit.ps1 (not loaded yet)
  [ ] tools/python-hunter.py (not needed)

BURP STATE:
  Project: example-com-20260607.burp
  Scope: *.example.com
  Intercept: On (in-scope only)
  Collaborator: xxxxxx.oastify.com — 2 callbacks
  Macros: Login macro configured
  Extensions: JSON Decoder, Param Miner, JWT Editor active
```

### 4.2 Tool State History

```
| Session | Burp Project | Collaborator | Tools Loaded |
|---------|-------------|--------------|--------------|
| 2026-06-07 | example-com-20260607.burp | xxxxxx.oastify.com | PS, curl |
| 2026-06-06 | example-com-20260606.burp | aaaaaa.oastify.com | PS, curl, evidence |
| 2026-06-05 | example-com-20260605.burp | cccccc.oastify.com | PS, curl |
| 2026-06-04 | other-com-20260604.burp | dddd.oastify.com | PS, curl, recon |
```

---

## 5. Accounts State

### 5.1 Current Accounts State

```
ACCOUNTS STATE: 2026-06-07 10:45

Account A (attacker):
  Email: attacker+1@test.com
  Token: [REDACTED — first 10 chars: eyJhbGciOiJ...]
  Token valid: Yes (expires 10:45 — just refreshed)
  Last used: 10:40 (SSRF request)

Account B (victim):
  Email: victim+1@test.com
  Token: [REDACTED]
  Token valid: Yes (expires 10:45)
  Last used: 10:35

Account C (admin):
  Email: admin+1@test.com
  Token: [REDACTED]
  Token valid: No — EXPIRED
  Last used: 2026-06-05
  Action needed: Refresh before admin testing
```

### 5.2 Account State History

```
| Session | Attacker | Victim | Admin |
|---------|----------|--------|-------|
| 2026-06-07 | OK | OK | EXPIRED |
| 2026-06-06 | OK | OK | OK |
| 2026-06-05 | OK | OK | OK |
| 2026-06-04 | OK | N/A | N/A |
```

---

## 6. Payload State

### 6.1 Current Payload State

```
PAYLOAD STATE: 2026-06-07 10:45

LAST SENT PAYLOAD:
  Method: POST
  URL: https://api.example.com/api/avatar
  Headers:
    Authorization: Bearer [token]
    Content-Type: application/json
  Body:
    {"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}

LAST RECEIVED RESPONSE:
  Status: 200 OK
  Headers: Content-Type: text/plain
  Body:
    {
      "Code": "Success",
      "Type": "AWS-HMAC",
      "AccessKeyId": "AKIA...",
      "SecretAccessKey": "...",
      "Token": "...",
      "Expiration": "2026-06-07T11:00:00Z"
    }

PENDING PAYLOADS:
  Next SSRF:
    - GCP: http://metadata.google.internal/computeMetadata/v1/
    - Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01
    - Local: http://127.0.0.1:9200/_cat/indices
    - Hex: http://0x7f.0x0.0x0.0x1/

  Next JWT:
    - Retrieve JWK from /.well-known/jwks.json
    - Convert JWK to PEM
    - Sign admin JWT with HS256

  Next IDOR:
    - PUT /api/v2/users/4243/profile
    - DELETE /api/v2/users/4242
    - PUT /api/v2/users/4242/role
```

### 6.2 Payload Queue

```
SSRF QUEUE (3 remaining):
  1. GCP metadata — NOT YET TESTED
  2. Azure metadata — NOT YET TESTED
  3. Internal services — NOT YET TESTED

JWT QUEUE (1 remaining):
  1. HS256 confusion — NOT YET TESTED

IDOR QUEUE (3 remaining):
  1. Email change on victim 4243 — NOT YET TESTED
  2. Account deletion — NOT YET TESTED
  3. Role change — NOT YET TESTED
```

---

## 7. Response State

### 7.1 Current Response State

```
RESPONSE STATE: 2026-06-07 10:45

INTERESTING RESPONSES THIS SESSION:

1. SSRF — AWS metadata (10:15)
   Status: 200 OK
   Data: IAM role name + security credentials endpoint
   Significance: VULN — SSRF confirmed to cloud metadata
   Evidence: Screenshot captured (PKG-20260607-001/001)

2. SSRF — AWS IAM credentials (10:20)
   Status: 200 OK
   Data: Full IAM credentials (AccessKeyId, SecretAccessKey, Token)
   Significance: CRITICAL — IAM credentials exposed
   Evidence: Screenshot captured (PKG-20260607-001/002)

3. JWT — collaborator callback (previous session)
   Status: Callback received
   Data: DNS lookup from target server
   Significance: CONFIRMED — SSRF blind callback works
   Evidence: Burp Collaborator screenshot (PKG-20260605-001)
```

### 7.2 Response Patterns

```
RESPONSE PATTERNS FOUND:
  SSRF: 200 with metadata content = VULN
  JWT: 200 with admin data = VULN
  IDOR: 200 with victim data = VULN
  Auth: 302 redirect = not vulnerable (needs auth)

ERROR PATTERNS:
  403: Blocked by WAF or auth
  404: Endpoint not found
  500: Server error (possible injection)
  429: Rate limited (back off)
```

---

## 8. Evidence State

### 8.1 Current Evidence State

```
EVIDENCE STATE: 2026-06-07 10:45

EVIDENCE PACKAGE: PKG-20260607-001 (SSRF)
  Status: In Progress (50%)
  Screenshots:
    [x] 001 — AWS metadata request (Burp Repeater)
    [x] 002 — AWS metadata response (IAM credentials)
    [ ] 003 — Impact demonstration (cloud console access)
    [ ] 004 — Auth/user context (attacker token)
  HAR:
    [ ] Not yet captured
  Request:
    [x] Saved to requests/ssrf-aws-metadata.txt
  Response:
    [x] Saved to responses/ssrf-aws-response.json

EVIDENCE PACKAGE: PKG-20260606-001 (IDOR)
  Status: Complete (submitted with report)
  Screenshots: 4 (all captured)
  HAR: Captured and sanitized
  Request: Saved
  Response: Saved

EVIDENCE PACKAGE: PKG-20260605-001 (JWT)
  Status: Needs Work (25%)
  Screenshots: 1 (need 3 more)
  HAR: Not captured
  Request: Not saved
  Response: Not saved
```

---

## 9. State Restoration

### 9.1 Restore Procedure

To restore state from a previous session:

```
1. Load the previous session file:
   Get-Content context/YYYY-MM-DD-hunt-session.md

2. Check the STATE DUMP at the top of this file

3. Restore tools:
   - Start Burp Suite
   - Load previous Burp project or start fresh
   - Set up collaborator URL
   - Load PowerShell scripts
   - Configure proxy

4. Restore accounts:
   - Verify tokens are still valid
   - Refresh if expired
   - Set environment variables

5. Restore payloads:
   - Review last payload sent
   - Review pending tests
   - Continue where left off

6. Restore findings:
   - Reload finding state
   - Continue validation/reporting
```

### 9.2 Quick State Restoration

```
QUICK RESTORE (5 min):
  1. Start Burp Suite (load last project)
  2. New collaborator URL
  3. . .\tools\powershell-lib.ps1
  4. . .\tools\curl-hunter.ps1
  5. Set environment variables
  6. Verify tokens
  7. Read this file for current state
  8. Start hunting where you left off
```

---

## 10. Maintenance

```
DAILY:
  [ ] Save session state at end of each session
  [ ] Update tool state (which projects, URLs)
  [ ] Update account state (token validity)
  [ ] Log pending payloads and responses
  [ ] Note any state changes during session

WEEKLY:
  [ ] Review state history for consistency
  [ ] Clean up stale state entries
  [ ] Archive old states (keep last 10)

MONTHLY:
  [ ] Full state audit
  [ ] Remove very old states
  [ ] Update restoration procedure
  [ ] Verify restore from state works
```

---

*End of session-states.md*
