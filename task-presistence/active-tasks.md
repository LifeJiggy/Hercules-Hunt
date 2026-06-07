# Task Persistence — Active Tasks

Cross-session tracking of currently active tasks. This file maintains
state between hunting sessions so you can resume work immediately
without re-reading the full context.

---

## Table of Contents

1. [Active Tasks Overview](#1-active-tasks-overview)
2. [Current Session Tasks](#2-current-session-tasks)
3. [Carried-Over Tasks](#3-carried-over-tasks)
4. [Blocked Tasks](#4-blocked-tasks)
5. [Task Dependencies](#5-task-dependencies)
6. [Task Priority Matrix](#6-task-priority-matrix)
7. [Quick Resume](#7-quick-resume)
8. [Task State Archive](#8-task-state-archive)
9. [Maintenance](#9-maintenance)

---

## 1. Active Tasks Overview

### 1.1 Summary

```
TOTAL ACTIVE TASKS: [N]
THIS SESSION TASKS: [N]
CARRIED-OVER TASKS: [N]
BLOCKED TASKS: [N]

HIGHEST PRIORITY:
  1. [Task] — [target] — [status]
  2. [Task] — [target] — [status]
  3. [Task] — [target] — [status]

CURRENT FOCUS: [bug class / target]
```

### 1.2 State Snapshot

```
STATE SNAPSHOT: 2026-06-07 10:00

ACTIVE TASKS:
  TASK-HUNT-240607-001 — SSRF cloud metadata — IN PROGRESS
  TASK-HUNT-240607-002 — JWT HS256 confusion — PENDING
  TASK-HUNT-240607-003 — IDOR write operations — PENDING

CARRIED OVER:
  TASK-VAL-240606-001 — Validate JWT alg:none — CARRIED (needs evidence)
  TASK-RPT-240606-001 — SSRF report writing — CARRIED (waiting on validation)

BLOCKED:
  TASK-VAL-240606-002 — Validate XSS finding — BLOCKED (waiting for callback)
```

---

## 2. Current Session Tasks

### 2.1 Task List

```
SESSION: 2026-06-07 (2h planned)
TARGET:  example.com
FOCUS:   SSRF, JWT, IDOR

PRIORITY ORDER:
  1. TASK-HUNT-240607-001 — SSRF cloud metadata (30 min)
  2. TASK-HUNT-240607-002 — JWT HS256 confusion (20 min)
  3. TASK-HUNT-240607-003 — IDOR write operations (20 min)
  4. Evidence capture (20 min)
  5. Session review (10 min)

TIMEBOX:
  10:00-10:30  SSRF cloud metadata testing
  10:30-10:50  JWT HS256 confusion testing
  10:50-11:10  IDOR write operations
  11:10-11:30  Break + evidence capture
  11:30-11:50  Complete evidence, update logs
  11:50-12:00  Session review
```

### 2.2 Current Task Status

```
TASK-HUNT-240607-001: SSRF Cloud Metadata
  STATUS: IN PROGRESS
  PROGRESS: 40%
  STARTED: 10:00
  TIMEBOX: 30 min (ends 10:30)
  CURRENT STEP: Testing AWS metadata endpoint

  COMPLETED:
    [x] Test AWS 169.254.169.254/latest/meta-data/ — (200, data returned)
    [x] Test AWS 169.254.169.254/latest/meta-data/iam/ — (200, IAM role found)
    [ ] Test AWS 169.254.169.254/latest/meta-data/iam/security-credentials/ — PENDING
    [ ] Test GCP metadata.google.internal — PENDING
    [ ] Test Azure 169.254.169.254/metadata/instance — PENDING
    [ ] Test hex IP bypass — PENDING
    [ ] Test decimal IP bypass — PENDING

  NOTES:
    AWS metadata accessible! IAM role identified: ecs-service-role-prod.
    Need to enumerate the security credentials endpoint.

  STATE SAVE POINT:
    Last payload: {"url":"http://169.254.169.254/latest/meta-data/iam/"}
    Last response: {"Code":"Success","LastUpdated":"...","InstanceProfileArn":"...","RoleName":"ecs-service-role-prod"}
    Collaborator URL: xxxxxx.oastify.com

TASK-HUNT-240607-002: JWT HS256 Confusion
  STATUS: PENDING
  PROGRESS: 0%
  TIMEBOX: 20 min (starts 10:30)

  PREREQUISITES:
    [ ] Retrieve JWK from /.well-known/jwks.json
    [ ] Convert JWK to PEM
    [ ] Sign admin JWT with HS256 using PEM
    [ ] Send to admin endpoint

TASK-HUNT-240607-003: IDOR Write Operations
  STATUS: PENDING
  PROGRESS: 0%
  TIMEBOX: 20 min (starts 10:50)

  PREREQUISITES:
    [x] Victim user ID identified: 4242
    [ ] Test PUT /api/v2/users/4242/profile (email change)
    [ ] Test DELETE /api/v2/users/4242
    [ ] Test mass assignment: role=admin
```

---

## 3. Carried-Over Tasks

### 3.1 Carried Tasks

Tasks that were incomplete at the end of a previous session and carried over:

```
TASK-VAL-240606-001: Validate JWT alg:none
  ORIGINAL SESSION: 2026-06-06
  CARRIED OVER: 1 time
  CARRIED REASON: Needed additional evidence screenshots
  STATUS: PENDING (needs evidence capture)

  PROGRESS:
    [x] 7-Question Gate — PASS
    [x] Confirmed alg:none works
    [x] Confirmed admin API access
    [x] Documented payload and steps
    [ ] Capture screenshots (request, response, impact)
    [ ] Capture HAR file
    [ ] Write report

  NEXT ACTION: Capture screenshots in next session
  ESTIMATED TIME TO COMPLETE: 15 min

TASK-RPT-240606-001: SSRF Report Writing
  ORIGINAL SESSION: 2026-06-06
  CARRIED OVER: 1 time
  CARRIED REASON: Waiting for validation to complete
  STATUS: BLOCKED (waiting on task above)

  PROGRESS:
    [ ] Waiting for validation to pass
    [ ] Draft summary written
    [ ] Impact paragraph written
    [ ] Need screenshots and HAR

  NEXT ACTION: Complete after VALIDATION confirms
```

### 3.2 Max Carries Before Escalation

```
CARRY LIMITS:
  P1 task: Max 2 carries before escalation
  P2 task: Max 3 carries before escalation
  P3 task: Max 5 carries before cancellation

ESCALATION PROCEDURE:
  1. If a task is carried 2+ times, assess WHY
  2. Is it blocked? Unblock it.
  3. Is it too complex? Break it down.
  4. Is it low priority? Cancel or deprioritize.
  5. Is it scary/hard? Do it first next session.

CURRENT CARRIES:
  TASK-VAL-240606-001: 1 carry — OK
  TASK-RPT-240606-001: 1 carry — OK
```

---

## 4. Blocked Tasks

### 4.1 Blocked Task List

```
TASK-VAL-240606-002: Validate XSS Finding
  BLOCKED BY: Waiting for collaborator callback
  BLOCKED SINCE: 2026-06-06 (1 day)
  BLOCK REASON: XSS payload should send callback to collaborator,
    but no callback received yet

  UNBLOCK ACTIONS:
    1. Check if collaborator URL is correct
    2. Test XSS payload in browser directly
    3. Try different XSS payload (img/onerror instead of script)
    4. Check if CSP blocks the callback
    5. If still blocked after all attempts — KILL the finding

  STATUS: Attempted unblock 2 times — Failed
  NEXT UNBLOCK ATTEMPT: 2026-06-08
  FAILURE COUNT: 2
  AUTO-KILL AFTER: 5 failures (2026-06-11)
```

### 4.2 Blocked Task Management

```
DETECTING BLOCKED TASKS:
  A task is BLOCKED if:
    - Waiting for external input (callback, response)
    - Waiting for another task to complete
    - Awaiting tool availability
    - Technical issue preventing progress

RESOLVING BLOCKED TASKS:
  1. Clearly identify the blocker
  2. Determine if YOU can resolve it
  3. If yes: resolve it and resume
  4. If no: document what is needed
  5. Set a reminder to check back
  6. If blocked for 7+ days: escalate or kill
```

### 4.3 Block Resolution Log

```
| Task | Blocker | Attempt | Date | Result |
|------|---------|---------|------|--------|
| TASK-VAL-240606-002 | No callback received | 1 | 2026-06-06 | Reactivated collaborator |
| TASK-VAL-240606-002 | No callback received | 2 | 2026-06-07 | Changed payload format |
```

---

## 5. Task Dependencies

### 5.1 Dependency Map

```
TASK-HUNT-240607-001 (SSRF cloud metadata)
  Depends on: None (can start immediately)
  Needed by: TASK-VAL-240607-001 (SSRF validation)
  
TASK-HUNT-240607-002 (JWT HS256 confusion)
  Depends on: None (can start immediately)
  Needed by: TASK-VAL-240607-002 (JWT validation)

TASK-HUNT-240607-003 (IDOR write operations)
  Depends on: None (can start immediately)
  Needed by: TASK-VAL-240607-003 (IDOR validation)

TASK-VAL-240607-001 (SSRF validation)
  Depends on: TASK-HUNT-240607-001
  Needed by: TASK-RPT-240607-001 (SSRF report)

TASK-RPT-240607-001 (SSRF report)
  Depends on: TASK-VAL-240607-001
  Needed by: SUBMISSION
```

### 5.2 Dependency Graph

```
Current Session Flow:
  
  HUNT PHASE (10:00-11:30):
  ┌─────────────────────┐
  │ SSRF cloud metadata │ ◄── Can start now
  └──────────┬──────────┘
             │
  ┌──────────▼──────────┐
  │ JWT HS256 confusion │ ◄── Can start in parallel
  └──────────┬──────────┘
             │
  ┌──────────▼──────────┐
  │ IDOR write ops      │ ◄── Can start in parallel
  └─────────────────────┘

  VALIDATION PHASE (after hunt):
  ┌─────────────────────┐     ┌─────────────────────┐
  │ SSRF validation     │     │ JWT validation       │
  │ Needs: HUNT-001 done│     │ Needs: HUNT-002 done │
  └──────────┬──────────┘     └──────────┬──────────┘
             │                           │
  ┌──────────▼──────────┐     ┌──────────▼──────────┐
  │ SSRF report         │     │ JWT report           │
  │ Needs: VAL-001 done │     │ Needs: VAL-002 done │
  └─────────────────────┘     └─────────────────────┘
```

---

## 6. Task Priority Matrix

### 6.1 Eisenhower Matrix

```
                  ┌─────────────────────────────────────────┐
                  │ URGENT            │ NOT URGENT           │
┌─────────────────┼──────────────────┼──────────────────────┤
│ IMPORTANT       │ DO FIRST         │ SCHEDULE             │
│                 │ SSRF cloud meta  │ Learn GraphQL        │
│                 │ JWT HS256 conf   │ Wordlist update      │
│                 │ IDOR write ops   │ Evidence cleanup     │
├─────────────────┼──────────────────┼──────────────────────┤
│ NOT IMPORTANT   │ DELEGATE/SKIP   │ DON'T DO             │
│                 │ (N/A)           │ Non-critical updates  │
│                 │                 │ Nice-to-have features │
└─────────────────┴──────────────────┴──────────────────────┘
```

### 6.2 Priority Scoring

```
SCORING FORMULA:
  Priority Score = (Impact × Urgency) / Effort

  Impact: 1-10 (how much does this matter?)
  Urgency: 1-10 (how soon does it need to be done?)
  Effort: 1-10 (how much effort is required?)

CURRENT TASKS:
  SSRF cloud metadata:      (9 × 9) / 3 = 27.0  ★ HIGHEST
  JWT HS256 confusion:      (9 × 8) / 2 = 36.0  ★ HIGHEST
  IDOR write ops:           (8 × 8) / 2 = 32.0  ★ HIGHEST
  Validate JWT alg:none:    (9 × 6) / 2 = 27.0  ★ HIGH
  SSRF report writing:      (8 × 5) / 3 = 13.3
  Learn GraphQL:            (5 × 2) / 5 = 2.0
  Wordlist update:          (3 × 2) / 3 = 2.0
```

---

## 7. Quick Resume

### 7.1 One-Click Resume

When starting a new session, this section gets you up to speed immediately:

```
====== QUICK RESUME ======
TARGET: example.com
PROGRAM: HackerOne
SCOPE: *.example.com

LAST SESSION: 2026-06-06 (1.5h)
  - Found SSRF on POST /api/avatar
  - Found JWT alg:none on API
  - Found IDOR write on PUT /api/v2/users/{id}/profile
  - Submitted IDOR report (FIND-003)

THIS SESSION: 2026-06-07 (2h)
  GOAL 1: SSRF cloud metadata (confirmed working, get IAM creds)
  GOAL 2: JWT HS256 confusion (test algorithm confusion)
  GOAL 3: IDOR write operations (test more endpoints)

CARRY-OVER FROM LAST SESSION:
  - Validate JWT alg:none finding (need screenshots)
  - Write SSRF report (waiting on validation)

BLOCKED:
  - XSS validation blocked (no callback)

ACCOUNTS:
  - Attacker+1: Token valid (expires 2026-06-08)
  - Victim+1: Token valid (expires 2026-06-08)
  - Admin+1: Token expired — ROTATE NOW

NEXT ACTION: Test SSRF AWS metadata endpoint
```

### 7.2 Session Handoff

If switching between machines or users:

```
HANDOFF FROM: primary
HANDOFF TO: secondary (laptop)
HANDOFF DATE: 2026-06-07

ESSENTIAL FILES TO COPY:
  [ ] context/hunt-session.md (active session state)
  [ ] context/active-target.md (target context)
  [ ] memory/target-registry.md (target memory)
  [ ] .env.local (tokens and secrets)
  [ ] Burp project file
  [ ] Evidence screenshots

STATE NOTES:
  - Burp project named: example-com-20260607.burp
  - Collaborator URL: xxxxxx.oastify.com (same session)
  - Current testing phase: SSRF cloud metadata (40% done)
  - Next payload to send: IAM credentials request
```

---

## 8. Task State Archive

### 8.1 Previous Session States

```
STATE: 2026-06-06
  COMPLETED:
    - Recon: subdomain enum on example.com
    - HUNT: SSRF callback verification (confirmed)
    - HUNT: JWT alg:none testing (confirmed)
    - HUNT: IDOR write (confirmed)
    - RPT: IDOR report submitted (H1-XXXXX)
  
  INCOMPLETE (carried over):
    - VAL: JWT alg:none validation (needs evidence)
    - RPT: SSRF report (needs validation)
  
  TOOLS STATE:
    - Burp project saved: example-com-20260606.burp
    - Session file saved: context/2026-06-06-hunt-session.md
```

### 8.2 State Persistence Rules

```
RULES:
  1. Always save session state at end of session
  2. Carry incomplete tasks to next session
  3. Track how many times a task is carried
  4. Auto-kill tasks carried more than max allowed
  5. State includes: active payloads, pending responses,
     current findings, tool state
  6. Session file is the primary state record
  7. This file is the quick-reference summary
```

---

## 9. Maintenance

```
DAILY:
  [ ] Update active task status during session
  [ ] Mark tasks completed as they finish
  [ ] Carry incomplete tasks to next session
  [ ] Update blocked task status

WEEKLY:
  [ ] Review carried tasks (escalate if needed)
  [ ] Clear stale blocked tasks (7+ days)
  [ ] Update priority scores
  [ ] Review dependency graph

MONTHLY:
  [ ] Archive old task states
  [ ] Review carry metrics
  [ ] Update priority matrix
  [ ] Clean up cancelled tasks
```

---

*End of active-tasks.md*
