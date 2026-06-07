# Tasks — Task Registry

Master registry for all hunting tasks. Each task is a well-defined unit of
work that can be assigned, tracked, and completed. Tasks range from recon
operations to vulnerability validation to report writing.

---

## Table of Contents

1. [Registry Overview](#1-registry-overview)
2. [Active Tasks](#2-active-tasks)
3. [Planned Tasks](#3-planned-tasks)
4. [Completed Tasks](#4-completed-tasks)
5. [Task by Priority](#5-task-by-priority)
6. [Task by Target](#6-task-by-target)
7. [Task Templates](#7-task-templates)
8. [Maintenance](#8-maintenance)

---

## 1. Registry Overview

### 1.1 Summary

```
TOTAL TASKS: [N]
  Active:   [N]
  Planned:  [N]
  Completed: [N]
  Cancelled: [N]

BY PRIORITY:
  P0 (Critical): [N]
  P1 (High):     [N]
  P2 (Medium):   [N]
  P3 (Low):      [N]

BY CATEGORY:
  Recon:          [N]
  Active Hunting: [N]
  Validation:     [N]
  Reporting:      [N]
  Maintenance:    [N]
  Learning:       [N]
```

### 1.2 Task ID Format

```
TASK ID FORMAT: TASK-{category}-{YYMMDD}-{XXX}
  category: RECON, HUNT, VAL, RPT, MAINT, LEARN
  YYMMDD:   Date of creation
  XXX:      Sequential number

Example: TASK-RECON-240607-001
```

### 1.3 Task Lifecycle

```
CREATED → QUEUED → ACTIVE → COMPLETED
                        └→ BLOCKED
                        └→ CANCELLED
                        └→ DEFERRED
```

---

## 2. Active Tasks

### 2.1 Currently Active

```
| Task ID | Description | Priority | Started | Target | ETA |
|---------|-------------|----------|---------|--------|-----|
| TASK-HUNT-240607-001 | SSRF cloud metadata testing | P1 | 10:00 | example.com | 30 min |
| TASK-HUNT-240607-002 | JWT HS256 confusion testing | P1 | 10:30 | example.com | 20 min |
| TASK-HUNT-240607-003 | IDOR write operations | P1 | 11:00 | example.com | 20 min |
```

### 2.2 Active Task Details

```
TASK-HUNT-240607-001: SSRF Cloud Metadata Testing
  Status:     Active
  Priority:   P1 (High)
  Target:     api.example.com
  Created:    2026-06-07
  Started:    10:00
  ETA:        10:30
  Assigned:   self

  Description:
    Test SSRF on POST /api/avatar by sending URLs pointing
    to cloud metadata services (AWS, GCP, Azure).

  Prerequisites:
    [x] Valid attacker token
    [x] Burp Collaborator running
    [x] SSRF callback verified in previous session

  Subtasks:
    [x] Test AWS metadata (169.254.169.254)
    [ ] Test GCP metadata (metadata.google.internal)
    [ ] Test Azure metadata (169.254.169.254/metadata/instance)
    [ ] Test hex IP bypass
    [ ] Test decimal IP bypass
    [ ] Test DNS rebinding

  Dependencies: None

  Outcome: [Pending / Confirmed / Killed]
```

### 2.3 Blocked Tasks

```
| Task ID | Description | Blocked By | Since | Unblock Action |
|---------|-------------|------------|-------|----------------|
| TASK-VAL-240606-001 | Validate JWT finding | Waiting for collaborator callback | 2026-06-06 | Check collaborator, try new callback URL |
| TASK-RPT-240606-001 | Write SSRF report | Awaiting evidence screenshots | 2026-06-06 | Capture screenshots in next session |
```

---

## 3. Planned Tasks

### 3.1 Queue

```
| Task ID | Description | Priority | Target | Plan Date |
|---------|-------------|----------|--------|-----------|
| TASK-RECON-240607-001 | Subdomain recon on *.example.com | P1 | example.com | Next session |
| TASK-HUNT-240607-005 | Test file upload on avatar endpoint | P2 | example.com | Next session |
| TASK-HUNT-240607-006 | Test auth bypass on admin panel | P2 | example.com | Next session |
| TASK-LEARN-240607-001 | Study GraphQL hunting methodology | P3 | — | This week |
| TASK-MAINT-240607-001 | Update wordlists with new payloads | P3 | — | This week |
```

### 3.2 Backlog

```
| Task ID | Description | Priority | Target | Notes |
|---------|-------------|----------|--------|-------|
| TASK-HUNT-240607-007 | Race condition on password reset | P3 | example.com | Need turbo intruder |
| TASK-RECON-240607-002 | JS bundle analysis | P2 | example.com | After recon finds new endpoints |
| TASK-REP-240607-002 | Write JWT report | P2 | example.com | After validation completes |
| TASK-LEARN-240607-002 | Study disclosed SSRF reports | P3 | — | Evening review |
| TASK-MAINT-240607-002 | Clean up old evidence packages | P3 | — | Monthly |
```

---

## 4. Completed Tasks

### 4.1 Recent Completions

```
| Task ID | Description | Completed | Outcome |
|---------|-------------|-----------|---------|
| TASK-RECON-240606-001 | Initial recon on example.com | 2026-06-06 | 25 subdomains, 8 live |
| TASK-HUNT-240606-001 | SSRF callback verification | 2026-06-06 | SSRF confirmed |
| TASK-HUNT-240606-002 | JWT alg:none testing | 2026-06-06 | Critical finding |
| TASK-VAL-240606-001 | Validate IDOR write | 2026-06-06 | IDOR confirmed |
| TASK-RPT-240606-002 | IDOR report writing | 2026-06-06 | Submitted |
```

### 4.2 Completion Stats

```
TASKS COMPLETED THIS WEEK: [N]
AVERAGE COMPLETION TIME: [N] minutes
MOST PRODUCTIVE DAY: [day]
COMPLETION RATE: [N]%
```

---

## 5. Task by Priority

### 5.1 P0 (Critical) Tasks

```
| Task ID | Description | Deadline | Status |
|---------|-------------|----------|--------|
```

### 5.2 P1 (High) Tasks

```
| Task ID | Description | Target | Status |
|---------|-------------|--------|--------|
| TASK-HUNT-240607-001 | SSRF cloud metadata | example.com | Active |
| TASK-HUNT-240607-002 | JWT HS256 confusion | example.com | Active |
| TASK-HUNT-240607-003 | IDOR write operations | example.com | Active |
| TASK-RECON-240607-001 | Subdomain recon | example.com | Planned |
| TASK-VAL-240607-001 | Validate SSRF finding | example.com | Planned |
```

### 5.3 P2 (Medium) Tasks

```
| Task ID | Description | Target | Status |
|---------|-------------|--------|--------|
| TASK-HUNT-240607-005 | File upload testing | example.com | Planned |
| TASK-HUNT-240607-006 | Auth bypass testing | example.com | Planned |
| TASK-RECON-240607-002 | JS bundle analysis | example.com | Planned |
| TASK-RPT-240607-002 | JWT report writing | example.com | Planned |
```

### 5.4 P3 (Low) Tasks

```
| Task ID | Description | Status |
|---------|-------------|--------|
| TASK-LEARN-240607-001 | Study GraphQL methodology | Planned |
| TASK-LEARN-240607-002 | Study disclosed SSRF reports | Planned |
| TASK-MAINT-240607-001 | Update wordlists | Planned |
| TASK-MAINT-240607-002 | Clean up evidence packages | Planned |
```

---

## 6. Task by Target

### 6.1 Target Task Overview

```
| Target | Active Tasks | Completed Tasks | Total |
|--------|-------------|-----------------|-------|
| example.com | 5 | 5 | 10 |
| other.com | 0 | 0 | 0 |
| Private target | 0 | 0 | 0 |
```

### 6.2 Target Task Details

```
example.com:
  Active:
    TASK-HUNT-240607-001 — SSRF cloud metadata
    TASK-HUNT-240607-002 — JWT HS256 confusion
    TASK-HUNT-240607-003 — IDOR write operations
    TASK-RECON-240607-001 — Subdomain recon
    TASK-VAL-240607-001 — Validate SSRF
  Completed:
    TASK-RECON-240606-001 — Initial recon
    TASK-HUNT-240606-001 — SSRF callback
    TASK-HUNT-240606-002 — JWT alg:none
    TASK-VAL-240606-001 — IDOR validation
    TASK-RPT-240606-002 — IDOR report
```

---

## 7. Task Templates

### 7.1 Recon Task Template

```
TASK ID: TASK-RECON-{YYMMDD}-{XXX}
CATEGORY: Recon
PRIORITY: [P0/P1/P2/P3]
STATUS: [Planned / Active / Completed]

TARGET: [domain]
SCOPE: [scope]
DESCRIPTION: [what recon to perform]

TOOLS: [list of tools]

SUBTASKS:
  [ ] Subdomain enumeration (subfinder, chaos, crtsh)
  [ ] Live host discovery (httpx, dnsx)
  [ ] URL crawling (katana, waybackurls, gau)
  [ ] Technology fingerprinting (httpx, wappalyzer)
  [ ] Directory fuzzing (ffuf)
  [ ] JS bundle discovery and analysis

OUTPUT: [expected output]
```

### 7.2 Hunt Task Template

```
TASK ID: TASK-HUNT-{YYMMDD}-{XXX}
CATEGORY: Active Hunting
PRIORITY: [P0/P1/P2/P3]
STATUS: [Planned / Active / Completed]

TARGET: [domain]
BUG CLASS: [vuln class]
ENDPOINT: [endpoint to test]
DESCRIPTION: [what to test]

PAYLOADS:
  - [payload 1]
  - [payload 2]
  - [payload 3]

EXPECTED BEHAVIOR:
  Vulnerable: [expected vulnerable response]
  Not vulnerable: [expected secure response]

TIMEBOX: [N] minutes
```

### 7.3 Validation Task Template

```
TASK ID: TASK-VAL-{YYMMDD}-{XXX}
CATEGORY: Validation
PRIORITY: [P0/P1/P2/P3]
STATUS: [Planned / Active / Completed]

FINDING: [finding description]
BUG CLASS: [vuln class]

VALIDATION STEPS:
  [ ] 7-Question Gate
  [ ] 4-Gate Checklist
  [ ] Reproduce 3x
  [ ] Check always-rejected list
  [ ] Check chain potential

OUTCOME: [Valid / Kill / Downgrade / Chain]
```

### 7.4 Report Task Template

```
TASK ID: TASK-RPT-{YYMMDD}-{XXX}
CATEGORY: Reporting
PRIORITY: [P0/P1/P2/P3]
STATUS: [Planned / Active / Completed]

FINDING: [finding description]
BUG CLASS: [vuln class]
SEVERITY: [Critical/High/Medium/Low]

REPORT COMPONENTS:
  [ ] Title
  [ ] Summary
  [ ] Impact statement
  [ ] Reproduction steps
  [ ] Technical detail
  [ ] Payload/request
  [ ] Screenshots (N)
  [ ] HAR file
  [ ] CVSS score

SUBMITTED: [Yes / No]
SUBMISSION URL: [link]
```

---

## 8. Maintenance

### 8.1 Tasks

```
DAILY:
  [ ] Register new tasks before session
  [ ] Update active task status
  [ ] Complete tasks when finished
  [ ] Move blocked tasks to blocked section

WEEKLY:
  [ ] Review task completion rate
  [ ] Reprioritize backlog
  [ ] Defer low-priority tasks
  [ ] Clean up cancelled tasks

MONTHLY:
  [ ] Archive completed tasks
  [ ] Review task templates for improvements
  [ ] Update backlog based on new knowledge
```

### 8.2 Task Metrics

```
TASKS COMPLETED: [N]
AVG COMPLETION RATE: [N] tasks/session
MOST COMMON TASK TYPE: [category]
LEAST COMMON TASK TYPE: [category]

TASK COMPLETION BY PRIORITY:
  P0: [N]% completed
  P1: [N]% completed
  P2: [N]% completed
  P3: [N]% completed
```

---

*End of task-registry.md*
