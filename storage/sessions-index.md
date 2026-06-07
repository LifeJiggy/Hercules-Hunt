# Storage — Sessions Index

Master index of all hunting sessions across all targets. Each session is registered
here at creation and archived at completion. This file is the canonical record of
all hunting activity.

---

## Table of Contents

1. [Session Overview](#1-session-overview)
2. [Active Sessions](#2-active-sessions)
3. [Completed Sessions](#3-completed-sessions)
4. [Session by Target](#4-session-by-target)
5. [Session by Bug Class](#5-session-by-bug-class)
6. [Time Statistics](#6-time-statistics)
7. [Session Archive](#7-session-archive)
8. [Maintenance](#8-maintenance)

---

## 1. Session Overview

### 1.1 Current State

```
TOTAL SESSIONS: [N]
ACTIVE SESSIONS: [N]
COMPLETED SESSIONS: [N]
TOTAL HUNTING TIME: [N] hours

SESSIONS THIS WEEK: [N]
SESSIONS THIS MONTH: [N]
SESSIONS THIS YEAR: [N]

AVERAGE SESSION LENGTH: [N] min
TOTAL FINDINGS: [N]
FINDINGS PER SESSION: [N]
```

### 1.2 Session ID Format

```
SESSION ID FORMAT: YYYY-MM-DD-TARGET-XXX
  YYYY-MM-DD: Date of session
  TARGET:     Target codename
  XXX:        Sequential number (001, 002, etc.)

Example: 2026-06-07-EXAMPLE-001
```

### 1.3 Session Registration

Before each session begins, register it here:

```
SESSION REGISTRATION:
  ID:    2026-06-07-EXAMPLE-001
  Date:  2026-06-07
  Target:  example.com
  Program: HackerOne
  Scope:  *.example.com
  Hunter:  [name]
  Start:   HH:MM
  Planned Duration: 2h
  Focus:  SSRF, JWT, IDOR
  Tools:  Burp Suite, curl-hunter, python-hunter
  Accounts: 3 (attacker, victim, admin)
  Status:  Active / Completed / Archived
```

---

## 2. Active Sessions

### 2.1 Currently Active

```
SESSION 2026-06-07-EXAMPLE-001
  Target:  example.com
  Start:   10:00
  Elapsed: 1h 30min
  Remaining: 30min
  Status:  In Progress
  Findings: 2 (SSRF confirmed, JWT pending)
  File:    context/hunt-session.md
```

### 2.2 Active Session Details

```
| Session ID | Target | Started | Duration | Findings | Status |
|------------|--------|---------|----------|----------|--------|
| 2026-06-07-EXAMPLE-001 | example.com | 10:00 | 2h | 2 | Active |
```

### 2.3 Session Continuity Notes

Use this section to note anything about active sessions that needs to be
remembered for the next continuation:

```
SESSION 2026-06-07-EXAMPLE-001 — Continuity Notes
  Stopped because: [Time ran out / Found critical chain / Tool issue]
  Resume plan:
    1. Continue SSRF testing on internal services
    2. Validate IDOR write finding with screenshots
    3. Test JWT HS256 confusion
  Critical state:
    - Burp project saved: session-001.burp
    - Screenshots saved: evidence/2026-06-07/
    - Tokens need refresh: [Yes / No]
```

---

## 3. Completed Sessions

### 3.1 Recent Sessions

```
| Session ID | Target | Date | Duration | Findings | Outcome |
|------------|--------|------|----------|----------|---------|
| 2026-06-06-EXAMPLE-001 | example.com | 2026-06-06 | 1.5h | 1 (IDOR) | Submitted H1 |
| 2026-06-05-EXAMPLE-001 | example.com | 2026-06-05 | 2h | 2 (SSRF, JWT) | Validating |
| 2026-06-04-OTHER-001 | other.com | 2026-06-04 | 2h | 0 | Killed all |
| 2026-06-03-TEST-001 | test.com | 2026-06-03 | 1h | 1 (XSS) | Submitted BC |
| 2026-06-02-EXAMPLE-001 | example.com | 2026-06-02 | 2h | 0 | Recon only |
```

### 3.2 Completed Session Details

```
SESSION 2026-06-06-EXAMPLE-001
  Target:    example.com
  Program:   HackerOne
  Duration:  1.5h (90min)
  Date:      2026-06-06
  Status:    Completed
  Findings:  IDOR write on PUT /api/v2/users/{id}/profile (High)
  Submitted: Yes — H1-123456
  Outcome:   Triaged
  Payout:    $500
  File:      storage/archive/2026-06-06-EXAMPLE-001.md

SESSION 2026-06-05-EXAMPLE-001
  Target:    example.com
  Program:   HackerOne
  Duration:  2h (120min)
  Date:      2026-06-05
  Status:    Completed
  Findings:  SSRF via /api/avatar (High), JWT alg:none (Critical)
  Submitted: SSRF yes — H1-123455, JWT in progress
  Outcome:   SSRF triaged, JWT validating
  File:      storage/archive/2026-06-05-EXAMPLE-001.md
```

### 3.3 Sessions With No Findings

Tracking dry sessions is important — they reveal scope issues or skill gaps:

```
| Session ID | Target | Date | Duration | Notes |
|------------|--------|------|----------|-------|
| 2026-06-04-OTHER-001 | other.com | 2026-06-04 | 2h | Heavy WAF, no bypass |
| 2026-06-02-EXAMPLE-001 | example.com | 2026-06-02 | 2h | Recon only session |

DRY SESSION STATS:
  Total dry sessions: 2
  Dry rate: [N]% of all sessions
  Common pattern: Heavy WAF, new target first session
```

---

## 4. Session by Target

### 4.1 Target Overview

```
| Target | Sessions | Total Time | Findings | Avg/Session | Last Session |
|--------|----------|------------|----------|-------------|--------------|
| example.com | 4 | 7.5h | 5 | 1.25 | 2026-06-07 |
| other.com | 1 | 2h | 0 | 0 | 2026-06-04 |
| test.com | 1 | 1h | 1 | 1 | 2026-06-03 |
```

### 4.2 Target Session Details

```
example.com — Session History
  2026-06-07 (active): 2h planned — SSRF, JWT, IDOR
  2026-06-06 (1.5h): IDOR write confirmed — submitted H1
  2026-06-05 (2h): SSRF confirmed, JWT alg:none confirmed
  2026-06-02 (2h): Recon only — subdomain enum, tech stack mapping
```

### 4.3 Target Finding Yield

```
example.com:
  SSRF: 1 finding (High)
  JWT: 1 finding (Critical)
  IDOR: 1 finding (High)
  Total: 3 findings
  Pending payout: $0 (not yet paid)

other.com:
  No findings yet
  Notes: Heavy WAF, consider different approach

test.com:
  XSS: 1 finding (Medium)
  Total: 1 finding
  Pending payout: $0 (not yet paid)
```

---

## 5. Session by Bug Class

### 5.1 Bug Class Coverage

```
| Bug Class | Sessions Tested | Findings | Success Rate |
|-----------|-----------------|----------|--------------|
| SSRF | 3 | 1 | 33% |
| IDOR | 3 | 1 | 33% |
| JWT | 2 | 1 | 50% |
| XSS | 2 | 1 | 50% |
| Auth Bypass | 2 | 0 | 0% |
| File Upload | 1 | 0 | 0% |
| Business Logic | 1 | 0 | 0% |
| Race Condition | 1 | 0 | 0% |
| GraphQL | 0 | 0 | — |
| Subdomain Takeover | 0 | 0 | — |
| MFA Bypass | 1 | 0 | 0% |
| SQLi | 0 | 0 | — |
| SSTI | 0 | 0 | — |
| OAuth | 1 | 0 | 0% |
| CSRF | 0 | 0 | — |
| XXE | 0 | 0 | — |
| Cloud Misconfig | 1 | 0 | 0% |
```

### 5.2 Most Successful Bug Classes

Ranked by findings per session tested:

```
1. JWT — 0.50 findings/session (1 in 2 sessions)
2. XSS — 0.50 findings/session (1 in 2 sessions)
3. SSRF — 0.33 findings/session (1 in 3 sessions)
4. IDOR — 0.33 findings/session (1 in 3 sessions)
```

### 5.3 Bug Classes Not Yet Tested

```
Bug classes that have not been tested in any session:

  [ ] SQLi
  [ ] GraphQL
  [ ] Subdomain Takeover
  [ ] SSTI
  [ ] CSRF
  [ ] XXE

Action: Prioritize one untested class per week
```

---

## 6. Time Statistics

### 6.1 Time Investment

```
TOTAL TIME INVESTED: [N] hours
AVERAGE SESSION LENGTH: [N] minutes

TIME BY TARGET:
  example.com: 7.5h (71%)
  other.com: 2h (19%)
  test.com: 1h (10%)

TIME BY PHASE:
  Recon: [N]h ([N]%)
  Active Hunting: [N]h ([N]%)
  Validation: [N]h ([N]%)
  Reporting: [N]h ([N]%)
  Admin/Setup: [N]h ([N]%)
```

### 6.2 Time Efficiency

```
FINDINGS PER HOUR: [N]
TIME PER FINDING: [N] minutes

GOAL: 1 finding per 2h session minimum
```

### 6.3 Weekly Trends

```
WEEK 1 (2026-06-01 to 2026-06-07):
  Sessions: 6
  Hours: 10.5h
  Findings: 5
  Avg session: 1.75h
```

---

## 7. Session Archive

### 7.1 Archived Sessions

Sessions older than 30 days are removed from the active index and stored here:

```
ARCHIVE INDEX:

| Date | Target | ID | Duration | Findings | Archive File |
|------|--------|----|----------|----------|--------------|
| 2026-05-01 | old-target.com | 2026-05-01-OLD-001 | 2h | 0 | archive/2026-05-01.md |
| 2026-04-28 | legacy.com | 2026-04-28-LEGACY-001 | 1.5h | 1 | archive/2026-04-28.md |
```

### 7.2 Archive File Format

Archived session files follow this structure:

```
# Archived Session: YYYY-MM-DD-TARGET-XXX

## Metadata
- Original Session Date: YYYY-MM-DD
- Target: domain.com
- Duration: 2h

## Summary
Brief description of what was accomplished.

## Findings
- Finding 1: Bug class, severity, status
- Finding 2: ...

## Lessons
Lessons learned from this session.

## Raw Notes
Any remaining raw notes (optional).

## File References
- Original session file: context/YYYY-MM-DD-TARGET-XXX.md
```

### 7.3 Archive Maintenance

```
NEXT ARCHIVAL DATE: [YYYY-MM-DD]
SESSIONS TO ARCHIVE: [N]

ARCHIVAL RULES:
  - Sessions older than 30 days from today
  - Sessions with no findings and older than 14 days
  - Completed target investigations (all findings submitted/resolved)

ARCHIVE CHECKLIST:
  [ ] Verify session is complete
  [ ] Copy to storage/archive/
  [ ] Update sessions-index.md
  [ ] Remove from memory/target-registry.md active sessions
```

---

## 8. Maintenance

### 8.1 Index Health

```
REGISTERED SESSIONS: [N]
  - Active: [N]
  - Completed: [N]
  - Archived: [N]

LAST UPDATED: [YYYY-MM-DD HH:MM]
LAST ARCHIVAL: [YYYY-MM-DD]
```

### 8.2 Maintenance Tasks

```
DAILY:
  [ ] Register new session before starting
  [ ] Complete session entry after finishing
  [ ] Update active session status

WEEKLY:
  [ ] Review session statistics
  [ ] Check dry session percentage
  [ ] Plan next week's targets

MONTHLY:
  [ ] Archive old sessions
  [ ] Review bug class coverage gaps
  [ ] Update efficiency metrics
  [ ] Rebalance time investment across targets

QUARTERLY:
  [ ] Full session review
  [ ] Update session template based on lessons
  [ ] Recalculate goals and targets
```

### 8.3 Templates

#### New Session Registration Template

```
SESSION REGISTRATION:
  ID:    YYYY-MM-DD-TARGET-XXX
  Date:  YYYY-MM-DD
  Target:  domain.com
  Program: HackerOne
  Scope:  *.domain.com
  Hunter:  [name]
  Start:   HH:MM
  Planned Duration: 2h
  Focus:  [bug classes]
  Tools:  [tools loaded]
  Accounts: [N]
```

#### Session Completion Template

```
SESSION COMPLETION:
  ID:    YYYY-MM-DD-TARGET-XXX
  End:   HH:MM
  Actual Duration: [N]h [N]min
  Findings Discovered: [N]
  Findings Validated: [N]
  Findings Submitted: [N]
  Session File: context/YYYY-MM-DD-TARGET-XXX.md
  Outcome Summary:
    [2-3 sentence summary]
```

---

## 15. Session Index Maintenance

### When to Add a Session
```
1. Start new hunt → create new session record
2. Resume interrupted session → verify existing record
3. Complete session → update with final stats
4. Archive target → mark all sessions as archived
```

### When to Clean Up
- Stale sessions (no activity for 30+ days)
- Sessions for archived or de-scoped targets
- Test sessions created during tool validation
- Duplicate records from system errors

### Cleanup Procedure
```
1. Identify stale sessions
2. Archive or delete session records
3. Remove corresponding context files
4. Update cross-references in other storage files
5. Log cleanup to lessons-log.md
6. Update findings archive if affected
```

---

## 16. Session Index Health Checks

| Check | Frequency | Description | Fix |
|-------|-----------|-------------|-----|
| Cross-ref integrity | Per session | All sessions link to valid finding IDs | Remove orphan sessions |
| Timestamp ordering | Per session | New sessions have later timestamps | Fix any out-of-order entries |
| Duration accuracy | Weekly | Recorded duration matches evidence | Adjust if evidence shows different |
| Finding count | Weekly | Session finding count matches archive | Recount if mismatch |
| File existence | Monthly | All session context files exist | Flag missing files |

---

## 17. Session Search & Retrieval

### Search by Target
```
Select target from [target-registry.md]
  → Find all sessions for target
  → Filter by status (ACTIVE / COMPLETED / ARCHIVED)
  → Sort by date (newest first)
  → Read session details
```

### Search by Finding
```
Select finding from [findings-archive.md]
  → Find session that generated it
  → Review session context for testing methodology
  → Check if other findings from same session are related
```

### Search by Date Range
```
Specify date range
  → List all sessions within range
  → Group by target
  → Calculate total time spent per target
  → Identify patterns (e.g., most productive days)
```

---

## 18. Backup & Recovery

### Session Backup
- Full index backup triggered every 10 sessions
- Individual session backup on completion
- Automatic backup before any cleanup operation

### Recovery from Index Corruption
```
1. Identify the last valid backup
2. Restore sessions-index.md from backup
3. Check against findings-archive.md for consistency
4. Restore any missing session context files
5. Verify all cross-references are valid
6. Log the recovery event
```

### Versioning
Each session record includes a version field. When updating:
- Increment minor version (v1.0 → v1.1) for small edits
- Increment major version (v1.0 → v2.0) for bulk updates
- Track version history in last modified timestamp

