---
name: memory-universal
description: Universal memory context for Jiggy-2026. Master memory index — the persistent brain that survives between sessions, across tool restarts, and between different AI coding CLIs. Tracks every target, session, discovery, lead, lesson, and cross-hunt state in one centralized index.
---

# Universal Memory Context

This file is the persistent memory backbone of Jiggy-2026. It is the first file loaded in every session and the last file updated when a session ends. Every tool, agent, and skill relies on this index to know what has been done, what is being worked on, and what should happen next.

---

## 1. Memory Architecture Overview

```
memory/
├── universal.md         ← THIS FILE — master memory index and cross-hunt state
├── persistence.md       ← Session lifecycle, save/restore, garbage collection
├── target-registry.md   ← All targets ever worked: scope, status, metadata
├── lessons-log.md       ← Cross-hunt lessons, wins, losses, techniques learned
├── session-state.md     ← Current live hunt session: step-by-step progress
├── discoveries.md       ← Interesting leads, partial findings, chain opportunities
└── technical-notes.md   ← Deep technical research: tech stacks, auth, endpoints
```

Every write to any memory file should be reflected in the relevant section of this index. This file is the single source of truth for "what do we know?"

---

## 2. Session Lifecycle State Machine

```
START → INIT → RECON → HUNT → VALIDATE → REPORT → SUBMIT → REVIEW → DONE
                ↑        ↓        ↑           ↑                  ↓
                └────────┴────────┴───────────┴──────────────────┘
                    (loop back if new findings)
```

### State Definitions

| State | Description | Duration | Exit Criteria |
|-------|-------------|----------|---------------|
| INIT | Load memory, verify scope, set up tools | 5 min | All tools loaded, target verified |
| RECON | Active recon: subdomains, crawling, fuzzing | 30-120 min | No new assets after 2 rounds |
| HUNT | Active testing: IDOR, XSS, SSRF, auth, logic | 60-180 min | No signal after 3 rotations |
| VALIDATE | Confirm findings, check scope, run 7 gates | 10-20 min | Finding passes or fails validation |
| REPORT | Write report, capture evidence | 20-40 min | Report complete, ready to submit |
| SUBMIT | Submit to platform, document response | 10 min | Confirmation received |
| REVIEW | Review triage outcome, update lessons | 5-10 min | Outcome documented |
| DONE | Target complete, archive findings | — | All P1-P3 leads exhausted |

---

## 3. Master Target Index

### Active Targets

| # | Target | Domain | Program | Status | Phase | Findings | Last Active |
|---|--------|--------|---------|--------|-------|----------|-------------|
| — | — | — | — | — | — | — | — |

### Completed Targets

| # | Target | Findings | Bounty | Submitted | Outcome |
|---|--------|----------|--------|-----------|---------|
| — | — | — | — | — | — |

### Stale / Archived Targets

| # | Target | Reason Archived | Last Active | Possible Return |
|---|--------|----------------|-------------|----------------|
| — | — | — | — | — |

### Blocked Targets

| # | Target | Block Reason | Blocked Since | Unblock Condition |
|---|--------|-------------|---------------|-------------------|
| — | — | — | — | — |

---

## 4. Current Session State

| Field | Value |
|-------|-------|
| **Target** | — |
| **Program** | — |
| **Phase** | — |
| **Session ID** | — |
| **Started** | — |
| **Elapsed** | — |
| **Time Budget** | — |
| **Tools Loaded** | — |
| **Focus Area** | — |
| **Current Endpoint** | — |
| **Working Hypothesis** | — |
| **Next Action** | — |
| **Blocker** | — |

---

## 5. Finding Pipeline

### Active Findings (In Progress / Ready to Submit)

| # | Target | Bug Class | Endpoint | Severity | Status | Chain With |
|---|--------|-----------|----------|----------|--------|------------|
| — | — | — | — | — | — | — |

### Submitted Findings

| # | Target | Bug Class | Program | Severity | Bounty | Date | Outcome |
|---|--------|-----------|---------|----------|--------|------|---------|
| — | — | — | — | — | — | — | — |

### Killed Findings (Failed Validation)

| # | Target | Bug Class | Why Killed | Gate Failed | Date |
|---|--------|-----------|------------|-------------|------|
| — | — | — | — | — | — |

---

## 6. Priority Lead Pipeline

### P1 — Hunt Now

| Lead | Target | Endpoint | Why P1 | Started | Time Spent |
|------|--------|----------|--------|---------|------------|
| — | — | — | — | — | — |

### P2 — Hunt After Current

| Lead | Target | Endpoint | Why P2 | ETA |
|------|--------|----------|--------|-----|
| — | — | — | — | — |

### P3 — Nice to Have

| Lead | Target | Endpoint | Notes |
|------|--------|----------|-------|
| — | — | — | — |

### P4 — Information Only

| Lead | Target | Notes |
|------|--------|-------|
| — | — | — |

---

## 7. Cross-Hunt Knowledge Base

### Tech Stack Encyclopedia

```
target.com:
  - Frontend: React 18 (SPA), Webpack 5
  - Backend: Node.js 20, Express 4
  - API: REST + GraphQL (Apollo)
  - Auth: JWT (Bearer) + session cookies
  - WAF: Cloudflare
  - CDN: Cloudflare
  - Hosting: AWS (us-east-1)
  - DB: PostgreSQL (inferred from error messages)
  - Cache: Redis (inferred from headers)
  - Queue: SQS (inferred from /health response)
```

### Authentication Patterns Registry

```
target.com:
  - Login: POST /api/auth/login → {email, password} → JWT + session cookie
  - MFA: POST /api/auth/mfa/verify → {code} → optional after login
  - Password Reset: POST /api/auth/reset → {email} → email link
  - Session: Cookie "session" + Authorization "Bearer <jwt>"
  - JWT Decode: {"alg":"HS256","typ":"JWT"}.{"sub":"user_123","role":"user","iat":...}
  - Rate Limit: 5 attempts per IP per 15 min on /login
  - Lockout: 15 min after 5 failed attempts
```

### API Endpoint Catalog

```
target.com:
  REST Base: /api/v2
  GraphQL: /graphql (POST)
  
  Auth:
    POST /api/v2/auth/login          → 200 {token, session}
    POST /api/v2/auth/register        → 201 {user}
    POST /api/v2/auth/refresh         → 200 {token}
    POST /api/v2/auth/logout          → 204
    POST /api/v2/auth/reset-password  → 200 {message}
    
  Users:
    GET  /api/v2/users/me             → 200 {user}
    GET  /api/v2/users/{id}           → 200 {user} | 403
    PUT  /api/v2/users/me/profile     → 200 {user}
    POST /api/v2/users/me/avatar      → 200 {url}
    
  Invoices:
    GET  /api/v2/invoices             → 200 [{invoice}]
    GET  /api/v2/invoices/{id}        → 200 {invoice} | 403
    POST /api/v2/invoices             → 201 {invoice}
    PUT  /api/v2/invoices/{id}        → 200 {invoice}
    DELETE /api/v2/invoices/{id}      → 204
    
  Admin:
    GET  /api/v2/admin/users          → 200 [{user}]  (auth required)
    POST /api/v2/admin/users          → 201 {user}    (auth required)
    GET  /api/v2/admin/logs           → 200 [{log}]
    
  GraphQL:
    POST /graphql
    introspection: enabled/disabled
```

### Known Vulnerability Chains

```
Chain A: IDOR on invoice ID + no rate limit on PDF generation
  → A: GET /api/v2/invoices/{id} returns any invoice (IDOR)
  → B: GET /api/v2/invoices/{id}/pdf also returns any invoice (no extra auth)
  → Impact: Mass PDF exfiltration of all invoices
  → Status: A confirmed, B untested

Chain B: SSRF in avatar URL + internal Redis accessible
  → A: PUT /api/v2/users/me/avatar {"url":"..."} fetches URL server-side
  → B: Point to internal Redis → read session tokens
  → Impact: Session theft → ATO
  → Status: A confirmed, B requires Redis access verification
```

---

## 8. Time Tracking & Budget

### Session Budget

| Activity | Budget | Spent | Remaining |
|----------|--------|-------|-----------|
| Recon | 60 min | — | — |
| IDOR Testing | 30 min | — | — |
| SSRF Testing | 30 min | — | — |
| XSS Testing | 30 min | — | — |
| Auth Testing | 45 min | — | — |
| Business Logic | 30 min | — | — |
| Validation | 20 min | — | — |
| Reporting | 40 min | — | — |
| **Total** | **285 min** | — | — |

### Session Log

| Time | Activity | Target | Notes |
|------|----------|--------|-------|
| — | — | — | — |

---

## 9. Tooling State

### Loaded Tools

| Tool | Path | Loaded | Version | Notes |
|------|------|--------|---------|-------|
| curl-hunter | tools/powershell/curl-hunter.ps1 | ✓/✗ | — | — |
| powershell-lib | tools/powershell/powershell-lib.ps1 | ✓/✗ | — | — |
| python-hunter | tools/python/python-hunter.py | ✓/✗ | — | — |
| recon-toolkit | tools/powershell/recon-toolkit.ps1 | ✓/✗ | — | — |
| fuzzer-toolkit | tools/powershell/fuzzer-toolkit.ps1 | ✓/✗ | — | — |
| evidence-toolkit | tools/powershell/evidence-toolkit.ps1 | ✓/✗ | — | — |
| js-analyzer | tools/powershell/js-analyzer.ps1 | ✓/✗ | — | — |

### External Tool Availability

| Tool | Available | Path | Notes |
|------|-----------|------|-------|
| curl.exe | ✓/✗ | — | — |
| python3 | ✓/✗ | — | — |
| subfinder | ✓/✗ | — | — |
| httpx | ✓/✗ | — | — |
| dnsx | ✓/✗ | — | — |
| ffuf | ✓/✗ | — | — |
| nuclei | ✓/✗ | — | — |

---

## 10. Decision Log

### Key Decisions Made This Session

| # | Time | Decision | Rationale | Outcome |
|---|------|----------|-----------|---------|
| — | — | — | — | — |

### Open Questions

| # | Question | Target | Need To Decide By | Answer |
|---|----------|--------|-------------------|--------|
| — | — | — | — | — |

---

## 11. Risk Register

| Risk | Likelihood | Impact | Mitigation | Status |
|------|-----------|--------|------------|--------|
| Out of scope test | Low | Report rejected | Verify scope before each test | Active |
| WAF block | Medium | Lost access | Rotate IPs, rate limit, passive first | Active |
| Duplicate finding | Medium | No bounty | Check disclosed reports first | Active |
| Account banned | Low | Loss of access | Separate test accounts, no aggression | Active |
| Evidence lost | Low | Report invalidated | Save everything immediately | Active |

---

## 12. Memory Health

### Consistency Checks

- [ ] All active targets have a status in master index
- [ ] All P1 leads have a started timestamp
- [ ] All submitted findings have an outcome
- [ ] Session state matches actual progress
- [ ] Lessons-log has at least one entry per target
- [ ] Storage files exist for current target
- [ ] Evidence captured for all confirmed findings
- [ ] Scope verified for each target tested

### Maintenance Schedule

| Task | Frequency | Last Done |
|------|-----------|-----------|
| Prune stale targets | Weekly | — |
| Archive completed targets | Weekly | — |
| Review P3/P4 leads | Weekly | — |
| Check tool updates | Monthly | — |
| Clean storage artifacts | Monthly | — |
| Back up memory files | Weekly | — |

---

## 13. Session Handoff Protocol

When a session ends and another begins, the following must be loaded:

```
1. Read universal.md → restore master index, session state, active target
2. Read target-registry.md → restore current target details
3. Read session-state.md → restore step-by-step progress
4. Read discoveries.md → restore active leads
5. Load persistence.md → check save/restore validity
6. Verify → all timestamps are consistent
7. Confirm → session ID matches expected
```

Any inconsistency in timestamps or session IDs must be flagged before work resumes.

---

## 14. Emergency Override

If the session state is corrupted or inconsistent:

```
1. FREEZE — stop all testing
2. DUMP — save all current tool outputs to storage/tool-outputs.md
3. LOG — write current state to persistence.md
4. RESET — clear session-state.md
5. RESTORE — reload from last known good state in persistence.md
6. VERIFY — confirm restored state is consistent
7. RESUME — continue with restored state
```

---

## 15. Notes & Meta-Reflections

This section is free-form. Use it for cross-hunt observations, strategy notes, tooling improvements, and anything that doesn't fit elsewhere.

```
[date] — [observation]
```

---

## 16. Memory Indexing Rules

### Rule 1: One Entry Per Event
Every finding, lead, decision, and session gets exactly one entry in the index. No duplicates. No orphans.

### Rule 2: Update on Every Phase Change
When the hunting phase changes (recon → hunt → validate → report → submit), update the master index immediately.

### Rule 3: Cross-Reference Everything
Every finding references its evidence. Every lead references its session. Every session references its findings. The index is a graph, not a list.

### Rule 4: Timestamp All Changes
Every update to any memory file includes a timestamp. Without timestamps, the index has no ordering and no audit trail.

### Rule 5: Clean Empty Entries
Empty sections (no active targets, no current session) should be marked with em-dashes, not left blank. This distinguishes "not filled in yet" from "empty/no data."

### Rule 6: Archive Before Delete
Never delete entries from the index. Archive them to the archive section. Deleted entries mean lost knowledge.

### Rule 7: Self-Check on Load
Every session start verifies the index is consistent. If the index disagrees with the files it indexes, the index wins (it was updated most recently).

---

## 17. Common Index Operations

### Adding a New Target
```
1. Add to Master Target Index (§3) with status=ACTIVE
2. Initialize target sections in all memory files
3. Verify target scope in scope-records.md
4. Set session phase to INIT
5. Update "Last Active" timestamp
```

### Adding a New Finding
```
1. Add to Finding Pipeline (§5) with status=TESTING
2. Create evidence package reference
3. Link to source lead (if applicable)
4. Update target finding count
5. Update session state
```

### Completing a Session
```
1. Set session status to COMPLETED
2. Update all time tracking (§8)
3. Archive completed phase data
4. Update target last active timestamp
5. Write next actions
6. Verify all cross-references are consistent
```

### Archiving a Target
```
1. Set target status to ARCHIVED
2. Move active findings to submitted or killed
3. Archive all associated storage
4. Clear session state
5. Write final summary to target-registry.md
6. Update master index
```

---

## 18. Index Health Scoring

Run this health check weekly to ensure the memory index is accurate:

| Check | Score | Notes |
|-------|-------|-------|
| All active targets have valid status | — | — |
| All findings have a severity assigned | — | — |
| All P1 leads have a started timestamp | — | — |
| No duplicate target entries | — | — |
| All cross-references resolve | — | — |
| Session state matches actual elapsed time | — | — |
| Lessons-log has entries for completed targets | — | — |
| Timestamps are chronological | — | — |
| No orphaned evidence references | — | — |
| Storage index matches actual files | — | — |

**Score:** /10 — entries with issues flagged for review

---

## 19. Emergency Index Recovery

If the universal.md index is corrupted or lost:

```
1. [ASSESS DAMAGE] — What sections are affected?
2. [COLLECT DATA] — Read all other memory files for their state
3. [REBUILD] — Reconstruct master index from peer files
   - targets → target-registry.md
   - findings → findings-archive.md (storage/)
   - sessions → sessions-index.md (storage/)
   - leads → discoveries.md
   - lessons → lessons-log.md
4. [VERIFY] — Check reconstructed index against all peer files
5. [FIX] — Any inconsistencies in peer files vs reconstructed index
6. [LOG] — Write the rebuild event to lessons-log.md
7. [RESTORE] — Save rebuilt index as universal.md
```

This recovery can reconstruct approximately 95% of the index state from peer files alone.

---

## 20. Memory File Dependency Map

```
universal.md ──┬── target-registry.md    (target data)
               ├── lessons-log.md        (lessons reference)
               ├── session-state.md      (current state)
               ├── discoveries.md        (lead pipeline)
               ├── technical-notes.md    (tech reference)
               ├── persistence.md        (save/restore config)
               ├── storage/universal.md  (storage index)
               ├── storage/evidence-packages.md
               ├── storage/findings-archive.md
               ├── storage/hunt-logs.md
               ├── storage/scope-records.md
               ├── storage/credentials-vault.md
               └── storage/sessions-index.md
```

Every arrow represents a cross-reference. If any file is missing or corrupted, the affected references are flagged at session start.

---

## 21. Multi-Session Workflow State

When a target requires multiple sessions, track the overall state here.

### Target Progress: [target.com]

| Session | Date | Phase | Findings | Status |
|---------|------|-------|----------|--------|
| JGY-20260315-143022-4a7f | 2026-03-15 | HUNT | 6 found | COMPLETED |
| JGY-20260316-090000-3b2c | 2026-03-16 | REPORT | 6 reported | COMPLETED |
| — | — | — | — | PLANNED |

### Multi-Session State Machine

```
SESSION 1 (Recon)
  → Discover attack surface
  → Identify high-value endpoints
  → Plan hunt strategy
  
SESSION 2 (Hunt — IDOR/Auth)
  → Test high-priority bug classes
  → Confirm findings
  → Capture evidence
  
SESSION 3 (Hunt — SSRF/XSS/Logic)
  → Test remaining bug classes
  → Explore chain opportunities
  → Capture evidence
  
SESSION 4 (Validate/Report)
  → Run 7-Question Gate on all findings
  → Write reports
  → Chain related findings
  
SESSION 5 (Submit/Review)
  → Submit to program
  → Monitor triage
  → Update lessons
```

---

## 22. Recurring Tasks

Tasks that repeat across all targets:

| Task | Frequency | Last Done | Next Due | Notes |
|------|-----------|-----------|----------|-------|
| Search target in disclosed reports | Per target | — | — | Avoid duplicates |
| Verify scope document | Per target | — | — | Check for changes |
| Check for CVE disclosures | Weekly | — | — | New vulnerabilities |
| Review program policy | Per target | — | — | Scope changes |
| Rotate test credentials | Per target | — | — | After completion |


