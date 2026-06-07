---
name: session-state
description: Live hunt session state tracker for Hercules-Hunt. Records step-by-step progress, endpoint queue, time tracking, test results matrix, hypothesis tracking, What-If experiment log, and next actions. Updated every heartbeat and at every phase transition.
---

# Session State

This file tracks the current live hunt session. It is updated every 5 minutes (heartbeat) and every time the phase, endpoint, or finding status changes. If this file is empty, no active session exists.

---

## 1. Session Header

| Field | Value |
|-------|-------|
| **Session ID** | — |
| **Target** | — |
| **Domain** | — |
| **Program** | — |
| **Platform** | — |
| **Started** | — |
| **Last Heartbeat** | — |
| **Elapsed Time** | — |
| **Phase** | — |
| **Status** | — |

### Status Values
- `ACTIVE` — Session is live and running
- `PAUSED` — Session interrupted (user break or timeout)
- `COMPLETED` — Session finished normally
- `ABANDONED` — Session abandoned due to interruption

---

## 2. Phase Tracker

| Phase | Status | Started | Completed | Duration | Outcome |
|-------|--------|---------|-----------|----------|---------|
| INIT | ☐ | — | — | — | — |
| RECON | ☐ | — | — | — | — |
| HUNT | ☐ | — | — | — | — |
| VALIDATE | ☐ | — | — | — | — |
| REPORT | ☐ | — | — | — | — |
| SUBMIT | ☐ | — | — | — | — |
| REVIEW | ☐ | — | — | — | — |

---

## 3. Current Focus

| Field | Value |
|-------|-------|
| **Bug Class** | — |
| **Endpoint** | — |
| **HTTP Method** | — |
| **Parameters** | — |
| **Auth Required** | — |
| **Working Hypothesis** | — |
| **Test Round** | — |
| **Time Spent on Current** | — |

---

## 4. Endpoint Queue

### Current Endpoint
```
URL:      —
Method:   —
Headers:  —
Body:     —
Auth:     —
Notes:    —
```

### Queued Endpoints (To Test)

| # | URL | Method | Bug Class | Priority | Notes |
|---|-----|--------|-----------|----------|-------|
| — | — | — | — | — | — |

### Completed Endpoints

| # | URL | Method | Bug Classes Tested | Result | Time |
|---|-----|--------|-------------------|--------|------|
| — | — | — | — | — | — |

---

## 5. Test Results Matrix

### IDOR Testing

| Endpoint | Method | Parameter | Own ID | Other ID | Result | Notes |
|----------|--------|-----------|--------|----------|--------|-------|
| /api/v2/invoices/{id} | GET | id | 200 (own data) | 200 (other's data) | VULNERABLE | No ownership check |
| /api/v2/invoices/{id} | PUT | id | 200 (updated) | 200 (updated other's) | VULNERABLE | Write IDOR |
| /api/v2/invoices/{id} | DELETE | id | 204 (deleted) | 204 (deleted other's) | VULNERABLE | Delete IDOR |
| /api/v2/invoices/{id}/pdf | GET | id | 200 (own PDF) | 200 (other's PDF) | VULNERABLE | PDF generation IDOR |
| /api/v2/invoices | POST | — | — | — | NOT TESTED | — |
| /api/v2/users/{id} | GET | id | 200 (own data) | 403 (access denied) | SECURE | Has ownership check |

### SSRF Testing

| Endpoint | Parameter | Payload | Result | Notes |
|----------|-----------|---------|--------|-------|
| /api/user/avatar | url | http://169.254.169.254/ | BLOCKED | WAF catch |
| /api/user/avatar | url | http://[::ffff:169.254.169.254]/ | BLOCKED | WAF catch |
| /api/user/avatar | url | http://0x7f000001/ | BLOCKED | WAF catch |
| /api/user/avatar | url | http://burpcollaborator.net | DNS CALLBACK | SSRF confirmed |
| /api/user/avatar | url | http://internal.target.com/ | 200 (internal page) | SSRF confirmed |
| /api/import | url | http://169.254.169.254/ | 200 (IAM creds) | CRITICAL |

### XSS Testing

| Endpoint | Parameter | Payload | Reflected | Stored | Result |
|----------|-----------|---------|-----------|--------|--------|
| /api/user/profile | name | <script>alert(1)</script> | NO | NO | SAFE |
| /api/user/profile | bio | <img src=x onerror=alert(1)> | NO | YES | VULNERABLE (Stored) |
| /api/support/ticket | message | <script>alert(1)</script> | NO | YES | VULNERABLE (Stored) |
| /search?q= | q | <script>alert(1)</script> | YES (HTML encoded) | N/A | SAFE |
| /search?q= | q | "><script>alert(1)</script> | YES (raw) | N/A | VULNERABLE (Reflected) |

### Auth Bypass Testing

| Endpoint | Method | Without Auth | With Auth (User) | With Auth (Admin) | Result |
|----------|--------|-------------|-----------------|-------------------|--------|
| /api/admin/users | GET | 401 | 403 | 200 | SECURE |
| /api/admin/users | POST | 201 (created admin) | 201 | 201 | CRITICAL (no auth) |
| /api/v2/invoices | GET | 401 | 200 | 200 | SECURE |
| /api/v2/invoices/{id} | GET | 401 | 200 (own only) | 200 (all) | SECURE (if properly implemented) |

### Business Logic Testing

| Endpoint | Test | Normal Result | Anomalous Input | Result |
|----------|------|--------------|-----------------|--------|
| /api/checkout | Negative quantity | $100 total | qty=-1 → -$100 | VULNERABLE (credit generation) |
| /api/checkout | Decimal quantity | $100 total | qty=0.5 → $50 | EXPECTED (partial allowed) |
| /api/coupons/redeem | Race condition | 1 success | 20 parallel → 12 successes | VULNERABLE |
| /api/auth/reset-password | Predictable token | Random token | token=123456 → works | VULNERABLE |

---

## 6. Hypothesis Log

| # | Hypothesis | Target | Test Method | Result | Date |
|---|-----------|--------|-------------|--------|------|
| 1 | Invoice IDs are sequential and enumerable | /api/v2/invoices/{id} | GET 1 → 100 | CONFIRMED — IDs 1-50000 all valid | 2026-03-15 |
| 2 | Avatar URL fetch blocks public IPs but allows internal | /api/user/avatar | SSRF to internal.target.com | CONFIRMED — internal DNS resolves | 2026-03-15 |
| 3 | Admin endpoint auth check is client-side only | /api/admin/users | POST without Authorization header | CONFIRMED — 201 Created | 2026-03-15 |
| 4 | Coupon redemption is not atomic | /api/coupons/redeem | 20 parallel requests | CONFIRMED — 12/20 succeeded | 2026-03-15 |
| 5 | JWT uses weak HMAC secret | /api/auth/login | Collected JWT → brute-force secret | REFUTED — HS256 with strong secret | 2026-03-15 |
| 6 | GraphQL introspection is enabled | /graphql | query {__schema{types{name}}} | CONFIRMED — full schema exposed | 2026-03-15 |
| 7 | Password reset token is timestamp-based | /api/auth/reset | Analyze token pattern | REFUTED — crypto-random | 2026-03-16 |

---

## 7. What-If Experiment Log

| # | What If... | Experiment | Time Allowed | Result |
|---|-----------|------------|-------------|--------|
| 1 | What if invoice IDs work across user sessions? | Session A (user1) → invoice 5000 | 2 min | CONFIRMED — cross-user access |
| 2 | What if avatar URL accepts data: URIs? | url=data:image/png;base64,... | 2 min | REJECTED — invalid format |
| 3 | What if rate limiting is per-IP, not per-user? | Same IP, different user: 100 requests | 5 min | REFUTED — rate limit is per-session |
| 4 | What if admin creation logs to an endpoint we can access? | GET /api/admin/logs after creating admin | 3 min | CONFIRMED — logs visible to any user |
| 5 | What if coupon code is case-sensitive? | Code=SAVE20, save20, Save20 | 2 min | CONFIRMED — case INsensitive (easier to exploit) |
| 6 | What if deleting an invoice doesn't invalidate the PDF? | DELETE /api/v2/invoices/100 → GET /api/v2/invoices/100/pdf | 2 min | CONFIRMED — PDF still accessible after delete |
| 7 | What if password reset link doesn't expire after use? | Use reset link → reset again → same link works | 3 min | REFUTED — single-use token |

---

## 8. Time Budget Tracker

### Session Allocation

| Activity | Budget | Spent | Remaining | % Used |
|----------|--------|-------|-----------|--------|
| Recon | 60 min | — | — | —% |
| IDOR Testing | 30 min | — | — | —% |
| SSRF Testing | 30 min | — | — | —% |
| XSS Testing | 30 min | — | — | —% |
| Auth Testing | 45 min | — | — | —% |
| Business Logic | 30 min | — | — | —% |
| Validation | 20 min | — | — | —% |
| Reporting | 40 min | — | — | —% |
| **Total** | **285 min** | — | — | —% |

### Per-Endpoint Time

| Endpoint | Bug Class | Start | Budget | Spent | Result |
|----------|-----------|-------|--------|-------|--------|
| — | — | — | 10 min | — | — |
| — | — | — | 10 min | — | — |
| — | — | — | 10 min | — | — |

### Time Checkpoints

```
[Session Start] — 0:00
[Recon Done] — 0:00
[Hunt Start] — 0:00
[First Finding] — 0:00
[Last Finding] — 0:00
[Validate Done] — 0:00
[Report Done] — 0:00
[Submit Done] — 0:00
[Session End] — 0:00
```

---

## 9. Activity Timeline

| Time | Action | Target | Duration | Notes |
|------|--------|--------|----------|-------|
| — | — | — | — | — |

---

## 10. Findings Discovered This Session

| # | Time | Bug Class | Endpoint | Severity | Status | Notes |
|---|------|-----------|----------|----------|--------|-------|
| — | — | — | — | — | — | — |

---

## 11. Current Blocker

| Field | Value |
|-------|-------|
| **Blocked Since** | — |
| **Blocker Type** | — |
| **Description** | — |
| **Unblock Strategy** | — |
| **Fallback** | — |

### Blocker Types
- `TOOL_UNAVAILABLE` — Required tool not installed
- `WAF_BLOCKED` — IP blocked by WAF
- `ACCOUNT_BANNED` — Test account disabled
- `ENDPOINT_DOWN` — Endpoint returning 5xx
- `AUTH_REQUIRED` — Can't bypass authentication
- `SCOPE_UNCLEAR` — Need to verify scope
- `NEEDS_RESEARCH` — Need to research a technique
- `TIME_OVERRUN` — Time budget exceeded

---

## 12. Next Actions

### Immediate (Do Now)
1. —
2. —
3. —

### Short-Term (This Session)
1. —
2. —
3. —

### Long-Term (Future Session)
1. —
2. —
3. —

---

## 13. Session Notes

Free-form notes about the current session:

```
- [Observation]
- [Idea]
- [Question for later]
- [Tool issue]
- [Interesting response pattern]
- [WAF behavior noted]
```

---

## 14. Exit Criteria

This session is complete when:

```
[ ] All P1 leads exhausted
[ ] All high-value endpoints tested for top 3 bug classes
[ ] No more testable hypotheses remaining
[ ] Time budget consumed or overrun justified
[ ] All confirmed findings validated
[ ] Reports written for all confirmed findings
[ ] Lessons updated in lessons-log.md
[ ] Memory files saved and backed up
```

---

## 15. Bug Class Rotation Timer

Use this timer to rotate through bug classes. Spend no more than 10-20 minutes on a class per endpoint without a finding.

| Bug Class | Time Per Endpoint | Endpoints Tested | Total Time | Findings |
|-----------|------------------|-----------------|------------|----------|
| IDOR | 10 min | — | — | — |
| SSRF | 15 min | — | — | — |
| XSS | 10 min | — | — | — |
| Auth Bypass | 15 min | — | — | — |
| Business Logic | 15 min | — | — | — |
| Race Condition | 10 min | — | — | — |
| SQLi | 20 min | — | — | — |
| GraphQL | 15 min | — | — | — |
| File Upload | 15 min | — | — | — |
| SSTI | 10 min | — | — | — |
| CSRF | 5 min | — | — | — |
| Open Redirect | 5 min | — | — | — |
| Info Disclosure | 10 min | — | — | — |
| Mass Assignment | 10 min | — | — | — |
| JWT | 10 min | — | — | — |

---

## 16. Session Action Log

Detailed action-by-action log of everything done this session.

| # | Time | Action | Input | Output | Result | Duration | Evidence ID |
|---|------|--------|-------|--------|--------|----------|-------------|
| — | — | — | — | — | — | — | — |

### Action Types
- `RECON` — Reconnaissance activity
- `FUZZ` — Fuzzing/directory bruteforce
- `TEST` — Manual vulnerability test
- `VALIDATE` — Confirming/reproducing a finding
- `CHAIN` — Testing chain between findings
- `EVIDENCE` — Capturing evidence
- `REPORT` — Writing a report
- `RESEARCH` — Looking up technique or config

---

## 17. Confidence Log

For every tested hypothesis, record your confidence level before and after testing.

| # | Hypothesis | Pre-Test Confidence | Post-Test Confidence | Result | Lesson |
|---|-----------|-------------------|--------------------|--------|--------|
| — | — | — | — | — | — |

### Confidence Scale
- `1 — Uncertain` — Low likelihood
- `3 — Plausible` — Reasonable chance
- `5 — Likely` — Good probability
- `7 — Very Likely` — Strong expectation
- `10 — Certain` — Confirmed by others or documentation

---

## 18. Related Findings Cross-Reference

List findings from this session that relate to findings from other sessions or targets.

| This Session Finding | Related Finding | Target | Relationship |
|--------------------|----------------|--------|-------------|
| — | — | — | — |

### Relationship Types
- `SAME_BUG` — Same bug class and vector, different endpoint
- `CHAIN_A` — This finding is the A in an A→B chain
- `CHAIN_B` — This finding is the B in an A→B chain
- `PATTERN` — Same vulnerability pattern across targets
- `TECH_SPECIFIC` — Same technology, different targets
- `LEARNED_FROM` — Used technique learned from prior session

---

## 19. Session Quality Metrics

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| Findings per hour | — | >1.0 | — |
| Time per finding | — | <30 min | — |
| Endpoint coverage | — | >80% of high-value endpoints | — |
| Bug class coverage | — | >5 classes tested | — |
| Evidence quality score | — | >8/10 | — |
| Report quality score | — | >8/10 | — |
| Kill rate (killed/total leads) | — | <50% | — |
| Conversion rate (confirmed/tested) | — | >30% | — |

---

## 20. Session Termination Reasons

When a session ends, log the primary reason:

| Reason | Description | Follow-Up |
|--------|-------------|-----------|
| TIME_BUDGET_EXHAUSTED | Session time ran out | Schedule next session |
| ALL_LEADS_EXHAUSTED | No more testable leads | Move to report phase |
| TARGET_EXHAUSTED | All high-value endpoints tested | Archive target or move to new target |
| WAF_BLOCKED | IP or account blocked | Rotate and wait |
| TOOL_FAILURE | Critical tool unavailable | Fix tooling, resume |
| USER_INTERRUPTION | Manual stop by user | Save state for resume |
| EXTERNAL_FACTOR | Network, platform, or other | Resume when resolved |
| GOAL_ACHIEVED | Session goal met early | Review if time remains for more |

---

## 21. Session Recovery Data

If the session is interrupted, this section stores the recovery checkpoint.

```
=== Last Checkpoint ===
Timestamp: [YYYY-MM-DD HH:MM:SS UTC]
Phase: [current phase]
Current Endpoint: [URL being tested]
Current Bug Class: [bug class being tested]
Last Action: [what was being done]
Findings This Session: [N confirmed, N in progress]
Evidence Saved: [N packages]
Next Action: [what to do on resume]
```

### Auto-Save Trigger
Session auto-saves every time:
- A finding is confirmed or killed
- A phase transition occurs
- The session is active for 5+ minutes without a save
- User executes a manual `Save-JiggySession` command

### Recovery Check
On resume, verify:
1. All findings captured match evidence packages
2. No duplicate testing on already-completed endpoints
3. Session timestamp is continuous (no gap > 15 min)
4. All saved evidence is accessible

---

## 22. Parallel Session Tracking

If working on multiple targets in parallel, track each session separately.

| Target | Session ID | Phase | Last Active | Priority | Interleave |
|--------|-----------|-------|-------------|----------|------------|
| — | — | — | — | — | — |

### Interleaving Rules
- Only ONE session per target at a time
- Maximum 2 targets in parallel
- Each switch costs ~5 min context recovery
- Track total interleaving overhead

### Context Switch Cost
```
Session A → Session B:
  Save A:  2 min
  Load B:  3 min
  Recover: 2 min
  Total:   7 min lost per switch
```

---

## 23. Session Artifacts Index

Every session generates artifacts. Track them here.

| Artifact Type | Description | Path | Session ID |
|--------------|-------------|------|------------|
| Tool output | [tool] [target] [date] | storage/tool-outputs.md | — |
| Evidence | [finding ID] | storage/evidence-packages.md | — |
| Screenshot | [description] | assets/screenshots/ | — |
| Log entry | [session log] | storage/hunt-logs.md | — |

---

## 24. Session State Inconsistency Checks

If something feels wrong about the session state, run these diagnostics:

```
[DIAG] Last heartbeat: [timestamp]
[DIAG] Expected vs actual elapsed: [expected N min, actual N min]
[DIAG] File write test: [PASS/FAIL]
[DIAG] Cross-reference consistency: [PASS/FAIL]

Corrective actions:
1. Reads timing mismatch → force heartbeat write
2. File write fails → check disk space
3. Cross-ref fails → re-read all memory files
4. If all fails → save what you can, start fresh session
```

---

## 25. State Diff Tracking

Track what changed between consecutive sessions:

| State Variable | Session A | Session B | Delta |
|---------------|-----------|-----------|-------|
| Active target | — | — | — |
| Phase | — | — | — |
| Findings count | — | — | — |
| Leads count | — | — | — |
| Endpoint queue size | — | — | — |
| Time spent | — | — | — |

