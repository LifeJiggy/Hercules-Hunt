---
name: storage-hunt-logs
description: Session execution logs and activity timelines for Hercules-Hunt. Records every hunting session in detail — endpoints tested, results observed, time spent, tools used, hypotheses tested, and findings discovered. Session timelines are the raw material for reports and lessons learned.
---

# Hunt Logs

This file records every hunting session in chronological order. Every endpoint tested, every hypothesis checked, every finding discovered, every dead-end encountered. Session logs are the complete audit trail of all hunting activity.

---

## 1. Session Log Format

```
=== Session: [SESSION-ID] ===
Date: [YYYY-MM-DD]
Target: [domain]
Program: [HackerOne/Bugcrowd/Private]
Platform: [Web/Mobile/API]
Start Time: [HH:MM]
End Time: [HH:MM]
Duration: [X hours, Y minutes]
Tools Used: [tool1, tool2, ...]
Phase: [Recon/Hunt/Validate/Report/Submit]

=== Summary ===
[Brief summary of what was accomplished this session]

=== Activity Timeline ===
[HH:MM] [Activity description] → [Result] → [Evidence ID]

=== Endpoints Tested ===
[URL] [Method] [Bug Class] [Result] [Notes]

=== Hypotheses Tested ===
[What If] → [Result]

=== Findings ===
[New/existing] — [Description] — [Severity] — [Status]

=== Leads ===
[New/existing] — [Description] — [Priority] — [Status]

=== Time Budget ===
[Activity] — [Budget] — [Spent] — [Remaining]

=== Notes ===
[Free-form observations]

=== Next Session ===
[Planned next actions]
```

---

## 2. Session Logs

### Session: JGY-20260315-143022-4a7f

```
=== Session: JGY-20260315-143022-4a7f ===
Date: 2026-03-15
Target: target.com
Program: HackerOne (private invite)
Platform: Web
Start Time: 14:30
End Time: 17:45
Duration: 3 hours, 15 minutes
Tools Used: curl, httpx, ffuf, gau, katana, nuclei, Burp Suite
Phase: HUNT (initial deep dive)

=== Summary ===
First focused hunting session on target.com after initial recon. 
Confirmed 4 vulnerabilities in 3 hours:
1. IDOR on GET /api/v2/invoices/{id} (read any invoice — PII exposure)
2. IDOR on GET /api/v2/invoices/{id}/pdf (follows same pattern)
3. IDOR on DELETE /api/v2/invoices/{id} (delete any invoice)
4. Auth bypass on POST /api/admin/users (create admin without auth)

All confirmed with two-account proof. Added chain opportunities.

=== Activity Timeline ===
14:30 — Loaded tools, restored session state
14:32 — Verified test accounts (attacker + victim) — both active
14:35 — Started IDOR testing on /api/v2/invoices/{id}
14:37 — GET /api/v2/invoices/1001 (own) → 200 OK — baseline
14:38 — GET /api/v2/invoices/2002 (victim) → 200 OK — IDOR CONFIRMED
14:40 — Captured evidence: evd-001 (IDOR read)
14:42 — Tested PDF endpoint: /api/v2/invoices/2002/pdf → PDF download — IDOR CONFIRMED
14:45 — Captured evidence: evd-002 (IDOR PDF)
14:48 — Tested PUT invoice: /api/v2/invoices/2002 → 200 — WRITE IDOR CONFIRMED
14:50 — Tested DELETE invoice: DELETE /api/v2/invoices/5000 → 204 — DELETE IDOR CONFIRMED
14:52 — Verified deleted invoice: GET /api/v2/invoices/5000 → 404
14:55 — Captured evidence: evd-003 (IDOR write + delete)
15:00 — Checked invoice list endpoint: GET /api/v2/invoices → returns own invoices only (secure)
15:05 — Started auth bypass testing on admin endpoints
15:08 — GET /api/v2/admin/users without auth → 401 (expected)
15:10 — POST /api/v2/admin/users without auth → 201 Created — AUTH BYPASS CONFIRMED
15:12 — Logged in with created admin account → admin dashboard access
15:15 — Captured evidence: evd-004 (auth bypass — admin creation)
15:20 — Tested admin impersonation: POST /api/admin/impersonate → 403 (requires higher privilege)
15:25 — Started SSRF testing on avatar endpoint
15:28 — PUT /api/user/avatar {"url":"http://burpcollaborator.net/test"} → DNS callback received
15:32 — PUT /api/user/avatar {"url":"http://169.254.169.254/"} → 403 WAF BLOCKED
15:40 — Tried 5 SSRF bypass techniques for metadata IP (all blocked)
15:45 — Tested internal DNS: PUT {"url":"http://internal.target.com/health"} → 200 — SSRF to internal confirmed
15:50 — Captured evidence: evd-005 (SSRF — internal DNS resolution)
16:00 — Started race condition testing on coupon endpoint
16:05 — Normal redemption: POST /api/coupons/redeem {"code":"SAVE20"} → 200
16:06 — Second same code: → 403 ("already redeemed")
16:10 — 20 parallel requests: 12 succeeded, 8 failed — RACE CONFIRMED
16:15 — Captured evidence: evd-006 (race condition — coupon)
16:20 — Started XSS testing on support ticket endpoint
16:22 — POST /api/support/ticket with XSS payload → stored
16:25 — Logged in as support agent → viewed ticket → XSS fired
16:30 — Captured evidence: evd-007 (stored XSS)
16:35 — Tested reflected XSS on /search?q= → HTML encoded (safe)
16:40 — Started business logic testing on checkout
16:43 — Negative quantity: POST /api/checkout {"qty":-1} → order for -$100 (CREDIT)
16:45 — Captured evidence: evd-008 (negative quantity business logic)
17:00 — Started JWT analysis
17:05 — Decoded JWT from login: HS256, strong key, no obvious flaws
17:10 — Tested alg=none: {"alg":"none"} → rejected by server
17:15 — Tested kid path traversal: {"kid":"../../../../"} → rejected
17:20 — Moved to GraphQL testing
17:22 — Checked introspection: POST /graphql {"query":"{__schema{types{name}}}"} → schema returned
17:25 — Exported schema, analyzed for auth bypass possibilities
17:30 — Tested node(id:) query: {"query":"{node(id:\"dXNlcjoy\"){...on User{email role}}}"} → 200 with data
17:35 — Node query returns other user's data — GRAPHQL AUTH BYPASS confirmed
17:40 — Captured evidence: evd-009 (GraphQL auth bypass — node query)
17:42 — Started evidence packaging
17:45 — Session end — 6 confirmed findings, 1 deferred

=== Endpoints Tested ===
GET  /api/v2/invoices/1001         IDOR     VULNERABLE — read own data (baseline)
GET  /api/v2/invoices/2002         IDOR     VULNERABLE — read other's data (confirmed)
GET  /api/v2/invoices/2002/pdf     IDOR     VULNERABLE — other's PDF
PUT  /api/v2/invoices/2002         IDOR     VULNERABLE — modify other's invoice
DELETE /api/v2/invoices/5000       IDOR     VULNERABLE — delete other's invoice
GET  /api/v2/invoices              LIST     SECURE — own data only
POST /api/v2/admin/users           AUTH     VULNERABLE — no auth required
POST /api/admin/impersonate        AUTH     SECURE — 403 (needs admin+)
PUT  /api/user/avatar              SSRF     VULNERABLE — DNS callback, internal DNS
PUT  /api/user/avatar              SSRF     Partially blocked — metadata IP blocked
POST /api/coupons/redeem           RACE     VULNERABLE — 12/20 parallel succeeded
POST /api/support/ticket           XSS      VULNERABLE — stored XSS in admin panel
GET  /search?q=                    XSS      SECURE — HTML encoded output
POST /api/checkout                 LOGIC    VULNERABLE — negative quantity
POST /graphql                      GRAPHQL  Introspection enabled
POST /graphql                      GRAPHQL  VULNERABLE — node() auth bypass

=== Hypotheses Tested ===
"Invoice IDs are sequential and enumerable" → CONFIRMED — IDs 1-50000
"Admin user creation endpoint has no auth" → CONFIRMED
"Avatar URL fetch can be used for SSRF" → CONFIRMED — internal DNS
"Metadata IP is blocked by WAF" → CONFIRMED — all bypass attempts failed
"Coupon redemption is not atomic" → CONFIRMED — race condition works
"Support ticket stores HTML without sanitization" → CONFIRMED — XSS
"JWT uses weak HMAC secret" → REFUTED — strong key
"GraphQL introspection is enabled" → CONFIRMED
"GraphQL node() bypasses per-object auth" → CONFIRMED
"Checkout accepts negative quantities" → CONFIRMED — generates credit

=== Findings ===
NEW — IDOR on GET /api/v2/invoices/{id} — HIGH
NEW — IDOR on GET /api/v2/invoices/{id}/pdf — HIGH (chain with above)
NEW — IDOR on DELETE /api/v2/invoices/{id} — HIGH (chain with above)
NEW — Auth bypass on POST /api/admin/users — CRITICAL
NEW — SSRF on avatar import — HIGH (pending metadata bypass)
NEW — Race condition on coupon redemption — HIGH
NEW — Stored XSS in support ticket — HIGH
NEW — Business logic — negative quantity — MEDIUM
NEW — GraphQL node() auth bypass — HIGH

=== Leads ===
P1 — SSRF metadata bypass (DNS rebinding, redirect bypass)
P2 — Admin impersonation exploration
P2 — Feature flag manipulation via LaunchDarkly
P3 — Deprecated API v1 endpoint scan
P3 — Swagger/OpenAPI doc analysis

=== Time Budget ===
IDOR Testing      30 min   20 min used  10 min remaining (3 findings)
SSRF Testing      30 min   15 min used  15 min remaining (1 partial finding)
XSS Testing       30 min   10 min used  20 min remaining
Auth Testing      45 min   10 min used  35 min remaining (1 finding)
Business Logic    30 min   20 min used  10 min remaining (1 finding)
Validation        20 min   0 min used   20 min remaining
Reporting         40 min   0 min used   40 min remaining
Recon             60 min   0 min used   60 min remaining (pre-completed)

=== Notes ===
- target.com is very vulnerable — impressive attack surface
- WAF is strong on SSRF metadata IP but weak on everything else
- Dev/Staging subdomains have no WAF — attack surface
- Created admin account via exploit — must delete after testing
- GraphQL introspection is dangerous — full schema available
- Chain IDOR (read+delete) into single report for higher CVSS
- Consider chaining XSS with support agent's refund capability

=== Next Session ===
1. Run 7-Question Gate on all findings
2. Write reports for confirmed findings
3. Test SSRF metadata bypass (DNS rebinding)
4. Test GraphQL depth attacks
5. Submit first batch of findings
```

### Session: JGY-20260316-090000-3b2c

```
=== Session: JGY-20260316-090000-3b2c ===
Date: 2026-03-16
Target: target.com
Program: HackerOne (private invite)
Platform: Web
Start Time: 09:00
End Time: 11:30
Duration: 2 hours, 30 minutes
Tools Used: curl, Burp Suite, browser DevTools
Phase: VALIDATE + REPORT

=== Summary ===
Validation and reporting session. Ran 7-Question Gate on all findings from 
yesterday. Refuted JWT manipulation and open redirect. Killed rate limit 
bypass (worked as designed). Wrote reports for confirmed findings.

=== Activity Timeline ===
09:00 — Loaded session state from previous session
09:05 — Re-verified all 6 confirmed findings from yesterday
09:10 — IDOR: re-tested cross-account — still works (confirmed)
09:15 — Auth bypass: re-tested without auth — still works (confirmed)
09:20 — SSRF: re-tested DNS callback — still works (confirmed)
09:25 — Race condition: re-tested 20 parallel requests — 13/20 (confirmed)
09:30 — XSS: re-tested payload — still executes (confirmed)
09:35 — Business logic: negative quantity — still generates credit (confirmed)
09:40 — Ran 7-Question Gate for IDOR finding
09:45 — Gate result: PASS (all 7 questions answered correctly)
09:50 — Wrote report for IDOR chain (read+write+delete = full invoice control)
10:15 — Wrote report for auth bypass (admin creation without auth)
10:40 — Wrote report for SSRF (internal DNS resolution, WAF bypass needed)
11:00 — Wrote report for race condition (coupon redemption)
11:15 — Wrote report for stored XSS (support ticket → admin panel)
11:25 — Wrote report for business logic (negative quantity)
11:30 — Session end — 6 reports ready to submit

=== 7-Question Gate Results ===
Finding: IDOR read+write+delete invoices
1. Can attacker directly cause harm? YES — read PII, delete data
2. Is the harm concrete? YES — demonstrated with test accounts
3. Requires unlikely conditions? NO — any authenticated user
4. Tested with two accounts? YES — attacker + victim
5. Can impact be quantified? YES — 50K invoices, PII + financial data
6. Is this in scope? YES — in-scope wildcard
7. Is there a viable chain? YES — full invoice control
→ PASS — report as chain (HIGH)

Finding: Auth bypass admin creation
1. Can attacker directly cause harm? YES — create admin accounts
2. Is the harm concrete? YES — demonstrated admin dashboard access
3. Requires unlikely conditions? NO — unauthenticated
4. Tested with two accounts? YES — anonymous + attacker
5. Can impact be quantified? YES — full platform takeover
6. Is this in scope? YES
7. Is there a viable chain? YES — admin → all user data
→ PASS — report as CRITICAL

[Additional gates omitted for brevity — all findings passed]

=== Findings ===
Existing — IDOR Chain (read+write+delete) — HIGH — REPORTED
Existing — Auth Bypass (admin creation) — CRITICAL — REPORTED
Existing — SSRF (internal DNS, IP blocked) — HIGH — REPORTED (with metadata bypass pending)
Existing — Race Condition (coupon) — HIGH — REPORTED
Existing — Stored XSS (support ticket) — HIGH — REPORTED
Existing — Business Logic (negative qty) — MEDIUM — REPORTED

=== Killed ===
JWT weak secret → Gate failed: no viable exploit, strong key confirmed
Open redirect → Gate failed: whitelist only, no bypass found
Rate limit bypass → Gate failed: rate limiting works as intended

=== Next Session ===
1. Submit reports (if not already done)
2. Continue SSRF metadata bypass research
3. Test dev.target.com (no WAF — fresh attack surface)
4. Analyze GraphQL schema for more endpoints
```

---

## 3. Session Statistics

### Per-Target

| Target | Sessions | Total Time | Findings | Submitted | Paid |
|--------|----------|-----------|----------|-----------|------|
| target.com | 2 | 5h 45m | 6 | 6 | 0 |

### All-Time

| Metric | Value |
|--------|-------|
| Total Sessions | 2 |
| Total Time | 5h 45m |
| Total Findings | 6 |
| Submitted | 6 |
| Paid | 0 |
| N/A | 0 |
| Duplicate | 0 |
| Killed | 3 |
| Best Hour | target.com (2 findings/hour) |

---

## 4. Endpoint Coverage Matrix

### target.com

| Endpoint | IDOR | SSRF | XSS | Auth | Logic | Race | SQLi | XXE |
|----------|------|------|-----|------|-------|------|------|-----|
| GET /invoices/{id} | ✓ | — | — | — | — | — | — | — |
| GET /invoices/{id}/pdf | ✓ | — | — | — | — | — | — | — |
| PUT /invoices/{id} | ✓ | — | — | — | — | — | — | — |
| DELETE /invoices/{id} | ✓ | — | — | — | — | — | — | — |
| POST /admin/users | — | — | — | ✓ | — | — | — | — |
| PUT /user/avatar | — | ✓ | — | — | — | — | — | — |
| POST /coupons/redeem | — | — | — | — | — | ✓ | — | — |
| POST /support/ticket | — | — | ✓ | — | — | — | — | — |
| POST /checkout | — | — | — | — | ✓ | — | — | — |
| POST /graphql | ✓ | — | — | ✓ | — | — | — | — |

**Coverage:** 10 endpoints tested, 6 bug classes covered
**Vulnerable:** 8/10 endpoints have at least one bug class

---

## 5. Productivity Tracker

### Findings Per Hour

| Session | Duration | Findings | Rate |
|---------|----------|----------|------|
| JGY-20260315-143022-4a7f | 3h 15m | 6 | 1.85/hr |
| JGY-20260316-090000-3b2c | 2h 30m | 0 (validation) | validation session |

### Time by Bug Class

| Bug Class | Total Time | Findings | Time Per Finding |
|-----------|-----------|----------|-----------------|
| IDOR | 20 min | 3 | 6.7 min |
| Auth Bypass | 10 min | 1 | 10 min |
| SSRF | 15 min | 1 | 15 min |
| Race Condition | 10 min | 1 | 10 min |
| XSS | 10 min | 1 | 10 min |
| Business Logic | 20 min | 1 | 20 min |

---

## 6. Session Notes (Free-Form)

```
[2026-03-15] target.com — First impressions:
This target is unusually vulnerable. Multiple critical and high findings in
one session suggest either a very new application or minimal security testing.
The WAF is effective at blocking metadata IP SSRF but everything else is wide
open. Should focus on this target before the program hardens it.

[2026-03-16] target.com — Report writing:
Writing chain reports is more efficient than individual ones. The IDOR 
read+write+delete chain takes the same time to report as a single IDOR 
but gets higher CVSS. Always chain related bugs into one report.

Lesson: Don't submit individual IDOR findings — chain them.
The auth bypass admin creation is Critical regardless of chain.
```

---

## 7. Log Maintenance

### When to Start a New Session

```
Start a new session entry when:
- New target
- New day
- Change of phase (recon → hunt → report)
- Different toolset focus
- Interruption longer than 2 hours
```

### When to Archive Session Logs

```
Archive detailed session logs when:
- Target completed (all findings submitted)
- Target inactive for 30+ days
- Log file exceeds 500 KB
```

### Session Log Integrity

```
[ ] Session ID is unique
[ ] Start time < End time
[ ] Duration matches actual time
[ ] All activity entries have timestamps
[ ] Findings referenced exist in findings-archive.md
[ ] Evidence IDs referenced exist in evidence-packages.md
[ ] Leads referenced exist in discoveries.md
[ ] Next session actions are actionable
[ ] Summary accurately reflects the session
```

---

## 8. Sample Session Logs (Reference Templates)

Use these templates for common session types.

### Recon Session Template
```
=== Session: [SESSION-ID] ===
Date: [YYYY-MM-DD]
Target: [domain]
Type: RECON — First pass
Tools: [tools used]
Duration: [Xh Ym]

=== Passive Recon ===
[source] → [discovery] → [notable]

=== Active Recon ===
[subdomain brute-force] → [N resolved]
[massdns/puredns] → [N resolved]

=== URL Crawling ===
[wayback/gau] → [N URLs]
[katana] → [N URLs]

=== Tech Fingerprinting ===
[target] → [tech stack]

=== Notable Discoveries ===
[subdomain] — [interesting thing]
[endpoint] — [interesting thing]

=== Attack Surface Summary ===
Live hosts: [N]
Unique endpoints: [N]
Tech stack: [summary]
WAF: [type]
Interesting: [anything unusual]

=== Next Steps ===
1. Test [endpoint] for [bug class]
2. Investigate [unusual discovery]
3. Fuzz [interesting directory]
```

### Hunt Session Template
```
=== Session: [SESSION-ID] ===
Date: [YYYY-MM-DD]
Target: [domain]
Type: HUNT — [bug class focus]
Duration: [Xh Ym]

=== Focus: [Bug Class] ===
Endpoint: [URL]
Hypothesis: [what I expect to find]

=== Tests ===
1. [test description]
   Request: [exact HTTP request]
   Response: [status + key body excerpt]
   Result: [VULNERABLE/SAFE/INCONCLUSIVE]

2. [test description]
   Request: [exact HTTP request]
   Response: [status + key body excerpt]
   Result: [VULNERABLE/SAFE/INCONCLUSIVE]

=== Additional Testing ===
[bug class switch] — [endpoint] — [result]

=== Findings ===
[NEW] [bug class] — [endpoint] — [severity]
[NEW] [bug class] — [endpoint] — [severity]

=== Time Breakdown ===
[Bug class 1]: [X min]
[Bug class 2]: [X min]

=== Next Session ===
1. Validate findings
2. Write reports
3. Continue testing [other bug class]
```

---

## 9. Log Analysis Techniques

### Pattern: Finding Density by Time

Track which hours produce the most findings to optimize scheduling.

| Hour | Sessions | Findings | Rate |
|------|----------|----------|------|
| 09:00-10:00 | — | — | — |
| 10:00-11:00 | — | — | — |
| 14:00-15:00 | — | — | — |
| 15:00-16:00 | — | — | — |
| 20:00-21:00 | — | — | — |

### Pattern: Bug Class Success Rate

| Bug Class | Sessions Tested | Findings | Success Rate | Avg Time |
|-----------|---------------|----------|-------------|----------|
| IDOR | — | — | —% | — |
| SSRF | — | — | —% | — |
| XSS | — | — | —% | — |
| Auth Bypass | — | — | —% | — |
| Business Logic | — | — | —% | — |
| Race Condition | — | — | —% | — |

### Pattern: Session Length vs. Productivity

| Session Length | Sessions | Avg Findings | Notes |
|---------------|----------|-------------|-------|
| <1 hour | — | — | Quick recon/validation |
| 1-2 hours | — | — | Focused hunt |
| 2-4 hours | — | — | Deep hunt |
| 4+ hours | — | — | Diminishing returns expected |

---

## 10. Session Archive

Completed sessions are moved here after target archival.

### Archived: [target.com]

| Session ID | Date | Duration | Findings | Key Outcome |
|-----------|------|----------|----------|-------------|
| JGY-20260315-143022-4a7f | 2026-03-15 | 3h 15m | 6 | Confirmed IDOR, Auth Bypass, SSRF, Race, XSS, Logic |
| JGY-20260316-090000-3b2c | 2026-03-16 | 2h 30m | 0 (validation) | Reports written, 6 findings validated |

### Archived: [TARGET-PLACEHOLDER]

| Session ID | Date | Duration | Findings | Key Outcome |
|-----------|------|----------|----------|-------------|
| — | — | — | — | — |

