---
name: memory-discoveries
description: Lead and discovery pipeline for Jiggy-2026. Tracks every interesting finding, partial exploit, suspicious endpoint, and chain opportunity from initial observation through validation, reporting, or kill. Every finding starts here before it becomes a report.
---

# Discoveries & Leads Pipeline

This file is the raw lead funnel. Every interesting observation — from a 403 that should be 401 to a response that includes extra fields — gets logged here. Leads are triaged into priorities, tested, validated, and either promoted to findings or killed.

---

## 1. Lead Pipeline Architecture

```
DISCOVER → TRIAGE → TEST → CONFIRMED → VALIDATE → REPORT
                          → REFUTED  → KILL
                          → INCONCLUSIVE → DEFER
```

### Pipeline Stages

| Stage | Description | Exit Actions |
|-------|-------------|-------------|
| DISCOVER | First observation — suspicious behavior, unusual response, interesting endpoint | Add to pipeline with priority |
| TRIAGE | Assign priority (P1-P4), estimate impact, plan test | Begin testing if P1-P2 |
| TEST | Run exploit attempts, gather evidence | Confirm, refute, or defer |
| CONFIRMED | Exploit works consistently | Run 7-Question Gate |
| REFUTED | Exploit doesn't work, was a false positive | Document why, move to killed |
| VALIDATE | Passes 7-Question Gate | Write report |
| KILL | Failed validation or not exploitable | Document reason, move to killed |
| DEFER | Needs more info, tools, or access | Revisit later |
| REPORT | Report written and ready to submit | Submit |

---

## 2. Active Leads (P1-P2 — Currently Testing)

### P1 — Critical / High Potential

| # | Date | Target | Endpoint | Bug Class | Lead Summary | Status | Time Invested |
|---|------|--------|----------|-----------|-------------|--------|-------------|
| — | — | — | — | — | — | — | — |

### P2 — Medium Potential

| # | Date | Target | Endpoint | Bug Class | Lead Summary | Status | Time Invested |
|---|------|--------|----------|-----------|-------------|--------|-------------|
| — | — | — | — | — | — | — | — |

---

## 3. Lead Cards (Detailed)

Each active lead has a detailed card with full context.

### Lead-001: IDOR on Invoice GET

```
Target:     target.com
Endpoint:   GET /api/v2/invoices/{id}
Bug Class:  IDOR
Priority:   P1 (Critical — PII exposure)
Status:     CONFIRMED
Discovered: 2026-03-15 14:30
Time:       15 min invested

Observation:
While testing /api/v2/invoices/1001 (my own invoice), I changed the ID to 2002 
and received a different customer's full invoice data. No authorization error, 
no access denied — just returned the data immediately.

Evidence:
- Request A: GET /api/v2/invoices/1001 → 200 (my invoice: $250.00)
- Request B: GET /api/v2/invoices/2002 → 200 (customer Jane Smith: $4,200.00)
- Both requests used the same session cookie (attacker account)

Impact Estimate:
- 50,000 invoices accessible by iterating IDs 1-50000
- Data exposed: customer name, email, address, phone, amount, card_last4
- GDPR violation, PCI-DSS exposure

Chain Opportunities:
- Lead-002: PDF generation also vulnerable (same IDOR pattern)
- Lead-003: Invoice DELETE also vulnerable (write access)
- Chain: IDOR read + IDOR delete = complete invoice control

Next Steps:
- [✓] Confirm basic IDOR (cross-account)
- [✓] Test PDF endpoint (Lead-002)
- [ ] Test write endpoints (PUT, DELETE)
- [ ] Test mass enumeration speed
- [ ] Run 7-Question Gate
- [ ] Write report
```

### Lead-002: IDOR on Invoice PDF

```
Target:     target.com
Endpoint:   GET /api/v2/invoices/{id}/pdf
Bug Class:  IDOR
Priority:   P1 (follows from Lead-001)
Status:     CONFIRMED
Discovered: 2026-03-15 14:45

Observation:
Same IDOR pattern as Lead-001. PDF generation also doesn't check ownership.

Evidence:
- Request: GET /api/v2/invoices/2002/pdf → 200 (PDF with Jane Smith's invoice)
- Same attacker session as Lead-001

Impact Estimate:
- PDF contains same PII as JSON endpoint
- PDFs can be downloaded in bulk
- Harder to detect in logs (looks like normal PDF download)

Chain: Chain with Lead-001 for mass invoice exfiltration (JSON + PDF)
```

### Lead-003: IDOR on Invoice DELETE

```
Target:     target.com
Endpoint:   DELETE /api/v2/invoices/{id}
Bug Class:  IDOR (Write)
Priority:   P1 (write access — high impact)
Status:     CONFIRMED
Discovered: 2026-03-15 14:50

Observation:
DELETE endpoint also lacks ownership check. Can delete any customer's invoice.

Evidence:
- Request: DELETE /api/v2/invoices/5000 → 204 (deleted)
- Invoice was another customer's record
- Confirmed deletion by GET /api/v2/invoices/5000 → 404

Impact Estimate:
- Attacker can delete all 50,000 invoices
- Business disruption, data loss
- Financial impact: customers can't pay invoices

Chain: FULL_CONTROL — read + delete any invoice
```

### Lead-004: Auth Bypass on Admin User Creation

```
Target:     target.com
Endpoint:   POST /api/admin/users
Bug Class:  Auth Bypass
Priority:   P1 (Critical — admin account creation)
Status:     CONFIRMED
Discovered: 2026-03-15 15:10

Observation:
POST /api/admin/users accepts requests without any authentication header. 
Created an admin account from a fresh session with no login.

Evidence:
- Request: POST /api/admin/users {"email":"hacker@evil.com","password":"Pwned123!","role":"admin"}
  No Authorization header, no Cookie header
- Response: 201 Created
- Login with hacker@evil.com / Pwned123! → admin dashboard access

Impact Estimate:
- Any unauthenticated attacker can create admin accounts
- Full platform takeover
- All user data, financial records, configuration accessible

Chain: LEAD_TO_ATO — create admin → access all user data
```

### Lead-005: SSRF on Avatar Import

```
Target:     target.com
Endpoint:   PUT /api/user/avatar {"url":"..."}
Bug Class:  SSRF
Priority:   P1 (Critical — cloud metadata access)
Status:     NEEDS_FURTHER_TESTING
Discovered: 2026-03-15 15:30

Observation:
The avatar import feature accepts a URL and fetches it server-side. 
WAF blocks 169.254.169.254 but internal DNS resolves to internal services.

Evidence:
- PUT /api/user/avatar {"url":"http://burpcollaborator.net/test"} → DNS callback received
- PUT /api/user/avatar {"url":"http://169.254.169.254/"} → 403 WAF block
- PUT /api/user/avatar {"url":"http://internal.target.com/health"} → 200 (internal health page)
- PUT /api/user/avatar {"url":"http://127.0.0.1:6379/"} → timeout (Redis accessible?)

Bypass Attempts:
- [✓] DNS pinning: burpcollaborator confirms SSRF works
- [✗] Direct metadata IP: blocked by WAF
- [✓] Internal DNS: works (internal.target.com resolves)
- [✗] Decimal IP: 2886729724 → blocked
- [✗] IPv6 ::ffff:169.254.169.254 → blocked
- [ ] DNS rebinding: not tested yet
- [ ] Redirect bypass: not tested yet

Next Steps:
- Try DNS rebinding to bypass WAF metadata block
- Try redirect from attacker.com → 169.254.169.254
- Try alternative metadata endpoints: http://metadata.google.internal/ (GCP)
- Scan internal ports via timing: Redis, MySQL, Elasticsearch
```

### Lead-006: Race Condition on Coupon Redemption

```
Target:     target.com
Endpoint:   POST /api/coupons/redeem {"code":"SAVE20"}
Bug Class:  Race Condition
Priority:   P2 (High — financial impact)
Status:     CONFIRMED
Discovered: 2026-03-15 16:00

Observation:
Sending 20 simultaneous POST requests to the coupon redemption endpoint 
resulted in 12 successful redemptions instead of the expected 1.

Evidence:
- Normal: POST /api/coupons/redeem {"code":"SAVE20"} → 200 (once), then 403
- Race: 20 parallel requests → 12 returned 200, 8 returned 403
- Each success adds $20 store credit → $240 total from one code

Impact Estimate:
- Single coupon code → $240 (12x $20)
- 100 coupon codes → $24,000
- Depends on coupon value and user's coupon access

Chain: Combine with IDOR (find admin coupon codes?) for higher payout
```

### Lead-007: Stored XSS in Support Ticket

```
Target:     target.com
Endpoint:   POST /api/support/ticket
Bug Class:  Stored XSS
Priority:   P2 (High — admin panel execution)
Status:     CONFIRMED
Discovered: 2026-03-15 16:20

Observation:
Support ticket message field stores HTML without sanitization. Payload 
executes when support agent views the ticket in the admin panel.

Evidence:
- POST /api/support/ticket {"message":"<img src=x onerror=alert(document.cookie)>"}
- Login as support agent → view tickets → alert fires with session cookie
- Confirmed session cookie theft possible

Impact Estimate:
- Steal support agent session → access all tickets (PII)
- If agent has refund permissions → financial theft
- If agent has user impersonation → full user data access

Chain: XSS → session theft → pivot to admin if agent has admin privileges
```

---

## 4. Deferred Leads (P3-P4 — Low Priority / Information)

| # | Date | Target | Endpoint | Bug Class | Why Deferred | Revisit? |
|---|------|--------|----------|-----------|-------------|----------|
| — | — | — | — | — | — | — |

---

## 5. Dead Ends / Killed Leads

| # | Date | Target | Endpoint | Bug Class | Why Killed | Gate Failed |
|---|------|--------|----------|-----------|------------|-------------|
| 1 | 2026-03-15 | target.com | /api/auth/login | Weak JWT Secret | JWT uses HS256 with strong key — can't brute-force in reasonable time | Impact (5) — no viable exploit path |
| 2 | 2026-03-15 | target.com | /api/user/profile | Open Redirect | redirect parameter only accepts whitelisted domains | Exploitability (4) — limited to whitelist |
| 3 | 2026-03-16 | target.com | /api/auth/reset-password | Predictable Token | Token is crypto-random (64 bytes) — analysis showed no pattern | Impact (5) — tokens are secure |
| 4 | 2026-03-16 | target.com | /api/v2/search?q= | Reflected XSS | Output is HTML-encoded — no bypass found after 5 attempts | Exploitability (4) — no bypass |
| 5 | 2026-03-16 | target.com | /api/v2/invoices/{id} | Rate Limit Bypass | Rate limit is session-based, not IP-based — can't bypass | Impact (5) — rate limiting works as intended |

---

## 6. Chain Opportunity Matrix

| Chain ID | Bug A | Bug B | Bug C | Resulting Impact | Status |
|----------|-------|-------|-------|-----------------|--------|
| CHAIN-001 | IDOR Read (Lead-001) | IDOR PDF (Lead-002) | — | Mass invoice exfiltration | BOTH CONFIRMED — ready to chain |
| CHAIN-002 | IDOR Read (Lead-001) | IDOR Delete (Lead-003) | — | Full invoice control | BOTH CONFIRMED — report as single finding |
| CHAIN-003 | Auth Bypass (Lead-004) | Admin Access | — | Full platform takeover | CONFIRMED — report as Critical |
| CHAIN-004 | SSRF (Lead-005) | Cloud Metadata | IAM Credentials | Cloud account takeover | NEEDS BYPASS — metadata IP blocked |
| CHAIN-005 | Race Condition (Lead-006) | Multiple Coupons | — | Financial theft | CONFIRMED — report as High |
| CHAIN-006 | Stored XSS (Lead-007) | Admin Session | Refund Abuse | Financial theft + data access | CONFIRMED — needs chain validation |

---

## 7. Lead Quality Indicators

### High-Quality Lead Signals
- Response returns data from another user (IDOR)
- Response includes extra fields not shown in UI (mass assignment)
- Internal IP or hostname appears in response (info disclosure)
- WAF blocks specific patterns but allows others (SSRF bypass potential)
- Error message reveals stack trace or DB structure (debug enabled)
- Response time varies with input (timing side-channel)
- Same request works differently with different sessions (auth issue)
- Parameter changes response behavior unexpectedly (parameter pollution)

### Low-Quality Lead Signals (Kill or Defer)
- Requires impossible conditions (MITM, physical access)
- Only works on your own account (not cross-user)
- Error is client-side only (browser console, not server response)
- Rate limiting prevents meaningful exploitation
- Behavior is documented as intended
- Requires social engineering of privileged user
- Only works on stale/deprecated endpoints

---

## 8. Test Protocol Reference

When testing any lead, follow this protocol:

```
1. [VERIFY SCOPE] — confirm endpoint is in program scope
2. [ESTABLISH BASELINE] — normal request/response with your account
3. [TEST CROSS-ACCOUNT] — repeat with another account if applicable
4. [DOCUMENT EVIDENCE] — save request/response pair
5. [TEST CONSISTENCY] — repeat 3 times to confirm non-flaky
6. [ASSESS IMPACT] — what data/access can attacker gain?
7. [CHECK CHAINS] — can this combine with another lead?
8. [RUN GATE] — run 7-Question Gate before reporting
9. [SAVE] — all evidence to storage/evidence-packages.md
10. [LOG] — update this file with result
```

---

## 9. Discovery Sources

Track where leads come from to optimize testing strategy:

| Source | Leads Found | Best For | Effectiveness |
|--------|-------------|----------|--------------|
| Passive Recon (subdomains) | — | New attack surface | ★★★★★ |
| URL Crawling (wayback/gau) | — | Parameter discovery | ★★★★☆ |
| Directory Fuzzing (ffuf) | — | Hidden endpoints | ★★★★★ |
| JS Analysis | — | API keys, internal paths | ★★★★☆ |
| Manual Testing | — | Business logic, chaining | ★★★★★ |
| Auth Flow Analysis | — | Auth bypass, MFA bypass | ★★★★☆ |
| Response Diff Analysis | — | IDOR, mass assignment | ★★★☆☆ |
| Error Message Analysis | — | Info disclosure, stack traces | ★★★☆☆ |
| Timing Analysis | — | Timing side-channels | ★★☆☆☆ |

---

## 10. Lead Summary

### This Session
| Status | Count |
|--------|-------|
| DISCOVERED | — |
| TESTING | — |
| CONFIRMED | — |
| REFUTED | — |
| DEFERRED | — |
| KILLED | — |
| REPORTED | — |
| **TOTAL** | — |

### All Sessions (Lifetime)
| Status | Count |
|--------|-------|
| CONFIRMED | — |
| REFUTED | — |
| KILLED | — |
| REPORTED | — |
| PAID | — |
| N/A | — |

---

## 11. Lead Refinement Workflow

Each lead goes through refinement stages before it reaches the pipeline.

### Stage 1: Raw Observation
```
Source: [how the lead was discovered]
Observation: [what was seen/suspected]
Raw data: [the request/response or behavior]
```

### Stage 2: Refined Hypothesis
```
Hypothesis: [specific testable statement]
Test method: [exact request or tool command]
Expected result: [what would confirm the vulnerability]
```

### Stage 3: Test Plan
```
1. Baseline test — establish normal behavior
2. Exploit test — attempt the attack
3. Cross-account test — confirm with second account
4. Consistency test — repeat 3 times
5. Impact assessment — quantify the damage
```

---

## 12. Lead Scoring System

Each lead gets a numeric score to prioritize testing:

```
Score = (Impact × 3) + (Exploitability × 2) + (Confidence × 1)

Impact:
  10 = Full RCE / Cloud takeover
  9 = Admin ATO / Mass PII exfil
  8 = User ATO / Financial theft
  7 = Write IDOR / Delete data
  6 = Read IDOR / SSRF with callback
  5 = Stored XSS in admin panel
  4 = Business logic abuse / Race condition
  3 = Reflected XSS / CSRF
  2 = Open redirect / Info disclosure
  1 = Missing headers / Best practice

Exploitability:
  10 = Unauthenticated, one request
  9 = Any user account, one request
  8 = Specific role, one request
  7 = Unauthenticated, multiple requests
  6 = User account, multiple requests
  5 = Requires user interaction (click)
  4 = Requires specific timing/conditions
  3 = Requires MITM or physical access
  2 = Requires social engineering
  1 = Theoretical only

Confidence:
  10 = Confirmed with two accounts
  9 = Confirmed with one account
  8 = Reproducible but not cross-account
  7 = Observed once, needs confirmation
  5 = Strong suspicion, not yet tested
  3 = Weak signal, low confidence
  1 = Gut feeling only
```

**Score Ranges:**
- 80-100: P0 — Drop everything, test now
- 60-79: P1 — Test this session
- 40-59: P2 — Test after current P1
- 20-39: P3 — Test if time permits
- 0-19: P4 — Defer indefinitely

---

## 13. Lead-to-Finding Conversion

When a lead becomes a confirmed finding, follow this protocol:

```
1. [CONFIRMED] — Lead passes all test plan stages
2. [EVIDENCE] — Capture all evidence to evidence-packages.md
3. [GATE] — Run 7-Question Gate (triage-validation skill)
   a. Can attacker directly cause harm?
   b. Is the harm concrete and demonstrable?
   c. Does the exploit require unlikely conditions?
   d. Is cross-account/cross-user impact proven?
   e. Can impact be quantified?
   f. Is the endpoint in scope?
   g. Is there a viable chain for higher severity?
4. [PASS] — Move to findings pipeline with severity
5. [FAIL] — Move to killed leads with reason
```

### Conversion Statistics

Track conversion rate to improve lead selection:

| Period | Leads Tested | Confirmed | Killed | Conversion Rate | Avg Score |
|--------|-------------|-----------|--------|----------------|-----------|
| This session | — | — | — | —% | — |
| This target | — | — | — | —% | — |
| All time | — | — | — | —% | — |

---

## 14. Cross-Target Pattern Recognition

Track vulnerability patterns that repeat across targets. These indicate systemic issues with specific technologies or frameworks.

| Pattern | First Seen | Targets Affected | Bug Classes | Notes |
|---------|-----------|-----------------|-------------|-------|
| — | — | — | — | — |

### Common Cross-Target Patterns
- JWT stored in localStorage (XSS → ATO chain)
- GraphQL introspection enabled (attack surface expansion)
- S3 buckets with misconfigured policies (data exposure)
- CORS with wildcard + credentials (data theft via XSS)
- Deprecated API versions still active (old code = bugs)
- Missing rate limiting on auth endpoints (enumeration)
- Admin panels with no IP restriction (attack surface)
- Cloud metadata accessible via SSRF (critical chain)

