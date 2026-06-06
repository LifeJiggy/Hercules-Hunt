---
name: triage-validation
description: Finding validation before writing any report — 7-Question Gate (all 7 questions), 4 pre-submission gates, always-rejected list, conditionally valid with chain table, CVSS 3.1 quick reference, severity decision guide, report title formula, 60-second pre-submit checklist. Identity-check rules (Q8), deduplication SOP, retraction discipline, and engagement-scale triage workflows. Use BEFORE writing any report. One wrong answer = kill the finding and move on. Saves N/A ratio.
---

# TRIAGE & VALIDATION — Q8 IDENTITY EDITION

One wrong answer = STOP **this finding**. Kill **the finding**. Move on **to the next test class**.

> **Scope of "STOP" in this skill:** This skill's gates kill INDIVIDUAL FINDINGS that fail validation. They do NOT authorize stopping the engagement. Killing a finding via the 7-Question Gate just means *that finding* doesn’t get submitted — every other test class in the engagement is still pending. See `redteam-mindset` "DO NOT STOP primary directive" for the coverage-axis rule.

> "N/A hurts your validity ratio. Informative is neutral. Only submit what passes all 7 questions."

---

## THE 7-QUESTION GATE

Ask IN ORDER. One wrong answer = STOP immediately.

---

### Q1: Can an attacker use this RIGHT NOW, step by step?

**Decision rule:** You must be able to write a complete HTTP request with method, URL, headers, and body that demonstrates the vulnerability on a live system in under 5 minutes.

**Template:**
```
1. Setup:    I need [own account / another user's ID / no account]
2. Request:  [exact HTTP method, URL, headers, body — copy-paste ready]
3. Result:   I can [read / modify / delete] [exact data shown in response]
4. Impact:   The real-world consequence is [account takeover / PII read / money stolen]
5. Cost:     Time: [X minutes], Capital: [$0 / $X subscription required]
```

**If you CANNOT write step 2 as a real HTTP request → KILL IT.**

---

#### Q1 expanded

**Failure mode definitions:**

Response echo: You send a payload and see it in the response body because the server is literally echoing the request — not executing the payload. Kill unless you can show execution in a victim-viewable browser context.

Status with no leak: You receive HTTP 200 on another user's resource, but the body is empty, a generic success message, or byte-identical to your own account's response. Need actual third-party data in the body.

Code-reading-only: Source review showed a missing authorization check, but you never issued the live request. Kill until live reproduction is recorded.

VPN-only reproduction: Works only inside the corporate network. Kill unless the in-scope list explicitly includes that network.

---

### Q2: Is the impact on the program's accepted impact list?

**Decision rule:** Map your finding to the program's published "In Scope / Out of Scope / Severity" definitions. If the program explicitly excludes the impact class, the finding is dead regardless of technical validity.

| Program-stated impact | Typical primitive | Valid? |
|---|---|---|
| Any-user ATO without interaction | Session hijack via stored XSS on profile bio | Yes — Critical or High |
| Mass PII exfil | IDOR enumerating all user profiles | Yes — High |
| Admin auth bypass | JWT none algorithm on admin endpoints | Yes — Critical |
| Internal SSRF with data exfil | SSRF to AWS metadata | Yes — High |
| Stored XSS affecting all users | Stored XSS in comment field | Yes — High |
| Clickjacking requiring CAPTCHA bypass | Clickjacking on login with CAPTCHA | Usually No |
| Pure info disclosure with no sensitive data | Error message reveals framework version | Usually No |

---

### Q3: Is the root cause in an in-scope asset?

**Decision rule:** Confirm the exact host, path, and protocol are within the program's scope.

Checklist:
- [ ] Vulnerable hostname appears on the program's in-scope list
- [ ] Port and protocol match scope (443 standard; 8080/8443 only if listed)
- [ ] Asset is production (not staging/dev unless explicitly in scope)
- [ ] Third-party services excluded unless the issue is in YOUR integration, not the service itself
- [ ] Redirect endpoint lands on an in-scope asset for the full chain

---

### Q4: Does it require privileged access that an attacker can't realistically get?

**Decision rule:** Evaluate whether the attacker role is realistic.

| Attacker starting point | Verdict |
|---|---|
| Any free registered account | Valid, low or medium baseline |
| No account, anonymous | Valid, higher severity |
| Account I already own, no victim required | Valid |
| Requires another user to click a link | Valid if click is realistic |
| Requires victim to perform unlikely multi-step workflow | Questionable |
| Admin role required to observe behavior | **KILL IT** |
| Physical access to corporate network | **KILL IT** |
| Requires a leaked API key or prior breach | **KILL IT** |

---

### Q5: Is this already known or accepted behavior?

**Decision rule:** If the behavior is documented in public API docs, public GitHub issues, changelogs, or previously disclosed reports, the program has accepted the risk. Move on.

**Search procedure:**
1. HackerOne Hacktivity — filter by program + vuln class + endpoint
2. GitHub issues — `is:issue is:open ENDPOINT_NAME`, then `is:closed ENDPOINT_NAME security`
3. Changelog/CHANGELOG.md — API behavior changes often logged here
4. Public API docs / Swagger — if schema includes the field, it is designed behavior

**Signals to kill immediately:**
- Open issue labeled "wontfix" with same symptom
- Closed as "by design"
- Mentioned in release notes
- Existing disclosed report with same endpoint + vuln class

---

### Q6: Can you prove impact beyond "technically possible"?

**Decision rule:** The finding must demonstrate a concrete attacker gain, not just an anomaly.

| Vuln class | Technically possible (kill) | Proven impact (submit) |
|---|---|---|
| XSS | `alert(1)` fires in isolated HTML page | Cookie theft or admin session hijack on a live user-viewable page |
| SSRF | SSRF to 169.254.169.254 returns HTTP 200 | Metadata returns AWS credentials or Redis returns session keys |
| SQLi | Error message contains SQL syntax text | Extracted real data from a real table |
| IDOR | 200 OK on `/users/456` while authenticated as user 1 | Response contains another user's PII |
| CSRF | Form submits successfully from attacker.com | Email changed or funds moved |
| Race | Some requests return 200 in parallel | Duplicate coupon or double spend |
| JWT none | Forged token returns 200 on an endpoint | Forged token returns admin-only response |
| Open redirect | `?next=https://evil.com` redirects | Chain to OAuth code theft |

---

### Q7: Is this a known-invalid bug class?

**Decision rule:** Check the NEVER SUBMIT and CONDITIONALLY VALID lists below. If your finding matches an always-rejected entry and does not form part of a chain → **KILL IT.**

---

### Q8: Identity check — which session found this, and does it survive?

**Decision rule:** For any authenticated finding, record the session context and confirm the bug reproduces across identity boundaries.

```
1. Session ID:         [12-char BBHUNT_SESSION_ID hash from audit.jsonl]
2. Identity:          [low-priv user A / high-priv user B / API key / etc.]
3. Anonymous repro:   Does the same request work with NO auth header?
4. Cross-identity:    Does it work under session B with the same data scope?
5. Stale-cred repro:  Does a logged-out / expired session still get the data?
```

Why this matters:
- **IDOR / BOLA**: must work with session A reading session B's data — if it only works with no auth, that's "missing auth" not IDOR.
- **Priv-esc**: must work with low-priv session reading high-priv data.
- **Auth bypass**: must work *without* a valid session — if it stops working when you log out, you have a permissions issue, not a bypass.
- **Always check both directions**: a finding that only reproduces under one identity is often a real, scoped permission boundary, not a vuln.

`audit.jsonl` entries are tagged with `session_id`. Re-run the request under each identity and confirm the bug holds.

---

## 4 PRE-SUBMISSION GATES

Run ALL four. Every gate must PASS before report drafting begins.

---

### Gate 0: Reality Check (30 seconds)
```
[ ] Bug is REAL — confirmed with actual HTTP requests
[ ] Bug is IN SCOPE — checked program scope page explicitly
[ ] Reproducible from scratch — fresh session reproduction
[ ] Evidence ready — screenshot, response body, or video recorded
```

### Gate 1: Impact Validation (2 minutes)
```
[ ] Can answer: "What can attacker DO that they couldn't before?"
[ ] Answer is more than "see non-sensitive data"
[ ] Real victim: another user's data, company's data, financial loss
[ ] Not relying on victim doing something unlikely
```

### Gate 2: Deduplication Check (5 minutes)
```
[ ] Searched HackerOne Hacktivity for this program
[ ] Searched GitHub issues for target repo
[ ] Read most recent 5 disclosed reports
[ ] Not a "known issue" in changelog or public docs
[ ] Google: "TARGET_NAME ENDPOINT_NAME bug bounty"
```

### Gate 3: Report Quality (10 minutes)
```
[ ] Title: [Bug Class] in [Endpoint] allows [actor] to [impact]
[ ] Steps to Reproduce: copy-pasteable HTTP request
[ ] Evidence: screenshot/video of actual impact
[ ] Severity: matches CVSS 3.1 AND program definitions
[ ] Remediation: 1-2 sentences of concrete fix
[ ] NEVER used "could potentially" or "may allow"
```

---

## NEVER SUBMIT LIST

Submitting these destroys your validity ratio.

```
Missing CSP / HSTS / security headers
Missing SPF / DKIM / DMARC
GraphQL introspection alone (no auth bypass, no IDOR demonstrated)
Banner / version disclosure without working CVE exploit
Clickjacking on non-sensitive pages (no sensitive action PoC)
Tabnabbing
CSV injection (no actual code execution shown)
CORS wildcard (*) without credential exfil proof of concept
Logout CSRF
Self-XSS (only exploits own account)
Open redirect alone (no ATO or OAuth theft chain)
OAuth client_secret in mobile app (known, expected)
SSRF DNS callback only (no internal service access or data)
Host header injection alone (no password reset poisoning PoC)
Rate limit on non-critical forms (search, contact, login with Cloudflare)
Session not invalidated on logout
Concurrent sessions
Internal IP in error message
Mixed content
SSL weak ciphers
Missing HttpOnly / Secure cookie flags alone
Broken external links
Autocomplete on password fields
Pre-account takeover (usually — very specific conditions required)
```

---

## CONDITIONALLY VALID — CHAIN REQUIRED

Build the chain first, prove it works end to end, THEN report.

| Standalone Finding | Chain Required | Valid Result |
|---|---|---|
| Open redirect | + OAuth redirect_uri → auth code theft | ATO (Critical) |
| Clickjacking | + sensitive action + working PoC | Medium |
| CORS wildcard | + credentialed request exfils user PII | High |
| CSRF | + sensitive action (transfer funds, change email, delete account) | High |
| Rate limit bypass | + OTP/reset token brute force succeeds | Medium/High |
| SSRF DNS-only | + internal service access + data returned | Medium |
| Host header injection | + password reset email uses injected host | High |
| Prompt injection | + reads other user's data (IDOR) | High |
| S3 bucket listing | + JS bundles contain API keys or OAuth secrets | Medium/High |
| Self-XSS | + CSRF to trigger it on victim without their knowledge | Medium |
| Subdomain takeover | + OAuth redirect_uri registered at that subdomain | Critical |
| GraphQL introspection | + auth bypass mutation or IDOR on node() | High |

---

## CVSS 3.1 QUICK REFERENCE

### Common Score Examples

| Finding | Score | Severity | Vector |
|---|---|---|---|
| IDOR read PII, any user, auth required | 6.5 | Medium | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |
| IDOR write/delete, any user | 7.5 | High | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| Auth bypass → admin panel | 9.8 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Stored XSS → cookie theft, stored | 8.8 | High | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N |
| SQLi → full DB dump | 8.6 | High | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| SSRF → cloud metadata | 9.1 | Critical | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N |
| Race → double spend | 7.5 | High | AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N |
| GraphQL auth bypass | 8.7 | High | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| JWT none algorithm | 9.1 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |

### Metric Quick Guide

| What you have | Metric | Value |
|---|---|---|
| Exploitable over internet | AV | Network (N) |
| No special timing or race | AC | Low (L) |
| Free account needed | PR | Low (L) |
| No login needed | PR | None (N) |
| Admin needed | PR | High (H) |
| No victim action | UI | None (N) |
| Victim must click | UI | Required (R) |
| Reads all data | C | High (H) |
| Reads some data | C | Low (L) |
| Modifies all data | I | High (H) |
| Crashes service | A | High (H) |
| Affects only app | S | Unchanged (U) |
| Affects browser/OS/cloud | S | Changed (C) |

---

## KILL FAST RULES

1. **5-minute rule**: If you can't fill in Q1's template in 5 minutes → move on
2. **Precondition count**: More than 2 preconditions simultaneously required → kill it
3. **Impact test**: "What does attacker walk away with?" — if nothing tangible → kill it
4. **Admin bypass**: "Admin can do X" is NEVER a bug → kill it immediately
5. **Design doc test**: If it's documented behavior → kill it immediately
6. **Rabbit hole signal**: 30+ min on Q6 with no reproducible PoC → kill it

---

## ANTI-PATTERNS THAT LOSE MONEY

```
Writing a report before confirming the bug exists (most common)
Submitting theoretical impact without proof
"The API returns more fields than necessary" (sensitivity matters)
Chaining A+B into one report when they're separate bugs (two separate payouts)
Reporting B saying "similar to A in my other report"
Overclaiming severity — triagers trust you less next time
Under-describing impact — triager doesn't understand why it matters
```

---

## Extended operator notes — engagement behavior patterns

### Engagement-scale triage cadence

Run the 7-question gate plus the Q8 identity check the moment a candidate signal appears. Do not defer triage to "after the engagement." Deferred findings have higher false-positive rates because context has degraded.

**Recommended cadence:**
- Hour 1–2: candidates come in; triage every candidate immediately.
- Hour 3+: blitz through remaining candidates in 15-minute batches.
- End of day: aggregate rejected candidates into a retraction appendix block.
- Before submitting ANY finding: re-run Q1 through Q8 on the actual report draft, not your discovery notes.

### Engagement-grade identity discipline

The Q8 identity check exists because many "confirmed IDOR" findings fail at this exact gate:

- Session A reads Session B's data: Real IDOR.
- Session A reads the same data as Session B: Permission boundary, not IDOR.
- Session A with no auth reads any user's data: Missing auth / auth bypass, not IDOR.
- Session A reads Session B's data but only when Session B has a specific role: `admin`-scoped IDOR; valid, higher severity.
- Session A reads Session B's data but only in `debug=true` mode: Feature-flag-dependent; document mode requirement in report.

If cross-identity reproduction is impossible because your test environment only has one account, create two accounts. Do not skip this step.

### When to violate a gate

| Gate | Acceptable exception | Procedure |
|---|---|---|
| Gate 1 (Impact) | Impact is "confidential data leak" but sensitivity unclear | Consult program scope "What We Look For" section; if stated, proceed. |
| Gate 2 (Dedupe) | Disclosure index is empty or reports unavailable | Note "No disclosed reports found as of engagement date" in your notes. |
| Gate 3 (Quality) | Technical complexity requires >10 minutes of explanation | Wrap the complex logic into a numbered flow; do not abbreviate severity. |
| Q8 (Identity) | Finding is entirely in the anonymous, unauthenticated path | Mark Session as "anonymous" and Anonymous repro as "N/A"; proceed. |

If you cannot state a clear exception, the finding stays dead.

### When to kill a chain instead of the primitive

Sometimes the primitive passes all gates but the chain does not. When to kill which:

- Primitive valid but chain requires an unrealistic victim action → report the primitive alone only if it meets severity thresholds alone.
- Primitive valid but chain requires a second vulnerability that is outside scope → report the in-scope primitive alone; document the chain potential without claiming it.
- Chain valid but primitive violates scope (e.g., out-of-scope redirect for OAuth) → Kill the entire chain; the chain starts out-of-scope.
- Primitive valid, chain valid, but the triager has previously rejected this chain shape → Re-read rejected reports; adapt your proof to address the triager's stated concern, or kill and move on.

### Retraction appendix format

If a finding must be retracted after triage but before submission:
1. Add a top-level section "## Retractions" to your report.
2. List each retracted finding using the canonical template.
3. Do not silently remove findings to "clean up" before submission.
4. Do include a finding in the submission body and reference its retraction in a footnote.

### Engagement signature hygiene

Every submitted report should carry a consistent evidence structure:
- Request/response pairs (no redacted tokens in the request line itself)
- Screenshots with developer tools open showing network panel
- Specific HTTP version (HTTP/1.1 vs HTTP/2 matters for some findings)
- Timestamp evidence for time-based blind findings (at least 3 samples)

---

## Extended anti-patterns

Overclaim severity to compensate for weak impact: A triager will downgrade. A cleaner path: downgrade yourself, note in the report "this would be High if exfiltrated records > 10,000; confirmed 120 unique records at this severity."

Underclaiming to play safe: If the program explicitly pays for the impact class, submit at full severity. Triagers do not upgrade after the fact; they close as N/A or downgrade.

Chaining A + B when they are actually the same bug in two places: One report per root cause. Multiple affected endpoints within one report is fine; one report per endpoint when the mechanism differs is noise.

Submitting a finding at a lower severity than the program's scope specifies for that impact class: Programs update their scope. Read it fresh before submitting.

Waiting for "perfect evidence" for 48+ hours: If you need more than 48 hours to prove a finding, the signal is weak. Set a personal deadline and kill or submit by then.

---

## Repro checklist per bug class

| Bug class | Minimum repro evidence | Common failure |
|---|---|---|
| IDOR | Response body containing other user's PII | Response is 200 with no body |
| XSS | Payload executes in victim-viewable context | Payload executes only in isolated test page |
| SSRF | Internal service reachable with real data in response | DNS callback only |
| SQLi | Extracted data from a real table | Error message only |
| CSRF | State change triggered from attacker.com | Form submits but no consequence demonstrated |
| Race | Duplicate application of state-changing operation | Some requests return 200 but state unchanged |
| JWT none | Forged token returns admin response | Token returns 200 on non-admin endpoint |
| Open redirect | Redirect proven end-to-end | Redirect proven but no chain to impact |
| SSTI | `{{7*7}}` evaluates to 49 | `{{7*7}}` appears in response literally |

Use this checklist during Gate 1. If your evidence doesn't satisfy the first column, return to testing before writing the report.

---

## Q8 deep dive: identity-state mapping

The Q8 question turns "did the request succeed" into "which identity border did you cross to get there." Without the identity-state map, Q8 is just five checkboxes. With it, Q8 becomes the strongest known discriminator between real and false-positive authenticated vulns.

### Step 1: Map your identity vocabulary

Create a table before you start an authenticated test session:

| Label | Session token source | Privilege level | Notes |
|---|---|---|---|
| Session A | Your low-priv test account | Low | Primary attacker perspective |
| Session B | Second low-priv test account | Low | Secondary attacker perspective |
| Session C | Admin test account (if available) | High | Privilege boundary target |
| API key | Static API key from dev portal | Varies | Often unscoped |
| Anonymous | No token sent | None | Baseline for "missing auth" vs "IDOR" |

### Step 2: Run the identity-state matrix

For each authenticated finding, fill the matrix before you write anything:

| Request | Session A | Session B | Session C | Anonymous |
|---|---|---|---|---|
| GET /users/me | 200 (own data) | 200 (own data) | 200 (own data) | 401/redirect |
| GET /users/456 (target) | 200 (A's own data) | 200 (B's own data) | 200 (C's own data) | 401/redirect |
| GET /admin/users | 403 | 403 | 200 | 403/redirect |
| GET /users/456 (actual cross) | 200 (B's data) — **BUG** | — | — | — |

### Step 3: Map your finding to a known pattern

**Cross-user read** — Session A reads Session B's data with the same request shape. Classic IDOR. Severity depends on data sensitivity.

**Cross-user write** — Session A modifies Session B's data. Severity escalates compared to read; write usually qualifies for High or Critical depending on data type.

**Priv-esc read** — Session A reads data available to Session C but not Session A. Classic broken authorization. Higher severity than cross-user read.

**Missing auth** — Anonymous (no token) reads data that authenticated users can read. Different vuln class from IDOR, different severity.

**Privilege boundary enforcement** — Session B cannot read Session C's data, but Session A can read Session B's data. This is correct behavior for cross-user; no bug.

**Stale credential replay** — Logged-out token still accesses data. Session-state bug, often Low/Medium unless data is sensitive.

### Step 4: Recognize false positive identity patterns

| Observed behavior | Common misinterpretation | Correct interpretation |
|---|---|---|
| 200 on `/users/456` with Session A | "IDOR on userId" | Check body: if body == Session A's own data, it is actually `users/me` aliasing. No bug. |
| 200 on `/admin/users` with Session A | "Auth bypass" | Check response: if body is empty or error HTML, likely stack trace revealing internal path, not actual admin panel. |
| 403 on Session B, 200 on Session A for `/users/B_id` | "IDOR" | If 403 is a deliberate access-control response and 200 is "user not found" returning 200 itself, this is data-scoping, not a leak. |
| Random UUID in response is guessable | "IDOR" | If the UUID is a per-user deterministic string (base64(userId)), enumeration is possible but not IDOR — it is information disclosure. |
| `user_id` cookie accepted without auth | "IDOR" | If the app accepts client-set `user_id` as session identifier, this is session fixation or auth bypass, not IDOR. Severity higher. |

---

## Session-boundary testing methodology

### Cross-account test setup

```bash
# Create two accounts via API or UI
# Record: session tokens, user IDs, UUIDs, email addresses

# Test 1: Cross-user read
SESSION_A="token_for_alice"
SESSION_B="token_for_bob"
ALICE_ID="123"
BOB_ID="456"

curl -sk "https://target.com/api/users/$BOB_ID" \
  -H "Authorization: Bearer $SESSION_A" \
  -o alice-reading-bob.txt

# Check: does alice-reading-bob.txt contain bob's actual PII?
grep -i "bob@example.com" alice-reading-bob.txt
grep -i "bob's_phone" alice-reading-bob.txt
grep -i "bob's_address" alice-reading-bob.txt

# If grep returns results → IDOR confirmed
# If grep returns nothing → not IDOR; kill or downgrade
```

### Multi-session correlation

When testing with 3+ sessions (A, B, C), name them explicitly in your notes. Correlate by `audit.jsonl` session_id hash so you can reconstruct the test matrix at report-writing time.

```json
// audit.jsonl entries
{"ts":"2025-01-15T10:00:00Z","session_id":"Bb7xK2mP","action":"GET /users/456","principal":"low-priv-A","response":"200"}
{"ts":"2025-01-15T10:00:02Z","session_id":"Kp3nL9qR","action":"GET /users/456","principal":"low-priv-B","response":"200"}
{"ts":"2025-01-15T10:00:04Z","session_id":"Ad8vM5xZ","action":"GET /users/456","principal":"admin-C","response":"200"}
```

Before submitting, verify the response bodies from each session are meaningfully different.

### Anonymous baseline test

For every authenticated finding, run the same request with no token:

```bash
curl -sk "https://target.com/api/users/456" \
  -o anonymous-test.txt

# Compare with authenticated response
diff alice-reading-bob.txt anonymous-test.txt

# If identical → no auth required → "missing auth" not "IDOR"
# Severity changes from Medium/High (IDOR) to High/Critical (auth bypass)
```

### Session replay test (stale credentials)

```bash
# Login and record token
SESSION_TOKEN=$(curl -sk -X POST "https://target.com/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"pass"}' | jq -r .token)

# Logout
curl -sk -X POST "https://target.com/logout" \
  -H "Authorization: Bearer $SESSION_TOKEN"

# Attempt replay
curl -sk "https://target.com/api/users/me" \
  -H "Authorization: Bearer $SESSION_TOKEN"

# Expected: 401/redirect
# Actual 200 → session not invalidated → separate finding
```

---

## Bug-class-specific identity checks

### IDOR cross-account validation

```
Minimum test set:
1. Session A GET /api/resource/A_ID → 200 (A's data)
2. Session A GET /api/resource/B_ID → ?
3. Session B GET /api/resource/B_ID → 200 (B's data)
4. Session B GET /api/resource/A_ID → ?

All four results must be recorded.
IDOR exists only if:
  - Session A GET /api/resource/B_ID returns B's data (not A's)
  - AND Session B GET /api/resource/A_ID does NOT return A's data (boundary enforcement confirmed)
```

Analysis of degenerate IDOR patterns:
- **Self-referential IDOR**: Application returns the authenticated user's data regardless of the path parameter. This is `users/me` behavior, not a bug.
- **Shared-data IDOR**: Multi-tenant applications where all users legitimately share certain documents. Check if the document has an `owner_id` field before claiming IDOR.
- **Enumeration vs IDOR**: Sequential or guessable IDs that return user data is often "user enumeration" not IDOR. IDOR requires that Resource X is owned by User X and Resource Y is owned by User Y, and the system fails to enforce that boundary.

### XSS identity validation

Stored XSS severity is tied to which identity's view triggers execution:
- Self-XSS only: Low severity at best, usually Informative/N/A
- Other-user XSS: Valid if payload in a shared context (comment, message, profile bio)
- Admin-triggered XSS: High to Critical severity

Validation checklist:
- [ ] Payload stored in user A's profile/comment
- [ ] Payload executes when user B (or admin) views it
- [ ] Document the viewer identity in the report

### CSRF identity requirements

CSRF requires victim authentication. Validate:
- [ ] Victim account is logged in to target.com (session cookie present)
- [ ] CSRF form is hosted on attacker.com
- [ ] Victim visits attacker.com while authenticated
- [ ] State change occurs on target.com using victim's credentials

If any of the above is false, this is not CSRF.

### SSRF identity context

SSRF validation does not require authentication, but the impact classification depends on what identity-privilege the SSRF reveals:
- Anonymous SSRF to AWS metadata → Critical (cloud credentials)
- Authenticated-user SSRF to internal admin panel → High (privilege escalation)
- SSRF to same-app endpoints → usually Medium

Document: which identity context produced the SSRF, and what internal data was reached.

### Auth bypass identity discipline

The Q8 rule is strictest for auth bypass claims:

- Claim: "I bypassed auth" — must work WITHOUT any token.
- Test: Same request with Authorization header removed.
- Test: Same request with invalid/expired token.
- Test: Same request with Session B's token.

If any of these still works, identify which dimension is the actual bypass. Token format bypass, token validation bypass, and session-not-invalidated are different findings with different severities.

### Race condition identity

Race conditions require concurrent requests under the same identity context:

```python
import asyncio, aiohttp

async def race_request(session, url, payload):
    async with session.post(url, json=payload) as r:
        return await r.json()

async def main():
    url = "https://target.com/api/cart/coupon"
    payload = {"coupon": "ONETIME50"}
    async with aiohttp.ClientSession(cookies={"session": "ALICE_TOKEN"}) as s:
        tasks = [race_request(s, url, payload) for _ in range(50)]
        results = await asyncio.gather(*tasks)
        successes = [r for r in results if r.get("success")]
        print(f"Successful: {len(successes)}/50")

asyncio.run(main())
```

Verify: race was run under a SINGLE authenticated session, not distributed across multiple accounts. Cross-account race results are not the same finding.

---

## Authentication-specific anti-patterns

### Claiming "session not invalidated" when it is

You log out, try the old token, and get 200. Real finding? Check:
1. Was the token actually removed from the session store?
2. Or is the app using JWTs with no server-side revocation?
3. If JWT with 1-hour expiry and no blacklist → this is expected behavior, not a new finding.

### Claiming "concurrent sessions allowed" as a finding

Most programs accept multiple concurrent sessions. Only report if:
- The program's scope explicitly says "single session only"
- Or concurrent sessions enable another attack (e.g., concurrent MFA sessions bypass)

### Confusing client-side role attribute with privilege escalation

Front-end code shows `role: "user"`. Back-end returns `role: "admin"` in response. This is excessive data exposure, not IDOR, unless the attacker can actually USE the admin role.

---

## Final triage rules (consolidated)

1. Run Q1–Q8 in order; do not skip to Q6.
2. If Gate 0 fails, do not attempt Gates 1–3.
3. If a finding passes gates but the program has a track record of rejecting the chain shape, re-read prior disclosures before submitting.
4. When a finding is borderline between two severity levels, submit at the LOWER severity. Triagers downgrade over N/A: a downgrade preserves payout; an N/A does not.
5. When in doubt, jailbreak the 7-question gate by gathering more evidence, not by weakening the gate.
6. The fastest way to improve your bounty earnings is not better exploitation — it is a higher submission-validity ratio.
7. Every retracted finding that makes it to the appendix improves your credibility signal.
8. Identity check (Q8) is the final discriminant. If the finding only reproduces under one user, explain why that reproduces across the identity boundary before submitting.

---

## Q8 IDENTITY CHECK — EXTENDED DEEP DIVE

### Identity-state mapping template

Before starting any authenticated test session, record your identity vocabulary:

```
SESSION REGISTRY:

Label | Token source | Privilege level | Notes
Session A | Primary test account (alice) | Low | Created [date], verified low-priv
Session B | Secondary test account (bob) | Low | Created [date], verified low-priv  
Session C | Admin test account (admin) | High | Program-provided or team account
Session D | API key | Varies | Often unscoped, test separately
Session E | Expired/invalid token | None | For auth bypass testing
Anonymous | No token | None | Baseline for "missing auth" checks

Record: session_id hashes from audit.jsonl for each session
```

### Identity matrix testing procedure

For EVERY authenticated finding before submission:

| Request | Session A | Session B | Session C | Anonymous |
|---|---|---|---|---|
| GET /users/me | 200 (own data) | 200 (own data) | 200 (own data) | 401 |
| GET /users/A_ID | 200 (self OR A's data) | 200 (self) | 200 (self) | 401 |
| GET /users/B_ID | 200 (A's data) → BUG or sees A's data (no bug) | 200 (B's data) | 200 (B's|C's data) | 401 |
| GET /admin/panel | 403 | 403 | 200 (admin view) | 403 |

Filling this matrix takes 5 minutes and eliminates the most common IDOR false positives.

### Identity pattern recognition — common misreadings

**Pattern: "200 on /users/456"**
- If session A GET /users/456 returns A's own data → no bug (users/me aliasing)
- If session A GET /users/456 returns DIFFERENT user's data → IDOR confirmed
- If session A GET /users/456 returns empty/404 → app properly scopes; no IDOR

**Pattern: "Session A can access admin endpoint"**
- If admin endpoint returns admin data for Session A → auth bypass (CRITICAL)
- If admin endpoint returns error/redirect for Session A → access control works
- If admin endpoint returns empty/stack-trace for Session A → may be info disclosure, not ATO

**Pattern: "Forged token accepted"**
- If forged JWT (none algorithm) returns ANY 200 → test if it's admin
- If forged JWT returns 200 on non-admin → token validation bypass, not admin ATO
- If forged JWT returns 200 on admin → full auth bypass confirmed

---

## EXTENDED ANTI-PATTERNS AND DEATH PATTERNS

### Death Pattern: The Single-Account Blind Spot

```
MANIFESTATION: "I found an IDOR — user 456's email showed up in the response"
On closer examination: You only tested from ONE account.
The endpoint is /api/users/me. The app returns the authenticated user's
email regardless of the path parameter (which is ignored).

REALITY: This is users/me aliasing, not IDOR.
The path parameter /456 is decorative; the server ignores it.
The username shows up because you're logged in as user 456.

HOW TO CATCH:
→ Always create a SECOND test account (Bob, ID=789)
→ Verify Bob's data is DIFFERENT from Alice's
→ Send Session A's request for Session B's resource
→ If it returns Session A's data → users/me aliasing → KILL
→ If it returns Session B's data → IDOR CONFIRMED
→ If it returns error → no bug, this is scoping
```

### Death Pattern: The Self-XSS Illusion

```
MANIFESTATION: "Stored XSS in profile bio — I can execute JavaScript"
On closer examination: The only person who views your own bio is yourself.

REALITY: Self-XSS requires victim to click a link AND log in AND visit
YOUR profile. Multi-step with low probability = usually N/A.

EXCEPTION: If stored XSS is in a context where OTHER users see it:
- Comment on public article
- Group chat message
- Forum post
- Review

THEN it's genuine stored XSS.

HOW TO CATCH:
→ Ask: "Who views this content?"
→ If only the author → self-XSS → KILL
→ If any logged-in user → could be valid (check victim action required)
→ If unauthenticated visitors can see → stronger impact
```

### Death Pattern: The Missing Auth Misidentification

```
MANIFESTATION: "Found IDOR — user 456's data with no authentication"
On closer examination: The same data appears when you send NO auth token.

REALITY: If no-token and Session-A-token return the SAME data,
this is MISSING AUTHENTICATION, not IDOR.

DIFFERENCE:
- Missing auth: No token needed at all → higher severity (anyone can access)
- IDOR: Valid token needed, but wrong token gets access → different attack

HOW TO CATCH:
→ Re-run the request WITHOUT Authorization header
→ If response changes → IDOR or privilege issue
→ If response is IDENTICAL → missing auth, NOT IDOR → report as auth bypass

REPORTING:
Auth bypass is often HIGHER severity than IDOR.
Report correctly: "Missing authentication on GET /api/users/{id}" not "IDOR"
```

### Death Pattern: The Admin Illusion

```
MANIFESTATION: "If I set my role to admin, I can see the admin panel"
On closer examination: The role field was in the JWT payload and you modified it.

REALITY: If the JWT signature is verified, you can't "set your role to admin."
If the role is in the payload but NOT verified server-side, you have an auth
bypass (JWT none algorithm or key confusion).

HOW TO CATCH:
→ Modify role in JWT → sign with your own key or use "none" algorithm
→ Send the modified token
→ If it works → auth bypass
→ If it fails with 401 → properly validated; the test was impossible

DO NOT:
- Change role in frontend state only and claim privilege escalation
- Use user-role from response body to claim "I am now admin"
- Confuse client-side role display with actual server-side authorization
```

---

## ADVANCED IDENTITY TESTING SCENARIOS

### Scenario: Multi-Tenant Application

```
Setting: SaaS app where multiple companies use same instance
Each company has its own "tenant ID" accessible via API

Testing approach:
1. Session A (tenant Alpha) creates resource
2. Session B (tenant Beta) tries to access Session A's resource
3. Session B (tenant Beta) tries to access tenant Gamma's resource

Valid bug: Session B can access Session A's tenant data
Invalid: Session B can always see some "public" tenant resources

What's the scope boundary?
- Each tenant IS a separate administrative domain
- Cross-tenant access IS a real bug
- BUT some fields may be intentionally shared (public company info)
```

### Scenario: API Key with Variable Scopes

```
Setting: API key system where keys can have different permission scopes

Testing approach:
1. Get key with "read:users" scope only
2. Try read endpoint → should work
3. Try write endpoint with same key → should fail (out of scope)
4. Try admin endpoint with same key → should fail

Valid bug: Write endpoint accepts key with only read scope
Invalid: App correctly rejects write with read-only key

Multi-key testing:
- Key A (read-only): can read users but not admin data
- Key B (read+write): can update users
- Key C (admin): can do everything

Check: Does Key A read anything Key C can read? If yes → over-privileged API
```

### Scenario: OAuth Token Confusion

```
Setting: OAuth 2.0 application with multiple grant types

Testing approach:
1. Get access_token via Authorization Code flow
2. Use same token in different client context (mobile vs web)
3. Use token after user revokes consent
4. Use token from different IP/geography
5. Try to use refresh_token for different user

Valid bugs:
- Token works after user revoked consent → token not properly bound
- Token from mobile client works on web client → scope not validated
- Refresh token of user A gets user B's access token → token leakage

Common pattern that's NOT a bug:
- OAuth token has long expiry → this is configurable, not a vuln
- Token works across subdomains → expected for single-page apps
- Token survives page reload → expected behavior
```

---

## AUTHENTICATION-SPECIFIC DEEP DIVES

### Session Management Validation

```
Session invalidation test sequence:
1. Login → record token T1
2. Use T1 → confirm works (200)
3. Logout → send logout request
4. Immediately retry T1 on protected endpoint
5. Expected: 401 (token invalidated)
6. If 200: session not invalidated on logout → NEW FINDING

Token persistence test:
1. Login via browser → close browser → reopen
2. Check if session persists (cookie with far-future expiry)
3. Expected: Session should require re-login or short expiry
4. If persists indefinitely → info disclosure risk (stolen laptop = account access)

Concurrent session test:
1. Login from Device A → get token T1
2. Login from Device B → get token T2
3. Use T1 from Device A → should still work
4. Check: Does the app limit concurrent sessions?
5. If YES and limit is exceeded → does it revoke older or newer?

Most programs: concurrent sessions = NOT a finding
Some programs: concurrent sessions = MEDIUM (if stated in scope)
```

### Password Reset Flow Exploitation

```
Standard password reset flow:
1. Request reset: POST /api/forgot-password {"email": "victim@example.com"}
2. App sends email with reset link (or inline code)
3. User clicks link + enters new password
4. Account password updated

Attack vectors:

Vector 1: Host header injection
→ Attacker controls Host header to their domain
→ App sends password reset email to attacker's domain
→ Attacker receives reset code → resets victim password

Vector 2: Token predictability
→ Reset tokens are sequential or timestamp-based
→ Attacker enumerates tokens → resets victim password
→ ID: Must verify tokens are NOT sequential first

Vector 3: Account enumeration via reset response
→ POST /api/forgot-password with victim's email
→ Response: "If that email exists, we sent a reset"
→ Individual testing: valid email → "Reset sent" vs invalid → "Email not found"
→ Some programs consider enumeration alone OUT OF SCOPE
→ Enumeration + password reset = in scope

Vector 4: Race condition in reset
→ Send 100 simultaneous reset requests for victim
→ All 100 tokens valid, short expiry
→ Attacker just needs to guess/capture one

VALIDATION:
For each password reset vector:
[ ] Verify no CSRF token required on /forgot-password endpoint
[ ] Verify host header manipulation changes email destination
[ ] Verify reset tokens are not guessable
[ ] Measure concurrent reset token acceptance
```

### Multi-Factor Authentication Bypass Testing

```
2FA bypass test vectors:

Vector 1: Response manipulation
→ After entering correct password, server returns 
   {"requires_2fa": true, "user_id": "123", "temp_token": "abc"}
→ Attacker modifies response: {"requires_2fa": false}
→ App logs user in without 2FA

Vector 2: Direct API access
→ Login flow: POST /api/login → 2FA required
→ Direct access: GET /api/dashboard → sometimes bypasses 2FA
→ Check if protected endpoints enforce 2FA independently

Vector 3: Previous session reuse
→ User has valid session from before 2FA was enabled
→ Session not invalidated when 2FA was added
→ Attacker uses old session → bypass 2FA

Vector 4: Backup code enumeration
→ 2FA backup codes: 8-digit numerical codes
→ Bruteforce: 10^8 combinations (with rate limiting: infeasible)
→ Without rate limiting: feasible if codes aren't hashed

VALIDATION:
[ ] Bypass requires prior login (not applicable to account creation)
[ ] Does NOT require victim's 2FA code (that's bypass, not exploitation)
[ ] Prove bypass without the legitimate 2FA response
```

---

## BUG CLASS INTERACTION MATRIX

### Which bugs chain well together

```
HIGH-VALUE CHAINS:

XSS → Session Hijack → ATO
How: Stored XSS steals session cookie → use stolen cookie → full ATO
Impact: CRITICAL
Evidence: Cookie appears in attacker's server logs

SQLi → Data Exfil → Phishing
How: SQLi extracts user emails → targeted phishing campaign
Impact: HIGH (depends on scope)
Evidence: Extracted query results showing email list

IDOR → Email Change → Password Reset → ATO
How: IDOR changes victim's email → request reset → reset goes to attacker
Impact: CRITICAL
Evidence: Email change request + reset link received by attacker

SSRF → Cloud Metadata → AWS Credentials → S3 Data
How: SSRF reaches metadata endpoint → AWS creds exfiltrated → access company S3
Impact: CRITICAL
Evidence: AWS credentials in response + S3 bucket list

CSRF → Password Reset → Account Takeover
How: CSRF on password reset sets victim's email → request reset → attacker resets
Impact: HIGH
Evidence: Reset email to attacker's address

Open Redirect → OAuth Code Theft → ATO
How: App has open redirect on OAuth callback → attacker gets authorization code → exchange for token
Impact: CRITICAL
Evidence: auth_code in attacker.com server logs

Race Condition → Coupon/Discount Abuse
How: Send 50 parallel requests to apply 50% coupon → stack discounts
Impact: HIGH
Evidence: Multiple discount applications visible in cart

JWT None → Admin API Access
How: Modify JWT header to "none" → send to admin endpoint → gets admin response
Impact: CRITICAL
Evidence: Admin response in forged token response
```

### Chains that DON'T work / are overstated

```
OVERCLAIMED CHAINS:

"SSRF + open redirect" — 
SSRF reaches internal service → response contains redirect → attacker follows redirect
VERDICT: Redundant. If SSRF works, you already have the response.

"IDOR + information disclosure" — 
IDOR exposes user list → each user's email is listed
VERDICT: Just IDOR. The enumeration is not an additional exploit.

"Missing CSP + XSS" — 
App has no CSP AND has XSS capability
VERDICT: These are separate issues. Missing CSP is usually INFORMATIVE.
XSS with no impact (same-origin) is also often N/A.
Both together? Still N/A. The XSS payload would need to prove impact WITHOUT CSP.

"Rate limit bypass + brute force" — 
Rate limit bypass works on login → brute force passwords
VERDICT: This IS a valid chain IF brute force succeeds. If it just bypasses rate limit
but brute force takes 1000 years, the chain doesn't prove the impact.
```

---

## ENGAGEMENT-SPECIFIC TRIAGE ADAPTATIONS

### Private Program Triage

Private programs often have:
- Higher severity payouts on average
- Lower disclosure volumes (less to dedupe against)
- More program-specific rules

Adaptations:
```
1. Read the program's "What We Look For" VERY carefully
   - Private programs often have specific impact types they value
2. Dedup is faster (smaller disclosed report history)
3. Severity calibration may differ from public programs
4. Relationship matters: first report quality sets triager trust level
5. Response time may be slower; don't pester triagers
```

### VDP (Vulnerability Disclosure Program) Triage

VDPs (no bounty, responsible disclosure only):
```
1. Programs accept reports without bounty
2. Research MUST respect program's disclosure timeline
3. Severity is about risk, not payout
4. Same triage rules apply, but focus on:
   - Confirming vuln exists even if N/A or out-of-scope elements
   - Being thorough in remediation advice
   - Clear communication
5. Note: Do NOT pile on findings just because there's no payout ceiling
6. Maintain same quality standard — relationships matter
```

### Responsible Disclosure (No Bounty)

When there's NO bounty:
```
Adjust your perspective:
- Not about maximizing payout
- About making the internet safer
- About building a track record
- About helping the program improve

Still apply YES gates on:
- Real vuln (not theoretical)
- In scope
- Well-evidenced
- Good report quality

STILL avoid:
- Spamming with marginal findings
- Claiming severity without proof
- Testing without scope confirmation
```

---

## CONTINUOUS TRIAGE IMPROVEMENT LOG

Maintain a personal triage log:

```markdown
# Triage Log — [Your Name]

## Death Reasons (Learn from kills)

| Date | Finding | Death reason | Lesson learned |
|---|---|---|---|
| 2025-01-15 | XSS in search | Self-XSS only | Check who views the page before claiming XSS |
| 2025-01-16 | IDOR on /api/users | 200 with no body diff | Always check response body for actual third-party data |
| 2025-01-18 | SSRF to metadata | Body empty, CDN response | Register Burp Collaborator for real SSRF validation |
| 2025-01-20 | Open redirect | No chain to impact | Open redirects don't pay alone — chain or don't submit |

## Successful Patterns (Reinforce)

| Date | Finding | What worked |
|---|---|---|
| 2025-01-17 | IDOR + gender change chain | Chained two bugs for Critical payout |
| 2025-01-19 | SSRF → AWS creds | DNS callback + metadata PoC + live evidence |
| 2025-01-22 | Stored XSS on admin page | Required admin view, proved with second account |

## Retraction Reasons

| Date | Finding | Why retracted | Time wasted |
|---|---|---|---|
| 2025-01-16 | "IDOR on profile" | Users/me aliasing, not IDOR | 45 min |

## Quality Score Tracker

| Submission | Bug class | Severity claimed | Quality score (1-10) | Outcome |
|---|---|---|---|---|
| #1 | IDOR | High | 8 | Approved |
| #2 | SSRF | Critical | 9 | Approved |
| #3 | XSS | Medium | 4 | N/A |
| #4 | Chain XSS+CSRF | High | 8 | Approved |
| #5 | IDOR chain+ATO | Critical | 9 | Pending |
| #6 | SSRF+cloud | High | 7 | Approved |

Keep this log updated after EVERY submission. Tracking quality over quantity is the fastest path to consistent bounty income.

---

## Q8 IDENTITY CHECK — EXTENDED DEEP DIVE

### Identity-state mapping template

Before starting any authenticated test session, record your identity vocabulary:

```
SESSION REGISTRY:

Label | Token source | Privilege level | Notes
Session A | Primary test account (alice) | Low | Created [date], verified low-priv
Session B | Secondary test account (bob) | Low | Created [date], verified low-priv  
Session C | Admin test account (admin) | High | Program-provided or team account
Session D | API key | Varies | Often unscoped, test separately
Session E | Expired/invalid token | None | For auth bypass testing
Anonymous | No token | None | Baseline for "missing auth" checks

Record: session_id hashes from audit.jsonl for each session
```

### Identity matrix testing procedure

For EVERY authenticated finding before submission:

| Request | Session A | Session B | Session C | Anonymous |
|---|---|---|---|---|
| GET /users/me | 200 (own data) | 200 (own data) | 200 (own data) | 401 |
| GET /users/A_ID | 200 (self OR A's data) | 200 (self) | 200 (self) | 401 |
| GET /users/B_ID | 200 (A's data) → BUG or sees A's data (no bug) | 200 (B's data) | 200 (B's|C's data) | 401 |
| GET /admin/panel | 403 | 403 | 200 (admin view) | 403 |

Filling this matrix takes 5 minutes and eliminates the most common IDOR false positives.

### Identity pattern recognition — common misreadings

**Pattern: "200 on /users/456"**
- If session A GET /users/456 returns A's own data → no bug (users/me aliasing)
- If session A GET /users/456 returns DIFFERENT user's data → IDOR confirmed
- If session A GET /users/456 returns empty/404 → app properly scopes; no IDOR

**Pattern: "Session A can access admin endpoint"**
- If admin endpoint returns admin data for Session A → auth bypass (CRITICAL)
- If admin endpoint returns error/redirect for Session A → access control works
- If admin endpoint returns empty/stack-trace for Session A → may be info disclosure, not ATO

**Pattern: "Forged token accepted"**
- If forged JWT (none algorithm) returns ANY 200 → test if it's admin
- If forged JWT returns 200 on non-admin → token validation bypass, not admin ATO
- If forged JWT returns 200 on admin → full auth bypass confirmed

---

## EXTENDED ANTI-PATTERNS AND DEATH PATTERNS

### Death Pattern: The Single-Account Blind Spot

```
MANIFESTATION: "I found an IDOR — user 456's email showed up in the response"
On closer examination: You only tested from ONE account.
The endpoint is /api/users/me. The app returns the authenticated user's
email regardless of the path parameter (which is ignored).

REALITY: This is users/me aliasing, not IDOR.
The path parameter /456 is decorative; the server ignores it.
The username shows up because you're logged in as user 456.

HOW TO CATCH:
→ Always create a SECOND test account (Bob, ID=789)
→ Verify Bob's data is DIFFERENT from Alice's
→ Send Session A's request for Session B's resource
→ If it returns Session A's data → users/me aliasing → KILL
→ If it returns Session B's data → IDOR CONFIRMED
→ If it returns error → no bug, this is scoping
```

### Death Pattern: The Self-XSS Illusion

```
MANIFESTATION: "Stored XSS in profile bio — I can execute JavaScript"
On closer examination: The only person who views your own bio is yourself.

REALITY: Self-XSS requires victim to click a link AND log in AND visit
YOUR profile. Multi-step with low probability = usually N/A.

EXCEPTION: If stored XSS is in a context where OTHER users see it:
- Comment on public article
- Group chat message
- Forum post
- Review

THEN it's genuine stored XSS.

HOW TO CATCH:
→ Ask: "Who views this content?"
→ If only the author → self-XSS → KILL
→ If any logged-in user → could be valid (check victim action required)
→ If unauthenticated visitors can see → stronger impact
```

### Death Pattern: The Missing Auth Misidentification

```
MANIFESTATION: "Found IDOR — user 456's data with no authentication"
On closer examination: The same data appears when you send NO auth token.

REALITY: If no-token and Session-A-token return the SAME data,
this is MISSING AUTHENTICATION, not IDOR.

DIFFERENCE:
- Missing auth: No token needed at all → higher severity (anyone can access)
- IDOR: Valid token needed, but wrong token gets access → different attack

HOW TO CATCH:
→ Re-run the request WITHOUT Authorization header
→ If response changes → IDOR or privilege issue
→ If response is IDENTICAL → missing auth, NOT IDOR → report as auth bypass

REPORTING:
Auth bypass is often HIGHER severity than IDOR.
Report correctly: "Missing authentication on GET /api/users/{id}" not "IDOR"
```

### Death Pattern: The Admin Illusion

```
MANIFESTATION: "If I set my role to admin, I can see the admin panel"
On closer examination: The role field was in the JWT payload and you modified it.

REALITY: If the JWT signature is verified, you can't "set your role to admin."
If the role is in the payload but NOT verified server-side, you have an auth
bypass (JWT none algorithm or key confusion).

HOW TO CATCH:
→ Modify role in JWT → sign with your own key or use "none" algorithm
→ Send the modified token
→ If it works → auth bypass
→ If it fails with 401 → properly validated; the test was impossible

DO NOT:
- Change role in frontend state only and claim privilege escalation
- Use user-role from response body to claim "I am now admin"
- Confuse client-side role display with actual server-side authorization
```

---

## ADVANCED IDENTITY TESTING SCENARIOS

### Scenario: Multi-Tenant Application

```
Setting: SaaS app where multiple companies use same instance
Each company has its own "tenant ID" accessible via API

Testing approach:
1. Session A (tenant Alpha) creates resource
2. Session B (tenant Beta) tries to access Session A's resource
3. Session B (tenant Beta) tries to access tenant Gamma's resource

Valid bug: Session B can access Session A's tenant data
Invalid: Session B can always see some "public" tenant resources

What's the scope boundary?
- Each tenant IS a separate administrative domain
- Cross-tenant access IS a real bug
- BUT some fields may be intentionally shared (public company info)
```

### Scenario: API Key with Variable Scopes

```
Setting: API key system where keys can have different permission scopes

Testing approach:
1. Get key with "read:users" scope only
2. Try read endpoint → should work
3. Try write endpoint with same key → should fail (out of scope)
4. Try admin endpoint with same key → should fail

Valid bug: Write endpoint accepts key with only read scope
Invalid: App correctly rejects write with read-only key

Multi-key testing:
- Key A (read-only): can read users but not admin data
- Key B (read+write): can update users
- Key C (admin): can do everything

Check: Does Key A read anything Key C can read? If yes → over-privileged API
```

### Scenario: OAuth Token Confusion

```
Setting: OAuth 2.0 application with multiple grant types

Testing approach:
1. Get access_token via Authorization Code flow
2. Use same token in different client context (mobile vs web)
3. Use token after user revokes consent
4. Use token from different IP/geography
5. Try to use refresh_token for different user

Valid bugs:
- Token works after user revoked consent → token not properly bound
- Token from mobile client works on web client → scope not validated
- Refresh token of user A gets user B's access token → token leakage

Common pattern that's NOT a bug:
- OAuth token has long expiry → this is configurable, not a vuln
- Token works across subdomains → expected for single-page apps
- Token survives page reload → expected behavior
```

---

## AUTHENTICATION-SPECIFIC DEEP DIVES

### Session Management Validation

```
Session invalidation test sequence:
1. Login → record token T1
2. Use T1 → confirm works (200)
3. Logout → send logout request
4. Immediately retry T1 on protected endpoint
5. Expected: 401 (token invalidated)
6. If 200: session not invalidated on logout → NEW FINDING

Token persistence test:
1. Login via browser → close browser → reopen
2. Check if session persists (cookie with far-future expiry)
3. Expected: Session should require re-login or short expiry
4. If persists indefinitely → info disclosure risk (stolen laptop = account access)

Concurrent session test:
1. Login from Device A → get token T1
2. Login from Device B → get token T2
3. Use T1 from Device A → should still work
4. Check: Does the app limit concurrent sessions?
5. If YES and limit is exceeded → does it revoke older or newer?

Most programs: concurrent sessions = NOT a finding
Some programs: concurrent sessions = MEDIUM (if stated in scope)
```

### Password Reset Flow Exploitation

```
Standard password reset flow:
1. Request reset: POST /api/forgot-password {"email": "victim@example.com"}
2. App sends email with reset link (or inline code)
3. User clicks link + enters new password
4. Account password updated

Attack vectors:

Vector 1: Host header injection
→ Attacker controls Host header to their domain
→ App sends password reset email to attacker's domain
→ Attacker receives reset code → resets victim password

Vector 2: Token predictability
→ Reset tokens are sequential or timestamp-based
→ Attacker enumerates tokens → resets victim password
→ ID: Must verify tokens are NOT sequential first

Vector 3: Account enumeration via reset response
→ POST /api/forgot-password with victim's email
→ Response: "If that email exists, we sent a reset"
→ Individual testing: valid email → "Reset sent" vs invalid → "Email not found"
→ Some programs consider enumeration alone OUT OF SCOPE
→ Enumeration + password reset = in scope

Vector 4: Race condition in reset
→ Send 100 simultaneous reset requests for victim
→ All 100 tokens valid, short expiry
→ Attacker just needs to guess/capture one

VALIDATION:
For each password reset vector:
[ ] Verify no CSRF token required on /forgot-password endpoint
[ ] Verify host header manipulation changes email destination
[ ] Verify reset tokens are not guessable
[ ] Measure concurrent reset token acceptance
```

### Multi-Factor Authentication Bypass Testing

```
2FA bypass test vectors:

Vector 1: Response manipulation
→ After entering correct password, server returns 
   {"requires_2fa": true, "user_id": "123", "temp_token": "abc"}
→ Attacker modifies response: {"requires_2fa": false}
→ App logs user in without 2FA

Vector 2: Direct API access
→ Login flow: POST /api/login → 2FA required
→ Direct access: GET /api/dashboard → sometimes bypasses 2FA
→ Check if protected endpoints enforce 2FA independently

Vector 3: Previous session reuse
→ User has valid session from before 2FA was enabled
→ Session not invalidated when 2FA was added
→ Attacker uses old session → bypass 2FA

Vector 4: Backup code enumeration
→ 2FA backup codes: 8-digit numerical codes
→ Bruteforce: 10^8 combinations (with rate limiting: infeasible)
→ Without rate limiting: feasible if codes aren't hashed

VALIDATION:
[ ] Bypass requires prior login (not applicable to account creation)
[ ] Does NOT require victim's 2FA code (that's bypass, not exploitation)
[ ] Prove bypass without the legitimate 2FA response
```

---

## BUG CLASS INTERACTION MATRIX

### Which bugs chain well together

```
HIGH-VALUE CHAINS:

XSS → Session Hijack → ATO
How: Stored XSS steals session cookie → use stolen cookie → full ATO
Impact: CRITICAL
Evidence: Cookie appears in attacker's server logs

SQLi → Data Exfil → Phishing
How: SQLi extracts user emails → targeted phishing campaign
Impact: HIGH (depends on scope)
Evidence: Extracted query results showing email list

IDOR → Email Change → Password Reset → ATO
How: IDOR changes victim's email → request reset → reset goes to attacker
Impact: CRITICAL
Evidence: Email change request + reset link received by attacker

SSRF → Cloud Metadata → AWS Credentials → S3 Data
How: SSRF reaches metadata endpoint → AWS creds exfiltrated → access company S3
Impact: CRITICAL
Evidence: AWS credentials in response + S3 bucket list

CSRF → Password Reset → Account Takeover
How: CSRF on password reset sets victim's email → request reset → attacker resets
Impact: HIGH
Evidence: Reset email to attacker's address

Open Redirect → OAuth Code Theft → ATO
How: App has open redirect on OAuth callback → attacker gets authorization code → exchange for token
Impact: CRITICAL
Evidence: auth_code in attacker.com server logs

Race Condition → Coupon/Discount Abuse
How: Send 50 parallel requests to apply 50% coupon → stack discounts
Impact: HIGH
Evidence: Multiple discount applications visible in cart

JWT None → Admin API Access
How: Modify JWT header to "none" → send to admin endpoint → gets admin response
Impact: CRITICAL
Evidence: Admin response in forged token response
```

### Chains that DON'T work / are overstated

```
OVERCLAIMED CHAINS:

"SSRF + open redirect" — 
SSRF reaches internal service → response contains redirect → attacker follows redirect
VERDICT: Redundant. If SSRF works, you already have the response.

"IDOR + information disclosure" — 
IDOR exposes user list → each user's email is listed
VERDICT: Just IDOR. The enumeration is not an additional exploit.

"Missing CSP + XSS" — 
App has no CSP AND has XSS capability
VERDICT: These are separate issues. Missing CSP is usually INFORMATIVE.
XSS with no impact (same-origin) is also often N/A.
Both together? Still N/A. The XSS payload would need to prove impact WITHOUT CSP.

"Rate limit bypass + brute force" — 
Rate limit bypass works on login → brute force passwords
VERDICT: This IS a valid chain IF brute force succeeds. If it just bypasses rate limit
but brute force takes 1000 years, the chain doesn't prove the impact.
```

---

## ENGAGEMENT-SPECIFIC TRIAGE ADAPTATIONS

### Private Program Triage

Private programs often have:
- Higher severity payouts on average
- Lower disclosure volumes (less to dedupe against)
- More program-specific rules

Adaptations:
```
1. Read the program's "What We Look For" VERY carefully
   - Private programs often have specific impact types they value
2. Dedup is faster (smaller disclosed report history)
3. Severity calibration may differ from public programs
4. Relationship matters: first report quality sets triager trust level
5. Response time may be slower; don't pester triagers
```

### VDP (Vulnerability Disclosure Program) Triage

VDPs (no bounty, responsible disclosure only):
```
1. Programs accept reports without bounty
2. Research MUST respect program's disclosure timeline
3. Severity is about risk, not payout
4. Same triage rules apply, but focus on:
   - Confirming vuln exists even if N/A or out-of-scope elements
   - Being thorough in remediation advice
   - Clear communication
5. Note: Do NOT pile on findings just because there's no payout ceiling
6. Maintain same quality standard — relationships matter
```

### Responsible Disclosure (No Bounty)

When there's NO bounty:
```
Adjust your perspective:
- Not about maximizing payout
- About making the internet safer
- About building a track record
- About helping the program improve

Still apply YES gates on:
- Real vuln (not theoretical)
- In scope
- Well-evidenced
- Good report quality

STILL avoid:
- Spamming with marginal findings
- Claiming severity without proof
- Testing without scope confirmation
```

---

## CONTINUOUS TRIAGE IMPROVEMENT LOG

Maintain a personal triage log:

```markdown
# Triage Log — [Your Name]

## Death Reasons (Learn from kills)

| Date | Finding | Death reason | Lesson learned |
|---|---|---|---|
| 2025-01-15 | XSS in search | Self-XSS only | Check who views the page before claiming XSS |
| 2025-01-16 | IDOR on /api/users | 200 with no body diff | Always check response body for actual third-party data |
| 2025-01-18 | SSRF to metadata | Body empty, CDN response | Register Burp Collaborator for real SSRF validation |
| 2025-01-20 | Open redirect | No chain to impact | Open redirects don't pay alone — chain or don't submit |

## Successful Patterns (Reinforce)

| Date | Finding | What worked |
|---|---|---|
| 2025-01-17 | IDOR + gender change chain | Chained two bugs for Critical payout |
| 2025-01-19 | SSRF → AWS creds | DNS callback + metadata PoC + live evidence |
| 2025-01-22 | Stored XSS on admin page | Required admin view, proved with second account |

## Retraction Reasons

| Date | Finding | Why retracted | Time wasted |
|---|---|---|---|
| 2025-01-16 | "IDOR on profile" | Users/me aliasing, not IDOR | 45 min |

## Quality Score Tracker

| Submission | Bug class | Severity claimed | Quality score (1-10) | Outcome |
|---|---|---|---|---|
| #1 | IDOR | High | 8 | Approved |
| #2 | SSRF | Critical | 9 | Approved |
| #3 | XSS | Medium | 4 | N/A |
| #4 | Chain XSS+CSRF | High | 8 | Approved |
| #5 | IDOR chain+ATO | Critical | 9 | Pending |
| #6 | SSRF+cloud | High | 7 | Approved |

Keep this log updated after EVERY submission. Tracking quality over quantity is the fastest path to consistent bounty income.
```

---

## COMPLETE BUG-CLASS-SPECIFIC IDENTITY CHECK PROTOCOLS

### IDOR Cross-Account Validation Checklist

```
Minimum test set (ALL 4 required):
1. Session A GET /api/resource/A_ID → 200 (A's data — baseline)
2. Session A GET /api/resource/B_ID → ? (the test)
3. Session B GET /api/resource/B_ID → 200 (B's data — confirms data exists)
4. Session B GET /api/resource/A_ID → ? (cross-check)

IDOR confirmed ONLY if:
- Result #2 shows B's actual data (email, name, etc.)
- AND Result #4 shows 403/404 (boundary enforced, B can't read A)

IDOR NOT confirmed if:
- Result #2 shows A's own data → users/me aliasing
- Result #2 shows 404 → resource not found (proper behavior)
- Result #2 shows empty response → unclear, investigate further

Degenerate IDOR patterns to watch for:
- Self-referential IDOR: app returns authenticated user's data regardless of ID parameter
- Shared-data IDOR: multi-tenant where all users legitimately share certain docs
- Enumeration vs IDOR: sequential/guessable IDs that return user data is often enumeration, not IDOR
  (IDOR requires: Resource X is owned by User X, Resource Y is owned by User Y, and the system FAILS to enforce that boundary)
```

### XSS Cross-User Visibility Validation

```
Stored XSS severity depends on WHO VIEWS the content:
1. Self-XSS only: Only attacker sees their own payload → LOW or N/A
2. Other user views: Any logged-in user views attacker's content → VALID (MEDIUM-HIGH)
3. Admin views: Admin/targeted user views → HIGH-CRITICAL
4. Public view: Unauthenticated visitors can see → HIGHEST

Validation checklist for stored XSS:
[ ] Payload stored in user A's profile/comment
[ ] Payload executes when user B (or admin) views it
[ ] Document the viewer identity in the report
[ ] Show the audience size (how many users/viewers see this content)
```

### SSRF Impact Classification by Identity Context

```
SSRF validation does not require authentication, but IMPACT depends on privilege:

Anonymous SSRF:
- SSRF to AWS metadata returns credentials → CRITICAL (anyone can exploit)
- SSRF to internal admin panel → HIGH (privilege escalation to internal)

Authenticated-user SSRF:
- SSRF to internal admin panel → HIGH (user gets admin access)
- SSRF to same-app internal endpoints → MEDIUM
- SSRF to file:///etc/passwd → MEDIUM (info disclosure)

Document for SSRF reports:
- Which identity context produced the SSRF (anonymous, authenticated, role)
- What internal data/service was reached
- What was the output (creds, data, error)
- Scope note: is internal host directly in scope, or just the SSRF primitive?
```

### Auth Bypass Identity Discipline

The Q8 rule is strictest for auth bypass claims:

```
Claim: "I bypassed authentication"
Must test (all 4):
✓ Request WITHOUT any token → works (bypass confirmed)
✓ Request WITH invalid/expired token → works (bypass confirmed)
✓ Request WITH Session B's token → works (session confusion)
✓ Request WITH valid attacker token → works (expected; confirms baseline)

If request works WITHOUT token → MISSING AUTHENTICATION
  (not "IDOR", not "BOLA" — this is auth bypass, severity typically HIGH)

If request works WITH Session A token on Session B's data → IDOR

If request works WITH Session B token on Session A's data → IDOR

If request works WITH attacker token but NOT without → AUTHENTICATED, not bypass
```

### Race Condition Identity Requirements

```
Race conditions require concurrent requests under SAME identity:

VALID: 50 parallel requests from Session A's token
- Result: duplicate coupon applied to Session A's cart
- Impact: financial benefit to Session A

INVALID: 25 requests from Session A, 25 from Session B, both hit the race
- Result: mixed credit — not verifiable as single attacker's gain
- Fix: run race under SINGLE authenticated session

Test protocol:
1. Login once → get session token
2. Spawn 50 parallel requests with SAME token
3. Confirm outcome (e.g., balance, coupon count) for THAT account
4. Don't spread across multiple accounts
```

---

## FINAL IDENTITY VERIFICATION PROTOCOL (PRE-SUBMIT)

Before submitting ANY authenticated finding, run this final identity check:

```
MANDATORY PRE-SUBMIT IDENTITY CHECKLIST:

[ ] I created TWO distinct test accounts (not just one + the victim I found)
[ ] I tested with Session A (attacker) and Session B (victim)
[ ] The finding reproduces with Session A accessing Session B's data
[ ] Session B accessing Session A's data ALSO reproduces (symmetry check)
[ ] The behavior is NOT the same as Session A accessing Session A's own data
[ ] No-token baseline test: the same request without auth behaves differently
[ ] I can describe which identity boundary was crossed in ONE sentence
[ ] I can point to the exact code or configuration failure that allowed it

IF ANY CHECKBOX IS UNCHECKED → Go back and run the identity matrix.
DO NOT submit until all boxes are checked.
```

---

## ANTI-PATTERN REFERENCE: WHAT NOT TO CLAIM

### Claiming escalation without verified exploitation

```
BAD: "I was able to elevate to admin privileges"
GOOD: "I was able to access the admin endpoint at /admin/dashboard
       using my low-privilege user session. The response contained
       admin-only data: user management table with 15,000 user records."

The difference: GOOD has evidence, endpoint, data sample, and scope.
BAD has only a vague escalation claim.
```

### Claiming impact without impact demonstration

```
BAD: "This could lead to full account takeover"
GOOD: "Using the stolen session cookie (shown in screenshot), I logged
       into the victim's account and changed their password to my own,
       demonstrating full account takeover."

The difference: GOOD shows each step with evidence. BAD uses "could"
language that triagers consistently reject.
```

### Claiming persistence without persistence proof

```
BAD: "I was able to create a persistent backdoor"
GOOD: "I created a new admin account 'backup_admin' via the IDOR 
       vulnerability. This account persists in the user database
       (verified by re-login 24h later)."

The difference: persistence claims require showing the account STILL EXISTS.
A temporary action is not persistence.
```
```
