---
name: triage-validation
description: Finding validation before writing any report — 7-Question Gate (all 7 questions), 4 pre-submission gates, always-rejected list, conditionally valid with chain table, CVSS 3.1 quick reference, severity decision guide, report title formula, 60-second pre-submit checklist. Use BEFORE writing any report. One wrong answer = kill the finding and move on. Saves N/A ratio.
---

# TRIAGE & VALIDATION

One wrong answer = STOP **this finding**. Kill **the finding**. Move on **to the next test class**.

> **Scope of "STOP" in this skill:** This skill's gates kill INDIVIDUAL FINDINGS that fail validation. They do NOT authorize stopping the engagement. Killing a finding via the 7-Question Gate just means *that finding* doesn't get submitted — every other test class in the engagement is still pending. See `redteam-mindset` "DO NOT STOP primary directive" for the coverage-axis rule.

> "N/A hurts your validity ratio. Informative is neutral. Only submit what passes all 7 questions."

---

## THE 7-QUESTION GATE

Ask IN ORDER. One wrong answer = STOP immediately.

Every question below includes a decision rule, a template to fill in, and common failure modes that cause hunters to ship invalid findings.

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

#### Q1 expanded — common failure modes

Each example below maps a specific invalid pattern to its failure outcome.

Failure mode 1 — response echo:
- You send `"<script>alert(1)</script>"` and see it in the response body.
- This proves the server reflected your input, not that it executed.
- Kill unless you can show the payload runs in a browser context via a real page.

Failure mode 2 — 200 ≠ leak:
- You request another user’s resource and get HTTP 200.
- Body is byte-identical to baseline or contains zero third-party data.
- Kill unless the response body actually contains a different user’s data.

Failure mode 3 — internal-only reproduction:
- Reproduction works only inside corporate VPN or on a staging subdomain.
- No public in-scope asset reproduces it.
- Kill unless scope explicitly includes that asset.

Failure mode 4 — code-reading-only:
- Source review showed a missing authorization check.
- You did not manage to issue the live HTTP request.
- Kill until live reproduction is recorded.

---

### Q2: Is the impact on the program's accepted impact list?

**Decision rule:** Map your finding to the program’s published "In Scope / Out of Scope / Severity" definitions. If the program explicitly excludes the impact class, the finding is dead regardless of technical validity.

---

#### Q2 expanded — tier mapping examples

| Program-stated impact | Typical technical primitive | Valid? |
|---|---|---|
| Any-user ATO without interaction | Session hijack via stored XSS on profile bio | Yes — Critical or High |
| Mass PII exfil | IDOR enumerating all user profiles | Yes — High |
| Admin auth bypass | JWT none algorithm on admin endpoints | Yes — Critical |
| Internal SSRF with data exfil | SSRF to AWS metadata returning credentials | Yes — High |
| Stored XSS affecting all users | Stored XSS in comment field viewed by any user | Yes — High |
| Clickjacking requiring CAPTCHA bypass | Clickjacking on login with CAPTCHA | Usually No if bypass unrealistic |
| Pure information disclosure with no sensitive data | Error message reveals framework version | Usually No |

---

### Q3: Is the root cause in an in-scope asset?

**Decision rule:** Confirm the exact host, path, and protocol are within the program’s scope. Internal subdomains, third-party integrations, and dev environments are out of scope unless the program explicitly lists them.

**Checklist:**
- [ ] Vulnerable hostname appears on the program’s in-scope list
- [ ] Port and protocol match scope (443 standard; 8080/8443 only if listed)
- [ ] Asset is production, not staging/dev/testing, unless stated
- [ ] Third-party services (Stripe, Google Auth, Twilio) are excluded unless the issue is in YOUR integration with them, not the service itself
- [ ] Redirect endpoint lands on an in-scope asset for the full chain

---

### Q4: Does it require privileged access that an attacker can't realistically get?

**Decision rule:** Evaluate whether the attacker role is realistic. Admin-level findings are almost always invalid. Findings requiring a compromised victim account are borderline-to-invalid.

| Attacker starting point | Verdict |
|---|---|
| Any free registered account | Valid, low or medium severity baseline |
| No account, anonymous | Valid, higher severity |
| Account I already own, no victim required | Valid |
| Requires another user to click a link | Valid if click is realistic (phishing, message, comment) |
| Requires victim to perform an unlikely multi-step workflow | Questionable |
| Admin role required to observe the behavior | **KILL IT** |
| Physical access to corporate network | **KILL IT** for remote programs |
| Requires a leaked API key or prior breach | **KILL IT** unless the key is also the target of disclosure |

---

### Q5: Is this already known or accepted behavior?

**Decision rule:** If the behavior is documented in public API docs, public GitHub issues, changelogs, or previously disclosed reports, the program has accepted the risk. Move on.

---

#### Q5 expanded — search procedure

Step 1 — HackerOne Hacktivity:
```
Filters:
- Program name in quotes
- Vuln class keyword
- Endpoint keyword
Sort by most recent first. Case-insensitive Ctrl+F through the last 20 reports.
```

Step 2 — GitHub:
```
1. Open target/repo-name
2. Issues → Search: "is:issue is:open ENDPOINT_NAME"
3. Issues → Search: "is:closed ENDPOINT_NAME security"
4. PRs mentioning the endpoint
```

Step 3 — Changelog/CHANGELOG.md:
```
Search for behavior keywords: "allow", "permit", "expose", "return additional"
A changelog line that says "API now returns additional account fields" is an acceptance signal.
```

Step 4 — Public API docs/swagger:
```
If the documented schema includes the field you believe is an IDOR leak, the API is working as designed.
```

**Signals to KILL immediately:**
- Open issue in target repo labeled "wontfix" with same symptom
- Closed as "by design"
- Mentioned in release notes
- Existing disclosed report with same endpoint and bug class

---

### Q6: Can you prove impact beyond "technically possible"?

**Decision rule:** The finding must demonstrate a concrete attacker gain, not just an anomaly. For each vuln class below, a "technically possible" threshold and a "proven impact" threshold are given.

| Vuln class | Technically possible (kill) | Proven impact (submit) |
|---|---|---|
| XSS | `alert(1)` fires in isolated HTML page | Cookie theft, token exfil, or admin session hijack on a live user-viewable page |
| SSRF | SSRF to `169.254.169.254` returns HTTP 200 | Metadata returns AWS credentials, or Redis returns session keys |
| SQLi | Error message contains SQL syntax text | Extracted real data from a real table (user, order, payment) |
| IDOR | 200 OK on `/users/456` while authenticated as user 1 | Response contains another user’s email, phone, address, or payment data |
| CSRF | Form submits successfully from attacker.com | Email changed, password reset initiated, funds moved on victim’s behalf |
| Race | Some requests return 200 in parallel | Duplicate coupon application, double spend, or account creation |
| JWT none | Forged token returns 200 on an endpoint | Forged token returns admin-only response body |
| Open redirect | `?next=https://evil.com` redirects | Chain to OAuth code theft via redirect_uri abuse |

**Key principle:** If the only thing you can show is an HTTP status code, you have not proven impact. Get body content that is concretely different from your own account’s data.

---

#### Q6 expanded — proof thresholds by bug class

XSS proof thresholds:
- Minimum: Payload executes in a victim-viewable context (profile, comment, feed).
- Preferred: Stolen cookie appears in server access logs.
- Chain required if the only execution context is your own account page.

SSRF proof thresholds:
- Minimum: Internal endpoint returns HTTP 200 and a body not available from the public internet.
- Preferred: Body contains real secrets (AWS keys, Redis keys, JWT tokens).
- DNS-only is treated as Informative unless chained.

SQLi proof thresholds:
- Minimum: Union-based extraction returns non-base-table data.
- Preferred: Extraction from users/passwords table demonstrated.
- Error-only is treated as Informative unless chained with data exfil.

IDOR proof thresholds:
- Minimum: Another user’s non-public PII in a response you triggered with your own credentials.
- Preferred: Financial, credential, or admin data demonstrated.
- A 200 with empty or `{"success":true}` is not IDOR; it is a missing/inconsistent response.

---

### Q7: Is this a known-invalid bug class?

**Decision rule:** Check the NEVER SUBMIT and CONDITIONALLY VALID lists below. If your finding matches an always-rejected entry and does not form part of a chain with another bug → **KILL IT.**

---

## 4 PRE-SUBMISSION GATES

Run ALL four. Every gate must PASS before report drafting begins.

---

### Gate 0: Reality Check — 30 seconds

```
[ ] Bug is REAL — confirmed with actual HTTP requests, not code reading alone
[ ] Bug is IN SCOPE — checked program scope page explicitly, hostname verified
[ ] Reproducible from scratch — can reproduce starting from a fresh session
[ ] Evidence ready — screenshot, response body, or video recorded
```

**Failure handling:**
- Bug is REAL fails → Return to recon/testing until live reproduction exists.
- IN SCOPE fails → Kill; do not chain out-of-scope to in-scope unless the chain starts in-scope end-to-end (redirects, SSRF callbacks).
- Reproducible from scratch fails → Retest from zero; if still fails, this is a flaky finding. Flaky findings should be retracted, not patched in reports.
- Evidence ready fails → Capture evidence before writing. Reports without evidence go to triage backlog indefinitely.

---

### Gate 1: Impact Validation — 2 minutes

```
[ ] Can answer: "What can attacker DO that they couldn't before?"
[ ] Answer is more than "see non-sensitive data" (unless program pays for info disclosure)
[ ] Real victim: another user's data, company's data, financial loss
[ ] Not relying on victim doing something unlikely
```

**Failure handling:**
- Cannot answer "What can attacker DO?" → downgrade to Informative or kill.
- Answer is only "see non-sensitive data" → Check program scope; if info disclosure is out of scope, kill.
- Real victim is "themselves" → This is self-XSS; kill unless chained.
- Relies on unlikely victim action → Questionable; downgrade to Low at best.

---

### Gate 2: Deduplication Check — 5 minutes

```
[ ] Searched HackerOne Hacktivity for this program + similar bug title/endpoint
[ ] Searched GitHub issues for target repo
[ ] Read most recent 5 disclosed reports for this program
[ ] Not a "known issue" in their changelog or public docs
[ ] Google: "TARGET_NAME ENDPOINT_NAME bug bounty"
```

**Failure handling:**
- Disclosed report with same endpoint + same vuln class exists → Property of the program; do not resubmit the same finding.
- Disclosed report with same endpoint but different vuln class is fine if your bug is distinct.
- Changelog mentions fix or accepts behavior → Kill; behavior is intentional.

---

### Gate 3: Report Quality — 10 minutes

```
[ ] Title: [Bug Class] in [Endpoint] allows [actor] to [impact]
[ ] Steps to Reproduce: copy-pasteable HTTP request
[ ] Evidence: screenshot/video of actual impact (not just 200 status)
[ ] Severity: matches CVSS 3.1 score AND program's severity definitions
[ ] Remediation: 1-2 sentences of concrete fix
[ ] NEVER used "could potentially" or "may allow"
```

**Failure handling:**
- Title is vague ("Bug in login") → Rewrite using the formula above.
- Steps not copy-pasteable → Fill in exact headers, exact body, exact URL.
- Evidence is only a 200 status → Capture body content; a 200 without body is not an impact proof.
- Severity mismatch → Revisit CVSS metrics; downgrade rather than overclaim.
- Uses "could potentially" or "may allow" → Rewrite to definitive language.

---

## NEVER SUBMIT LIST

Submitting these destroys your validity ratio. These are standalone rejections with or without proof.

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

Build the chain first, prove it works end to end, THEN report. The chain must be proven IN YOUR REPORT; "could chain with …" is not a reportable chain.

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

## OVERCLAIM DISCIPLINE

Overclaim severity to test triager calibration. You want:
- Fast triage approvals because the report is accurate.
- Long-term trust so the triager accepts your severity claim on future reports.

Priority list for severity language:
1. Use program’s own severity definitions verbatim.
2. Use CVSS vector and score as secondary justification.
3. Justify with "real-world impact" wording, not theoretical max damage.

---

## RETRACTION DISCIPLINE

When a previously-claimed finding fails reproduction — **never silently drop it.** Document the retraction in the report's appendix. This proves to the triager that you validate your own work, and it saves them from chasing a phantom you've already disproved.

**Retraction entry template:**

```markdown
### Retracted: <finding name>

- **Original signal:** <one-line description>
- **Disproving evidence:** <concrete repro-step + observation>
- **Why it looked like a bug:** <root cause — e.g., natural marker collision>
- **Retraction date:** <YYYY-MM-DD>
```

**Concrete retractions from an authorized engagement — pattern reference:**

- **X-Forwarded-Proto reflection** — looked like header reflection across 4 pages; was the literal word `javascript` in SP help-link hrefs.
- **Host header `:80@evil` bypass** — 200 OK on a path that normally 403s; body byte-identical to baseline (8341 bytes).
- **`download.aspx` file-existence oracle** — looked like a differentiator; was a file-extension blocklist.
- **`Administrator` timing leak** — single-shot 1527 ms vs ~700 ms; n=80 trials collapsed to uniform timing.
- **`?next=` parameter claimed as open redirect** — Redirected but target required matching Origin header next request, so chain to OAuth code theft did not complete.
- **GraphQL introspection claimed as auth bypass** — Introspection worked but node() queries still returned `null` for unauthenticated users; no IDOR demonstrated.

---

## Related Skills & Chains

| Skill | Role in workflow |
|---|---|
| `report-writing` | After this skill’s 7Q + 4 gates pass. Only findings that clear get the report-template handoff. |
| `vulnerability-chaining` | When an always-rejected finding needs a chain. Workflow primitive: build chain first, then come back to this skill. |
| `evidence-hygiene` | When a validated finding needs PoC evidence captured. Workflow primitive: Q6 requires proof; this skill invokes capture protocol. |
| `security-arsenal` | When checking always-rejected / conditionally-valid tables. Either entry-point lookup shares alignment. |
| `bb-methodology` | Phase 5 invokes this skill before any report is drafted. Workflow primitive: this skill is the Phase 5 gate. |

---

## Operator Notes (Claude-BugHunter)

> Engagement-derived additions to the vendored foundation. Wisdom from real
> authorized engagements + Phase 2 verification across this repo's 31+
> skill-area live tests. The upstream methodology covers the WHAT; this
> layer covers WHEN-IT-ACTUALLY-WORKS and the FAILURE-MODES.

### 7-Question Gate at scale

Phase 2D's hardened-lab campaign verified the 7Q gate kills four distinct false-positive shapes:

1. **URL echo dressed as reflection** — payload appears in response because response IS the URL. Q1 kills it because the server state never changed.
2. **Word collision dressed as marker hit** — the canary string matched a CSS class, not your payload. Q1 + Marker Discipline kills it.
3. **Server policy mistaken for state oracle** — returns "blocked" regardless of file existence. Q6 kills it: no oracle, just a deny-list.
4. **200 OK without leak** — status differs from baseline 403; body is byte-identical. Q6 + Body-Diff Rule kills it.

Without the 7Q gate, expect 10-20% submission validity loss. With it, retraction rates trend to single digits.

### Pre-Severity Gate before reporting Critical

An authorized SharePoint engagement nearly submitted a Critical when a primitive that read auth state was conflated with a primitive that mutated it. The Pre-Severity Gate would have caught it.

Process: write your draft Critical title. Take each Q and answer with the Critical claim. If Q6 returns "I have a primitive that should let me do X, but I haven't demonstrated X end-to-end," downgrade.

### Retraction discipline

If a finding stops reproducing within 24h of submission, retract preemptively. Self-retraction signals "the researcher validates their own work." Triager retraction signals "the researcher submitted noise."

### When the 7Q feels obstructive

The friction is the gate working. The half of findings that get killed by the 7Q are the half that would have come back as Informative or N/A. Take the friction. Your average payout per submission goes up when low-confidence findings stop diluting the funnel.

If the 7Q kills a finding but you still believe it, gather more evidence, do not bypass the gate.

---

## Expanded edge cases

### Scope creep examples

- `cdn.target.com` serves user-uploaded avatars; a stored XSS in an image filename executes on `www.target.com`. This is **in scope** because the vulnerability chain starts on an in-scope asset and achieves impact there.
- `dev-api.target.com` exposes real production user data. If scope explicitly lists `*.target.com`, this is in scope. If scope lists only production subdomains, this is **out of scope**.
- An OAuth `redirect_uri` on `staging.target.com` that redirects to `www.target.com`. The staging domain is out of scope, but the OAuth code theft happens at the in-scope domain. Treat the chain as **in scope only if the initial OAuth request itself is accepted by an in-scope client**; otherwise kill.

### Chain-only acceptance patterns

| Primitive | Required chain | Outcome when proven |
|---|---|---|
| SSRF to 169.254.169.254 returning 200 | → AWS credentials extracted → S3 bucket listed and a real file read | **Critical** |
| Stored XSS in own bio viewable only by self | → CSRF form auto-submitted on admin view | **Medium to High** |
| IDOR returning 200 with empty body | → IDOR returning another user’s order total and last 4 digits | **High** |
| GraphQL introspection enabled | → node() query returns other user’s email without auth | **High** |
| Open redirect to attacker.com | → OAuth code appears in attacker.com access logs | **Critical** |

### Severity ceiling rules

| Impact type | Typical CVSS range | Notes |
|---|---|---|
| PII read only, one user | Medium 6.5 | Single-user IDOR |
| Mass PII, no auth, no user interaction | High 8.6+ | Depends on PII volume |
| Session hijack via XSS on popular page | High 8.8+ | Scope: C = Changed (affects browser) |
| ATO via password reset email change | High 7.5 – Critical | Depends on whether victim interaction required |
| RCE / full DB dump | Critical 9.0+ | C / I / A all High, PR often None |
| Cloud metadata credential exfil | Critical 9.1+ | S = Changed (cloud ecosystem) |

---

## 60-Second Pre-Submit Checklist

Before clicking submit, confirm ALL of the following:

- [ ] HTTP request copy-pastes without redacted secrets.
- [ ] Impact section describes a concrete attacker gain, not a theoretical maximum.
- [ ] Remediation is a real code-level fix, not "use parameterized queries" as filler.
- [ ] Severity language matches the program’s definitions.
- [ ] No "potentially", "may", "could" language remains.
- [ ] No internal hostname, API key, or production credential appears in the report body or attachments.
- [ ] No retracted finding is included in the submission body.
- [ ] Report title follows the formula: `[Bug Class] in [Endpoint] allows [actor] to [impact]`.

---

## COMPLETE 7-QUESTION DEEP DIVE — EXTENDED EXAMPLES

### Q1 Extended — Technical Reproducibility

The Q1 gate is the strongest single filter against invalid submissions. It forces you to convert "I found something" into "I can demonstrate this in 30 seconds with a copy-paste command."

**Reproducibility tests:**

Test 1 — Direct HTTP reproduction:
```bash
# Can you write this request right now from memory?
curl -sk -X POST "https://target.com/api/users/123" \
  -H "Authorization: Bearer ATTACKER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"userId": 456, "email": "attacker@evil.com"}'
# If you cannot write this without looking at Burp → kill.
```

Test 2 — From-fresh-session reproduction:
```bash
# Clear all cookies, logout, login fresh
# Re-run the exact request from Test 1
# If it fails → state-dependent finding; investigate state dependency
```

Test 3 — Minimal payload reproduction:
```bash
# Strip your PoC to the MIMIMUM payload that still triggers
# If removing ANY non-essential parameter breaks the PoC,
# you need to know which parameter is essential
```

**Q1 death signals:**
- "I need to look at the Burp history to remember the exact request"
- "It only works if I'm logged in and have a specific user role"
- "I can show it in the browser UI but not as an HTTP request"
- "The payload fires in one specific tab but not from a clean request"

---

### Q2 Extended — Impact Mapping Deep Dive

**Programs with explicit impact lists:**

HackerOne programs typically state:
- "Critical: Account takeover without user interaction"
- "High: Access to sensitive user PII"
- "Medium: Information disclosure of non-sensitive data"
- "Low: Best practice violations"

Map your finding to the program's EXACT wording:

```
Your finding: "Can read user email via IDOR"
Program definition for HIGH: "Unauthorized access to PII including email, phone, address"

Verdict: HIGH — match

Your finding: "Can read user's avatar URL"
Program definition for MEDIUM: "Access to user profile data"
Program does NOT mention avatar URL specifically
Verdict: MEDIUM at best — or INFORMATIVE if avatar is non-sensitive

Your finding: "CSRF on email change"
Program definition for HIGH: "Account takeover via CSRF"
CSRF on email change is 1 step from ATO
Verdict: MEDIUM or HIGH depending on program's definition
```

---

### Q3 Extended — Asset Verification

**Automated scope verification:**

```bash
# For each subdomain in scope, verify resolution
for sub in api admin cdn staging dev; do
  host="${sub}.target.com"
  ip=$(dig +short $host | head -1)
  echo "$host → $ip"
  
  # Check if IP is in listed CIDR range
  # Verify SSL certificate matches domain
done

# For IP ranges in scope, verify alive hosts:
nmap -sn 1.2.3.0/24
```

**Scope violation vectors (subtle):**
- CDN domains serving target.com content (OUT OF SCOPE unless wildcard includes them)
- OAuth provider domains that happen to serve target's clients (usually OUT OF SCOPE)
- API gateway domains for target's vendors (OUT OF SCOPE unless vendor integration is the bug)

---

### Q4 Extended — Privilege Reality Check

**Attack path privilege analysis matrix:**

| Starting privilege | Target data | Realistic? |
|---|---|---|
| Anonymous | Any user PII | Depends — if auth bypass exists YES |
| Free registered account | Other users' PII | YES — standard IDOR scenario |
| Free registered account | Admin endpoints | NO unless auth bypass proven |
| Free registered account | Cloud metadata (SSRF) | YES |
| User A (regular) | User B's data (regular) | YES — read IDOR |
| User A (regular) | User B's payment data | YES if different sensitivity class |
| User A (regular) | User A's own data (role escalation) | Only if can USE escalated role |
| Admin account | Admin-only data | NO — this is expected behavior |

**Privilege escalation proof requirements:**
- Must show: Session A reads data from Session C (admin) that Session A couldn't access as Session B (low-priv)
- NOT enough: Session A gets role change that doesn't unlock new endpoints

---

### Q5 Expanded — Comprehensive Search Procedure

**Platform-specific search techniques:**

HackerOne Hacktivity (detailed):
```
1. https://hackerone.com/hacktivity?filter=type=disclosed&program=target
2. Use browser Ctrl+F for keywords:
   - Endpoint paths: "/api/users/" 
   - Bug types: "IDOR" "SSRF" "XSS"
   - Parameters: "userId" "password" "email"
3. Click "Load more" to see older reports
4. Read FULL reports, not just titles
5. Check "Closed as Informative" — these show what program rejected
```

GitHub (detailed):
```
1. https://github.com/target/repo/issues?q=security
2. https://github.com/target/repo/security/advisories
3. Search GHSA (GitHub Security Advisory) in NVD:
   https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=target
4. Check COMMITS for security patches:
   git log --all --grep="security" --grep="fix" --grep="vuln"
```

Google Dorks (comprehensive):
```
site:hackerone.com "target.com" "critical"
site:hackerone.com "target.com" "IDOR" "bypass"
site:hackerone.com "target.com" "admin" "access"
site:bugcrowd.com "target" "disclosed"
site:intigriti.com "target" "responsible disclosure"
site:medium.com "@researcher" "target" "bug bounty"
site:github.com "target" "released" "security"
site:youtube.com "target" "bug bounty"
```

---

### Q6 Expanded — Proof Requirement by Bug Class

**Complete proof threshold table:**

| Bug Class | Minimum Proof | Preferred Proof | Chain Proof |
|---|---|---|---|
| XSS (stored) | Payload executes in shared context | Cookie/identity theft captured | ATO via stolen session |
| XSS (reflected) | Payload displays in response | Executes in browser | CSRF or credential theft |
| XSS (DOM) | sink location documented | Actual execution proven | Full chain to impact |
| SQLi (error) | SQL error in response | Data extracted | Full DB access |
| SQLi (blind) | Time/Boolean differences proven | Actual data extracted | Table names + data |
| IDOR | Other user's data in response | Admin/sensitive data accessed | ATO via IDOR chain |
| SSRF | Internal service reached | Real secrets extracted | Cloud compromise |
| CSRF | State change from attacker origin | Unauthorized action on victim account | Full ATO |
| Race | Consistent parallel success shown | Financial/membership impact | Double-spend proven |
| JWT none | Forged token accepted | Privileged endpoint accessible | Admin access |
| Open redirect | Redirect to attacker-controlled domain | OAuth code theft demonstrated | ATO |
| Auth bypass | Access without valid token | Admin-only response returned | Full admin panel access |

---

## CVSS 3.1 EXTENDED REFERENCE

### Complete CVSS Vector Breakdown

**Scope (S) interpretation for bug bounty:**

Scope = Unchanged (U): The vulnerable component and impacted component are the same.
- IDOR on API: API is both vulnerable and impacted → S:U
- XSS on profile page: Browser is impacted alongside app → S:C
- SSRF to cloud: Cloud environment impacted alongside the app → S:C
- Auth bypass: Same system, just wrong auth → S:U

**Temporal score adjustments:**

Base CVSS is a starting point. Adjust for:
- Exploit availability (PoC published = higher severity)
- Remediation complexity (widespread deployment = more urgent)
- Attack vector (remote = more severe than local)

**Temporal scoring guidance:**
```
CVSS v3.1 Temporal Formula:
TemporalScore = RoundUp(BaseScore × [Exploitability×RemediationLevel×ReportConfidence])

For bug bounty:
- Exploitability: 0.95 (easy) to 0.85 (difficult)
- Remediation Level: 0.95 (official fix available) to 1.00 (no fix)
- Report Confidence: 0.95 (confirmed) to 0.90 (reasonably sure)

Example: Base 7.5 × 0.95 × 0.95 × 0.95 ≈ 7.1 (round up to 7.5 for High)
```

---

## SEVERITY DECISION GUIDE (Extended)

### When to upgrade or downgrade severity

**Downgrade triggers:**
1. Victim interaction is extremely unlikely (multi-step social engineering)
2. Requires specific version/config of client software
3. Only works on outdated browser versions
4. Requires physical proximity (Bluetooth, NFC, local network)
5. Impact requires chaining with separate vuln that isn't proven

**Upgrade triggers:**
1. Mass-scale impact (all 10M+ users affected, not just 1,000)
2. Financial institution compliance implications (PCI DSS, SOX)
3. Health data exposure (HIPAA tier breach)
4. Government/military data involved
5. High-profile target (reputational impact amplifies severity)
6. Used in active attacks (threat intelligence value)

### Severity reasoning template (enhanced)

```markdown
SEVERITY: HIGH
CVSS: 8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L)

BASE FACTORS:
- Network exploitable: Yes
- Low complexity: Single HTTP request
- Low privilege: Any authenticated user
- No victim interaction: None required
- Scope unchanged: Same system
- Confidentiality HIGH: Full PII exposure

TEMPORAL ADJUSTMENTS:
- Proof-of-concept: Confirmed, PoC provided
- Remediation status: Unpatched, fix-able in middleware
- Report confidence: High (3+ independent reproductions)

PROGRAM-SPECIFIC FACTORS:
- Program scope: HIGH for "PII read without authorization"
- User count: 50,000 stored payment methods affected
- Data sensitivity: Payment last-4, type, billing address

REAL-WORLD CONTEXT:
- Combined with user enumeration → targeted phishing
- Combined with password pattern → credential stuffing
- PCI DSS scope: Stored payment data falls under PCI compliance
```

---

## EXTENDED ANTI-PATTERNS

### Anti-pattern: The "Potential" Finding

```
BAD: "The application may be vulnerable to SQL injection..."
GOOD: "SQL injection confirmed via UNION-based extraction..."

Rule: Remove ALL uncertain language. If you're not sure, test more.
"No public proof" = "I haven't tested thoroughly enough."
```

### Anti-pattern: The Parameter Salad

```
BAD: "The id, user_id, account, and accountId parameters all return data..."
GOOD: One report per root cause. If GET /api/user/{id}, PUT /api/user/{id},
and POST /api/user/{id} all have the SAME missing authorization check,
ONE report covering all three methods is correct.

If GET has one auth check and PUT has a DIFFERENT auth check,
two reports (two different root causes) is correct.
```

### Anti-pattern: The Severity Gamble

```
BAD: Submit as Critical hoping triager will settle at High 
GOOD: Submit at the severity you can PROVE with evidence
Reasoning: A legitimate Critical gets approved faster than a gambling Critical.
A downgrade from High → Medium still pays. N/A pays nothing.
```

---

## FINAL TRIAGE RULES (Extended)

9. **The 2-minute rule** — if you can't answer Q1 in 2 minutes, the finding is weak.
10. **The impact-first rule** — know the impact BEFORE writing the report. Write the title last.
11. **The evidence-while-hot rule** — capture evidence during discovery, not after you forget the test steps.
12. **The compare-before-submit rule** — re-read your report as if you're the triager. Would YOU approve it?
13. **The one-finding-per-root-cause rule** — multiple endpoints with same mechanism = one report.
14. **The version-check rule** — if the disclosed bug says "fixed in v2.1," test whether YOUR target is updated before declaring duplicate.
15. **The scope-affects-everything rule** — an out-of-scope asset makes the ENTIRE finding out of scope.
16. **The double-check-everything rule** — before submitting, verify: (a) in-scope hostname, (b) fresh evidence, (c) no claimed fix, (d) true impact.
17. **The chain-proves-each-link rule** — a 3-link chain requires proof for each link, not just the start and end.
18. **The program-rules-supersede rule** — if the program says "we don't pay for XSS without session theft," self-XSS findings are dead regardless of CVSS score.

---

## BUG-CLASS-SPECIFIC TRIAGE DEEP DIVES

### IDOR/BOLA Triage Checklist

```
REQUIRED EVIDENCE:
[ ] Two distinct test accounts (Session A, Session B)
[ ] Session A request to own resource: shows A's data
[ ] Session A request to B's resource: shows B's data OR shows B's data alongside A's
[ ] Session B request to B's resource: confirms B can access same data legitimately
[ ] Response body comparison: proves data is actually B's, not A's

COMMON IDOR DEATH SIGNS:
[ ] App returns current user's data regardless of ID parameter → users/me aliasing → KILL
[ ] Response is 200 with no body → missing evidence → KILL until body diff proven
[ ] App returns 404 for non-existent IDs but 200 for any existing ID → data scoping, not leak
[ ] UUID is deterministic (base64(userId)) → enumeration is IDOR, but severity is usually LOWER
[ ] App uses sequential IDs but enforces ownership via hash in response → check carefully

SEVERITY CALIBRATION FOR IDOR:
- Read own PII (name, email): LOW-INFORMATIVE
- Read other user's PII (name, email, address): MEDIUM
- Read other user's financial data: HIGH
- Read other user's payment data (card last-4): HIGH
- Admin data read via IDOR: CRITICAL
- Write IDOR (change victim's data): escalate one level
- Delete IDOR: escalate one level above write
```

### XSS Triage Checklist

```
STORED XSS VALIDATION:
[ ] Payload stored in database or persistent storage
[ ] Payload retrieved and rendered on page load
[ ] Page is viewable by users OTHER than the attacker
[ ] Execution context confirmed (HTML body, attribute, JS, etc.)
[ ] No sanitization bypass required (payload works as-is)

COMMON XSS DEATH SIGNS:
[ ] Payload appears in response as HTML-escaped string → not executed → KILL
[ ] Payload executes ONLY on attacker's own profile → self-XSS → KILL unless chained
[ ] Payload requires admin to view AND admin doesn't view that field → KILL
[ ] CSP present and blocks inline scripts → check if bypass exists before claiming
[ ] React/Vue escaping escapes by default → need specific sink (dangerouslySetInnerHTML)

CONTEXT ASSESSMENT:
- HTML body context: <div>[PAYLOAD]</div> → standard reflected/stored
- Attribute context: <div title="[PAYLOAD]"> → need " to break out
- JavaScript context: <script>var x = '[PAYLOAD]';</script> → need ' to break
- URL context: <a href="[PAYLOAD]"> → need javascript: URI scheme
- CSS context: <style>body { background: url([PAYLOAD]); }</style>

SEVERITY BY CONTEXT AND TRIGGER:
- Stored XSS on homepage/landing page viewed by all: HIGH-CRITICAL
- Stored XSS in comments on article with 1M views: HIGH
- Stored XSS in profile bio (anyone views): MEDIUM-HIGH
- Stored XSS in own profile only: LOW/N/A (self-XSS)
- Reflected XSS in search results: MEDIUM (if popular search, HIGH)
- Reflected XSS in rarely-visited error page: LOW-INFORMATIVE
- DOM XSS with #fragment: depends on sink, usually MEDIUM
```

### SSRF Triage Checklist

```
SSRF VALIDATION:
[ ] Request from attacker reaches internal/service host
[ ] Response contains data NOT available from public internet
[ ] Service is actually running at the internal address
[ ] Response is from the internal service, not a localhost redirect

COMMON SSRF DEATH SIGNS:
[ ] DNS-only callback: only sees DNS resolution, no actual data → INFORMATIVE
[ ] 127.0.0.1 redirects to 404 page: 200 on 127.0.0.1 but body is generic → KILL
[ ] Server returns same response for all URLs → policy, not oracle → Q6 kills
[ ] Cloud metadata returns 200 but body is empty → probably CDN/WAF → KILL

PROOF REQUIREMENTS:
MINIMUM: Internal endpoint reachable, body contains something not on public internet
PREFERRED: Body contains real secrets (AWS keys, Redis keys, JWT tokens, config data)
CHAIN: SSRF → metadata → AWS creds → real S3 data read

CLOUD METADATA VALIDATION:
→ Check AWS: 169.254.169.254/latest/meta-data/iam/security-credentials/
→ Check Azure: 169.254.169.254/metadata/instance?api-version=2021-02-01
→ Check GCP: 169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
→ Check DigitalOcean: 169.254.169.254/metadata/v1.json

SEVERITY CALIBRATION:
- SSRF to localhost/admin panel: MEDIUM
- SSRF to cloud metadata returning creds: CRITICAL
- SSRF to internal database returning data: HIGH
- SSRF to Redis returning session data: HIGH-CRITICAL
```

### SQL Injection Triage Checklist

```
SQLi VALIDATION:
[ ] Error-based: SQL syntax error visible in response
[ ] Boolean-based: TRUE/FALSE responses differ from baseline
[ ] Time-based: Measurable delay (5s+) with SLEEP/WAITFOR
[ ] Union-based: Data from other table visible in response

COMMON SQLi DEATH SIGNS:
[ ] SQL syntax error BUT no data extractable → informative only → KILL
[ ] Error only on invalid input → expected behavior, not SQLi → KILL
[ ] Same error for all inputs → not SQL injection → KILL
[ ] Error is from WAF, not database → WAF artifact, not vuln → KILL

PROOF PROGRESSION:
Level 1: Error message confirms SQL parsing → INFORMATIVE
Level 2: Boolean/union shows data structure → LOW-MEDIUM
Level 3: Extracted real table data (users table, version, etc.) → MEDIUM-HIGH
Level 4: Extracted sensitive data (passwords, PII, financial) → HIGH-CRITICAL
Level 5: Full DB access or RCE via SQLi → CRITICAL

BLIND SQLi TIMING THRESHOLDS:
Baseline: <100ms (typical)
SLEEP 5 payload: 5000ms ± 500ms (5 seconds)
Bypass if: payload response ≥ 4500ms consistently (n≥10)
Kill if: responses overlap with baseline (network jitter)
```

### CSRF Triage Checklist

```
CSRF VALIDATION:
[ ] Sensitive action performed (password change, email change, fund transfer)
[ ] Attack hosted on attacker-controlled domain (attacker.com)
[ ] Victim authenticated to target.com during attack
[ ] State change occurs WITHOUT victim explicitly clicking "confirm"
[ ] CSRF token is NOT required OR token is predictable/static

COMMON CSRF DEATH SIGNS:
[ ] Requires victim to click a link → that's GET, not meaningful CSRF → KILL (unless sensitive GET)
[ ] Login CSRF → usually not impactful unless you chain it → KILL alone
[ ] Logout CSRF → minor nuisance, not security issue → KILL
[ ] Action requires CAPTCHA that CSRF can't bypass → KILL

SEVERITY BY ACTION:
- CSRF password change → HIGH (potential ATO)
- CSRF email change → HIGH (ATO via password reset)
- CSRF fund transfer → HIGH
- CSRF account deletion → MEDIUM-HIGH
- CSRF comment/rating change → LOW-MEDIUM
- CSRF profile update (non-email) → LOW-MEDIUM

CHAIN OPPORTUNITIES:
Standalone CSRF → KILL or LOW
CSRF + stored XSS on same comment field → attacker's comment auto-XSSes admin → HIGH
CSRF + SSRF on parameter → attacker forces victim's browser to trigger SSRF → HIGH-CRITICAL
CSRF to change email → then reset password → ATO → CRITICAL chain
```

### Race Condition Triage Checklist

```
RACE VALIDATION:
[ ] Operation is NOT idempotent (doing it twice ≠ doing it once)
[ ] Parallel requests succeed where sequential would fail
[ ] Server has NO internal locking mechanism
[ ] State is modified in a way that should prevent duplicates

COMMON RACE DEATH SIGNS:
[ ] Request succeeds because cache was cleared → not a race → KILL
[ ] App intentionally allows some duplicates (eventual consistency) → check if this is designed
[ ] All parallel requests fail → no race condition → KILL
[ ] 1 of 20 requests succeeds → could be retry, not race → investigate more

PROOF REQUIREMENTS:
MINIMUM: 20+ parallel requests, at least 2 succeed with unique outcomes
PREFERRED: Show unique transaction IDs, unique coupon uses, or balance changes
BEST: Financial/membership gain demonstrated

SAMPLE SIZE CALCULATION:
- Race condition detection: n ≥ 20 concurrent requests
- Minimum successful rate to confirm: ≥ 30% (6/20)
- Run 5 trials; if consistent pattern → real race
- Document request timing (all sent within 100ms window)
```

---

## ENGAGEMENT-SCALE TRIAGE WORKFLOWS

### Hour-by-Hour Triage Cadence

```
ENGAGEMENT DAY STRUCTURE:

Hour 1-2: Initial recon candidates
→ Triage each candidate through Q1-Q8
→ Kill obvious false positives aggressively
→ Document survivors for further testing

Hour 3-4: Deep testing on top candidates
→ For each surviving candidate, attempt exploitation
→ Capture evidence for all successful reproductions
→ Run Gates 1-3 on confirmed findings

Hour 5-6: Chain exploration
→ Can any single findings be chained?
→ Does chain improve severity?
→ Capture chain evidence

End of Day 1: First submission batch
→ Submit highest-confidence findings
→ Retract any that are marginal
→ Update triage log with outcomes

Day 2+: Iterate
→ Re-run triage on new candidates
→ Fix and resubmit any reasonable rejections
→ Continue testing new attack surfaces
```

### Candidate Log Format

Maintain a running log during engagement:

```markdown
## Candidate Log

| # | Time | Signal | Q1-Q8 Result | Gate Result | Status | Notes |
|---|---|---|---|---|---|---|
| 1 | 10:15 | GET /api/users/1 returns 456's email | Passed | Pending | Testing | Cross-verify account state |
| 2 | 10:45 | XSS in search reflected | Passed | Gate 1 fail | KILLED | Self-XSS only, no victim context |
| 3 | 11:30 | SSRF to 169.254 returns 200 | Passed | Gate 1 fail | KILLED | Body empty - CDN response |
| 4 | 12:00 | Chain: IDOR + password reset | Passed | Pending | Submitting | ATO chain, 3-step PoC |

### Triage velocity benchmarks:
- Week 1: ~10-20 candidates/hour with practice
- 7Q gate execution: 2-3 minutes per candidate
- Retraction learning: Update death-signal list after each rejection
```

### Finding Quality Scoring System

Assign yourself a quality score for each submitted finding:

```
SCORING RUBRIC (out of 10 points):

Q1 Reproducibility (2 pts):
  2: Request copy-paste ready in <2 min
  1: Works but requires looking at notes
  0: Can't reproduce from scratch

Q6 Proof (2 pts):
  2: Impact clearly demonstrated with real data
  1: Impact shown but generic
  0: No concrete impact proof

Q8 Identity (2 pts):
  2: Cross-identity reproduction confirmed
  1: Single identity but reasoned
  0: Only tested on one account without checking

Evidence (2 pts):
  2: Screenshot + request/response + video
  1: Request/response in text only
  0: No evidence captured

Report Quality (2 pts):
  2: Copy-paste steps, quantified impact, specific remediation
  1: Most steps present, some gaps
  0: Needs significant work

SCORE INTERPRETATION:
7-10: Submit immediately
5-6: Minor improvements needed, submit
3-4: Needs work before submission
1-2: Significant gaps, re-test
0: Kill and move on

TRACKING:
Average your last 20 submission quality scores.
Target: >7.0 average over 20 submissions.
```

---

## ADVANCED TRIAGE SCENARIOS

### Scenario: The "Almost Dup"

```
SITUATION: Disclosure found that's 90% matching your finding
Difference: Your finding includes one additional parameter attack vector

DECISION TREE:
1. Is the core root cause IDENTICAL? → Same missing auth check?
   YES → Is YOUR additional parameter a genuinely separate code path?
         YES → Submit with clear differentiation note
         NO  → This is the same bug; don't resubmit
   NO  → Different root cause → Submit both

2. Does the disclosed report's FIX address your vector?
   YES → Same fix, same bug → KILL
   NO  → Different code path, different bug → Submit

3. Is your additional vector a side-effect of the same root cause?
   Example: Disclosed reports GET /api/users/123
            Your PUT /api/users/123 uses the same authorize() function
   Verdict: Same root cause. One report covering both methods.
```

### Scenario: The Regressed Bug

```
SITUATION: Bug was fixed, now it works again

EVIDENCE REQUIRED:
1. Link to original disclosure (URL + date)
2. Version where it was fixed
3. Version where it regressed (if known)
4. Current reproduction proof

SUBMISSION TEXT:
"Finding regressed from previously disclosed #12345.
Original: Fixed in v2.1.0 on 2023-06-15.
Current: Re-tested on v2.3.1 and the same IDOR on
GET /api/users/{id} is present. Root cause appears to be
a refactor in PR #789 that removed the userId ownership
check from the getUserById method.
New PoC and screenshots attached."

PROGRAM REACTION TYPICALLY:
- Most programs pay for regressions (confirm via program rules)
- Some require explicit "regression" label in title
- High-quality regression reports get faster approval
```

### Scenario: The Chained Duplicate

```
SITUATION: Disclosed report has primitive A. You have primitive A + B chain.

QUESTION: Is the chain genuinely new?

CHECKLIST:
[ ] Read FULL disclosed report — not just the title
[ ] Does the disclosed report mention the chained impact?
    YES → Same finding, don't resubmit
    NO  → New finding, submit with reference
[ ] Does the chain require a DIFFERENT endpoint, parameter, or bug class?
    YES → Different root cause chain → Submit
    NO  → Same chain shape → Proceed carefully, reference disclosure
[ ] Is your chain MORE impactful than the disclosed primitive alone?
    YES → Justifies separate report (some programs prefer this)
    NO  → Consider adding to existing disclosure as update

FORMAT FOR CHAIN SUBMISSION:
Title: [Primitive A] + [Primitive B] on [Endpoint] allows [Actor] to [Impact]

Body:
"Primitive A is disclosed in #12345 (researcher, date).
This report covers the additional impact achievable by chaining
A with B [describe B]. The combined impact is [C] vs the
originally reported [A] impact."

RESULT: New finding, separate payout, reference to prior.
```

---

## RETRACTION AND CORRECTION PROCEDURES

### Pre-Submission Self-Correction

Before you click "Submit", run this self-check:

```markdown
## Self-Correction Checklist

1. Re-read the report as if you're a triager seeing this for the first time.
2. Can you reproduce EXACTLY what you described?
3. Is there any language you would downgrade if you read it?
4. Does the impact section leave you wanting more detail?
5. Is the remediation advice actually useful?
6. Would you pay a bounty for this report?
```

If any answer is weak, fix it before submitting.

### Post-Submission Correction Process

If you discover an error AFTER submitting:

```
IMMEDIATELY:
1. Comment on your own report with "EDIT: [correction]"
2. Do NOT create a new report for the same finding
3. Do NOT delete and resubmit

CORRECTION FORMAT:
```
EDIT (2025-01-15 14:30): Initial reproduction used test account
ID 123. Re-tested with fresh account ID 456 and confirmed
same behavior. Updated request to use ID 456.
```

FOR SIGNIFICANT ERRORS:
If severity claim was wrong, and triager hasn't acted yet:
Comment asking triager to review severity before processing.

If triager already processed, and triage was wrong:
Reply to triager response, ask for re-evaluation with new evidence.

DO NOT:
- Dispute triager decisions aggressively
- Threaten public disclosure
- Resubmit as new finding for same vuln
```

### Attestation Statements for Reports

Include this in reports where applicable:

```markdown
## Attestations

- [ ] I have verified all actions are within program scope
- [ ] I have used test accounts for this engagement
- [ ] I have not accessed data belonging to real users beyond
      what was needed to confirm the vulnerability
- [ ] I have read and agree to the program's safe harbor provisions
- [ ] I have redacted all tokens/credentials from this submission
- [ ] I confirm this is original work and not previously disclosed

Timestamp: 2025-01-15T10:30:00Z
Researcher: [Name]
Engagement: [Program name]
Session ID: [BBHUNT_SESSION_ID hash]
```

---

## TRIAGE FRAMEWORK SUMMARY

The complete triage framework in one view:

```
ENGAGEMENT START:
1. Read scope page → record all in-scope assets
2. Read program rules → note exclusions, restrictions
3. Read disclosed reports → know what's already found
4. Set up evidence capture (Burp, Logger++, screenshots)

DURING TESTING:
1. Every candidate signal → run Q1 first (2 min)
2. Q1 passes → run Q2-Q3 (5 min)
3. Q1-Q3 pass → run Q4-Q6 (5 min)
4. Q1-Q6 pass → run Q7-Q8 (3 min)
5. All pass → run Gates 1-3 (20 min)
6. Gate 3 pass → draft report
7. Gate 3 fail → fix report issues

SUBMISSION:
1. Run 60-second checklist
2. Submit
3. Respond to triager comments promptly
4. Track quality score

POST-ENGAGEMENT:
1. Review which gates caught issues
2. Update your false-positive hunter log
3. Note missing vuln classes to study
4. Improve evidence capture workflow
```

---

## FINAL WORDS ON TRIAGE PHILOSOPHY

Triage is not about being skeptical. Triage is about being YOUR OWN harshest critic before the triager has to be.

```
The researcher who submits 5 high-quality findings every week 
beats the researcher who submits 30 low-quality findings monthly.

Why?
- Faster approval on fewer reports
- Better triager relationship → faster future reviews
- Higher payout per hour invested
- Cleaner track record for private programs
- More time spent on deep, impactful vulnerabilities

The ratio that matters: VALID_SUBMISSIONS / TOTAL_TESTING_HOURS

A 50% validity rate means half your time was wasted.
A 90% validity rate means your time is well-invested.
The 7-Question Gate gets you from 50% to 90%.
```

The goal is not to "pass triage" — the goal is to find good bugs, prove them well, and make the internet safer while getting paid for it.
