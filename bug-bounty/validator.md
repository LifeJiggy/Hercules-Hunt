---
name: validator
description: Bug bounty finding validation specialist. Runs the 7-Question Gate, 4 pre-submission gates, CVSS verification, deduplication checks, and always-rejected list filtering. Determines if a finding is a real, in-scope, payable bug or should be killed. Includes validation workflows, decision trees, duplicate check strategies, and quality scoring. Use when: validating findings before reporting, triaging potential bugs, checking if something is in scope, calculating real impact, or deciding whether to submit. Chinese trigger: 验证、检查漏洞、7-Question Gate、重复检查、漏洞评估、提交前检查
---

# Skill: Validator

The gatekeeper. Kills weak findings before you waste time writing reports.

## Core Principle

> **"Can an attacker do this RIGHT NOW against a real user who has taken NO unusual actions -- and does it cause real harm (stolen money, leaked PII, account takeover, code execution)?"**
>
> If the answer is NO -- STOP. Do not write. Do not explore further. Move on.

---

## The 7-Question Gate (Run BEFORE Writing ANY Report)

All 7 must be YES. Any NO -> KILL THE FINDING.

### Q1: Can I exploit this RIGHT NOW with a real PoC?

**Gate:** Write the exact HTTP request. If you cannot produce a working request -> KILL IT.

**Validation Steps:**
1. Write the exact request (method, path, headers, body)
2. Execute it against the live target
3. Does it return the expected vulnerable response?
4. Can you do it 3 times in a row (not just once)?

**Kill Signals:**
- "It should work based on the code" (you didn't test it)
- "Sometimes it works" (not reproducible)
- "I haven't actually sent the request yet" (you're not done)
- Requires 5+ steps to reproduce and you've only done 2

**Pass Criteria:**
```
[ ] Exact request written with all headers
[ ] Request executed against live target
[ ] Expected vulnerable response received
[ ] Reproduced 3 consecutive times
[ ] Screenshot/evidence captured
```

### Q2: Does it affect a REAL user who took NO unusual actions?

**Gate:** No "the user would need to..." with 5 preconditions. Victim did nothing special.

**Validation Steps:**
1. Describe the victim: who are they? (free user, paid user, admin, unauthenticated visitor)
2. What did the victim do? (logged in, viewed a page, clicked a link)
3. What did the victim NOT do? (no developer tools, no special settings, no prior knowledge)
4. Is this a normal user flow?

**Kill Signals:**
- "User would need to have admin enabled" (unless admin is the default)
- "User would need to click a malicious link from attacker" (unless stored XSS)
- "User would need to disable security features" (not a real bug)
- "User would need to be on an old browser" (not a real bug)
- "User would need to install a malicious extension" (not in scope usually)

**Pass Criteria:**
```
[ ] Victim is a normal user (free account minimum)
[ ] Victim's only action is normal app usage
[ ] No security features need to be disabled
[ ] No special browser/OS/device required
[ ] Attack works from default browser state
```

### Q3: Is the impact concrete (money, PII, ATO, RCE)?

**Gate:** "Technically possible" is not impact. "I read victim's SSN" is impact.

**Validation Steps:**
1. State the exact harm: what data/access/money does the attacker gain?
2. Can you quantify it? (N users, $ amount, data type)
3. Is it more than "see non-sensitive data"?
4. Is there a real victim (another user, the company)?

**Impact Levels:**

| Impact Level | Example | Submit? |
|--------------|---------|---------|
| Concrete | "Read 500 users' SSNs and card numbers" | YES |
| Concrete | "Create admin accounts, full platform takeover" | YES |
| Concrete | "Steal AWS credentials, access 200K user records" | YES |
| Vague | "May lead to information disclosure" | NO |
| Vague | "Could potentially be used in an attack" | NO |
| Theoretical | "If combined with another bug..." | NO (build the chain first) |
| Informational | "Missing security header" | NO (unless chained) |

**Kill Signals:**
- "Could theoretically allow..."
- "Might lead to..."
- "Potentially could be used..."
- "Depending on configuration..."
- "If an attacker also has..."

**Pass Criteria:**
```
[ ] Exact harm stated in one sentence
[ ] Can quantify: N users, $ amount, or data type named
[ ] Real victim identified (not hypothetical)
[ ] Impact is more than "non-sensitive data exposure"
[ ] No "could" or "might" or "potentially" in impact statement
```

### Q4: Is this in scope per the program policy?

**Gate:** Check the exact domain/endpoint against the program's scope page.

**Validation Steps:**
1. Get the program's scope list (HackerOne: program page → Scope)
2. Check the exact domain: is `target.com` in scope? What about `*.target.com`?
3. Check subdomains: are `staging.target.com`, `dev.target.com` in scope?
4. Check specific exclusions: "out of scope: production payment processing"
5. Check API endpoints: are `api.target.com` and `api.v2.target.com` covered?

**Common Scope Patterns:**

| Pattern | Means |
|---------|-------|
| `*.target.com` | All subdomains included |
| `target.com` | Only root domain |
| `api.target.com` | Only API subdomain |
| `target.com/*` | All paths on target.com |
| `Staging` or `Testing` | Often excluded or lower bounty |
| `Production payment processing` | Often excluded due to PCI compliance |

**Kill Signals:**
- Domain not in scope list
- Subdomain explicitly excluded
- Asset type excluded (e.g., "no mobile apps")
- Bug class explicitly out of scope (e.g., "no clickjacking")
- Program is closed / not accepting reports

**Pass Criteria:**
```
[ ] Exact domain matches scope list
[ ] Subdomain is included (check wildcards)
[ ] Asset type is in scope (web app, API, mobile)
[ ] Bug class is not excluded
[ ] Program is actively accepting reports
```

### Q5: Did I check Hacktivity/changelog for duplicates?

**Gate:** Search the program's disclosed reports and recent changelog entries.

**Validation Steps:**
1. Search HackerOne Hacktivity for program: similar bug titles, same endpoint
2. Search program's own changelog/blog for "security fix" or "bug bounty"
3. Search GitHub issues for target repo
4. Read the 5 most recent disclosed reports for this program
5. Check if your bug is a known issue already fixed

**Duplicate Detection:**

| Finding | Action |
|---------|--------|
| Exact same bug (same endpoint, same vuln) | DO NOT SUBMIT — duplicate |
| Same vuln class, different endpoint | Submit — different bug |
| Same endpoint, different vuln class | Submit — different bug |
| Same vuln, better impact proof | Consider submitting with note |
| Disclosed but no fix confirmed | Submit — may be unfixed |

**Kill Signals:**
- Identical bug already disclosed on Hacktivity
- Bug fixed in last 30 days changelog
- Program explicitly said "known issue, won't fix"
- Same researcher already reported it (check report IDs)

**Pass Criteria:**
```
[ ] Searched Hacktivity (program page, filter by vuln class)
[ ] Searched program changelog/blog
[ ] Searched GitHub issues/repos
[ ] Read 5 most recent disclosed reports
[ ] Confirmed this is not a known/duplicate issue
```

### Q6: Is this NOT on the "always rejected" list?

**Gate:** Check the list below. If it's there and you can't chain it -> KILL IT.

**Always Rejected (Don't Submit These):**

| Finding | Why Rejected | Can Chain? |
|---------|-------------|------------|
| Missing CSP | Too low severity alone | + XSS = YES |
| Missing HSTS | Too low severity alone | + MITM = rarely |
| Missing SPF/DKIM/DMARC | Email spoofing, not in-scope usually | Rarely |
| GraphQL introspection alone | Informational only | + field-level auth bypass = YES |
| Banner/version disclosure | No working CVE exploit | Never |
| Clickjacking on non-sensitive pages | No real impact | + sensitive action = YES |
| Tabnabbing | Theoretical, requires victim action | Rarely |
| CSV injection | Requires victim opens in Excel | Rarely |
| CORS wildcard without credential exfil | No proof of data theft | + credentialed exfil = YES |
| Logout CSRF | Minimal impact | + session fixation = rarely |
| Self-XSS | Requires victim to self-inject | Never |
| Open redirect alone | Needs ATO or OAuth chain | + OAuth = YES |
| OAuth client_secret in mobile app | Known limitation | Never |
| SSRF DNS-ping only | No internal access proof | + internal service = YES |
| Host header injection alone | Needs password reset or other chain | + reset poisoning = YES |
| No rate limit on non-critical forms | No brute-force path | + OTP/brute-force = YES |
| Session not invalidated on logout | Low severity alone | + session theft = rarely |
| Concurrent sessions allowed | Not a vulnerability | Never |
| Internal IP disclosure (own IP) | No internal access | Never |
| Mixed content (HTTP on HTTPS page) | No exploitation path | + MITM = rarely |
| SSL weak ciphers | Server config, no PoC | Never |
| Missing HttpOnly/Secure alone | Flag, not exploitable | + XSS = rarely |
| Broken external links | Not a security issue | Never |
| Pre-account takeover | Usually not in scope | Rarely |
| Autocomplete on password fields | UI issue, not security | Never |

**Chainable Findings (Low Alone, High With Chain):**

| Low Finding | + Chain | = Valid Bug |
|-------------|---------|-------------|
| Open redirect | + OAuth code theft | ATO |
| Clickjacking | + sensitive action + PoC | Account action |
| CORS wildcard | + credentialed exfil | Data theft |
| CSRF | + sensitive state change | ATO |
| No rate limit | + OTP brute force | ATO |
| SSRF (DNS only) | + internal access proof | Internal network access |
| Host header injection | + password reset poisoning | ATO |
| Self-XSS | + login CSRF | Stored XSS on victim |

**Pass Criteria:**
```
[ ] Finding is NOT on "Always Rejected" list
[ ] If on "Conditionally Valid" list, have a working chain
[ ] Chain produces concrete impact (not theoretical)
[ ] Chain is tested end-to-end (not just two separate bugs)
```

### Q7: Would a triager reading this say "yes, that's a real bug"?

**Gate:** Read your report as if you're a tired triager at 5pm on a Friday. Does it pass?

**Triager Psychology:**
- Triagers read 50+ reports/day. They skim.
- If they can't understand the bug in 30 seconds -> rejected or delayed
- If the PoC is unclear -> "needs more info" -> you lose time
- If impact is vague -> downgraded or rejected
- If it looks like a known issue -> duplicate closed

**Self-Check Questions:**
1. Can I explain this bug to a non-technical manager in 2 sentences?
2. Would a developer reading this know exactly what to fix?
3. Is the PoC copy-pasteable without my explanation?
4. Would I pay money for this if I were the company?
5. Am I 100% sure this is a real bug (not theoretical)?

**Kill Signals:**
- You can't explain it simply -> you don't understand it well enough
- You're unsure if it's a real bug -> it probably isn't
- The PoC requires "first do X, then Y, then maybe Z" -> too complex or not real
- You're excited because "it might be something" -> it's probably nothing

**Pass Criteria:**
```
[ ] Can explain bug to non-technical person in 2 sentences
[ ] Developer knows exactly what to fix from the report
[ ] PoC is copy-pasteable without additional explanation
[ ] You'd pay a bounty for this if you were the company
[ ] 100% confidence this is a real, exploitable bug
```

---

## 4 Pre-Submission Gates (Detailed)

### Gate 0: Reality Check (30 seconds)

```
[ ] The bug is real -- confirmed with actual HTTP requests, not just code reading
[ ] The bug is in scope -- checked program scope explicitly
[ ] I can reproduce it from scratch (not just once)
[ ] I have evidence (screenshot, response, video)
```

**How to Verify:**
1. Open a fresh incognito window
2. Follow your own Steps to Reproduce exactly
3. Does it work? If no -> you didn't prove it

### Gate 1: Impact Validation (2 minutes)

```
[ ] I can answer: "What can an attacker DO that they couldn't before?"
[ ] The answer is more than "see non-sensitive data"
[ ] There's a real victim: another user's data, company's data, financial loss
[ ] I'm not relying on the user doing something unlikely
```

**Impact Validation Tree:**

```
Does the bug allow...
├── Reading other users' data?
│   ├── PII (name, email, phone, SSN, address) → VALID
│   ├── Financial (card, bank, transaction) → VALID
│   ├── Health data → VALID
│   ├── Messages/communications → VALID
│   └── Non-sensitive (preferences, public profile) → KILL
├── Modifying other users' data?
│   ├── Changing password/email → VALID (ATO path)
│   ├── Deleting data → VALID
│   ├── Modifying orders/transactions → VALID
│   └── Changing own preferences via other's ID → VALID
├── Privilege escalation?
│   ├── User → admin → VALID
│   ├── Free → paid features → VALID
│   └── Read-only → write access → VALID
├── Server-side actions?
│   ├── SSRF to internal service → VALID
│   ├── SSRF to cloud metadata → VALID
│   ├── RCE → VALID
│   └── DNS-only callback → KILL (unless internal access proven)
└── Client-side actions?
    ├── Stored XSS in sensitive context → VALID
    ├── Stored XSS in admin panel → VALID
    ├── Reflected XSS (self) → KILL
    └── XSS requiring unusual user action → KILL
```

### Gate 2: Deduplication Check (5 minutes)

```
[ ] Searched HackerOne Hacktivity for this program + similar bug title
[ ] Searched GitHub issues for target repo
[ ] Read the most recent 5 disclosed reports for this program
[ ] This is not a "known issue" in their changelog or public docs
```

**Deduplication Strategy:**

1. **HackerOne Hacktivity Search:**
   ```
   URL: https://hackerone.com/hacktivity?filter=type:team&team=PROGRAM_HANDLE
   Look for: same endpoint, similar vuln class, recent reports
   Sort by: newest first (last 6 months most relevant)
   ```

2. **Program Scope Page:**
   ```
   Check: "Fixed" section, "Known Issues" section
   Look for: similar bug titles, same feature area
   ```

3. **Google Dorks for Duplicates:**
   ```
   site:hackerone.com "target.com" "IDOR"
   site:hackerone.com "target.com" "SSRF"
   site:github.com "target" "security" "fix"
   ```

4. **Changelog/Release Notes:**
   ```
   curl https://target.com/changelog | grep -i "security\|fix\|vulnerability"
   git log --oneline | grep -i "security\|CVE\|fix" | head -20
   ```

### Gate 3: Report Quality (10 minutes)

```
[ ] Title: One sentence, contains vuln class + location + impact
[ ] Steps to Reproduce: Copy-pasteable HTTP request
[ ] Evidence: Screenshot/video showing actual impact (not just 200 response)
[ ] Severity: Matches CVSS 3.1 score AND program's severity definitions
[ ] Remediation: 1-2 sentences of concrete fix
```

**Quality Checklist:**

| Element | Requirement | Common Failure |
|---------|-------------|----------------|
| Title | Vuln class + endpoint + impact | "Security bug found" |
| Summary | Impact-first, 3 sentences | "I found a vuln in..." |
| Steps | Exact HTTP requests | "I sent a request..." |
| Evidence | Screenshot + response body | Just "I got data" |
| Impact | Quantified, concrete | "May lead to issues" |
| CVSS | Vector + score + justification | Just a number |
| Fix | Specific to this bug | "Fix your code" |

---

## Validation Decision Tree

```
FINDING DETECTED
       │
       ▼
  Q1: PoC ready?
  ┌─── NO ───┐
  │  KILL     │
  └───────────┘
       │ YES
       ▼
  Q2: Real user, no unusual actions?
  ┌─── NO ───┐
  │  KILL     │
  └───────────┘
       │ YES
       ▼
  Q3: Concrete impact?
  ┌─── NO ───┐
  │  KILL     │
  └───────────┘
       │ YES
       ▼
  Q4: In scope?
  ┌─── NO ───┐
  │  KILL     │
  └───────────┘
       │ YES
       ▼
  Q5: Not a duplicate?
  ┌─── YES ──┐
  │  KILL     │
  └───────────┘
       │ NO
       ▼
  Q6: Not always rejected?
  ┌─── YES ──┐
  │  KILL     │
  └───────────┘
       │ NO
       ▼
  Q7: Triager would say "real bug"?
  ┌─── NO ───┐
  │  KILL     │
  └───────────┘
       │ YES
       ▼
  SUBMIT
```

---

## Always Rejected List (Complete)

**Never submit these:**

1. **Missing security headers alone**
   - Missing CSP, HSTS, X-Frame-Options, X-XSS-Protection
   - These are flags, not exploitable bugs
   - Exception: CSP missing AND XSS found → report the XSS, mention CSP gap

2. **GraphQL introspection alone**
   - Introspection enabled = informational
   - Chain: introspection + missing field-level auth = valid

3. **Banner/version disclosure**
   - Server: Apache/2.4.41 = not a bug
   - Only if combined with a working CVE exploit

4. **Clickjacking on non-sensitive pages**
   - Login page clickjacking = low
   - Admin panel clickjacking with PoC = higher
   - Need to show actual damage (CSRF to sensitive action)

5. **Tabnabbing / reverse tabnabbing**
   - Theoretical, requires victim to switch tabs and click
   - Not considered exploitable by most programs

6. **CSV injection**
   - Requires victim to open exported CSV in Excel
   - Rarely in scope, often requires social engineering

7. **CORS wildcard without proof**
   - `Access-Control-Allow-Origin: *` alone = not a bug
   - Chain: wildcard + `credentials: true` + exfil PoC = valid

8. **Logout CSRF**
   - Minimal impact (annoyance, not data loss)
   - Chain: logout CSRF + session fixation = higher

9. **Self-XSS**
   - Attacker attacks themselves = no bug
   - Exception: if attacker can trick victim into running it (not self-XSS then)

10. **Open redirect alone**
    - `?next=` to attacker.com = not a bug
    - Chain: open redirect in OAuth flow = valid

11. **OAuth client_secret in mobile app**
    - Known limitation, impossible to fully protect
    - Most programs explicitly exclude this

12. **SSRF with DNS-only callback**
    - Need to prove internal access, not just DNS resolution
    - Chain: DNS SSRF + internal service access = valid

13. **Host header injection alone**
    - Need to prove password reset poisoning or cache poisoning
    - Chain: host header + reset link sent to attacker = valid

14. **No rate limit on non-critical endpoints**
    - Only valid if there's a brute-force path (login, OTP, reset)
    - Rate limit on search = not a bug

15. **Session not invalidated on logout**
    - Low severity, often accepted as informational
    - Chain: session reuse after logout + hijack = rarely paid

16. **Concurrent sessions allowed**
    - Not a security vulnerability
    - Some programs accept with low severity

17. **Internal IP disclosure (own IP)**
    - `X-Forwarded-For` showing your own IP = not a bug
    - Internal IP of server = medium (recon only)

18. **Mixed content warnings**
    - HTTP resource on HTTPS page = flag
    - Chain: mixed content + MITM = rarely paid

19. **SSL/TLS configuration issues**
    - Weak ciphers, old TLS versions
    - Usually infrastructure, not application scope

20. **Missing cookie flags alone**
    - Missing HttpOnly/Secure/on HTTP = flag
    - Chain: missing HttpOnly + XSS = mention in XSS report

21. **Broken external links**
    - Not a security issue
    - Never submit

22. **Pre-account takeover**
    - Before account exists, can reserve username/email
    - Most programs exclude this

23. **Autocomplete on password fields**
    - UI/UX issue, not security
    - Never submit

---

## CVSS Validation

### Common CVSS Mistakes

| Mistake | Example | Correct |
|---------|---------|---------|
| Overclaiming Scope | S:C when impact is only in app | S:U unless cloud/multi-system |
| Wrong AV | AV:L for remote web bug | AV:N |
| Wrong PR | PR:N for authenticated bug | PR:L |
| Wrong UI | UI:N for XSS requiring click | UI:R |
| Inflated Impact | C:H for reading one user's name | C:L for limited PII |

### CVSS Validation Checklist

```
[ ] AV:N for remotely exploitable web bugs
[ ] AV:L only if attacker needs local access (rare for web)
[ ] AC:L unless race condition or specific timing needed
[ ] PR:L for authenticated user (free account = low privilege)
[ ] PR:N only for truly unauthenticated bugs
[ ] PR:H only if needs admin/privileged account
[ ] UI:R if victim must click/view something
[ ] UI:N if server-side only (SSRF, SQLi)
[ ] S:U if impact limited to the app
[ ] S:C if cloud metadata, SSRF to internal, multi-system impact
[ ] C:H for full data breach / PII dump
[ ] C:L for partial/limited data access
[ ] I:H for full data modification / admin access
[ ] I:L for limited modification (own data only → no vuln)
[ ] A:H for complete DoS
[ ] A:L for partial degradation
```

### CVSS Examples with Justification

**IDOR (read own invoice):**
```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N = 5.3 Medium
Justification: Network exploitable, low complexity, needs basic account,
no user interaction, scope unchanged (just invoices), low confidentiality impact
```

**IDOR (read all invoices, PII):**
```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 7.5 High
Justification: Full PII exposure (names, addresses, amounts), all users affected
```

**SSRF (cloud metadata, IAM creds):**
```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H = 9.1 Critical
Justification: Scope changed (cloud service), IAM creds = full AWS access,
confidentiality + integrity + availability all high
```

**Stored XSS (admin panel):**
```
CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H = 8.8 High
Justification: Admin session hijack = full platform access, user interaction
required (admin must view page), scope unchanged but impact high
```

---

## Duplicate Detection Strategy

### Step-by-Step Dedup Process

**1. Search HackerOne Hacktivity:**
```
Go to: https://hackerone.com/hacktivity?filter=type%3Ateam&team=PROGRAM_HANDLE
Sort by: newest first
Look for: same endpoint path, same vuln class, similar title
Time window: last 12 months most relevant
```

**2. Search Program's Disclosed Reports:**
```
curl -s "https://hackerone.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{
      team(handle: \"PROGRAM\") {
        name
        hacktivity_items(first: 50, order_by: {field: popular, direction: DESC}) {
          nodes {
            ... on HacktivityDocument {
              report { title severity_rating }
            }
          }
        }
      }
    }"
  }' | jq '.data.team.hacktivity_items.nodes[].report'
```

**3. Search Program's Changelog:**
```
curl -s https://target.com/changelog | grep -i "security\|fix\|vulnerability\|bug"
curl -s https://target.com/releases | grep -i "security\|patch"
```

**4. Check GitHub Issues:**
```
Search: site:github.com/target-org/repo "security" "vulnerability"
Check: Closed issues with "security" label
Look for: same component/endpoint fixed recently
```

**5. Google Dorks:**
```
site:hackerone.com "target.com" "IDOR"
site:hackerone.com "target.com" "SSRF" "metadata"
site:bugcrowd.com "target" "security"
```

### Duplicate Decision Matrix

| Scenario | Decision |
|----------|----------|
| Exact same bug, same endpoint, same impact | DO NOT SUBMIT |
| Same vuln class, different endpoint | Submit (different bug) |
| Same endpoint, different vuln class | Submit (different bug) |
| Same vuln, different impact chain | Submit (different impact) |
| Same vuln, better/different PoC | Submit with note |
| Bug fixed but no disclosure | Submit (if not in scope policy exclusion) |
| Duplicate from same researcher | Accept duplicate, move on |
| Partial duplicate (different parameter) | Submit (different parameter = different bug) |

---

## Quality Scoring System

Score your finding 0-100 before submitting:

### Scoring Criteria

| Criteria | Points | Notes |
|----------|--------|-------|
| PoC is exact, copy-pasteable | 20 | Full HTTP request with headers |
| Two accounts tested | 15 | Attacker + victim, cross-user proof |
| Impact quantified | 15 | N users, $ amount, data type |
| Impact is concrete (not theoretical) | 15 | Specific harm, not "could" |
| In scope (verified) | 10 | Explicitly checked program scope |
| Not a duplicate | 10 | Searched Hacktivity, changelog |
| Not always rejected | 10 | Not on kill list |
| CVSS calculated correctly | 5 | Vector matches impact |
| **Total** | **100** | **70+ = submit, <70 = fix or kill** |

### Score Interpretation

| Score | Action |
|-------|--------|
| 90-100 | Strong finding, submit immediately |
| 70-89 | Good finding, review weak points then submit |
| 50-69 | Borderline, can it be improved? |
| 30-49 | Likely weak, look for chain or kill |
| 0-29 | Kill, move on |

### Common Score Deductions

| Issue | Deduction | Fix |
|-------|-----------|-----|
| No PoC | -30 | Write and test the request |
| Only one account | -15 | Create victim account, retest |
| Impact not quantified | -15 | Count users, identify data types |
| Theoretical impact | -15 | Prove it or drop it |
| Haven't checked scope | -10 | Check program scope page |
| Haven't checked duplicates | -10 | Search Hacktivity |
| On always-rejected list | -10 | Kill or find chain |
| Wrong CVSS | -5 | Recalculate |

---

## Scope Verification Guide

### HackerOne Scope Check

1. Go to program page: `https://hackerone.com/PROGRAM_HANDLE`
2. Click "Policy" or "Scope" tab
3. Check:
   - **In-scope domains:** exact matches and wildcards
   - **Out-of-scope domains:** anything explicitly excluded
   - **Asset types:** web application, API, mobile, etc.
   - **Bug classes:** some programs exclude XSS, SSRF, etc.
   - **Special rules:** "only production," "no DoS," etc.

### Common Scope Patterns

| Pattern | Example | Interpretation |
|---------|---------|----------------|
| `*.target.com` | All subdomains | dev.target.com IN SCOPE |
| `target.com` | Root only | app.target.com OUT OF SCOPE unless wildcard |
| `target.com/*` | All paths | Includes /api, /admin, etc. |
| `api.target.com` | API only | Web app at target.com may be excluded |
| `Staging` | Explicitly listed | Staging env in scope |
| `Production` | Explicitly listed | Only production, no staging |
| `*.target.com` excluding `*.target.com/admin` | Wildcard with exclusion | admin subdomain excluded |

### Scope Edge Cases

| Scenario | Decision |
|----------|----------|
| Subdomain with different IP | Check if in wildcard |
| Subdomain redirects to out-of-scope | Usually in scope if subdomain matches |
| API subdomain not in wildcard | Check if explicitly listed |
| Dev/staging environment | Often in scope, sometimes lower bounty |
| Third-party hosted assets | Usually out of scope unless specified |
| Mobile app endpoints | Check if API in scope |
| GraphQL endpoint | Check if API is in scope |

---

## Impact Validation Framework

### Impact Hierarchy (Highest to Lowest)

1. **RCE / Code Execution** — attacker runs arbitrary code on server
2. **Cloud Metadata / IAM Theft** — AWS/GCP/Azure credentials exposed
3. **Admin Takeover** — full administrative access
4. **ATO (Account Takeover)** — take over any user account
5. **Mass PII Exfiltration** — dump of user database
6. **Financial Theft** — steal money, credits, gift cards
7. **Business Logic Abuse** — free items, price manipulation, double-spend
8. **Data Modification** — modify other users' data
9. **Selective PII Read** — read specific users' sensitive data
10. **Internal Recon** — internal IPs, services, structure (low alone)

### Impact Quantification Guide

**Users Affected:**
- All users (unauthenticated bug) = highest impact
- All authenticated users = high impact
- Specific user segment = medium impact
- Single user = low impact (unless admin/sensitive)

**Data Sensitivity:**
- Financial (card, bank, transaction) = highest
- Identity (SSN, DOB, passport) = highest
- Health/medical = highest
- PII (email, phone, address) = high
- Business data (revenue, contracts) = high
- Non-sensitive (preferences, public data) = low

**Access Gained:**
- Admin panel = high
- Internal services = high
- Other users' data = high
- Own data only = no bug
- Public data = no bug

---

## Bug Chain Validation

When you think you have a chain, validate it end-to-end:

### Chain Validation Checklist

```
[ ] Step 1: Confirm Bug A works independently
[ ] Step 2: Confirm Bug B works independently
[ ] Step 3: Chain A→B in a single attack flow
[ ] Step 4: Prove the combined impact (not just A + B separately)
[ ] Step 5: Document the chain as ONE report
```

### Chain Quality Test

**Bad Chain (two separate bugs):**
- "I found SSRF and also XSS on the same target"
- These are independent findings, not a chain

**Good Chain (A enables B):**
- "SSRF on image import reaches Redis → Redis has session tokens → session tokens grant ATO"
- Bug A (SSRF) enables Bug B (ATO via session theft from Redis)

### Common Chain Patterns to Validate

| Chain | Validate By |
|-------|-------------|
| SSRF → cloud metadata | Prove IAM creds work, access real resource |
| SSRF → Redis/Mongo | Prove you can read/modify data in DB |
| XSS → session theft | Steal HttpOnly cookie via XSS |
| IDOR → write → admin | Read admin ID via IDOR, then modify admin data |
| Open redirect → OAuth | Full flow: redirect → auth code → token |
| CORS + credentials | Prove credentialed data exfil |
| Race → double spend | Show actual credit/money gained |

---

## The "Kill Fast" Rules

These patterns = instant kill. Don't waste time.

1. **"Could theoretically..."** → KILL
2. **"If combined with..."** → Build the chain first, THEN validate
3. **"Sometimes it works"** → Not reproducible = KILL
4. **"I haven't tested it on production"** → Test or KILL
5. **"It's in the code but I can't reach it"** → Dead code = KILL
6. **"Only affects my own account"** → Not cross-user = KILL (usually)
7. **"DNS callback only"** → Prove internal access or KILL
8. **"I found a key but haven't tested what it accesses"** → Not proven = KILL
9. **"It's a known issue in the changelog"** → Duplicate = KILL
10. **"Not in the program scope"** → Out of scope = KILL

---

## Responding to Validation Failures

### When Q1 Fails (No Working PoC)
- Go back to hunting
- You have a hypothesis, not a bug
- Document it as a "lead" not a "finding"

### When Q2 Fails (Requires Unusual Actions)
- Document the precondition count
- If > 2 preconditions → kill
- Exception: if the precondition is "has an account" → that's fine

### When Q3 Fails (No Concrete Impact)
- Ask: "What's the worst thing an attacker does?"
- If answer is "see some data" → how sensitive is it?
- If answer is "not much" → kill
- Try to chain: can this lead to something worse?

### When Q4 Fails (Out of Scope)
- Check if there's an in-scope equivalent
- E.g., api.v1.target.com out of scope, api.v2.target.com in scope
- If no in-scope version → kill, move to next target

### When Q5 Fails (Duplicate)
- Read the original report
- If truly the same → accept it, learn, move on
- If different impact or different bug class → submit with distinction

### When Q6 Fails (Always Rejected)
- Can you chain it to something valid?
- If no chain → kill
- Don't submit always-rejected findings hoping for an exception

### When Q7 Fails (Triager Test)
- Rewrite the report from scratch
- Focus on impact, not vuln class
- Show the PoC clearly
- If still can't explain simply → you don't have a real bug

---

## Validator Anti-Patterns

**DON'T:**
- Spend 30 minutes writing a report before running the 7-Question Gate
- Claim impact you didn't prove ("leads to RCE" when SSRF only)
- Submit borderline bugs hoping for a "nice triager"
- Ignore scope because "it's almost the same domain"
- Assume a bug is real because you saw it in the code
- Submit the same bug to multiple programs without checking each scope

**DO:**
- Run the 7-Question Gate immediately after finding a bug
- Test on production before writing anything
- Check scope FIRST before deep testing
- Check duplicates BEFORE deep testing
- Kill fast — move on to the next target quickly
- Document leads separately from confirmed findings

---

## Quick Validation Script

```python
#!/usr/bin/env python3
"""
Bug Bounty Validator — 7-Question Gate
Run this before writing ANY report.
"""

def validate_finding(finding):
    results = {}
    
    # Q1: PoC Ready
    results['q1_poc'] = all([
        finding.get('request_method'),
        finding.get('request_path'),
        finding.get('request_body') is not None,
        finding.get('response_shows_vuln'),
        finding.get('reproduced_times', 0) >= 3
    ])
    
    # Q2: Real User
    results['q2_real_user'] = all([
        not finding.get('requires_admin', False),
        not finding.get('requires_special_browser', False),
        not finding.get('requires_security_disable', False),
        finding.get('victim_action') in ['login', 'view_page', 'click_link', 'none']
    ])
    
    # Q3: Concrete Impact
    concrete_impacts = ['pii_read', 'data_modify', 'ato', 'rce', 'financial_theft', 'admin_takeover']
    results['q3_concrete'] = (
        finding.get('impact_type') in concrete_impacts and
        finding.get('impact_quantified') and
        'could' not in finding.get('impact_statement', '').lower()
    )
    
    # Q4: In Scope
    results['q4_scope'] = (
        finding.get('domain_in_scope') and
        not finding.get('in_scope_excluded') and
        finding.get('program_accepting', True)
    )
    
    # Q5: Not Duplicate
    results['q5_dedup'] = (
        not finding.get('is_duplicate') and
        not finding.get('in_changelog_fixed')
    )
    
    # Q6: Not Always Rejected
    always_rejected = ['missing_csp_alone', 'introspection_alone', 'banner_only', 'self_xss']
    results['q6_accepted'] = finding.get('vuln_class') not in always_rejected
    
    # Q7: Triager Test
    results['q7_triager'] = (
        len(finding.get('impact_statement', '').split()) < 50 and
        finding.get('confidence', 0) >= 90 and
        not finding.get('theoretical_aspects')
    )
    
    # Results
    all_pass = all(results.values())
    print("=" * 50)
    print("7-QUESTION GATE RESULTS")
    print("=" * 50)
    for q, passed in results.items():
        status = "PASS" if passed else "FAIL"
        print(f"{q}: {status}")
    print("=" * 50)
    print(f"OVERALL: {'SUBMIT' if all_pass else 'KILL'}")
    print("=" * 50)
    
    if not all_pass:
        failed = [q for q, p in results.items() if not p]
        print(f"\nFailed gates: {', '.join(failed)}")
        print("\nAction: Review failed gates before submitting.")
    
    return all_pass


# Example usage:
finding = {
    'request_method': 'GET',
    'request_path': '/api/invoices/123',
    'request_body': None,
    'response_shows_vuln': True,
    'reproduced_times': 5,
    'requires_admin': False,
    'requires_special_browser': False,
    'requires_security_disable': False,
    'victim_action': 'login',
    'impact_type': 'pii_read',
    'impact_quantified': True,
    'impact_statement': 'Read 500 users PII including SSNs and card numbers',
    'domain_in_scope': True,
    'in_scope_excluded': False,
    'program_accepting': True,
    'is_duplicate': False,
    'in_changelog_fixed': False,
    'vuln_class': 'idor',
    'confidence': 95,
    'theoretical_aspects': False
}

validate_finding(finding)
```

---

## Final Rule

> **If you cannot answer YES to all 7 questions, the finding is not ready. Go back, retest, find the real impact, or move on. N/As hurt your validity ratio. Only submit winners.**

The validator's job is to be ruthless. Every weak finding you submit damages your reputation with the program. Better to have 10 validated submissions with 80% acceptance than 50 submissions with 20% acceptance.

---

## Advanced Validation Techniques

### Dynamic Validation: Testing on Production

Before submitting ANY finding, verify it on production:

```
Step 1: Fresh Environment Test
  - Use incognito browser
  - Clear all cookies/cache
  - Register new test account
  - Follow your PoC steps exactly

Step 2: Cross-Environment Validation
  - If staging and prod differ, test BOTH
  - Some bugs only exist in production
  - Some bugs only exist in staging (not in scope)

Step 3: Consistency Check
  - Run the PoC 5 times
  - Does it work every time?
  - If intermittent → not a valid finding
```

### Blind Spot Detection

```
Common blind spots in validation:

1. "I tested with my own account" — Did you test with TWO accounts?
2. "I got a 200 response" — Does the response contain actual sensitive data?
3. "The API returned user data" — Whose data? Yours or someone else's?
4. "It works sometimes" — Intermittent bugs are not bugs
5. "I found it in the code" — Can you exploit it in production?
6. "Theoretically it should work" — Prove it or kill it
```

### False Positive Detection

```
Red flags indicating false positive:

1. Response is 200 but data is your own (not other user's)
2. Response contains empty values or nulls
3. Bug only works with specific edge case inputs
4. Bug requires admin token you obtained elsewhere
5. Bug works in staging but not production (different code)
6. Response timing suggests caching (not real data access)
7. Error messages suggest the endpoint doesn't exist/function
```

---

## Pre-Submission Deep Dive

### The Full Pre-Submission Checklist (Expanded)

```
PHASE 1: PoC Verification (5 minutes)
[ ] Can I reproduce this from a completely fresh state?
[ ] Have I tested it 5+ times consistently?
[ ] Does it work without Burp/modifications to the request?
[ ] Is the exact HTTP request copy-pasteable?
[ ] Are all required headers/parameters included?

PHASE 2: Impact Quantification (10 minutes)
[ ] Can I count affected records? (SELECT COUNT(*), API total)
[ ] Can I identify the data types? (PII, financial, health)
[ ] Can I demonstrate the worst-case scenario?
[ ] Is there a compliance angle? (GDPR, HIPAA, PCI-DSS)
[ ] Can I estimate financial impact? ($ per record × N records)

PHASE 3: Scope Verification (5 minutes)
[ ] Exact domain matches program scope
[ ] Subdomain wildcards checked
[ ] Asset type in scope (web, API, mobile)
[ ] Bug class not excluded by program
[ ] No out-of-scope systems accessed

PHASE 4: Duplicate Check (10 minutes)
[ ] Searched HackerOne Hacktivity (program page)
[ ] Searched program's disclosed reports
[ ] Searched program's changelog/blog
[ ] Searched GitHub issues for similar fixes
[ ] Read 5 most recent disclosed reports
[ ] This is not a variation of a known issue

PHASE 5: Quality Check (10 minutes)
[ ] Title follows formula: [Class] in [endpoint] allows [actor] to [impact]
[ ] First sentence states exact impact
[ ] Steps are copy-pasteable
[ ] Evidence is clear (screenshot + response)
[ ] Two accounts used (attacker + victim)
[ ] CVSS calculated correctly
[ ] Remediation is specific
[ ] Report under 500 words
[ ] No typos in endpoints/parameters
[ ] No theoretical language ("could", "might", "potentially")
```

---

## Scope Verification Deep Dive

### Complex Scope Scenarios

**Scenario 1: Wildcard Subdomains**
```
Program scope: *.target.com

Test:
- app.target.com → IN SCOPE
- api.target.com → IN SCOPE
- admin.target.com → IN SCOPE
- dev.target.com → IN SCOPE (if wildcard covers it)
- target.com (root) → CHECK: is root included?

Sometimes root domain is NOT included in *.target.com
Always verify the exact scope language.
```

**Scenario 2: Excluded Subdomains**
```
Program scope: *.target.com
Out of scope: *.target.com/admin, staging.target.com

Test:
- app.target.com → IN SCOPE
- admin.target.com → OUT OF SCOPE (explicitly excluded)
- admin-api.target.com → CHECK: is this "admin" subdomain?
- staging.target.com → OUT OF SCOPE

Ambiguous exclusions → email program for clarification
```

**Scenario 3: API vs Web App**
```
Program scope:
- In scope: https://target.com/*
- Out of scope: https://api.target.com/*

Bug in api.target.com found → OUT OF SCOPE
Check if there's a similar bug in target.com

Sometimes mobile API (api.target.com) is separate from web (target.com)
```

**Scenario 4: Third-Party Assets**
```
Program scope: target.com and subdomains
Bug found in: segment.com (analytics used by target.com)

→ Usually OUT OF SCOPE unless program explicitly includes third-party
→ Check program policy for "third-party services" clause
```

---

## Impact Validation Framework (Expanded)

### Impact Scoring Matrix

| Factor | Points | Your Finding |
|--------|--------|--------------|
| Data type: Financial | +40 | Card numbers, bank accounts, transactions |
| Data type: Identity | +35 | SSN, DOB, passport, driver's license |
| Data type: Health | +35 | Medical records, prescriptions, diagnoses |
| Data type: PII | +25 | Email, phone, address |
| Data type: Credentials | +30 | Passwords, API keys, tokens |
| Data type: Business | +20 | Revenue data, contracts, strategies |
| Scale: All users | +30 | Unauthenticated access |
| Scale: All authenticated | +20 | Any logged-in user |
| Scale: Segment | +10 | Specific user type |
| Scale: Single user | +5 | Only one victim |
| Action: RCE | +50 | Code execution on server |
| Action: Admin takeover | +45 | Full platform control |
| Action: Data exfil | +35 | Mass data extraction |
| Action: ATO | +35 | Take over any account |
| Action: Data modification | +25 | Modify other users' data |
| Action: Data read | +15 | Read other users' data |
| **Maximum** | **200** | **Critical** |
| **Threshold** | **70+** | **Submit** |

### Impact Calculation Examples

```
Example 1: IDOR on invoices
Data type: Financial (40) + PII (25) = 65
Scale: All authenticated (20) = 85
Action: Read (15) = 100
→ SCORE: 100 → High impact → SUBMIT

Example 2: Open redirect alone
Data type: N/A (0)
Scale: All users (30)
Action: Redirect (5) = 35
→ SCORE: 35 → Low → KILL (or chain)

Example 3: SSRF → cloud metadata
Data type: Credentials (30) + All data types accessible
Scale: All users (20)
Action: RCE/Admin (50) = 100+
→ SCORE: 100+ → Critical → SUBMIT

Example 4: Stored XSS in admin
Data type: Admin access (45)
Scale: Admin viewers (15)
Action: ATO via admin (35) = 95
→ SCORE: 95 → Critical → SUBMIT
```

---

## Duplicate Detection Deep Dive

### Hacktivity Search Strategy

```
Step 1: Direct search
URL: https://hackerone.com/hacktivity?filter=type%3Ateam&team=PROGRAM
Look for: Same endpoint path, similar vuln class, recent date

Step 2: GraphQL query for program reports
curl -s "https://hackerone.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{
      team(handle: \"PROGRAM\") {
        name
        hacktivity_items(first: 50, order_by: {field: popular, direction: DESC}) {
          nodes {
            ... on HacktivityDocument {
              report { 
                title 
                severity_rating 
                disclosed_at 
              }
            }
          }
        }
      }
    }"
  }' | jq '.data.team.hacktivity_items.nodes[].report'

Step 3: Analyze each disclosed report
- Same endpoint? → Likely duplicate
- Same vuln class? → Check if different impact
- Same timeframe? → Bug may be recently fixed
- Similar title? → Compare actual bugs
```

### Disclosed Report Analysis Template

```
For each disclosed report in the program:

Report: [Title]
Date: [Disclosed date]
Severity: [Rating]

Analysis:
- Bug class: [IDOR/SSRF/XSS/etc]
- Affected endpoint: [path]
- Impact: [what they demonstrated]
- Is my bug the same? [Yes/No/Similar]

If Same:
  → DO NOT SUBMIT (duplicate)
  
If Similar but Different:
  → Document the difference clearly
  → Submit with "This is distinct from #X because..."
  
If Different:
  → Safe to submit
```

---

## Chain Validation Deep Dive

### Validating End-to-End Chains

```
CHAIN VALIDATION CHECKLIST:

Bug A Verification:
[ ] Bug A works independently
[ ] Have exact PoC for Bug A
[ ] Bug A impact is confirmed

Bug B Verification:
[ ] Bug B works independently
[ ] Have exact PoC for Bug B
[ ] Bug B impact is confirmed

Chain A→B Verification:
[ ] Bug A actually enables Bug B (not just adjacent)
[ ] Can demonstrate full chain in one flow
[ ] Chain produces impact beyond A+B separately
[ ] No manual intervention between A and B

Chain Documentation:
[ ] Document chain as ONE report (not two)
[ ] Title reflects the chain
[ ] Steps show the complete chain
[ ] Impact reflects combined effect
```

### Chain Quality Examples

```
BAD CHAIN (two unrelated bugs):
"I found SSRF on endpoint X and XSS on endpoint Y"
→ Submit as TWO separate reports

BAD CHAIN (theoretical connection):
"SSRF could reach Redis which might have sessions"
→ Prove it: actually access Redis, actually extract sessions

GOOD CHAIN (proven connection):
"SSRF on PUT /api/avatar reaches Redis at 127.0.0.1:6379. 
Redis contains session tokens. Extracted admin session token 
and accessed /admin panel. Full chain demonstrated end-to-end."

GOOD CHAIN (business impact):
"IDOR on /api/transactions/{id} reveals transaction amounts.
Combined with no rate limit on /api/refund, attacker can:
1. Enumerate all transaction IDs via IDOR
2. Issue refunds for each transaction
3. Steal funds from all users"
```

---

## Edge Case Handling

### When You're Unsure

```
1. Can you prove it works on production? If no → KILL
2. Can you explain it to a developer? If no → study more
3. Can you quantify the impact? If no → find the impact
4. Have you checked for duplicates? If no → check first
5. Would you pay $X for this bug? If no → it's not worth reporting
```

### When the Program Disagrees

```
They say "Not a bug":
- Re-read your own report objectively
- Ask: "What am I missing?"
- If you genuinely disagree, respond once with evidence
- If they still disagree → move on. N/As hurt your ratio

They downgrade severity:
- Pick ONE strongest counter-argument
- Cite similar disclosed reports
- Keep response under 150 words
- If they still disagree → accept and move on

They duplicate your report:
- Check if they're actually right
- If different bug → explain the distinction
- If truly duplicate → accept, learn, move on
```

### When You Find Multiple Bugs

```
Same target, same bug class, different endpoints:
→ One report listing all affected endpoints
→ Example: "IDOR in 12 invoice endpoints"

Same target, different bug classes:
→ Separate reports (one per bug class)
→ Exception: if chained → one chain report

Same bug across multiple programs:
→ Check scope of EACH program
→ Adjust PoC for each program's specific endpoints
→ Don't blindly submit same report everywhere
```

---

## Validation Metrics

### Track Your Validation Stats

```
Weekly metrics to track:
- Total findings: X
- Submitted: Y
- Accepted: Z
- Duplicate: A
- Not a bug: B
- Informational: C
- Acceptance rate: Z/Y × 100%

Target metrics:
- Acceptance rate > 60% (top hunters: 70-80%)
- Duplicate rate < 15%
- N/A rate < 10%

If acceptance rate < 50%:
→ You're not running the 7-Question Gate
→ Spend more time validating before writing
→ Kill weaker findings before submitting

If duplicate rate > 20%:
→ Not checking Hacktivity thoroughly enough
→ Review search strategy
→ Check more disclosed reports before hunting
```

---

## Advanced Duplicate Detection

### Beyond Hacktivity

```
Sources to check for duplicates:

1. Program's own security page
   curl https://target.com/security | grep -i "fixed\|resolved\|patched"

2. Program's blog/changelog
   curl https://target.com/blog | grep -i "security\|fix\|vulnerability"
   curl https://target.com/changelog | grep -i "security\|fix"

3. GitHub commits
   git log --oneline | grep -i "security\|fix\|vuln\|CVE"
   Look for: Fix security issue in /api/...

4. CVE databases
   https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=target
   https://nvd.nist.gov/vuln/search

5. Twitter/LinkedIn
   Search: "target.com bug bounty" "fixed" "hackerone"
   Security researchers often tweet about fixes

6. Wayback Machine
   Check if disclosed reports page was different in past
   https://web.archive.org/web/*/https://target.com/security
```

---

## Pre-Submission Automation

### Automated Pre-Submission Checker

```python
#!/usr/bin/env python3
"""
Automated pre-submission validation
"""
import json
import sys

class PreSubmitChecker:
    def __init__(self, report_path):
        self.report = self.load_report(report_path)
        self.issues = []
    
    def load_report(self, path):
        with open(path) as f:
            return f.read()
    
    def check_title(self):
        title = self.report.split('\n')[0]
        checks = [
            ('Class in endpoint', any(x in title.lower() for x in ['idor', 'ssrf', 'xss', 'sqli', 'race', 'bypass'])),
            ('Contains endpoint', '/' in title),
            ('Contains impact', any(x in title.lower() for x in ['allows', 'leads', 'exposes', 'grants'])),
        ]
        for name, passed in checks:
            if not passed:
                self.issues.append(f"Title missing: {name}")
    
    def check_impact(self):
        impact_section = self.report[re.search(r'## Impact', self.report).start():]
        weak_words = ['could', 'might', 'potentially', 'may', 'possibly', 'theoretically']
        for word in weak_words:
            if word in impact_section.lower():
                self.issues.append(f"Impact contains weak word: '{word}'")
    
    def check_quantification(self):
        # Check for numbers indicating scale
        has_numbers = bool(re.search(r'\d+[,.]?\d*\s*(users?|records?|accounts?)', self.report, re.I))
        if not has_numbers:
            self.issues.append("Impact not quantified (add N users/records)")
    
    def check_two_accounts(self):
        account_mentions = len(re.findall(r'(attacker|victim|user[ab]|account[12])', self.report, re.I))
        if account_mentions < 4:
            self.issues.append("May not use two distinct accounts (check PoC)")
    
    def check_http_requests(self):
        if 'HTTP/1.1' not in self.report:
            self.issues.append("No HTTP requests in report")
    
    def check_cvss(self):
        if 'CVSS' not in self.report and 'CVSS' not in self.report:
            self.issues.append("CVSS score missing")
        if 'AV:' not in self.report:
            self.issues.append("CVSS vector missing")
    
    def check_word_count(self):
        words = len(self.report.split())
        if words > 600:
            self.issues.append(f"Report too long ({words} words, target: <500)")
    
    def run_all_checks(self):
        self.check_title()
        self.check_impact()
        self.check_quantification()
        self.check_two_accounts()
        self.check_http_requests()
        self.check_cvss()
        self.check_word_count()
        
        if self.issues:
            print("ISSUES FOUND:")
            for issue in self.issues:
                print(f"  ❌ {issue}")
            print(f"\nFix {len(self.issues)} issues before submitting.")
            return False
        else:
            print("✅ All checks passed! Ready to submit.")
            return True

checker = PreSubmitChecker('report.md')
checker.run_all_checks()
```

---

## Final Rule

> **Validation is not a formality — it's the difference between paid and rejected. Run every check. Kill every weak finding. Only submit winners. Your validity ratio is your reputation.**
