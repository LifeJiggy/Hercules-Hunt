---
name: skill-report-writer
description: Bug bounty report writing specialist. Generates human-quality vulnerability reports for HackerOne, Bugcrowd, Intigriti, and private programs. Handles report structure, CVSS 3.1 calculation, impact statement writing, PoC documentation, severity escalation, submission checklists, and triager psychology. Includes templates for every major vuln class, human-tone rules, title formulas, and counter-arguments for severity downgrades. Use when: writing reports, preparing submissions, calculating CVSS, drafting impact statements, or responding to triager feedback. Chinese trigger: 写报告、漏洞报告、报告模板、CVSS、提交报告、影响陈述
---

# Skill: Report Writer

Turns a confirmed bug into a report that gets paid. Fast.

## Core Principle

Triagers read 50+ reports a day. Your report must be:
1. **Scannable** — triager understands the bug in 30 seconds
2. **Credible** — PoC is copy-pasteable, evidence is clear
3. **Impactful** — first sentence states the damage, not the vuln class
4. **Correct** — CVSS matches impact, severity matches business context

---

## The 60-Second Structure

```
[TITLE]          1 line    — vuln class + endpoint + impact
[SUMMARY]        3-4 lines — what, where, worst-case outcome
[STEPS]          numbered  — exact copy-pasteable HTTP requests
[EVIDENCE]       inline    — response bodies, screenshots, videos
[IMPACT]         2-3 lines — concrete harm to real users/company
[CVSS]           table     — all 3 metrics with justification
[REMEDIATION]    1-2 lines — specific fix, not generic advice
```

Total: under 400 words. Triagers skim. Long reports get rushed.

---

## Title Formula

```
[Vuln Class] in [Exact Endpoint/Feature] allows [attacker role] to [impact] [victim scope]
```

**Good:**
- `IDOR in /api/v2/invoices/{id} allows authenticated user to read any customer's invoice data`
- `Missing auth on POST /api/admin/users allows unauthenticated attacker to create admin accounts`
- `Stored XSS in profile bio executes in admin panel -- allows privilege escalation`
- `SSRF via image import URL reaches AWS EC2 metadata service`
- `Race condition in coupon redemption allows same code to be used unlimited times`

**Bad:**
- `IDOR vulnerability found` (no location, no impact)
- `Broken access control` (too vague)
- `XSS in user input` (no scope, no impact)
- `Security issue in API` (meaningless)

### Title Rules
- Start with vuln class (IDOR, SSRF, XSS, Auth Bypass, Race Condition...)
- Include exact endpoint or feature name
- State attacker role (unauthenticated, authenticated user, low-privilege user)
- State concrete impact (read PII, ATO, RCE, financial theft)
- Keep it under 120 characters

---

## Summary Writing (The First 3 Sentences)

The summary is the first thing triagers read. Get the impact OUT FIRST.

**Wrong:**
```
I discovered an IDOR vulnerability in the /api/v2/invoices endpoint.
The application fails to validate that the requesting user owns the invoice.
This allows an attacker to read other users' invoice data.
```

**Right:**
```
An authenticated user can read any customer's invoice -- including names, 
addresses, payment amounts, and partial card numbers -- by changing a single 
ID in the URL path. No special permissions are needed beyond a free account.
This affects every invoice in the system: roughly 50,000 records.
```

### Summary Rules
- Sentence 1: Who can do what to whom
- Sentence 2: How (one sentence, technical but readable)
- Sentence 3: Scope/scale (N users, $ value, data types)
- No jargon without explanation
- No "vulnerability was discovered" passive voice
- Write in active voice: "I found that..." or "An attacker can..."

---

## Steps to Reproduce

Each step must be copy-pasteable. No paraphrasing.

### Format

```
1. Log in as attacker (account: test-attacker@example.com / Pass123!)
2. Send the following request:
   
   GET /api/v2/invoices/4892 HTTP/1.1
   Host: target.com
   Authorization: Bearer eyJhbGciOi...
   Cookie: session=abc123...

3. Observe the response contains victim's full invoice data:
   
   {
     "id": 4892,
     "customer_name": "Jane Smith",
     "address": "123 Main St",
     "amount": "$4,200.00",
     "card_last4": "4242"
   }

4. Repeat with victim account (test-victim@example.com) and swap ID to victim's invoice ID.
   Attacker receives victim's data, confirming IDOR.
```

### Steps Rules
- Use exact HTTP requests with all headers
- Include full request and relevant response
- Test accounts clearly labeled (attacker vs victim)
- Show before/after or cross-account proof
- No screenshots as replacement for HTTP requests
- Keep each step to ONE action

---

## Evidence Requirements

### Minimum Evidence Per Bug Class

| Bug Class | Required Evidence |
|-----------|------------------|
| IDOR | Two requests: attacker ID returns own data, victim ID returns victim's data via attacker's account |
| SSRF | Request showing internal service response (not just DNS callback) |
| XSS | Screenshot of alert/payload execution in browser |
| Auth Bypass | Request to protected endpoint without auth returning 200 + data |
| Race Condition | Video or multi-request proof showing successful double-action |
| SQLi | Response showing data exfil or error revealing DB structure |
| SSRF (cloud metadata) | Response containing IAM credentials or internal config |

### Screenshot Rules
- Must show the URL bar (proves it's the real target)
- Must show the full impact (PII, admin panel, etc.)
- Annotate with arrows/circles on the relevant part
- Include request in Burp Suite history as backup

### Video Rules (for race conditions, multi-step)
- 30 seconds max
- Show browser or terminal clearly
- Narrate what's happening or use on-screen text
- Start from logged-out state, end showing the bug

---

## Impact Statement Formula

```
An [attacker access level] can [exact action] by [method], resulting in [concrete harm].
This requires [prerequisites] and affects [scope].
[Optional: financial/legal/compliance impact]
```

### Examples by Bug Class

**IDOR (PII read):**
```
An authenticated user can read any customer's invoice by changing a single ID 
in the URL. This requires only a free account and affects all ~50,000 invoices 
in the system, including names, addresses, and partial payment card numbers.
```

**SSRF (cloud metadata):**
```
An attacker with any account can make the server fetch its own IAM credentials 
from the EC2 metadata service. This requires no special privileges and gives 
access to AWS keys that allow reading S3 buckets containing 200,000 user records.
```

**Race condition (financial):**
```
An attacker can redeem the same promo code multiple times by sending 20 
simultaneous requests. Each successful redemption adds $20 store credit. 
We demonstrated $400 credit from a single code. Affects all promotional campaigns.
```

**Auth bypass:**
```
An unauthenticated attacker can create admin accounts by sending a single POST 
request to /api/admin/users. No authentication or special headers required. 
Grants full administrative access to the entire platform.
```

### Impact Rules
- Lead with the harm, not the vuln class
- Quantify whenever possible (N users, $ amount, data types)
- Name the specific data at risk (SSNs, card numbers, health records)
- Mention compliance implications if relevant (HIPAA, PCI-DSS, GDPR)
- Be honest — don't inflate, but don't understate either

---

## CVSS 3.1 Scoring

### Quick Score Reference

| Bug Class | AV | AC | PR | UI | S | C | I | A | Typical Score |
|-----------|-----|-----|-----|-----|---|---|---|---|---------------|
| Auth bypass -> admin | N | L | N | N | C | H | H | H | 9.8 Critical |
| SSRF (cloud metadata) | N | L | L | N | C | H | H | H | 9.1 Critical |
| JWT none algorithm | N | L | N | N | C | H | H | H | 9.1 Critical |
| SQLi (data exfil) | N | L | L | N | C | H | H | L | 8.6 High |
| GraphQL auth bypass | N | L | N | N | C | H | H | L | 8.7 High |
| IDOR (write/delete) | N | L | L | N | C | H | L | L | 7.5 High |
| Race (double spend) | N | H | L | N | U | L | L | L | 7.5 High |
| IDOR (read PII) | N | L | L | N | C | L | L | L | 6.5 Medium |
| Stored XSS (low) | N | L | R | R | U | L | L | N | 5.4 Medium |
| Stored XSS (admin) | N | L | N | N | C | L | L | N | 8.8 High |

### CVSS Vector Breakdown

**Attack Vector (AV):**
- Network (N): Exploited remotely (most web bugs)
- Adjacent (A): Same network segment (Bluetooth, local network)
- Local (L): Needs local access or user action
- Physical (P): Needs physical device access

**Attack Complexity (AC):**
- Low (L): No special conditions needed
- High (H): Needs specific race condition, user interaction timing, etc.

**Privileges Required (PR):**
- None (N): Unauthenticated
- Low (L): Basic user account needed
- High (H): Admin/privileged account needed

**User Interaction (UI):**
- None (N): Victim does nothing
- Required (R): Victim must click/view something

**Scope (S):**
- Unchanged (U): Impact only the vulnerable component
- Changed (C): Impact extends beyond the component (e.g., cloud access via SSRF)

**Confidentiality (C) / Integrity (I) / Availability (A):**
- High (H): Total loss of that CIA aspect for many resources
- Low (L): Partial loss or limited scope
- None (N): No impact on that aspect

### CVSS Calculation Example (SSRF -> Cloud Metadata)

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
= 9.1 Critical
```

Breakdown:
- AV:N — attacker sends HTTP request remotely
- AC:L — no special conditions
- PR:L — needs any user account (low privilege)
- UI:N — server-side only, no victim interaction
- S:C — cloud metadata service extends beyond app scope
- C:H — IAM credentials = full data access
- I:H — can use creds to modify cloud resources
- A:H — can spin up resources, delete data, cause DoS

---

## Report Templates by Vuln Class

### Template: IDOR

```
Title: IDOR in /api/v2/invoices/{id} allows authenticated user to read any customer's invoice data

Summary:
An authenticated user can access any other user's invoice by replacing the ID 
in the URL path. No authorization check validates that the invoice belongs to 
the requesting user. This exposes names, addresses, amounts, and card data.

Steps to Reproduce:
1. Log in as attacker: attacker@test.com / Pass123!
2. GET /api/v2/invoices/1001 → returns attacker's own invoice (baseline)
3. GET /api/v2/invoices/2002 → returns victim's full invoice data (proof)
4. Confirm with victim account: victim@test.com can access invoice 1001 (attacker's)

Supporting Material:
[Burp request: attacker requesting victim's invoice]
[Screenshot: victim invoice data returned to attacker session]

Impact:
Any authenticated user can enumerate and read all customer invoices. 
This includes PII (names, addresses) and financial data (amounts, card last4).
Affects ~50,000 invoices across all customers.

CVSS 3.1: 6.5 Medium
AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N

Remediation:
Add server-side ownership check: verify invoice.user_id == requesting_user.id 
before returning data. Apply to all endpoints in the invoices controller.
```

### Template: SSRF

```
Title: SSRF in profile picture URL import reaches AWS EC2 metadata service

Summary:
The "import profile picture from URL" feature at PUT /api/user/avatar 
fetches any user-supplied URL server-side. An attacker can supply the EC2 
metadata endpoint and receive the server's IAM credentials.

Steps to Reproduce:
1. Log in as any user
2. PUT /api/user/avatar
   Content-Type: application/json
   {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
3. Observe response contains IAM role credentials:
   {"AccessKeyId": "ASIA...", "SecretAccessKey": "...", "Token": "..."}
4. Use credentials to list S3 bucket: aws s3 ls s3://target-user-data/

Supporting Material:
[Request/response showing IAM creds]
[Screenshot of S3 bucket listing with user data]

Impact:
IAM credentials allow full access to AWS resources in this account. 
We confirmed read access to S3 buckets containing 200K user records.
Attacker can exfiltrate all user data, modify cloud resources, or pivot to other services.

CVSS 3.1: 9.1 Critical
AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

Remediation:
Restrict URL fetching to allowlist of image hosting domains. 
Block private/reserved IP ranges (RFC 1918, link-local, metadata) server-side.
```

### Template: Stored XSS

```
Title: Stored XSS in job title field executes in admin panel -- allows admin session hijacking

Summary:
The job title field on the profile page is stored and rendered without 
sanitization in the admin user management panel. An attacker sets their 
job title to an XSS payload, which executes when any admin views their profile.

Steps to Reproduce:
1. Log in as attacker
2. PUT /api/user/profile {"job_title": "<img src=x onerror=alert(document.cookie)>"}
3. Log in as admin: admin@target.com
4. Navigate to /admin/users → click attacker's profile
5. Observe: alert fires with admin's session cookie

Supporting Material:
[Screenshot: alert firing in admin panel showing session cookie]
[Request: attacker setting XSS payload]

Impact:
Admin session hijacking leads to full account takeover of administrative accounts.
With admin access, attacker can modify any user data, change permissions, 
access financial records, and pivot to internal systems.

CVSS 3.1: 8.8 High
AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H

Remediation:
Sanitize job_title on input using DOMPurify or framework-native sanitizer. 
Apply Output Encoding in admin panel (React's default JSX encoding is sufficient).
```

### Template: Race Condition

```
Title: Race condition in coupon redemption allows same code to be redeemed multiple times

Summary:
The coupon redemption endpoint checks code validity but deducts usage count 
in a separate database operation. By sending 20 simultaneous requests, an 
attacker can redeem the same code before the usage counter updates.

Steps to Reproduce:
1. Log in as attacker
2. Note coupon code: SAVE20 (gives $20 credit, 1 use per user)
3. Send 20 simultaneous POST requests to /api/coupons/redeem:
   
   POST /api/coupons/redeem HTTP/1.1
   Content-Type: application/json
   {"code": "SAVE20"}

   [Send via: seq 20 | xargs -P 20 -I {} curl -s -X POST ...]

4. Observe: 12 of 20 requests returned 200, adding $240 credit total
5. Normal redemption returns 200 once, then 403 for subsequent uses

Supporting Material:
[Video: 20 parallel requests, 12 successes]
[Response showing 12x $20 credits added]

Impact:
Attacker can extract unlimited store credit from single-use coupon codes.
For high-value promo codes ($100+ signup bonuses), this directly converts 
to cash. Affects all promotional campaigns.

CVSS 3.1: 7.5 High
AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L

Remediation:
Make coupon redemption atomic: check availability and mark as used in a 
single DB transaction with row-level locking. Or use Redis distributed lock.
```

### Template: Auth Bypass

```
Title: Missing authentication on POST /api/admin/users allows unauthenticated account creation

Summary:
The admin user creation endpoint does not require authentication or 
authorization. Any unauthenticated user can create accounts with arbitrary 
roles including admin.

Steps to Reproduce:
1. Without logging in, send:
   
   POST /api/admin/users HTTP/1.1
   Content-Type: application/json
   
   {
     "email": "attacker@evil.com",
     "password": "Pwned123!",
     "role": "admin"
   }

2. Observe: 201 Created, admin account created
3. Log in with attacker@evil.com / Pwned123! → full admin panel access

Supporting Material:
[Request/response showing admin creation without auth]
[Screenshot: attacker logged into admin panel]

Impact:
Unauthenticated attacker can create arbitrary admin accounts. Full platform 
takeover possible. All user data, financial records, and configuration 
accessible. Immediate critical severity.

CVSS 3.1: 9.8 Critical
AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

Remediation:
Add authentication middleware to all /api/admin/* routes. 
Add role authorization check: only existing admins can create admin accounts.
```

---

## Severity Escalation Counter-Arguments

When programs downgrade your severity, respond with these:

| They Say | You Counter |
|----------|-------------|
| "Requires authentication" | "Attacker needs only a free account — no paid tier, no special role, no approval process" |
| "Limited impact" | "Affects N users / exposes [PII type] / potential $X financial loss" |
| "Already known" | "Show me the report number — I searched Hacktivity and found no prior disclosure" |
| "By design" | "Show me the documentation stating this is intended behavior. No user would expect IDOR on invoices" |
| "Low CVSS" | "CVSS doesn't capture business impact. Attacker can steal [X] which has real-world consequences beyond the base score" |
| "Needs social engineering" | "The 'social engineering' is sending one HTTP request. No victim interaction beyond normal app usage" |
| "Only affects test data" | "Confirmed with live production data. [Attach screenshot of real user record]" |
| "Depends on internal network" | "SSRF from a user-facing endpoint reaches internal metadata service — no internal network access needed by attacker" |

### Escalation Rules
- Never get emotional
- Always cite specific evidence from your PoC
- Reference disclosed reports for similar bugs at the same program
- If they say "informational" — explain exactly what harm an attacker causes
- One counter-argument per response, not a wall of text

---

## Submission Checklist (60-Second Final Check)

```
[ ] Title: [Vuln Class] in [endpoint] allows [actor] to [impact]
[ ] First sentence states exact impact (not "a vulnerability exists")
[ ] Steps to Reproduce: copy-pasteable HTTP requests with all headers
[ ] Response showing the bug is pasted inline (not just "I got data")
[ ] Two accounts tested (attacker + victim, not one account testing itself)
[ ] CVSS calculated with vector string AND numeric score
[ ] Remediation: 1-2 sentences, specific to this bug (not "use prepared statements" for XSS)
[ ] No typos in endpoint paths or parameter names
[ ] Report under 500 words (triagers skim long reports)
[ ] Severity claimed matches impact described
[ ] Scope verified against program policy
[ ] No theoretical bugs ("could potentially" → KILL)
[ ] PoC works every time (not "sometimes it works")
```

---

## Responding to Triager Feedback

### When They Ask for More Information
- Respond within 24 hours
- Paste the exact additional request/response they need
- Don't send a wall of text — use bullet points
- If they need a video, record a 20-second screencast

### When They Downgrade Severity
- Pick ONE strongest counter-argument from the table above
- Cite a similar disclosed report if available
- Keep it under 150 words

### When They Say "Not a Bug" / "Won't Fix"
- Re-read your own report as if you didn't find it
- Ask: "If I'm wrong, what am I missing?"
- If you genuinely think they're wrong, respond once with evidence
- If they still disagree, move on. N/As hurt your ratio.

### When They Duplicate Your Report
- Check if they're right (same endpoint, same bug class)
- If different bug class or different impact, explain the distinction clearly
- If truly duplicate: accept it, learn from it, move on

---

## Platform-Specific Notes

### HackerOne
- Title max ~80 chars displayed in list view
- Use markdown — triagers and customers read it
- Attach Burp Suite export file (.json) if complex
- Severity field: match your CVSS score
- CWE number helps (add at bottom if relevant)

### Bugcrowd
- Severity: P1 (Critical) / P2 (High) / P3 (Medium) / P4 (Low) / P5 (Informational)
- Bug Type dropdown — pick the closest match
- Target: URL or component name
- Private programs often want POC video

### Intigriti
- CVSS 3.1 mandatory
- Impact statement required separately from description
- Pre-submission validation helps avoid rejection

---

## Common Report Mistakes That Kill Payouts

| Mistake | Why It Kills | Fix |
|---------|-------------|-----|
| "I found a vulnerability" | Passive voice, no impact | Start with "An attacker can..." |
| No HTTP requests | Can't verify the bug | Paste full requests with headers |
| "May lead to" | Theoretical | Prove it or drop it |
| Only one account | Can't prove cross-user impact | Always use two accounts |
| No response body | Can't see the data leaked | Paste the actual response |
| "Potentially serious" | Vague | State exact harm with numbers |
| 1000-word essay | Triagers skim and miss key info | Under 500 words |
| Wrong CVSS | Looks inexperienced | Use the table above |
| "I think this might be..." | Uncertain | Be confident or retest |
| Missing remediation | Shows you didn't think it through | Add one specific fix sentence |

---

## Impact Escalation Templates

When your finding gets downgraded and you need to escalate impact:

### IDOR: Medium → High
```
This IDOR allows read access to ALL customer records. I confirmed access to 
500+ accounts containing full names, emails, phone numbers, and billing addresses. 
With this data, an attacker can:
- Conduct targeted phishing campaigns against every customer
- Perform identity theft using the collected PII
- Map the customer base for competitive intelligence
The GDPR exposure (EU customer data) adds regulatory risk for the company.
```

### SSRF: Medium → Critical
```
This SSRF reaches the AWS metadata service and exposes IAM credentials. 
Using these credentials, I gained read access to 3 S3 buckets containing:
- 200,000 user records (email, name, phone, address)
- Financial transaction logs (amounts, dates, status)
- Internal API keys for payment processing
This is a direct path to full cloud account takeover.
```

### XSS: Medium → High
```
This stored XSS executes in the admin panel. I demonstrated session cookie 
theft from an admin account. With admin access, an attacker can:
- Modify any user account (including password resets)
- Access all platform financial data
- Change site-wide settings (add their own accounts, modify permissions)
The impact extends beyond XSS to full administrative takeover.
```

---

## Writing for Different Audiences

### For Technical Triagers
- Be precise with HTTP methods, paths, parameters
- Include exact payloads
- Mention framework details if relevant (Express, Django, etc.)
- Reference OWASP categories

### For Non-Technical Customers (Bugcrowd/Intigriti)
- Start with business impact
- Use analogies: "like a postal worker opening other people's mail"
- Quantify in business terms ($ risk, user count, compliance)
- Explain remediation in plain English too

### For Program Managers (escalation)
- Lead with the number: N users affected, $X at risk
- Mention compliance: HIPAA, PCI-DSS, GDPR exposure
- Reference similar CVEs or breaches
- Show worst-case scenario clearly

---

## Report Quality Self-Check

Before submitting, read your own report and answer:

1. **Can a triager reproduce this in 5 minutes?** (If no → add more detail)
2. **Does the first sentence state impact?** (If no → rewrite it)
3. **Is the scope quantified?** (If no → add N users, $ amounts, data types)
4. **Would a jury understand the harm?** (If no → simplify the impact statement)
5. **Is the fix obvious?** (If no → be more specific in remediation)
6. **Did I use two accounts?** (If no → retest properly)
7. **Is the CVSS justified?** (If no → recalculate with evidence)

---

## Bonus: PoC Scripts

### Python Request PoC
```python
import requests

BASE = "https://target.com"
ATTACKER_SESSION = {"session": "attacker_session_cookie"}
VICTIM_ID = 12345

# IDOR proof
r = requests.get(f"{BASE}/api/invoices/{VICTIM_ID}", cookies=ATTACKER_SESSION)
print(r.json())  # shows victim's invoice
```

### Bash One-Liner PoC
```bash
# SSRF proof
curl -s -X PUT https://target.com/api/user/avatar \
  -H "Cookie: session=ATTACKER_SESSION" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

### Burp Suite Macro (for authenticated scans)
```
1. Session Handling Rules → Add
2. Rule Action: Run a macro
3. Macro: Login macro (POST /login, extract session cookie)
4. Apply to: target scope only
```

---

## Report Writing Anti-Patterns

**NEVER:**
- Copy-paste from AI without reading it (hallucinated endpoints)
- Claim impact you didn't prove ("leads to RCE" when you only got SSRF)
- Submit the same bug at multiple programs without checking scope
- Use screenshots from a different target/version
- Claim "all users affected" without testing at scale
- Write reports at 2am before sleep — review in the morning
- Use "vulnerability was discovered" (passive voice)
- Pad the report with irrelevant details

**ALWAYS:**
- Test with two distinct accounts
- Include the exact HTTP request
- Show the exact response proving the bug
- State impact before vuln class
- Keep it under 500 words
- Review the program scope before submitting
- Calculate CVSS carefully

---

## Quick Reference: Report Length Targets

| Section | Target Length |
|---------|--------------|
| Title | 1 line (~100 chars) |
| Summary | 3-4 sentences |
| Steps to Reproduce | 4-6 numbered steps |
| Evidence | Inline requests + 1-2 screenshots |
| Impact | 2-3 sentences |
| CVSS | 1 line with vector |
| Remediation | 1-2 sentences |
| **Total** | **300-500 words** |

---

## Final Rule

> **If you cannot write the impact statement in ONE sentence that a non-technical person would understand, you don't understand the bug well enough to report it. Go back, retest, and find the real impact.**

The best reports are boring to write and exciting to read. State the facts. Show the proof. Name the harm. Done.

---

## Advanced Report Writing

### Writing Impact Statements for Different Audiences

**For Technical Triagers (HackerOne, Intigriti):**
- Be precise with HTTP methods, paths, parameters
- Include exact payloads
- Reference OWASP categories and CWE IDs
- Include CVSS vector with justification

**For Non-Technical Customers (Bugcrowd, private programs):**
- Start with business impact
- Use analogies: "like a postal worker opening other people's mail"
- Quantify in business terms: "$X at risk, N users affected, compliance exposure"
- Explain remediation in plain English

**For Program Managers (escalation):**
- Lead with the number: N users affected, $X at risk
- Mention compliance: HIPAA, PCI-DSS, GDPR exposure
- Reference similar CVEs or breaches for context
- Show worst-case scenario clearly

---

## Report Writing Psychology

### What Triagers Actually Think

```
"I have 50 reports to triage today"
"I spent 3 seconds on the title"
"I'm scanning for: impact, proof, reproducibility"
"If I can't understand it in 30 seconds, I'm moving on"
"I'm comparing this to 10 similar reports I just read"
"I'm looking for reasons to say 'not a bug' or 'duplicate'"
"If the researcher seems unsure, I'm going to doubt it too"
```

### Writing for the Tired Triager

**Opening lines (first 10 words) determine everything:**
```
BAD:  "I would like to report a vulnerability I found..."
GOOD: "Any user can read every other user's invoice by changing one ID."
```

**Structure that works:**
```
1. Impact statement (first sentence) — WHAT HAPPENS
2. How it works (second sentence) — HOW IT WORKS  
3. Scale (third sentence) — HOW MANY / HOW MUCH
4. Proof (numbered steps) — SHOW ME
5. Fix (one sentence) — HERE'S HOW
```

---

## Advanced Template: IDOR with Business Impact

```
Title: IDOR in /api/v2/invoices/{id} allows authenticated user to read all customer invoices

Summary:
An authenticated user can read any customer's invoice — including full names, 
addresses, phone numbers, payment amounts, and last 4 digits of payment cards — 
by changing a single number in the URL. No special permissions needed beyond 
a free account. This affects every invoice in the system (approximately 50,000 records).

Steps to Reproduce:
1. Log in as attacker: attacker@test.com / Pass123!
2. Send: GET /api/v2/invoices/1001 HTTP/1.1
   Authorization: Bearer eyJhbGciOi...
3. Observe: 200 OK with attacker's own invoice (baseline)
4. Send: GET /api/v2/invoices/2002 HTTP/1.1
   Authorization: Bearer eyJhbGciOi...
5. Observe: 200 OK with VICTIM's full invoice data:
   {
     "id": 2002,
     "customer_name": "Jane Smith",
     "email": "jane@example.com",
     "address": "123 Main St, City, State 12345",
     "phone": "+1-555-0123",
     "amount": "$4,200.00",
     "card_last4": "4242",
     "items": [...]
   }
6. Confirm: With victim account victim@test.com, attacker can access 
   invoice 1001 (attacker's invoice) using same technique.

Supporting Material:
[Burp Suite request: GET /api/v2/invoices/2002 with attacker's session]
[Screenshot: Full victim invoice returned in attacker's session]
[Second screenshot: Victim's account dashboard showing invoice 2002]

Impact:
Any authenticated user can enumerate and read all 50,000 customer invoices. 
This includes PII (full names, addresses, phone numbers, emails) and financial 
data (amounts, card last4). An attacker could:
- Export all customer data for resale or phishing campaigns
- Map the customer base for competitive intelligence
- Identify high-value customers for targeted attacks
- Violate GDPR (if EU customers) with potential regulatory fines

CVSS 3.1: 7.5 High
AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N

Remediation:
Add server-side ownership check: verify invoice.user_id == requesting_user.id 
before returning data. Apply to ALL endpoints in the invoices controller.

References:
- CWE-639: Authorization Bypass Through User-Controlled Key
- OWASP Top 10 2021: A01:2021 – Broken Access Control
```

---

## Advanced Template: SSRF with Full Chain

```
Title: SSRF in profile picture import reaches AWS EC2 metadata — allows cloud account takeover

Summary:
The "import profile picture from URL" feature (PUT /api/user/avatar) fetches 
any user-supplied URL server-side without validating the destination. An attacker 
can supply the EC2 metadata endpoint (169.254.169.254) and receive the server's 
IAM credentials. These credentials grant full access to AWS resources, including 
S3 buckets containing 200,000 user records.

Steps to Reproduce:
1. Log in as any user: attacker@test.com / Pass123!
2. Send: PUT /api/user/avatar HTTP/1.1
   Authorization: Bearer eyJhbGciOi...
   Content-Type: application/json

   {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}

3. Observe: 200 OK with response containing IAM role name:
   {"role": "prod-app-role"}

4. Extract credentials:
   GET http://169.254.169.254/latest/meta-data/iam/security-credentials/prod-app-role
   
   Response:
   {
     "AccessKeyId": "ASIAXXXXXXXXXX",
     "SecretAccessKey": "XXXXXXXXXX",
     "Token": "XXXXXXXXXX",
     "Expiration": "2024-01-01T00:00:00Z"
   }

5. Use credentials (AWS CLI configured with stolen creds):
   $ aws s3 ls s3://target-user-data/ --region us-east-1
   
   Output shows 200,000 user records with PII and payment data

6. Download sample:
   $ aws s3 cp s3://target-user-data/users.json ./stolen.json
   File contains: email, name, phone, address, card_last4 for all users

Supporting Material:
[Request: PUT /api/user/avatar with metadata URL]
[Response: IAM role name]
[Response: Full IAM credentials]
[Screenshot: AWS CLI listing S3 bucket contents]
[Screenshot: Sample of downloaded user data]

Impact:
This SSRF grants full AWS account access via stolen IAM credentials. Confirmed 
read access to 3 S3 buckets containing 200,000 user records including PII 
(emails, names, phones, addresses) and financial data (card last4, transaction 
history). An attacker can:
- Exfiltrate all user data in bulk
- Modify or delete cloud resources
- Pivot to other AWS services (Lambda, RDS, ECS)
- Use compromised AWS environment for cryptomining or as attack launchpad
- Achieve persistent access by creating backdoor IAM users

Compliance impact: GDPR violation for EU users, potential PCI-DSS breach for 
card data, state breach notification laws in 50+ US states.

CVSS 3.1: 9.1 Critical
AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

Remediation:
1. Implement URL allowlist for avatar import (only approved image hosts)
2. Block private/reserved IP ranges (RFC 1918, link-local 169.254, metadata) 
   server-side before fetching
3. Use SSRF-protected HTTP client (e.g., Python requests with adapter that 
   blocks private IPs)
4. Consider removing server-side URL fetching entirely; use client-side upload

References:
- CWE-918: Server-Side Request Forgery (SSRF)
- OWASP Top 10 2021: A10:2021 – Server-Side Request Forgery
- AWS Security Best Practices: https://docs.aws.amazon.com/general/latest/gr/ec2-instance-metadata.html
```

---

## Handling Severity Disputes

### Complete Escalation Playbook

**Scenario 1: "Requires authentication" downgrade**

```
Counter:
"Confirmed: requires only a free, unauthenticated account (no paid tier, no 
admin role, no approval process). This is the minimum privilege level — any 
visitor can register and exploit this within 2 minutes. The 'requires 
authentication' argument does not apply to free-tier accounts."

Reference: HackerOne #1234567 (similar IDOR, paid at High with same auth level)
```

**Scenario 2: "Limited impact" downgrade**

```
Counter:
"Impact quantified: 50,000 user records affected, including full PII (names, 
addresses, phone numbers, card last4). Using this data, an attacker can:
1. Conduct phishing campaigns against all 50,000 users
2. Commit identity theft using collected PII
3. Map customer base for targeted attacks
4. Trigger GDPR breach notification (EU users)
This is not 'limited impact' — this is mass data exposure."

Reference: Company's own privacy policy states "we protect your personal data"
```

**Scenario 3: "Already known" / duplicate**

```
Counter:
"I searched HackerOne Hacktivity for [PROGRAM] on [DATE] and found no prior 
disclosure of this specific issue on [endpoint] with [specific impact]. 
The closest report (#12345) covers [different endpoint/different impact]. 
Please provide the report number if this is considered a duplicate so I can 
review and understand the distinction."

Action: Actually read the referenced report. If truly duplicate, accept and move on.
```

**Scenario 4: "By design"**

```
Counter:
"This behavior is not documented in any public-facing documentation, API docs, 
or help center articles I reviewed. Users would reasonably expect that changing 
a URL ID from their own record to another user's record would either return 
their own data or an access denied error — not the other user's full record. 
If this is by design, please direct me to the specific documentation that 
states this is intended behavior."

Action: Check if there's any documentation. If not, push back firmly.
```

**Scenario 5: "CVSS too high"**

```
Counter:
"CVSS 3.1 base score accounts for the technical severity, but the program's 
severity guidelines also consider business impact. This vulnerability allows 
[quantified harm], which [program name]'s policy defines as [reference severity 
level]. The CVSS is justified — the scope change (S:C) is real because the 
SSRF extends beyond the application to cloud infrastructure, and the 
confidentiality impact (C:H) is confirmed with 200K user records at risk."
```

---

## Writing for Specific Bug Classes

### Writing IDOR Reports That Get Paid

```
Key elements:
1. Show TWO requests: attacker gets victim's data, victim gets attacker's data
2. Show the ID in BOTH requests (proving ID swapping)
3. Show what data is leaked (specific fields, not just "data")
4. Quantify: how many records? How sensitive?

Common mistake: "I can access other users' data"
Fixed: "I can access invoices containing full name, address, phone, and 
partial card number for all 50,000 customers by changing the invoice ID 
from 1001 to 1002"

Advanced: Include enumeration potential
"By iterating IDs from 1 to 50000, an attacker can dump the entire 
customer database in under 10 minutes"
```

### Writing SSRF Reports That Get Paid

```
Key elements:
1. Show the vulnerable parameter
2. Show the SSRF payload
3. Show the internal service response (NOT just DNS callback)
4. Show what the internal service contains
5. Show the impact of accessing that service

Common mistake: "I got a DNS callback"
Fixed: "I received the EC2 IAM credentials (AccessKeyId, SecretAccessKey) 
which I used to list S3 buckets containing 200K user records"

Advanced: Chain the SSRF
"SSRF → Redis → session tokens → ATO as admin"
Include each step with proof
```

### Writing XSS Reports That Get Paid

```
Key elements:
1. Show the payload
2. Show where it's injected (form field, URL parameter)
3. Show where it executes (which page, which user context)
4. Show what the attacker can do (steal cookies, perform actions)

Common mistake: "alert(1) fired"
Fixed: "Stored XSS in job_title field executes when admin views user profile 
page. Payload steals admin's session cookie via document.cookie, enabling 
full admin account takeover."

Advanced: Show the chain
"This XSS in the support ticket system executes when support agents view 
tickets. Combined with the fact that agents can refund any transaction, an 
attacker can steal an agent's session and issue refunds to themselves."
```

### Writing Race Condition Reports That Get Paid

```
Key elements:
1. Show the normal behavior (single request works once)
2. Show the race (multiple simultaneous requests)
3. Show the anomalous result (multiple successes)
4. Quantify the gain (how much stolen per successful race)

Common mistake: "I can redeem the coupon multiple times"
Fixed: "By sending 20 simultaneous POST requests to /api/coupons/redeem, 
12 requests returned 200 (success) instead of the expected 1. Each successful 
redemption adds $20 credit. Demonstrated $240 gain from single coupon code."

Advanced: Video evidence
Race conditions are hard to prove with screenshots. Include a 20-second 
video showing:
1. Normal redemption (1 success)
2. Parallel redemption (multiple successes)
3. Resulting credit balance
```

---

## International Report Writing

### Writing for Non-English Programs

```
General rules:
1. Keep technical terms in English (XSS, SSRF, API, HTTP)
2. Use simple sentence structure
3. Avoid idioms and cultural references
4. Be explicit about impact (don't assume cultural context)

Example:
BAD:  "This is a goldmine for identity theft"
GOOD: "This data can be used to impersonate users and commit fraud"

BAD:  "Low-hanging fruit"
GOOD: "Easy to exploit with basic tools"

BAD:  "Smoking gun"
GOOD: "Definitive proof of the vulnerability"
```

---

## Report Quality Metrics

### Self-Assessment Checklist

```
Readability:
[ ] A non-technical manager understands the impact from paragraph 1
[ ] A developer knows exactly what to fix from the report
[ ] No unexplained acronyms without first use definition
[ ] Sentences are under 30 words average

Completeness:
[ ] All 7 sections present (title, summary, steps, evidence, impact, CVSS, fix)
[ ] Every claim has evidence
[ ] HTTP requests are complete with all headers
[ ] Two accounts demonstrated (not one account testing itself)

Accuracy:
[ ] Every endpoint path is correct (tested, not guessed)
[ ] Every parameter name is correct
[ ] CVSS vector matches described impact
[ ] No theoretical claims ("could", "might", "potentially")

Professionalism:
[ ] No typos in endpoint paths or parameter names
[ ] No em dashes or fancy punctuation
[ ] No corporate jargon ("leverage", "comprehensive", "seamless")
[ ] Under 500 words total
```

---

## Report Templates: Additional Bug Classes

### Template: CSRF

```
Title: CSRF on email change endpoint allows attacker to change victim's email

Summary:
The email change endpoint (POST /api/user/email) accepts requests without 
CSRF token validation. An attacker can craft a malicious page that submits 
a form to this endpoint, changing the victim's email to one controlled by 
the attacker. After email change, attacker requests password reset → ATO.

Steps to Reproduce:
1. As attacker, create HTML file:
   <form action="https://target.com/api/user/email" method="POST">
     <input name="email" value="attacker@evil.com">
   </form>
   <script>document.forms[0].submit();</script>
2. Host on attacker.com, send link to victim
3. Victim logged into target.com visits attacker.com
4. Email changed to attacker@evil.com
5. Attacker requests password reset → gains account access

Supporting Material:
[HTML file content]
[Proof: email changed in victim's account settings]

Impact:
Attacker can take over any account by changing the email address. Combined 
with password reset, this is a full account takeover chain.

CVSS 3.1: 6.5 Medium
AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N

Remediation:
Add CSRF token validation to all state-changing endpoints. Use SameSite=Strict 
cookies as defense-in-depth.
```

### Template: Business Logic

```
Title: Negative quantity in checkout allows $1000 item purchase for -$100 (store credit)

Summary:
The checkout endpoint accepts negative item quantities. A negative quantity 
causes the system to ADD to the cart total instead of subtracting, and 
generates store credit for the difference. An attacker can buy any item 
and receive money back.

Steps to Reproduce:
1. Add item to cart: Premium Subscription ($1000/year)
2. Send: POST /api/checkout
   {"items": [{"id": "premium", "qty": -1}], "payment_method": "card"}
3. Observe: Order created with -$1000 total
4. Account receives $1000 store credit
5. Use credit to purchase other items for free

Supporting Material:
[Request/response showing negative total]
[Screenshot: store credit balance after exploit]

Impact:
Any user can generate unlimited store credit by submitting negative quantities. 
This directly converts to free products/services. Affects all pricing tiers.

CVSS 3.1: 7.5 High
AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L

Remediation:
Validate that item quantities are positive integers on the server side. 
Add business logic check: total must be >= 0 before processing payment.
```

### Template: GraphQL Auth Bypass

```
Title: GraphQL node() query bypasses per-object authorization, exposes all user records

Summary:
The GraphQL API enforces authorization on user queries (user(id: X) returns 
only the requesting user's data). However, the generic node(id:) query bypasses 
per-object authorization and returns any user's full record. This exposes PII 
for all users in the system.

Steps to Reproduce:
1. Log in as attacker: attacker@test.com
2. Query own data (works correctly):
   {"query": "{ user(id: 1) { name email } }"}
   → Returns only attacker's data
3. Query other user via node():
   {"query": "{ node(id: \"dXNlcjoy\") { ... on User { name email phone ssn address } } }"}
   → Returns victim's FULL data including SSN, address, phone
4. Enumerate all users by iterating node IDs

Supporting Material:
[Request: user(id: 1) - returns own data]
[Request: node(id: "dXNlcjoy") - returns other user's full PII]
[Screenshot: victim's SSN and address in response]

Impact:
The node() query exposes full PII (name, email, phone, address, SSN) for all 
users. An attacker can dump the entire user database. Affects ~100,000 users.

CVSS 3.1: 8.6 High
AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N

Remediation:
Implement per-object authorization check in node() resolver. Verify requesting 
user has permission to access the requested object type before returning data.
```

---

## Advanced Impact Escalation

### The Impact Ladder

```
Level 1: Non-sensitive data
"User can see another user's public profile picture"
→ KILL or chain to something else

Level 2: Low-sensitivity PII
"User can see another user's display name and join date"
→ Usually Low/Informational

Level 3: Medium PII
"User can see another user's email and phone number"
→ Medium, unless mass exfil possible

Level 4: High PII
"User can see SSN, DOB, address, financial data"
→ High, especially if mass exfil

Level 5: Credential exposure
"User can see password hashes, API keys, session tokens"
→ High-Critical depending on type

Level 6: Account takeover
"Attacker can take over any user account"
→ High-Critical

Level 7: Admin takeover
"Attacker can take over admin accounts"
→ Critical

Level 8: Full platform control
"Attacker can modify any data, create users, change settings"
→ Critical

Level 9: Infrastructure access
"Attacker can access internal systems, cloud credentials"
→ Critical

Level 10: Full cloud takeover
"Attacker has AWS admin credentials"
→ Critical
```

### Escalating from Low to High

**Technique: Show the data exfiltration path**

```
Weak: "API returns more fields than the UI shows"
Strong: "API returns full user record including SSN and card number. 
By iterating user IDs, an attacker can dump the entire user database 
in a single script. Here's the Python PoC that exfiltrates 50K records."

Technique: Show the attacker capability

Weak: "Attacker can modify their own profile"
Strong: "Attacker can modify ANY user's profile including admins. 
By changing the admin's email to attacker-controlled, then requesting 
password reset, attacker achieves full admin access."

Technique: Show the scale

Weak: "This affects some users"
Strong: "This affects ALL 50,000 users. I confirmed access to accounts 
registered in the last 24 hours, showing the bug is not limited to old accounts."
```

---

## Special Report Types

### Chain Report (A→B→C)

```
Title: SSRF in image import → Redis session theft → admin account takeover

Summary:
The image import feature (PUT /api/avatar?url=) is vulnerable to SSRF, 
allowing access to the internal Redis server. Redis stores session tokens 
in plaintext. Stealing an admin session token grants full admin access — 
a complete compromise chain from a single SSRF vulnerability.

Chain breakdown:
1. SSRF: PUT /api/avatar {"url": "http://127.0.0.1:6379/"} 
   → Redis accessible
2. Session theft: Redis KEYS "session:*" → GET session:ADMIN_TOKEN
   → Admin session token extracted
3. Admin ATO: Use stolen session token to access /admin 
   → Full admin panel access

This is ONE report. Don't split into 3 separate reports — the chain is 
the finding.

Impact:
Full admin account takeover via SSRF → Redis → session theft chain. 
No user interaction required beyond any user having an account.

CVSS 3.1: 9.8 Critical
```

### Multiple Endpoints Report

```
If you find the same bug class on multiple endpoints:

Title: IDOR in 12 invoice endpoints allows authenticated user to read all customer invoices

Summary:
The /api/invoices/* endpoints lack authorization checks. Testing revealed 
12 endpoints where changing the invoice ID in the URL returns other users' 
invoice data. All 12 endpoints share the same root cause (missing ownership 
check in invoices controller).

Affected endpoints:
- GET /api/invoices/{id}
- PUT /api/invoices/{id}
- DELETE /api/invoices/{id}
- GET /api/invoices/{id}/pdf
- GET /api/invoices/{id}/items
- ... (list all 12)

Steps to Reproduce:
(Show one PoC, then list the other 11 endpoints)

Impact:
All 12 endpoints expose customer invoice data. Combined, this is a systemic 
authorization failure affecting the entire invoicing module.

CVSS 3.1: 7.5 High
```

---

## Report Anti-Patterns (Advanced)

### The "Wall of Evidence" Anti-Pattern

```
BAD:
[20 screenshots]
[5 videos]
[Burp export with 1000 requests]
[50 pages of analysis]
→ Triagers skip this. Include only what's needed.

GOOD:
[1 screenshot showing the bug]
[Exact HTTP request + response]
[That's it]
→ Triagers read this. Submit.
```

### The "Hedge Words" Anti-Pattern

```
BAD:  "I believe this might potentially be an IDOR vulnerability..."
GOOD: "This is an IDOR vulnerability. Changing the ID from 1001 to 2002 
       returns victim's invoice data."

BAD:  "It seems like the server doesn't check authorization..."
GOOD: "The server does not check authorization. I confirmed by sending 
       requests as two different users."

BAD:  "This could potentially lead to data exposure..."
GOOD: "This exposes 50,000 user records containing names, emails, and card numbers."

Hedge words kill credibility. Be confident or retest.
```

### The "Feature Request" Anti-Pattern

```
BAD:  "The application should validate that users can only access their own data"
GOOD: "The invoices controller lacks ownership validation. Add: 
       if (invoice.user_id !== req.user.id) return 403"

BAD:  "Consider implementing rate limiting"
GOOD: "The /api/reset-password endpoint accepts unlimited requests. Add 
       rate limiting: max 5 requests per IP per hour"

Fixes should be specific enough that a developer can copy-paste them.
```

---

## Report Templates: Edge Cases

### Template: Chained Bugs (Single Report)

```
Title: SSRF in image import → Redis session theft → admin account takeover

Summary:
PUT /api/avatar accepts a URL parameter and fetches it server-side without 
validation. This SSRF reaches the internal Redis server (127.0.0.1:6379). 
Redis stores session tokens. Stealing an admin session token grants full 
admin access.

Chain:
1. SSRF: curl -X PUT /api/avatar -d '{"url": "http://127.0.0.1:6379/"}'
2. Redis access: GET session:ADMIN_TOKEN_HASH
3. Admin ATO: Use stolen session cookie to access /admin

Impact:
Full admin account takeover via 3-step chain. No special tools needed beyond 
curl. Affects all admin accounts.

CVSS: 9.8 Critical
```

### Template: Multiple Users Affected

```
Title: IDOR in /api/messages/{id} exposes private messages between any two users

Summary:
The private messaging system allows reading any user's messages by changing 
the conversation ID. I confirmed access to messages from 3 different users, 
including conversations containing sensitive personal information.

Scale testing:
- Tested IDs 1-100: accessed 47 different users' conversations
- Confirmed message types: personal messages, financial discussions, 
  support requests with PII
- Estimated total: 10,000+ conversations accessible

Impact:
Mass private message exposure. Users expect private messaging to be private. 
Exposure of sensitive conversations creates phishing, extortion, and social 
engineering risk. GDPR exposure for EU users.

CVSS: 7.5 High
```

---

## Final Rule

> **The difference between a rejected report and a paid report is usually 10 minutes of editing. Read your report as if you're the triager. Is it scannable? Is it credible? Is the impact concrete? If not, rewrite it before submitting.**
