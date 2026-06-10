---
name: recon-to-chain-mapper
description: Reconnaissance for exploit chain building. Maps recon outputs to chain primitive pairs (A->B) for chaining findings into higher severity. Covers IDOR->auth bypass, SSRF->cloud metadata, XSS->ATO, open redirect->OAuth theft, subdomain takeover->OAuth, file upload->RCE chains. Use after finding bug A to systematically locate bug B and C for chaining.
---

# Recon Chaining: From Raw Recon to Exploit Chains

## Purpose

A single P2 bug can become P0 when chained. This file teaches how to use recon data to identify **chainable pairs** (A links to B). The methodology: for each bug class A, recon for specific signals that predict bug class B exists on the same asset.

---

## Chain Philosophy

### Why Chain?

- Single finding: IDOR on profile endpoint = High (P2)
- Chained: IDOR on profile -> email change -> password reset -> full account takeover = Critical (P0)
- Reports with chains get funded at 1337x rates

### Chain Rules

1. **Each link must be independently exploitable** — if A alone is "could potentially", the chain fails.
2. **Chain amplifies scope, not severity mechanically** — a chain from Read to Write IDOR on the same endpoint often doesn't change severity. A chain that crosses trust boundaries (user -> admin) does.
3. **Prefer functional chains over config chains** — IDOR + auth bypass is stronger than missing header + missing header.
4. **Keep the chain readable** — report should flow: "I can do X, which allows Y, which gives Z."

---

## Recon Primitive Morphology

Each critical bug class has a **recon signature** — specific data patterns you look for during recon that predict the bug's existence.

---

### Chain Primitive: IDOR

**Recon signature for IDOR:**
```
API endpoints with resource IDs: /api/users/{id}, /api/orders/{id}
File serving: /files/{id}/download, /documents/{id}
Profile endpoints: /profile/{id}, /account/{id}
Parameters: ?userId=, ?accountId=, ?orderId=, ?invoiceNo=
```

**IDOR chains available:**

| Chain | Link A (IDOR) | Link B | Why it chains | Recon signals for B |
|---|---|---|---|---|
| A1 | Horizontal IDOR (read profile) | Capture victim's password reset token from email metadata | Token appears in profile preview | Find email-sending features, check if token is in data |
| A2 | IDOR on user.update | Modify victim email to attacker email | Direct account takeover | Find email-change endpoint (link it to user update) |
| A3 | IDOR on user.update | Set victim role to admin | Privilege escalation | Find role field in profile update API |
| A4 | IDOR on file download | Download victim's uploaded documents containing credentials | Credential theft from stored files | Map file upload/download pairs |

**Recon for A1 chain:**
```bash
# Find IDOR patterns
cat urls/all-urls.txt | grep -oP '/api/[a-zA-Z0-9/-]+/\d+' | sort -u > idor-targets.txt

# For each endpoint, check if it returns email addresses
# (email presence = email change chain possible)
```

**Recon for A2 chain:**
```bash
# Find email change endpoints
cat urls/all-urls.txt | grep -iE '(email|mail).*(change|update|edit|modify)' | sort -u

# Check if same API handles both profile read and email update
# Common pattern: GET /api/users/{id} and PATCH /api/users/{id}
```

**Recon for A3 chain:**
```bash
# Find role field exposure in profile APIs
cat js-endpoints.txt | grep -i 'role\|permission\|admin\|is_admin' | sort -u
curl -s https://target.com/api/users/1 | jq .role
```

---

### Chain Primitive: SSRF

**Recon signature for SSRF:**
```
URL parameters: ?url=, ?uri=, ?link=, ?redirect=, ?fetch=, ?proxy=, ?webhook=
Webhook endpoints: /webhook, /callback, /notify
PDF/document generation: /export, /generate, /preview, /report
Image processing: /resize, /crop, /convert
OAuth metadata fetch: /.well-known/openid-configuration
```

**SSRF chains available:**

| Chain | Link A (SSRF) | Link B | Recon signals for B |
|---|---|---|---|
| B1 | SSRF to internal HTTP | Read AWS metadata (169.254.169.254) for IAM credentials | Cloud infra, EC2 detected in tech stack |
| B2 | SSRF to internal HTTP | Access internal dashboard (Elasticsearch, Redis, Jenkins) | Internal hostnames from DNS or JS |
| B3 | SSRF + gopher | Write SSH key to Redis via gopher:// | Redis on port 6379 from nmap/naabu |
| B4 | SSRF + DNS rebinding | Bypass SSRF allowlist (second-stage IP) | Cloudflare/Route53 DNS found in recon |

**Recon for B1 chain:**
```bash
# Check for cloud metadata endpoints
cat hosts/live.txt | while read host; do
  curl.exe -s --max-time 3 "$host/api/v1/metadata" 2>&1 | head -5
  curl.exe -s --max-time 3 "$host/latest/meta-data/" 2>&1 | head -5
done | tee cloud-metadata-check.txt

# Check tech stack for AWS/cloud indicators
cat technology/stack.txt | grep -iE 'amazon|aws|cloud|s3|ec2|lambda'

# Check DNS for internal hostnames
cat subdomains/all.txt | grep -iE 'internal|intranet|admin|dashboard|jenkins|elasticsearch'
```

**Recon for B3 chain:**
```bash
# Check ports for Redis from naabu
cat hosts/ports.txt | grep ':6379'
# Then gopher://redis:6379/... payload in SSRF parameter
```

---

### Chain Primitive: XSS

**Recon signature for XSS:**
```
Reflective parameters: parameters that appear in response body
DOM sinks: innerHTML, document.write, eval() in discovered JS
Upload endpoints: profile pic, file upload with HTML/SVG allowed
Admin-rendered content: profile fields, comments, reviews stored and shown to others
JSON endpoints with unescaped output
```

**XSS chains available:**

| Chain | Link A (XSS) | Link B | Recon signals for B |
|---|---|---|---|
| C1 | Stored XSS in profile bio | Admin views user list -> steals admin session cookie | Admin panel detected in recon (admin.target.com) |
| C2 | XSS in message field | Send message to admin via contact/notification endpoint | Notification/messaging endpoints in API |
| C3 | XSS -> postMessage | postMessage listener executes attacker payload | PostMessage listeners found in JS analysis |
| C4 | XSS + OAuth redirect_uri | XSS on same domain as OAuth provider -> steal token | OAuth callback URLs on target's domains |

**Recon for C1 chain:**
```bash
# Find admin panel
ffuf -u https://target.com/FUZZ -w admin-panels.txt -fc 404 | grep -E '302|200|401|403' > urls/admin-panels.txt

# Find stored XSS vectors (profile endpoints with user input)
cat urls/all-urls.txt | grep -iE 'profile|bio|comment|review|message|display' | sort -u

# Cross-ref: do admin endpoints render user data?
# Recon question: does admin panel load profile data from the same profile API?
```

**Recon for C2 chain:**
```bash
# Find notification/messaging endpoints
cat urls/all-urls.txt | grep -iE 'notify|message|chat|contact|support|ticket' | sort -u

# Find if admin is the viewer/receiver
# Patterns: ?to=admin, /admin/notifications, /admin/support
```

---

### Chain Primitive: Authentication Bypass

**Recon signature for auth bypass:**
```
Admin panels: /admin, /dashboard, /manage
Internal APIs: /internal, /api/v2/admin
Unauthenticated API: no 401/403 on authz-required endpoints
Middleware bypass candidates: X-Forwarded-For, X-Real-IP, X-Original-URL handling
```

**Auth bypass chains:**

| Chain | Link A (Auth Bypass) | Link B | Recon signals |
|---|---|---|---|
| D1 | View admin panel without auth | Read admin-only settings containing credentials/secrets | Admin settings endpoints |
| D2 | Auth bypass on API | Call privileged GraphQL mutation without token | GraphQL mutations in introspection |
| D3 | Bypass MFA -> access admin | Modify user role via admin API (no re-auth on MFA-completed session) | MFA completing endpoints + role mutation |

---

### Chain Primitive: File Upload

**Recon signature for file upload:**
```
Upload parameters: multipart/form-data fields, file fields
Upload endpoints: /upload, /attachment, /avatar, /import
Image/service processing: /resize, /convert (may process uploaded files)
Web-accessible storage: /uploads/, /public/, /static/files/
```

**File upload chains:**

| Chain | Link A (Upload) | Link B | Recon signals |
|---|---|---|---|
| E1 | Upload .htaccess / .user.ini | Enable PHP execution in uploads dir | PHP detected in tech stack, upload dir is web-accessible |
| E2 | Upload DOCX with XXE | XXE exfiltrates internal config/credentials | File processed server-side (conversion to PDF/HTML) |
| E3 | Upload SVG with XSS | Admin views upload list or image preview -> XSS fires | Admin panel with file browser detected |
| E4 | Upload deserialization payload | PHP/Golang deserialization on file processing | Framework version with known deser vuln |

**Recon for E1 chain:**
```bash
# Check if PHP is in tech stack
cat technology/stack.txt | grep -i 'php'
cat hosts/detailed.txt | grep -i 'php'

# Check if upload dir is web-accessible
cat urls/all-urls.txt | grep -i '/uploads/\|/public/\|/attachments/' | sort -u

# Check if .htaccess/.user.ini are served (check response headers)
curl.exe -sI https://target.com/uploads/.htaccess
```

---

### Chain Primitive: Open Redirect

**Recon signature for open redirect:**
```
Redirect parameters: ?next=, ?redirect=, ?return=, ?url=, ?goto=, ?continue=
OAuth redirect_uri parameters
Header-based redirects: Location, Refresh
```

**Open redirect chains:**

| Chain | Link A (Open Redirect) | Link B | Recon signals |
|---|---|---|---|
| F1 | Open redirect on target.com | Steal OAuth authorization code via redirect_uri | OAuth endpoints found in recon |
| F2 | Open redirect -> SSRF | Redirect to internal host via open redirect | Internal hostnames discovered, redirect params found |
| F3 | Open redirect -> XSS | javascript:alert in redirect param (directly XSS) | Redirect param is reflected in response |

**Recon for F1 chain:**
```bash
# Find OAuth endpoints
cat urls/all-urls.txt | grep -iE 'oauth|authorize|token|sso|saml' | sort -u

# Find redirect parameters
cat urls/all-urls.txt | grep -oP '(?<=\?|&)(next|redirect|return|url|goto|continue|dest|forward)=[^&]+' | sort -u

# Cross-ref: does redirect endpoint exist on target domain?
# (redirect on target.com + OAuth on target.com = chain candidate)
```

---

### Chain Primitive: Subdomain Takeover

**Recon signature for subdomain takeover:**
```
CNAMEs pointing to:
  *.s3.amazonaws.com
  *.herokuapp.com
  *.azure.com
  *.github.io
  *.pages.dev
  *.shopify.com
NXDOMAIN responses on CNAME target
```

**Subdomain takeover chains:**

| Chain | Link A (Takeover) | Link B |
|---|---|---|
| G1 | Takeover subdomain | Host phishing page stealing target.com cookies |
| G2 | Takeover subdomain -> valid TLS cert | OAuth redirect_uri accepts the subdomain -> steal OAuth codes |
| G3 | Takeover subdomain | JS delivery via subdomain -> bypass CSP, load malicious JS |

**Recon for G2 chain:**
```bash
# Find CNAMEs to known-takeover services
cat subdomains/cname.txt | grep -iE 's3.amazonaws|herokuapp|github.io|pages.dev|azure'

# Check OAuth redirect_uri patterns
cat urls.all-urls.txt | grep -iE 'redirect_uri' | grep target.com

# Do any redirect_uris use subdomains?
grep -oP 'redirect_uri=https?://[^&]+\.target\.com[^&]*' urls/all-urls.txt
```

---

### Chain Primitive: CORS Misconfiguration + Credential Theft

**Recon signature for CORS misconfig:**
```
API responses with:
  Access-Control-Allow-Origin: *
  Access-Control-Allow-Origin: null
  Access-Control-Allow-Origin: attacker.com
  Access-Control-Allow-Credentials: true
```

**CORS chains:**

| Chain | Link A (CORS) | Link B | Recon signals |
|---|---|---|---|
| H1 | CORS w/ credentials + wildcard origin | Steal user data (API responses) from attacker.com | API endpoints returning sensitive data in JSON |
| H2 | CORS misconfig + JSONP callback | JSONP + CORS = full JS execution + data exfil | JSONP callback params: ?callback=, ?jsonp= |
| H3 | CORS origin reflection + wildcard subdomain | Attacker registers subdomain.target.com -> CORS allows it | Wildcard CORS response, known subdomains |

**Recon for H1 chain:**
```bash
# Find CORS headers on API endpoints
cat urls/api-endpoints.txt | while read url; do
  curl.exe -sH "Origin: https://evil.com" -sI "$url" | Select-String "Access-Control"
done > cors-check.txt

# Identify sensitive data endpoints
cat urls/api-endpoints.txt | grep -iE 'user|profile|account|payment|billing|order' | sort -u
```

---

### Chain Primitive: GraphQL Introspection + Mass Assignment

**Recon signature:**
```
GraphQL endpoints: /graphql, /api/graphql, /gql
Introspection enabled (responds to __schema query)
Mutations that return sensitive data
```

**GraphQL chains:**

| Chain | Link A | Link B | Recon signals |
|---|---|---|---|
| I1 | Introspection enabled -> find admin mutation | Call admin mutation without auth token | mutations field in __schema |
| I2 | Introspection -> find mutation with hidden fields | Mass assign via mutation to elevate role | mutation input fields |
| I3 | Introspection -> find query returning credentials | Query admin fields without auth -> bypass | Query name: admin, system, config |

**Recon approach:**
```bash
# Find GraphQL endpoints
cat urls/all-urls.txt | grep -i graphql | sort -u > graphql-endpoints.txt

# Check introspection on each
cat graphql-endpoints.txt | while read url; do
  curl.exe -s -X POST "$url" -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}' | jq .
done | tee introspection-results.txt

# If introspection returns data, extract admin mutations for hunting
```

---

## Cross-Primitive Chain Mapping

Some bugs chain across types. Recon should look for **co-location patterns** — multiple primitive signals on the same asset.

### Asset Co-location = Chain Potential

```
Asset: api.target.com
Signals found during recon:
  - API endpoints with IDs (IDOR P2)
  - Profile update endpoint with role field (IDOR P1 write)
  - User email field in GET response (IDOR P1)
  - Email change endpoint exposed (auth bypass candidate)
  Result: CHAIN CANDIDATE - IDOR read + IDOR write + email change = ATO

Asset: app.target.com
Signals:
  - File upload endpoint (RCE candidate)
  - .htaccess served (webroot write possible)
  - PHP detected in tech stack
  Result: CHAIN CANDIDATE - upload .htaccess -> write webshell -> RCE

Asset: internal.target.com
Signals:
  - No auth on admin APIs (auth bypass P1)
  - Dev tools exposed (/_next/static, /.env)
  - Internal Elasticsearch (9200)
  Result: CHAIN CANDIDATE - auth bypass + data exfil from ES
```

---

## Recon Strategy for Chain Discovery

### Phase 1: Asset Signal Mapping

After standard recon, map each asset by primitive presence:

```
ASSET: api.target.com
=======================
PRIMITIVE SIGNALS FOUND:
  [IDOR] /api/v1/users/{id} (sequential IDs)
  [IDOR] /api/v1/orders/{id}
  [AUTH] No auth check on GET /api/v1/users/me
  [CORS] aria-allow-credentials: true, origin reflection
  [API] GraphQL endpoint
CHAIN OPPORTUNITIES:
  IDOR read + IDOR write on user object
  IDOR on orders + CORS data exfil
  GraphQL introspection + mass assignment

CHAIN RANK: HIGH
```

### Phase 2: Link Verification

For each chain opportunity, verify both links work:

```
CHAIN: IDOR on /users -> email change -> password reset

Verify Link A:
  GET /api/users/4242 -> returns email field [PASS: email returned]

Verify Link B:
  Check if email change endpoint exists: PATCH /api/users/4242/email [PASS: exists, no authz]

Chain confirmed. Proceed to PoC.
```

### Phase 3: Chain Pruning

Prune chains where links don't add impact:

| Single bug severity | With chain | Outcome |
|---|---|---|
| P2 IDOR (read) | + same endpoint write | Still P2 (no scope change) | KEEP |
| P2 IDOR (read) | + email change + password reset | P0 ATO | KEEP |
| P1 auth bypass | + read secrets from config | Still P1 (same impact) | DROP |
| P1 auth bypass | + mass assign admin | P0 full compromise | KEEP |
| P2 stored XSS | + stored in admin-viewed field | P0 admin ATO | KEEP |

---

## Chain Detection Checklist

Use this checklist during recon:

- [ ] Do API endpoints with IDs also return sensitive fields in GET responses?
- [ ] Does the profile/account API accept email/role/status fields in PATCH/PUT?
- [ ] Are there upload endpoints where uploaded files are web-accessible?
- [ ] Can a CNAME be pointed at an attacker-controlled service?
- [ ] Are there OAuth/SSO redirect_uris on the same subdomain as upload/storage features?
- [ ] Does a GraphQL endpoint have introspection enabled?
- [ ] Do admin APIs exist that accept the same mutations as user APIs?
- [ ] Is there an email/notification system where mail content can be predicted?
- [ ] Are password reset tokens predictable or time-based?
- [ ] Is there a webhook/notify endpoint on the same server as an SSRF-vulnerable request fetcher?

---

## Output Format: Chain-Ready Asset Dossier

```
target-chain-dossier/
├── assets/
│   ├── api.target.com.md
│   ├── app.target.com.md
│   └── admin.target.com.md
├── chains/
│   ├── idor-ato-chain.md
│   ├── ssrf-credential-chain.md
│   └── xss-admin-chain.md
└── chain-priority.md
```

Each asset dossier includes:
- Primitive signals found (with evidence URLs)
- Confirmed vs hypothetical links
- Recommended chain direction
- Severity uplift estimate

---

## Key Principles

1. **Recon for chains, not just bugs** — always ask "what can this connect to?"
2. **Cross-reference primitives** — a resource-ID endpoint is interesting; a resource-ID endpoint adjacent to an email-change endpoint is chain-worthy.
3. **Signal co-location beats signal strength** — two P2 bugs chaining to P0 beats hunting for a standalone P0 that doesn't exist.
4. **Document the chain before exploitation** — chain hypothesis guides which recon data to prioritize.
5. **Stale recon kills chains** — re-verify chain links right before report writing. APIs change.
