# Active Target Deep Dive

Current target context — loaded at the start of every hunting session. This file is
the single source of truth for what you are actively working on. It tracks scope,
endpoints, accounts, findings in progress, and the plan for the current session.

---

## Table of Contents

1. [Target Overview](#1-target-overview)
2. [Scope Analysis](#2-scope-analysis)
3. [Subdomain Inventory](#3-subdomain-inventory)
4. [Technology Fingerprints](#4-technology-fingerprints)
5. [API Endpoint Catalog](#5-api-endpoint-catalog)
6. [Authentication Flow Map](#6-authentication-flow-map)
7. [Account & Session Inventory](#7-account--session-inventory)
8. [JS Bundle Analysis](#8-js-bundle-analysis)
9. [Finding Tracker](#9-finding-tracker)
10. [Vulnerability Test Coverage Grid](#10-vulnerability-test-coverage-grid)
11. [Chain Primitive Status](#11-chain-primitive-status)
12. [Pending Investigations](#12-pending-investigations)
13. [Session Plan](#13-session-plan)
14. [Quick Reference](#14-quick-reference)
15. [Session History](#15-session-history)

---

## 1. Target Overview

```
TARGET: [domain.com]
ALIAS: [short name used in notes]
PROGRAM: [HackerOne / Bugcrowd / Intigriti / Immunefi / Private]
PROGRAM URL: [link to program page]
STATUS: [Active / Stalled / Completed / Archived]

TECH STACK:
  Frontend: [React / Vue / Angular / Next.js / Nuxt / SPA / SSR]
  Backend:  [Rails / Django / Node / ASP.NET / Go / PHP / Spring / FastAPI]
  Database: [PostgreSQL / MySQL / MongoDB / Redis / Elasticsearch]
  Auth:     [JWT / Session / OAuth / SAML / OIDC / Custom / Devise / Auth0]
  Cloud:    [AWS / GCP / Azure / On-prem / Cloudflare]
  CDN/WAF:  [Cloudflare / Akamai / Fastly / CloudFront / Imperva]
  CMS:      [WordPress / Shopify / Custom / Headless / Contentful / Strapi]
  Payments: [Stripe / PayPal / Braintree / Klarna / Adyen]
  Email:    [SendGrid / Mailgun / SES / Postmark / Mailchimp]
  Search:   [Algolia / Elasticsearch / Meilisearch / Custom]
  Cache:    [Redis / Memcached / Varnish / CDN edge caching]
  Queue:    [Sidekiq / RabbitMQ / SQS / Bull / Kafka]
  Monitoring: [Datadog / New Relic / Sentry / Grafana / Prometheus]
  CDN:      [Cloudflare / Akamai / Fastly / CloudFront / KeyCDN / BunnyCDN]
  WAF:      [Cloudflare / Akamai Kona / Imperva / AWS WAF / ModSecurity / Barracuda]

SCOPE PATTERN: [*.domain.com / *.domain.com except x.domain.com / specific list]
REGISTRATION: [Open / OAuth only / Invite only / Disabled / Program provides accounts]
TEST ACCOUNTS: [Self-created / Provided by program / None]
```

### Current Status Summary

```
Last Session: [YYYY-MM-DD]
Total Sessions: [N]
Total Hours: [N]

Current Phase:
  [ ] Phase 1 — Recon & Asset Discovery
  [ ] Phase 2 — Pre-Hunt Learning & Threat Modeling
  [ ] Phase 3 — Active Hunting
  [ ] Phase 4 — Validation & Triage
  [ ] Phase 5 — Evidence Collection & Reporting

Progress:
  Subdomains discovered: [N]
  Live hosts identified: [N]
  API endpoints catalogued: [N]
  JS bundles analyzed: [N]

Findings:
  Confirmed (ready to report): [N]
  In progress (need validation): [N]
  Killed: [N]
  Submitted: [N]

Chain Primitives Available: [N]
Next Step: [one sentence describing the immediate next action]
```

---

## 2. Scope Analysis

### 2.1 In-Scope Domains

| Domain | Notes |
|--------|-------|
| target.com | Primary domain |
| *.target.com | Wildcard — all subdomains |
| api.target.com | API endpoint |
| admin.target.com | Admin panel |

### 2.2 Out-of-Scope Exclusions

| Domain/Path | Reason | Source |
|-------------|--------|--------|
| blog.target.com | Explicitly excluded in program policy | Scope document |
| vendor.target.com | Third-party SaaS (Zendesk) | Not owned by target |
| *.staging.target.com | Staging environment | Policy exclusion |

### 2.3 Scope Verification Checklist

Before testing any asset, verify:
- [ ] Asset is explicitly listed in scope OR matches wildcard
- [ ] Asset is not on the exclusion list
- [ ] Asset is owned by the target (not a third-party integration)
- [ ] Asset is a production environment (not staging/dev)
- [ ] Asset belongs to the current program (not another program)

### 2.4 Scope-Related Endpoints Found

Endpoints that are interesting because of their scope implications:

| Endpoint | Finding | Scope Status | Notes |
|----------|---------|-------------|-------|
| /_debug/ | Server info disclosure | In scope | Check if intentionally exposed |
| admin.otherbrand.com | Similar app, different brand | Check | May be wholly-owned subsidiary |

---

## 3. Subdomain Inventory

### 3.1 Live Subdomains

| Subdomain | IP | Status Code | Title | Tech | Notes |
|-----------|----|-------------|-------|------|-------|
| www.target.com | 1.2.3.4 | 200 | Target - Home | React, Next.js | Primary |
| api.target.com | 1.2.3.5 | 200 | — | Node.js, REST | API server |
| admin.target.com | 1.2.3.6 | 401 | Admin | React | Auth required |
| blog.target.com | 2.3.4.5 | 200 | Target Blog | WordPress | OOS |
| m.target.com | 1.2.3.4 | 200 | Target Mobile | React | Mobile redirect |
| status.target.com | 3.4.5.6 | 200 | Status | Atlassian Statuspage | Third-party |
| cdn.target.com | 4.5.6.7 | 403 | — | Cloudflare | CDN origin |
| dev.target.com | 1.2.3.8 | 404 | — | — | No DNS, removed? |

### 3.2 Interesting Subdomain Observations

| Subdomain | Why Interesting | Tested? | Result |
|-----------|----------------|---------|--------|
| admin.target.com | Admin panel, 401 | Yes | X-Forwarded-For gives 200! |
| api.target.com | All API endpoints | Yes | IDOR on /api/orders |
| dev.target.com | 404 but used to exist | No | Check Wayback |

### 3.3 Subdomain Discovery Method Tracking

| Method | Subdomains Found | Notable Finds | Effectiveness |
|--------|-----------------|---------------|---------------|
| crt.sh | 23 | admin.target.com, api.target.com | High |
| subfinder | 15 | dev.target.com, staging.target.com | Medium |
| DNS brute-force | 47 | internal.target.com, vault.target.com | High |
| Wayback Machine | 12 | old-api.target.com, blog.target.com | Medium |
| JS bundle extraction | 8 | api-v2.target.com, ws.target.com | High |

---

## 4. Technology Fingerprints

### 4.1 Server Software

| Subdomain | Server Header | X-Powered-By | Set-Cookie Pattern | Framework Detected |
|-----------|---------------|--------------|-------------------|-------------------|
| www.target.com | cloudflare | — | __next-* | Next.js |
| api.target.com | nginx/1.24.0 | Express | connect.sid | Express.js |
| admin.target.com | cloudflare | — | __next-* | Next.js |

### 4.2 WAF/CDN Fingerprinting

| Signal | Detection | Action Required |
|--------|-----------|----------------|
| Server: cloudflare | Cloudflare WAF | Test origin IP bypass |
| _cfduid cookie | Cloudflare | Standard rate limiting |
| 403 with cf-error | Cloudflare WAF blocking | Modify payload encoding |
| No direct IP access | Cloudflare proxied | Find origin IP via shodan/censys |

### 4.3 Notable Tech Versions

| Technology | Version | Known CVEs | Checked? |
|------------|---------|------------|----------|
| nginx | 1.24.0 | CVE-2023-44487 (HTTP/2 rapid reset) | Not yet |
| Express | — | No specific version | — |
| Next.js | — | No specific version | — |

### 4.4 Tech Stack Attack Surface Map

```
User Browser (React SPA)
    |
    v
Cloudflare (CDN + WAF)
    |
    v
Next.js Server (SSR + API routes)
    |
    v
Express REST API (api.target.com)
    |
    v
PostgreSQL Database
    |
    v
Redis Cache
```

Trust boundaries:
- Browser <-> Cloudflare: Client-side, assume compromised
- Cloudflare <-> Next.js: WAF provides some protection
- Next.js <-> Express API: Internal network, but APIs should still be auth'd
- Express <-> PostgreSQL: Database layer, SQLi protection
- Express <-> Redis: Cache/token storage, Redis abuse if accessible

---

## 5. API Endpoint Catalog

### 5.1 Endpoint Index

| # | Method | Endpoint | Auth | Description | Tested For | Result |
|---|--------|----------|------|-------------|------------|--------|
| 1 | GET | /api/v2/users/{id}/profile | JWT | User profile | IDOR | 403 — authz working |
| 2 | GET | /api/v2/users/{id}/orders | JWT | Order history | IDOR | **VULN — IDOR confirmed** |
| 3 | POST | /api/login | None | Login | SQLi, rate-limit | Rate limit noted |
| 4 | POST | /api/register | None | Registration | Mass assignment | Role field accepted |
| 5 | GET | /api/admin/users | JWT (admin) | List all users | Auth bypass | 401 — blocked |
| 6 | POST | /api/cart/apply-coupon | JWT | Apply coupon code | Race condition | Not tested |
| 7 | GET | /api/search?q= | None | Product search | SQLi, XSS | XSS reflected out of context |
| 8 | POST | /api/avatar | JWT | Upload avatar from URL | SSRF | Callback received! |
| 9 | GET | /.well-known/jwks.json | None | Public JWKs | JWT alg confusion | RS256 public keys found |

### 5.2 Endpoint Details

#### GET /api/v2/users/{id}/orders
- **Method:** GET
- **Auth:** JWT (any authenticated user)
- **Rate Limit:** 100 req/min per IP
- **Response Statuses:** 200 (success), 401 (bad token), 404 (no orders)
- **Parameters:** id (integer, path param)
- **Response Body:** `{ "orders": [{ "id": "...", "total": 99.99, "items": [...], "shipping_address": "..." }] }`
- **Vulnerable:** Yes — IDOR. Any user can read any other user's orders by changing the ID.

#### POST /api/register
- **Method:** POST
- **Auth:** None
- **Rate Limit:** 10 req/min per IP (registration IP check)
- **Content-Type:** application/json
- **Parameters:** email, password, password_confirmation, first_name, last_name
- **Additional Accepted:** role, is_admin (mass assignment!)
- **Response Statuses:** 201 (created), 422 (validation error), 429 (rate limit)

#### POST /api/avatar
- **Method:** POST
- **Auth:** JWT
- **Content-Type:** application/json
- **Parameters:** url (the URL to fetch the avatar from)
- **Response Statuses:** 200 (avatar fetched and set), 400 (invalid URL)
- **Vulnerable:** Yes — SSRF confirmed via DNS callback

### 5.3 Endpoint Parameter Analysis

For each discovered endpoint, document the parameters accepted and whether they
have been tested for specific vulnerabilities:

| Endpoint | Method | Parameters | IDOR Tested | SQLi Tested | SSRF Tested | Auth Bypass Tested | Mass Assign Tested | Notes |
|----------|--------|------------|-------------|-------------|-------------|-------------------|-------------------|-------|
| /api/v2/users/{id} | GET | id (path) | Yes — vuln | No | N/A | No | — | IDOR confirmed on orders |
| /api/login | POST | email, password | N/A | No | N/A | No | No | Rate limit: 10/min |
| /api/register | POST | email, password, name | N/A | No | N/A | No | Yes — role accepted | Mass assign confirmed |
| /api/avatar | POST | url | N/A | No | Yes — callback | No | No | SSRF confirmed |
| /api/search | GET | q, page, sort, size | N/A | No | N/A | No | No | XSS tested — reflected but context is JSON |

### 5.4 Endpoint Response Analysis

Document the response structure of each endpoint for quick reference:

```
GET /api/v2/users/{id}/orders (200 OK)
Response body:
{
  "status": "success",
  "data": {
    "user": {
      "id": 4242,
      "name": "Victim Name",
      "email": "victim@test.com"
    },
    "orders": [
      {
        "id": "ORD-98765",
        "total": 99.99,
        "currency": "USD",
        "items": [...],
        "shipping_address": {
          "line1": "123 Victim St",
          "city": "Victim City",
          "state": "VS",
          "zip": "12345"
        },
        "payment": {
          "method": "visa",
          "last4": "4242"
        },
        "status": "shipped",
        "created_at": "2026-01-15T10:30:00Z"
      }
    ],
    "total_orders": 47,
    "page": 1,
    "per_page": 20
  }
}
```

Common response patterns to look for:
- Error messages that reveal stack traces or SQL errors
- Internal IP addresses or hostnames
- Debug information in headers (X-Debug, X-Internal, etc.)
- Session tokens or API keys in response bodies
- Other users' data in list endpoints

### 5.5 Endpoint Testing Status Matrix

| Endpoint | GET | POST | PUT | PATCH | DELETE | OPTIONS |
|----------|-----|------|-----|-------|--------|---------|
| /api/v2/users/{id}/profile | IDOR: 403 | N/A | IDOR: pending | IDOR: pending | N/A | Tested |
| /api/v2/users/{id}/orders | IDOR: VULN | N/A | N/A | N/A | IDOR: pending | Tested |
| /api/v2/users/{id}/settings | 401 — auth needed | N/A | Testing needed | Testing needed | N/A | Tested |
| /api/login | N/A | Rate limit noted | N/A | N/A | N/A | Tested |
| /api/avatar | N/A | SSRF: VULN | N/A | N/A | N/A | Tested |
| /api/admin/dashboard | Auth bypass: VULN | N/A | N/A | N/A | N/A | Tested |

### 5.6 Endpoint Discovery Method

| Method | Endpoints Found | Example |
|--------|----------------|---------|
| JS bundle analysis | 15 | /api/v2/users/{id}/profile |
| Wayback Machine | 8 | /api/v1/users/list |
| Direct brute-force | 5 | /api/admin/users |
| GraphQL introspection | N/A | No GraphQL found |
| OpenAPI/Swagger | N/A | No Swagger found |

---

## 6. Authentication Flow Map

### 6.1 Auth Flow Diagram

```
Flow: Login -> Get JWT -> Use JWT for API calls -> Token expiry -> Re-login

Step 1: POST /api/login
  Body: { "email": "user@test.com", "password": "***" }
  Response: { "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", "user": {...} }
  
Step 2: Use JWT
  Header: Authorization: Bearer <token>
  All /api/v2/* endpoints use this for auth
  
Step 3: Token Details
  Decoded JWT: { "sub": "user_id", "iat": timestamp, "exp": timestamp + 24h }
  Algorithm: HS256 (original), accepts "none" (vulnerable!)
  
Step 4: Token Expiry
  Expires: 24 hours after issuance
  No refresh token mechanism
```

### 6.2 Registration Flow

```
Step 1: GET /api/register
  - Returns registration form HTML (or JSON for API)
  
Step 2: POST /api/register
  Body: { "email": "user@test.com", "password": "test123", "password_confirmation": "test123" }
  Response: 201 + { "token": "eyJ...", "user": { "id": 42, "email": "user@test.com" } }
  
Step 3: Email verification (if required)
  - Check email for verification link
  - Click link to activate account
  - Some endpoints may work without verification

Registration Status: Open
Email verification: Required
Rate limit: 10 attempts/IP/minute
Mass assignment: role field accepted!
```

### 6.3 Password Reset Flow

```
Step 1: POST /api/password/reset
  Body: { "email": "user@test.com" }
  Response: { "message": "If the email exists, a reset link has been sent" }
  
Step 2: Check email for reset link
  - Link format: https://target.com/password/reset?token=<6-digit-token>
  - Token type: Numeric, 6 digits
  - Token expiry: 1 hour

Step 3: POST /api/password/reset/confirm
  Body: { "token": "123456", "password": "newpass123", "password_confirmation": "newpass123" }
  Response: 200 + new JWT

Observations:
- Token is 6-digit numeric — only 1,000,000 combinations
- No rate limit on the confirm endpoint!
- Could brute-force the token if you know a victim's email
- Host header injection test needed on step 1
```

### 6.4 OAuth Flow (If Configured)

```
Providers: Google, Apple, Facebook
Endpoints:
  GET /api/auth/providers -> lists available providers
  GET /api/auth/{provider}/url -> returns OAuth authorization URL
  POST /api/auth/{provider}/callback -> handles OAuth callback

Observations:
- OAuth providers are configured but may not be fully implemented in sandbox
- redirect_uri validation to test
- CSRF on OAuth link (no state parameter)
- Account linking CSRF test needed
```

### 6.5 Auth-Specific Vulnerability Assessment

For each authentication-related endpoint, assess specific vulnerability classes:

| Auth Endpoint | Method | Test for | Status | Notes |
|---------------|--------|----------|--------|-------|
| /api/login | POST | SQLi, brute-force, rate limit bypass | Partial — rate limit noted | Test SQLi in email field |
| /api/register | POST | Mass assignment, SQLi, rate limit bypass | Mass assign confirmed | Role field accepted |
| /api/password/reset | POST | Host header injection, token prediction | Not tested | Token is 6-digit numeric |
| /api/password/reset/confirm | POST | Rate limit, token brute-force | Not tested | 1M combinations, no rate limit? |
| /api/auth/providers | GET | Provider list, OAuth flow existence | Not tested | Google/Apple/Facebook |
| /api/auth/{provider}/url | GET | redirect_uri validation | Not tested | Need to test redirect_uri |
| /api/auth/{provider}/callback | POST | Account linking CSRF, token theft | Not tested | State parameter check |
| /api/logout | POST | Session invalidation | Not tested | Does it invalidate server-side? |
| /api/sessions | GET | Session fixation, concurrent sessions | Not tested | Check active sessions list |
| /api/account/email | PUT | Email change without password | Not tested | ATO vector |
| /api/account/password | PUT | Password change without old password | Not tested | ATO vector |

### 6.6 Rate Limiting Assessment

| Endpoint | Rate Limit Observed | Bypass Method | Status |
|----------|-------------------|---------------|--------|
| /api/login | 10 attempts/min/IP | X-Forwarded-For rotation | Not tested |
| /api/register | 10 attempts/min/IP | X-Forwarded-For rotation | Not tested |
| /api/password/reset | Unknown | — | Not tested |
| /api/password/reset/confirm | Unknown | — | Not tested |
| /api/avatar | 100 req/min/IP | — | Observed |
| /api/v2/users/{id}/orders | 100 req/min/IP | — | Observed |
| /api/search | 200 req/min/IP | — | Observed |

Rate limit bypass techniques to try:
- X-Forwarded-For: <different IP>
- X-Real-IP: <different IP>
- X-Client-IP: <different IP>
- Rotate User-Agent headers
- Use IPv6 instead of IPv4
- Use HTTP/2 multiplexing
- Use batch endpoints (GraphQL, batch REST)
- Space requests with random delays

### 6.7 Session Management

| Property | Value | Security Implication |
|----------|-------|---------------------|
| Token type | JWT | Risks: alg:none, weak secret, no rotation |
| Token location | Authorization header | Can't be stolen via XSS as easily as cookies |
| Token expiry | 24 hours | Long window — if stolen, attacker has 24h |
| Refresh token | None | When JWT expires, user must re-login |
| Concurrent sessions | Allowed | No session invalidation on password change |
| Session invalidation on logout | Yes (client-side token delete only) | Token still valid until expiry |

---

## 7. Account & Session Inventory

### 7.1 Active Test Accounts

| Alias | Email | Password | Role | Token/Cookie | Status | Notes |
|-------|-------|----------|------|-------------|--------|-------|
| Attacker A | attacker+1@test.com | testPass123! | user | eyJ... (active) | Active | Primary testing account |
| Victim B | victim+1@test.com | testPass456! | user | eyJ... (active) | Active | Used for IDOR testing |
| Admin C | — | — | admin | — | Needed | No admin account available |

### 7.2 Account Creation Log

| Date | Email | Method | Success? | Notes |
|------|-------|--------|----------|-------|
| 2026-06-05 | attacker+1@test.com | POST /api/register | Yes | Created with + alias |
| 2026-06-05 | victim+1@test.com | POST /api/register | Yes | Created with + alias |

### 7.3 Token/Cookie Current Values

| Account | Token Type | Current Value | Expires | Rotated? |
|---------|-----------|------------|---------|----------|
| Attacker A | JWT | eyJ... | 2026-06-06 | No — last used today |
| Victim B | JWT | eyJ... | 2026-06-06 | No — last used today |

### 7.4 Account Safety Checklist

- [ ] All passwords are unique per target
- [ ] No personal information used in accounts
- [ ] Gmail + alias trick is working
- [ ] Email inbox is accessible for verification links
- [ ] Accounts are logged out after session
- [ ] Passwords rotated if shared across targets

---

## 8. JS Bundle Analysis

### 8.1 Bundle Inventory

| Bundle URL | Size | Source Maps? | Secrets Found | Endpoints Found | Completed? |
|------------|------|-------------|---------------|-----------------|------------|
| /_next/static/chunks/pages/app-abc123.js | 2.3 MB | Yes | 3 API keys | 15 endpoints | Yes |
| /_next/static/chunks/framework-xyz789.js | 500 KB | No | 0 | 0 | Yes |
| /_next/static/chunks/pages/login-def456.js | 150 KB | Yes | 0 | 2 endpoints | Yes |
| /assets/js/main.bundle.js | 800 KB | No | 1 JWT example | 8 endpoints | No |

### 8.2 Key Findings from JS Bundles

```
Bundle: /_next/static/chunks/pages/app-abc123.js

Endpoints Found:
  /api/v2/quote/historical
  /api/v3/cryptocurrency/listings/latest
  /api/v3/user/login
  /api/v3/user/register
  /api/v3/user/password-reset
  /api/v3/user/portfolio/overview
  /api/v3/user/watchlist
  /api/v3/user/transactions
  /api/v3/user/notifications
  /api/v3/user/settings
  /api/v3/user/accounts
  /api/v3/user/swap
  /api/v3/user/orders
  /api/v3/user/balances
  /api/v3/sitemap

Secrets Found:
  - Stripe publishable key: pk_live_XXXXX (UI only, low risk)
  - Google Maps API key: AIzaXXXXX (maybe restricted)
  - Sentry DSN: https://XXXXX@sentry.io/XXXXX (should be safe)

JWT Example:
  Header: {"alg":"HS256","typ":"JWT"}
  Payload: {"sub":"test_user","plan":"hobbyist","iat":1700000000,"exp":1700086400}
  Note: alg is HS256, plan field is interesting
```

### 8.3 Source Map Analysis

```
Bundle: /_next/static/chunks/pages/app-abc123.js.map
Status: Publicly accessible!

Interesting Code Patterns:
  - Line 234: const verifyJWT = (token) => { try { return jwt.verify(token, 'secret123'); } catch { return null; } }
    Note: Hardcoded secret 'secret123' in source! May be test/dev secret.
    
  - Line 567: const adminRoutes = ['/admin/dashboard', '/admin/users', '/admin/settings']
    Note: Admin route cluster discovered
    
  - Line 1023: fetch('/api/internal/v1/reindex', { method: 'POST', headers: {'X-Internal': 'true'} })
    Note: Internal API endpoint discovered in bundle
```

---

## 9. Finding Tracker

### 9.1 Confirmed Findings (Ready to Report)

| # | Bug Class | Severity | CVSS | Endpoint | Status | Priority |
|---|-----------|----------|------|----------|--------|----------|
| 1 | JWT alg:none | High | 8.1 | All authenticated endpoints | Ready to write report | High |
| 2 | — | — | — | — | — | — |

### 9.2 Findings In Progress (Need Validation)

| # | Bug Class | Lead | Endpoint | What's Missing | Last Tested | Priority |
|---|-----------|------|----------|---------------|-------------|----------|
| 1 | SSRF | URL callback | POST /api/avatar | Need internal service access | 2026-06-05 | Medium |
| 2 | IDOR | Enumeration | GET /api/v2/users/{id}/orders | Need to test write operations | 2026-06-05 | Low |
| 3 | Mass Assignment | Role injection | POST /api/register | Need to test if admin actually works | 2026-06-05 | Medium |

### 9.3 Killed Findings (Not Submittable Alone)

| # | Bug Class | Reason | Endpoint | Could Chain With | Date Killed |
|---|-----------|--------|----------|-----------------|-------------|
| 1 | Missing CSP | Always Rejected #1 | All | XSS (if found) | 2026-06-05 |
| 2 | API Key in JS | Q3 — No exploitation | JS bundle | None identified | 2026-06-05 |
| 3 | Open Redirect | Always Rejected #4 | /api/v3/partner/routing | OAuth redirect_uri bypass | 2026-06-05 |

### 9.4 Submitted Findings

| # | Bug Class | Target | Severity | Submitted | Status | Payout |
|---|-----------|--------|----------|-----------|--------|--------|
| — | — | — | — | — | Not submitted | — |

---

## 10. Vulnerability Test Coverage Grid

### 10.1 Bug Class Coverage

| Bug Class | Status | Endpoints Tested | Endpoints To Test | Priority |
|-----------|--------|-----------------|------------------|----------|
| IDOR / BOLA | Partial | orders, profile | accounts, transactions, settings | High |
| Auth Bypass | Partial | /admin/dashboard | /admin/*, /internal/*, /api/v3/admin/* | High |
| SSRF | Confirmed | /api/avatar | cloud metadata, internal services | High |
| XSS (Reflected) | Tested (not vuln) | /search | — | Low |
| XSS (Stored) | Not tested | — | profile bio, comments, support forms | Medium |
| SQLi | Not tested | — | login, search, sort, filter | Medium |
| Business Logic | Not tested | — | coupons, cart, checkout | Medium |
| Mass Assignment | Confirmed | /api/register | /api/account (PUT), /api/settings | High |
| JWT Attacks | Confirmed (alg:none) | All endpoints | HS256/RS256 confusion, JWK injection | High |
| File Upload | Not tested | — | avatar upload (file), document upload | Low |
| Race Conditions | Not tested | — | coupon, checkout, vote | Medium |
| CORS | Not tested | — | /api/* | Low |
| Subdomain Takeover | Not tested | — | CNAME records | Low |
| GraphQL | N/A | — | No GraphQL found | N/A |
| SSTI | Not tested | — | profile bio, error pages | Low |
| OAuth / SSO | Not tested | — | /api/auth/* | Medium |
| Rate Limiting | Partial | /api/register, /api/login | reset password, 2FA | Low |

### 10.2 Coverage Tracking

**Phase 1 Complete:**
- [ ] Subdomain enumeration
- [ ] Live host probing
- [ ] Wayback URL collection
- [ ] JS bundle analysis
- [ ] API endpoint catalog
- [ ] Tech stack fingerprinting

**Phase 2 Complete:**
- [ ] Disclosed report research
- [ ] Tech stack CVE research
- [ ] Threat model creation
- [ ] Mind map creation

**Phase 3 — Bug Classes Tested:**
- [x] JWT Attacks (alg:none confirmed)
- [x] IDOR (orders confirmed, profile tested not vuln)
- [x] SSRF (callback confirmed)
- [x] Auth Bypass (partial)
- [x] Mass Assignment (role accepted in registration)
- [ ] Stored XSS
- [ ] Business Logic
- [ ] Race Conditions
- [ ] SQLi
- [ ] File Upload
- [ ] CORS
- [ ] Subdomain Takeover
- [ ] OAuth / SSO

**Phase 4 Complete:**
- [ ] Reproduce findings 3x
- [ ] Cross-account testing (if applicable)
- [ ] Edge case testing
- [ ] Impact assessment

**Phase 5 Complete:**
- [ ] 5-shot evidence sequence
- [ ] Report drafted
- [ ] 7-Question Gate confirmed
- [ ] Data verified not public
- [ ] Report submitted

---

## 11. Chain Primitive Status

### 11.1 Available Primitives

| # | Primitive | Bug Class | Endpoint | Status | Chain Target |
|---|-----------|-----------|----------|--------|-------------|
| 1 | Open Redirect | Open redirect | /api/v3/partner/routing | Available | OAuth token theft if OAuth found |
| 2 | Self-XSS candidate | Self-XSS | profile bio | Not tested | CSRF chain if CSRF found |
| 3 | JWK endpoint | — | /.well-known/jwks.json | Available | JWT alg confusion (HS256) |

### 11.2 Chain Partners Needed

| Primitive | Needed Partner | Target Chain | Priority | Search Strategy |
|-----------|---------------|-------------|----------|----------------|
| Open Redirect | OAuth redirect_uri validation bypass | OAuth token theft | Medium | Test OAuth providers at /api/auth/* |
| Self-XSS | CSRF on update endpoint | Stored XSS hitting victim | Low | Test CSRF protection on profile update |
| JWT alg:none | JWT admin payload modification | Admin access | High | Already achieved! Next: test admin routes |

### 11.3 Chain Construction Ideas

```
Chain 1: JWT alg:none -> Admin Access -> Stored XSS in admin panel -> Cookie theft
Priority: High
Steps:
  1. Create JWT with alg:none and role:admin
  2. Use admin JWT to access admin panel
  3. Find stored XSS in admin panel features (user management, site settings)
  4. XSS payload steals admin cookies -> full admin access

Chain 2: Open Redirect -> OAuth Token Theft -> Account Takeover
Priority: Medium
Steps:
  1. Test if OAuth providers exist in production
  2. Test redirect_uri validation
  3. If open redirect is on same domain as OAuth callback, chain:
     redirect_uri=https://target.com/partner/routing?url=https://attacker.com
  4. Auth code sent to target.com, then redirected to attacker -> token theft -> ATO

Chain 3: JWT Weak Secret -> Forge Any User -> IDOR All User Data
Priority: High
Steps:
  1. Capture a JWT and crack the HMAC secret (hashcat -m 16500)
  2. Forge JWT as any user (sub: user_id)
  3. Access all user data via IDOR-vulnerable endpoints
  4. Full data breach of all users
```

---

## 11.5 Feature Attack Surface Analysis

Analyze each major application feature for potential vulnerabilities:

### Feature: User Registration
- **Endpoint(s):** POST /api/register
- **Auth Required:** None
- **Inputs:** email, password, password_confirmation, first_name, last_name
- **Accepted Extra Fields:** role, is_admin (mass assignment)
- **Attack Vectors:**
  - Mass assignment: POST with role=admin -> creates admin account
  - Rate limit bypass: X-Forwarded-For rotation -> unlimited registration
  - Email verification bypass: skip verification step -> immediate access
  - Duplicate registration: same email multiple times -> multiple accounts
- **Tested:** Mass assignment confirmed (role field accepted and creates different role)
- **Not Tested:** Rate limit bypass, email verification bypass, duplicate registration

### Feature: Password Reset
- **Endpoint(s):** POST /api/password/reset, POST /api/password/reset/confirm
- **Auth Required:** None
- **Inputs:** email, token, new_password, password_confirmation
- **Attack Vectors:**
  - Host header injection: modify Host header -> reset link points to attacker domain
  - Token prediction: token is 6-digit numeric -> brute-force 1M combinations
  - Rate limit bypass: no rate limit on confirm -> unlimited brute-force attempts
  - Token leakage: token in URL -> Referer header leaks it
  - Token in response: response might contain the token in body or headers
- **Tested:** None
- **Priority:** High (if token is predictable, this is account takeover)

### Feature: Product Search
- **Endpoint(s):** GET /api/search?q=
- **Auth Required:** None
- **Inputs:** q (query), page, sort, size
- **Attack Vectors:**
  - SQL injection: q=test' OR '1'='1
  - NoSQL injection (if MongoDB): q[$ne]=null
  - XSS: q=<script>alert(1)</script> (if reflected)
  - SSRF: q=http://internal/ (if search indexes external content)
- **Tested:** XSS (reflected but context is JSON, not HTML)
- **Not Tested:** SQLi, NoSQLi, SSRF

### Feature: Avatar Upload
- **Endpoint(s):** POST /api/avatar
- **Auth Required:** JWT
- **Inputs:** url (URL to fetch image from)
- **Attack Vectors:**
  - SSRF: url=http://169.254.169.254/latest/meta-data/ (cloud metadata access)
  - SSRF: url=http://127.0.0.1:9200/ (internal Elasticsearch)
  - SSRF: url=file:///etc/passwd (local file inclusion via file:// protocol)
  - SSRF: url=gopher://redis:6379/ (Redis protocol injection)
  - File upload: upload malicious image file (shell in EXIF data)
- **Tested:** SSRF confirmed (DNS callback received)
- **Not Tested:** Cloud metadata, internal services, file protocol, gopher protocol

### Feature: Coupon/Discount Code
- **Endpoint(s):** POST /api/cart/apply-coupon
- **Auth Required:** JWT
- **Inputs:** coupon_code
- **Attack Vectors:**
  - Coupon stacking: apply multiple codes -> >100% discount
  - Race condition: apply same code 20x concurrently -> 20x discount
  - Coupon reuse: use same code after it should be used -> unlimited discount
  - Invalid coupon: expired or non-existent coupon might still work
  - Coupon prediction: guess coupon codes from patterns
- **Tested:** None
- **Priority:** Medium (e-commerce logic bugs pay well)

### Feature: User Profile
- **Endpoint(s):** GET/PUT /api/v2/users/{id}/profile
- **Auth Required:** JWT
- **Inputs:** name, bio, website, avatar_url, social_links
- **Attack Vectors:**
  - IDOR read: access other user's profile by changing ID
  - IDOR write: modify other user's profile by changing ID
  - Stored XSS: bio contains <script> -> executes when other users view profile
  - SSTI: bio contains {{7*7}} -> if template engine renders it, SSTI
  - SSRF: avatar_url=http://internal/ -> fetch internal URL
- **Tested:** IDOR read (403 -> authz working)
- **Not Tested:** IDOR write, stored XSS, SSTI, SSRF

### Feature: Admin Dashboard
- **Endpoint(s):** GET /api/admin/dashboard, /api/admin/users, /api/admin/settings
- **Auth Required:** Should be admin role
- **Attack Vectors:**
  - Auth bypass: direct access without valid admin session
  - Auth bypass: X-Forwarded-For: 127.0.0.1 (IP-based allowlisting)
  - Auth bypass: JWT with role:admin via alg:none attack
  - IDOR: admin endpoints that return all users' data without filtering
  - Privilege escalation: low-privilege user accessing admin endpoints
- **Tested:** Auth bypass via X-Forwarded-For: 127.0.0.1 (confirmed — 200 OK!)
- **Not Tested:** Full admin endpoint enumeration, data access via admin panel

## 12. Pending Investigations

### 12.1 Investigation Tracker

| # | Investigation | Bug Class | Endpoint | Status | Priority | Notes |
|---|--------------|-----------|----------|--------|----------|-------|
| 1 | Test IDOR write operations | IDOR | PUT /api/v2/users/{id}/profile | Not started | High | Could be ATO via email change |
| 2 | SSRF: cloud metadata | SSRF | POST /api/avatar | Needs testing | High | AWS metadata at 169.254.169.254 |
| 3 | JWT alg confusion | JWT | /.well-known/jwks.json | Needs testing | High | RS256 -> HS256 with public key |
| 4 | Admin route enumeration | Auth Bypass | /api/admin/* | Not started | High | Using JWT with admin role |
| 5 | OAuth redirect_uri test | OAuth | /api/auth/* | Not started | Medium | Test redirect_uri validation |
| 6 | Coupon stacking | Business Logic | POST /api/cart/apply-coupon | Not started | Medium | Check if codes stack |
| 7 | Race condition on coupon | Race Condition | POST /api/cart/apply-coupon | Not started | Medium | Concurrent apply |

### 12.2 Investigation Deep Dives

#### Investigation 1: SSRF Cloud Metadata Access
- **Endpoint:** POST /api/avatar
- **Parameter:** url (URL to fetch avatar from)
- **Status:** SSRF confirmed (DNS callback received), cloud metadata not yet tested
- **Steps Remaining:**
  1. Send url=http://169.254.169.254/latest/meta-data/ on AWS
  2. Send url=http://metadata.google.internal/ on GCP  
  3. Send url=http://169.254.169.254/metadata/instance on Azure
  4. If blocked by IP validation, try bypass techniques (decimal, octal, DNS rebinding)
  5. If cloud metadata returns IAM credentials -> Critical finding
- **Expected Impact:** If AWS metadata accessible: IAM credentials, full cloud access (Critical, CVSS 10.0)
- **Blockers:** May be cloud provider specific

#### Investigation 2: JWT RS256 -> HS256 Algorithm Confusion
- **Endpoint:** /.well-known/jwks.json
- **Status:** Public keys found, confusion attack not yet attempted
- **Steps Remaining:**
  1. Retrieve public key from /.well-known/jwks.json
  2. Convert JWK to PEM format
  3. Create JWT with alg: HS256, signed with PEM as HMAC secret
  4. Send to API endpoint with admin payload
  5. If accepted -> account takeover without any secret
- **Expected Impact:** Forge JWT as any user, admin access (Critical, CVSS 9.1)
- **Blockers:** Server must accept HS256 for an RS256 key

#### Investigation 3: IDOR Write Operations
- **Endpoint:** PUT /api/v2/users/{id}/profile
- **Status:** Not tested
- **Steps Remaining:**
  1. As Account A, capture valid session
  2. Try PUT /api/v2/users/VICTIM_ID/profile with modified email
  3. If email changes -> Account Takeover via IDOR write
  4. Also test: role changes, password changes, account deletion
- **Expected Impact:** Account takeover (High, CVSS 8.3)
- **Blockers:** None — accounts are ready

#### Investigation 4: Admin Route Enumeration
- **Endpoint:** /api/admin/* (various)
- **Status:** /api/admin/dashboard accessible via X-Forwarded-For bypass
- **Steps Remaining:**
  1. Enumerate all /api/admin/* endpoints using the X-Forwarded-For bypass
  2. Use ffuf or similar: `ffuf -w endpoints.txt -u https://target.com/api/admin/FUZZ -H "X-Forwarded-For: 127.0.0.1"`
  3. Test each discovered admin endpoint for functionality and data exposure
  4. If admin endpoints have full access -> auth bypass confirmed
- **Expected Impact:** Full admin access (Critical, CVSS 9.3)
- **Blockers:** None — bypass already confirmed

### 12.3 Open Questions

Questions that need answers before proceeding:

| # | Question | Why Important | How to Answer | Status |
|---|----------|---------------|---------------|--------|
| 1 | Does the sandbox have the same auth as production? | alg:none might only work on sandbox | Compare endpoints | Unknown |
| 2 | Is the HMAC secret 'secret123' real or a testing artifact? | If real, we can forge arbitrary tokens | Test against production API | Unknown |
| 3 | Does the admin role actually exist? | Need to know if JWT role escalation works | Access admin routes with admin JWT | Pending |
| 4 | Are there more endpoints behind auth? | More endpoints = more attack surface | Check authenticated JS bundles | Likely |

---

## 13. Session Plan

### 13.1 Current Session Plan

```
SESSION PLAN: YYYY-MM-DD
Target: [target.com]
Expected Duration: [N] hours

Phase Focus: [Recon / Pre-Hunt / Active Hunting / Validation / Reporting]

Objectives (in order):
1. [Primary objective]
2. [Secondary objective]
3. [Tertiary objective]

Time Allocation:
| Time | Activity | Endpoint |
|------|----------|----------|
| 0:00-0:15 | [Setup] | — |
| 0:15-0:45 | [Testing 1] | [endpoint] |
| 0:45-1:15 | [Testing 2] | [endpoint] |
| 1:15-1:45 | [Testing 3] | [endpoint] |
| 1:45-2:00 | [Validation/Evidence] | [endpoint] |

Risks:
- [Risk 1] (mitigation: [how to handle])
- [Risk 2] (mitigation: [how to handle])

Tools to Load:
  - [ ] .\tools\powershell\powershell-lib.ps1
  - [ ] .\tools\powershell\curl-hunter.ps1
  - [ ] .\tools\powershell\fuzzer-toolkit.ps1
  - [ ] .\tools\powershell\evidence-toolkit.ps1
  - [ ] Burp Suite
  - [ ] Python

Accounts Needed:
  - [ ] Account A session active
  - [ ] Account B session active
  - [ ] Burp Collaborator / interact.sh running
```

### 13.2 Session Templates

#### Quick Recon Session (30 min)
Use when you have limited time but want to check a new target quickly:
```
SESSION PLAN: Quick Recon — [target.com]
Expected Duration: 30 minutes

Phase Focus: Recon (Phase 1)

Objectives:
1. Subdomain passive enumeration (5 min)
2. Wayback URL collection (5 min)
3. JS bundle identification and download (10 min)
4. Tech stack fingerprinting (5 min)
5. Quick endpoint extraction from JS (5 min)

Deliverables:
- Subdomain list (discovered.txt)
- URL list (urls.txt)
- JS bundle list (bundles.txt)
- Tech stack notes
- Top 3 interesting endpoints
```

#### Deep Hunt Session (3 hours)
```
SESSION PLAN: Deep Hunt — [target.com]
Expected Duration: 3 hours

Phase Focus: Active Hunting (Phase 3)

Objectives:
1. JWT attacks (10 min)
2. Auth bypass (15 min)
3. IDOR — all object ID endpoints (30 min)
4. SSRF — all URL fetch features (30 min)
5. Stored XSS — all user content endpoints (30 min)
6. Business logic — coupons, cart, checkout (30 min)
7. SQLi — search, filter, sort (15 min)
8. Mass assignment — all create/update endpoints (20 min)

Time Allocation:
  | 0:00-0:10 | Load tools, validate accounts, setup Burp Collaborator
  | 0:10-0:20 | JWT: alg:none, HS256 confusion, JWK injection
  | 0:20-0:35 | Auth bypass: admin endpoints, X-Forwarded-For, HEAD/OPTIONS
  | 0:35-1:05 | IDOR: Sequential enum on all object ID endpoints
  | 1:05-1:35 | SSRF: Cloud metadata, internal services, protocol switch
  | 1:35-2:05 | Stored XSS: Profile, comments, support forms, bio
  | 2:05-2:35 | Business logic: Coupons, cart manipulation, workflow skip
  | 2:35-2:50 | SQLi: Error-based, time-based on search/filter/sort
  | 2:50-3:00 | Mass assignment: Extra fields on create/update endpoints
```

#### Validation + Evidence Session (1 hour)
Use when you have confirmed findings and need to capture evidence:
```
SESSION PLAN: Evidence Capture — [target.com]
Expected Duration: 1 hour

Phase Focus: Validation + Evidence (Phase 4/5)

Objectives:
1. Reproduce finding 3x with clean state (15 min)
2. Capture 5-shot evidence sequence (20 min)
3. Cross-account verification (10 min)
4. Impact assessment and CVSS scoring (10 min)
5. Draft report (5 min)

Evidence Checklist:
- [ ] Screenshot 1: Setup (auth state)
- [ ] Screenshot 2: Request (malicious request)
- [ ] Screenshot 3: Before (baseline)
- [ ] Screenshot 4: Exploit (vulnerability result)
- [ ] Screenshot 5: Verify (scope/reproducibility)
- [ ] HAR file (sanitized)
- [ ] Video (if needed for complex chains)
```

### 13.3 Session Plan for Next Session

```
SESSION PLAN: 2026-06-07
Target: coinmarketcap.sandbox
Expected Duration: 2 hours

Phase Focus: Active Hunting + Validation

Objectives:
1. SSRF: Confirm cloud metadata access (Critical path)
2. JWT: Test HS256/RS256 confusion (High payout)
3. IDOR: Test write operations (PATCH/PUT/DELETE)

Time Allocation:
  | 0:00-0:10 | Load tools, validate accounts active, start Burp Collaborator
  | 0:10-0:30 | SSRF: Send metadata payloads (169.254.169.254)
  | 0:30-0:50 | JWT: Test HS256 confusion with public key from /.well-known/jwks.json
  | 0:50-1:10 | IDOR: Test PUT on /api/v2/users/{id}/profile
  | 1:10-1:30 | SSRF: Internal service discovery if metadata fails
  | 1:30-1:50 | Validation: Reproduce and capture evidence for any confirmed findings
  | 1:50-2:00 | Session review and log update

Tools to Load:
  - [x] .\tools\powershell\powershell-lib.ps1
  - [x] .\tools\powershell\curl-hunter.ps1
  - [ ] Burp Suite (must have Collaborator running)
  - [ ] Python (for JWT manipulation)
  - [ ] interact.sh (backup for SSRF callbacks)

Accounts Needed:
  - [x] Account A (attacker+1@test.com) — session valid
  - [x] Account B (victim+1@test.com) — session valid
  - [ ] Burp Collaborator URL: [GET FROM BURP]
  - [ ] interact.sh URL: [CREATE IF BURP COLLAB FAILS]

Risks:
  - Sandbox may not have AWS metadata (different cloud provider) -> try GCP + Azure too
  - JWK endpoint may return test keys that don't work -> check key usage
  - Rate limiting on write operations -> wait and retry
  - Sandbox may have different auth than production -> note differences

Contingency:
  - If SSRF metadata fails, try internal service discovery (Redis 6379, ES 9200)
  - If JWT confusion fails, move to mass assignment exploitation
  - If IDOR write fails, test IDOR read on more endpoints
```

---

## 14. Quick Reference

### 14.1 Key Commands

```powershell
# Load tools
. .\tools\powershell\powershell-lib.ps1
. .\tools\powershell\curl-hunter.ps1

# Test endpoint
Test-Endpoint -Url "https://api.target.com/api/v2/users/42"

# IDOR enumeration
Test-IDOR -BaseUrl "https://api.target.com/api/v2/users" -SessionCookie "session=XYZ" -StartId 1 -EndId 1000

# SSRF test
Test-SSRF -TargetUrl "https://api.target.com/api/avatar" -ParameterName "url" -CallbackUrl "http://YOUR.oastify.com"

# JWT decode/debug
python tools/python/python-hunter.py decode --jwt "eyJ..."
```

### 14.2 Key URLs

| URL | Purpose |
|-----|---------|
| https://target.com | Main site |
| https://api.target.com | API server |
| https://target.com/.well-known/jwks.json | Public JWK keys |
| https://webhook.site/#!/YOUR-UUID | Callback collector |
| https://jwt.io/ | JWT debugger |
| https://target.com/robots.txt | Disallowed paths |
| https://target.com/sitemap.xml | All pages |

### 14.3 Key Payloads

```
# JWT alg:none
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.

# SSRF AWS metadata
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# SSRF GCP metadata
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Mass assignment admin
{"email":"test@test.com","password":"test","role":"admin","is_admin":true}
```

---

## 15. Session History

### 15.1 Session Log

| # | Date | Duration | Phase | Findings Found | Findings Killed | Notes |
|---|------|----------|-------|---------------|----------------|-------|
| 1 | 2026-06-05 | 8h | 1, 2, 3 | 4 (JWT, SSRF, Open Redirect, Missing CSP) | 3 | Heavy recon session. JS analysis productive. |
| 2 | — | — | — | — | — | — |
| 3 | — | — | — | — | — | — |

### 15.2 Session Details

**Session 1: 2026-06-05 (8 hours)**
- Phase: Recon + Pre-Hunt + Active Hunting
- Completed: Subdomain enum, JS bundle analysis (8 files), endpoint catalog (45+ endpoints)
- Found: JWT alg:none, SSRF callback, open redirect, missing CSP, API key in JS
- Killed: Open redirect (chain primitive), missing CSP (always rejected), API key (Q3 no PoC)
- Submitted: 0
- Next: SSRF cloud metadata, JWT alg confusion, IDOR write ops
- Tags: #session-1 #recon #jwt

---

### Tool-Specific Acceleration Tips

**Burp Suite:**
- Use "Copy as curl command" for quick evidence capture
- Use "Copy to file" in Repeater for saving request/response pairs
- Set scope to target-only to reduce noise
- Use Intruder with Pitchfork attack type for multi-parameter IDOR
- Use Collaborator for SSRF and blind XSS
- Use the "Sitemap" tab to track all discovered endpoints

**PowerShell:**
- Use `.\tools\powershell\jiggy.ps1` CLI for quick requests
- Dot-source tools once, then call functions directly
- Use `$session` variable for cookie persistence
- Use `$results` array to collect multiple test results
- Use parameter splatting for complex requests

**Python:**
- Use `python tools/python/python-hunter.py` for batch processing
- Use `api` module for session management across multiple requests
- Use `SecretScanner` for JS bundle analysis
- Use `EndpointFuzzer` for mass parameter testing

**curl.exe:**
- Use `-v --insecure` for verbose debug
- Use `-b cookies.txt -c cookies.txt` for session persistence
- Use `-H "Cookie: session=..."` for manual auth
- Use `--data-raw` for exact request bodies

## Active Target Maintenance

- **Last Updated:** [YYYY-MM-DD HH:MM]
- **Current Phase:** [Phase N]
- **Next Action:** [Immediate next step]

### End-of-Session Checklist

After every session, complete this checklist:
- [ ] Kill all findings that fail the 7-Question Gate
- [ ] Update finding tracker with new findings and statuses
- [ ] Update coverage grid (what was tested, what wasn't)
- [ ] Add evidence package to any confirmed findings
- [ ] Log session in session history
- [ ] Rotate test account passwords
- [ ] Log out of all sessions
- [ ] Clear browser cookies for target domain
- [ ] Close Burp project (save if needed)
- [ ] Kill Burp Collaborator / interact.sh sessions
- [ ] Update memory/ files (target-registry, lessons-log)
- [ ] Note next actions for next session

### Before Next Session
- [ ] Review findings in progress
- [ ] Check if tokens/sessions are still valid
- [ ] Review pending investigations
- [ ] Confirm program is still active
- [ ] Check for any new features or changes
- [ ] Review disclosed reports for similar targets
- [ ] Refresh any expired tokens
