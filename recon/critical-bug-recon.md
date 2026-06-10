---
name: critical-bug-recon
description: Reconnaissance methodology specifically targeting critical and high severity bugs. Maps recon outputs to high-probability bug classes: IDOR, SSRF, auth bypass, RCE, XSS, race conditions, business logic flaws, file upload bugs, API misconfigs, and SSTI. Use after initial recon to prioritize assets and hunt for P1 findings.
---

# Critical Bug Reconnaissance

## Purpose

Standard recon maps attack surface. This file maps attack surface to **critical/high bug likelihood**. The goal is to identify which assets, features, and patterns are most likely to yield P1-P2 findings before active hunting begins.

---

## Bug Class → Recon Mapping

Recon outputs are not equal. Below is how to interpret recon data to find high-severity bugs.

---

### 1. IDOR (Insecure Direct Object Reference)

**Likely Critical When:**
- API endpoints with sequential IDs: `/api/user/123`, `/api/order/456`, `/api/invoice/789`
- File download endpoints with IDs: `/download?file=123`, `/api/report/pdf/456`
- UUID-based resources that might be guessable
- GraphQL queries with object IDs that can be modified

**Recon Signals:**
```
1. Extract all numeric IDs from URLs
2. Look for patterns: /api/v1/resource/{number}
3. Check for GraphQL introspection on ID-returning queries
4. Find file serving endpoints: /files/{id}, /downloads/{id}
5. Look for reference parameters: ?userId=, ?accountId=, ?invoiceId=
```

**Commands:**
```bash
# Extract numeric IDs from URLs
cat all-urls.txt | grep -oP '/api/[a-zA-Z0-9/-]+/\d+' | sort -u

# Find file download patterns
cat all-urls.txt | grep -iE 'download|file|document|report' | sort -u

# Find GraphQL IDOR potential
cat all-urls.txt | grep -i graphql | sort -u
```

---

### 2. SSRF (Server-Side Request Forgery)

**Likely Critical When:**
- URL fetch endpoints: `?url=`, `?link=`, `?uri=`, `?redirect=`, `?callback=`
- Webhook registration endpoints
- PDF/document generators that accept URLs
- Image processing with external URLs
- File import features from URLs

**Recon Signals:**
```
1. Search for URL-accepting parameters in all URLs
2. Find webhook endpoints: /webhook, /callback, /notify
3. Look for PDF/doc generation: /generate, /export, /preview
4. Find image proxy or processing features
5. Check for OAuth redirect URIs that might be SSRF-able
```

**Commands:**
```bash
# Find SSRF-prone parameters
cat all-urls.txt | unfurl -k params | sort -u | grep -iE 'url|link|uri|redirect|fetch|proxy|webhook|callback|target|uri'

# Find webhook/notification endpoints
cat all-urls.txt | grep -iE 'webhook|callback|notify|ping|import' | sort -u

# Find PDF/doc generation
cat all-urls.txt | grep -iE 'pdf|generate|export|document' | sort -u
```

---

### 3. Authentication Bypass / Broken Auth

**Likely Critical When:**
- OAuth implementations with misconfigured redirect URIs
- Password reset endpoints without proper rate limiting
- Login endpoints with suspicious parameters
- JWT endpoints with weak validation
- Admin panels reachable without auth or with default creds

**Recon Signals:**
```
1. Find all auth-related endpoints
2. Look for OAuth client_id and redirect_uri parameters
3. Check for JWT in URLs or JS files
4. Look for admin paths: /admin, /dashboard, /internal, /manage
5. Find password reset with predictable tokens
```

**Commands:**
```bash
# Find auth endpoints
cat all-urls.txt | grep -iE 'login|oauth|auth|reset|forgot|signin|sso' | sort -u

# Find admin/internal panels
ffuf -u https://target.com/FUZZ -w /path/to/admin-panels.txt -fc 404 -o admin-panels.json

# Extract OAuth client IDs
cat all-urls.txt | grep -oP 'client_id=[A-Za-z0-9_-]+' | sort -u

# Find JWT tokens in JS
cat js-secrets.txt | grep 'eyJ' | head -20
```

---

### 4. Remote Code Execution (RCE)

**Likely Critical When:**
- File upload endpoints without validation
- Deserialization endpoints
- Template engines: Jinja2, Twig, Freemarker, ERB
- SSRF chained with cloud metadata
- Command injection in old frameworks

**Recon Signals:**
```
1. Find all file upload endpoints
2. Look for deserialization: ?data=, ?payload=, base64 in params
3. Identify template engines from tech stack
4. Check for `/api/execute`, `/api/run`, `/api/command` endpoints
5. Look for GraphQL mutations that execute code
```

**Commands:**
```bash
# Find file upload endpoints
cat all-urls.txt | grep -iE 'upload|import|file' | grep -iE 'post|put' | sort -u

# Find deserialization patterns
cat all-urls.txt | unfurl -k params | grep -iE 'data|payload|serialize|object|json|base64'

# Find template injection possibility (from tech stack)
cat tech-stack.txt | grep -iE 'jinja|twig|freemarker|erb|velocity|thymeleaf|smarty'
```

---

### 5. XSS (Cross-Site Scripting)

**Likely High When:**
- Reflection of parameters in responses
- DOM sinks in JS: `innerHTML`, `document.write`, `eval()`
- Upload endpoints that allow HTML/SVG uploads
- Rich text editors with insufficient sanitization
- JSON endpoints with unescaped output

**Recon Signals:**
```
1. Find parameters that reflect in page content
2. Extract all innerHTML/document.write/eval from JS
3. Find file uploads that accept HTML/SVG
4. Look for markdown/render endpoints
5. Check for JSONP callbacks
```

**Commands:**
```bash
# Find reflective parameters (manual testing required)
cat all-urls.txt | grep '\?' | sort -u | head -100

# Find DOM sinks in JS
cat all-js-urls.txt | while read js; do
  curl -s "$js" | grep -oP '(innerHTML|document\.write|\.html\(|dangerouslySetInnerHTML|eval\()'
done | sort -u
```

---

### 6. Race Conditions

**Likely High When:**
- Coupon/ voucher apply endpoints
- Balance/credit/points deduction endpoints
- Stock/inventory management
- Account limits: password reset, login attempt limits
- Rate limiting bypass possibilities

**Recon Signals:**
```
1. Find balance/transaction endpoints
2. Look for coupon/promo code application
3. Check for registration/login endpoints with duplicate constraints
4. Find withdrawal points
5. Look for voting/like endpoints with single-use tokens
```

---

### 7. Business Logic Flaws

**Likely High When:**
- Multi-step checkout/workflows
- Price manipulation: negative quantities, bulk discounts
- Privilege escalation paths in role changes
- State machine bypass: cancelled orders still process
- Free item with expired coupon

**Recon Signals:**
```
1. Map complete checkout/purchase flows
2. Find price/quantity parameters
3. Look for role/permission endpoints
4. Find order status transitions
5. Look for time-based logic: expiry, schedule
```

---

### 8. File Upload Vulnerabilities

**Likely Critical When:**
- Accepts images but doesn't validate magic bytes
- Allows SVG/HTML uploads (XSS)
- Path traversal in filenames
- Upload to webroot
- No file size limits

**Recon Signals:**
```
1. Find all upload endpoints
2. Check allowed extensions from responses or JS
3. Look for web-accessible upload directories
4. Check for filename override parameters
5. Find image processing features
```

---

### 9. API Misconfigurations

**Likely High When:**
- GraphQL introspection enabled
- Missing authentication on sensitive mutations
- Mass assignment: JSON body with unexpected fields
- HTTP verb tampering: PUT where POST expected
- CORS misconfiguration: wildcard origin with credentials

**Recon Signals:**
```
1. Check GraphQL introspection on all endpoints
2. Test PUT/DELETE on POST-only endpoints
3. Find CORS headers: Access-Control-Allow-Origin
4. Check mass assignment by adding unexpected fields
5. Look for API versioning: /v1, /v2, /internal
```

---

### 10. SSTI (Server-Side Template Injection)

**Likely Critical When:**
- Template engines identified: Jinja2, Twig, Freemarker, ERB, Velocity, Mako, Thymeleaf, Smarty, Pug
- Custom template features in CMS
- Error messages revealing template syntax
- Template parameters in URLs or forms

**Recon Signals:**
```
1. Identify template engine from tech stack
2. Find features that use templates: email, PDF, pages
3. Look for template-related parameters
4. Check for template in error messages
```

---

## Asset Prioritization for P1 Hunting

Not all assets found during recon are equal. Prioritize as follows:

### Tier 1 (Hunt First)
- **New assets** (created in last 30 days) — often have undiscovered bugs
- **Admin/Internal panels** — less hardened, more sensitive functionality
- **API endpoints with CRUD operations** — IDOR, mass assignment, auth bypass
- **File upload/download features** — RCE, path traversal, XSS
- **Authentication systems** — OAuth, SSO, password reset — auth bypass goldmine
- **Older frameworks with known CVEs** — nmap -sV + version match = instant win

### Tier 2 (Hunt Second)
- **Payment/subscription endpoints** — business logic flaws, race conditions
- **User profile management** — IDOR, XSS, stored attacks
- **GraphQL endpoints** — introspection, batching, query depth
- **Redirect/URL fetch features** — SSRF, open redirect
- **Search functionality** — reflected attacks, injection

### Tier 3 (Hunt Last)
- Static marketing pages
- CDN-hosted assets
- Documentation/wiki sites
- Public status pages

---

## Recon → Hunt Workflow Integration

### Step 1: Tag Recon Output
After standard recon, tag each URL/asset with likely bug classes:

```
URL: https://api.target.com/v1/user/123/profile
Likely Bugs: [IDOR, BOLA]
Priority: TIER 1

URL: https://app.target.com/api/graphql
Likely Bugs: [GraphQL introspection, IDOR in queries]
Priority: TIER 1

URL: https://target.com/admin/login
Likely Bugs: [Auth bypass, default creds]
Priority: TIER 1
```

### Step 2: Run Bug-Class-Specific Recon
For each Tier 1 asset, run targeted recon:

```bash
# For IDOR hunting
cat api-urls.txt | sort -u > idor-targets.txt

# For SSRF hunting
cat ssrf-prone-urls.txt >> ssrf-targets.txt

# For auth bypass
cat auth-endpoints.txt >> auth-bypass-targets.txt
```

### Step 3: Hunting Sequence
1. **Quick wins first** — check for exposed keys, default creds, known CVEs
2. **Logic flaws second** — race conditions, business logic
3. **Injection/Code exec third** — XSS, SSTI, deserialization
4. **Auth complex flows last** — OAuth chain, MFA bypass

---

## Quick Win Recon Commands

### Exposed Credentials (5 minutes)
```bash
# GitHub recon
gh search code "target.com" --limit 30 | grep -iE 'api.key|password|secret|token|credential'

# JS secrets
cat js-urls.txt | while read url; do
  curl -s "$url"
done | grep -oP '(?:api[_-]?key|api[_-]?secret|access[_-]?token|secret[_-]?key|password)[=:]["'"'"'][^"'"'"]+["'"'"']'
```

### Exposed Admin Panels (5 minutes)
```bash
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/admin-panel.txt -fc 404
```

### GraphQL Introspection (2 minutes)
```bash
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}'
```

### Common CVEs (10 minutes)
```bash
# Use nuclei with critical templates
nuclei -l live-hosts.txt -t ~/nuclei-templates/cves/ -severity critical -o cves-critical.txt

# Check for specific framework versions
nuclei -l live-hosts.txt -t ~/nuclei-templates/exposures/ -severity high -o exposures-high.txt
```

---

## Recon by Bug Class Checklist

Use this checklist during recon to ensure no high-value hunting grounds are missed:

### IDOR Hunting Recon
- [ ] All API endpoints with numeric IDs extracted
- [ ] GraphQL queries with object IDs found
- [ ] File download endpoints with IDs found
- [ ] Sequential vs UUID ID pattern analyzed

### SSRF Hunting Recon
- [ ] All URL-accepting parameters found
- [ ] Webhook/callback endpoints identified
- [ ] PDF/doc generators with URL inputs found
- [ ] Image processing with external URLs found
- [ ] Cloud metadata endpoints discovered (169.254.169.254)

### Auth Bypass Recon
- [ ] Login endpoints documented
- [ ] Password reset flow mapped
- [ ] OAuth/OIDC endpoints found
- [ ] JWT locations in URLs/JS/cookies found
- [ ] Admin panels identified
- [ ] Default credential checks run

### RCE Hunting Recon
- [ ] File upload endpoints documented
- [ ] Template engines identified from tech stack
- [ ] Deserialization endpoints found
- [ ] API execution endpoints found (`/run`, `/execute`)
- [ ] Cloud metadata exposure checked

### XSS Hunting Recon
- [ ] Reflective parameter extraction completed
- [ ] DOM sinks extracted from all JS bundles
- [ ] Upload endpoints allowing HTML/SVG found
- [ ] JSON endpoints with unescaped output found

### API Misconfig Recon
- [ ] GraphQL introspection checked on all endpoints
- [ ] CORS headers analyzed on all origins
- [ ] HTTP verb tampering tested on API endpoints
- [ ] Mass assignment fields guessed from API docs/JS

---

## Output Format: P1 Attack Surface

After applying this methodology, produce:

```
target-p1-surface/
├── tier1-assets/
│   ├── idor-potential.txt
│   ├── ssrf-prone.txt
│   ├── auth-bypass-targets.txt
│   ├── rce-potential.txt
│   ├── xss-vectors.txt
│   ├── graphql-endpoints.txt
│   ├── file-upload-endpoints.txt
│   └── api-misconfig-tests.txt
├── quick-wins/
│   ├── exposed-keys.txt
│   ├── default-creds.txt
│   ├── known-cves.txt
│   └── exposed-panels.txt
└── hunting-priority.md
```

---

## Key Principles for Critical Bug Recon

1. **Bug class drives recon, not just asset discovery** — know what you're hunting before you crawl
2. **Technology stack predicts bug class** — old PHP = RCE/SQLi, modern JS framework = client-side bugs, GraphQL = IDOR/introspection
3. **New code = new bugs** — prioritize assets launched in last 90 days
4. **Complexity = bugs** — multi-step flows, integrations, and legacy migrations are high-value
5. **Trust boundaries = gold** — any point where data/traffic crosses a trust boundary is a potential exploit
6. **Cross-reference recon outputs** — a subdomain with both file upload AND a known old framework version = prioritize
7. **Never skip the boring stuff** — default creds on a Jenkins instance, exposed AWS keys — these are the 5-minute wins that pay rent
