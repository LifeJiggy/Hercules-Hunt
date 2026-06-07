---
name: storage-tool-outputs
description: Raw tool output storage and indexing for Jiggy-2026. Every command run, every scan output, every discovery from tooling is recorded here. Organized by tool category with summaries, raw output references, and cross-links to leads and findings.
---

# Tool Outputs

This file stores the output of every recon and hunting tool. Each entry includes the command run, a summary of findings, and references to the raw output file. Tool outputs are the raw material from which leads are identified and findings are built.

---

## 1. Tool Output Organization

```
├── Subdomain Enumeration
├── DNS Resolution
├── HTTP Probing
├── URL Crawling
├── Directory Fuzzing
├── Technology Fingerprinting
├── Port Scanning
├── Vulnerability Scanning
├── JavaScript Analysis
├── Manual Testing
└── Custom Scripts
```

Each section is organized by target, then by date.

---

## 2. Target: target.com

### Subdomain Enumeration

```
=== subfinder (Passive) ===
Date: 2026-03-15
Target: target.com
Command: subfinder -d target.com -all -o outputs/subfinder-passive.txt
Duration: 45 seconds
Total Results: 1,247 subdomains

Notable Discoveries:
  admin.target.com          → 203.0.113.10  (Cloudflare)
  api.target.com            → 203.0.113.11  (Cloudflare)
  dev.target.com            → 203.0.113.12  (Direct — no WAF)
  staging.target.com        → 203.0.113.13  (Direct — no WAF)
  vault.target.com          → 203.0.113.14  (Direct — no WAF)
  jenkins.target.com        → 203.0.113.15  (Direct — no WAF)
  graphql.target.com        → 203.0.113.16  (Cloudflare)
  ws.target.com             → 203.0.113.17  (Cloudflare)
  m.target.com              → 203.0.113.18  (Cloudflare)
  internal.target.com       → 10.0.10.5     (Private IP — INTERNAL)

Interesting Patterns:
  - *.dev.target.com → 7 subdomains not behind Cloudflare
  - *.staging.target.com → 5 subdomains not behind Cloudflare
  - Internal DNS names revealed: db.internal, redis.internal, api.internal
  - Old subdomains: v1.api.target.com (deprecated?)

Raw Output: outputs/subfinder-passive.txt (1,247 lines)

=== crt.sh (Certificate Transparency) ===
Date: 2026-03-15
Target: target.com
Command: curl -s 'https://crt.sh/?q=%25.target.com&output=json' | jq -r '.[].name_value' | sort -u
Duration: 10 seconds
Total Results: 892 certificates, 156 unique subdomains

New Subdomains Not in subfinder:
  *.backup.target.com       → not resolving (may be stale)
  *.eu.target.com            → 203.0.113.20  (AWS)
  *.cdn.target.com           → 203.0.113.21  (Cloudflare)
  *.static.target.com        → 203.0.113.22  (Cloudflare — CDN?)
  *.r53.target.com           → Route53 domain (pinned)

Certificate Details:
  - Most certs issued by Let's Encrypt
  - Wildcard: *.target.com (issued 2026-01-15, expires 2026-04-15)
  - *.admin.target.com has separate cert (more strict issuance?)

Raw Output: outputs/crtsh-target.com.txt (156 lines)

=== DNS Brute Force (active) ===
Date: 2026-03-15
Target: target.com
Wordlist: subdomains-top1million-5000.txt (5,000 entries)
Command: dnsx -d target.com -w wordlist.txt -r resolvers.txt -o outputs/dnsx-brute.txt
Duration: 2 minutes
Total Results: 342 resolved subdomains

Notable New Finds:
  console.target.com        → 203.0.113.30  (Admin panel?)
  dashboard.target.com      → 203.0.113.31  (Dashboard)
  partner.target.com        → 203.0.113.32  (Partner portal)
  corporate.target.com      → 203.0.113.33  (Corporate site)
  blog.target.com           → 203.0.113.34  (Ghost CMS)

Raw Output: outputs/dnsx-brute.txt (342 lines)
```

### DNS Resolution Details

```
=== Resolved Subdomains (dnsx) ===
Date: 2026-03-15
Target: all-subdomains.txt (1,745 unique)
Command: dnsx -l all-subdomains.txt -a -cname -o outputs/dnsx-resolved.txt
Duration: 1 minute
Total Results: 892 resolved

CNAME Records (CDN Detection):
  www.target.com            → target.com.cdn.cloudflare.net (Cloudflare)
  api.target.com             → target.com-123456.us-east-1.elb.amazonaws.com (ALB)
  admin.target.com           → target.com-123456.us-east-1.elb.amazonaws.com (ALB)
  cdn.target.com             → target.com.cdn.cloudflare.net (Cloudflare)
  blog.target.com            → target.com-ghost.ghost.io (Ghost hosted)

Private IPs (Internal):
  internal.target.com       → 10.0.10.5 (VPC internal)
  db.internal.target.com    → 10.0.20.10 (Database tier)
  redis.internal.target.com → 10.0.20.20 (Cache tier)

Raw Output: outputs/dnsx-resolved.txt (892 lines)
```

### HTTP Probing

```
=== Live Host Detection (httpx) ===
Date: 2026-03-15
Target: resolved-subdomains.txt (892 hosts)
Command: httpx -l resolved.txt -title -tech-detect -status-code -content-length -o outputs/httpx-live.txt
Duration: 5 minutes
Total Results: 312 live hosts (200/301/302/401/403)

Live Hosts by Status:
  200: 189 hosts
  301: 43 hosts (redirects)
  302: 12 hosts (redirects with params)
  401: 28 hosts (auth required)
  403: 32 hosts (forbidden — interesting!)
  404: 8 hosts (custom 404 pages)

Notable 403s (Potential IDOR/Bypass):
  https://admin.target.com/settings     → 403 (should exist, just restricted)
  https://admin.target.com/users        → 403 (should exist)
  https://api.target.com/v2/admin       → 403 (admin API)
  https://staging.target.com/debug      → 403 (debug endpoint exists!)

Technology Breakdown:
  React:       189 hosts (SPA)
  Express:     156 hosts (Node.js API)
  Cloudflare:  245 hosts (WAF/CDN)
  AWS ALB:     67 hosts (Load balancer)
  Ghost CMS:   3 hosts (Blog)
  Nginx:       34 hosts (Static assets)

Title Highlights:
  "Admin Panel — target.com" → admin.target.com (confirmed admin)
  "Jenkins — target.com" → jenkins.target.com (CI/CD!)
  "Target API v2" → api.target.com
  "GraphQL Playground — target.com" → graphql.target.com
  "Kibana — target.com" → kibana.target.com (Logs!)
  "Prometheus — target.com" → prometheus.target.com (Metrics!)
  "Grafana — target.com" → grafana.target.com (Monitoring)

Raw Output: outputs/httpx-live.txt (312 lines)
```

### URL Crawling

```
=== Wayback URLs (gau) ===
Date: 2026-03-15
Target: target.com and subdomains
Command: cat live-hosts.txt | gau -o outputs/gau-urls.txt
Duration: 3 minutes
Total Results: 45,678 URLs

Unique Endpoints:
  /api/v2/auth/*           → 12 endpoints
  /api/v2/users/*          → 8 endpoints
  /api/v2/invoices/*       → 7 endpoints
  /api/v2/admin/*          → 15 endpoints
  /api/v2/coupons/*        → 5 endpoints
  /api/v2/support/*        → 4 endpoints
  /graphql                 → GraphQL endpoint
  /api/v1/*                → 20 endpoints (deprecated?)

Parameters Found (unique):
  id, userId, invoiceId, token, email, url, redirect, 
  page, limit, cursor, search, q, query, code, coupon,
  status, type, role, sort, order, filter

Interesting Wayback Finds:
  /api/v1/admin/users (deprecated? Still works?)
  /api/v2/debug/env (environment variables?)
  /api/v2/health/db (database health — info disclosure)
  /api/v2/swagger.json (API docs — swagger!)
  /api/v2/openapi.json (OpenAPI spec — possible)

Raw Output: outputs/gau-urls.txt (45,678 lines)

=== Active Crawling (katana) ===
Date: 2026-03-15
Target: live-hosts.txt (top 50)
Command: katana -list top50.txt -d 3 -jc -kf -o outputs/katana-crawl.txt
Duration: 10 minutes
Total Results: 12,345 URLs

New Endpoints Discovered:
  /api/v2/internal/health (internal health — more detail than /health)
  /api/v2/feature-flags (all feature flags!)
  /api/v2/admin/impersonate (impersonation endpoint!)
  /api/v2/admin/billing (billing data)
  /api/v2/metrics (Prometheus metrics endpoint)
  /api/v2/debug/cache (cache debug — Redis info?)

JavaScript Files Found:
  /assets/main.abc123.js       (2.4 MB)
  /assets/vendor.def456.js     (1.8 MB)
  /assets/admin.ghi789.js      (480 KB)
  /assets/graphql.jkl012.js    (120 KB)
  /assets/swagger-ui.js        (Swagger UI — confirms API docs)

Raw Output: outputs/katana-crawl.txt (12,345 lines)
```

### Directory Fuzzing

```
=== Directory Discovery (ffuf) ===
Date: 2026-03-15
Target: https://target.com
Wordlist: common.txt (4,700 entries)
Command: ffuf -u https://target.com/FUZZ -w common.txt -mc 200,204,301,302,401,403 -o outputs/ffuf-dirs.json
Duration: 2 minutes
Total Results: 45 directories

Interesting Directories:
  /admin          → 200 (Admin panel — login page)
  /api            → 200 (API docs page)
  /graphql        → 200 (GraphQL playground)
  /health         → 200 (Health check — JSON)
  /metrics        → 200 (Prometheus metrics)
  /swagger        → 200 (Swagger UI)
  /docs           → 200 (API docs)
  /debug          → 403 (Forbidden — exists!)
  /backup         → 404 (Not found)
  /.git           → 404 (Not exposed — good)
  /sitemap.xml    → 200 (Sitemap — useful for endpoint discovery)
  /robots.txt     → 200 (Robots — check for disallowed paths)

=== Recursive Fuzzing on /admin ===
Date: 2026-03-15
Target: https://target.com/admin
Wordlist: raft-large-directories.txt (50,000 entries)
Command: ffuf -u https://target.com/admin/FUZZ -w raft-large.txt -mc 200,401,403 -o outputs/ffuf-admin.json
Duration: 10 minutes
Total Results: 28 paths

Admin Directories:
  /admin/login         → 200 (Login page)
  /admin/users         → 403 (Forbidden — no access)
  /admin/settings      → 403 (Forbidden)
  /admin/logs          → 403 (Forbidden — but exists!)
  /admin/audit         → 403 (Forbidden)
  /admin/impersonate   → 403 (Forbidden)
  /admin/reports       → 403 (Forbidden)
  /admin/billing       → 403 (Forbidden)
  /admin/coupons       → 403 (Forbidden)

=== API Fuzzing (ffuf) ===
Date: 2026-03-15
Target: https://api.target.com
Wordlist: api-endpoints.txt (2,000 entries)
Command: ffuf -u https://api.target.com/FUZZ -w api-endpoints.txt -mc 200,201,204,401,403 -o outputs/ffuf-api.json
Duration: 3 minutes
Total Results: 34 endpoints

API Endpoints:
  /api/v2/auth/login          → 200
  /api/v2/auth/register       → 200
  /api/v2/auth/logout         → 204
  /api/v2/auth/reset-password → 200
  /api/v2/users/me            → 200 (when authenticated)
  /api/v2/invoices            → 200 (requires auth)
  /api/v2/admin/users         → 403 (without auth) / 200 (with admin auth)

Raw Output: outputs/ffuf-api.json
```

### Technology Fingerprinting

```
=== Tech Stack Detection (httpx + whatweb) ===
Date: 2026-03-15
Target: live-hosts.txt
Command: httpx -l live.txt -tech-detect -json -o outputs/tech-stack.json
Duration: 5 minutes
Total Results: 189 hosts with tech fingerprint

Frontend:
  React: 189/189 (100%) — All SPA
  Material UI: 189/189 (100%) — Design system
  Redux: 156/189 (82%) — State management
  React Router: 189/189 (100%) — Routing
  Axios: 189/189 (100%) — HTTP client
  Formik: 145/189 (77%) — Forms
  Webpack: 189/189 (100%) — Bundler

Backend:
  Express: 156/312 (50%) — API servers
  Node.js: 167/312 (53%) — Runtime
  Apollo: 12/312 (4%) — GraphQL server
  Ghost: 3/312 (1%) — Blog CMS

Infrastructure:
  Cloudflare: 245/312 (79%) — CDN/WAF
  AWS ALB: 67/312 (21%) — Load balancer
  AWS ECS: 45/312 (14%) — Container (from headers)
  Nginx: 34/312 (11%) — Static/Proxy

Monitoring:
  Datadog: 189/312 (61%) — APM (x-datadog-trace-id header)
  Sentry: 156/312 (50%) — Error tracking (from JS)

=== WAF Detection (wafw00f) ===
Date: 2026-03-15
Target: target.com, api.target.com, admin.target.com
Command: wafw00f -i live-top20.txt -o outputs/waf-detect.txt
Duration: 2 minutes

Results:
  target.com      → Cloudflare (detected: Cloudflare WAF)
  api.target.com  → Cloudflare (detected: Cloudflare WAF)
  admin.target.com → Cloudflare (detected: Cloudflare WAF)
  dev.target.com  → No WAF detected (direct AWS!)
  staging.target.com → No WAF detected (direct AWS!)
  jenkins.target.com → No WAF detected (direct AWS!)

Raw Output: outputs/tech-stack.json + outputs/waf-detect.txt
```

### Port Scanning

```
=== Quick Port Scan (naabu) ===
Date: 2026-03-15
Target: all-resolved-ips.txt (892 IPs)
Command: naabu -l resolved-ips.txt -top-ports 100 -o outputs/naabu-ports.txt
Duration: 3 minutes

Common Open Ports:
  80 (HTTP):       312 hosts
  443 (HTTPS):     312 hosts
  8080 (HTTP-alt): 12 hosts (dev/staging)
  8443 (HTTPS-alt): 8 hosts (dev/staging)
  22 (SSH):        34 hosts (infra — filtered)
  3306 (MySQL):    0 hosts (filtered — good)
  6379 (Redis):    0 hosts (filtered — good)
  9200 (ES):       0 hosts (filtered — good)

Dev/Staging Exceptions:
  dev.target.com:      80, 443, 8080, 8443 (more ports open!)
  staging.target.com:  80, 443, 8080 (Jenkins on non-standard)
  jenkins.target.com:  8080 (Jenkins!)

Raw Output: outputs/naabu-ports.txt
```

### JavaScript Analysis

```
=== JS Bundle Discovery ===
Date: 2026-03-15
Target: target.com
Command: katana -list live.txt -jc -o outputs/js-urls.txt
Duration: 3 minutes
Total Results: 47 JS files

Key Bundles:
  /assets/main.abc123.js       (2.4 MB) — Main app bundle
  /assets/vendor.def456.js     (1.8 MB) — Vendor libraries
  /assets/admin.ghi789.js      (480 KB) — Admin panel
  /assets/graphql.jkl012.js    (120 KB) — GraphQL client

=== Main Bundle Analysis ===
Date: 2026-03-15
File: /assets/main.abc123.js
Tool: LinkFinder + manual grep

API Endpoints Found (hardcoded):
  /api/v2/*
  /api/v1/* (deprecated, still referenced)
  /graphql

Keys Found:
  Stripe PK: pk_live_XXXXX (publishable — safe)
  Sentry DSN: https://XXXXX@sentry.io/123456
  LaunchDarkly: 5def789abc123
  Mixpanel: abc123def456
  Google Analytics: UA-123456-1
  Intercom: xyz789

Internal Paths:
  /admin/users
  /admin/settings
  /admin/audit
  /admin/impersonate
  /feature-flags
  /debug/cache
  /health/db

GraphQL Operations:
  query user($id: ID!) { user(id: $id) { ... } }
  query invoice($id: ID!) { invoice(id: $id) { ... } }
  query node($id: ID!) { node(id: $id) { ... on User { ... } } }
  mutation login($email: String!, $password: String!) { ... }
  mutation createAdminUser($input: CreateAdminUserInput!) { ... }

=== Admin Bundle Analysis ===
Date: 2026-03-15
File: /assets/admin.ghi789.js
Tool: LinkFinder + SecretFinder + manual grep

Admin-Only Endpoints:
  /api/v2/admin/users (create, list, delete)
  /api/v2/admin/settings (read, update)
  /api/v2/admin/audit (read with filters)
  /api/v2/admin/impersonate (post — ATO!)
  /api/v2/admin/billing (read)
  /api/v2/admin/coupons (create, delete)
  /api/v2/admin/logs (read with filters)

Admin Feature Flags:
  new-dashboard (enabled)
  export-users (enabled)
  beta-mfa (enabled)
  audit-logs (enabled)

Hardcoded Admin URL (for testing):
  https://admin.target.com/impersonate?userId={id}

Raw Output: outputs/js-endpoints.txt + outputs/js-secrets.txt
```

### Vulnerability Scanning

```
=== Nuclei Scan ===
Date: 2026-03-15
Target: live-hosts.txt (312 hosts)
Command: nuclei -l live.txt -t ~/nuclei-templates/ -severity critical,high,medium -o outputs/nuclei-results.txt
Duration: 15 minutes
Total Results: 12 findings

Findings:
  - CVE-2023-44487 (HTTP/2 Rapid Reset) — LOW (patched likely)
  - Missing Security Headers on dev.* — MEDIUM (no HSTS, no CSP on dev)
  - GraphQL Introspection Enabled — MEDIUM (graphql.target.com)
  - Swagger UI Exposed — LOW (docs access)
  - Jenkins Exposed — HIGH (jenkins.target.com:8080 — unauthenticated?)
  - Prometheus Metrics — MEDIUM (metrics endpoint visible)
  - CORS Misconfiguration — MEDIUM (api.target.com allows *.target.com)
  - Health Check Disclosure — LOW (health endpoint reveals DB type)
  - Open S3 Bucket — CRITICAL (s3.amazonaws.com/target-user-data — listable?)
  - Deprecated API Version — LOW (/api/v1/ still responds)

Raw Output: outputs/nuclei-results.txt
```

---

## 3. Output Summary Statistics

### target.com Session (2026-03-15)

| Tool Category | Commands Run | Total Output | Notable Findings |
|--------------|-------------|-------------|-----------------|
| Subdomain Enum | 5 | 1,745 unique subs | 5 internal DNS names |
| DNS Resolution | 2 | 892 resolved | 6 private IPs |
| HTTP Probing | 2 | 312 live hosts | 32 403s (interesting) |
| URL Crawling | 3 | 58,023 URLs | 15 admin endpoints |
| Dir Fuzzing | 4 | 107 paths found | 28 admin paths |
| Tech Fingerprint | 3 | 189 hosts scanned | Full stack known |
| Port Scan | 1 | 892 IPs scanned | Dev exposed |
| JS Analysis | 2 | 47 JS files | Endpoints, keys, flags |
| Vuln Scan | 1 | 12 findings | 2 critical leads |

### All Targets Lifetime

| Target | Sessions | Total Commands | Leads Generated | Findings |
|--------|----------|--------------|----------------|----------|
| target.com | 3 | 23 | 7 | 0 |
| — | — | — | — | — |

---

## 4. Tool Output File Index

### By Target: target.com

| File | Tool | Date | Size | Lines |
|------|------|------|------|-------|
| outputs/subfinder-passive.txt | subfinder | 2026-03-15 | 45 KB | 1,247 |
| outputs/crtsh-target.com.txt | crt.sh | 2026-03-15 | 6 KB | 156 |
| outputs/dnsx-brute.txt | dnsx | 2026-03-15 | 12 KB | 342 |
| outputs/dnsx-resolved.txt | dnsx | 2026-03-15 | 32 KB | 892 |
| outputs/httpx-live.txt | httpx | 2026-03-15 | 45 KB | 312 |
| outputs/gau-urls.txt | gau | 2026-03-15 | 2.1 MB | 45,678 |
| outputs/katana-crawl.txt | katana | 2026-03-15 | 580 KB | 12,345 |
| outputs/ffuf-dirs.json | ffuf | 2026-03-15 | 12 KB | 45 |
| outputs/ffuf-admin.json | ffuf | 2026-03-15 | 8 KB | 28 |
| outputs/ffuf-api.json | ffuf | 2026-03-15 | 10 KB | 34 |
| outputs/tech-stack.json | httpx | 2026-03-15 | 156 KB | 189 |
| outputs/waf-detect.txt | wafw00f | 2026-03-15 | 2 KB | 5 |
| outputs/naabu-ports.txt | naabu | 2026-03-15 | 24 KB | 892 |
| outputs/js-endpoints.txt | LinkFinder | 2026-03-15 | 45 KB | 234 |
| outputs/js-secrets.txt | SecretFinder | 2026-03-15 | 12 KB | 12 |
| outputs/nuclei-results.txt | nuclei | 2026-03-15 | 8 KB | 12 |

---

## 5. Tool Configuration Registry

### Active Tool Configs

| Tool | Config File | Version | Last Updated | Notes |
|------|------------|---------|-------------|-------|
| subfinder | ~/.config/subfinder/config.yaml | 2.6.x | 2026-03-01 | Custom resolvers, all sources |
| httpx | ~/.config/httpx/config.yaml | 1.6.x | 2026-03-01 | Rate limit 100, random UA |
| ffuf | ~/.config/ffuf/config.yaml | 2.1.x | 2026-03-01 | 50 threads, 10s timeout |
| nuclei | ~/.config/nuclei/config.yaml | 3.2.x | 2026-03-01 | Rate limit 150/min |

### Config Backups

```
=== subfinder config ===
Backup: 2026-03-01
Path: ~/.config/subfinder/config.yaml
Content saved to: config-backups.md

resolvers:
  - 1.1.1.1
  - 1.0.0.1
  - 8.8.8.8
  - 8.8.4.4
sources:
  - alienvault
  - certspotter
  - crtsh
  - hackertarget
  - otx
  - securitytrails
  - threatcrowd
  - waybackarchive
  - urlscan
  - dnsdb

=== httpx config ===
Backup: 2026-03-01
Path: ~/.config/httpx/config.yaml

threads: 100
timeout: 10
retries: 2
follow-redirects: true
```

---

## 6. Output Analysis Rules

### When to Investigate Output

| Signal | Action |
|--------|--------|
| Private IP in response | SSRF vector — investigate immediately |
| Internal DNS name | Possible internal path discovery |
| 403 on standard path | Potential auth bypass |
| Deprecated endpoint | Old code = more bugs |
| No WAF detected | Attack surface on dev/staging |
| Extra response fields | Mass assignment potential |
| Error message with details | Info disclosure |
| Response time variance | Timing side-channel |
| New subdomain not in scope | Scope expansion opportunity |
| JS bundle with admin endpoints | Hidden attack surface |

### Output Retention Decisions

| Output Type | Keep Raw? | Keep Summary? | Retention |
|-------------|-----------|--------------|-----------|
| Subdomain lists | For active target | Permanent | Until target archived |
| URL lists | No (too large) | With counts | Summary permanent |
| Ffuf results | For active target | With notable paths | Summary permanent |
| Tech fingerprints | No | With breakdown | Summary permanent |
| JS analysis results | Yes | With findings | Permanent |
| Nuclei results | Yes | With CVEs | Permanent |
| Port scans | No | With open ports | Summary permanent |
| WAF detection | No | With bypass notes | Summary permanent |
