# Reconnaissance Rules

Recon is not data collection. Recon is attack surface discovery.
The difference determines whether you find bugs or just fill disk space.

---

## 0. ENGAGEMENT CONTEXT (READ FIRST)

This tooling is operated by an authorized bug bounty hunter against public bounty programs with published safe-harbor terms. Recon is performed only against assets confirmed in-scope via `/scope`.

- Passive recon (DNS, certificates, search engines, public data) is always safe and has no rate limits.
- Active recon (port scanning, directory brute-force, parameter fuzzing) requires scope confirmation AND must respect rate limits.
- Never probe out-of-scope assets even passively. One mistake = program ban.
- Never use the target's production infrastructure for your recon infra.

---

## 1. RECON DISCIPLINE

### 1.1 The Purpose
Recon finds attack surface: reachable endpoints, parameterized inputs, auth boundaries, tech versions with known CVEs, misconfigured cloud resources, leaked credentials. If your recon output doesn't answer "what can I attack?" it's wrong.

### 1.2 What Recon Is NOT
Collecting every subdomain ever registered (useless without live filtering), saving every URL ever crawled (useless without endpoint classification), running every tool on every target (you have limited time), feeling busy while learning nothing about the target.

### 1.3 Recon Paralysis
Set a hard timebox per recon phase:
```
Small target (startup, <$50 bounties):     30 minutes max
Medium target (growth stage, $50-200):     2 hours max
Large target (enterprise, $200+):          4 hours max
New asset on existing target:              15 minutes max
```

### 1.4 Actionable vs. Noise Filter
Every piece of recon data must pass: "Can I attack this TODAY?"
If you can't attack it today, deprioritize it. Note it for later.
```
Actionable: api.target.com → resolves → 443 open → returns JSON
Noise: dev.target.com → resolves → 443 → 403 → no known exploit
Actionable: s3.target.com → resolves → XML with ListBucketResult
Noise: mail.target.com → resolves → Exchange OWA login
Actionable: graphql.target.com → introspection query enabled
Noise: staging.target.com → default nginx page
```

### 1.5 Surface-First, Depth-Second
Always expand surface before deepening. Wrong: deep crawl 10,000 URLs on one subdomain. Right: find all subs → check live → prioritize → hunt.

### 1.6 The Recon Spiral
Recon is iterative, not linear. Each phase feeds back:
```
Scope → Subdomains → Live check → URLs → JS → APIs
  ↑                                        |
  +--------- New subdomain in JS ----------+
```
Found a new subdomain in JS? Go back to subdomain enum. Found a new API path? Crawl deeper on it.

### 1.7 Never Skip Recon on a New Asset
Minimum per new subdomain: tech stack, top 100 paths, API check, auth mechanism, known CVEs for detected stack.

### 1.8 The 80/20 Rule
80% of actionable findings from 20% of data: live API endpoints with auth, non-standard ports, JS bundles with secrets, GraphQL introspection, public S3 buckets, admin/dev portals.

### 1.9 Recon Output Must Be Consumable
Format: `host.tld | tech stack | interesting ports | notes | priority`

### 1.10 You Will Miss Things
The goal is not to find everything. The goal is to find enough to get paid.

---

## 2. SCOPE-FIRST RECON

### 2.1 Scope Confirmation Before Any Request
Read program policy in full. Note in-scope wildcards, explicit exclusions, excluded technologies, rate limits or testing windows.

### 2.2 Wildcard Scope Interpretation
`*.target.com` means all subdomains (www, api, app, dev, etc.). Ambiguous: target.com subdomain hosted on third-party (AWS). If the content is target.com's, usually in scope. If shared infrastructure, program may claim OOS. Check past disclosed reports for the program's stance.

Always save scope for programmatic filtering:
```
*.target.com
*.api.target.com
!admin.target.com (OOS)
```

### 2.3 Third-Party Asset Identification
```
3rd party    | Evidence
CDN          | CloudFront, Cloudflare, Akamai, Fastly
Auth         | Auth0, Okta, Firebase Auth, AWS Cognito
Infra        | AWS, GCP, Azure, DigitalOcean, Heroku, Netlify
```
Test the integration, not the third-party service itself.

### 2.4 Scope Expansion Opportunities
Same ASN, same SSL cert org, acquired company domain — probe carefully, ask the program if unsure.

### 2.5 Scope Filtering in Automation
Every automated tool must filter against scope. Set up at the workflow level, not per-tool.

### 2.6 Out-of-Scope Detection By Signal
Some assets loudly announce they're OOS:
```
Host returns:                       | Likely OOS
"Service not found"                 | Different platform
Default nginx/greeting page         | Unconfigured domain
CNAME to unclaimed S3 bucket        | Potential takeover but OOS
WordPress default page              | Personal/abandoned project
"IIS7" default page                 | Check carefully, could be legacy
```
Stop probing immediately on OOS signal. Note for future use if scope changes.

### 2.7 Scope Changes Tracking
Check at session start, after dry spells, on new features.

### 2.8 Wildcard Edge Cases
Some programs have unusual wildcards:
```
*.target.com        → standard (all subdomains)
target.com/*        → path scope (certain paths only)
*.target.com/*      → subdomain AND path scope
target.com          → apex only (no subdomains)
*.target.com,!*.dev → wildcard with explicit exclusions
```
Always test the edges. What about subdomains not listed but owned by target?

---

## 3. RECON DEPTH BY TARGET TYPE

### 3.1 Target Maturity Matrix
```
Startup (<50 emp)       | Light: 30 min
Growth (50-500)         | Medium: 2 hrs
Mid-Market (500-5000)   | Deep: 4 hrs
Enterprise (5000+)      | Very Deep: 8 hrs+
```

### 3.2 Bounty-Calibrated Depth
```
<$50 bounty    → 30 min recon, spray-and-pray
$50-200        → 2 hrs, ~2-3 bugs/week needed
$200-500       → 4 hrs, 1 good bug = good week
$500+          → deep recon, find the critical path
```

### 3.3 Program Seen Count
New (<1 month): deep recon, racing other hunters. Established: medium recon, easy bugs gone. Mature: strategic recon on new features only.

### 3.4 Startup Rules
Startups have less attack surface, more obvious bugs (lack of security maturity), faster triage. Strategy: skip deep subdomain enum (they have ≤10 subs), focus on auth bypass/IDOR/mass assignment, check for obvious cloud misconfigs, 30 min max then move on.

### 3.5 Enterprise Rules
Enterprises have massive surface (100-1000+ subdomains), complex auth (SSO, MFA, multiple providers), legacy + modern systems, slower triage but larger payouts. Strategy: full subdomain enum + permutations, deep JS analysis (micro-frontends = more bundles), API-focused recon, auth flow mapping (SSO = OAuth/SAML bugs), cloud misconfig scanning, CDN/WAF identification.

### 3.6 Platform Effects
H1: higher avg bounties, deeper recon worth it. Bugcrowd: varied quality, check VRT. Intigriti: European, smaller. Immunefi: Web3.

### 3.7 Unknown Target First Pass
subfinder + httpx (5 min) → katana + gau (10 min) → whatweb top 10 (5 min) → pick 3 interesting (5 min) → API/GQL check (5 min).

---

## 4. SUBDOMAIN ENUMERATION RULES

### 4.1 Passive Sources Priority
Passive first, always. Priority: crt.sh > DNS records > Google dorks > Shodan > SecurityTrails > AlienVault OTX > Wayback > VirusTotal > DNSDumpster.

### 4.2 Certificate Transparency
crt.sh is the single best source. Every publicly-trusted TLS certificate is logged.
```powershell
curl -s "https://crt.sh/?q=%25.target.com&output=json" | ConvertFrom-Json | Select-Object -ExpandProperty name_value | Sort-Object -Unique
```

### 4.3 DNS Enumeration
Check A, AAAA, CNAME, MX, NS, TXT records. Try zone transfer (rarely works). Bulk resolve with `[System.Net.Dns]::GetHostAddresses($sub)`.

### 4.4 Search Engine Dorking
```
Google: site:*.target.com -www, site:target.com intitle:"index of"
Shodan: shodan search hostname:target.com, ssl:"target.com"
```

### 4.5 Active Enumeration
Use only when passive is insufficient. DNS brute force with wordlist sized to target (100 for startup, 50,000 for enterprise).

### 4.6 Wordlist Selection
```
Startup: 100-500 words      | top100, common names
Medium: 1,000-5,000        | commonspeak2
Enterprise: 10,000-50,000   | best-dns-wordlist
```
Custom categories to create:
```
api-names.txt:     api, v1, v2, v3, dev-api, sandbox, graphql, gateway, backend
admin-names.txt:   admin, dashboard, portal, console, management, backoffice, cpanel
dev-names.txt:     dev, staging, stage, test, qa, sandbox, uat, beta, canary, lab
internal-names.txt: internal, corp, employee, staff, jira, jenkins, gitlab, confluence
```

### 4.7 Permutation Rules
From found subdomains generate variations:
```
Base: api-v2.target.com
  → api-v1, api-v3, api-v4 (version iteration)
  → api-dev, api-staging, api-qa (environment suffixes)
  → dev-api, staging-api, qa-api (environment prefixes)
  → api.target.com:8443 (port variation)
  → api.target.com/v1, api.target.com/graphql (path variation)
```

### 4.8 Subdomain Takeover Detection
Every subdomain that resolves but returns no content is a potential takeover. Signatures: AWS S3 (NoSuchBucket), CloudFront (BadRequest), Heroku (No such app), GitHub Pages (404), Azure (not found), Shopify, Fastly, Pantheon.

### 4.9 Recursive Enumeration
Run enumeration recursively: get all subs → extract second-level domains → brute force those for third-level subs.

### 4.10 Check the Obvious
www, mail, remote, blog, webmail, admin, api, dev, staging, test, m, portal, login, auth, sso, support, docs, status, wiki, git, jenkins, jira, partner, cdn, static, assets, store, billing, webhook, graphql.

---

## 5. LIVE HOST DISCOVERY RULES

### 5.1 Port Selection
```
Web (always): 80, 443, 8080, 8443
APIs: 3000, 5000, 8000, 9000
Depth: startup (80,443), medium (+8080,8443), enterprise (top 100)
```

### 5.2 HTTP vs HTTPS Probing
HTTP → serves content (interesting), HTTPS → invalid/self-signed cert (very interesting: dev/staging/internal).

### 5.3 Status Code Analysis
```
200 → live, probe deeper. 301/302 → follow redirect target.
401 → auth wall, map the auth. 403 → exists but blocked, try bypass.
404 → dead path, try others. 500 → potential vuln or misconfig.
429 → rate limited, slow down. 502/503 → gateway issues, may expose upstream.
```

### 5.4 Content-Type Prioritization
```
application/json       → Critical (API endpoint)
text/javascript        → Critical (JS bundle)
text/html (admin)      → Critical (hunt immediately)
text/html (login)      → High (auth testing)
application/xml        → High (SOAP/XML endpoint)
image/*                → Low (static, unless upload endpoint)
```

### 5.5 Response Size Anomaly
Compare sizes across similar endpoints. Same path, different params: size difference = different behavior. Large response on normally small endpoint = potential data leak. Small response on normally large endpoint = error or access denied.

---

## 6. URL COLLECTION RULES

### 6.1 Source Selection
Web Archive CDX, GAU, Katana, WaybackURLs, Gospider. For enterprises add Common Crawl.

### 6.2 Wayback Machine
```powershell
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com&output=json&fl=original&collapse=urlkey"
```

### 6.3 JS URL Extraction
Extract embedded URLs, paths, and endpoints from JS files with regex: `(https?://[^"'\s]+)` and relative path patterns.

### 6.4 Active Crawling
Use when passive sources give <100 URLs or target is a SPA. Katana for large targets. Depth: startup=1, enterprise=3+.

### 6.5 Directory Brute-Force (When Needed)
Use only when other URL sources fail or suspect hidden paths. Wordlist: 1,000-50,000 depending on target.

### 6.6 URL Cleanup and Deduplication
Remove duplicates, static assets (.css, .png, .jpg, .svg, .ico, .woff), third-party analytics URLs, CDN URLs (cdn.cloudflare.com → remove, cdn.target.com → keep).

Strip fragment identifiers and sort unique by path. Normalize query params to identify endpoint patterns.

### 6.7 Parameter Extraction
URLs with parameters are more interesting than those without. Extract all unique param names across collected URLs:

Interesting params to flag: id, user, admin, token, api_key, file, path, url, redirect, return, next, callback, page, document, upload, download, debug, test, mode, action, method, preview, dry_run.

### 6.8 URL Trie Building
Build a prefix tree of URL paths to find patterns:
```
/api/v1/users          /api/v2/users
/api/v1/users/{id}     /api/v2/users/{id}
/api/v1/products       /api/v2/orders
```
Reveals: API structure (RESTful), ID patterns (numeric vs UUID), resource relationships.

---

## 7. JS BUNDLE ANALYSIS RULES

### 7.1 JS File Priority
P1 (analyze immediately): app.js, main.js, bundle.js, vendor.js, [hash].js. P2: api.js, config.js, auth.js, admin.js. P3: third-party libs, analytics, chat widgets. P4 (skip): known CDN libs.

### 7.2 What to Look For
```
API Endpoints:       /api/v1/, /graphql, /internal/, /partner/
Auth:                JWT tokens, apiKey, accessToken, Firebase config, Auth0/Okta domain
Credentials:         AWS keys (AKIA*), GCP service account JSON, Azure connection strings
Feature Flags:       showAdminDashboard, isAdmin, debug, featureFlags
Internal Hostnames:  Jenkins, Jira, Grafana, Kibana, internal.target.com
Sensitive:           password, secret, s3://, gs://, slack://, webhook URLs, http:// (internal)
```

### 7.3 JS Analysis Quick Scan
```powershell
# Extract all URLs from JS:
[regex]::Matches($js, "['\"](https?://[^\"'\s]+)['\"]") | ForEach-Object { $_.Groups[1].Value }

# Find secrets/key patterns in JS:
$patterns = @('(AKIA[0-9A-Z]{16})', '(sk-[a-zA-Z0-9]{20,})', '(ghp_[a-zA-Z0-9]{36})')
```

### 7.4 Framework Identification
React (React.createElement, useState), Angular (ng-version, Zone.js), Vue (createApp, defineComponent), Next.js (_next/static, __NEXT_DATA__), Nuxt, Gatsby, Svelte.

### 7.5 Source Map Exploitation
Source maps (.map) reveal original, unminified code with comments, debug statements, and internal docs. Check by appending `.map` to JS URLs.

Common locations: /js/app.js.map, /assets/app.[hash].js.map, /static/js/main.[hash].js.map, /_next/static/chunks/pages/index-[hash].js.map.

```powershell
$mapUrl = "https://target.com/assets/app.js.map"
try { $map = Invoke-WebRequest $mapUrl; $mapJson = $map.Content | ConvertFrom-Json; $mapJson.sources }
```

### 7.6 JS Bundle Diffing
Track changes between sessions. Hash comparison: `(Get-FileHash app.js -Algorithm SHA256).Hash`. Changed bundles may contain new endpoints/secrets.

### 7.7 Deobfuscation
Tools: de4js, jsnice.org, UnPacker, Prettier. Signs: eval(), String.fromCharCode(), base64 arrays, _0x1234 function names. Even obfuscated, URLs and endpoints are often in plain strings.

### 7.8 Prioritization of JS Findings
Immediate: hardcoded API keys/secrets, internal API endpoints, admin routes, debug endpoints, GraphQL endpoints. High: new API endpoints, internal hostnames, feature flags, OAuth client IDs.

### 7.9 JS File Discovery
Find JS files from HTML `src` attributes, sitemap.xml, or by crawling common JS paths.

---

## 8. API ENDPOINT EXTRACTION

### 8.1 API Detection
Indicators in responses: Content-Type (application/json, application/xml), X-API-Version, X-RateLimit-* headers, WWW-Authenticate: Bearer, response body starts with `{` or `[`.

Indicators in URLs: /api/, /v1/, /v2/, /rest/, /graphql, /soap/, /services/, /rpc/, /odata/, .json or .xml extension.

### 8.2 GraphQL Detection
Check /graphql with `{"query":"{__typename}"}`. Try introspection to dump schema. Common paths: /graphql, /query, /api/graphql, /graphiql, /playground, /explorer.

### 8.3 REST API Structure Mapping
```
GET    /api/v1/users              → List users
POST   /api/v1/users              → Create user
GET    /api/v1/users/{id}         → Get user (IDOR hunting)
PUT    /api/v1/users/{id}         → Update user
DELETE /api/v1/users/{id}         → Delete user
```
Enumerate resources: users, posts, products, orders, accounts, payments, organizations. Check versioning (v1, v2, date-based, beta, experimental).

### 8.4 API Parameter Enumeration
Common params: page, limit, offset, filter, search, sort, orderBy, include, expand, fields, debug, dry_run. Test IDs, expansion, and debug params.

### 8.5 Custom API Recognition
Look for JSON-RPC, XML-RPC, SOAP (WSDL), gRPC (hard to detect), WebSocket (ws://), SSE (text/event-stream), OData ($metadata).

### 8.6 API Documentation Discovery
Check /docs, /swagger.json, /openapi.json, /api/spec, /api/v1/docs. Parse Swagger/OpenAPI for full endpoint listing.

### 8.7 API Key Storage Patterns
JS config, localStorage, sessionStorage, cookies, Authorization header, X-API-Key header.

### 8.8 Rate Limit Recognition
Headers: X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After. Status: 429, 403. Bypass: change IP, add X-Forwarded-For, change UA, use different endpoints/methods, cache buster params.

---

## 9. TECHNOLOGY FINGERPRINTING RULES

### 9.1 HTTP Header Analysis
```
Server header:       nginx, Apache/2.4.41, Microsoft-IIS/10.0, CloudFront, GSE
X-Powered-By:        Express, ASP.NET, PHP/7.4
Security headers:    HSTS, CSP, X-Frame-Options, X-Content-Type-Options (missing = risk)
Custom headers:      X-API-Version, X-Upstream (internal host leak), X-Backend (internal IP),
                     X-Served-By (naming convention), X-Debug, X-Environment (staging leak)
```

### 9.2 Favicon Hashing
Download favicon.ico, compute MD5 hash, match against known hashes for Confluence, Jenkins, GitLab, Grafana, Kibana.

### 9.3 Error Page Analysis
Force errors (nonexistent page, SQL injection in param, invalid method). Error messages reveal: ASP.NET, Express, Laravel, Flask, Java/Tomcat. Stack traces = debug mode enabled.

### 9.4 Framework-Specific Detection
```
Spring Boot:  /actuator, /actuator/health, Whitelabel Error Page, X-Application-Context
Django:       /admin/, csrftoken cookie, "Django version X.Y.Z" in errors
Rails:        /assets/application-[hash].js, _session_id cookie, /rails/info/routes
Laravel:      /_debugbar/open, laravel_session cookie, /api/user
Express:      X-Powered-By: Express, "Cannot GET /path", connect.sid cookie
ASP.NET:      __VIEWSTATE hidden field, WebResource.axd, X-AspNet-Version
Next.js:      _next/static/ paths, __NEXT_DATA__ script tag, /api/* serverless
```

### 9.5 WAF Identification
```
Cloudflare:   Server: cloudflare, cf-ray header, __cfduid cookie
Akamai:       Server: AkamaiGHost, X-Akamai-* headers
AWS WAF:      x-amzn-RequestId, x-amzn-ErrorType
CloudFront:   X-Amz-Cf-Id, X-Cache: Error from cloudfront
F5 BIG-IP:    TSxxxxxxxx cookie, X-Content-Type-Options: nosniff
ModSecurity:  "ModSecurity: Access denied", 406 responses
Imperva:      X-Iinfo header, visid_incap cookie
```

### 9.6 Tech → Bug Class Mapping
```
WordPress:       plugin CVEs, user enum, XSS
Laravel:         debug mode, .env file, mass assignment, deserialization
Spring Boot:     actuator endpoints, SpEL injection, env disclosure
Django:          debug mode, ORM injection, mass assignment
Rails:           YAML deserialization, mass assignment, SQLi
Express:         NoSQL injection, prototype pollution, XSS
ASP.NET:         ViewState deserialization, machineKey, IIS CVEs
Next.js:         SSRF via _next/image, middleware bypass
Java (Tomcat):   Manager app, AJP, Ghostcat (CVE-2020-1938)
Python (Flask):  SSTI (Jinja2), debug console, path traversal
Go:              Path traversal, template injection, header injection
```

---

## 10. RECON CACHE MANAGEMENT

### 10.1 Staleness Thresholds
```
Data Type             | Staleness | Rationale
Subdomains            | 7 days    | New subdomains appear frequently
Live hosts            | 1 day     | Hosts go up/down, IPs change
URLs                  | 3 days    | New endpoints deployed constantly
JS bundles            | 1 day     | Changes often = new features/secrets
Tech fingerprint      | 7 days    | Technology rarely changes daily
Secrets               | 0 days    | Expire or get revoked, re-check daily
Scope                 | 1 day     | Program changes scope, check each session
```

### 10.2 Incremental vs. Full Recache
Incremental (5-10 min): run passive sources only (crt.sh, wayback, search engines), compare with previous results, only download new/changed items.

Full (30-60 min): run all sources including active, fresh screenshots, fresh tech detect. Frequency: weekly for active targets, or after major product announcements, when current data is stale (many 404s), or when finding nothing and needing fresh perspective.

### 10.3 Cache Storage Structure
```
/recon_cache/target.com/
  metadata.json         # Last scan times, tool versions, counts
  scope.txt             # Scope at time of scan
  subdomains/           # raw_results.json, unique_subs.txt, new_subs.txt
  urls/                 # raw_urls.txt, clean_urls.txt, params.txt
  js/                   # js_files.txt, cached [hash].js, findings.json
  tech/                 # fingerprint.json, screenshots/
  api/                  # endpoints.txt, docs/
```

### 10.4 Cross-Target Correlation
Same tech stack = similar params, auth, IDOR patterns. Same org, different domains = shared auth, overlapping user bases.

### 10.5 Hunt Memory Integration
Log findings immediately with source, finding, priority, potential, status.

### 10.6 Cache Expiration Enforcement
Check cache age at session start. Delete screenshots and stale JS older than 14 days.

---

## 11. SENSITIVE DATA HANDLING

### 11.1 Never Store Raw Credentials
NEVER save AWS keys, DB passwords, session tokens, API keys to disk. ALWAYS redact, store only TYPE and LOCATION, test immediately then discard.

### 11.2 Secret Discovery Triage
P1 (report immediately): cloud provider keys, DB connection strings, payment processor live keys. P2 (same session): auth tokens, API keys for paid services. P3: env vars, session tokens. P4: public API keys, analytics IDs.

### 11.3 Impact Assessment
For AWS keys: `aws sts get-caller-identity`, `aws s3 ls`, `aws iam list-users`. Only test with program permission, read-only, document access, report immediately.

### 11.4 JavaScript Secret Redaction
Auto-redact known patterns (AKIA*, sk_live_*, ghp_*, JWTs) when saving JS files.

### 11.5 Incident Response Protocol
If you find exposed credentials: document URL/file/line, do NOT use them, report immediately, delete local copies after reporting.

---

## 12. RECON DATA STRUCTURE

### 12.1 Standard Directory Layout
```
/recon/target.com/
  0-scope/           policy.md, inscope.txt, outofscope.txt
  1-subdomains/      sources/, live.txt, tech.txt, screenshots/
  2-urls/            all_urls.txt, unique_endpoints.txt, params.txt, interesting.txt
  3-js/              files/, endpoints.txt, secrets.txt, routes.txt, apis.txt
  4-api/             endpoints.txt, graphql.txt, swagger.json, auth.txt
  5-tech/            tech_stack.txt, cves.txt, waf.txt, cdn.txt
  6-misc/            cloud.txt, buckets.txt, takeover.txt, leaks.txt
  7-reports/         priority_high.txt, priority_medium.txt, priority_low.txt, killed.txt
  metadata.json
```

### 12.2 File Naming Conventions
`[target]_[type]_[source].txt`, screenshots as `[subdomain]_[protocol]_[port].png`, JS as `[subdomain]_[path_hash].js`.

### 12.3 Output Formats
JSON/CSV for automation, sorted TXT for lists, prioritized MD for hunting.

### 12.4 Metadata Tracking
JSON file with target, program, last scan times, counts per category, sources used.

### 12.5 Version Control
Git init recon directory, .gitignore for sensitive data, commit after each session.

---

## 13. AUTOMATED VS MANUAL RECON

### 13.1 What to Automate
Subdomain enum (passive), DNS resolution, port scanning, HTTP probing, screenshots, tech fingerprinting, URL collection, JS discovery, basic secret scanning, S3 bucket checks, takeover detection, favicon hashing.

### 13.2 What to Do Manually
JS analysis review, API relevance assessment, auth flow mapping, OAuth redirect analysis, app structure understanding, distinguishing test from prod, error interpretation, spotting business logic hints.

### 13.3 Semi-Automated Workflow
Collect automatically → manually review first 50 results + high priority + anomalies → targeted re-automation → repeat.

### 13.4 Automation Pitfalls
```
1. Scope creep: tools don't understand scope nuance → filter output through scope list
2. Noise generation: tools grab everything including 3rd-party → post-filter for target.com
3. False positives: secret scanners flag test keys → manual review ALL secrets before acting
4. Rate limiting: aggressive automation triggers WAF → rate-limit, add delays between runs
5. Stale data: automated results immediately somewhat stale → refresh critical checks each session
6. Tool blindness: tools don't understand app logic → manual review always catches what tools miss
```

### 13.5 Time Allocation (4-hr session)
Setup 15min → automated collection 30min → manual review subs 15min → JS analysis 30min → app exploration 30min → endpoint review 30min → auth mapping 30min → prioritization 15min → docs 15min → buffer 30min.

---

## 14. ZERO INTERESTING HOSTS?

### 14.1 Kill Signal Analysis
KILL signals: all hosts return 403/401, default Cloudflare on every page, all endpoints require 2FA + hardware key, marketing site only, no user accounts, hunted by 1000+ researchers for 2+ years.

### 14.2 Alternative Approaches
If standard recon fails, change one variable at a time:

1. **Change perspective**: What does a new user see? (registration flow → endpoints). What does a logged-in user see? (dashboard → API calls). What does an admin see? (different endpoints).

2. **Look at the business**: What data is valuable? (PII, financial, health). Where does data flow? Where are the auth/role/tier boundaries? What features cost money? (premium = access control).

3. **Change entry point**: IP ranges instead of subdomains, mobile API instead of web, staging/dev instead of prod, partner portal.

4. **Change timing**: Hunt after major releases (regression bugs), on weekends (less monitoring), during off-peak hours.

### 14.3 Target Switching Decision Framework
```
Found anything actionable?          → YES: Hunt it first
Tried ALL alternative approaches?  → NO: Try them first
                                   → YES: Target may be dead for now
Payout potential?                  → High ($500+): Invest another session
                                   → Low (<$100): Move on after initial sweep
Program age?                       → New (<1 month): Keep digging (first hunter advantage)
                                   → Old (>6 months): Already picked over
Multiple targets?                  → Switch to more promising one
```

### 14.4 The "Boring" Target Opportunity
Static site → check subdomains/dev builds. 403 everywhere → path bypass. SPA login → check /register. No API calls → check WebSocket/service workers. WordPress default → wp-admin, wp-json.

### 14.5 When to Kill a Target Permanently
No scope changes in 6+ months, >50% N/A rate, no disclosed reports in 12+ months, product being sunset. Document why, set 3-month re-check reminder.

---

## 15. RECON BEFORE EACH SESSION

### 15.1 Pre-Session Checklist (5 min)
Check scope changes, disclosed reports, changelog for new features, re-scan JS bundles, re-check crt.sh, review last session notes, set today's priorities.

### 15.2 Incremental Refresh
```powershell
# Diff crt.sh for new subdomains
$new = Invoke-RestMethod "https://crt.sh/?q=%25.target.com&output=json" | % { $_.name_value } | Sort -U
$diff = Compare-Object (Get-Content cached_crtsh.txt) $new | ? { $_.SideIndicator -eq '=>' }
if ($diff) { Write-Output "NEW SUBDOMAINS: $($diff.InputObject)" }

# Check Wayback for new URLs (last 24h)
$yesterday = (Get-Date).AddDays(-1).ToString("yyyyMMdd")
$today = (Get-Date).ToString("yyyyMMdd")
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com&from=${yesterday}&to=${today}&output=json"
```

### 15.3 Changelog Monitoring
Check public changelog, blog posts, social media for new features, job postings ("seeking GraphQL Engineer" = GraphQL exists), GitHub activity, npm/PyPI releases, app store updates.

### 15.4 Session Planning
List new findings since last session. Set priority targets for today. Follow up on previous session's open items.

---

## 16. WINDOWS-SPECIFIC RECON

### 16.1 PowerShell Command Equivalents
```
cat → Get-Content, grep → Select-String, sort -u → Sort-Object -Unique
curl → curl.exe (PS alias is Invoke-WebRequest), dig → Resolve-DnsName
```

### 16.2 API-Only Recon (No Native Tools)
```powershell
# crt.sh via API
Invoke-RestMethod "https://crt.sh/?q=%25.target.com&output=json" | ForEach-Object { $_.name_value } | Sort-Object -Unique
# AlienVault OTX (free, no key)
Invoke-RestMethod "https://otx.alienvault.com/api/v1/indicators/domain/target.com/passive_dns"
```

### 16.3 Batch Recon Script
```powershell
$domain = "target.com"; $out = "./recon/$domain"
New-Item -Type Directory -Path $out -Force | Out-Null
# Phase 1: crt.sh subdomains
$subs = Invoke-RestMethod "https://crt.sh/?q=%25.$domain&output=json" | % { $_.name_value } | Sort -U
$subs | Out-File "$out/subs.txt"
# Phase 2: DNS resolution
$resolved = foreach ($s in $subs) { try { $ip=[Net.Dns]::GetHostAddresses($s); "$s,$([string]::Join(';',$ip))" } catch {} }
$resolved | Out-File "$out/resolved.csv"
# Phase 3: Web probe
foreach ($r in $resolved) { $h=($r -split ',')[0]; try { $resp=Invoke-WebRequest "https://$h" -Method Head -TimeoutSec 10; "$h,$($resp.StatusCode)" } catch {} }
```

### 16.4 Tool Installation
Use Scoop for tools: `scoop install go python curl wsl`. Go tools via `go install`. Python via `pip`.

### 16.5 WSL Integration
```powershell
# Run Linux tools from PowerShell via WSL:
wsl subfinder -d target.com -o /mnt/c/Users/ADMIN/recon/subs.txt
wsl httpx -l /mnt/c/Users/ADMIN/recon/subs.txt -o /mnt/c/Users/ADMIN/recon/live.txt
# Use WSL for heavy lifting, PowerShell for orchestration and parsing:
$subs = Get-Content "recon/live.txt"; $subs.Count
```

### 16.6 Performance
Use StreamReader/StreamWriter for large files. Use `ForEach-Object -Parallel` (PS7+) for concurrent resolution.

---

## 17. RECON FOR MOBILE TARGETS

### 17.1 APK/IPA Acquisition
Android: Google Play, apkeep, adb pull. iOS: ipatool, iMazing, jailbroken device with Clutch.

### 17.2 APK Decompilation
jadx decompiled code. Check: AndroidManifest.xml (permissions, activities), strings.xml (API keys, URLs), native libs, assets, network config. React Native: index.android.bundle (same analysis as web JS). Flutter: libapp.so.

### 17.3 iOS IPA Analysis
Unzip IPA, check Info.plist (ATS exceptions, URL schemes, Firebase keys, API base URLs). Check main binary with `strings`.

### 17.4 Endpoint Extraction
```powershell
Select-String -Path "decompiled/**/*.java" -Pattern 'https?://'
Select-String -Path "strings.txt" -Pattern 'firebaseio\.com|graphql'
```

### 17.5 Mobile Secret Scanning
P1: Firebase URLs (unsecured = full data access). P2: Backend API keys. P3: Cloud service keys. P4: Third-party API keys. P5: Test credentials.

### 17.6 Deep Link Analysis
Extract URL schemes (`android:scheme`) and hosts (`android:host`) from AndroidManifest.xml intent filters. Deep link vulnerabilities: XSS via deep link parameters, path traversal, SQLi, authentication bypass, intent injection (Android).

Test on Android:
```
adb shell am start -W -a android.intent.action.VIEW -d "targetapp://profile/123"
adb shell am start -W -a android.intent.action.VIEW -d "targetapp://webview?url=javascript:alert(1)"
```

### 17.7 Mobile API Differences
Check mobile-specific endpoints (/api/v2/mobile/, /mobile-api/). Mobile endpoints may have less security, no rate limits, return more data (offline caching), skip validation. Try different User-Agent and X-Platform headers.

---

## 18. RECON FOR CLOUD TARGETS

### 18.1 S3 Bucket Enumeration
Name patterns: `target`, `target-dev`, `target-staging`, `target-backup`, `target-logs`, `target-assets`, `target-static`, `target-media`, `target-uploads`, `target-config`, `target-data`, `target-public`, `target-private`.

Check if bucket exists and is public:
```powershell
$buckets = @("target", "target-backup", "target-dev", "target-assets")
foreach ($b in $buckets) { try { $r = Invoke-WebRequest "https://${b}.s3.amazonaws.com" -TimeoutSec 5
  if ($r.Content -match 'ListBucketResult') { Write-Output "PUBLIC (listing): ${b}" }
} catch { $sc = $_.Exception.Response.StatusCode.value__; if ($sc -eq 403) { Write-Output "EXISTS (denied): ${b}" } } }
```

### 18.2 GCS Bucket Enumeration
Check `https://www.googleapis.com/storage/v1/b/{bucket}/o` for public listing. Name patterns same as S3.

### 18.3 Azure Blob Enumeration
Check `https://{account}.blob.core.windows.net/{container}` for public listing. Common containers: uploads, assets, media, public, backups, config.

### 18.4 CloudFront/CDN Origin Discovery
Find origin via DNS history (pre-CDN IPs from Wayback), cert transparency (scan subjectAltName IPs), error page analysis (some CDNs reveal origin IP), HTTP header differences (compare with/without CDN).

Common bypass techniques: send request to origin IP directly, modify Host header, use HTTP/1.0 instead of 1.1/2, try older TLS versions, add double slashes in path (`//admin`).

### 18.5 IAM Role Identification from Errors
AWS: `arn:aws:iam::123456789012:user/app-user`. GCP: `Service account [project-id@appspot.gserviceaccount.com]`. Azure: `Subscription 'sub-id' not found`.

### 18.6 Cloud Metadata Surface
When SSRF is possible: AWS IMDSv1 (http://169.254.169.254/latest/meta-data/), GCP (http://metadata.google.internal), Azure (http://169.254.169.254/metadata/instance).

### 18.7 Multi-Cloud Bucket Check
```powershell
$base = "target"; @("s3.amazonaws.com", "storage.googleapis.com", "blob.core.windows.net") | ForEach-Object { try { Invoke-WebRequest "https://${base}.$_" -TimeoutSec 5 | Out-Null; Write-Output "FOUND" } catch {} }
```

---

## 19. RECON FOR CI/CD

### 19.1 GitHub Actions Enumeration
Check public repos for `.github/workflows/`. Look for hardcoded secrets in workflow files, pull_request_target triggers (dangerous — untrusted code runs in privileged context), actions that deploy to production on push, AWS/Azure/GCP credentials in workflow steps.

```powershell
$url = "https://api.github.com/repos/org/repo/contents/.github/workflows"
$files = Invoke-RestMethod $url; $files | % { $_.name }
```

Pull request target vulnerability: contains `pull_request_target` AND checks out code and runs it = RCE via PR.

### 19.2 Exposed CI/CD Dashboards
Jenkins (/script console, /manage), GitLab CI (/explore for public projects), GitHub Actions (public workflow logs = secrets leak), CircleCI, Travis CI, Artifactory/Nexus.

### 19.3 Artifact Repository Scanning
Docker registries (Docker Hub, GCR, ACR). Package registries (npm, PyPI, Maven). Binary storage (S3 with build artifacts). Look for debug symbols, unencrypted configs, Docker images with secrets, decompilable jars, build logs with env vars.

### 19.4 CI/CD Recon Commands
```powershell
Invoke-RestMethod "https://api.github.com/orgs/{org}/repos" | ForEach-Object { $_.name }
Invoke-RestMethod "https://api.github.com/repos/{org}/{repo}/contents/.github/workflows"
```

### 19.5 CI/CD Security Indicators
Public workflow logs with env vars, GITHUB_TOKEN with excessive permissions, actions pinned to tags (not SHAs), self-hosted runners on pull_request_target, artifact uploads with .env files, unauthenticated Jenkins/GitLab.

---

## 20. RECON OUTPUT PRIORITIZATION

### 20.1 Ranking Findings by Likely Payout
```
Payout Tier   | Finding Type                          | Typical $ Range
Critical      | Cloud credentials (AWS keys)          | $2,000 - $10,000
Critical      | RCE chain                             | $2,000 - $10,000
Critical      | Full ATO (no user action)              | $1,500 - $5,000
High          | Auth bypass                           | $1,000 - $3,000
High          | SQLi with data extraction              | $500 - $2,500
High          | IDOR with PII exposure                 | $500 - $2,000
High          | S3 bucket with sensitive data          | $500 - $2,000
High          | SSRF to cloud metadata                 | $750 - $2,500
Medium        | Stored XSS                            | $250 - $1,000
Medium        | IDOR (non-sensitive)                   | $200 - $500
Medium        | Subdomain takeover                     | $200 - $500
Medium        | GraphQL introspection                  | $150 - $500
Low           | Reflected XSS                         | $100 - $250
Low           | Open redirect                         | $50 - $150
Low           | Missing security headers               | $0 - $100 (often N/A)
```

### 20.2 Confidence Scoring
```
5 - Confirmed vulnerability, exploitable (start writing report)
4 - Strong evidence, needs one more test
3 - Interesting signal, needs investigation
2 - Weak signal, could be nothing
1 - Noise, ignore
```
Examples: 5 = AWS key in JS → confirmed active via AWS CLI. 4 = API endpoint with sequential IDs → test IDOR. 3 = new dev subdomain found. 2 = unusual header response. 1 = default nginx page.

Action: Score 5 → write report. Score 4 → investigate this session. Score 3 → add to hunt list. Score 2 → note, don't spend time. Score 1 → delete.

### 20.3 Tech Stack Match with Known Bugs
```
Detected Stack      | Known Vulnerability Patterns
Rails + YAML        | CVE-2013-0156, YAML.load deserialization
Struts 2            | CVE-2017-5638, CVE-2018-11776 (OGNL injection)
Spring Boot + JDBC  | CVE-2022-22965 (Spring4Shell)
Django + Pickle     | Unsigned pickle deserialization risk
PHP + unserialize   | PHP object injection vulnerabilities
WordPress + plugins | Known CVEs for each plugin version
Jenkins + no auth   | Script console RCE
GraphQL + no auth   | Introspection + data extraction
```

### 20.4 Priority Assignment Matrix
```
P0 | Critical chain, immediate exploitation  | Hunt NOW
P1 | High confidence, high impact            | Within 1 hour
P2 | Medium confidence/impact                | Within this session
P3 | Low confidence, needs investigation     | If time permits
P4 | Informational, no immediate path        | Note and move on
```

### 20.5 Recon Output Summary
At session end, produce a summary:
```
=== Recon Summary: target.com ===
Date: 2026-01-16 | Subs: 142 | Live: 38 | JS analyzed: 23 | API endpoints: 67 | Secrets: 2
P0: None | P1: Stripe API key in app.js → confirmed → report drafted
P2: IDOR on /api/v2/users/{id} → needs fuzzing | P3: GraphQL introspection open
Next: Complete GraphQL schema, fuzz IDOR param, re-check JS bundle
```

---

## 21. RECON QUALITY CHECKS

### 21.1 The Recon Quality Checklist
```
Before you start hunting, verify you have:

[ ] Subdomains:    ≥10 for small, ≥30 for medium, ≥100 for enterprise
[ ] Live hosts:    At least 25% of subdomains should be live
[ ] Tech stack:    Identified for top 5 live hosts
[ ] APIs:          At least 1 API endpoint identified
[ ] Auth flow:     Login mechanism identified (JWT, cookie, OAuth, none)
[ ] URLs:          ≥100 for small, ≥500 for medium, ≥2000 for enterprise
[ ] JS files:      Found and analyzed (at least the main bundle)
[ ] Screenshots:   Reviewed for interesting content
[ ] Cloud:         Quick S3/GCS check done
[ ] Third-party:   Services identified and noted

If any of these are missing, GO DEEPER before starting to hunt.
```

### 21.2 Missing Data Remediation
Missing subdomains: check additional crt.sh wildcards, larger wordlist, Shodan. Missing live hosts: check non-standard ports, resolve via IP. Missing tech stack: whatweb with full URLs, check /favicon.ico, /robots.txt, error pages. Missing APIs: check JS bundles, /swagger, /docs, register account. Missing auth: visit login page, check cookies/localStorage/network tab.

### 21.3 The 10-Minute Sanity Check
Open main page in browser (2 min). Check robots.txt (1 min). Check sitemap.xml (1 min). Manual crt.sh check (1 min). Google dork site:target.com (1 min). Check status page (1 min). Check GitHub for target repos (2 min). Gut check (1 min).

### 21.4 When Quality Check Fails
Identify what's missing. If <15 min to fix: do it now. If >15 min: fix the most critical gap, note the rest. Never hunt blind — if you don't know what APIs exist, how auth works, or what tech stack is used, fix recon first.

---

## APPENDIX A: QUICK REFERENCE COMMANDS

```powershell
# crt.sh subdomains
Invoke-RestMethod "https://crt.sh/?q=%25.target.com&output=json" | % { $_.name_value } | Sort -U
# DNS resolution
[System.Net.Dns]::GetHostAddresses("target.com").IPAddressToString
# HTTP headers
Invoke-WebRequest "https://target.com" -Method Head | % Headers
# Wayback URLs
iwr "http://web.archive.org/cdx/search/cdx?url=*.target.com&output=json" | ConvertFrom-Json | % { $_[2] } | Sort -U
# JS URL extraction
(gc app.js -Raw) | Select-String '(https?://[^"''\s]+)' -AllMatches | % { $_.Matches.Value } | Sort -U
# S3 bucket check
iwr "https://target.s3.amazonaws.com" | % Content | Select-String "ListBucketResult"
```

## APPENDIX B: COMMON MISTAKES

1. Out-of-scope recon — always check scope first.
2. Over-reconning — spend 80% of time on recon, 20% on hunting. Reverse this.
3. Ignoring mobile — mobile apps have different endpoints with weaker security.
4. Skipping JS analysis — where the high-value intel lives.
5. Not filtering noise — 90% of recon data is noise. Filter aggressively.
6. Stale data — don't use week-old recon for today's session.
7. No prioritization — all findings equal = none get hunted.
8. Saving secrets — never save raw credentials to disk.
9. Tool-dependence — no tool replaces human analysis and context.
10. Giving up too early — recon that finds nothing is still valuable data.

## APPENDIX C: RECON TOOLKIT CHECKLIST

```
Passive Recon:    [ ] crt.sh  [ ] SecurityTrails  [ ] Shodan  [ ] VT  [ ] AlienVault OTX  [ ] Wayback CDX
Active Recon:     [ ] DNS wordlists  [ ] Directory wordlists  [ ] Port scanner
Analysis:         [ ] Whatweb/Wappalyzer  [ ] curl  [ ] jq  [ ] Screenshot tool  [ ] JS beautifier
Cloud:            [ ] AWS CLI  [ ] GCloud SDK  [ ] Azure CLI
Mobile:           [ ] APK downloader  [ ] jadx  [ ] apktool  [ ] iOS IPA tools
```
