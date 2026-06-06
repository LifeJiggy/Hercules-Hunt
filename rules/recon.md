# Reconnaissance Rules

Recon is not data collection. Recon is attack surface discovery.
The difference determines whether you find bugs or just fill disk space.

These rules govern how recon is run, interpreted, and turned into actionable
hunting targets. Breaking them wastes the first 40-80% of your time on every
target and guarantees you miss the highest-payout bugs.

---

## 0. ENGAGEMENT CONTEXT (READ FIRST)

This tooling is operated by an authorized bug bounty hunter against public
bounty programs with published safe-harbor terms. Recon is performed only
against assets confirmed in-scope via `/scope`.

Recon boundaries:
- Passive recon (DNS, certificates, search engines, public data) is always
  safe and has no rate limits.
- Active recon (port scanning, directory brute-force, parameter fuzzing)
  requires scope confirmation AND must respect rate limits.
- Never probe out-of-scope assets even passively. One mistake = program ban.
- Never use the target's production infrastructure for your recon infra
  (no proxying through their servers, no DNS resolution through their resolvers).

The recon below assumes you have identified the in-scope wildcard domain(s)
and know the bounty range. If you don't know the bounty range, you can't
calibrate recon depth.

---

## 1. RECON DISCIPLINE

Recon is the most dangerous phase of bug bounty. It is where most hunters
fail — not by missing bugs, but by wasting time on irrelevant data.

### 1.1 The Purpose

Recon finds attack surface. That's it. Attack surface is:
- An endpoint you can reach
- A parameter that accepts input
- An authentication boundary you can cross
- A technology version with known CVEs
- A misconfigured cloud resource
- A leaked credential that grants access

If your recon output doesn't answer "what can I attack?" it's wrong.

### 1.2 What Recon Is NOT

Recon is not:
- Collecting every subdomain ever registered (useless without live filtering)
- Saving every URL ever crawled (useless without endpoint classification)
- Running every tool on every target (you have limited time)
- Building the biggest wordlist (bigger is not better — targeted is better)
- Feeling busy while learning nothing about the target

### 1.3 Recon Paralysis

Recon paralysis is the #1 time waste in bug bounty. Symptoms:
- Running the same tools with bigger wordlists hoping for different results
- Re-running subdomain enumeration with every new tool that gets released
- Spending weeks on recon before starting to hunt
- Finding interesting data but never exploiting it because "I need to finish recon first"

Cure: Set a hard timebox per recon phase.
```
Small target (startup, <$50 bounties):     30 minutes max
Medium target (growth stage, $50-200):     2 hours max
Large target (enterprise, $200+):          4 hours max
New asset on existing target:              15 minutes max
```

After the timebox, start hunting. You can always expand recon later
when you find a specific need (e.g., "I need more subdomains of api.x.com").

### 1.4 Actionable vs. Noise Filter

Every piece of recon data must pass this test:
"Can I attack this TODAY?"

```
Actionable:   api.target.com → resolves → 443 open → returns JSON
Noise:        dev.target.com → resolves → 443 open → returns 403 → no known exploit
Noise:        staging.target.com → resolves → 443 → default nginx page
Actionable:   s3.target.com → resolves → returns XML with ListBucketResult
Noise:        mail.target.com → resolves → 443 → Exchange OWA login
Actionable:   graphql.target.com → resolves → introspection query enabled
```

If you can't attack it today, deprioritize it. Note it for later, but don't
spend time on it now.

### 1.5 Surface-First, Depth-Second

Always expand surface before deepening on any single point.
```
WRONG: Run subdomain enum → get 100 subs → pick one → deep crawl all 10,000 URLs
RIGHT: Run subdomain enum → get 100 subs → check live → find 40 live → get URLs
       → tech fingerprint → prioritize 5 most interesting → hunt those
```

You can't pick the right target if you don't know the full surface.

### 1.6 The Recon Spiral

Recon is iterative, not linear. Each phase feeds back into earlier phases:
```
Scope → Subdomain enum → Live check → URL crawl → JS analysis
  ↑                                           |
  |                                           v
  +---------- New subdomain found in JS ------+
```

When you find a new subdomain in JS, go back to subdomain enum.
When you find a new API endpoint, go back to URL crawl with that path.
When you find a new technology, go back to fingerprinting for that tech.

### 1.7 Never Skip Recon on a New Asset

Every new subdomain, every new IP range, every new cloud resource
gets its own mini-recon. You don't hunt blind.

Minimum for a new subdomain:
```
1. What technology runs here? (headers, favicon, error page)
2. What paths exist? (top 100 common paths)
3. Is it an API? (JSON response, /api prefix, GraphQL indicators)
4. What's the auth mechanism? (cookie, JWT, API key, none)
5. Any known CVEs for detected tech stack?
```

### 1.8 The 80/20 Rule of Recon

80% of actionable findings come from 20% of recon data.
That 20% is:
- Live API endpoints with auth
- Non-standard ports on interesting subdomains
- JS bundles with embedded secrets
- GraphQL introspection endpoints
- S3 buckets with public listing
- Admin/dev/staging portals accessible from the internet

Focus recon effort on finding these, not on filling out the other 80%.

### 1.9 Recon Output Must Be Consumable

Your future self (and anyone helping you) must be able to read your recon
output and immediately know what to attack. Use consistent formats:
```
host.tld | tech stack | interesting ports | notes | priority
```

### 1.10 You Will Miss Things

Accept it. The goal is not to find everything. The goal is to find enough
to get paid. Move fast, hunt what you find, and if you get stuck, go back
and find more. Perfect recon is the enemy of profitable hunting.

---

## 2. SCOPE-FIRST RECON

Never recon without scope. Never scope without reading the full policy.

### 2.1 Scope Confirmation Before Any Request

Before ANY recon request:
```
1. Read program policy in full (not just the scope table)
2. Note in-scope wildcards: *.target.com → target.com AND all subdomains
3. Note out-of-scope explicitly listed subdomains
4. Note excluded technologies (e.g., "no testing on 3rd party services")
5. Note rate limits or testing windows
```

### 2.2 Wildcard Scope Interpretation

Wildcards like `*.target.com` mean:
- IN SCOPE: target.com, www.target.com, api.target.com, app.target.com
- IN SCOPE: any-target.target.com, 123.target.com
- AMBIGUOUS: target.com's subdomain hosted on third-party (e.g., AWS)
  - If the content is target.com's, it's usually in scope
  - If the infrastructure is shared with other customers, program may claim OOS
  - Check past disclosed reports for the program's stance

Always save the scope to a file for programmatic filtering:
```
# scope.txt
*.target.com
*.api.target.com
!admin.target.com (OOS)
!*.dev.target.com (OOS)
```

### 2.3 Third-Party Asset Identification

Not everything pointing at target.com is owned by target.com.
Identify third-party services and note them:
```
3rd party         | Evidence
CDN               | CloudFront, Cloudflare, Akamai, Fastly, StackPath
Email             | SendGrid, Mailgun, SES, Mailchimp, Constant Contact
Auth              | Auth0, Okta, Firebase Auth, AWS Cognito
Analytics         | Google Analytics, Hotjar, Mixpanel, Amplitude
Support           | Zendesk, Freshdesk, Intercom, Helpscout
Media             | Brightcove, Vimeo, YouTube, Wistia
Forms             | Typeform, Google Forms, JotForm, Formspree
Payments          | Stripe, Braintree, PayPal, Square, Adyen
Infrastructure    | AWS, GCP, Azure, DigitalOcean, Heroku, Netlify
```

For third-party assets:
- Test the integration, not the third-party service itself
- E.g., Stripe integration bugs in target.com's code → in scope
- E.g., Stripe's own dashboard bug → OOS (Stripe's own bug bounty)
- OAuth flow with Auth0 → test the redirect_uri, not Auth0's login page

### 2.4 Scope Expansion Opportunities

Sometimes recon reveals assets that aren't explicitly in scope but are
owned by the target and related to in-scope assets. These require
a judgment call:

```
Opportunity                           | Action
Same ASN as in-scope assets           | Probe carefully, ask program if unclear
Same SSL certificate org              | Usually in scope, ask if uncertain
Acquired company domain               | Often excluded unless explicitly listed
Subdomain on different TLD            | Check scope wording carefully
Same WHOIS registrant                 | Weak signal, verify through program
```

Rule: If you're not sure, ask the program. One H1 message is cheaper
than a ban for testing OOS assets.

### 2.5 Scope Filtering in Automation

Every automated recon tool must filter against scope. Set this up
at the workflow level, not per-tool.

PowerShell scope filter:
```powershell
$scope = @("*.target.com", "*.target.io")
Get-Content subs.txt | Where-Object {
  $matched = $false
  foreach ($pattern in $scope) {
    $regex = $pattern -replace '\*\.', '.*\.'
    if ($_ -match "^$regex$") { $matched = $true }
  }
  return $matched
} | Out-File inscope_subs.txt
```

### 2.6 Out-of-Scope Detection By Signal

Some assets loudly announce they're OOS. Recognize these early:
```
Host returns:                        | Likely OOS
"Service not found"                  | Different platform
Default nginx/greeting page          | Unconfigured domain → potential takeover but OOS
CNAME to unconfigured S3 bucket      | Same, OOS unless specifically allowed
WordPress default page               | May be personal/abandoned project
"IIS7" default page                  | Could be legacy, check carefully
```

When you detect an OOS signal, stop probing immediately. Note it for
possible future use (if scope changes) and move on.

### 2.7 Scope Changes Tracking

Programs change scope. Track changes:
```
Check at session start: Read program page → compare with cached scope
Check after dry spells: "Maybe they expanded scope"
Check on new features: "New API likely added to scope"
```

Save scope changes to git:
```
echo "2026-01-15: Added *.new.target.com" >> scope_changelog.md
echo "2026-01-15: Removed old.admin.target.com" >> scope_changelog.md
```

### 2.8 Wildcard Edge Cases

Some programs have unusual wildcards:
```
*.target.com        → standard
target.com/*        → path scope (only certain paths)
*.target.com/*      → subdomain AND path scope
target.com          → apex only (no subdomains)
*.target.com,!*.dev → wildcard with explicit exclusions
```

Always test the edges:
- What happens if you access a subdomain not listed in scope but owned by target?
- What about target.com's staging site on staging-target.com? (Ask)

---

## 3. RECON DEPTH BY TARGET TYPE

Not all targets deserve equal recon effort. Calibrate by:

### 3.1 Target Maturity Matrix

```
Target Type       | Examples                    | Recon Depth
Startup           | <50 employees, <$5M funding | Light: 30min, focus on obvious stuff
Growth Stage      | 50-500, $5-100M             | Medium: 2hrs, include sub+JS
Mid-Market        | 500-5000, $100M-1B          | Deep: 4hrs, full pipeline
Enterprise        | 5000+, public               | Very Deep: 8hrs, multiple passes
Buggy Enterprise  | Known buggy (Uber, etc.)    | Infinite: return repeatedly
```

### 3.2 Bounty-Calibrated Depth

```
Avg Bounty  | Recon Investment | Break-even
<$50        | 30 min           | Find 1 bug to break even
$50-200     | 2 hours          | Need ~2-3 bugs/week
$200-500    | 4 hours          | 1 good bug = good week
$500-2000   | 8 hours          | 1 bug = very good month
$2000+      | As long as needed| Critical bug territory
```

Use this to decide:
- Low bounty target → shallow recon, spray-and-pray approach
- High bounty target → deep recon, find the critical path
- New program → deep recon (first hunter advantage)
- Old program → focus on new features, recent changes

### 3.3 Program Seen Count

```
New program (<1 month old):     Deep recon → You're racing other hunters
Established (1-6 months):       Medium recon → Most easy bugs are gone
Mature (6+ months):             Strategic recon → Hunt new features, edges
Old (>1 year, high bounties):   Deep recon on new assets only
Old (>1 year, low bounties):    Skip or shallow only
```

### 3.4 Startup Rules

Startups have:
- Less attack surface (fewer subdomains, simpler stacks)
- More obvious bugs (lack of security maturity)
- Lower bounties (but sometimes surprisingly high for critical)
- Faster triage and payout

Startup recon strategy:
```
1. Skip deep subdomain enum (they have ≤10 subdomains)
2. Focus on auth bypass, IDOR, mass assignment
3. Check for obvious cloud misconfigs
4. 30 minutes max, then start hunting
5. If nothing in first 30min, move on (they're too small)
```

### 3.5 Enterprise Rules

Enterprises have:
- Massive attack surface (100-1000+ subdomains)
- Complex authentication (SSO, MFA, multiple auth providers)
- Legacy systems alongside modern ones
- Slower triage but larger payouts

Enterprise recon strategy:
```
1. Full subdomain enum (every source, permutations)
2. Separate legacy from modern (different stacks, different bugs)
3. Deep JS analysis (enterprises love micro-frontends = more bundles)
4. API-focused recon (enterprises have internal/external APIs)
5. Auth flow mapping (SSO = OAuth bugs, SAML bugs)
6. Cloud misconfig scanning (S3, GCS, Azure blobs)
7. CDN/WAF identification (bypass opportunities)
```

### 3.6 Bug Bounty Platform Effects

```
HackerOne:       More technical programs, higher avg bounties, deeper recon worth it
Bugcrowd:        More varied quality, check VRT for payout ranges
Intigriti:       European targets, often smaller, adjust depth
Immunefi:        Web3 targets, deep recon on smart contracts + frontend
```

### 3.7 Unknown Target First Pass

When you know nothing about a target:
```
1. Quick grab: subfinder target.com + httpx  (5 min)
2. Shallow crawl: katana + gau                  (10 min)
3. Tech detect: whatweb on top 10 subs          (5 min)
4. Priority review: pick 3 most interesting     (5 min)
5. Quick API scan: look for GraphQL, /api       (5 min)
Total: 30 min → decide if it's worth more
```

---

## 4. SUBDOMAIN ENUMERATION RULES

Subdomain enumeration is the foundation of recon. Do it right.

### 4.1 Passive Sources Priority

Passive first. Always. Active enumeration is noisier and more likely
to trigger alerts.

Priority order (most useful first):
```
Source              | Tool/Command                     | Notes
Certificate Transp. | crt.sh                           | Best single source
DNS records         | dig, nslookup                    | A, AAAA, CNAME, MX, NS, TXT
Search engines      | Google dork: site:*.target.com   | Old but gold
Shodan              | shodan search org:"Target"       | Finds exposed services
SecurityTrails      | API call                          | Paid but comprehensive
AlienVault OTX      | Passive DNS API                   | Good historical data
Wayback Machine     | Wayback Machine CDX               | Old subdomains still live
RapidDNS.io         | RapidDNS lookup                   | Free, decent coverage
VirusTotal          | virustotal.com domain             | Includes passive DNS
DNSDumpster         | dnsdumpster.com                   | Visual map
BufferOver.run      | bufferover.run                    | Certs + DNS
```

### 4.2 Certificate Transparency (Primary Source)

Certificate transparency logs are the single best source for subdomains.
Every publicly-trusted TLS certificate is logged.

```powershell
# crt.sh query (JSON output)
curl -s "https://crt.sh/?q=%25.target.com&output=json" | `
  ConvertFrom-Json | Select-Object -ExpandProperty name_value | `
  Sort-Object -Unique | Out-File crtsh_subs.txt

# Using PowerShell with Invoke-RestMethod
$url = "https://crt.sh/?q=%25.target.com&output=json"
$subs = Invoke-RestMethod -Uri $url -Method Get | `
  ForEach-Object { $_.name_value } | `
  ForEach-Object { $_ -split "`n" } | Sort-Object -Unique

# Alternative endpoint (crt.sh v1)
curl -s "https://crt.sh/?q=%25.target.com&output=csv" | Select-String -Pattern "target.com"
```

### 4.3 DNS Enumeration

```powershell
# Standard DNS records
nslookup -type=A target.com
nslookup -type=MX target.com
nslookup -type=NS target.com
nslookup -type=TXT target.com
nslookup -type=CNAME www.target.com

# Zone transfer (rarely works but try it)
nslookup -type=NS target.com
# Get NS servers from above, then:
nslookup -type=AXFR target.com <nameserver>

# Bulk DNS resolution with PowerShell
$subs = Get-Content subs.txt
$results = foreach ($sub in $subs) {
  try {
    $ip = [System.Net.Dns]::GetHostAddresses($sub)
    [PSCustomObject]@{ Subdomain = $sub; IP = $ip.IPAddressToString -join ', ' }
  } catch {
    [PSCustomObject]@{ Subdomain = $sub; IP = "No resolution" }
  }
}
$results | Export-Csv -Path resolved.csv -NoTypeInformation
```

### 4.4 Search Engine Dorking

```
# Google dorks for subdomains
site:*.target.com -www
site:target.com intitle:"index of"
site:target.com inurl:wp-admin
site:target.com inurl:admin
site:target.com ext:pdf
site:target.com ext:xml
site:target.com ext:json

# Bing (often has different results)
domain:target.com

# Shodan
shodan search hostname:target.com
shodan search org:"Target Inc"
shodan search ssl:"target.com"
```

### 4.5 Active Enumeration

Only use active enumeration when passive is insufficient or when
you suspect blind spots (internal subdomains, dev servers).

```powershell
# DNS brute force
# Use a wordlist appropriate for the target type:

# For enterprises: common.txt (all ~3000 common names)
# For startups: small.txt (top 100 names only)
# For specific tech: tech-specific.txt

# PowerShell DNS brute force
$wordlist = Get-Content "wordlists/subdomains/top100.txt"
$domain = "target.com"
$results = foreach ($word in $wordlist) {
  $fqdn = "${word}.${domain}"
  try {
    $null = [System.Net.Dns]::GetHostAddresses($fqdn)
    Write-Output $fqdn
  } catch {
    # no resolution, skip
  }
}
$results | Out-File dns_brute.txt
```

### 4.6 Wordlist Selection

Wordlist size by target type:
```
Target Type       | Wordlist Size  | Example Wordlist
Startup           | 100-500        | top100, common names
Medium            | 1,000-5,000    | subdomain_mega, commonspeak2
Enterprise        | 10,000-50,000  | all.txt, best-dns-wordlist
Specific (API)    | 100            | api-names.txt (api, v1, v2, dev-api, etc.)
Specific (Admin)  | 50             | admin-names.txt (admin, dashboard, portal)
```

Custom wordlist categories to create:
```
api-names.txt:     api, v1, v2, v3, dev-api, api-dev, staging-api, api-staging,
                   api-v1, api-v2, api-v3, sandbox-api, public-api, private-api,
                   internal-api, partner-api, graphql, api-graphql, gateway,
                   api-gateway, backend, api-backend, services, api-services

admin-names.txt:   admin, admin1, admin2, dashboard, portal, admin-portal,
                   administrator, control, manage, management, admin-console,
                   console, cpanel, admin-panel, admin-backend, backoffice,
                   admin-dashboard, admincp, admin-area, admin-console

dev-names.txt:     dev, staging, stage, test, testing, qa, sandbox, development,
                   develop, uat, beta, alpha, preprod, pre-production, canary,
                   integration, int, demo, trial, playground, lab, experimental

internal-names.txt: internal, internal-api, internal-admin, internal-tools,
                    internal-dashboard, internal-app, internal-portal,
                    corp, corporate, employee, employees, staff, hr, payroll,
                    jira, confluence, jenkins, gitlab, github, bitbucket
```

### 4.7 Permutation Rules

After initial enumeration, generate permutations of found subdomains:

```
Base subdomain: api-v2.target.com
Permutations:
  api-v1.target.com          (version iteration)
  api-v3.target.com          (version iteration)
  api-v4.target.com          (version iteration)
  api-dev.target.com         (environment suffix)
  api-staging.target.com     (environment suffix)
  api-qa.target.com          (environment suffix)
  dev-api.target.com         (environment prefix)
  staging-api.target.com     (environment prefix)
  api.target.com:8443        (port variation, for dead subdomains)
  api.target.com/api         (path variation)
  api.target.com/v1          (path version)
  api.target.com/v2          (path version)
  api.target.com/graphql     (path technology)
```

PowerShell permutation generator:
```powershell
$base = "api-v2"
$domain = "target.com"
$versions = @("v1", "v3", "v4")
$envs = @("dev", "staging", "qa", "sandbox", "test")
$results = @()

# Version iterations
foreach ($v in $versions) { $results += "$($base -replace 'v2', $v).$domain" }

# Environment suffixes
foreach ($env in $envs) { $results += "${base}-${env}.$domain" }

# Environment prefixes
foreach ($env in $envs) { $results += "${env}-${base}.$domain" }

$results | Sort-Object -Unique | Out-File permutations.txt
```

### 4.8 Subdomain Takeover Detection

Every subdomain that resolves but returns no content is a potential takeover:
```
Check these signatures:
NXDOMAIN:                     Not a CNAME target → not a takeover risk
CNAME points to unclaimed:    CloudFront, S3, Heroku, GitHub Pages → TAKEOVER
CNAME points to claimed:      Third-party service in use → normal
CNAME points to dead:         Past due service → TAKEOVER

Common takeover signatures:
  AWS S3: NoSuchBucket
  AWS CloudFront: BadRequest (no distribution found)
  Heroku: No such app
  GitHub Pages: 404 (custom domain)
  Azure: The specified resource does not exist
  Shopify: Only one shop is allowed
  Fastly: Fastly error: unknown domain
  Pantheon: The site you are looking for is not found
  Bitbucket: Repository not found
  Desk: Get Started
  Zendesk: Help Center Closed
```

### 4.9 Recursive Subdomain Enumeration

Sometimes subdomains of subdomains exist:
```
app.target.com
  └─ app.api.target.com (found by crt.sh)
  └─ app.dev.target.com (found by crt.sh)
  └─ app.cdn.target.com (found by DNS brute force)
```

Run enumeration recursively:
```
1. Get all subdomains of *.target.com
2. Extract unique second-level domains (e.g., app, api, dev)
3. Run brute force on those: api.target.com, app.target.com, dev.target.com
4. Check if results have new third-level subdomains
```

### 4.10 Check the Obvious

Don't overthink it. Check these first:
```
www.target.com, mail.target.com, remote.target.com, blog.target.com,
webmail.target.com, server.target.com, ns1.target.com, ns2.target.com,
smtp.target.com, pop.target.com, secure.target.com, vpn.target.com,
admin.target.com, api.target.com, dev.target.com, stage.target.com,
staging.target.com, test.target.com, m.target.com, mobile.target.com,
my.target.com, portal.target.com, login.target.com, auth.target.com,
sso.target.com, help.target.com, support.target.com, docs.target.com,
status.target.com, wiki.target.com, git.target.com, jenkins.target.com,
jira.target.com, confluence.target.com, kb.target.com, knowledgebase.target.com,
partner.target.com, partners.target.com, vendor.target.com, vendors.target.com,
edge.target.com, cdn.target.com, static.target.com, assets.target.com,
media.target.com, img.target.com, images.target.com, upload.target.com,
download.target.com, files.target.com, store.target.com, shop.target.com,
billing.target.com, payments.target.com, checkout.target.com,
webhook.target.com, hooks.target.com, callback.target.com,
monitor.target.com, metrics.target.com, logs.target.com,
graphql.target.com, api-gateway.target.com, gateway.target.com
```

---

## 5. LIVE HOST DISCOVERY RULES

Not all subdomains are live. Not all live hosts are interesting.

### 5.1 Port Selection

By default, probe these ports:
```
Web (always):       80, 443, 8080, 8443
APIs (common):      3000, 5000, 8000, 9000
Admin (common):     2082, 2083, 2086, 2087
Database (check):   3306 (MySQL), 5432 (Postgres), 27017 (Mongo), 6379 (Redis)
Other:              22 (SSH), 21 (FTP), 25 (SMTP), 8443 (alt SSL)
```

Depth by target:
```
Shallow (startup):  80, 443 only
Medium (growth):    80, 443, 8080, 8443
Deep (enterprise):  Full top 100 ports
Full:               All 65535 ports (only on critical targets)
```

### 5.2 HTTP vs HTTPS Probing

```
Always probe both:
  HTTP:  http://sub.target.com:80
  HTTPS: https://sub.target.com:443

Check for:
  HTTP → redirects to HTTPS     (normal, note the redirect)
  HTTP → serves content         (interesting, security issue potential)
  HTTP → times out              (firewall, note)
  HTTPS → valid cert            (normal)
  HTTPS → invalid cert          (interesting: internal service, expired cert)
  HTTPS → self-signed cert      (very interesting: dev/staging/internal)

Port-specific checks:
  http://sub.target.com:8080    (alternative HTTP)
  https://sub.target.com:8443   (alternative HTTPS)
  http://sub.target.com:3000    (dev server, API)
```

### 5.3 Screenshot Analysis

Screenshots tell you more than headers in seconds:
```
What to look for in screenshots:
  Login pages:                 auth surface (SSO, OAuth, custom auth)
  Admin panels:                potential privilege escalation
  Dashboards:                  potential IDOR, exposed metrics
  Default pages:               unconfigured service (takeover?)
  Error pages:                 tech stack disclosure
  Blank pages:                 API endpoint without UI
  "Under construction":        dev/staging, may have weaker security
  Mobile views:                different functionality from desktop

For each screenshot, assign:
  Priority 1: Login/Admin/Dashboard pages → hunt immediately
  Priority 2: API responses, error pages   → review for endpoints
  Priority 3: Default/blank pages          → low unless takeover possible
```

### 5.4 Status Code Analysis

```
200 OK:                 Live, serving content → probe deeper
301/302 Redirect:       Check redirect target, follow it
401 Unauthorized:       Auth wall → interesting, map the auth
403 Forbidden:          Service exists but blocked → try bypass, path fuzzing
404 Not Found:          Dead path but host is live → try other paths
500 Server Error:       Interesting! Potential vulnerability or misconfig
502/503/504:            Gateway/proxy issues → might expose upstream services
429 Rate Limited:       WAF/proxy rate limiting active → slow down
999 Request Denied:     Often LinkedIn/Facebook blocking → stop scanning
```

### 5.5 Content-Type Based Prioritization

```
Content-Type                    | Priority | Action
text/html (login page)          | High     | Auth testing
text/html (admin panel)         | Critical | Immediate hunting
application/json                | Critical | API endpoint
application/xml                 | High     | SOAP/XML endpoint
text/plain (API response)       | High     | May contain data
application/octet-stream        | Medium   | File download, check path traversal
application/pdf                 | Low      | Documentation (unless sensitive)
image/*                         | Low      | Static assets (unless upload endpoint)
text/javascript                 | Critical | JS bundle → analysis
```

### 5.6 Response Size Anomaly Detection

Compare response sizes across similar endpoints:
```
Same endpoint, different parameters:
  /api/user?id=1      → 5KB response
  /api/user?id=2      → 5KB response
  /api/user?id=admin  → 2KB response    ← Anomaly! Different behavior

Same host, different paths:
  / → 15KB (full app)
  /api → 0.2KB (API response)
  /admin → 20KB (admin panel)

Large response on a normally small endpoint → potential data leak
Small response on a normally large endpoint → error or access denied
```

---

## 6. URL COLLECTION RULES

URLs are your raw material. Collect them wisely.

### 6.1 Source Selection By Target Type

```
Source              | Startup | Medium | Enterprise | Best For
Web Archive (CDX)   | Yes     | Yes    | Yes        | Historical endpoints
Common Crawl        | No      | No     | Yes        | Deep historical
GAU                 | Yes     | Yes    | Yes        | Quick broad crawl
Katana              | Yes     | Yes    | Yes        | Active crawl
WaybackURLs         | Yes     | Yes    | Yes        | Quick passive
Gospider            | Yes     | Yes    | Yes        | Spider-based
Burp Spider         | Yes     | Yes    | Yes        | Interactive crawl
```

### 6.2 Wayback Machine Depth

The Wayback Machine has multiple ways to query:
```powershell
# CDX API (most comprehensive)
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com&output=json&fl=original&collapse=urlkey"

# Wayback Machine changes (new URLs since last check)
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com&from=2025&to=2026&output=json"

# Specific timestamp ranges
$from = "2025"
$to = "2026"
$url = "http://web.archive.org/cdx/search/cdx?url=*.target.com&from=${from}&to=${to}&output=json"
Invoke-RestMethod -Uri $url | ConvertFrom-Json | Select-Object -Skip 1

# PowerShell function for wayback
function Get-WaybackUrls {
  param($domain, $from = "2020", $to = "2026")
  $url = "http://web.archive.org/cdx/search/cdx?url=*.${domain}&from=${from}&to=${to}&output=json"
  $results = Invoke-RestMethod -Uri $url | ConvertFrom-Json
  return $results | Select-Object -Skip 1 | ForEach-Object { $_[2] } | Sort-Object -Unique
}
Get-WaybackUrls -domain "target.com" | Out-File wayback_urls.txt
```

### 6.3 JS URL Extraction

JavaScript files contain embedded URLs, endpoints, and routes:
```powershell
# Extract URLs from JS files
curl -s "https://target.com/app.js" | Select-String -Pattern '(https?://[^"''\s]+)' -AllMatches

# Extract paths from JS files (relative URLs)
curl -s "https://target.com/app.js" | Select-String -Pattern "[''']/([a-zA-Z0-9_\-./]+)[''']" -AllMatches

# PowerShell JS URL extraction
function Extract-JsUrls {
  param($jsContent)
  $patterns = @(
    '(https?://[^"''\s>)]+)',
    "[''']/(api|v[0-9]+|graphql|rest|service)[^"''\s]*[''']",
    "['''](/[a-zA-Z0-9_\-./]+?\.(json|xml|php|aspx|jsp|do|action))[''']",
    '(?:url|path|endpoint|route|baseURL)\s*[:=]\s*["'']([^"'']+)["'']'
  )
  foreach ($pattern in $patterns) {
    [regex]::Matches($jsContent, $pattern) | ForEach-Object { $_.Groups[1].Value }
  }
}

$js = (Invoke-WebRequest -Uri "https://target.com/app.js").Content
Extract-JsUrls -jsContent $js | Sort-Object -Unique | Out-File js_urls.txt
```

### 6.4 Active Crawling Rules

Active crawling (live spider) is useful but noisy:
```
When to use:
  - When passive sources give <100 URLs
  - When you need to find client-side rendered routes
  - When the target is a SPA (single page application)

Tool selection:
  Katana:      Fast, configurable, good for large targets
  Gospider:    Good correlation with other data sources
  Burp Spider: Good for interactive exploration

Depth settings:
  Startup:     Depth 1 only (no form submission)
  Medium:      Depth 2 (follow links within target.com)
  Enterprise:  Depth 3+ (follow cross-links within scope)

Crawl delay:
  Default:     1 second between requests
  Slow:        5+ seconds (if rate limited)
  Fast:        0.1 seconds (if no rate limiting detected)
```

### 6.5 Directory Brute-Force (When Needed)

Use only when other URL sources fail:
```powershell
# PowerShell brute force (single-threaded, slow but works):
$wordlist = Get-Content "wordlist.txt"
$base = "https://target.com"
$results = foreach ($path in $wordlist) {
  try {
    $resp = Invoke-WebRequest -Uri "${base}/${path}" -Method Head -TimeoutSec 5
    $code = $resp.StatusCode
    if ($code -ne 404) { Write-Output "${base}/${path} → ${code}" }
  } catch { }
}
```

When to brute-force:
```
  - Target has no JS files (rare in modern apps)
  - Passive URL collection returns <50 URLs
  - You suspect hidden admin or dev paths
  - You found a new subdomain with no existing URL data

Wordlist selection:
  Small:    directory-list-2.3-small.txt (top 1000)
  Medium:   directory-list-2.3-medium.txt (top 10000)
  Large:    directory-list-2.3-big.txt (top 50000)

Extensions to check:
  Web:      .php, .asp, .aspx, .jsp, .do, .action
  API:      .json, .xml, .yaml, .yml
  Config:   .env, .config, .conf, .ini
  Data:     .sql, .bak, .old, .txt, .log, .csv
  Docs:     .pdf, .doc, .docx, .xls, .xlsx
```

### 6.6 URL Cleanup and Deduplication

Collected URLs need cleanup:
```powershell
$urls = Get-Content raw_urls.txt
$clean = $urls | ForEach-Object {
  $_ -replace '#.*$', '' `
     -replace '\.([a-z0-9]{20,})\.(js|css)', '.*.$2' `
     -replace '\?.*$', '' `
     -replace '/$', ''
} | Sort-Object -Unique
$clean | Out-File clean_urls.txt
```

Remove:
```
  - Duplicate URLs (same path, different params)
  - Static asset URLs (.css, .png, .jpg, .svg, .ico, .woff, .woff2)
  - Third-party analytics URLs
  - CDN URLs (cdn.target.com → keep; cdn.cloudflare.com → remove)
```

### 6.7 Parameter Extraction

URLs with parameters are more interesting than those without:
```powershell
# Extract all unique parameter names
$urls = Get-Content all_urls.txt
$params = $urls | ForEach-Object {
  if ($_ -match '\?(.+?)(?:#|$)') {
    $matches[1] -split '&' | ForEach-Object { $_ -split '=' | Select-Object -First 1 }
  }
} | Sort-Object -Unique
$params | Out-File params.txt

# Find URLs with specific interesting params
$interestingParams = @("id", "user", "admin", "token", "key", "api", "file",
  "path", "url", "redirect", "return", "next", "callback", "page", "page_id",
  "document", "upload", "download", "debug", "test", "mode", "action", "method")

$urls | Where-Object {
  $interestingParams | Where-Object { $_ -match "[?&]${_}[= ]" }
} | Out-File interesting_param_urls.txt
```

### 6.8 URL Trie Building

Build a trie (prefix tree) of URL paths to find common patterns:
```
Given URLs:
  /api/v1/users
  /api/v1/users/123
  /api/v1/users/123/profile
  /api/v2/users
  /api/v2/users/123
  /api/v1/products
  /api/v1/products/456

Trie:
  /api
    /v1
      /users
        /{id}
          /profile
      /products
        /{id}
    /v2
      /users
        /{id}

This reveals:
  - API structure (versioned, RESTful)
  - ID patterns (numeric, UUID)
  - Relationships between resources
```

---

## 7. JS BUNDLE ANALYSIS RULES

JavaScript files are your highest-value recon target. They contain
the entire client-side application structure.

### 7.1 Which JS Files to Analyze

Not all JS files are equal. Prioritize:
```
Priority 1 (analyze immediately):
  app.js, main.js, bundle.js, index.js
  commons.js, vendor.js (shared dependencies)
  [hash].js (large webpack bundles)

Priority 2 (analyze after priority 1):
  api.js, service.js, client.js
  config.js, settings.js, constants.js
  auth.js, login.js, signup.js
  admin.js, dashboard.js, management.js

Priority 3 (quick scan only):
  third-party libraries (jquery, lodash, react)
  analytics scripts (GA, Hotjar, Mixpanel)
  chat widgets (Intercom, Drift, LiveChat)
  minified dependencies (usually no custom code)

Priority 4 (skip):
  Known CDN libraries (cdnjs, unpkg, jsdelivr)
  Map files (.map) → handle separately (see 7.5)
```

### 7.2 What to Look For

Every JS file gets analyzed for:
```
API Endpoints:
  /api/v1/, /api/v2/, /api/rest/
  /graphql, /query
  /internal/, /private/, /partner/

Authentication:
  JWT tokens, apiKey, api_key, accessToken, refreshToken
  OAuth client IDs, redirect URIs
  Firebase config (apiKey, authDomain, projectId)
  Auth0 domain, Okta domain

Hardcoded Credentials:
  AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
  GCP service account JSON
  Azure connection strings
  Database connection strings
  API keys for third-party services

Feature Flags / Hidden Features:
  showAdminDashboard, isAdmin, isInternalUser
  debug: true, testing: true, maintenance: false
  featureFlags, experiments, ABTesting

Internal Hostnames:
  internal.target.com, dev.target.com, admin.target.com
  Jenkins URL, Jira URL, Confluence URL
  Grafana, Kibana, Prometheus URLs
  Database hostnames, Redis hostnames

Sensitive Patterns:
  password, secret, token, key, credential
  admin, root, sudo, superuser
  internal, private, hidden, debug, test, dev
  s3://, gs://, azure://, wasabi://
  http:// (internal HTTP endpoints)
  slack://, discord://, webhook URLs
```

### 7.3 JS Analysis Commands

```powershell
# Quick regex scan for endpoints and secrets
$js = Get-Content raw_js.js -Raw

# Find API endpoints
[regex]::Matches($js, "['''](https?://[^"''\s]+)[''']") |
  ForEach-Object { $_.Groups[1].Value } |
  Where-Object { $_ -notmatch '(google|facebook|twitter|cdn|cloudflare|gstatic)' } |
  Sort-Object -Unique | Out-File js_endpoints.txt

# Find potential API keys and tokens
$patterns = @(
  "['''](?:api[_-]?key|apikey)[''']\s*[:=]\s*[''']([^"'']+)[''']",
  "['''](?:access[_-]?key|accesskey)[''']\s*[:=]\s*[''']([^"'']+)[''']",
  "['''](?:secret|secret[_-]?key)[''']\s*[:=]\s*[''']([^"'']+)[''']",
  "['''](?:token|bearer)[''']\s*[:=]\s*[''']([^"'']+)[''']",
  '(?:AKIA[0-9A-Z]{16})',  # AWS access key
  '(?:sk-[a-zA-Z0-9]{20,})',  # Stripe/OpenAI key pattern
  '(?:ghp_[a-zA-Z0-9]{36})'  # GitHub token
)

foreach ($pattern in $patterns) {
  $matches = [regex]::Matches($js, $pattern)
  foreach ($match in $matches) {
    $value = if ($match.Groups[1]) { $match.Groups[1].Value } else { $match.Value }
    Write-Output "[SECRET] Pattern: $pattern → Value: $value"
  }
}

# Find GraphQL operations
[regex]::Matches($js, '(query|mutation|subscription)\s+\w+\s*\{', 'IgnoreCase') |
  ForEach-Object { $_.Value }

# Find React route definitions
[regex]::Matches($js, '(path|route|to)\s*[:=]\s*["'']([^"'']+)["'']", 'IgnoreCase') |
  ForEach-Object { $_.Groups[2].Value } | Sort-Object -Unique |
  Out-File react_routes.txt
```

### 7.4 Identifying Bundled Frameworks

Recognizing the framework helps you understand the app structure:
```
React:
  - __REACT_DEVTOOLS_GLOBAL_HOOK__
  - React.createElement
  - useState, useEffect, useRef, useCallback

Angular:
  - ng-version attribute
  - Zone.js presence
  - main-es2015.js pattern

Vue:
  - vue.esm.js, vue.runtime.esm.js
  - _createElementVNode, _createBlock
  - createApp, defineComponent

Next.js:
  - _next/static/chunks/
  - __NEXT_DATA__
  - next: { }

Nuxt.js:
  - _nuxt/ pattern
  - __NUXT__

Gatsby:
  - webpack-runtime-
  - chunk-map.json pattern

Svelte:
  - __SVELTE_APP
  - svelte/internal
```

### 7.5 Source Map Exploitation

Source maps (.map files) can reveal the original, unminified code:
```powershell
# Check if source maps are available
$base = "https://target.com/assets/app.js"
$mapUrl = $base + ".map"
$mapUrl2 = $base -replace '\.js$', '.js.map'

try {
  $map = Invoke-WebRequest -Uri $mapUrl -Method Get
  if ($map.StatusCode -eq 200) {
    Write-Output "Source map available: $mapUrl"
    $mapJson = $map.Content | ConvertFrom-Json
    $mapJson.sources | ForEach-Object { Write-Output "Source: $_" }
  }
} catch { Write-Output "No source map at $mapUrl" }
```

Source map contents reveal:
```
  - Original file structure
  - Commented-out code
  - Debug statements
  - Internal documentation
  - Unminified variable names (more readable)

Common source map locations:
  /js/app.js.map
  /assets/app.[hash].js.map
  /static/js/main.[hash].js.map
  /_next/static/chunks/pages/index-[hash].js.map
  /dist/app.js.map
```

### 7.6 JS Bundle Diffing Over Time

Track changes in JS bundles between sessions:
```powershell
# Download current version
curl -s "https://target.com/assets/app.js" -o app_current.js

# Compare with previous version
if (Test-Path "app_previous.js") {
  $diff = Compare-Object (Get-Content app_current.js) (Get-Content app_previous.js)
  $diff | Where-Object { $_.SideIndicator -eq '=>' } | ForEach-Object {
    Write-Output "[NEW] $_"
  }
  $diff | Where-Object { $_.SideIndicator -eq '<=' } | ForEach-Object {
    Write-Output "[REMOVED] $_"
  }
}

# Save for next comparison
Copy-Item app_current.js app_previous.js -Force

# Alternatively, compare by hash
$currentHash = (Get-FileHash app_current.js -Algorithm SHA256).Hash
$prevHash = if (Test-Path "app_hash.txt") { Get-Content app_hash.txt } else { "" }

if ($currentHash -ne $prevHash) {
  Write-Output "JS bundle changed! Review for new endpoints/secrets."
  $currentHash | Out-File app_hash.txt
}
```

### 7.7 Deobfuscation

When JS is heavily obfuscated:
```
Tools:
  - de4js (https://lelinhtinh.github.io/de4js/)
  - jsnice.org
  - UnPacker (for eval-based packing)
  - Prettier (for basic formatting)

Signs of obfuscation:
  - eval() calls with encoded strings
  - String.fromCharCode()
  - base64-like strings in variables
  - Huge arrays of strings
  - Functions named _0x1234

If you can't deobfuscate:
  - Still extract URLs with regex patterns
  - Still find API endpoints (they're often in plain strings)
  - Still identify framework patterns
  - Look for smaller, non-obfuscated bundles
  - Check if the source map is available (often not obfuscated)
```

### 7.8 Prioritization Within JS Analysis

After analyzing all JS files, prioritize findings:
```
Immediate action:
  - Hardcoded API keys/secrets
  - Internal API endpoints (different domain)
  - Admin routes (/admin/dashboard)
  - Debug endpoints
  - GraphQL endpoints

High priority:
  - New API endpoints not in your URL collection
  - Internal hostnames
  - Feature flags for hidden functionality
  - OAuth client IDs with redirect URIs

Medium priority:
  - API structure understanding (how they version, auth, error)
  - React/Vue route definitions
  - Parameter structures for known endpoints

Low priority:
  - Third-party library URLs (already known)
  - Common endpoints already collected
  - Generic configuration values
```

### 7.9 JS File Discovery

Find all JS files on the target:
```powershell
# From HTML source
curl -s "https://target.com" | Select-String -Pattern 'src=["'']([^"'']+\.js[^"'']*)'

# From sitemap
curl -s "https://target.com/sitemap.xml" | Select-String -Pattern '\.js'

# PowerShell to collect all JS URLs from page
$html = (Invoke-WebRequest -Uri "https://target.com").Content
$jsUrls = [regex]::Matches($html, '(?:src|href)=["'']([^"'']*\.js(?:[?#][^"'']*)?)') |
  ForEach-Object { $_.Groups[1].Value }
$jsUrls | Sort-Object -Unique | Out-File js_files.txt
```

---

## 8. API ENDPOINT EXTRACTION

APIs are where the money is. Find them, map them, test them.

### 8.1 API Detection from HTTP Traffic

```
API indicators in responses:
  Content-Type: application/json
  Content-Type: application/xml
  Content-Type: text/plain (with JSON-like body)
  X-API-Version header
  X-RateLimit-* headers
  WWW-Authenticate: Bearer
  Response body starts with { or [
  Response body is a single string (token, ID)

API indicators in URLs:
  /api/
  /v1/, /v2/, /v3/
  /rest/
  /graphql
  /soap/
  /odata/
  /services/
  /rpc/
  /json/
  /xmlrpc/
  .json extension
  .xml extension
```

### 8.2 GraphQL Detection

GraphQL is increasingly common and offers a massive attack surface:
```powershell
# Detection methods:
# 1. POST to /graphql with {"query":"{__typename}"}
# 2. GET to /graphql?query={__typename}
# 3. Check for Apollo, Relay, urql in JS bundles
# 4. Response has "errors" array with GraphQL format
# 5. Presence of __typename in responses

# Test for GraphQL
curl -s "https://target.com/graphql" -H "Content-Type: application/json" `
  -d '{"query":"{__typename}"}' | ConvertFrom-Json | ConvertTo-Json

# Introspection query to dump the entire schema:
$introspection = @{
  query = "query { __schema { types { name fields { name type { name kind } } } } }"
} | ConvertTo-Json
curl -s "https://target.com/graphql" -H "Content-Type: application/json" `
  -d $introspection | ConvertFrom-Json | ConvertTo-Json -Depth 10
```

Common GraphQL paths to check:
```
/graphql, /graphql/v1, /graphql/v2, /query, /api/graphql
/api/query, /gql, /gql/v1, /v1/graphql, /v2/graphql
/explorer, /graphiql, /graphql/explorer, /playground, /api/playground
```

### 8.3 REST API Structure Mapping

Map the REST API structure from endpoints found:
```
Standard REST patterns:
  GET    /api/v1/users              → List users
  GET    /api/v1/users/{id}         → Get user
  POST   /api/v1/users              → Create user
  PUT    /api/v1/users/{id}         → Update user
  PATCH  /api/v1/users/{id}         → Partial update
  DELETE /api/v1/users/{id}         → Delete user
  GET    /api/v1/users/{id}/posts   → User's posts

Common API patterns to enumerate:
  {resource}:        users, posts, products, orders, payments, accounts
  {resource}/{id}:   users/123, posts/456
  {parent}/{id}/{child}:  users/123/orders

API versioning patterns:
  /api/v1/          → most common
  /api/v1.2/        → semantic versioning
  /api/2022-01-01/  → date-based
  /api/beta/        → beta channel
  /api/experimental/ → experimental
```

### 8.4 API Parameter Enumeration

For each API endpoint, enumerate parameters:
```
Common API parameters:
  Pagination:   page, limit, offset, cursor, after, before, since, until
  Filtering:    filter, search, q, query, sort, order, orderBy
  IDs:          id, ids, userId, postId, accountId, organizationId
  Expansion:    include, expand, fields, select, embed
  Auth:         token, api_key, apikey, access_token, session
  Action:       action, method, operation, command
  Testing:      debug, test, dry_run, simulate, preview
```

### 8.5 Custom API Recognition

Not all APIs follow REST or GraphQL standards:
```
Custom API indicators:
  - /rpc/[method] format
  - /command/[action] format
  - /do/[action] format
  - JSON-RPC (Content-Type: application/json-rpc)
  - XML-RPC (Content-Type: text/xml)
  - SOAP (WSDL available at /service?wsdl)
  - gRPC (Content-Type: application/grpc, but hard to detect externally)
  - WebSocket (ws:// or wss:// endpoints)
  - Server-Sent Events (text/event-stream)
  - OData ($metadata endpoint)
```

### 8.6 API Documentation Discovery

API docs are a goldmine:
```
Common doc locations:
  /docs, /api/docs, /api-docs
  /swagger, /swagger.json, /swagger.yaml, /swagger.yml
  /api/swagger.json, /api/swagger.yaml
  /openapi.json, /openapi.yaml, /api/openapi.json
  /api/spec, /api/spec.json
  /api/v1/docs, /api/v1/swagger
  /rest/docs, /rest/swagger
  /graphql/docs, /graphql/playground, /graphiql
  /api/playground, /api/graphiql

Swagger/OpenAPI parsing:
  $swagger = Get-Content swagger.json | ConvertFrom-Json
  $swagger.paths.PSObject.Properties | ForEach-Object {
    $path = $_.Name
    $methods = $_.Value.PSObject.Properties | ForEach-Object { $_.Name.ToUpper() }
    foreach ($method in $methods) { Write-Output "${method} ${path}" }
  }
```

### 8.7 API Key Storage Patterns

How does the client store and send API keys?
```
In JS config file:        const API_KEY = "abc123def456";
In localStorage:          Check for auth tokens
In sessionStorage:        Check for temp tokens
In cookies:               httpOnly → can't access via JS
In request headers:       Authorization: Bearer <token>
                          X-API-Key: <key>
                          X-Auth-Token: <token>
```

### 8.8 API Rate Limit Recognition and Testing

Before testing, understand rate limits:
```
Rate limit indicators:
  X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, Retry-After
  Response codes: 429 Too Many Requests, 403 Forbidden (when rate limited)

Rate limit bypass techniques:
  1. Change IP (VPN, proxy, IPv6 rotation)
  2. Add X-Forwarded-For header with different IPs
  3. Change User-Agent
  4. Use different endpoints (same function, different route)
  5. Use different HTTP methods
  6. Add random query parameters (?cacheBuster=123)
```

---

## 9. TECHNOLOGY FINGERPRINTING RULES

Knowing the tech stack tells you which bugs are most likely to exist.

### 9.1 HTTP Header Analysis

Headers reveal more than most people check:
```
Server header (often revealing):
  Server: nginx               → nginx-specific config bugs
  Server: Apache/2.4.41      → Apache version-specific CVEs
  Server: Microsoft-IIS/10.0  → IIS-specific attacks
  Server: CloudFront          → CDN, check origin bypass
  Server: GSE                 → Google Search Appliance (old, vulnerable)
  No Server header            → Possibly behind WAF/proxy

X-Powered-By header:
  X-Powered-By: Express       → Node.js Express app
  X-Powered-By: ASP.NET       → .NET Framework
  X-Powered-By: PHP/7.4       → PHP version

Security headers (present or missing):
  Strict-Transport-Security     → Missing = MITM risk
  Content-Security-Policy       → Present = evaluate for bypass
  X-Frame-Options              → Missing = clickjacking
  X-Content-Type-Options       → Missing = MIME sniffing
  X-XSS-Protection             → Deprecated but sometimes present
  Referrer-Policy               → Info disclosure
  Set-Cookie (SameSite)        → SameSite=None = CSRF in some cases

Custom headers (very interesting):
  X-API-Version: 2             → API version info
  X-Upstream: server-42        → Internal hostname leak
  X-Backend: 10.0.0.5         → Internal IP leak
  X-Served-By: target-web-01   → Server naming convention
  X-Debug: true                → Debug mode enabled?
  X-Environment: staging       → Environment disclosure
```

### 9.2 Favicon Hashing

Favicons uniquely identify technologies and platforms:
```powershell
# Download favicon
curl -s "https://target.com/favicon.ico" -o favicon.ico

# Compute hash (MD5)
$hash = (Get-FileHash favicon.ico -Algorithm MD5).Hash.ToLower()

# Check against known favicon hashes
$knownFavicons = @{
  "815075b0c6a2f60e3f8d7f6a7b8c9d0e" = "Confluence"
  "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" = "Jenkins"
  "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6" = "GitLab"
  "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6" = "Grafana"
  "d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6" = "Kibana"
}

if ($knownFavicons.ContainsKey($hash)) {
  Write-Output "Favicon matches: $($knownFavicons[$hash])"
} else {
  Write-Output "Unknown favicon hash: $hash"
}
```

### 9.3 Error Page Analysis

Error pages leak technology information:
```
Force errors intentionally:
  curl "https://target.com/nonexistent_page_12345"
  curl "https://target.com/?id=1'"
  curl -X PURGE "https://target.com/api/v1/users"
  curl "https://target.com/../../../etc/passwd"

Error page tells you:
  "The resource you are looking for..."           → ASP.NET
  "File not found."                                → PHP, generic
  "Not Found" (plain text)                        → nginx (custom)
  "404 Not Found: Requested route not found"      → Express.js
  "No route matched"                              → Laravel
  "Not Found: /nonexistent"                       → Flask
  "HTTP Status 404 – Not Found"                   → Java (Tomcat/JBoss)
  Stack trace with line numbers                   → Debug mode enabled!
  Exception with SQL query                        → SQL error disclosure
```

### 9.4 Framework-Specific Detection

```
Spring Boot (Java):
  - /actuator, /actuator/health, /actuator/info
  - Error page: Whitelabel Error Page
  - Header: X-Application-Context

Django (Python):
  - /admin/ (Django admin interface)
  - csrftoken cookie
  - Error: "Django version X.Y.Z"

Rails (Ruby):
  - /assets/application-[hash].js
  - Cookie: _session_id
  - /rails/info/routes (if dev mode)

Laravel (PHP):
  - /_debugbar/open (if debug enabled)
  - Cookie: laravel_session
  - /api/user (default auth endpoint)

Express (Node.js):
  - X-Powered-By: Express
  - Error: "Cannot GET /path"
  - Cookie: connect.sid

ASP.NET:
  - ViewState in HTML (__VIEWSTATE hidden field)
  - /WebResource.axd
  - X-AspNet-Version header

Next.js:
  - _next/static/ paths
  - __NEXT_DATA__ script tag
  - Serverless functions at /api/*
```

### 9.5 WAF Identification

Know if there's a WAF and which one:
```
Cloudflare:
  - Server: cloudflare
  - cf-ray header
  - __cfduid cookie

Akamai:
  - Server: AkamaiGHost
  - X-Akamai-* headers

AWS WAF:
  - x-amzn-RequestId header
  - x-amzn-ErrorType header

CloudFront:
  - X-Amz-Cf-Id header
  - X-Cache: Error from cloudfront

F5 BIG-IP:
  - X-Content-Type-Options: nosniff
  - TSxxxxxxxx cookie (TS = TrafficShield)

ModSecurity:
  - "ModSecurity: Access denied"
  - 406 Not Acceptable responses

Imperva/Incapsula:
  - X-Iinfo header
  - visid_incap cookie

WAF bypass techniques by type:
  Cloudflare:           HTTP/1.0, path normalization
  Akamai:               Parameter pollution, encoding bypass
  AWS WAF:              Size limits, content-type switching
  ModSecurity:          Rule ID lookup, specific bypass payloads
  F5:                   HTTP method manipulation
```

### 9.6 When Tech Fingerprint Guides Exploit Selection

```
Detected Tech      | Likely Bug Classes (in order of probability)
WordPress          | WP config disclosure, plugin CVEs, user enum, XSS
Drupal             | Drupalgeddon (if old), access bypass, XSS
Joomla             | Com_user, extension CVEs, XSS
Laravel            | Debug mode, env file, mass assignment, deserialization
Spring Boot        | Actuator endpoints, SpEL injection, env disclosure
Django             | Debug mode, SQL injection (ORM bypass), mass assignment
Rails              | Mass assignment, YAML deserialization, SQL injection
Express            | NoSQL injection, prototype pollution, XSS
ASP.NET            | ViewState deserialization, machineKey, IIS CVEs
Next.js            | SSRF via _next/image, middleware bypass
Gatsby             | GraphQL introspection, SSG-specific paths
React              | XSS via dangerouslySetInnerHTML, prototype pollution
Vue                | XSS via v-html, template injection
Java (Tomcat)      | Manager app, JMX, AJP, Ghostcat (CVE-2020-1938)
Python (Flask)     | SSTI (Jinja2), debug console, path traversal
PHP (generic)      | LFI, RFI, PHP wrappers, type juggling, deserialization
Go                 | Path traversal, template injection, header injection
Ruby               | YAML.load deserialization, mass assignment, regex DoS
```

---

## 10. RECON CACHE MANAGEMENT

Don't re-do what you already have. Cache intelligently.

### 10.1 Staleness Thresholds

Different recon data types have different shelf lives:
```
Data Type             | Staleness | Rationale
Subdomains            | 7 days    | New subdomains appear frequently
Live hosts            | 1 day     | Hosts go up/down, IPs change
URLs                  | 3 days    | New endpoints deployed constantly
JS bundles            | 1 day     | Changes often indicate new features
Tech fingerprint      | 7 days    | Technology rarely changes daily
Screenshots           | 7 days    | Only needed when host changes
Secrets/keys          | 0 days    | Expire or get revoked, re-check daily
API endpoints         | 3 days    | New APIs added with feature releases
Auth flows            | 14 days   | Auth rarely changes
Scope                 | 1 day     | Program changes scope, check each session
```

### 10.2 Incremental vs. Full Recache

```
Incremental recache (preferred for most data):
  - Run passive sources only (crt.sh, wayback, search engines)
  - Compare with previous results
  - Only download and analyze new/changed items
  - Time: 5-10 minutes per target

Full recache (needed periodically):
  - Run all sources, including active
  - Fresh screenshots, fresh tech detect
  - Time: 30-60 minutes per target
  - Frequency: Weekly for active targets

When to do full recache:
  - Target not visited in 7+ days
  - After major product announcement
  - After acqui-hire (new assets added to scope)
  - When current data is clearly stale (many 404s from cached URLs)
  - When you're finding nothing and need fresh perspective
```

### 10.3 Cache Storage Structure

```
/recon_cache/
  /target.com/
    metadata.json           # Last scan times, tool versions
    scope.txt               # Scope at time of scan
    subdomains/
      raw_results.json      # From each tool
      unique_subs.txt       # Deduplicated list
      new_subs.txt          # New since last scan
    urls/
      raw_urls.txt
      clean_urls.txt
      new_urls.txt
    js/
      js_files.txt          # List of JS files found
      js_[hash].js          # Cached JS bundles
      findings.json         # Extracted endpoints, secrets, routes
    tech/
      fingerprint.json      # Tech stack per host
      screenshots/          # Screenshot files
    api/
      endpoints.txt         # API endpoints
      docs/                 # Any API documentation found
```

### 10.4 Cross-Target Correlation

Reuse recon data across similar targets:
```
Correlation opportunities:
  Same tech stack (e.g., multiple Rails apps):
    - Same parameter structure likely
    - Same auth patterns likely
    - Same IDOR patterns likely

  Same cloud provider:
    - Same S3 bucket naming convention
    - Same CDN configuration
    - Same IAM role patterns

  Same organization, different domains:
    - Overlapping user bases
    - Shared authentication
    - Same employee naming conventions

Example:
  target.com and target.io are both in scope
  target.com uses Auth0 → target.io might use the same Auth0 tenant
  Check: auth0 domain in target's JS → try on target.io
```

### 10.5 Hunt Memory Integration

Link recon findings to hunting notes:
```
When you find something in recon:
  1. Log it to your hunt notes immediately
  2. Tag what it could lead to
  3. Set a priority

Example:
  Date: 2026-01-15
  Source: JS from target.com/app.js
  Finding: /internal/api/v2/admin/users
  Priority: Critical
  Potential: IDOR on admin users, privilege escalation
  Status: Not yet tested
```

### 10.6 Cache Expiration Enforcement

```powershell
# Check cache age
$cacheFile = "recon_cache/target.com/metadata.json"
if (Test-Path $cacheFile) {
  $meta = Get-Content $cacheFile | ConvertFrom-Json
  $age = (Get-Date) - [DateTime]$meta.lastFullScan
  if ($age.TotalDays -gt 7) {
    Write-Output "Cache is $($age.TotalDays) days old. Full recache needed."
  }
}

# After recache, delete old screenshots and stale JS
$threshold = (Get-Date).AddDays(-14)
Get-ChildItem -Path "recon_cache/target.com/screenshots" -Recurse |
  Where-Object { $_.LastWriteTime -lt $threshold } |
  Remove-Item -Force
```

---

## 11. SENSITIVE DATA HANDLING

You will find secrets in recon. Handle them correctly.

### 11.1 Never Store Raw Credentials

This is the most important rule in recon:
```
NEVER:
  - Save AWS keys to a text file
  - Save database passwords to recon output
  - Store session tokens in your recon files
  - Keep hardcoded credentials in downloaded JS bundles
  - Save API keys in version-controlled files

ALWAYS:
  - Redact secrets before saving (replace with [REDACTED])
  - Store only the TYPE of secret found and its LOCATION
  - If you need to test a secret, test it immediately then discard
  - Use a secure enclave or encrypted file for temporary storage
  - Rotate any test accounts you create
```

### 11.2 Secret Discovery Triage

When you find a secret, triage immediately:
```
Priority 1 (Critical, report immediately):
  Cloud provider keys: AWS (AKIA*), GCP service account, Azure connection string
  Database connection strings: postgres://mysql://mongodb://
  Payment processor keys: Stripe sk_live_*, Braintree live_*, PayPal live_*

Priority 2 (High, report same session):
  Authentication tokens: JWT, GitHub ghp_*, GitLab glpat-*
  API keys for paid services: OpenAI sk-*, Twilio, SendGrid, Mailgun
  Social media access tokens

Priority 3 (Medium, note and continue):
  Environment variables that look like secrets
  Session tokens (may expire soon)
  Development/test API keys (limited access)

Priority 4 (Low, informational):
  Public API keys (Google Maps, reCAPTCHA site key)
  Analytics tracking IDs
  OAuth client IDs (without secret)
```

### 11.3 Impact Assessment for Cloud Keys

Quickly determine the blast radius of a found cloud key:
```
AWS Key assessment:
  aws sts get-caller-identity  → Account ID, User ARN
  aws s3 ls                    → List S3 buckets
  aws iam list-users           → List IAM users
  aws ec2 describe-instances   → List EC2 instances

GCP Key assessment:
  gcloud auth activate-service-account --key-file=service_account.json
  gcloud projects list
  gcloud storage buckets list

Only test if:
  1. You have the program's permission
  2. You can test WITHOUT writing/deleting data
  3. You document exactly what you accessed
  4. You report immediately
  5. You rotate credentials after reporting
```

### 11.4 JavaScript Secret Redaction

When processing JS bundles, auto-redact secrets:
```powershell
function Redact-Secrets {
  param($content)
  $patterns = @(
    '(AKIA[0-9A-Z]{16})',
    '(sk_live_[a-zA-Z0-9]+)',
    '(ghp_[a-zA-Z0-9]{36})',
    '(xox[bpsa]-[a-zA-Z0-9\-]+)',
    '(sk-[a-zA-Z0-9]{20,})',
    '(eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)'
  )
  foreach ($pattern in $patterns) {
    $content = $content -replace $pattern, '[REDACTED: matched pattern]'
  }
  return $content
}

$js = Get-Content "raw.js" -Raw
$clean = Redact-Secrets -content $js
$clean | Out-File "cleaned.js"
```

### 11.5 Incident Response Protocol

If you find something that shouldn't be exposed:
```
1. Document: URL, file, line number, what you found
2. Do NOT: use the credential, save it unredacted, share it
3. Report: immediately to the program via HackerOne/Bugcrowd
4. Include: what you found, where, and what access it grants
5. Do NOT: test the extent of access unless program says "go ahead"
6. After: delete all local copies of the credential
```

---

## 12. RECON DATA STRUCTURE

Consistent structure = usable data.

### 12.1 Standard Directory Layout

```
/recon/
  /target.com/
    /0-scope/
      policy.md
      inscope.txt
      outofscope.txt
      scope_notes.txt
    /1-subdomains/
      sources/
        crtsh.txt, securitytrails.txt, dnsrecords.txt, permutations.txt
      live.txt
      tech.txt
      screenshots/
    /2-urls/
      all_urls.txt
      unique_endpoints.txt
      params.txt
      interesting.txt
    /3-js/
      files/
        app.abc123.js, vendor.def456.js
      endpoints.txt
      secrets.txt
      routes.txt
      apis.txt
    /4-api/
      endpoints.txt
      graphql.txt
      swagger.json
      auth.txt
    /5-tech/
      tech_stack.txt
      cves.txt
      waf.txt
      cdn.txt
    /6-misc/
      cloud.txt
      buckets.txt
      takeover.txt
      leaks.txt
    /7-reports/
      priority_high.txt
      priority_medium.txt
      priority_low.txt
      killed.txt
    metadata.json
```

### 12.2 File Naming Conventions

```
Subdomains:   [target]_subdomains_[source].txt  →  target_subdomains_crtsh.txt
URLs:         [target]_urls_[source].txt        →  target_urls_wayback.txt
Screenshots:  [subdomain]_[protocol]_[port].png  →  www.target.com_https_443.png
JS files:     [subdomain]_[path_hash].js         →  www.target.com_a1b2c3.js
Tech reports: [subdomain]_tech.txt               →  www.target.com_tech.txt
```

### 12.3 Output Formats

Use machine-readable formats for automation, human-readable for analysis:
```
Machine-readable (for scripts and correlation):
  # JSON: structured, verifiable
  # CSV: good for tables of data
  # TXT: one item per line, sorted uniqued

Human-readable (for hunting):
  # MD: Markdown with sections
  # TXT: Organized with headers
  # Priority sorted

Example JSON output format:
{
  "subdomain": "api.target.com",
  "ip": "203.0.113.42",
  "ports": [443, 8443],
  "tech": ["nginx", "Node.js", "Express"],
  "status": "live",
  "contentType": "application/json",
  "priority": "high"
}
```

### 12.4 Metadata Tracking

```json
{
  "target": "target.com",
  "program": "Target Company on HackerOne",
  "lastFullScan": "2026-01-15T14:30:00Z",
  "lastPartialScan": "2026-01-16T09:00:00Z",
  "subdomains": {
    "lastEnumerated": "2026-01-15T14:30:00Z",
    "totalFound": 142,
    "uniqueLive": 38,
    "sources": ["crtsh", "securitytrails", "dns", "permutations"]
  },
  "urls": {
    "lastCollected": "2026-01-16T09:00:00Z",
    "totalUrls": 15234,
    "uniqueEndpoints": 456
  },
  "js": {
    "lastAnalyzed": "2026-01-16T09:30:00Z",
    "filesAnalyzed": 23,
    "endpointsFound": 67,
    "secretsFound": 2
  },
  "tech": {
    "lastFingerprinted": "2026-01-15T15:00:00Z",
    "techStack": ["nginx", "Node.js", "Express", "MongoDB", "AWS"]
  }
}
```

### 12.5 Version Control for Recon Data

```powershell
# Initialize recon repo
git init recon_data
cd recon_data

# Add .gitignore for sensitive data
echo "*.json" >> .gitignore
echo "*secret*" >> .gitignore
echo "*credential*" >> .gitignore

# Commit after each session
git add -A
git commit -m "Recon update $(Get-Date -Format yyyy-MM-dd): target.com"
```

---

## 13. AUTOMATED VS MANUAL RECON

Know what to automate and what requires human judgment.

### 13.1 What to Automate

```
ALWAYS AUTOMATE (no human judgment needed):
  - Subdomain enumeration against all passive sources
  - DNS resolution of found subdomains
  - Port scanning (top 100 ports)
  - HTTP/HTTPS probing
  - Screenshot capture
  - Technology fingerprinting (basic)
  - URL collection from Wayback/CDX/CommonCrawl
  - JS file discovery from HTML
  - Basic secret scanning (regex patterns)
  - S3 bucket name checking
  - Subdomain takeover detection (CNAME analysis)
  - Favicon hash computation
  - Response code checking

Automation tools:
  Phase 1 (foundation): subfinder, assetfinder, findomain, amass
  Phase 2 (live check): httpx, httprobe, dnsx
  Phase 3 (detail):     whatweb, webanalyze, nuclei (templates only)
  Phase 4 (content):    katana, gospider, hakrawler, waybackurls, gau
  Phase 5 (analysis):   LinkFinder, SecretFinder, jsek, xnLinkFinder
```

### 13.2 What to Do Manually

```
NEVER AUTOMATE (requires human judgment):
  - JS analysis review (context matters)
  - API endpoint relevance assessment
  - Auth flow mapping
  - OAuth redirect URI analysis
  - Understanding the application structure
  - Identifying custom parameter names
  - Distinguishing test from production endpoints
  - Interpreting error messages
  - Spotting business logic hints
  - Deciding which endpoints to hunt first
  - Recognizing when a response is anomalous

Manual recon workflow:
  1. Open the live host in a browser
  2. Check what it actually does (not what headers say)
  3. Click around and understand the flow
  4. Open DevTools Network tab, browse as a real user
  5. Check localStorage, sessionStorage, cookies
  6. Review the HTML for hidden inputs, comments
  7. Look for endpoints that DevTools captured but tools missed
  8. Understand the auth flow (login → register → password reset)
  9. Note the app's behavior (SPA with API calls? Server-rendered?)
  10. Look for client-side validation that the server might not enforce
```

### 13.3 Semi-Automated (Script-Assisted Manual Review)

Best approach: automate the collection, manually review the results:
```
Step 1: Automated collection
Step 2: Manual review of collected data
  - First 50 results from each category
  - Anything flagged as high priority
  - Anomalies (unusual response sizes, codes, content types)
Step 3: Targeted re-automation
  (After manual review, automate specific follow-ups)
  E.g., found /api/v2/users → now brute-force /api/v2/<resources>
Step 4: Repeat
```

### 13.4 Automation Pitfalls

```
1. Scope creep: Automated tools don't understand scope nuance
   → Filter all output through scope list programmatically

2. Noise generation: Tools grab everything including 3rd-party content
   → Post-filter for target.com domains and relevant content

3. False positives: Secret scanners flag test keys and sample data
   → Manual review of ALL secrets before acting

4. Rate limiting: Aggressive automation triggers WAF
   → Rate limiting in tools, delays between runs

5. Stale data: Automated tool results are immediately somewhat stale
   → Run critical checks (live hosts, JS bundles) fresh each session

6. Tool blindness: Tools don't understand application logic
   → Manual review always catches what tools miss

7. Analysis paralysis: Too much data, no actionable output
   → Prioritize output, only highlight the top findings
```

### 13.5 Time Allocation

```
For a 4-hour recon session on a medium target:
  Automated setup:         15 min (start tools, get coffee)
  Automated collection:    30 min (tools running in background)
  Manual review of subs:   15 min (pick interesting ones)
  Manual JS analysis:      30 min (scan extracted endpoints)
  Manual app exploration:  30 min (open in browser, click around)
  Endpoint review:         30 min (what did we find?)
  Auth flow mapping:       30 min (understand auth)
  Priority assignment:     15 min (what to hunt first)
  Documentation:           15 min (write it down)
  Buffer:                  30 min (unexpected findings, rabbit holes)
  Total:                   4 hours
```

---

## 14. ZERO INTERESTING HOSTS?

What to do when your recon returns nothing obviously exploitable.

### 14.1 Kill Signal Analysis

Before giving up, check if these kill signals are present:
```
KILL (move to next target):
  - All hosts return 403/401 (WAF-blocks everything)
  - Default Cloudflare "Attention Required" on every page
  - All endpoints require 2FA + hardware key
  - Single page app with no API calls (server-rendered everything)
  - Only a marketing site (no user accounts, no functionality)
  - Only static content (no forms, no inputs, no auth)
  - Program has been hunted by 1000+ researchers for 2+ years
  - Bounty range is <$50 and there's a lot of attack surface

CONTINUE (try these approaches):
  - Check non-standard ports (maybe only custom ports are interesting)
  - Look at subdomains on different IP ranges
  - Check historical versions via Wayback
  - Search for GitHub repos of the target company
  - Look at the mobile app (if they have one)
  - Check API docs on a totally different domain
  - Try Google dorking for developer.target.com content
  - Check npm/PyPI/GitHub for their open-source packages
  - Look at job postings (new tech = new features = new endpoints)
```

### 14.2 Alternative Approaches

If standard recon fails:
```
1. Change perspective:
   - What does a new user see? (registration flow → endpoints)
   - What does a logged-in user see? (dashboard → API calls)
   - What does an admin see? (admin portal → different endpoints)
   - What does an API client see? (swagger → full API doc)

2. Look at the business, not the tech:
   - What data is valuable? (PII, financial, health, credentials)
   - Where does data flow? (user → app → API → database)
   - Where are the boundaries? (auth, role, org, tier)
   - What features cost money? (premium features → access control)

3. Change the entry point:
   - Instead of subdomains → scan IP ranges instead
   - Instead of web → check mobile API
   - Instead of API → check GraphQL
   - Instead of prod → check staging/dev
   - Instead of target.com → check partner portal

4. Change the timing:
   - Hunt during off-peak hours (fewer users, less monitoring)
   - Hunt after major releases (regression bugs common)
   - Hunt on weekends (DevOps less likely to patch immediately)

5. Change the methodology:
   - If blackbox → try greybox (register an account)
   - If scanning → try actually using the app
   - If automated → try manual exploration
   - If fast → try slow and methodical
```

### 14.3 Target Switching Decision Framework

```
Decision matrix for switching targets:

  Have you found ANYTHING actionable?
    YES → Hunt what you found first, switch later
    NO → Continue to next question

  Have you tried ALL alternative approaches?
    NO → Try them first, one at a time
    YES → This target might be dead for now

  What is the payout potential?
    High ($500+) → Invest another session, deep dive
    Medium ($100-500) → One more try, then move on
    Low (<$100) → Move on after initial sweep

  Is this a new or old target?
    New program (<1 month) → Keep digging, first hunter advantage
    Old program (>6 months) → Already picked over, move on

  How many other targets do you have?
    Only this one → Keep going, expand recon
    Several others → Switch to a more promising one

  Decision:
    Most dead targets → Switch within 1-2 sessions
    Keep a "long list" of dead targets to revisit monthly
    When they add features or scope → re-check immediately
```

### 14.4 The "Boring" Target Opportunity

Some "boring" targets are actually goldmines:
```
"Boring" surface           | Hidden Opportunity
Static marketing site      | Check subdomains, dev builds, staging
Default nginx page         | Common if CMS isn't configured → check other paths
403 Forbidden everywhere   | Path bypass, header manipulation, auth bypass
Single-page login only     | Registration might be open, check /register
No API calls visible       | Check WebSocket connections, service workers
WordPress default page     | wp-admin, wp-json, plugin CVEs
IIS default page           | /aspnet_client, trace.axd, app paths
"Coming soon" page         | May have hidden features behind the landing
```

### 14.5 When to Kill a Target Permanently

```
Hard kill signals:
  1. No scope changes in 6+ months
  2. No new features deployed
  3. Bounty range unchanged and low
  4. Program has marked >50% of reports as N/A
  5. Triagers consistently dismiss legitimate findings
  6. Program has been acquired and is winding down
  7. No disclosed reports in 12+ months
  8. CEO/CTO stated they're sunsetting the product

When you kill a target:
  - Document why (so you remember next time you see it)
  - Set a calendar reminder to re-check in 3 months
  - Note any specific events that would trigger a re-check
  - Move on without guilt. Target selection IS part of hunting.
```

---

## 15. RECON BEFORE EACH SESSION

Don't start a session cold. Refresh your recon data.

### 15.1 Pre-Session Checklist

```
Pre-session (5 minutes):
  [ ] Check program page for scope changes
  [ ] Check disclosed reports since last session
  [ ] Check changelog/blog for new features
  [ ] Quick re-scan of JS files for changes
  [ ] Quick re-check of crt.sh for new subdomains
  [ ] Review last session's notes
  [ ] Set today's priority targets
  [ ] Check if any of yesterday's findings need follow-up
```

### 15.2 Incremental Refresh

```powershell
# 1. Check crt.sh for new certificates
curl -s "https://crt.sh/?q=%25.target.com&output=json" | `
  ConvertFrom-Json | Select-Object -ExpandProperty name_value | `
  Sort-Object -Unique > crt_fresh.txt

$old = Get-Content "cached_crtsh.txt"
$new = Get-Content "crt_fresh.txt"
$diff = Compare-Object $old $new | Where-Object { $_.SideIndicator -eq '=>' }
if ($diff) {
  Write-Output "NEW SUBDOMAINS FOUND:"
  $diff | ForEach-Object { Write-Output $_.InputObject }
}

# 2. Check Wayback for new URLs (last 24h)
$yesterday = (Get-Date).AddDays(-1).ToString("yyyyMMdd")
$today = (Get-Date).ToString("yyyyMMdd")
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com&from=${yesterday}&to=${today}&output=json"

# 3. Quick tech re-check on top 5 hosts
$hosts = Get-Content priority_hosts.txt | Select-Object -First 5
foreach ($host in $hosts) {
  try {
    $resp = Invoke-WebRequest -Uri "https://${host}" -TimeoutSec 10
    Write-Output "${host}: $($resp.StatusCode) - $($resp.Headers['Server'])"
  } catch { Write-Output "${host}: DOWN or ERROR" }
}
```

### 15.3 Changelog Monitoring

Track what the target is building:
```
Where to check for changes:
  1. Public changelog: changelog.target.com, updates.target.com
  2. Blog posts: blog.target.com, engineering blog
  3. Social media: @target's tweets about new features
  4. Job postings: "Seeking Senior GraphQL Engineer" → GraphQL exists
  5. PR releases: new features, acquisitions, partnerships
  6. GitHub activity: open source repos, commit messages
  7. npm/PyPI packages: new versions released
  8. App store: iOS/Android app updates (new features)
```

### 15.4 Session Planning

After the pre-session refresh, plan the session:
```
Session Plan: 2026-01-16
Target: Target Company

New findings since last session:
  - 3 new subdomains from crt.sh
  - 1 new API endpoint in app.js
  - JS bundle hash changed (needs re-analysis)

Priority for today:
  1. Re-analyze JS bundle for new endpoints (from hash change)
  2. Test 3 new subdomains for live hosts and tech
  3. Follow up on yesterday's IDOR (need to check different IDs)
  4. If time: expand GraphQL testing on api.target.com
```

---

## 16. WINDOWS-SPECIFIC RECON

Real-world recon on Windows requires adapting Unix-centric workflows.

### 16.1 PowerShell Alternatives for Bash Commands

```
Bash Command              | PowerShell Equivalent
cat file.txt              | Get-Content file.txt
grep pattern file.txt     | Select-String -Path file.txt -Pattern pattern
sort -u                   | Sort-Object -Unique
wc -l                     | Measure-Object | Select-Object Count
head -n 10                | Select-Object -First 10
tail -n 10                | Select-Object -Last 10
cut -d: -f1               | ForEach-Object { ($_ -split ':')[0] }
uniq -c                   | Group-Object
tee output.txt            | Tee-Object -FilePath output.txt
sed 's/old/new/g'         | -replace 'old', 'new'
awk '{print $1}'          | ForEach-Object { ($_ -split '\s+')[0] }
diff file1 file2           | Compare-Object
curl -s URL               | Invoke-RestMethod -Uri URL
wget URL                  | Invoke-WebRequest -Uri URL -OutFile file
ping host                 | Test-NetConnection -ComputerName host
dig A target.com          | Resolve-DnsName -Name target.com -Type A
nslookup target.com       | Resolve-DnsName -Name target.com
whois target.com          | Requires external module
traceroute target.com     | Test-NetConnection -TraceRoute
```

### 16.2 Using curl from PowerShell

```powershell
# PowerShell's curl is an alias for Invoke-WebRequest
# Use curl.exe to invoke the real curl:
curl.exe -s "https://crt.sh/?q=%25.target.com&output=json"

# Or install via Scoop:
# scoop install curl
```

### 16.3 API-Only Recon (No Native Tools)

When you can't install tools, use web APIs:
```powershell
# crt.sh API (no tools needed)
Invoke-RestMethod "https://crt.sh/?q=%25.target.com&output=json" |
  ForEach-Object { $_.name_value } |
  Sort-Object -Unique | Out-File subs.txt

# VirusTotal API (with API key)
$apiKey = "YOUR_VT_API_KEY"
$url = "https://www.virustotal.com/api/v3/domains/target.com/subdomains"
$headers = @{ "x-apikey" = $apiKey }
$subs = Invoke-RestMethod -Uri $url -Headers $headers
$subs.data | ForEach-Object { $_.id } | Out-File vt_subs.txt

# SecurityTrails API
$apiKey = "YOUR_ST_API_KEY"
$url = "https://api.securitytrails.com/v1/domain/target.com/subdomains"
$headers = @{ "APIKEY" = $apiKey }
$response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
$response.subdomains | ForEach-Object { "${_}.target.com" }

# AlienVault OTX API (free, no key needed)
$url = "https://otx.alienvault.com/api/v1/indicators/domain/target.com/passive_dns"
$results = Invoke-RestMethod -Uri $url -Method Get
$results.passive_dns | ForEach-Object { $_.hostname } | Sort-Object -Unique

# Shodan API
$apiKey = "YOUR_SHODAN_KEY"
$url = "https://api.shodan.io/shodan/host/search?key=${apiKey}&query=hostname:target.com"
$results = Invoke-RestMethod -Uri $url -Method Get
$results.matches | ForEach-Object {
  [PSCustomObject]@{
    IP = $_.ip_str
    Port = $_.port
    Hostnames = $_.hostnames -join ','
    Product = $_.product
  }
}
```

### 16.4 Batch Scripting for Recon

```powershell
# Discover-ReconTarget.ps1
param(
  [string]$Domain = "target.com",
  [string]$OutputDir = "./recon"
)

New-Item -ItemType Directory -Path "$OutputDir/$Domain" -Force | Out-Null
Write-Output "=== Starting recon for $Domain ==="

# Phase 1: Subdomain enumeration via crt.sh
Write-Output "[Phase 1] Subdomain enumeration via crt.sh..."
$crtSubs = Invoke-RestMethod "https://crt.sh/?q=%25.$Domain&output=json" |
  ForEach-Object { $_.name_value } |
  ForEach-Object { $_ -split "`n" } |
  Sort-Object -Unique

$crtSubs | Out-File "$OutputDir/$Domain/crtsh_subs.txt"
Write-Output "  Found $($crtSubs.Count) subdomains"

# Phase 2: DNS resolution
Write-Output "[Phase 2] DNS resolution..."
$resolved = @()
foreach ($sub in $crtSubs) {
  try {
    $ip = [System.Net.Dns]::GetHostAddresses($sub)
    $resolved += [PSCustomObject]@{
      Subdomain = $sub
      IP = ($ip.IPAddressToString -join ', ')
      Date = Get-Date -Format yyyy-MM-dd
    }
  } catch { }
}
$resolved | Export-Csv "$OutputDir/$Domain/resolved.csv" -NoTypeInformation
Write-Output "  Resolved $($resolved.Count) subdomains"

# Phase 3: Web probe
Write-Output "[Phase 3] Web probe..."
$liveHosts = @()
foreach ($entry in $resolved) {
  try {
    $resp = Invoke-WebRequest -Uri "https://$($entry.Subdomain)" -TimeoutSec 10 `
      -Method Head -ErrorAction SilentlyContinue
    $liveHosts += [PSCustomObject]@{
      Host = $entry.Subdomain
      Status = $resp.StatusCode
      Server = $resp.Headers['Server']
    }
  } catch {
    try {
      $resp = Invoke-WebRequest -Uri "http://$($entry.Subdomain)" -TimeoutSec 10 `
        -Method Head -ErrorAction SilentlyContinue
      $liveHosts += [PSCustomObject]@{
        Host = $entry.Subdomain
        Status = $resp.StatusCode
        Server = $resp.Headers['Server']
      }
    } catch { }
  }
}
$liveHosts | Export-Csv "$OutputDir/$Domain/live.csv" -NoTypeInformation
Write-Output "  Found $($liveHosts.Count) live hosts"
Write-Output "=== Recon complete for $Domain ==="
```

### 16.5 Windows Tool Installation

```
# Scoop package manager (recommended for security tools)
# Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
# irm get.scoop.sh | iex
# scoop install main/git curl wget

# Go tools on Windows:
# scoop install go
# go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Python tools:
# scoop install python
# pip install arjun
# pip install waybackpy

# WSL (best option for Linux tools):
# wsl --install
```

### 16.6 Performance Optimizations

```powershell
# For large files, use StreamReader instead of Get-Content
$reader = [System.IO.StreamReader]::new("huge_file.txt")
while ($null -ne ($line = $reader.ReadLine())) {
  # Process $line
}
$reader.Close()

# Fast file write
$writer = [System.IO.StreamWriter]::new("output.txt")
$results | ForEach-Object { $writer.WriteLine($_) }
$writer.Close()

# Parallel processing (PowerShell 7+)
$subs = Get-Content subs.txt
$subs | ForEach-Object -Parallel {
  $sub = $_
  try {
    $ip = [System.Net.Dns]::GetHostAddresses($sub)
    "$sub,$($ip.IPAddressToString -join ';')"
  } catch { }
} -ThrottleLimit 20 | Out-File resolved.txt
```

### 16.7 WSL Integration

```powershell
# From PowerShell, invoke WSL commands:
wsl subfinder -d target.com
wsl httpx -l subs.txt -o live.txt
wsl grep 'api' all_urls.txt

# Share files between Windows and WSL:
# Windows: C:\Users\ADMIN\recon\
# In WSL: /mnt/c/Users/ADMIN/recon/

# Use WSL for heavy processing, PowerShell for orchestration:
$domain = "target.com"
wsl subfinder -d $domain -o /mnt/c/Users/ADMIN/recon/subs.txt
$subs = Get-Content "recon/subs.txt"
$subs.Count
```

---

## 17. RECON FOR MOBILE TARGETS

Mobile apps are an often-overlooked attack surface.

### 17.1 APK/IPA Acquisition

Getting the app binary:
```
Android APK:
  Official: Google Play Store
  Using apkeep: apkeep -a com.target.app ./
  From device: adb shell pm path com.target.app
               adb pull /data/app/com.target.app-1/base.apk

iOS IPA:
  ipatool download -b com.target.app -o target.ipa
  iMazing for purchased apps
  Jailbroken device with Clutch
```

### 17.2 APK Decompilation

Once you have the APK:
```
# Decompile with jadx
jadx -d decompiled/ base.apk

# What to look for:
#   1. AndroidManifest.xml (permissions, activities, services)
#   2. res/values/strings.xml (API keys, URLs, error messages)
#   3. smali/ or sources/ (decompiled Java code)
#   4. lib/ (native libraries)
#   5. assets/ (embedded files, certificates, configs)
#   6. res/xml/ (network config, app links, backup rules)

# For React Native apps:
#   Look for index.android.bundle in assets/
#   Same analysis as web JS (API endpoints, secrets)

# For Flutter apps:
#   Look for libapp.so (Dart compiled)
```

### 17.3 iOS IPA Analysis

```
# Decompile IPA:
# unzip target.ipa
# Payload/Application.app/
#   - Info.plist (permissions, URLs, app config)
#   - Main binary (Mach-O)
#   - Frameworks/ (embedded frameworks)

# Info.plist key things to check:
#   NSAppTransportSecurity (ATS exceptions = unencrypted HTTP)
#   CFBundleURLTypes (URL schemes = deep links)
#   Firebase config keys
#   API base URLs
```

### 17.4 Endpoint Extraction from Mobile

```powershell
# From decompiled Android code:
$decompDir = "decompiled/sources"
Select-String -Path "$decompDir/**/*.java" -Pattern 'https?://'

# From iOS binary strings:
# strings Payload/App.app/App | Select-String -Pattern 'https?://'

# Common patterns to search:
#   baseURL, BASE_URL, apiUrl
#   amazonaws.com, cloudfront.net
#   firebaseio.com (Firebase backend)
#   graphql

# PowerShell mobile recon:
$searchPaths = @("decompiled/sources/**/*.java",
  "decompiled/res/values/strings.xml",
  "decompiled/assets/**/*")

$patterns = @(
  'https?://[^"''\s<>,)]+',
  "['''](?:api[_-]?key|apikey|token|secret)[''']\s*:\s*[''']([^"'']+)[''']",
  '(?:AKIA|SK-[a-zA-Z0-9]+|ghp_[a-zA-Z0-9]+)',
  'firebaseio\.com', 'graphql'
)

foreach ($path in $searchPaths) {
  if (Test-Path $path) {
    foreach ($pattern in $patterns) {
      Select-String -Path $path -Pattern $pattern |
        ForEach-Object { Write-Output "$($_.Path): $($_.Line.Trim())" }
    }
  }
}
```

### 17.5 Mobile Secret Scanning

Mobile apps are rich sources of hardcoded secrets:
```
Common secrets in mobile apps:
  Firebase configuration (apiKey, authDomain, databaseURL, projectId)
  OAuth client IDs (Google, Facebook, Twitter)
  Third-party API keys (Stripe pk_*, Google Maps, Sentry)
  Backend URLs with paths (/api/v2/mobile/)
  Hardcoded testing credentials (test/test123, admin/admin)

Quick triage:
  Priority 1: Firebase URLs (unsecured Firebase = full data access)
  Priority 2: Backend API keys (direct data access)
  Priority 3: Cloud service keys (S3, GCS, Azure)
  Priority 4: Third-party API keys (limited scope)
  Priority 5: Test credentials (low impact)
```

### 17.6 Deep Link Analysis

```
# Android: AndroidManifest.xml has intent filters
# Extract URL schemes and paths:
$manifest = Get-Content "decompiled/AndroidManifest.xml" -Raw
[regex]::Matches($manifest, 'android:scheme="([^"]+)"') |
  ForEach-Object { $_.Groups[1].Value }

[regex]::Matches($manifest, 'android:host="([^"]+)"') |
  ForEach-Object { $_.Groups[1].Value }

# Deep link vulnerabilities:
#   - XSS via deep link parameters
#   - Path traversal via deep link
#   - SQL injection via deep link
#   - Authentication bypass via deep link
#   - Intent injection (Android)

# Test deep links:
# adb shell am start -W -a android.intent.action.VIEW \
#   -d "targetapp://profile/123"
# adb shell am start -W -a android.intent.action.VIEW \
#   -d "targetapp://webview?url=javascript:alert(1)"
```

### 17.7 Mobile API Differences

Mobile apps often use different API versions or endpoints:
```
Check for mobile-specific endpoints:
  /api/v2/mobile/, /api/v2/android/, /api/v2/ios/
  /api/mobile/, /mobile-api/, /mapi/

Check for different API behavior:
  - Mobile endpoints may have less security (assumed trusted client)
  - Mobile endpoints may not check for rate limits
  - Mobile endpoints may return more data (for offline caching)
  - Mobile endpoints may accept different auth mechanisms
  - Mobile endpoints may skip certain validation steps

Header differences to check:
  User-Agent: TargetApp/2.0 (Android 14)
  X-Platform: android
  X-App-Version: 2.1.3
  X-Device-ID: (may be used as auth factor)
```

---

## 18. RECON FOR CLOUD TARGETS

Cloud infrastructure misconfigurations are some of the highest-payout bugs.

### 18.1 S3 Bucket Enumeration

Standard patterns for S3 bucket names:
```
target.com-related:
  target, target-dev, target-staging, target-backup, target-logs
  target-assets, target-static, target-media, target-uploads
  target-config, target-data, target-public, target-private
  target-downloads, target-files, target-backups

Company name variations:
  targetcompany, target-corp, target-enterprise
  target-prod, target-production, target-test
  target-sandbox, target-demo, target-beta
  tgt, tgt-dev, tgt-prod, tgt-storage
```

```powershell
# Check if bucket exists and is public:
$buckets = @("target", "target-backup", "target-assets", "target-dev")
foreach ($bucket in $buckets) {
  $url = "https://${bucket}.s3.amazonaws.com"
  try {
    $resp = Invoke-WebRequest -Uri $url -Method Get -TimeoutSec 5
    if ($resp.Content -match 'ListBucketResult') {
      Write-Output "PUBLIC BUCKET: ${url} (listing enabled!)"
      $list = [xml]$resp.Content
      $list.ListBucketResult.Contents | ForEach-Object {
        Write-Output "  $($_.Key)"
      }
    } elseif ($resp.StatusCode -eq 200) {
      Write-Output "PUBLIC BUCKET: ${url} (no listing, accessible)"
    }
  } catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    if ($statusCode -eq 403) { Write-Output "EXISTS (denied): ${url}" }
  }
}
```

### 18.2 GCS Bucket Enumeration

```powershell
$buckets = @("target", "target-data", "target-assets")
foreach ($bucket in $buckets) {
  $listUrl = "https://www.googleapis.com/storage/v1/b/${bucket}/o"
  try {
    $resp = Invoke-WebRequest -Uri $listUrl -Method Get -TimeoutSec 5
    if ($resp.Content -match '"items"') {
      Write-Output "PUBLIC GCS BUCKET: ${bucket}"
      $data = $resp.Content | ConvertFrom-Json
      $data.items | ForEach-Object { Write-Output "  $($_.name)" }
    }
  } catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    if ($statusCode -eq 200) { Write-Output "PUBLIC GCS: ${bucket}" }
    elseif ($statusCode -eq 403) { Write-Output "EXISTS (denied): ${bucket}" }
  }
}
```

### 18.3 Azure Blob Enumeration

```powershell
$storageAccounts = @("target", "targetdata", "targetstorage")
$containers = @("uploads", "assets", "media", "public", "backups", "config")

foreach ($account in $storageAccounts) {
  foreach ($container in $containers) {
    $url = "https://${account}.blob.core.windows.net/${container}"
    try {
      $resp = Invoke-WebRequest -Uri $url -Method Get -TimeoutSec 5
      if ($resp.Content -match 'EnumerationResults') {
        Write-Output "PUBLIC AZURE BLOB: ${url} (listing enabled!)"
      }
    } catch {
      $statusCode = $_.Exception.Response.StatusCode.value__
      if ($statusCode -eq 403) { Write-Output "EXISTS (denied): ${url}" }
    }
  }
}
```

### 18.4 CloudFront/CDN Origin Discovery

Finding the real origin behind a CDN:
```
Origin discovery techniques:
  1. DNS history (find pre-CDN IPs)
  2. Certificate transparency (find origin IPs)
  3. Direct IP scanning (scan /24 range of known origin IPs)
  4. Subdomain-based origin (direct.target.com, origin.target.com)
  5. Error page analysis (some CDNs reveal origin IP in errors)
  6. HTTP header differences (compare with/without CDN)
  7. SSL certificate differences (origin may have different config)

Common origin bypass techniques:
  1. Send request to origin IP directly
  2. Modify Host header to target.com but go to origin IP
  3. Use HTTP instead of HTTPS to hit origin
  4. Use HTTP/1.0 instead of HTTP/1.1 or 2
  5. Add double slashes in path (//admin)
  6. Try older TLS versions (origin may accept SSLv3)
```

### 18.5 IAM Role Identification from Errors

Cloud error messages often leak IAM information:
```
AWS error patterns:
  "arn:aws:iam::123456789012:user/app-user"
  "arn:aws:sts::123456789012:assumed-role/app-role/i-12345"

GCP error patterns:
  "Service account [project-id@appspot.gserviceaccount.com]"
  "Project [project-id] does not exist"

Azure error patterns:
  "Subscription 'subscription-id' not found"
  "Tenant 'tenant-id' not found"
```

### 18.6 Cloud Metadata Surface

When SSRF is possible, the cloud metadata endpoints:
```
AWS IMDSv1: http://169.254.169.254/latest/meta-data/
  /iam/security-credentials/
  /user-data/

AWS IMDSv2:
  TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
  curl -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/

GCP Metadata: http://metadata.google.internal/computeMetadata/v1/
  Header: Metadata-Flavor: Google

Azure Instance Metadata:
  http://169.254.169.254/metadata/instance?api-version=2021-02-01
  Header: Metadata: true

DigitalOcean: http://169.254.169.254/metadata/v1/
Alibaba Cloud: http://100.100.100.200/latest/meta-data/
```

### 18.7 Cloud Recon Command Collection

```powershell
# Try all major cloud providers for a given bucket name:
$base = "target"
$urls = @(
  "https://${base}.s3.amazonaws.com",
  "https://${base}.s3.us-east-1.amazonaws.com",
  "https://storage.googleapis.com/${base}",
  "https://${base}.blob.core.windows.net",
  "https://${base}.digitaloceanspaces.com",
  "https://${base}.storage.googleapis.com"
)
foreach ($url in $urls) {
  try { $r = Invoke-WebRequest $url -TimeoutSec 5; Write-Output "FOUND: $url" }
  catch { }
}
```

---

## 19. RECON FOR CI/CD

CI/CD pipelines are a gateway to the entire application infrastructure.

### 19.1 GitHub Actions Workflow Enumeration

If the target has public repositories, check GitHub Actions:
```
# Check if the target organization has public repos:
# https://github.com/target-company
# https://github.com/orgs/target-company/repositories

# Look for GitHub Actions workflows:
# https://github.com/target-company/repo/tree/main/.github/workflows

What to look for in workflow files:
  - Hardcoded secrets in workflow files
  - Actions triggered by pull_request_target (dangerous!)
  - Actions that checkout and run untrusted code
  - Actions that deploy to production on push
  - AWS/Azure/GCP credentials in workflow steps

Check for exposed workflow YAML files:
  curl -s "https://raw.githubusercontent.com/target-company/repo/main/.github/workflows/deploy.yml"

Pull request target vulnerability check:
  Contains pull_request_target → VULNERABLE if checkout and run code
  Contains issue_comment → VULNERABLE if triggers build
  Contains workflow_run → VULNERABLE if uses default token
```

### 19.2 Exposed CI/CD Dashboards

```
Check these common CI/CD endpoints:
  Jenkins:
    https://jenkins.target.com/ (or /jenkins)
    https://ci.target.com/
    Check: /script (script console), /manage

  GitLab CI:
    https://gitlab.target.com/
    Check: /explore for public projects
    Check: runners, job logs

  GitHub Actions:
    https://github.com/target-company/repo/actions
    Check: public workflow run logs (may contain secrets)

  CircleCI:
    https://circleci.com/gh/target-company/repo

  Travis CI:
    https://travis-ci.com/target-company/repo

  Artifactory/Nexus:
    https://artifactory.target.com/
    https://nexus.target.com/
    Check: public artifacts, package repositories
```

### 19.3 Artifact Repository Scanning

```
Check for exposed build artifacts:
  Docker registries:
    https://hub.docker.com/u/targetcompany/
    https://gcr.io/target-project/
    https://target.azurecr.io/

  Package registries:
    npm: https://www.npmjs.com/~targetcompany
    PyPI: https://pypi.org/user/targetcompany/
    Maven: search.maven.org

  Binary storage:
    S3 buckets with build artifacts
    Jenkins build archives
    Sonatype Nexus repositories

What to look for:
  - Built artifacts with debug symbols
  - Unencrypted configuration files
  - Docker images with embedded secrets
  - Jar/DLL files that can be decompiled
  - Test reports with infrastructure details
  - Build logs with environment variables
```

### 19.4 CI/CD Recon Commands

```powershell
# Check GitHub for target's repositories
$org = "target-company"
$url = "https://api.github.com/orgs/${org}/repos"
$repos = Invoke-RestMethod -Uri $url -Method Get
$repos | ForEach-Object { Write-Output "$($_.name): $($_.html_url)" }

# Check for workflow files in each repo
foreach ($repo in $repos) {
  $workflowUrl = "https://api.github.com/repos/${org}/$($repo.name)/contents/.github/workflows"
  try {
    $files = Invoke-RestMethod -Uri $workflowUrl -Method Get
    $files | ForEach-Object {
      Write-Output "Workflow in $($repo.name): $($_.name)"
      $content = Invoke-RestMethod -Uri $_.download_url
      if ($content -match 'pull_request_target') {
        Write-Output "  WARNING: pull_request_target detected!"
      }
    }
  } catch { }
}
```

### 19.5 CI/CD Security Indicators

```
Indicators of weak CI/CD security:
  1. Public workflow logs that show environment variables
  2. Actions that use GITHUB_TOKEN with excessive permissions
  3. Third-party actions pinned to tags (not commit SHAs)
  4. Self-hosted runners on pull_request_target triggers
  5. Artifact uploads containing .env or config files
  6. Public CI/CD dashboards with anonymous access
  7. Docker images pushed to public registries with secrets
  8. Unauthenticated access to Jenkins/GitLab CI
```

---

## 20. RECON OUTPUT PRIORITIZATION

Not all findings are equal. Rank them by likely payout.

### 20.1 Ranking Findings by Likely Payout

```
Payout Tier   | Finding Type                          | Typical $ Range
Critical      | Cloud credentials (AWS keys)          | $2,000 - $10,000
Critical      | RCE chain                             | $2,000 - $10,000
Critical      | Full account takeover (no user action) | $1,500 - $5,000
High          | Authentication bypass                 | $1,000 - $3,000
High          | SQL injection with data extraction    | $500 - $2,500
High          | IDOR with PII exposure                | $500 - $2,000
High          | S3 bucket with sensitive data         | $500 - $2,000
High          | SSRF to cloud metadata                | $750 - $2,500
Medium        | Stored XSS                            | $250 - $1,000
Medium        | IDOR with non-sensitive data           | $200 - $500
Medium        | Subdomain takeover                    | $200 - $500
Medium        | GraphQL introspection                  | $150 - $500
Low           | Reflected XSS                         | $100 - $250
Low           | Open redirect                         | $50 - $150
Low           | Missing security headers              | $0 - $100 (often N/A)
```

### 20.2 Confidence Scoring

Assign a confidence score to every recon finding:
```
Confidence scoring:
  5 - Confirmed vulnerability, exploitable (start writing report)
  4 - Strong evidence, needs one more test
  3 - Interesting signal, needs investigation
  2 - Weak signal, could be nothing
  1 - Noise, ignore

Examples:
  5: AWS key found in JS → confirmed active via AWS CLI → write report
  4: API endpoint returns user data with sequential IDs → test IDOR
  3: Dev subdomain found → check if it's a different build
  2: Response has unusual header → probably nothing
  1: New subdomain with default nginx page → ignore

Action by confidence:
  Score 5: Write report immediately
  Score 4: Investigate within this session
  Score 3: Add to hunt list for this target
  Score 2: Note for reference, don't spend time
  Score 1: Delete from consideration
```

### 20.3 Tech Stack Match with Known Bugs

When the recon tech stack matches known vulnerability patterns:
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
Priority | Criteria                                | Action
P0       | Critical chain, immediate exploitation  | Hunt NOW, no delay
P1       | High confidence, high impact            | Hunt within 1 hour
P2       | Medium confidence/impact                | Hunt within this session
P3       | Low confidence, needs investigation     | Hunt if time permits
P4       | Informational, no immediate path        | Note and move on

Priority reassessment:
  - P2 → P1 if you find additional evidence
  - P3 → P2 if other findings support it
  - P4 → Kill after 2 sessions without progress
```

### 20.5 Recon Output Summary

At the end of each recon session, produce a summary:
```
=== Recon Summary: target.com ===
Date: 2026-01-16
Total subdomains found: 142
Live hosts: 38
JS files analyzed: 23
API endpoints found: 67
Secrets found: 2 (triaged)

Priority findings:
  P0: None
  P1: API key in app.js (Stripe) → Confirmed live → Report drafted
  P2: IDOR on /api/v2/users/{id} → Needs parameter fuzzing
  P3: GraphQL introspection open → Run full schema dump
  P4: Dev subdomain with default page → No action taken

Next session focus:
  - Complete GraphQL schema extraction
  - Fuzz IDOR parameter on /api/v2/users/{id}
  - Re-check JS bundle (hash changed during session)
```

---

## 21. RECON QUALITY CHECKS

Before moving from recon to hunting, verify completeness.

### 21.1 The Recon Quality Checklist

```
Before you start hunting, verify you have:

[ ] Subdomains:    ≥10 for small targets, ≥30 for medium, ≥100 for enterprise
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

If an item is missing from the checklist, fix it before hunting:
```
Missing subdomains:
  - Check additional crt.sh wildcards (%25.target.io, %25.target.co)
  - Run DNS brute force with a larger wordlist
  - Check Shodan for target.com hosts

Missing live hosts:
  - Check non-standard ports (8000, 9000, 3000, 5000)
  - Wait and retry (host may be temporarily down)
  - Check via IP: use resolved IPs instead of hostnames

Missing tech stack:
  - Use whatweb/wappalyzer with full URLs, not just root
  - Check /favicon.ico, /robots.txt, /sitemap.xml for clues
  - Look at error pages intentionally

Missing API endpoints:
  - Check JS bundles more carefully
  - Check /swagger, /openapi, /docs
  - Check sitemap.xml for API paths
  - Register an account and monitor API calls

Missing auth flow:
  - Visit the login page and observe form submission
  - Check cookies after login
  - Check localStorage for tokens
  - Check network tab during login
```

### 21.3 The 10-Minute Sanity Check

If you've done full recon but feel like you're missing something:
```
10-minute sanity check:
  1. Open the main target page in a browser (2 min)
     - Does it load? Is it the right page?
     - Is there a login/register flow?

  2. Check https://www.target.com/robots.txt (1 min)
     - Any interesting disallowed paths?

  3. Check https://www.target.com/sitemap.xml (1 min)
     - Any API paths or admin pages listed?

  4. Search crt.sh manually in a browser (1 min)
     - See any subdomains you missed?

  5. Quick domain google dork (1 min)
     - site:target.com -www

  6. Check if there's a status page (1 min)
     - status.target.com

  7. Check GitHub for target company repos (2 min)
     - github.com/target-company

  8. Final gut check (1 min)
     - What did you miss? What feels off?
```

### 21.4 When Quality Check Fails

If quality check reveals you're missing critical data:
```
Don't panic. This happens. Take action:

1. Identify what's missing (from the checklist)
2. Estimate how long to fix it
3. If <15 min: fix it now, then hunt
4. If >15 min: fix the most critical gap, note the rest
5. If multiple gaps: this target may need more recon time
   than you allocated. Either extend or switch targets.

Never hunt blind. If you don't know:
  - What API endpoints exist
  - How authentication works
  - What technology stack is in use
...you're wasting time. Fix recon first.
```

---

## APPENDIX A: QUICK REFERENCE COMMANDS

PowerShell one-liners for common recon tasks:
```powershell
# crt.sh subdomains
Invoke-RestMethod "https://crt.sh/?q=%25.target.com&output=json" | % { $_.name_value } | Sort -U

# DNS resolution
[System.Net.Dns]::GetHostAddresses("target.com").IPAddressToString

# HTTP headers
Invoke-WebRequest "https://target.com" -Method Head | % Headers

# Response body
Invoke-WebRequest "https://target.com" | % Content

# URL parameters extraction
(gc urls.txt | % { if($_ -match '\?(.+?)(?:#|$)'){ $matches[1] -split '&' | % { $_ -split '=' | Select -First 1 } } } | Sort -U)

# Check if S3 bucket is public
iwr "https://target.s3.amazonaws.com" -Method Get | % Content | Select-String "ListBucketResult"

# Wayback URLs
iwr "http://web.archive.org/cdx/search/cdx?url=*.target.com&output=json" -Method Get | ConvertFrom-Json | % { $_[2] } | Sort -U

# Quick JavaScript analysis (find URLs)
(gc app.js -Raw) | Select-String '(https?://[^"''\s]+)' -AllMatches | % { $_.Matches.Value } | Sort -U

# Hash comparison for JS bundle changes
(Get-FileHash app.js -Algorithm SHA256).Hash

# Bulk subdomain checking
gc subs.txt | % { try { $ip=[Net.Dns]::GetHostAddresses($_); "$_ -> $([string]::Join(', ',$ip))" } catch {} }
```

## APPENDIX B: COMMON MISTAKES

```
1. Out-of-scope recon: Always, always check scope first.
2. Over-reconning: Spending 80% of time on recon, 20% on hunting. Reverse this.
3. Ignoring mobile: Many targets have mobile apps with different endpoints.
4. Skipping JS analysis: This is where the high-value intel lives.
5. Not filtering noise: 90% of recon data is noise. Filter aggressively.
6. Stale data: Don't use week-old recon for today's hunting session.
7. No prioritization: All findings are equal = no findings get hunted.
8. Saving secrets: Never save raw credentials to disk.
9. Tool-dependence: No tool replaces human analysis and context.
10. Giving up too early: The recon that finds nothing is still valuable data.
```

## APPENDIX C: RECON TOOLKIT CHECKLIST

```
Passive Recon:
  [ ] crt.sh accessible
  [ ] SecurityTrails API key
  [ ] Shodan account
  [ ] VirusTotal API key
  [ ] AlienVault OTX access
  [ ] Wayback Machine CDX access

Active Recon:
  [ ] DNS brute force wordlists
  [ ] Directory brute force wordlists
  [ ] Port scanning capability

Analysis:
  [ ] Whatweb / Wappalyzer
  [ ] curl / PowerShell Invoke-WebRequest
  [ ] jq / ConvertFrom-Json for JSON parsing
  [ ] Screenshot tool
  [ ] JavaScript beautifier/prettier

Cloud Recon:
  [ ] AWS CLI (configured)
  [ ] GCloud SDK (configured)
  [ ] Azure CLI (configured)

Mobile Recon:
  [ ] APK downloader
  [ ] jadx decompiler
  [ ] apktool
  [ ] iOS IPA analysis tools
```
