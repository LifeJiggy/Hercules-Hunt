---
name: recon-skill
description: Reconnaissance and attack surface discovery specialist. Covers subdomain enumeration, live host discovery, URL crawling, technology fingerprinting, directory fuzzing, JavaScript analysis, and continuous monitoring. Use when starting recon on any web2 target or when asked about asset discovery, subdomain enum, or attack surface mapping.
---

# Reconnaissance Skill

## Overview

Systematic recon pipeline that maps a target's entire external attack surface. Passive first, then active. The goal is to find every asset, endpoint, technology, and potential entry point before hunting begins.

## Core Pipeline

```
1. Seed Discovery       → Find root domains, CIDR ranges
2. Subdomain Enum      → Passive + active subdomain discovery
3. Live Host Discovery → Filter live hosts from resolved domains
4. Port Scanning       → Identify open ports and services
5. Technology Fingerprint → Identify stack (WAF, frameworks, CDN)
6. URL Crawling        → Discover endpoints, parameters, paths
7. Directory Fuzzing   → Find hidden directories and files
8. JS Analysis         → Extract endpoints, API keys, secrets
9. Continuous Monitor  → Watch for new assets and changes
```

---

## Phases

### Phase 1: Seed Discovery
- Identify root domains from scope
- Find CIDR ranges via ASN lookup
- Acquire SSL certificates from Certificate Transparency logs
- Check WHOIS records for related domains
- Review program scope documentation

### Phase 2: Subdomain Enumeration
- Passive: subfinder, Chaos API, crt.sh, AlienVault OTX, SecurityTrails
- Active: DNS brute-force (dnsx, puredns)
- Scrape: certspotter, riddler, omnisint
- Permutations: altdns, dnsgen on discovered subdomains

### Phase 3: Live Host Discovery
- Resolve all discovered subdomains (dnsx)
- Probe for live HTTP/HTTPS hosts (httpx)
- Filter: remove dead hosts, stale DNS, parked domains

### Phase 4: URL Crawling
- Passive: waybackurls, gau, gauplus
- Active: katana, gospider
- Parameter extraction: URL patterns with params

### Phase 5: Technology Fingerprinting
- Identify: httpx, wappalyzer, whatweb
- Detect: WAF (wafw00f), CDN, frameworks, CMS
- Version detection for known CVE lookup

### Phase 6: Directory/File Fuzzing
- Tool: ffuf, dirsearch, gobuster
- Wordlists: SecLists, assetnote, custom
- Extensions: php, asp, aspx, jsp, do, action, json, xml

### Phase 7: JavaScript Analysis
- Extract JS URLs from crawled pages
- Analyze: LinkFinder, JSparser, SecretFinder
- Look for: API endpoints, hardcoded keys, internal paths, cloud configs

---

## Recommended Toolset

| Tool | Purpose |
|------|---------|
| subfinder | Passive subdomain enumeration |
| dnsx | DNS resolution and probing |
| httpx | HTTP live host probing |
| katana | Active URL crawling |
| ffuf | Directory/parameter fuzzing |
| gau | Wayback URL gathering |
| waybackurls | Historical URL extraction |
| wappalyzer | Tech stack detection |
| wafw00f | WAF detection |
| LinkFinder | JS endpoint extraction |
| SecretFinder | JS secret scanning |
| nuclei | Template-based vulnerability scanning |
| naabu | Fast port scanning |

---

## Output Format

Maintain structured output files per target:

```
target/
├── root-domains.txt
├── subdomains/
│   ├── passive.txt
│   ├── active.txt
│   ├── resolved.txt
│   └── all.txt
├── hosts/
│   └── live.txt
├── urls/
│   ├── wayback.txt
│   ├── crawler.txt
│   └── all.txt
├── tech.txt
├── js/
│   ├── urls.txt
│   ├── endpoints.txt
│   └── secrets.txt
├── dirs.txt
├── ports.txt
└── nuclei.txt
```

---

## Key Principles

1. **Passive first** — don't touch the target until you've exhausted passive sources
2. **Iterate** — found a new subdomain? Run all tools on it again
3. **Cross-reference** — check subdomains against known vulns, tech stack, scope
4. **Document everything** — recon output is the foundation for all hunting
5. **Continuous** — new assets appear daily. Re-run weekly.
6. **Quality > Quantity** — 100 verified live hosts > 10,000 unresolved DNS names

---

## When to Stop Recon

- All known subdomains are resolved and fingerprinted
- No new results after 3 rounds of permutation/subdomain discovery
- All live hosts have technology fingerprints
- URLs from all passive sources collected
- Directory fuzzing on all interesting paths completed
- JS bundles analyzed from all discovered pages

Move to hunting. Recon is never "done" but becomes diminishing returns.
