# Task Persistence — Recon Register

Per-target recon completion tracker. Records which recon phases are done, what assets are discovered, what's covered, and what's left. Prevents redundant recon and signals when it's safe to move to hunting or close a target.

---

## 1. Purpose

Recon is never truly "done", but it reaches diminishing returns. This file tracks completeness per target and prevents:
- Re-running the same recon on the same target
- Missing attack surface (e.g., never fuzzed GraphQL endpoint)
- Hunting before recon reach is sufficient

---

## 2. Register Entry Format

One section per target:

```
TARGET: example.com
STATUS: Active / Deprioritized / Abandoned / Complete
PROGRAM: HackerOne / Bugcrowd / Intigriti
SCOPE: *.example.com (excluding cdn.example.com)
FIRST RECON: YYYY-MM-DD
LAST RECON:   YYYY-MM-DD
NEXT RECON DUE: YYYY-MM-DD (re-run weekly)

ASSET COUNTS:
  Subdomains: [N] passive, [N] active, [N] resolved
  Live hosts: [N]
  URLs:       [N]
  JS bundles: [N]

PHASES COMPLETE:
  Seed:            [ ] / [x]
  Subdomain enum:  [ ] / [x]
  Live host:       [ ] / [x]
  Port scan:       [ ] / [x]
  URL crawl:       [ ] / [x]
  Tech fingerprint:[ ] / [x]
  Dir fuzz:        [ ] / [x]
  JS analysis:     [ ] / [x]
  Nuclei scan:     [ ] / [x]
  CT monitor:      [ ] / [x]

REMAINING ATTACK SURFACE:
  [list known-but-not-tested items]

FINDINGS FROM RECON: [N] (list: FIND-001, FIND-002)
REMAINING FINDING POTENTIAL: [High / Medium / Low]
```

---

## 3. Recon Phase Definitions

### Phase 1: Seed Discovery

```
CHECKLIST:
  [ ] Root domains identified
  [ ] CIDR ranges grabbed (if any)
  [ ] CT logs queried (crt.sh)
  [ ] WHOIS checked for related domains
  [ ] Acquisition targets identified

DONE CRITERIA:
  - All known root domains documented
  - No new domains found in CT logs after 2 lookups
```

### Phase 2: Subdomain Enumeration

```
CHECKLIST:
  [ ] subfinder (all sources) run
  [ ] crt.sh queried
  [ ] Active brute-force run (dnsx / shuffledns)
  [ ] Permutations run (dnsgen)
  [ ] All sources merged and deduped
  [ ] CNAME records collected

DONE CRITERIA:
  - Passive + active + permutations merged into subdomains/all.txt
  - Resolved via dnsx into subdomains/resolved.txt
  - New subdomain count stable (no new ones in last enumeration)
```

### Phase 3: Live Host Discovery

```
CHECKLIST:
  [ ] httpx probing run on all resolved subdomains
  [ ] Tech detection enabled
  [ ] Port scan run (naabu / nmap)
  [ ] Live hosts deduped and stored in hosts/live.txt

DONE CRITERIA:
  - hosts/live.txt populated
  - hosts/detailed.tsv has title, tech, status-code
  - hosts/ports.txt populated
```

### Phase 4: URL Crawling

```
CHECKLIST:
  [ ] waybackurls run
  [ ] gau run
  [ ] katana active crawl run (depth >= 2)
  [ ] gospider / hakrawler (optional)
  [ ] All merged and deduped into urls/all-urls.txt
  [ ] Parameters extracted (urls/parameters.txt)

DONE CRITERIA:
  - urls/all-urls.txt has at least [N] unique URLs
  - Parameters extracted from all URLs with query strings
  - URLs classified (API, files, auth, admin, etc.)
```

### Phase 5: Technology Fingerprinting

```
CHECKLIST:
  [ ] httpx -tech-detect run
  [ ] wafw00f run (WAF detected?)
  [ ] Key CMS/framework versions noted
  [ ] CDN provider identified

DONE CRITERIA:
  - technology/stack.txt populated
  - WAF/CDN status known
  - Version numbers recorded for CVE lookup
```

### Phase 6: Directory and File Fuzzing

```
CHECKLIST:
  [ ] ffuf common directories run on top hosts
  [ ] ffuf backup files run
  [ ] ffuf API endpoints run
  [ ] VHOST fuzzing run (if applicable)
  [ ] ffuf results parsed and classified

DONE CRITERIA:
  - Top 20 live hosts have directory enumeration
  - Interesting directories (200/401/403) documented
  - dirs.txt or equivalent populated and sorted
```

### Phase 7: JavaScript Analysis

```
CHECKLIST:
  [ ] JS URLs collected from katana / wayback
  [ ] JS bundles downloaded
  [ ] LinkFinder run (endpoints extracted)
  [ ] SecretFinder run (secrets extracted)
  [ ] API endpoints and GraphQL endpoints identified
  [ ] Source maps located

DONE CRITERIA:
  - js/urls.txt has all discovered JS files
  - js/endpoints.txt extracted
  - js/secrets.txt scanned (even if empty)
  - All non-CDN JS analyzed
```

### Phase 8: Nuclei Scan

```
CHECKLIST:
  [ ] nuclei -severity critical,high run on live hosts
  [ ] nuclei -t cves/ run
  [ ] nuclei -t exposures/ run
  [ ] Findings reviewed and false positives removed

DONE CRITERIA:
  - All critical/high nuclei findings reviewed
  - True positives added to active tasks or findings
  - False positives documented
```

### Phase 9: Certificate Transparency Monitoring

```
CHECKLIST:
  [ ] Initial crt.sh query run
  [ ] certstream configured (optional, for continuous monitoring)
  [ ] Any new certs found added to subdomains

DONE CRITERIA:
  - Initial CT collection done
  - New subdomains from CT added to subdomains/all.txt
```

---

## 4. Recon Completeness Signals

### When Recon is "Good Enough" for Hunting

```
CONDITIONS (all should be met):
  [ ] Hosts with known WAFs identified and excluded
  [ ] All API endpoints with IDs extracted
  [ ] All auth endpoints documented
  [ ] All upload/download endpoints documented
  [ ] GraphQL endpoints identified
  [ ] JS secrets scan complete
  [ ] Top 20 live hosts have directory fuzzing complete
  [ ] No new subdomains found in last 2 enumeration rounds

If all met: move to hunting. Recon becomes diminishing returns.
```

### When to Re-run Recon

```
RE-RUN RECON WHEN:
  - Weekly (continuous monitoring cadence)
  - New subdomains found via CT/certstream
  - Target launched new features (via blog / changelog / GitHub)
  - Previous recon was incomplete (time limited)
  - New wordlists available (Assetnote releases)
  - Hunting produced weak results (recon gap likely)

DO NOT RE-RUN RECON WHEN:
  - Same subdomains, same URLs, same results as last time
  - Still hunting the same bug class on the same feature
  - Just because it's been a few days (no new signal)
```

---

## 5. Attack Surface Coverage Map

Map each live host to recon status:

```
HOSTS COVERAGE MAP:

host1.example.com:
  Subdomain enum:   DONE
  Live probe:       DONE
  Port scan:        DONE (80, 443, 8080)
  URL crawl:        DONE (245 URLs)
  Tech detect:      DONE (Rails 7, Cloudflare)
  Dir fuzz:         DONE (common + raft-large)
  JS analysis:      DONE (3 bundles analyzed)
  Nuclei:           DONE (0 critical, 1 high - triaged N/A)
  Status:           HUNT READY

host2.example.com:
  Subdomain enum:   DONE
  Live probe:       DONE
  Port scan:        DONE (80, 443)
  URL crawl:        DONE (12 URLs)
  Tech detect:      DONE (WordPress 6.4)
  Dir fuzz:         INCOMPLETE (did only top 1000 dirs)
  JS analysis:      SKIP (no JS on WordPress)
  Nuclei:           DONE (2 high - reviewing)
  Status:           HUNT READY (dir fuzz incomplete but WP patterns well-known)

api.example.com:
  Subdomain enum:   DONE
  Live probe:       DONE
  Port scan:        DONE (3000)
  URL crawl:        DONE (API routes from JS + manual)
  Tech detect:      DONE (Express 4, Node 18)
  Dir fuzz:         SKIP (not relevant for API)
  JS analysis:      DONE (app.js -> endpoints extracted)
  Nuclei:           DONE
  Status:           HUNT READY (IDOR + auth targets identified)
```

---

## 6. Gap Detection

At end of each recon phase, run:

```
GAPS CHECK:
  [ ] Any live host not yet port scanned?
  [ ] Any host with 200 response not yet fuzzed?
  [ ] Any JS bundle not yet analyzed?
  [ ] Any API endpoint not yet mapped?
  [ ] Any GraphQL endpoint not yet introspection-checked?
  [ ] Any upload/download endpoint not yet listed?
  [ ] Any admin panel not yet probed?
  [ ] Any auth endpoint not yet reviewed?

If any YES: recon not complete for that host.
```

---

## 7. Recon Register File

Create and maintain this entry per target:

```markdown
# Recon Register: example.com

- Status: Active
- Program: HackerOne (target.com)
- Scope: *.example.com
- First recon: 2026-06-02
- Last recon: 2026-06-07

## Asset Counts
- Subdomains: 47 passive, 12 active, 39 resolved
- Live hosts: 23
- URLs: 1,247
- JS bundles: 5

## Phase Status
| Phase | Status | Notes |
|---|---|---|
| Seed discovery | Complete | 3 root domains |
| Subdomain enum | Complete | dnsgen + passive, no new for 2 days |
| Live host | Complete | 23 live |
| Port scan | Complete | top-ports done |
| URL crawl | Complete | wayback + gau + katana merged |
| Tech fingerprint | Complete | Rails 7, React, Cloudflare |
| Dir fuzz | Complete | common + raft-large on top 10 hosts |
| JS analysis | Complete | 3 bundles analyzed, endpoints extracted |
| Nuclei scan | Complete | 0 critical, 2 high (reviewed) |

## Remaining Attack Surface
- [ ] More endpoints on GraphQL (introspection not checked yet)
- [ ] Additional IDOR targets on newer endpoints
- [ ] SSRF on new avatar endpoint introduced last week

## Findings
- FIND-001: SSRF cloud metadata (to triage)
- FIND-002: JWT alg:none (to validate)
- FIND-003: IDOR write (submitted)

## Next Recon Due
- 2026-06-14 (weekly cadence)
- Trigger: check CT logs + new assets
```

---

## 8. Maintenance

```
AFTER EVERY RECON PHASE:
  [ ] Update phase status for current target
  [ ] Update asset counts
  [ ] Note any gaps discovered

AFTER EVERY HUNTING SESSION:
  [ ] Update "findings from recon" list
  [ ] Update "remaining attack surface" based on new findings

WEEKLY:
  [ ] Review all active targets
  [ ] Mark recon due targets
  [ ] Close recon-complete targets

MONTHLY:
  [ ] Archive recon register entries for abandoned targets
  [ ] Verify no stale "complete" entries (target may have changed)
```

---

*End of recon-register.md*
