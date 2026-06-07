---
name: recon-methodology
description: Detailed reconnaissance methodology for external attack surface mapping. Step-by-step instructions for subdomain enumeration, live host discovery, URL crawling, technology fingerprinting, port scanning, JS analysis, and continuous monitoring pipeline.
---

# Reconnaissance Methodology

## 1. Seed Discovery

### Purpose
Identify all root domains, IP ranges, and related assets from scope.

### Steps
```
1. Parse program scope for:
   - Wildcard domains (*.target.com)
   - Exact domains (target.com, app.target.com)
   - IP ranges (CIDR notation)
   - Acquisition targets

2. ASN lookup:
   $ whois -h whois.radb.net -- '-i origin AS<ASN>' | grep '^route:'

3. Certificate Transparency:
   $ curl -s 'https://crt.sh/?q=%25.target.com&output=json'

4. WHOIS lookup:
   $ whois target.com
   - Check registrant email for other domains
   - Check nameservers for related infrastructure

5. Reverse DNS:
   - Check known IP ranges for PTR records
```

### Output
```
root-domains.txt     → target.com, api.target.com, admin.target.com
cidr-ranges.txt      → 203.0.113.0/24
related-domains.txt  → target-corp.com, target-io.com
```

---

## 2. Subdomain Enumeration

### Passive Enumeration (Phase 1)

**subfinder:**
```
$ subfinder -d target.com -o subfinder.txt
$ subfinder -d target.com -all -o subfinder-all.txt
```

**Chaos:**
```
$ chaos -d target.com -o chaos.txt
```

**crt.sh:**
```
$ curl -s 'https://crt.sh/?q=%25.target.com&output=json' | jq -r '.[].name_value' | sort -u | grep -v '*' > crtsh.txt
```

**AlienVault OTX:**
```
$ curl -s 'https://otx.alienvault.com/api/v1/indicators/domain/target.com/passive_dns' | jq -r '.passive_dns[].hostname' | sort -u > otx.txt
```

**Combined passive:**
```
$ cat subfinder.txt chaos.txt crtsh.txt otx.txt | sort -u > passive-all.txt
```

### Active Enumeration (Phase 2)

**DNS brute-force with common wordlist:**
```
$ dnsx -d target.com -w subdomains-top1million-5000.txt -o dnsx-brute.txt
```

**DNS brute-force with large wordlist:**
```
# Requires resolver list for reliability
$ puredns bruteforce subdomains-top1million-20000.txt target.com -r resolvers.txt -o puredns-brute.txt
```

### Permutations (Phase 3)
```
$ cat passive-all.txt | dnsgen - | dnsx -o permutations.txt
```

### Aggregation
```
$ cat passive-all.txt dnsx-brute.txt permutations.txt | sort -u > all-subdomains.txt
```

---

## 3. Live Host Discovery

### DNS Resolution
```
$ dnsx -l all-subdomains.txt -o resolved.txt
```

### HTTP Probing
```
$ httpx -l resolved.txt -o live-hosts.txt
$ httpx -l resolved.txt -title -tech-detect -status-code -o live-detailed.txt
```

### Port Scanning
```
# Quick common ports
$ naabu -l resolved.txt -top-ports 100 -o ports.txt

# Full scan (targets with higher tolerance)
$ naabu -l resolved.txt -p - -o ports-full.txt
```

### Output
```
live-hosts.txt       → https://app.target.com, https://admin.target.com
live-detailed.txt    → with title, tech, status code
```

---

## 4. URL Crawling

### Passive URL Sources

**waybackurls:**
```
$ cat live-hosts.txt | waybackurls > wayback-urls.txt
```

**gau:**
```
$ cat live-hosts.txt | gau > gau-urls.txt
```

**gauplus:**
```
$ cat live-hosts.txt | gauplus -o gauplus-urls.txt
```

### Active URL Crawling

**katana:**
```
$ katana -list live-hosts.txt -o katana-urls.txt
$ katana -list live-hosts.txt -d 3 -jc -o katana-deep.txt
```

**gospider:**
```
$ gospider -S live-hosts.txt -o gospider-output/
```

### Parameter Extraction
```
# Extract unique parameters
$ cat wayback-urls.txt gau-urls.txt katana-urls.txt | sort -u > all-urls.txt
$ cat all-urls.txt | grep '?' | unfurl -k unique | sort -u > unique-params.txt
```

---

## 5. Technology Fingerprinting

### Tech Stack Detection
```
$ httpx -l live-hosts.txt -tech-detect -o tech-stack.txt
$ whatweb -i live-hosts.txt --log-verbose=whatweb.log
$ wappalyzer-cli batch live-hosts.txt
```

### WAF Detection
```
$ wafw00f -i live-hosts.txt -o waf-detect.txt
$ cf-check < target.com > cloudflare-check.txt
```

### CDN Detection
```
$ cat live-hosts.txt | while read host; do
    ip=$(dig +short $host | head -1)
    curl -s https://ipinfo.io/$ip/json | jq '.org'
  done
```

### CMS Detection
```
$ cmseek -l live-hosts.txt
```

---

## 6. Directory and File Fuzzing

### Directory Discovery
```
$ ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -o dirs.json
$ ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt -o raft-dirs.json
```

### File Discovery
```
$ ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-files.txt -o files.json
```

### Extension-Specific Fuzzing
```
# API endpoints
$ ffuf -u https://target.com/FUZZ -w api-endpoints.txt -mc 200,201,204

# Backup files
$ ffuf -u https://target.com/FUZZ -w backup-file-names.txt -e .bak,.old,.backup,.zip,.tar.gz

# Parameter fuzzing on discovered endpoints
$ ffuf -u https://target.com/api/endpoint?FUZZ=test -w params.txt -fc 400
```

### VHOST Fuzzing
```
$ ffuf -u https://target.com -H "Host: FUZZ.target.com" -w vhosts.txt -fc 301,302,404
```

---

## 7. JavaScript Analysis

### Extract JS URLs
```
# From HTML of discovered pages
$ katana -list live-hosts.txt -jc -o all-js-urls.txt

# From wayback machine
$ cat all-urls.txt | grep '\.js$' | sort -u > js-urls.txt
$ cat wayback-urls.txt | grep '\.js$' | sort -u >> js-urls.txt
```

### Endpoint Extraction
```
$ python3 LinkFinder.py -i https://target.com/bundle.js -o endpoints.html
$ python3 LinkFinder.py -d urls.txt -o cli
```

### Secret Scanning
```
$ python3 SecretFinder.py -i https://target.com/bundle.js -o secrets.txt
$ grep -rPi '(?:api[_-]?key|api[_-]?secret|access[_-]?key|secret[_-]?access)' --include='*.js'
```

### Automated JS Analysis
```
$ cat js-urls.txt | nuclei -t ~/nuclei-templates/exposures/configs/ -o js-exposures.txt
```

---

## 8. Certificate Transparency Monitoring

```
# Current certs
$ curl -s 'https://crt.sh/?q=%25.target.com&output=json' | jq -r '.[].name_value' | sort -u

# Stream new certs (certstream)
$ certstream --domain target.com --json
```

---

## 9. Continuous Monitoring

### Set Up Daily Recon
```bash
#!/bin/bash
# Run daily to catch new assets

TARGET="target.com"
DATE=$(date +%Y-%m-%d)

# Run passive subdomain enum
subfinder -d $TARGET -o passive-$DATE.txt

# Compare with previous
diff previous.txt passive-$DATE.txt | grep '>' > new-assets-$DATE.txt

# Probe new assets
httpx -l new-assets-$DATE.txt -o live-new-$DATE.txt

# Crawl new live hosts
katana -list live-new-$DATE.txt -o new-urls-$DATE.txt

# Tech detect
httpx -l live-new-$DATE.txt -tech-detect -o new-tech-$DATE.txt

# Update previous
mv passive-$DATE.txt previous.txt
```

### GitHub Monitoring
```
# Watch for leaked credentials
Search: target.com AND (api_key OR password OR secret OR token)
ORGANIZATION: target OR REPO: target/*

# Watch for new repos
Search: org:target created:>2025-01-01
```

---

## 10. Attack Surface Prioritization

When recon is complete, prioritize targets by:

1. **New/Recently modified** — often have new undiscovered bugs
2. **Uncommon tech stack** — less audited, more likely to have bugs
3. **Auth-heavy features** — IDOR, auth bypass potential
4. **API endpoints** — GraphQL, REST, SOAP
5. **File upload features** — RCE, XSS vulnerable
6. **Redirect functionality** — SSRF, open redirect
7. **Admin/Internal panels** — auth bypass goldmine
8. **Old/Unmaintained code** — known CVEs, no patches
9. **Cloud infrastructure** — misconfigured S3, exposed services
10. **Third-party integrations** — SSRF, OAuth bugs

---

## Pro Tips

### Resolver Selection for DNS
- Use trusted resolvers (Cloudflare 1.1.1.1, Google 8.8.8.8)
- Test resolver health before large brute-force
- Use 20-50 resolvers for parallel lookups
- Avoid rate-limited public resolvers

### Rate Limiting & WAFs
- Rotate user-agents in httpx and ffuf
- Add delays between requests when hitting WAFs
- Use `-rate-limit` flags where available
- If blocked, switch to passive sources only

### Scope Validation
- Double-check all discovered subdomains against scope
- Wildcard (*.target.com) ≠ www.target.com for some programs
- Check acquisition companies and their subdomains
- Some programs exclude CDN/WAF hosts

### Output Management
- Deduplicate everything: sort -u
- Keep session logs for reproducibility
- Tag results by date for continuous recon
- Maintain a master hosts list per target
