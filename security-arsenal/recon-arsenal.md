---
name: recon-arsenal
description: Complete reconnaissance guide for bug bounty hunters and penetration testers. Covers subdomain enumeration, OSINT, technology fingerprinting, JavaScript analysis, endpoint discovery, and attack surface mapping. Use when reconning a target or building your initial attack surface inventory before testing begins.
---

# Recon Arsenal

Bug bounty reconnaissance methodology and references.

---

## RECON PHILOSOPHY

```
RECON LIFECYCLE:
1. MAP — Identify all assets for a target (domains, subdomains, IPs)
2. PROBE — Determine live hosts, ports, and technologies
3. GATHER — Collect endpoints, parameters, and interfaces
4. MATCH — Overlay vuln signals on asset inventory
5. ITERATE — Loop back as new subdomains or URLs appear
```

### Recon rules

```
Build the map before firing payloads.
Fail fast on wildcard responses.
Prefer passive → active only when needed.
Keep a working spreadsheet of live assets.
Automate everything runnable from shell.
```

---

## ASSET DISCOVERY

### Subdomain Discovery (Passive)

```bash
# subfinder (ProjectDiscovery)
subfinder -d target.com -o subs.txt -silent

# amass (OWASP-oriented)
amass enum -d target.com -o amass.txt -silent

# assetfinder
assetfinder --subs-only target.com >> subs.txt

# findomain
findomain -t target.com -o findomain.txt

# chaos (ProjectDiscovery)
chaos -d target.com -o chaos.txt

# OneForAll
python3 OneForAll/oneforall.py --target target.com run

# Subdomainizer
python3 Subdomainizer/Subdomainizer.py -d target.com -o subdomainizer.txt

# Aggregate passive results
cat subs.txt amass.txt findomain.txt chaos.txt | sort -u > all-subs.txt
```

### Reverse DNS and Splitting

```bash
# Reverse whois / organization search
amass intel -org "Target Company" -asn AS12345

# Reverse WHOIS by contact
amass intel -active -d target.com -whois

# IP enumeration for CIDRs
amass intel -asn AS12345 -o asn-ips.txt
```

### Live Host Validation

```bash
# httpx (HTTP probing)
cat all-subs.txt | httpx -silent -o live.txt

# Include status codes and title
cat all-subs.txt | httpx -status-code -title -tech-detect -o live-with-tech.txt

# Httprobe alternative
cat all-subs.txt | httprobe -c 50 -t 3000 -o live-httprobe.txt

# With ports
httpx -list all-subs.txt -ports 80,443,8080,8443,3000 -o live-on-ports.txt

# Alive DNS with validation
cat all-subs.txt | dnsx -a -resp-only -o live-dns.txt
```

### Certificate Transparency

```bash
# crt.sh
curl -sk "https://crt.sh/?q=%25.target.com&output=json" \
  | jq -r '.[].name_value' | sort -u >> ct-subs.txt

# certspotter
curl -sk "https://certspotter.com/api/v1/certificates?domain=target.com&include_subdomains=true&match_wildcards=true" \
  | jq -r '.[].dns_names[]' | sort -u >> ct.txt

# Censys
# hosts search for target.com + subdomains
# certificates for all domains with SANs
```

### Subdomain Takeover Pre-Check

```bash
# Quick CNAME-based list
cat live.txt | dnsx -cname -resp-only -o cnames.txt

# Nuclei takeover
nuclei -l cnames.txt -t takeovers/ -o takeover-hits.txt

# Manual fingerprint spot checks
for sub in $(cat live.txt); do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "$sub")
  echo "$code $sub"
done | grep -E '404|502|503'
```

---

## OSINT AND SEARCH ENGINE HUNTING

### GitHub / Git Dorks

```bash
# GitDorker (or manual gh equivalents)
gitdorker -tf tokens.txt -q '<org-name>' -d dorks/alldorks.txt -o dork.json

# Commonly leaked paths
gh search code "filename:.env target.com" --limit 20
gh search code "filename:config.json target.com" --limit 20
gh search code "const API_KEY target.com" --limit 20
gh search code "aws_access_key_id target.com" --limit 20
gh search code "password target.com" --limit 20

# Repos tied to target org
gh search repos "org:target-company" --limit 50

# Code contents
gh search code '"target.com" api_key' --limit 20
gh search code '"target.com" aws_secret_access_key' --limit 20
```

### Google / Bing Dorks

```text
site:*.target.com inurl:admin
site:*.target.com intitle:"index of"
site:*.target.com filetype:env
site:*.target.com inurl:.git
site:*.target.com ext:sql
site:*.target.com inurl:swagger
site:*.target.com "powered by"
site:*.target.com ext:log "password"
site:*.target.com intitle:"database error"
site:*.target.com "internal server error" stack
site:*.target.com filetype:pdf "confidential"
site:*.target.com inurl:login
```

### Shodan / Censys / ZoomEye

```bash
# Shodan
shodan init YOUR_API_KEY
shodan host target.com
shodan search 'hostname:target.com'
shodan search 'org:"Target Company"'
shodan search 'http.html:"Target Dashboard" http.status:200'

# Censys
censys search target.com
censys hosts target.com
censys certificates target.com
censys searchs 'target.com'

# ZoomEye (web only if no API key)
# https://www.zoomeye.org/
# Search: app:"Target App" + site:target.com
```

### Leak / Breach Intelligence

```bash
# Have I Been Pwned (requests are API-paid; often used manually)
# https://haveibeenpwned.com/

# DeHashed (manual)
# https://dehashed.com/

# Breach directories
# https://www.avast.com/hackcheck/
# https://ghostproject.fr/

# Organization collection on GitLab
git harvest targets/<org>/

# Pastebin / GitHub Gist search
gh search code "target.com in:readme" --limit 50

# Cross-referencing with user databases
# Disclose responsibly if valid credentials found
```

---

## CONTENT DISCOVERY

### Historical URL Collection

```bash
# gau (General URL Archive)
gau target.com --subs --o gau.txt
gau target.com --threads 20 --o gau-fast.txt

# waybackurls
waybackurls target.com >> wayback.txt
waybackurls target.com --wayback | sort -u >> wb-unique.txt

# waymore
waymore -i target.com -mode V -o waymore.txt

# urlfinder
URLFinder -u target.com -o urlfinder.txt

# gitleaks / git-dump hunters
gitauthors target repo if public
```

### Spidering

```bash
# katana (modern crawler)
katana -u https://target.com -d 5 -t 30 -o katana.txt
katana -u https://target.com -d 5 -jc -kf all -o katana-js.txt

# gospider
gospider -s https://target.com -d 3 -t 20 -o gospider.txt

# hakrawler
echo "https://target.com" | hakrawler -d 3 -t 20 >> hakr.txt

# ffuf for files and extensions
ffuf -u "https://target.com/FUZZ" \
  -w ~/wordlists/raft-large-directories.txt \
  -mc 200,301,302,401,403,500 -t 80 -ac \
  -o ffuf-directories.json

# feroxbuster (recursive)
feroxbuster -u https://target.com -w ~/wordlists/raft-medium.txt -t 50 -o ferox.txt
```

### robots.txt and sitemap.xml

```bash
curl -sk https://target.com/robots.txt
curl -sk https://target.com/sitemap.xml
curl -sk https://target.com/sitemap_index.xml

# Parse sitemap URLs
grep -oE '<loc>.*</loc>' sitemap.xml | sed 's/<[^>]*>//g' > sitemap-urls.txt
```

### robots.txt and sitemap.xml Bonus Targets

```bash
# Often reveal admin, test, staging paths
# Parse robots.txt for disallowed paths
curl -sk https://target.com/robots.txt | grep -iE 'disallow|allow' | awk '{print $2}'
curl -sk https://target.com/robots.txt | grep -i 'sitemap' | awk '{print $2}'

# Crawl sitemap tree
cat sitemap-index.xml | grep -oE '<loc>.*</loc>' | while read loc; do
  loc=$(echo "$loc" | sed 's/<[^>]*>//g')
  curl -sk "$loc"
done | grep -oE '<loc>.*</loc>' | sed 's/<[^>]*>//g' >> sitemap-urls.txt
```

---

## JAVASCRIPT HARVESTING AND ANALYSIS

### JS Collection

```bash
# Collect all JS files from gathered URLs
cat all-urls.txt | grep '\.js$' | sort -u > js-urls.txt

# Use Gau and wayback for historical JS
gau target.com | grep '\.js$' | sort -u >> js-urls.txt
waybackurls target.com | grep '\.js$' | sort -u >> js-urls.txt

# Download JS for offline analysis
mkdir -p js-artifacts
cat js-urls.txt | while read url; do
  fname=$(echo "$url" | sed 's|https\?://||;s|/|_|g' | cut -c1-200)
  curl -sk "$url" -o "js-artifacts/$fname.js"
done

# Sort unique
cat js-artifacts/*.js -q | sort -u > js-combined.txt
```

### Endpoint Extraction

LinkFinder, JSLuice, and manual grep patterns work well after JS files are downloaded.

Use regex grep to detect fetch/axios calls:
```bash
grep -rEo 'fetch\(["\`][^"\`]+["\`]\)' js-artifacts/
grep -rEo 'axios\.[a-z]+\([^)]+\)' js-artifacts/
grep -rEo '\.ajax\([^)]+\)' js-artifacts/
```

### Secret Scanning

```bash
# SecretFinder (cli output)
python3 SecretFinder.py -i main.js -o cli -g google_api_key,aws_access_key,aws_secret_key

# Slurp (~/tools/slurp)
slurp -t target.com

# truffleHog
trufflehog filesystem . --json

# Manual regex sweep for API keys
grep -rEoi '(api[_-]?key|apikey|api_secret)\s*[:=]\s*["\`]?[a-zA-Z0-9_\-]{20,}["\`]?' js-artifacts/
grep -rEoi 'AIza[0-9A-Za-z-_\-]{35}' js-artifacts/  # Google API
grep -rEoi '(sk_live|sk_test)_[0-9a-zA-Z]{24,}' js-artifacts/  # Stripe
grep -rEoi '-----BEGIN (RSA )?PRIVATE KEY-----' js-artifacts/  # SSH keys
```

### Source Map Exploitation

```bash
# Detect source map reference
tail -1 target.js | grep -i sourcemapurl

# Download map
curl -sk target.js.map -o target.js.map

# List original source files
jq -r '.sources[]' target.js.map | head -50

# Extract all sources
jq -r '.sourcesContent[]' target.js.map > extracted-sources.js

# Or use REsource / Burp Source Maps extension
# Burp Extension: Source Maps Retriever
```

---

## PARAMETER AND ENDPOINT DISCOVERY

### Parameter Enumeration

```bash
# arjun
arjun -u https://target.com/api/v1/users/123 -m GET
arjun -u https://target.com/api/v1/users/123 -m POST

# ParamSpider
python3 paramspider.py -d target.com --level high
python3 paramspider.py -d target.com -o high-params.txt

# BParams
bparams -u https://target.com/api/v1/users/123

# ffuf parameter fuzz
ffuf -u "https://target.com/api/v1/users/123?FUZZ=1" \
  -w ~/wordlists/params.txt -mc 200,400,401,403 -t 80

# x8 (fast)
x8 -u https://target.com -o x8-results.txt
```

### gf Pattern Filtering

```bash
# Filter discovered URLs by vulnerability hint
cat all-urls.txt | gf xss > xss-urls.txt
cat all-urls.txt | gf sqli > sqli-urls.txt
cat all-urls.txt | gf ssrf > ssrf-urls.txt
cat all-urls.txt | gf idor > idor-urls.txt
cat all-urls.txt | gf lfi > lfi-urls.txt
cat all-urls.txt | gf redirect > redirect-urls.txt
cat all-urls.txt | gf rce > rce-urls.txt
cat all-urls.txt | gf debug_logic > debug-urls.txt
cat all-urls.txt | gf upload-fields > upload-urls.txt
```

---

## TECHNOLOGY FINGERPRINTING

### Framework Stack Identification

```bash
# whatweb
whatweb -a 3 target.com

# nuclei tech templates
nuclei -u https://target.com -tags tech -o tech-results.txt

# httpx with tech detection
httpx -u https://target.com -tech-detect -title -status-code

# Wappalyzer (browser extension; CLI via wappalyzer-cli)
npx @wappalyzer/cli https://target.com

# WPScan (WordPress only)
wpscan --url https://target.com --enumerate vp,vt,cb

# Droopescan (Drupal, Joomla, SilverStripe, etc.)
droopescan scan drupal -u https://target.com
droopescan scan joomla -u https://target.com
droopescan scan silverstripe -u https://target.com

# Joomscan
joomscan -u https://target.com

# Nuclei CMS suites
nuclei -u https://target.com -t ~/nuclei-templates/cms/
```

### WAF Detection

```bash
# wafw00f
wafw00f https://target.com

# nuclei
nuclei -u https://target.com -tags waf

# wafalyzer
wafalyzer -u https://target.com

# Check headers manually
curl -skI https://target.com \
  | grep -iE '(cloudflare|akamai|imperva|f5|sucuri|barracuda|waf)'
```

### Cloud Metadata Detection

When EC2/EKS/Lambda targets appear in recon, always preserve /latest/meta-data related paths for SSRF testing.

---

## NETWORK AND SERVICE RECON

### Port and Service Mapping

```bash
# naabu
naabu -list targets.txt -o naabu-ports.txt -silent

# nmap (slower but richer)
nmap -sV -sC -p- -iL targets.txt -oN nmap-results.txt

# masscan
masscan -p1-65535 -iL targets.txt --rate 10000 -oX masscan.xml

# httpx with ports
httpx -list targets.txt -ports 80,443,8080,8443,3000,5000,8000
```

### Common Bug Bounty Ports

```text
80, 443, 8080, 8443 → web
3000, 5000, 8000, 9000, 9001 → development apps
2375, 2376 → Docker API
5984 → CouchDB
6379 → Redis (unauthenticated default)
27017, 27018 → MongoDB
3306 → MySQL
5432 → PostgreSQL
1433 → MSSQL
1521 → Oracle
9200, 9300 → Elasticsearch
15672, 5672 → RabbitMQ
10250 → Kubernetes Kubelet
6443 → Kubernetes API
2379, 2380 → etcd
5601 → Kibana
```

### Service Fingerprinting

```bash
# Docker API (useful CVE hit or container breakout)
for host in $(cat live.txt); do
  echo "=== $host ==="
  curl -sk http://$host:2375/version
  curl -sk http://$host:2375/containers/json
  curl -sk http://$host:2375/info
done

# Elasticsearch
curl -sk http://$host:9200/_cat/indices
curl -sk http://$host:9200/_search?pretty

# Redis
redis-cli -h $host INFO
redis-cli -h $host KEYS '*'

# Kibana
curl -sk http://$host:5601/api/status

# Prometheus
curl -sk http://$host:9090/api/v1/targets
curl -sk http://$host:9090/api/v1/alerts

# Jenkins
curl -sk http://$host:8080/script
curl -sk http://$host:8080/scriptText
```

---

## CLOUD AND INFRASTRUCTURE

### Cloud Asset Enumeration

```bash
# S3 buckets (AWS)
for suffix in '' -dev -staging -prod -backup -assets -uploads -data -static -cdn; do
  for prefix in target target-assets target-data target-uploads target-static target-media; do
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://${prefix}${suffix}.s3.amazonaws.com/")
    [ "$code" != "404" ] && echo "$code ${prefix}${suffix}.s3.amazonaws.com"
  done
done

# S3 with AWS CLI
aws s3 ls s3://target-bucket --no-sign-request 2>&1
aws s3 ls s3://target-bucket/ --recursive --no-sign-request

# Azure Blob Storage
for prefix in target target-data target-assets target-logs target-uploads; do
  curl -sk "https://${prefix}.blob.core.windows.net/?restype=container&comp=list"
done

# GCP GCS Buckets
gsutil ls gs://target*
gsutil ls -la gs://target-bucket

# Async / LanceDB / other storage
# Replace with target-specific provider if needed
```

### Cloud Metadata Probes (for SSRF context)

```bash
# AWS metadata
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/

# GCP metadata
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Header: Metadata-Flavor: Google

# Azure IMDS
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Header: Metadata: true
```

---

## RECON AUTOMATION

### Aggregation Scripts

```bash
#!/bin/bash
# sync-recon.sh
TARGET="$1"
[ -z "$TARGET" ] && echo "Usage: $0 target.com" && exit 1

mkdir -p recon/$TARGET/{raw,parsed,js,params,report}

# 1. Passive subdomains
subfinder -d $TARGET -o recon/$TARGET/raw/subfinder.txt -silent
amass enum -d $TARGET -o recon/$TARGET/raw/amass.txt -silent
cat recon/$TARGET/raw/*.txt | sort -u > recon/$TARGET/all-subs.txt

# 2. Live probing
cat recon/$TARGET/all-subs.txt | httpx -silent -o recon/$TARGET/live.txt

# 3. Historical URLs
gau $TARGET >> recon/$TARGET/raw/gau.txt
waybackurls $TARGET >> recon/$TARGET/raw/wayback.txt
katana -u https://$TARGET -d 3 -o recon/$TARGET/crawled.txt
cat recon/$TARGET/raw/*.txt recon/$TARGET/crawled.txt | sort -u \
  > recon/$TARGET/all-urls.txt

# 4. JS extraction
cat recon/$TARGET/all-urls.txt | grep '\.js$' | sort -u \
  > recon/$TARGET/js-urls.txt

echo "[*] Recon done for $TARGET"
echo "[*] Assets:"
echo "  - $(wc -l < recon/$TARGET/all-subs.txt) subdomains"
echo "  - $(wc -l < recon/$TARGET/live.txt) live hosts"
echo "  - $(wc -l < recon/$TARGET/all-urls.txt) URLs"
echo "  - $(wc -l < recon/$TARGET/js-urls.txt) JS files"
```

---

## RECON PRODUCTIVITY CHECKS

- Avoid returning bare placeholder pages manually; chain arjun + JS discovery + API doc extraction
- If subdomain coverage stalls, pivot to ASN/CIDR-based enumeration
- Don’t close recon until JS analysis, parameter mining, and API doc checks are all done

---

## FINAL RECON RULES

1. Normalize and dedupe after every data pull
2. Re-run discovery against each newly discovered subdomain
3. Prefer passive first; active only after scoping rules allow
4. Cross-reference leaks responsibly; never access claimed data
5. Sort live assets into testing queue before starting payload work
6. Separate “submitted findings” from “raw recon” to avoid duplicate claims
7. Update recon weekly or during retest cycles as scope changes
