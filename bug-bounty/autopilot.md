---
name: autopilot
description: Automated bug bounty hunting engine. Orchestrates recon, passive enumeration, subdomain discovery, live host detection, crawling, JavaScript analysis, vulnerability scanning, and reporting. Includes tool routing, parallel execution patterns, output handling, and session management. Use when: running automated recon pipelines, scaling reconnaissance, batch processing targets, or coordinating multiple tools in sequence. Chinese trigger: 自动化、自动扫描、批量、管道、 recon、信息收集自动化
---

# Skill: Autopilot

Automated hunting engine. Runs the recon pipeline and hands you leads.

## Core Concept

Autopilot does NOT find bugs. It finds **leads** — things worth investigating manually.

```
AUTOPILOT OUTPUT = LEADS (not bugs)
YOUR JOB = Triage leads → confirm bugs → write reports
```

Autopilot replaces grunt work. You replace pattern recognition.

---

## Pipeline Architecture

```
TARGET INPUT
    │
    ▼
PHASE 1: PASSIVE RECON (5 min)
├── subdomain enumeration (subfinder, assetfinder)
├── DNS resolution (dnsx)
├── Live host probing (httpx)
└── Output: /target/live.txt, /target/subs.txt
    │
    ▼
PHASE 2: URL DISCOVERY (10 min)
├── Crawling (katana)
├── Archive mining (waybackurls, gau)
├── API endpoint discovery (kiterunner, ffuf)
└── Output: /target/urls.txt
    │
    ▼
PHASE 3: JS & SECRET MINING (10 min)
├── JS file extraction
├── SecretFinder / jsluice
├── Endpoint extraction from JS
└── Output: /target/secrets.txt, /target/js-endpoints.txt
    │
    ▼
PHASE 4: VULNERABILITY SCANNING (15 min)
├── Nuclei template scan
├── XSS scanning (dalfox)
├── Open redirect detection
├── CORS misconfig testing
├── SSRF parameter mining
└── Output: /target/nuclei.txt, /target/dalfox.txt
    │
    ▼
PHASE 5: DEEP SCAN (20 min, optional)
├── Authenticated scanning (if creds provided)
├── Parameter discovery (arjun)
├── GraphQL introspection
├── Directory brute-force (ffuf)
└── Output: /target/params.txt, /target/ffuf.txt
    │
    ▼
HANDOFF TO HUMAN
└── Prioritized lead list: /target/leads.md
```

---

## Tool Routing by Phase

### Phase 1: Passive Recon

```bash
#!/bin/bash
# autopilot-recon.sh
TARGET=$1
OUTDIR="targets/$TARGET"
mkdir -p "$OUTDIR"

echo "[*] Phase 1: Passive Recon - $TARGET"

# Subdomain enumeration
echo "[*] Enumerating subdomains..."
subfinder -d "$TARGET" -silent -o "$OUTDIR/subs-subfinder.txt"
assetfinder --subs-only "$TARGET" > "$OUTDIR/subs-assetfinder.txt"
cat "$OUTDIR/subs-subfinder.txt" "$OUTDIR/subs-assetfinder.txt" | sort -u > "$OUTDIR/subs.txt"
echo "[+] Found $(wc -l < "$OUTDIR/subs.txt") subdomains"

# DNS resolution
echo "[*] Resolving DNS..."
cat "$OUTDIR/subs.txt" | dnsx -silent -a -aaaa -cname -resp > "$OUTDIR/dns.txt"

# Live host probing
echo "[*] Probing live hosts..."
cat "$OUTDIR/subs.txt" | httpx -silent \
  -status-code -title -tech-detect -follow-redirects \
  -o "$OUTDIR/live.txt"
echo "[+] Found $(wc -l < "$OUTDIR/live.txt") live hosts"

# Extract just URLs from httpx output (first column)
awk '{print $1}' "$OUTDIR/live.txt" > "$OUTDIR/urls.txt"
```

### Phase 2: URL Discovery

```bash
#!/bin/bash
# autopilot-urls.sh
TARGET=$1
OUTDIR="targets/$TARGET"

echo "[*] Phase 2: URL Discovery - $TARGET"

# Crawling
echo "[*] Crawling with katana..."
cat "$OUTDIR/urls.txt" | katana -d 3 -silent -jc -kf all \
  -o "$OUTDIR/urls-katana.txt"

# Wayback URLs
echo "[*] Mining wayback machine..."
echo "$TARGET" | waybackurls > "$OUTDIR/urls-wayback.txt"

# gau (known URLs)
echo "[*] Running gau..."
gau "$TARGET" > "$OUTDIR/urls-gau.txt"

# Combine all URLs
cat "$OUTDIR/urls-katana.txt" "$OUTDIR/urls-wayback.txt" "$OUTDIR/urls-gau.txt" | sort -u > "$OUTDIR/all-urls.txt"
echo "[+] Total URLs: $(wc -l < "$OUTDIR/all-urls.txt")"

# Filter interesting URLs
echo "[*] Filtering interesting URLs..."
grep -E "\.(js|json|xml|php|asp|aspx|jsp)" "$OUTDIR/all-urls.txt" > "$OUTDIR/static-files.txt"
grep -E "(api|graphql|rest|v1|v2)" "$OUTDIR/all-urls.txt" > "$OUTDIR/api-urls.txt"
grep -E "(admin|dashboard|internal|debug|test)" "$OUTDIR/all-urls.txt" > "$OUTDIR/admin-urls.txt"
```

### Phase 3: JS & Secret Mining

```bash
#!/bin/bash
# autopilot-js.sh
TARGET=$1
OUTDIR="targets/$TARGET"

echo "[*] Phase 3: JS Mining - $TARGET"

# Extract JS files
echo "[*] Extracting JavaScript files..."
grep "\.js$" "$OUTDIR/all-urls.txt" | sort -u > "$OUTDIR/jsfiles.txt"
echo "[+] Found $(wc -l < "$OUTDIR/jsfiles.txt") JS files"

# Run SecretFinder on each JS file
echo "[*] Running SecretFinder..."
mkdir -p "$OUTDIR/secrets"
while read js_url; do
    domain=$(echo "$js_url" | sed 's|https\?://||' | cut -d/ -f1)
    outfile="$OUTDIR/secrets/${domain}.txt"
    python3 tools/SecretFinder.py -i "$js_url" -o cli >> "$outfile" 2>/dev/null
done < "$OUTDIR/jsfiles.txt"

# Combine secrets
cat "$OUTDIR/secrets/"*.txt | sort -u > "$OUTDIR/all-secrets.txt"
echo "[+] Found $(wc -l < "$OUTDIR/all-secrets.txt") potential secrets"

# Extract endpoints from JS
echo "[*] Extracting endpoints from JS..."
mkdir -p "$OUTDIR/js-endpoints"
while read js_url; do
    domain=$(echo "$js_url" | sed 's|https\?://||' | cut -d/ -f1)
    outfile="$OUTDIR/js-endpoints/${domain}.txt"
    curl -s "$js_url" | grep -oE 'https?://[^"'\'']+|/api/[^"'\'']+|/v[0-9]+/[^"'\'']+' >> "$outfile" 2>/dev/null
done < "$OUTDIR/jsfiles.txt"

cat "$OUTDIR/js-endpoints/"*.txt | sort -u > "$OUTDIR/all-js-endpoints.txt"
echo "[+] Extracted $(wc -l < "$OUTDIR/all-js-endpoints.txt") endpoints from JS"

# Secret patterns
echo "[*] Running jsluice..."
cat "$OUTDIR/jsfiles.txt" | xargs -I {} sh -c 'echo "=== {} ==="' > "$OUTDIR/jsluice.txt"
# jsluice secrets -i < "$OUTDIR/jsfiles.txt" >> "$OUTDIR/jsluice.txt" 2>/dev/null
```

### Phase 4: Vulnerability Scanning

```bash
#!/bin/bash
# autopilot-scan.sh
TARGET=$1
OUTDIR="targets/$TARGET"

echo "[*] Phase 4: Vulnerability Scanning - $TARGET"

# Nuclei scan
echo "[*] Running Nuclei..."
nuclei -l "$OUTDIR/live.txt" \
  -severity critical,high,medium \
  -silent \
  -o "$OUTDIR/nuclei.txt" \
  -rl 150
echo "[+] Nuclei: $(wc -l < "$OUTDIR/nuclei.txt") findings"

# XSS scanning
echo "[*] Running dalfox..."
cat "$OUTDIR/api-urls.txt" | dalfox pipe --mining-dict --output "$OUTDIR/dalfox.txt"
echo "[+] Dalfox: $(wc -l < "$OUTDIR/dalfox.txt") potential XSS"

# Open redirect scanning
echo "[*] Scanning for open redirects..."
cat "$OUTDIR/all-urls.txt" | gf redirect | qsreplace "https://evil.com" | \
  while read url; do
    code=$(curl -s -o /dev/null -w "%{http_code}" -L "$url")
    if [ "$code" == "301" ] || [ "$code" == "302" ]; then
      echo "$code $url" >> "$OUTDIR/open-redirects.txt"
    fi
  done

# CORS misconfig
echo "[*] Testing CORS..."
cat "$OUTDIR/urls.txt" | while read url; do
    origin="https://evil.com"
    response=$(curl -s -H "Origin: $origin" -H "Access-Control-Request-Method: GET" \
      -I "$url" 2>/dev/null)
    if echo "$response" | grep -qi "access-control-allow-origin.*evil.com"; then
      echo "$url" >> "$OUTDIR/cors.txt"
    fi
done

# SSRF parameter discovery
echo "[*] Mining SSRF parameters..."
cat "$OUTDIR/all-urls.txt" | \
  grep -iE "(url|uri|link|redirect|callback|fetch|webhook|import)" \
  > "$OUTDIR/ssrf-params.txt"

# JWT detection
echo "[*] Detecting JWT tokens..."
cat "$OUTDIR/all-urls.txt" | \
  xargs -I {} sh -c 'curl -s {} | grep -oE "[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"' \
  | grep -E "^\w+\.\w+\.\w+$" > "$OUTDIR/jwt-tokens.txt"
```

### Phase 5: Deep Scan (Authenticated)

```bash
#!/bin/bash
# autopilot-deep.sh
TARGET=$1
OUTDIR="targets/$TARGET"
AUTH_FILE=${2:-""}

echo "[*] Phase 5: Deep Scan - $TARGET"

# Authenticated ffuf (IDOR testing)
if [ -n "$AUTH_FILE" ]; then
    echo "[*] Running authenticated ffuf..."
    # ID parameter brute
    seq 1 10000 | ffuf \
      -request "$OUTDIR/req-idor.txt" \
      -request-proto http \
      -w - \
      -ac \
      -o "$OUTDIR/ffuf-idor.json" \
      -t 50
fi

# Parameter discovery
echo "[*] Running arjun..."
arjun -T 20 -u "$OUTDIR/urls.txt" -o "$OUTDIR/params-arjun.json"

# GraphQL introspection
echo "[*] Testing GraphQL..."
cat "$OUTDIR/all-urls.txt" | grep -i graphql | while read url; do
    curl -s -X POST "$url" \
      -H "Content-Type: application/json" \
      -d '{"query": "{ __schema { types { name } } }"}' | \
      jq -r '.data.schema.types[].name' >> "$OUTDIR/graphql-types.txt"
done

# Directory brute-force on interesting paths
echo "[*] Directory brute-force..."
ffuf -u "https://FUZZ.$TARGET/" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -ac \
  -t 50 \
  -o "$OUTDIR/ffuf-subs.json"
```

---

## Lead Generation (Human Handoff)

```markdown
# Autopilot Leads: $TARGET
Generated: $(date)
Live Hosts: $(wc -l < live.txt)
Total URLs: $(wc -l < all-urls.txt)

## Critical Leads (Investigate First)

### 1. Nuclei Findings
$(cat nuclei.txt | grep -i critical)

### 2. JWT Tokens Found
$(cat jwt-tokens.txt | head -10)

### 3. Secrets in JS
$(cat all-secrets.txt | head -20)

### 4. SSRF Parameters
$(cat ssrf-params.txt | head -20)

### 5. Open Redirects
$(cat open-redirects.txt | head -10)

## High Priority Leads

### 6. API Endpoints
$(cat api-urls.txt | head -30)

### 7. Admin Paths
$(cat admin-urls.txt | head -20)

### 8. GraphQL Endpoints
$(cat all-urls.txt | grep -i graphql | head -10)

## Next Steps

1. Review critical leads above
2. Test JWT tokens for alg:none / weak secret
3. Test SSRF parameters for cloud metadata
4. Verify open redirects chain into OAuth
5. Test admin paths for auth bypass
6. Review secrets: are they live?
```

---

## Parallel Execution Engine

```bash
#!/bin/bash
# autopilot-parallel.sh — run multiple targets concurrently
TARGETS_FILE=$1
MAX_JOBS=4

export -f run_autopilot

run_autopilot() {
    local target=$1
    echo "[*] Starting autopilot for $target"
    ./autopilot-full.sh "$target"
    echo "[+] Completed $target"
}

export -f run_autopilot

cat "$TARGETS_FILE" | xargs -P "$MAX_JOBS" -I {} bash -c 'run_autopilot "$1"' _ {}
```

---

## Configuration

### autopilot.conf

```ini
[general]
outdir = targets/
max_concurrent = 4
timeout = 3600

[recon]
subfinder = true
assetfinder = true
dnsx = true
httpx = true

[discovery]
katana_depth = 3
waybackurls = true
gau = true
kiterunner = true

[scanning]
nuclei_severity = critical,high,medium
dalfox = true
cors_scan = true
redirect_scan = true

[deep_scan]
ffuf_threads = 50
arjun = true
graphql_introspection = true
dir_brute = false

[output]
generate_leads = true
generate_report = false
```

---

## Session Management

```python
# autopilot/session.py
import json
import os
from datetime import datetime

class Session:
    def __init__(self, target):
        self.target = target
        self.outdir = f"targets/{target}"
        self.state_file = f"{self.outdir}/.session.json"
        self.state = self.load()
    
    def load(self):
        if os.path.exists(self.state_file):
            with open(self.state_file) as f:
                return json.load(f)
        return {"phases": {}, "started": datetime.now().isoformat()}
    
    def save(self):
        with open(self.state_file, 'w') as f:
            json.dump(self.state, f, indent=2)
    
    def complete_phase(self, phase, output_files):
        self.state["phases"][phase] = {
            "status": "completed",
            "completed_at": datetime.now().isoformat(),
            "outputs": output_files
        }
        self.save()
    
    def is_done(self, phase):
        return self.state.get("phases", {}).get(phase, {}).get("status") == "completed"
    
    def get_outputs(self, phase):
        return self.state.get("phases", {}).get(phase, {}).get("outputs", [])
```

---

## Performance Tuning

### Rate Limiting

```bash
# httpx: 150 req/s
httpx -rl 150 -t 50

# nuclei: 150 req/s
nuclei -rl 150 -t 25

# ffuf: 50 req/s, 10 threads
ffuf -rate 50 -t 10

# katana: headless browser, slower
katana -d 3 -timeout 10
```

### Memory Management

```bash
# Large targets: process in batches
split -l 1000 all-urls.txt batch-

# Use anew for dedup (memory efficient)
cat urls.txt | anew all-urls.txt

# Pipe chains to avoid temp files
subfinder -d target | httpx | katana -d 2
```

### Resume Interrupted Scans

```bash
# Use -s (from-resume) in katana
katana -d 3 -s "$OUTDIR/katana-state.txt"

# httpx auto-resumes from file
httpx -l "$OUTDIR/live.txt" -o "$OUTDIR/live-new.txt"

# ffuf resume from results
ffuf -rc "$OUTDIR/ffuf-resume.json"
```

---

## Output Formats

### JSON Output (for parsing)

```bash
# httpx JSON output
httpx -json -o "$OUTDIR/live.json"

# Nuclei JSON
nuclei -json -o "$OUTDIR/nuclei.json"

# ffuf JSON
ffuf -of json -o "$OUTDIR/ffuf.json"
```

### Markdown Report (for human review)

```bash
#!/bin/bash
# autopilot-report.sh
TARGET=$1
OUTDIR="targets/$TARGET"

cat > "$OUTDIR/REPORT.md" << EOF
# Autopilot Report: $TARGET
Generated: $(date)

## Summary
- Subdomains: $(wc -l < "$OUTDIR/subs.txt")
- Live hosts: $(wc -l < "$OUTDIR/live.txt")
- Total URLs: $(wc -l < "$OUTDIR/all-urls.txt")
- JS files: $(wc -l < "$OUTDIR/jsfiles.txt")
- Secrets found: $(wc -l < "$OUTDIR/all-secrets.txt")
- Nuclei findings: $(wc -l < "$OUTDIR/nuclei.txt")
- Potential XSS: $(wc -l < "$OUTDIR/dalfox.txt")

## Critical Findings
$(cat "$OUTDIR/nuclei.txt" | grep -i critical)

## High Findings
$(cat "$OUTDIR/nuclei.txt" | grep -i high)

## Secrets Found
$(cat "$OUTDIR/all-secrets.txt" | head -30)

## SSRF Parameters
$(cat "$OUTDIR/ssrf-params.txt" | head -20)

## Interesting URLs
- API endpoints: $(wc -l < "$OUTDIR/api-urls.txt")
- Admin paths: $(wc -l < "$OUTDIR/admin-urls.txt")
- JS files: $(wc -l < "$OUTDIR/jsfiles.txt")

## Next Actions
1. Review critical findings
2. Test SSRF parameters for cloud metadata
3. Verify secrets are live
4. Test open redirects in OAuth flow
5. Review JS endpoints for hidden API
EOF
```

---

## Autopilot Best Practices

1. **Always review output** — autopilot finds leads, you confirm bugs
2. **Don't trust automated findings** — verify every Nuclei alert
3. **Kill fast** — if target returns all 403/404 after 5 min, stop
4. **Respect rate limits** — `-rl 150` for httpx, `-t 25` for nuclei
5. **Use sessions** — resume interrupted scans, don't restart from scratch
6. **Clean output** — `anew` for dedup, `sort -u` for unique
7. **Parallel when independent** — multiple targets in parallel, not single target
8. **Don't spray** — automated scans hit WAFs, trigger rate limits
9. **Auth once** — load session cookies, all tools inherit
10. **Human triage required** — autopilot is Phase 1, human is Phase 2-5

---

## One-Liner Pipelines

```bash
# Quick recon (5 min)
subfinder -d target -silent | dnsx -silent | httpx -silent -status-code -title

# Quick scan (10 min)
httpx -silent -l live.txt | nuclei -severity critical,high -silent

# JS secret scan
cat urls.txt | grep "\.js$" | xargs -I {} curl -s {} | SecretFinder -i - -o cli

# Full pipeline
bash autopilot-recon.sh target && bash autopilot-urls.sh target && bash autopilot-scan.sh target
```

---

## Limitations (What Autopilot CANNOT Do)

- Find business logic bugs (requires human reasoning)
- Chain bugs together (requires understanding impact)
- Distinguish real bugs from false positives
- Understand application context
- Write reports
- Determine severity/business impact
- Test authenticated flows without credentials

Autopilot finds 20% of bugs. You find the other 80%.

---

## Advanced Reconnaissance Modules

### Subdomain Enumeration Deep Dive

```bash
#!/bin/bash
# autopilot-subdomains.sh — exhaustive subdomain discovery
TARGET=$1
OUTDIR="targets/$TARGET"
mkdir -p "$OUTDIR/subdomains"

echo "[*] Advanced Subdomain Enumeration - $TARGET"

# Passive sources
echo "[*] Running passive enumeration..."
subfinder -d "$TARGET" -silent -o "$OUTDIR/subdomains/subfinder.txt" \
  -sources shodan,censys,threatcrowd,virustotal,securitytrails,alienvault

assetfinder --subs-only "$TARGET" > "$OUTDIR/subdomains/assetfinder.txt"

# Certificate transparency logs
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | \
  jq -r '.[].name_value' | sort -u > "$OUTDIR/subdomains/ct-logs.txt"

# DNS brute force (if subdomains file available)
echo "[*] Running DNS brute force..."
puredns bruteforce "$TARGET" \
  /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -r /usr/share/seclists/Discovery/DNS/namservers-resolvers.txt \
  -w "$OUTDIR/subdomains/dns-brute.txt" \
  -t 2000

# Combine all sources
cat "$OUTDIR/subdomains/"*.txt | sort -u > "$OUTDIR/subdomains/all.txt"
echo "[+] Total subdomains: $(wc -l < "$OUTDIR/subdomains/all.txt")"
```

### Live Host Probing Deep Dive

```bash
#!/bin/bash
# autopilot-live.sh — comprehensive live host detection
TARGET=$1
OUTDIR="targets/$TARGET"

echo "[*] Live Host Probing - $TARGET"

# Comprehensive httpx scan
echo "[*] Probing with httpx..."
cat "$OUTDIR/subdomains/all.txt" | httpx \
  -silent \
  -status-code \
  -title \
  -tech-detect \
  -follow-redirects \
  -timeout 10 \
  -retries 2 \
  -rate-limit 150 \
  -threads 50 \
  -o "$OUTDIR/live.txt"

# Extract just URLs
awk '{print $1}' "$OUTDIR/live.txt" > "$OUTDIR/urls.txt"

# Port scanning on interesting hosts (top 1000 ports)
echo "[*] Port scanning top hosts..."
head -20 "$OUTDIR/live.txt" | awk '{print $1}' | \
  naabu -top-ports 1000 -silent -o "$OUTDIR/ports.txt"

# Technology fingerprinting
echo "[*] Technology fingerprinting..."
cat "$OUTDIR/live.txt" | httpx -tech-detect -json -o "$OUTDIR/tech.json"
```

### Cloud Asset Enumeration

```bash
#!/bin/bash
# autopilot-cloud.sh — cloud asset discovery
TARGET=$1
OUTDIR="targets/$TARGET"
mkdir -p "$OUTDIR/cloud"

echo "[*] Cloud Asset Enumeration - $TARGET"

# S3 bucket brute force
echo "[*] Checking S3 buckets..."
for suffix in "" "-dev" "-staging" "-test" "-backup" "-api" "-data" "-assets" "-static" "-cdn" "-uploads" "-media" "-files" "-bucket" "-storage" "-prod"; do
    for prefix in "$TARGET" "$TARGET-assets" "$TARGET-data" "$TARGET-backup" "assets-$TARGET" "static-$TARGET"; do
        bucket="${prefix}${suffix}"
        code=$(curl -s -o /dev/null -w "%{http_code}" "https://${bucket}.s3.amazonaws.com/" --max-time 5)
        if [ "$code" != "404" ] && [ "$code" != "000" ]; then
            echo "$code https://${bucket}.s3.amazonaws.com/" >> "$OUTDIR/cloud/s3.txt"
        fi
    done
done

# Azure blob storage
for suffix in "" "-dev" "-staging" "-prod"; do
    for prefix in "$TARGET" "$TARGET-data"; do
        account="${prefix}${suffix}"
        code=$(curl -s -o /dev/null -w "%{http_code}" "https://${account}.blob.core.windows.net/" --max-time 5)
        if [ "$code" != "404" ] && [ "$code" != "000" ]; then
            echo "$code https://${account}.blob.core.windows.net/" >> "$OUTDIR/cloud/azure.txt"
        fi
    done
done

# GCP buckets
for prefix in "$TARGET" "assets-$TARGET" "data-$TARGET" "static-$TARGET"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/${prefix}" --max-time 5)
    if [ "$code" != "404" ] && [ "$code" != "000" ]; then
        echo "$code https://storage.googleapis.com/${prefix}" >> "$OUTDIR/cloud/gcp.txt"
    fi
done

# Firebase apps
echo "[*] Checking Firebase..."
for app_id in "$TARGET" "$TARGET-app" "$TARGET-web" "$TARGET-prod"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://${app_id}.firebaseio.com/.json" --max-time 5)
    if [ "$code" == "200" ]; then
        echo "https://${app_id}.firebaseio.com/.json" >> "$OUTDIR/cloud/firebase.txt"
    fi
done

# Heroku apps
for app in "$TARGET" "$TARGET-api" "$TARGET-web" "$TARGET-app"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://${app}.herokuapp.com/" --max-time 5)
    if [ "$code" != "404" ] && [ "$code" != "000" ]; then
        echo "$code https://${app}.herokuapp.com/" >> "$OUTDIR/cloud/heroku.txt"
    fi
done

echo "[+] Cloud assets found: $(wc -l < "$OUTDIR/cloud/"*.txt 2>/dev/null || echo 0)"
```

### GitHub Reconnaissance

```bash
#!/bin/bash
# autopilot-github.sh — GitHub reconnaissance
TARGET=$1
OUTDIR="targets/$TARGET"
ORG=$2  # Optional: specific GitHub org name

echo "[*] GitHub Reconnaissance - $TARGET"

# If org not specified, try to find it
if [ -z "$ORG" ]; then
    ORG=$(curl -s "https://api.github.com/search/users?q=${TARGET}" | \
      jq -r '.items[0].login' 2>/dev/null)
fi

if [ "$ORG" != "null" ] && [ -n "$ORG" ]; then
    mkdir -p "$OUTDIR/github"
    
    # List repos
    echo "[*] Listing repos for $ORG..."
    curl -s "https://api.github.com/orgs/$ORG/repos?per_page=100" | \
      jq -r '.[].clone_url' > "$OUTDIR/github/repos.txt"
    
    # Search for exposed secrets in repo names/descriptions
    curl -s "https://api.github.com/orgs/$ORG/repos?per_page=100" | \
      jq -r '.[] | "\(.name): \(.description // "no desc")"' > "$OUTDIR/github/repos-info.txt"
    
    # Check for .github/workflows in each repo
    echo "[*] Checking workflows..."
    while read repo; do
        repo_name=$(echo "$repo" | sed 's|.*/||;s/\.git$//')
        workflows=$(curl -s "https://api.github.com/repos/$ORG/$repo_name/contents/.github/workflows" | \
          jq -r '.[].name' 2>/dev/null)
        if [ "$workflows" != "null" ]; then
            echo "$repo_name: $workflows" >> "$OUTDIR/github/workflows.txt"
        fi
    done < "$OUTDIR/github/repos.txt"
    
    # Search for exposed keys in code (using GitHub search API)
    echo "[*] Searching for exposed keys..."
    curl -s "https://api.github.com/search/code?q=${TARGET}+api_key+in:file" | \
      jq '.items[] | .repository.full_name' > "$OUTDIR/github/exposed-keys.txt"
    
    # GitDorker (if available)
    if command -v GitDorker &>/dev/null; then
        echo "[*] Running GitDorker..."
        GitDorker -org "$ORG" -d dorks/alldorksv3 -o "$OUTDIR/github/gitdorker.txt"
    fi
else
    echo "[-] Could not find GitHub org for $TARGET"
fi
```

### Wayback Machine Deep Mining

```bash
#!/bin/bash
# autopilot-wayback.sh — archive mining
TARGET=$1
OUTDIR="targets/$TARGET"

echo "[*] Wayback Machine Mining - $TARGET"

# Get all URLs from Wayback
echo "$TARGET" | waybackurls > "$OUTDIR/urls-wayback.txt"
echo "[+] Wayback URLs: $(wc -l < "$OUTDIR/urls-wayback.txt")"

# Get URLs from Common Crawl
echo "[*] Mining Common Crawl..."
curl -s "https://index.commoncrawl.org/CC-MAIN-2024-26-index?url=*.$TARGET&output=json" | \
  jq -r '.url' | sort -u > "$OUTDIR/urls-commoncrawl.txt"

# Get URLs from alienvault OTX
echo "[*] Mining OTX..."
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$TARGET/url_list?limit=1000" | \
  jq -r '.data[].url' | sort -u > "$OUTDIR/urls-otx.txt"

# Combine all URL sources
cat "$OUTDIR/urls-wayback.txt" "$OUTDIR/urls-commoncrawl.txt" "$OUTDIR/urls-otx.txt" | \
  sort -u > "$OUTDIR/all-historical-urls.txt"
echo "[+] Total historical URLs: $(wc -l < "$OUTDIR/all-historical-urls.txt")"

# Filter for interesting patterns
echo "[*] Filtering historical URLs..."
grep -E "\.(js|json|xml|php|asp|aspx|jsp)" "$OUTDIR/all-historical-urls.txt" > "$OUTDIR/historical-static.txt"
grep -E "(admin|dashboard|internal|debug|test|api|graphql)" "$OUTDIR/all-historical-urls.txt" > "$OUTDIR/historical-interesting.txt"
grep -E "(\.git|\.env|\.htaccess|web\.config)" "$OUTDIR/all-historical-urls.txt" > "$OUTDIR/historical-sensitive.txt"

# Check for removed endpoints (404 now but existed before)
echo "[*] Checking removed endpoints..."
while read url; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "$url" --max-time 5)
    if [ "$code" == "404" ] || [ "$code" == "000" ]; then
        echo "$code $url" >> "$OUTDIR/historical-removed.txt"
    fi
done < "$OUTDIR/historical-interesting.txt"
```

### JavaScript Bundle Analysis

```bash
#!/bin/bash
# autopilot-js-deep.sh — comprehensive JS analysis
TARGET=$1
OUTDIR="targets/$TARGET"

echo "[*] Deep JavaScript Analysis - $TARGET"

mkdir -p "$OUTDIR/js-analysis"

# Download all JS files
echo "[*] Downloading JS files..."
mkdir -p "$OUTDIR/js-analysis/downloads"
while read js_url; do
    filename=$(echo "$js_url" | sed 's|https\?://||' | tr '/?' '__' | cut -c1-100)
    curl -s "$js_url" -o "$OUTDIR/js-analysis/downloads/$filename.js"
done < "$OUTDIR/jsfiles.txt"

# Run analysis on each file
echo "[*] Analyzing JS files..."
for js_file in "$OUTDIR/js-analysis/downloads/"*.js; do
    basename=$(basename "$js_file" .js)
    
    # Size check
    size=$(wc -c < "$js_file")
    echo "$basename: ${size} bytes" >> "$OUTDIR/js-analysis/sizes.txt"
    
    # Extract strings
    strings "$js_file" | grep -E "^[A-Za-z0-9/]{20,}$" > "$OUTDIR/js-analysis/strings-$basename.txt"
    
    # Extract URLs
    grep -oE 'https?://[^"'\''>\s]+' "$js_file" | sort -u > "$OUTDIR/js-analysis/urls-$basename.txt"
    
    # Extract API endpoints
    grep -oE '"/api/[^"'\''>\s]+"' "$js_file" | sed 's/"//g' | sort -u > "$OUTDIR/js-analysis/endpoints-$basename.txt"
    
    # Check for source map
    grep "sourceMappingURL" "$js_file" | head -5 > "$OUTDIR/js-analysis/sourcemap-$basename.txt"
done

# Combined results
cat "$OUTDIR/js-analysis/endpoints-"*.txt | sort -u > "$OUTDIR/js-analysis/all-endpoints.txt"
cat "$OUTDIR/js-analysis/urls-"*.txt | sort -u > "$OUTDIR/js-analysis/all-urls.txt"
echo "[+] Extracted $(wc -l < "$OUTDIR/js-analysis/all-endpoints.txt") endpoints from JS"
```

### Nuclei Template Customization

```bash
#!/bin/bash
# autopilot-nuclei.sh — custom Nuclei scanning
TARGET=$1
OUTDIR="targets/$TARGET"

echo "[*] Advanced Nuclei Scanning - $TARGET"

# Standard scan
echo "[*] Running standard nuclei scan..."
nuclei -l "$OUTDIR/live.txt" \
  -severity critical,high,medium \
  -silent \
  -o "$OUTDIR/nuclei.txt" \
  -rl 150 \
  -t ~/nuclei-templates/

# Technology-specific scan
echo "[*] Running tech-specific scans..."
if grep -qi "wordpress" "$OUTDIR/live.txt"; then
    nuclei -l "$OUTDIR/live.txt" -t ~/nuclei-templates/technologies/wordpress/ -o "$OUTDIR/nuclei-wp.txt"
fi
if grep -qi "laravel" "$OUTDIR/live.txt"; then
    nuclei -l "$OUTDIR/live.txt" -t ~/nuclei-templates/technologies/laravel/ -o "$OUTDIR/nuclei-laravel.txt"
fi
if grep -qi "django" "$OUTDIR/live.txt"; then
    nuclei -l "$OUTDIR/live.txt" -t ~/nuclei-templates/technologies/django/ -o "$OUTDIR/nuclei-django.txt"
fi

# Exposures scan
echo "[*] Running exposure scan..."
nuclei -l "$OUTDIR/live.txt" \
  -t ~/nuclei-templates/exposures/ \
  -o "$OUTDIR/nuclei-exposures.txt"

# CVE scan
echo "[*] Running CVE scan..."
nuclei -l "$OUTDIR/live.txt" \
  -t ~/nuclei-templates/cves/ \
  -severity critical,high \
  -o "$OUTDIR/nuclei-cves.txt"

# Custom template scan (if you have custom templates)
if [ -d "./custom-nuclei-templates" ]; then
    echo "[*] Running custom templates..."
    nuclei -l "$OUTDIR/live.txt" \
      -t ./custom-nuclei-templates/ \
      -o "$OUTDIR/nuclei-custom.txt"
fi
```

---

## Complete Autopilot Pipeline Script

```bash
#!/bin/bash
# autopilot-full.sh — complete automated recon pipeline
# Usage: ./autopilot-full.sh target.com [org-name]

set -e

TARGET=$1
ORG=${2:-""}
OUTDIR="targets/$TARGET"
mkdir -p "$OUTDIR"

echo "=========================================="
echo "Autopilot Full Pipeline: $TARGET"
echo "Started: $(date)"
echo "=========================================="

# Phase 1: Recon
echo ""
echo "[PHASE 1] Passive Recon"
./autopilot-recon.sh "$TARGET"

# Phase 2: URL Discovery
echo ""
echo "[PHASE 2] URL Discovery"
./autopilot-urls.sh "$TARGET"

# Phase 3: Cloud Enumeration
echo ""
echo "[PHASE 3] Cloud Enumeration"
./autopilot-cloud.sh "$TARGET"

# Phase 4: GitHub Recon
echo ""
echo "[PHASE 4] GitHub Recon"
./autopilot-github.sh "$TARGET" "$ORG"

# Phase 5: Wayback Mining
echo ""
echo "[PHASE 5] Wayback Mining"
./autopilot-wayback.sh "$TARGET"

# Phase 6: JS Analysis
echo ""
echo "[PHASE 6] JavaScript Analysis"
./autopilot-js.sh "$TARGET"

# Phase 7: Vulnerability Scanning
echo ""
echo "[PHASE 7] Vulnerability Scanning"
./autopilot-scan.sh "$TARGET"

# Phase 8: Nuclei
echo ""
echo "[PHASE 8] Nuclei Deep Scan"
./autopilot-nuclei.sh "$TARGET"

# Phase 9: Generate Leads
echo ""
echo "[PHASE 9] Generating Leads Report"
./autopilot-leads.sh "$TARGET"

echo ""
echo "=========================================="
echo "Autopilot Complete: $TARGET"
echo "Finished: $(date)"
echo "Results: $OUTDIR/leads.md"
echo "=========================================="
```

---

## Lead Prioritization System

### Scoring Leads for Manual Investigation

```python
#!/usr/bin/env python3
# autopilot/score_leads.py
import re
import json

def score_finding(line):
    score = 0
    reasons = []
    
    line_lower = line.lower()
    
    # Critical findings
    if any(x in line_lower for x in ['critical', 'rce', 'remote code execution', 'sql injection']):
        score += 50
        reasons.append('Critical severity indicator')
    
    # High-value patterns
    if any(x in line_lower for x in ['admin', 'api/v2/admin', 'internal', 'debug']):
        score += 30
        reasons.append('Admin/internal endpoint')
    
    if any(x in line_lower for x in ['jwt', 'token', 'bearer', 'authorization']):
        score += 20
        reasons.append('Authentication token')
    
    if any(x in line_lower for x in ['ssrf', 'metadata', '169.254', 'cloud']):
        score += 40
        reasons.append('SSRF vector')
    
    if any(x in line_lower for x in ['idor', 'insecure direct object']):
        score += 30
        reasons.append('IDOR potential')
    
    if any(x in line_lower for x in ['api key', 'aws', 'stripe', 'secret']):
        score += 25
        reasons.append('Exposed secret')
    
    # Medium-value patterns
    if any(x in line_lower for x in ['graphql', 'introspection']):
        score += 15
        reasons.append('GraphQL endpoint')
    
    if any(x in line_lower for x in ['upload', 'file', 'image']):
        score += 15
        reasons.append('File upload surface')
    
    if any(x in line_lower for x in ['redirect', 'oauth', 'auth']):
        score += 15
        reasons.append('Auth flow')
    
    if re.search(r'\.js$', line):
        score += 10
        reasons.append('JavaScript file')
    
    return score, reasons

# Score all findings
findings = []
for line in open('targets/target/nuclei.txt'):
    score, reasons = score_finding(line)
    if score > 0:
        findings.append({'line': line.strip(), 'score': score, 'reasons': reasons})

# Sort by score
findings.sort(key=lambda x: x['score'], reverse=True)

# Output prioritized leads
print("=" * 60)
print("PRIORITIZED LEADS")
print("=" * 60)
for f in findings[:30]:
    print(f"\n[Score: {f['score']}] {f['line']}")
    print(f"  Reasons: {', '.join(f['reasons'])}")
```

---

## Autopilot Configuration Reference

### Full Configuration File

```ini
# autopilot.conf

[general]
outdir = targets/
max_concurrent = 4
timeout = 7200
notify = false
auto_report = false

[recon]
subfinder_threads = 50
assetfinder = true
dnsx_threads = 50
dnsx_retries = 2
httpx_threads = 50
httpx_timeout = 10
httpx_rate_limit = 150

[discovery]
katana_depth = 3
katana_headless = false
katana_timeout = 10
waybackurls = true
gau = true
common_crawl = true
otx = true

[scanning]
nuclei_severity = critical,high,medium
nuclei_threads = 25
nuclei_rate_limit = 150
dalfox = true
cors_scan = true
redirect_scan = true
redirect_payloads = https://evil.com,//evil.com,https://target.com@evil.com

[deep_scan]
ffuf_threads = 50
ffuf_rate_limit = 100
arjun = true
arjun_threads = 20
graphql_introspection = true
dir_brute = false
dir_wordlist = /usr/share/seclists/Discovery/Web-Content/common.txt

[js_analysis]
secretfinder = true
jsluice = true
linkfinder = true
sourcemap_analysis = true
retirejs = true

[cloud]
s3_brute = true
azure_blob = true
gcp_bucket = true
firebase_check = true
heroku_check = true

[github]
search_orgs = true
gitdorker = true
workflow_scan = true

[output]
generate_leads = true
generate_summary = true
json_output = true
markdown_report = true

[exclusions]
exclude_extensions = .png,.jpg,.gif,.css,.woff,.ttf,.svg
exclude_status_codes = 404,400,501,502,503
exclude_keywords = signup,signin,login,register
```

---

## Integration with Other Tools

### Integration: Autopilot + Burp Suite

```bash
# Export targets to Burp
cat "$OUTDIR/live.txt" | awk '{print $1}' > "$OUTDIR/burp-targets.txt"
# Import to Burp: Target → Site Map → Import

# Generate Burp macro from autopilot auth
# Use session cookie from autopilot auth file
```

### Integration: Autopilot + Note-Taking

```bash
# Export findings to Obsidian/Notion
cat "$OUTDIR/leads.md" | \
  sed 's/^# /## /' > "$OUTDIR/obsidian-note.md"

# Or JSON for further processing
python3 autopilot/json_to_notion.py "$OUTDIR/results.json"
```

### Integration: Autopilot + Slack/Discord Notifications

```bash
# Slack notification on completion
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"Autopilot complete for '$TARGET'. Found '"$(wc -l < "$OUTDIR/nuclei.txt")"' vulnerabilities."}' \
  "$SLACK_WEBHOOK"

# Discord notification
curl -X POST "$DISCORD_WEBHOOK" \
  -H "Content-Type: application/json" \
  -d "{\"content\": \"Autopilot complete for $TARGET: $(wc -l < "$OUTDIR/nuclei.txt") findings\"}"
```

---

## Troubleshooting Guide

### Common Issues

**Issue: subfinder returning no results**
```
Fix: Check internet connection, try different sources
Debug: subfinder -d target -v
```

**Issue: httpx timing out on many hosts**
```
Fix: Increase timeout: httpx -timeout 15
Fix: Reduce threads: httpx -t 25
Fix: Use rate limiting: httpx -rl 100
```

**Issue: Nuclei too slow**
```
Fix: Reduce templates: nuclei -t ~/nuclei-templates/http/
Fix: Increase threads: nuclei -t 50
Fix: Rate limit: nuclei -rl 200
```

**Issue: katana not crawling deep enough**
```
Fix: Increase depth: katana -d 5
Fix: Enable JS crawling: katana -jc
Fix: Increase timeout: katana -timeout 15
```

**Issue: Memory errors on large targets**
```
Fix: Process in batches
Fix: Use | anew for dedup instead of storing all in memory
Fix: Increase swap space
```

---

## Scaling Autopilot for Multiple Targets

### Target List Processing

```bash
# Create target list
cat > targets.txt << EOF
target1.com
target2.com
target3.com
EOF

# Process all targets with concurrency limit
cat targets.txt | xargs -P 4 -I {} bash -c '
  echo "=== Starting {} ==="
  ./autopilot-full.sh {}
  echo "=== Completed {} ==="
'

# Or use GNU Parallel (better output handling)
parallel -j 4 ./autopilot-full.sh {} ::: $(cat targets.txt)
```

### Distributed Scanning

```bash
# On multiple machines, split target list
split -n l/4 targets.txt targets-part-

# Machine 1: ./autopilot-full.sh @targets-part-aa
# Machine 2: ./autopilot-full.sh @targets-part-ab
# Machine 3: ./autopilot-full.sh @targets-part-ac
# Machine 4: ./autopilot-full.sh @targets-part-ad

# Combine results
for dir in targets/*/; do
    cat "$dir/nuclei.txt" >> all-nuclei.txt
    cat "$dir/leads.md" >> all-leads.md
done
```

---

## Maintenance and Updates

### Keeping Tools Updated

```bash
#!/bin/bash
# autopilot-update.sh — update all autopilot tools

echo "[*] Updating Go tools..."
go install -u github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -u github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -u github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -u github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -u github.com/projectdiscovery/katana/cmd/katana@latest
go install -u github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -u github.com/tomnomnom/waybackurls@latest
go install -u github.com/tomnomnom/gau@latest
go install -u github.com/tomnomnom/anew@latest
go install -u github.com/tomnomnom/qsreplace@latest
go install -u github.com/tomnomnom/gf@latest
go install -u github.com/lc/gau/v2/cmd/gau@latest
go install -u github.com/eth0izzle/sl0t/jsluice/cmd/jsluice@latest

echo "[*] Updating nuclei templates..."
nuclei -update

echo "[*] Updating wordlists..."
# If using SecLists from git
cd /usr/share/seclists
git pull

echo "[*] Update complete"
```

---

## Final Rule

> **Autopilot replaces grunt work. It finds leads. You find bugs. Never submit autopilot output as findings — every alert needs human verification.**

The best autopilot setup runs while you sleep and hands you a prioritized list of leads when you wake up. Your job is to triage those leads into confirmed bugs.
