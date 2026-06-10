---
name: recon-output-parser
description: Reconnaissance output parsing and structuring reference. Covers deduplication, normalization, JSON/CSV/text parsing, pipeline chaining, and structured output formats for subfinder, httpx, nuclei, katana, gau, waybackurls, dnsx, naabu, ffuf output. Use when standardizing recon results into the canonical target/ directory structure.
---

# Recon Output Parsing

## Purpose

Raw recon tool output is noisy. This file provides deterministic parsing patterns to:
1. Normalize and deduplicate results
2. Extract structured fields (URLs, parameters, headers, tech stack)
3. Convert between formats (JSON <-> CSV <-> plaintext)
4. Pipe recon output into hunting workflows

---

## Canonical Output Format

All parsed recon data should land in this structure:

```
target/
├── subdomains/
│   ├── passive.txt         # unique subdomains (passive)
│   ├── active.txt          # brute-forced subdomains
│   ├── resolved.txt        # A/AAAA records
│   ├── all.txt             # union of all subdomains
│   └── cname.txt           # CNAME chains
├── hosts/
│   ├── live.txt            # probing results
│   ├── detailed.txt        # with tech, title, status
│   └── ports.txt           # open ports per host
├── urls/
│   ├── all-urls.txt        # merged deduped URLs
│   ├── wayback.txt
│   ├── katana.txt
│   ├── endpoints.txt       # unique API endpoint paths
│   ├── parameters.txt      # unique query parameters
│   └── files.txt           # downloadable file URLs
├── technology/
│   ├── stack.txt
│   ├── cms.txt
│   └── waf.txt
├── js/
│   ├── urls.txt
│   ├── endpoints.txt
│   ├── secrets.txt
│   └── source-maps.txt
├── cves/
│   └── nuclei.csv
└── attack-surface/
    ├── idor-potential.txt
    ├── ssrf-prone.txt
    ├── auth-endpoints.txt
    └── file-upload.txt
```

---

## Tool Output Parsing

### subfinder (JSON -> subdomains)

```bash
# Raw JSON to plaintext subdomains
cat subfinder.json | jq -r '.[].host' | sort -u > subdomains/passive.txt

# With source tagging
cat subfinder.json | jq -r '.[] | "\(.host)\t\(.source)"' | sort -u > subdomains/passive-tagged.txt

# From subfinder-text output (already plain)
cp subfinder.txt subdomains/passive.txt
sort -u subdomains/passive.txt -o subdomains/passive.txt
```

### dnsx (dnsx output format -> resolved)

```bash
# dnsx with -a -aaaa -cname
# Format: host [ip1, ip2] [cname]
awk '{print $1}' dnsx-output.txt | sort -u > subdomains/resolved.txt

# With CNAME extraction
awk '{for(i=1;i<=NF;i++) if($i ~ /^\[/) print $1 "\t" $i}' dnsx-output.txt > subdomains/cname.txt

# Just successful resolutions
grep -v "\[failed\]" dnsx-output.txt | awk '{print $1}' | sort -u > subdomains/resolved.txt
```

### httpx (JSON -> live hosts)

```bash
# httpx -json output
cat httpx.json | jq -r '.url' | sort -u > hosts/live.txt

# With tech stack
cat httpx.json | jq -r '"\(.url)\t\(.tech)\t\(.title)\t\(.status-code)"' | sort -u > hosts/detailed.txt

# Extract just tech stack
cat httpx.json | jq -r '.tech[]?' | sort -u > technology/stack.txt

# Extract status codes
cat httpx.json | jq -r '.status-code' | sort -u > hosts/status-codes.txt
```

### httpx (plaintext -> live hosts)

```bash
# httpx -silent output is already plaintext URLs
cp httpx.txt hosts/live.txt
sort -u hosts/live.txt -o hosts/live.txt
```

### nuclei (JSON -> structured findings)

```bash
# nuclei -json output
cat nuclei.json | jq -r '"\(.template-id)\t\(.template-name)\t\(.severity)\t\(.host)\t\(.matched-at)"' > cves/nuclei.tsv

# Filter critical/high only
cat nuclei.json | jq -r 'select(.severity == "critical" or .severity == "high") | "\(.host)\t\(.template-id)\t\(.template-name)"' > cves/high-critical.txt

# Group by template
cat nuclei.json | jq -r '.template-id' | sort | uniq -c | sort -rn > cves/template-count.txt

# Group by host
cat nuclei.json | jq -r '.host' | sort | uniq -c | sort -rn > cves/host-count.txt
```

### nuclei (plaintext)

```bash
# nuclei -silent output
cp nuclei.txt cves/nuclei.txt

# Tag with severity (if using -severity)
grep -i '\[critical\]' nuclei.txt > cves/critical.txt
grep -i '\[high\]' nuclei.txt > cves/high.txt
grep -i '\[medium\]' nuclei.txt > cves/medium.txt
```

### katana (crawler output)

```bash
# katana output: one URL per line
cp katana.txt urls/katana.txt
sort -u urls/katana.txt -o urls/katana.txt

# Merge with wayback
cat urls/wayback.txt urls/katana.txt | sort -u > urls/all-urls.txt
```

### gau / waybackurls (passive URLs)

```bash
# Both output one URL per line
cat gau.txt | sort -u > urls/gau.txt
cat wayback.txt | sort -u > urls/wayback.txt

# Merge all
cat urls/wayback.txt urls/gau.txt | sort -u > urls/all-urls.txt
```

### ffuf (JSON -> findings)

```bash
# ffuf -of json output
cat ffuf.json | jq -r '.results[] | "\(.url)\t\(.status)\t\(.length)\t\(.words)"' > dirs/ffuf-results.tsv

# Filter by status
cat ffuf.json | jq -r '.results[] | select(.status == 200) | .url' > dirs/200.txt
cat ffuf.json | jq -r '.results[] | select(.status == 401 or .status == 403) | .url' > dirs/auth-required.txt

# Filter by size anomaly (find non-standard)
cat ffuf.json | jq -r '.results[] | select(.length != 0) | "\(.length)\t\(.url)"' | sort -n > dirs/by-size.txt

# Filter by word count (good for API endpoints)
cat ffuf.json | jq -r '.results[] | "\(.words)\t\(.url)"' | sort -n > dirs/by-words.txt
```

### naabu (ports)

```bash
# naabu output format: host:port
sort -u naabu.txt | sort -t: -k1,1 -k2,2n > hosts/ports.txt

# Per host
awk -F: '{print $1}' naabu.txt | sort -u > hosts/all-hosts.txt

# Specific ports
grep ':80$' naabu.txt > hosts/port-80.txt
grep ':443$' naabu.txt > hosts/port-443.txt
grep -E ':(8080|8443|3000|5000|8000|8888)' naabu.txt > hosts/alt-http.txt
```

---

## Deduplication Patterns

### URL Deduplication

```bash
# Remove duplicates, preserve order
awk '!seen[$0]++' urls/all-urls.txt > urls/all-urls-deduped.txt

# Remove query strings for deduplication (keep one per path)
cat urls/all-urls.txt | unfurl -u path | sort -u > urls/unique-paths.txt

# Dedupe with parameter order normalization
cat urls/all-urls.txt | awk -F'?' '{print $1}' | sort -u > urls/unique-bases.txt
```

### Subdomain Deduplication

```bash
# Already done by sort -u
sort -u subdomains/all.txt -o subdomains/all.txt

# Remove wildcards for root-only dedup
grep -v '^\*' subdomains/all.txt | sort -u > subdomains/non-wildcard.txt
```

### Parameter Deduplication

```bash
# Extract unique parameters (normalized to lowercase, sorted)
cat urls/all-urls.txt | grep '\?' | unfurl -k params | tr '[:upper:]' '[:lower:]' | sort -u > urls/unique-params.txt

# With occurrence count
cat urls/all-urls.txt | grep '\?' | unfurl -k params | tr '[:upper:]' '[:lower:]' | sort | uniq -c | sort -rn > urls/param-frequency.txt
```

---

## URL Classification

### API Endpoints

```bash
# API paths
grep -E '\/api\/v[0-9]+\/' urls/all-urls.txt > urls/api.txt
grep -E '\/graphql|\/gql|\/query' urls/all-urls.txt > urls/graphql.txt
grep -E '\.json(\?|$)' urls/all-urls.txt > urls/json-endpoints.txt

# Parameterized endpoints (contain { } or :param)
grep -E '\{[^}]+\}|:[a-zA-Z0-9_]+' urls/all-urls.txt > urls/parameterized.txt
```

### File Endpoints

```bash
# Downloads and file access
grep -iE 'download|file|document|pdf|report|export|import' urls/all-urls.txt > urls/files.txt

# By extension
grep '\.pdf$' urls/all-urls.txt > urls/pdfs.txt
grep -E '\.(zip|tar|gz|rar|7z)$' urls/all-urls.txt > urls/archives.txt
grep -E '\.(doc|docx|xls|xlsx|ppt|pptx)$' urls/all-urls.txt > urls/office.txt
grep -E '\.(png|jpg|jpeg|gif|svg|webp)$' urls/all-urls.txt > urls/images.txt
```

### Auth Endpoints

```bash
grep -iE 'login|oauth|auth|signin|signup|register|reset|forgot|password' urls/all-urls.txt > urls/auth.txt
grep -iE 'token|session|jwt|bearer' urls/all-urls.txt > urls/token-endpoints.txt
```

### Admin/Internal

```bash
grep -iE '\/admin|\/internal|\/dashboard|\/manage|\/console|\/wp-admin' urls/all-urls.txt > urls/admin.txt
grep -iE '\/dev|\/staging|\/test|\/debug|\/_next|\/\.git' urls/all-urls.txt > urls/dev-tools.txt
```

---

## Parameter Analysis

### Extract URL Parameters

```bash
# All parameters (flat)
cat urls/all-urls.txt | grep '\?' | unfurl -k params > urls/all-params-flat.txt

# Unique parameter names
cat urls/all-urls.txt | grep '\?' | unfurl -k params | cut -d= -f1 | sort -u > urls/param-names.txt

# Parameters with values
cat urls/all-urls.txt | grep '\?' | unfurl -k keypair > urls/param-values.txt
```

### ID Parameters (high-value for IDOR)

```bash
# Integer IDs
grep -oP '(?<=\?|&)(user|account|order|invoice|document|file|report|ticket|id|uid|aid|oid|did)[^=]*=\d+' urls/all-urls.txt > urls/id-params-int.txt

# UUIDs
grep -oP '(?<=\?|&)(id|user|account|order|document)[^=]*=[a-f0-9-]{36}' urls/all-urls.txt > urls/id-params-uuid.txt

# Any sequential-looking parameters
grep -oP '(?<=\?|&)[a-zA-Z_]*id[a-zA-Z_]*=\d+' urls/all-urls.txt > urls/id-params-all.txt

# GraphQL-style
grep -oP '"(input|id|userId|accountId)"\s*:\s*"[^"]*"' urls/all-urls.txt > urls/graphql-ids.txt
```

### SSRF-Prone Parameters

```bash
# URL-accepting parameters
cat urls/all-urls.txt | unfurl -k params | grep -iE 'url|uri|redirect|callback|link|fetch|target|webhook|proxy|dest|forward|next|continue|path|file|document' > urls/ssrf-params.txt
```

---

## Tech Stack Extraction

### From httpx

```bash
# httpx -json output
cat httpx.json | jq -r '.tech[]? | .name' | sort -u > technology/stack.txt

# With versions
cat httpx.json | jq -r '.tech[]? | "\(.name) \(.version // "unknown")"' | sort -u > technology/stack-versions.txt

# WAF detection
cat httpx.json | jq -r '.waf // empty' > technology/waf.txt
```

### From nuclei tech templates

```bash
# nuclei -t technologies/ output
cat nuclei-tech.json | jq -r 'select(.template-id | startswith("tech-")) | "\(.host)\t\(.template-id)\t\(.matched-at)"' > technology/nuclei-tech.tsv

# Extract detected technologies
cat nuclei-tech.json | jq -r '.info.name' | sort -u > technology/nuclei-names.txt
```

---

## JS Analysis Output

### JS URL Extraction

```bash
# From katana
grep '\.js$' urls/katana.txt | sort -u > js/urls.txt

# From wayback
grep '\.js$' urls/wayback.txt | sort -u >> js/urls.txt

# From HTML (all pages)
cat urls/all-urls.txt | while read url; do
  curl -s "$url" | grep -oP 'src=["\x27][^"\x27]+\.js[^"\x27]*["\x27]'
done | sed 's/src=["\x27]//' | sed 's/["\x27]$//' | sort -u >> js/urls.txt

# Filter out common CDNs for manual analysis
grep -vE 'cdn|googleapis|bootstrap|jquery|cloudflare' js/urls.txt > js/urls-local.txt
```

### Endpoint Extraction from JS

```bash
# LinkFinder CLI
python3 LinkFinder.py -i js/urls.txt -d cli > js/endpoints-raw.txt

# Or grep for API patterns
cat js/urls.txt | while read url; do
  curl -s "$url" | grep -oP 'https?://[a-zA-Z0-9._/-]+/api/[a-zA-Z0-9._/-]+' | sort -u
done > js/api-endpoints.txt

# GraphQL endpoints in JS
cat js/urls.txt | while read url; do
  curl -s "$url" | grep -oP 'https?://[a-zA-Z0-9._/-]*graphql[a-zA-Z0-9._/-]*' | sort -u
done > js/graphql-endpoints.txt
```

### Secret Extraction from JS

```bash
# SecretFinder
python3 SecretFinder.py -i js/urls.txt -o js/secrets-raw.txt

# Or grep patterns
cat js/urls.txt | while read url; do
  curl -s "$url" | grep -oP '(?:api[_-]?key|api[_-]?secret|access[_-]?key|secret[_-]?key|token|password|aws[_-]?key)[^"'\''[:space:]]*' | head -20
done > js/secrets-grep.txt
```

---

## Format Conversion

### JSON -> Plaintext

```bash
# Any JSON array of strings
jq -r '.[]' file.json > file.txt

# JSON objects to TSV
jq -r '[.field1, .field2, .field3] | @tsv' file.json > file.tsv
```

### Plaintext -> JSON

```bash
# Lines to JSON array
jq -R -s 'split("\n") | map(select(length > 0))' file.txt > file.json

# TSV to JSON
jq -R -s 'split("\n") | map(select(length > 0)) | map(split("\t")) | map({key: .[0], value: .[1]})' file.tsv > file.json
```

### CSV Processing

```bash
# Convert CSV to TSV
sed 's/,/\t/g' file.csv > file.tsv

# Filter CSV column
awk -F, '{print $1}' file.csv > column1.txt

# CSV with headers
tail -n +2 file.csv > file-no-header.csv
```

---

## Pipeline Chaining

### One-liners for common pipelines

```bash
# Subdomain -> resolve -> live -> tech
subfinder -d target.com -silent | \
  dnsx -silent -a -cname | \
  awk '{print $1}' | \
  sort -u | \
  httpx -silent -json | \
  jq -r '"\(.url)\t\(.tech)\t\(.title)\t\(.status-code)"' | \
  sort -u > hosts/full-pipeline.tsv

# URLs -> filter API -> extract params
cat urls/all-urls.txt | \
  grep -E '\/api\/' | \
  unfurl -k params | \
  sort -u > urls/api-params.txt

# Live hosts -> tech stack -> CVE matching
cat hosts/live.txt | \
  httpx -tech-detect -json | \
  jq -r '.tech[]?.name' | \
  sort -u > technology/stack.txt

# Subdomains -> CNAME -> takeover checks
cat subdomains/all.txt | \
  dnsx -cname -resp | \
  awk '{print $1, $NF}' | \
  grep -v 'target\.com' > subdomains/cname-external.txt
```

---

## Quality Checks

### Verify Output Integrity

```bash
# Count lines before/after processing
wc -l raw-subdomains.txt parsed-subdomains.txt

# Check for empty lines
grep -c '^$' processed.txt

# Check for duplicates
sort processed.txt | uniq -d

# Verify JSON validity
jq empty file.json && echo "Valid JSON" || echo "Invalid JSON"

# Sample random entries for manual review
shuf -n 10 parsed-output.txt
```

### Expected Counts

```bash
# Subdomain counts by phase
echo "Passive: $(wc -l < subdomains/passive.txt)"
echo "Active: $(wc -l < subdomains/active.txt)"
echo "Resolved: $(wc -l < subdomains/resolved.txt)"
echo "All: $(wc -l < subdomains/all.txt)"

# URL counts by source
echo "Wayback: $(wc -l < urls/wayback.txt)"
echo "Katana: $(wc -l < urls/katana.txt)"
echo "Merged: $(wc -l < urls/all-urls.txt)"

# Deduplication check
echo "Duplicates removed: $(cat urls/wayback.txt urls/katana.txt | sort | uniq -d | wc -l)"
```

---

## Integration with Hunt Modules

The canonical output files feed directly into hunting:

| Recon Output | Hunt Module | Used For |
|---|---|---|
| `subdomains/all.txt` | st Purpose - validate scope |
| `hosts/live.txt` | All hunters | Target list |
| `hosts/detailed.txt` | P1 priorities | Tech + title triage |
| `technology/stack.txt` | Framework-specific rules | Vuln pattern matching |
| `urls/all-urls.txt` | All hunters | Endpoint enumeration |
| `urls/parameters.txt` | SSRF, IDOR, SQLi | Parameter fuzzing |
| `urls/auth.txt` | Auth bypass hunter | Admin panel hunting |
| `urls/api.txt` | IDOR, GraphQL | API endpoint testing |
| `js/secrets.txt` | JS analysis | Exposed credentials |
| `js/endpoints.txt` | API discovery | Hidden endpoints |
| `cves/nuclei.json` | CVE verification | Exploit targeting |

## Key Principles

1. **Always sort and deduplicate** — sort -u is your best friend
2. **Preserve source metadata** — tag results by tool/phase when possible
3. **Normalize URLs** — lower-case scheme+host, preserve path casing
4. **Don't throw away raw output** — keep original tool output alongside parsed
5. **Verify counts** — if a step reduces file size by >90%, check for over-filtering
6. **Idempotent** — running the same parser twice should produce identical output
7. **Fail loud** — if a JSON file is malformed, print the error and stop
