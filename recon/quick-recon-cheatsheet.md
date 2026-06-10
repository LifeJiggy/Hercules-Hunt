---
name: recon-cheatsheet
description: One-page quick reference for Hercules-Hunt recon. Essential commands for subdomain enum, live host discovery, URL crawling, JS analysis, NUCLEI scanning, scope validation, and WAF bypass. Use as a memory aid during hunting sessions or when starting recon on a new target.
---

# Recon Quick Cheatsheet

## One-Liners

```bash
# Full recon pipeline (passive)
subfinder -d target.com -silent | dnsx -silent | httpx -silent -title -tech-detect

# Quick attack surface
subfinder -d target.com | sort -u | dnsx -silent -a | httpx -silent

# URLs from all sources
gau target.com | sort -u > urls.txt
echo "target.com" | waybackurls >> urls.txt
katana -u https://target.com -d 2 -silent >> urls.txt

# Parameter extraction
cat urls.txt | grep '\?' | unfurl -k unique | sort -u > params.txt

# Nuclei high+critical only
nuclei -l live.txt -severity critical,high -silent

# Full critical bug recon
cat live.txt | httpx -tech-detect -json | jq -r '.url' | sort -u
```

---

## Subdomain Enumeration

| Tool | Command |
|---|---|
| subfinder | `subfinder -d target.com -o subs.txt` |
| subfinder deep | `subfinder -d target.com -all -o subs-deep.txt` |
| crt.sh | `curl -s 'https://crt.sh/?q=%25.target.com&output=json' \| jq -r '.[].name_value' \| sort -u` |
| dnsx resolve | `dnsx -l subs.txt -a -resp -o resolved.txt` |
| dnsx brute | `dnsx -d target.com -w wordlist.txt` |
| permutations | `cat subs.txt \| dnsgen \| dnsx -o permutations.txt` |

---

## Live Host Discovery

| Tool | Command |
|---|---|
| httpx basic | `httpx -l subs.txt -o live.txt` |
| httpx detailed | `httpx -l subs.txt -title -tech-detect -status-code -o detailed.tsv` |
| httpx JSON | `httpx -l subs.txt -json -o httpx.json` |
| naabu quick | `naabu -l subs.txt -top-ports 100 -o ports.txt` |
| naabu full | `naabu -l subs.txt -p- -rate 100` |

---

## URL Collection

| Tool | Command |
|---|---|
| gau | `gau target.com \| sort -u > urls.txt` |
| gauplus | `gauplus -t 10 -random-agent target.com > urls.txt` |
| waybackurls | `echo "target.com" \| waybackurls > wayback.txt` |
| katana | `katana -u https://target.com -d 3 -jc -o katana.txt` |
| gospider | `gospider -S live.txt -d 2 -o spider-out/` |
| hakrawler | `cat live.txt \| hakrawler -d 3 > hakrawler.txt` |

---

## JavaScript Analysis

| Task | Command |
|---|---|
| Extract JS URLs | `katana -list live.txt -jc \| grep '\.js$' \| sort -u > js/urls.txt` |
| LinkFinder | `python3 LinkFinder.py -i https://target.com/app.js -d cli` |
| SecretFinder | `python3 SecretFinder.py -i https://target.com/app.js -o js/secrets.txt` |
| API endpoints in JS | `grep -oP 'https?://[^"]+/api/[^"]+' bundle.js \| sort -u` |
| GraphQL in JS | `grep -oP 'https?://[^"]*graphql[^"]*' bundle.js \| sort -u` |
| JWTs in JS | `grep -oP 'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+' bundle.js` |

---

## Technology Fingerprinting

| Tool | Command |
|---|---|
| httpx tech | `httpx -l live.txt -tech-detect -o tech.txt` |
| httpx JSON tech | `httpx -l live.txt -tech-detect -json \| jq -r '.tech[]?.name'` |
| whatweb | `whatweb -i live.txt --log-verbose=whatweb.log` |
| wafw00f | `wafw00f -i live.txt -o waf.txt` |
| nuclei tech | `nuclei -l live.txt -t technologies/ -o tech-nuclei.txt` |

---

## Directory Fuzzing

| Tool | Command |
|---|---|
| ffuf dirs | `ffuf -u https://target.com/FUZZ -w common.txt -mc 200,301,302,401,403` |
| ffuf files | `ffuf -u https://target.com/FUZZ -w files.txt -e .php,.asp,.aspx,.js,.json` |
| ffuf params | `ffuf -u 'https://target.com/api?id=1&FUZZ=test' -w params.txt -fc 400` |
| ffuf vhost | `ffuf -u https://target.com -H 'Host: FUZZ.target.com' -w vhosts.txt -fc 404` |
| ffuf POST | `ffuf -u https://target.com/login -X POST -d 'user=admin&pass=FUZZ' -w pass.txt -mc 200,302` |

---

## Common Wordlists

| Use | Path (Kali/Linux) |
|---|---|
| Subdomains (small) | `/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt` |
| Subdomains (large) | `/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt` |
| Dirs (common) | `/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt` |
| Dirs (raft-large) | `/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt` |
| Files | `/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-files.txt` |
| API endpoints | `/usr/share/wordlists/SecLists/Discovery/Web-Content/api-endpoints.txt` |
| Params | `/usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt` |
| Directory brute | `~/wordlists/httparchive_directories_2.3m_2025_01_28.txt` |
| Parameter brute | `~/wordlists/httparchive_parameters_1.9m_2025_01_28.txt` |

---

## Parameter Extraction

```bash
# All params (normalized lowercase)
cat urls.txt | grep '\?' | unfurl -k params | tr '[:upper:]' '[:lower:]' | sort -u

# Integer ID params (IDOR hunting)
grep -oP '(?<=[?&])(user|account|order|invoice|document|file|ticket|id|uid|aid|oid|did|pid)[^=]*=\d+' urls.txt

# UUID params
grep -oP '(?<=[?&])(id|userId|accountId|orderId|documentId)[^=]*=[a-f0-9-]{36}' urls.txt

# SSRF-prone params
cat urls.txt | unfurl -k params | grep -iE 'url|uri|redirect|fetch|callback|webhook|proxy|target'

# All URL parameters with frequency
cat urls.txt | grep '\?' | unfurl -k keypair | cut -d= -f1 | sort | uniq -c | sort -rn
```

---

## IDOR Hunting Quick Extraction

```bash
# Find API endpoints with IDs
cat urls.txt | grep -oP '/api/[a-zA-Z0-9/-]+/\d+' | sort -u > idor-api.txt

# Find sequential IDs
cat urls.txt | grep -oP '/[a-zA-Z]*/\d+' | sort -u > idor-seen.txt

# GraphQL IDOR candidates
cat urls.txt | grep -i graphql | sort -u > graphql-idor.txt

# File download endpoints
cat urls.txt | grep -iE 'download|file|document?fileId=|?docId=' | sort -u > file-idor.txt
```

---

## SSRF Hunting Quick Extraction

```bash
# SSRF-prone URL accepting params
cat urls.txt | unfurl -k params | sort -u | grep -iE 'url|uri|redirect|fetch|callback|link|target|proxy'

# Webhook endpoints
cat urls.txt | grep -iE 'webhook|callback|notify|ping|import' | sort -u > ssrf-webhooks.txt

# PDF/doc generation
cat urls.txt | grep -iE 'pdf|generate|export|document|preview|print' | sort -u > ssrf-pdf.txt

# Image processing
cat urls.txt | grep -iE 'image|resize|crop|convert|thumbnail|filter' | sort -u > ssrf-image.txt
```

---

## CORS Quick Check

```bash
# Quick CORS misconfig check
cat urls/api-endpoints.txt | while read url; do
  echo "=== $url ==="
  curl.exe -sI -H "Origin: https://evil.com" "$url" | Select-String "Access-Control"
done

# Check for credentials + wildcard combo
curl.exe -sI -H "Origin: https://evil.com" https://target.com/api/me | grep -iE "access-control.*\*|access-control.*credentials"
```

---

## Nuclei Quick Setup

```bash
# Install latest templates
nuclei -update-templates

# Scan with high/critical only
nuclei -l targets.txt -severity critical,high -o nuclei-critical.txt

# Scan for CVEs
nuclei -l targets.txt -t ~/nuclei-templates/cves/ -o cves.txt

# Scan for exposed configs/secrets
nuclei -l targets.txt -t ~/nuclei-templates/exposures/ -o exposures.txt

# Common tech templates
nuclei -l targets.txt -t ~/nuclei-templates/technologies/ -o tech-nuclei.txt

# With rate limiting (avoid WAF blocks)
nuclei -l targets.txt -rl 30 -c 20 -o nuclei.txt
```

---

## Scope Validation Quick Check

```bash
# Filter subdomains to scope
# (assumes scope.json with domains/wildcards/cidrs)

# Bash
python3 filter-scope.py scope.json subdomains/all.txt > subdomains/in-scope.txt

# Request counts comparison
echo "Raw subdomains: $(wc -l < subdomains/all.txt)"
echo "In scope:       $(wc -l < subdomains/in-scope.txt)"
echo "OOS:            $(wc -l < subdomains/out-of-scope.txt)"
```

---

## Windows Quick Reference

```powershell
# PowerShell aliases for recon
Set-Alias s subfinder.exe
Set-Alias h httpx.exe
Set-Alias k katana.exe
Set-Alias n nuclei.exe
Set-Alias f ffuf.exe
Set-Alias d dnsx.exe

# Win: dnsx
dnsx -l subs.txt -a -cname -resp -o resolved.txt

# Win: httpx
httpx -l resolved.txt -title -tech-detect -status-code -o live.tsv

# Win: nuclei
nuclei -l live.tsv -severity critical,high -o nuclei.txt

# Win: ffuf
ffuf -u https://target.com/FUZZ -w .\wordlists\common.txt -mc 200,301,302,401,403
```

---

## Rate Limiting Flags

| Tool | Flag | Value |
|---|---|---|
| httpx | `-rl` | `50` req/s |
| nuclei | `-rl` | `30` req/s |
| ffuf | `-rate` | `15` req/s |
| katana | `-rl` | `30` req/s |
| naabu | `-rate` | `100` req/s |
| subfinder | `-timeout` | `30` (seconds per source) |

---

## Health Checks

```bash
# Verify all tools work
for t in subfinder dnsx httpx katana ffuf nuclei naabu gau nuclei; do
  if command -v $t &>/dev/null; then
    echo "[OK] $t"
  else
    echo "[FAIL] $t"
  fi
done

# Check nuclei templates
nuclei -list-utilities | head -20
nuclei -template-count

# Check wordlist availability
test -f /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt && echo "OK" || echo "MISSING"
```

---

## Common Filter Patterns

```bash
# Remove common static assets
grep -vE '\.(png|jpg|jpeg|gif|svg|css|woff|woff2|ico|pdf)$' urls.txt > urls-no-static.txt

# API endpoints only
grep -E '/api/v[0-9]+/' urls.txt > api-urls.txt

# Keep only target domain URLs
grep 'target.com' urls.txt | sort -u > urls-target.com.txt

# Parameterized URLs only
grep '\?' urls.txt > urls-with-params.txt

# Remove tracking parameters
sed 's/&utm_[^&]*=\([^&]*\)//g' urls.txt | sed 's/\?utm_[^&]*=[^&]*//g' > urls-clean.txt
```

---

## Bug Class Signal Summary

| Bug Class | Primary Recon Signal | Time to confirm from recon |
|---|---|---|
| IDOR | Numeric IDs in endpoints | 5 min |
| SSRF | URL-accepting parameters | 10 min |
| Auth bypass | 200 on admin panel no-auth | 2 min |
| XSS | Reflective params + sinks in JS | 15 min |
| SQLi | Parameters, version match | 30 min |
| File upload | Upload endpoints in recon | 10 min |
| GraphQL | Introspection enabled | 2 min |
| CORS | ACAO header + credentials | 5 min |
| Mass assignment | API PATCH/PUT + unexpected fields | 10 min |
| Subdomain takeover | CNAME + NXDOMAIN | 15 min |

---

## Recon → Hunt Procedure

```
RECON OUTPUT READY
        |
        v
[1] Scope filter all outputs
        |
        v
[2] Tag each asset by bug class signal (use critical-bug-recon.md)
        |
        v
[3] Verify quick wins:
        - exposed keys (JS secrets)
        - open panels (ffuf admin paths)
        - GraphQL introspection
        - nuclei critical CVEs
        |
        v
[4] TIER 1: IDOR + SSRF + Auth Bypass (highest payoff)  [30-60 min]
        |
        v
[5] TIER 2: XSS + SQLi + File Upload  [30-60 min]
        |
        v
[6] TIER 3: Business logic + Race + API misconfig  [30-60 min]
        |
        v
[7] Validate findings. Kill weak. Write reports. SUBMIT.
```

---

## Key Principles

1. **Passive first — active second.** Don't touch the target until passive is exhausted.
2. **One target, one directory.** Output files per target/asset.
3. **sort -u is the secret weapon.** Dedupe everything.
4. **Tag outputs by bug class** as soon as recon is done — critical-bug-recon has patterns.
5. **Verify scope before every tool run** — probe only in-scope subdomains.
6. **30-minute quick win check** — run the 10 one-liners above before deep testing.
7. **Quality > quantity.** 200 verified live hosts beats 20,000 unresolved DNS records.
