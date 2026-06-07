---
name: recon-arsenal
description: Reconnaissance tool arsenal reference. Quick commands, output parsing, wordlists, and configuration for subdomain enumeration, DNS resolution, HTTP probing, URL crawling, directory fuzzing, and JS analysis tools.
---

# Recon Arsenal

## Subdomain Enumeration

### subfinder
```
$ subfinder -d target.com -o passive.txt
$ subfinder -d target.com -all -recursive -o deep.txt
$ subfinder -d target.com -nW -o no-wildcard.txt
```

### assetfinder
```
$ assetfinder --subs-only target.com > assetfinder.txt
```

### findomain
```
$ findomain -t target.com -o
$ findomain -t target.com -r -o   # recursive
```

### amass
```
$ amass enum -passive -d target.com -o amass.txt
$ amass intel -whois -d target.com -o whois.txt
```

### puredns (active brute-force)
```
$ puredns bruteforce wordlist.txt target.com -r resolvers.txt -o puredns.txt
$ puredns resolve subdomains.txt -r resolvers.txt -o resolved.txt
```

### dnsx (resolution)
```
$ dnsx -l subdomains.txt -o resolved.txt
$ dnsx -l subdomains.txt -a -aaaa -cname -o dns-records.txt
$ dnsx -l subdomains.txt -wildcard -o wildcard-detected.txt
```

### DNSGEN (permutations)
```
$ cat subdomains.txt | dnsgen - | dnsx -r resolvers.txt -o permutations.txt
```

### ShuffleDNS
```
$ shuffledns -d target.com -w wordlist.txt -r resolvers.txt -o shuffled.txt
```

---

## Certificate Transparency

### crt.sh
```
$ curl -s 'https://crt.sh/?q=%25.target.com&output=json' | jq -r '.[].name_value' | sort -u
$ curl -s 'https://crt.sh/?q=%25.target.com&output=json' | jq -r '.[].name_value' | sed 's/\*\.//' | sort -u
```

### Certspotter
```
$ curl -s 'https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names' | jq -r '.[].dns_names[]' | sort -u
```

### Certstream
```
$ certstream --domain target.com --json > certstream.log
```

---

## HTTP Probing

### httpx
```
$ httpx -l subdomains.txt -o live.txt
$ httpx -l subdomains.txt -title -tech-detect -status-code -content-length -o detailed.txt
$ httpx -l subdomains.txt -favicon -o favicon-hashes.txt
$ httpx -l subdomains.txt -ports 80,443,8080,8443 -o multi-port.txt
$ httpx -l subdomains.txt -vhost -o vhosts.txt
$ httpx -l subdomains.txt -csp-probe -o csp-hosts.txt
$ httpx -l subdomains.txt -response-length -o resp-length.txt
```

### httprobe
```
$ cat subdomains.txt | httprobe -c 50 -o live.txt
$ cat subdomains.txt | httprobe -c 50 -p 8080:8080 -p 8443:8443 -o multi-port.txt
```

---

## URL Crawling

### gau
```
$ cat live-hosts.txt | gau > gau-urls.txt
$ cat live-hosts.txt | gau --blacklist png,jpg,gif,svg,css,woff,woff2 -o filtered-urls.txt
$ gau --subs target.com > gau-all.txt
```

### waybackurls
```
$ cat live-hosts.txt | waybackurls > wayback-urls.txt
$ waybackurls target.com > wayback-all.txt
```

### gauplus
```
$ cat live-hosts.txt | gauplus -o gauplus-urls.txt
$ gauplus -t 5 -random-agent -o gauplus.txt
```

### katana
```
$ katana -list live-hosts.txt -o katana-urls.txt
$ katana -list live-hosts.txt -d 3 -jc -kf -o deep-crawl.txt
$ katana -list live-hosts.txt -H "Header: value" -o with-headers.txt
```

### gospider
```
$ gospider -S live-hosts.txt -o spider-output/
$ gospider -S live-hosts.txt -d 3 -c 10 -t 20 -o deep-spider/
```

### hakrawler
```
$ cat live-hosts.txt | hakrawler -d 3 -o hakrawler.txt
$ cat live-hosts.txt | hakrawler -d 3 -subs -o hakrawler-subs.txt
```

### Paramspider
```
$ python3 paramspider.py --domain target.com --output params.txt
$ python3 paramspider.py --domain target.com --exclude jpg,png,gif --level high
```

---

## Directory & File Fuzzing

### ffuf
```
# Directory discovery
$ ffuf -u https://target.com/FUZZ -w wordlist.txt -o dirs.json
$ ffuf -u https://target.com/FUZZ -w wordlist.txt -c -t 50 -o parallel.json
$ ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,204,301,302,307,401,403 -o filtered.json

# File discovery
$ ffuf -u https://target.com/FUZZ -w wordlist.txt -e .php,.asp,.aspx,.jsp,.do,.action.json

# Parameter fuzzing
$ ffuf -u 'https://target.com/api/endpoint?key=val&FUZZ=test' -w params.txt -fw 0
$ ffuf -u 'https://target.com/api/endpoint?FUZZ=test' -w params.txt -fc 400

# VHOST discovery
$ ffuf -u https://target.com -H "Host: FUZZ.target.com" -w vhosts.txt -fc 301,302,404

# Recursive
$ ffuf -u https://target.com/FUZZ -w wordlist.txt -recursion -recursion-depth 3

# POST data fuzzing
$ ffuf -u https://target.com/login -X POST -H "Content-Type: application/json" -d '{"username":"admin","password":"FUZZ"}' -w passwords.txt -mc 200,302
```

### dirsearch
```
$ python3 dirsearch.py -u https://target.com -w wordlist.txt
$ python3 dirsearch.py -u https://target.com -e php,asp,aspx,txt,json,xml
$ python3 dirsearch.py -u https://target.com -t 50 --deep-recursive
```

### gobuster
```
$ gobuster dir -u https://target.com -w wordlist.txt
$ gobuster dir -u https://target.com -w wordlist.txt -x php,txt,html
$ gobuster vhost -u https://target.com -w vhosts.txt
```

---

## JavaScript Analysis

### LinkFinder
```
$ python3 LinkFinder.py -i https://target.com/bundle.js -o report.html
$ python3 LinkFinder.py -i https://target.com/bundle.js -d cli
$ python3 LinkFinder.py -d urls.txt -o cli
```

### SecretFinder
```
$ python3 SecretFinder.py -i https://target.com/bundle.js -o secrets.txt
$ python3 SecretFinder.py -i app.js -g 'jwt,api,key,secret,token' -o custom.txt
```

### JSParser
```
$ python3 JSParser.py -u https://target.com -c session_cookie
```

### JS-Scan
```
$ python3 js-scanner.py -f urls.txt -o endpoints.txt
```

### custom grep patterns
```
# API endpoints
$ grep -oP '["'\''](https?://[^"'\'']*api[^"'\'']*)["'\'']' bundle.js | sort -u

# API keys and tokens
$ grep -oP '["'\''](?:api[_-]?key|api[_-]?secret|access[_-]?token|secret[_-]?key)[^:]*:\s*["'\''][^"'\'']+["'\'']' *.js | sort -u

# JWTs
$ grep -oP 'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+' *.js

# Cloud URLs
$ grep -oP '(?:s3|s3.amazonaws|storage.cloud.google|blob.core.windows)[^"'\'']*' *.js

# Internal /admin paths
$ grep -oP '["'\''](/[a-zA-Z0-9_/-]*admin[a-zA-Z0-9_/-]*)["'\'']' bundle.js | sort -u

# GraphQL endpoints
$ grep -oP '["'\''](https?://[^"'\'']*graphql[^"'\'']*)["'\'']' *.js | sort -u
```

---

## Technology Fingerprinting

### httpx (tech detection)
```
$ httpx -l live.txt -tech-detect -o tech-stack.txt
$ httpx -l live.txt -tech-detect -json -o tech-stack.json
```

### whatweb
```
$ whatweb -i live.txt --log-verbose=whatweb.log
$ whatweb https://target.com --aggression 3
```

### wappalyzer CLI
```
$ wappalyzer-cli batch live.txt
```

### wafw00f
```
$ wafw00f -i live.txt -o waf-results.txt
$ wafw00f https://target.com -a    # aggressive
```

### nuclei (tech detection templates)
```
$ nuclei -l live.txt -t ~/nuclei-templates/technologies/ -o tech-nuclei.txt
```

---

## Port Scanning

### naabu
```
$ naabu -l resolved.txt -top-ports 100 -o ports.txt
$ naabu -l resolved.txt -p 80,443,8080,8443,9090,3000 -o custom-ports.txt
$ naabu -host target.com -p - -rate 1000 -o full-portscan.txt
```

### nmap
```
$ nmap -sT -sV -T4 -iL live.txt -oN nmap-scan.txt
$ nmap -sV --script=http-title,http-server-header -iL targets.txt
$ nmap -p 80,443 -Pn --script=http-enum -iL live.txt
```

---

## Wordlists

### Directory & File Fuzzing
```
Security: 
  /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
  /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt
  /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-files.txt
  /usr/share/wordlists/SecLists/Discovery/Web-Content/api-endpoints.txt

Assetnote:
  ~/wordlists/httparchive_directories_2.3m_2025_01_28.txt
  ~/wordlists/httparchive_parameters_1.9m_2025_01_28.txt
```

### Subdomain Brute Force
```
Security:
  /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
  /usr/share/wordlists/SecLists/Discovery/DNS/deepmagic.com-prefixes-top50000.txt

Assetnote:
  ~/wordlists/best-dns-wordlist-1m.txt
  ~/wordlists/2m-subdomains.txt
```

### Parameters
```
Security:
  /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt

Assetnote:
  ~/wordlists/httparchive_parameters_1.9m.txt
```

---

## One-Liner Pipelines

### Full Recon Pipeline
```bash
# Passive subdomain -> resolve -> live probe -> tech detect
subfinder -d target.com -o /dev/stdout | \
  dnsx -o /dev/stdout | \
  httpx -title -tech-detect -status-code -o target-recon.txt
```

### URL Collection + Endpoint Extraction
```bash
# Gau -> katana -> JS extract -> endpoint grep
cat target.com | gau | sort -u | \
  katana -list /dev/stdin -o /dev/stdout | \
  grep '\.js$' | \
  while read js; do curl -s "$js" | grep -oP '(https?://[a-zA-Z0-9./_-]+)' | sort -u; done
```

### Quick Attack Surface
```bash
subfinder -d $1 -silent | dnsx -silent | httpx -silent -title -tech-detect -status-code
```

### New Asset Alert
```bash
diff <(cat previous.txt) <(subfinder -d target.com -silent | sort -u) | grep '>'
```

### JS Secret Sweep
```bash
cat targets.txt | gau | grep '\.js$' | sort -u | \
  while read url; do
    echo "[$url]"
    curl -s "$url" | grep -oP '(?:api[_-]?key|secret|token|password)[=:]["'"'"'][^"'"'"]+["'"'"']'
  done
```

---

## Configuration Templates

### ~/.config/subfinder/config.yaml
```yaml
resolvers:
  - 1.1.1.1
  - 1.0.0.1
  - 8.8.8.8
  - 8.8.4.4
sources:
  - alienvault
  - certspotter
  - crtsh
  - hackertarget
  - otx
  - securitytrails
  - threatcrowd
  - waybackarchive
  - whoisxmlapi
  - urlscan
```

### resolvers.txt (for puredns/dnsx)
```
1.1.1.1
1.0.0.1
8.8.8.8
8.8.4.4
9.9.9.9
149.112.112.112
```

### ~/.config/httpx/config.yaml
```yaml
threads: 100
timeout: 10
retries: 2
follow-redirects: true
```

---

## Rate Limiting & WAF Bypass

### When hitting rate limits
```
$ ffuf [...] -rate 10       # reduce requests per second
$ httpx [...] -rl 20         # rate limit in httpx
$ katana [...] -rl 30        # rate limit in katana
```

### User-agent rotation
```
$ httpx [...] -random-agent
$ ffuf [...] -H "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
$ katana [...] -H "User-Agent: Mozilla/5.0 [...]"
```

### Proxy rotation
```
$ ffuf [...] -x socks5://localhost:9050    # Tor
$ subfinder [...] -proxy http://proxy:8080
```

---

## Output Parsing Examples

### Extract unique subdomains from JSON
```bash
$ cat crtsh.json | jq -r '.[].name_value' | sort -u
```

### Extract URLs from gf patterns
```bash
$ cat all-urls.txt | gf ssrf
$ cat all-urls.txt | gf idor
$ cat all-urls.txt | gf lfi
$ cat all-urls.txt | gf redirect
$ cat all-urls.txt | gf rce
$ cat all-urls.txt | gf sqli
$ cat all-urls.txt | gf ssti
$ cat all-urls.txt | gf xss
```

### Sort by response size (find anomalies)
```bash
$ cat httpx-output.txt | sort -t, -k4 -n
```

### Extract unique HTTP response headers
```bash
$ cat live.txt | while read url; do curl -sI "$url" | grep -i '^x-\|^server:\|^set-cookie:'; done | sort -u
```
