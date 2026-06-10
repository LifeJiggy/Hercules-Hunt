---
name: windows-recon-workflow
description: Windows-native recon workflow for Hercules-Hunt. PowerShell replacements for Linux tools, curl.exe mastery, Burp Suite on Windows, ffuf/nuclei/httpx setup, JS bundle analysis, batch scripting, and WSL integration. Use when running recon on Windows or when asked about Windows-specific recon.
---

# Windows Recon Workflow

## Purpose

This file maps every Linux/macOS recon command to its Windows-native equivalent. PowerShell, curl.exe, and WSL are first-class here. Assumptions: Windows 10/11, PowerShell 5.1+, optional WSL2.

---

## Tool Availability Matrix

| Linux Tool | Windows Tool | Method |
|---|---|---|
| subfinder | subfinder.exe | Native / Scoop / WSL |
| httpx | httpx.exe | Native / WSL |
| katana | katana.exe | Native / WSL |
| ffuf | ffuf.exe | Native / WSL / Go |
| gau | gau.exe | Native via Go / WSL |
| nuclei | nuclei.exe | Native / WSL |
| dnsx | dnsx.exe | Native / WSL |
| waybackurls | not on Windows | Use gau (has Wayback source) |
| puredns | not on Windows | Use shuffledns.exe or dnsx |
| amass | not on Windows well | Use subfinder + dnsx |
| gauplus | gauplus.exe | Native / Go built |
| wappalyzer | wappalyzer-cli .exe | Node.js / npx |
| whatweb | not straightforward | Use httpx -tech-detect |

---

## Environment Setup

### PowerShell Profile

Add to `$PROFILE`:

```powershell
$_env:PATH += ";C:\tools\recon"
$env:PATH += ";C:\Users\ADMIN\go\bin"

# Aliases for common tools
Set-Alias subfinder subfinder.exe
Set-Alias httpx httpx.exe
Set-Alias katana katana.exe
Set-Alias ffuf ffuf.exe

# Hash tools for spoofing
Set-Alias nmap nmap.exe
Set-Alias burp "C:\tools\burp\burpsuite_community.exe"
```

### Verify Tool Installation

```powershell
function Test-ReconTools {
  $tools = @("subfinder", "httpx", "katana", "ffuf", "nuclei", "dnsx", "gau")
  foreach ($t in $tools) {
    $path = Get-Command $t -ErrorAction SilentlyContinue
    if ($path) {
      Write-Host "[OK] $t -> $($path.Source)"
    } else {
      Write-Host "[MISSING] $t" -ForegroundColor Red
    }
  }
}
Test-ReconTools
```

### Install via Scoop (Recommended)

```powershell
scoop install main/subfinder
scoop install main/httpx
scoop install main/nuclei
scoop install main/katana
scoop install main/ffuf
scoop install main/dnsx
scoop install main/naabu
```

---

## curl.exe Mastery on Windows

curl.exe is preinstalled on Windows 10+. Key patterns:

### Basic Requests

```powershell
# GET
curl.exe -s https://target.com/api/users

# POST with JSON body
curl.exe -s -X POST https://target.com/api/login `
  -H "Content-Type: application/json" `
  -d '{"username":"test","password":"test"}'

# With cookies
curl.exe -s -b "session=abc123" https://target.com/api/me

# Save response to file
curl.exe -s https://target.com/api/users | Out-File response.json
```

### Headers Only

```powershell
# Get headers
curl.exe -sI https://target.com

# Specific header
curl.exe -sI https://target.com | Select-String "Set-Cookie|X-Frame-Options|CORS"
```

### Follow Redirects

```powershell
# Follow redirects, show final URL
curl.exe -sL -w "Final URL: %{url_effective}\n" https://target.com

# Show redirect chain
curl.exe -sL -w "Redirects: %{num_redirects}\n" https://target.com
```

### Burp Integration

```powershell
# Route through Burp proxy
$env:HTTPS_PROXY = "http://127.0.0.1:8080"
$env:HTTP_PROXY = "http://127.0.0.1:8080"
curl.exe -s -k https://target.com/api/users

# Burp CA cert (install first, then use -k)
curl.exe -s -k --cacert "C:\tools\burp\burpca.cer" https://target.com
```

### Timeout and Retry

```powershell
# Timeout (5 seconds)
curl.exe -s --max-time 5 https://target.com

# Retry on failure
1..3 | ForEach-Object { curl.exe -s https://target.com }
```

---

## Recon Tool Commands (Windows)

### subfinder

```powershell
# Basic passive subdomain enum
subfinder -d target.com -o subdomains.txt

# All sources, silent
subfinder -d target.com -all -silent -o subdomains.txt

# With specific sources
subfinder -d target.com -source alienvault,crt.sh,otx -o subs.txt

# From list
subfinder -dL domains.txt -o all-subs.txt
```

### dnsx

```powershell
# Resolve subdomains
dnsx -l subdomains.txt -o resolved.txt

# Resolve with A records
dnsx -l subdomains.txt -a -resp -o resolved.txt

# Resolve with CNAMEs
dnsx -l subdomains.txt -cname -resp -o cnames.txt

# Wildcard detection
dnsx -l subdomains.txt -wildcard -o wildcards.txt

# For each domain, output: domain [status] [ip] [cname]
```

### httpx

```powershell
# Basic probe
httpx -l hosts.txt -o live.txt

# Detailed probe
httpx -l hosts.txt -title -tech-detect -status-code -content-length -o detailed.tsv

# JSON output for parsing
httpx -l hosts.txt -json -o httpx.json

# With follow redirects and custom headers
httpx -l hosts.txt -follow-redirects -H "X-Custom: value" -o live.txt

# Specify ports
httpx -l hosts.txt -ports 80,443,8080,8443 -o live.txt
```

### katana

```powershell
# Basic crawl
katana -u https://target.com -o urls.txt

# From list, depth 3, with JS parsing
katana -u https://target.com -d 3 -jc -o urls.txt

# From file list
katana -list urls.txt -d 2 -o crawled-urls.txt

# With headless browser (chromium)
katana -u https://target.com -headless -d 4 -o urls.txt

# Disable headless (faster, no JS rendering)
katana -u https://target.com -no-headless -d 3 -o urls.txt
```

### nuclei

```powershell
# Basic scan
nuclei -u https://target.com -o nuclei.txt

# From list
nuclei -l hosts.txt -o nuclei.txt

# Templates directory
nuclei -l hosts.txt -t ~/nuclei-templates/ -o nuclei.txt

# Severity filter
nuclei -l hosts.txt -severity critical,high -o nuclei-critical.txt

# JSON output
nuclei -l hosts.txt -json -o nuclei.json

# Progress and concurrency
nuclei -l hosts.txt -c 50 -timeout 10 -o nuclei.txt
```

### ffuf

```powershell
# Directory fuzzing
ffuf -u https://target.com/FUZZ -w C:\wordlists\common.txt -o dirs.json

# With match codes
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,204,301,302,401,403 -o dirs.json

# POST fuzzing
ffuf -u https://target.com/api/endpoint -X POST -H "Content-Type: application/json" -d '{"key":"FUZZ"}' -w wordlist.txt

# VHOST fuzzing
ffuf -u https://target.com -H "Host: FUZZ.target.com" -w vhosts.txt -fc 301,302,404

# Parameter fuzzing
ffuf -u "https://target.com/api?id=1&FUZZ=test" -w params.txt -fc 400

# Rate limiting (avoid WAF blocks)
ffuf -u https://target.com/FUZZ -w wordlist.txt -rate 15 -o dirs.json
```

### naabu

```powershell
# Quick scan (top 100 ports)
naabu -l hosts.txt -top-ports 100 -o ports.txt

# Full port scan
naabu -l hosts.txt -p - -o all-ports.txt

# Specific ports
naabu -l hosts.txt -p 80,443,8080,8443,9090,3000,5000 -o ports.txt

# Rate limiting
naabu -l hosts.txt -top-ports 100 -rate 100 -o ports.txt
```

### gau

```powershell
# URL gathering from Wayback
gau target.com -o wayback.txt

# From list with filters
gau -i live.txt -o all-gau-urls.txt

# From list, exclude static assets
gau -i live.txt -blacklist png,jpg,gif,css,js,woff,svg -o gau-filtered.txt

# With subs
gau --subs target.com -o gau-subs.txt

# With threads
gau -i live.txt -t 20 -o gau-urls.txt
```

---

## PowerShell Equivalents

### Where Linux uses pipes:

```bash
# Linux
cat subs.txt | sort -u > unique-subs.txt
grep "api" urls.txt | sort -u
```

```powershell
# Windows PowerShell (no cat)
Get-Content subs.txt | Sort-Object -Unique | Set-Content unique-subs.txt
Select-String -Path urls.txt -Pattern "api" | Sort-Object -Unique | Set-Content api-urls.txt
```

### jq Alternatives on Windows

```powershell
# Convert JSON to CSV
(Get-Content httpx.json | ConvertFrom-Json | Select-Object url, status, title) | ConvertTo-Csv > httpx.csv

# Extract specific field from JSON
(Get-Content httpx.json | ConvertFrom-Json).url | Sort-Object -Unique | Set-Content live.txt

# Using jq via WSL (recommended for complex JSON)
wsl jq -r '.url' httpx.json
```

### grep Alternatives

```powershell
# grep in PowerShell
Select-String -Path file.txt -Pattern "pattern"

# With regex
Select-String -Path file.txt -Pattern "api/v[0-9]+"

# Output just matches, not lines
(Select-String -Path file.txt -Pattern "api" -AllMatches).Matches.Value

# Case-insensitive
Select-String -Path file.txt -Pattern "api" -CaseSensitive:$false
```

### awk Alternatives

```powershell
# First column
(Get-Content file.txt) | ForEach-Object { ($_ -split '\t')[0] }

# Filter by column
Get-Content file.txt | Where-Object { ($_ -split '\t')[2] -eq "200" }

# Print multiple columns
Get-Content file.txt | ForEach-Object {
  $cols = $_ -split '\t'
  Write-Output "$($cols[0])\t$($cols[2])"
}
```

### sed Alternatives

```powershell
# Replace in file
(Get-Content file.txt) -replace 'old', 'new' | Set-Content file.txt

# Remove lines matching pattern
Get-Content file.txt | Where-Object { $_ -notmatch 'pattern' } | Set-Content file.txt

# Delete first line (header)
(Get-Content file.txt | Select-Object -Skip 1) | Set-Content file.txt
```

---

## WSL Integration

### When to Use WSL vs Native

| Task | Native | WSL |
|---|---|---|
| Run ffuf on large wordlist | OK | Better (faster I/O on LinuxFS) |
| Parse large JSON (jq) | Slow | Better |
| Bash pipelines | Complex in PS | Simple and fast |
| subfinder/dnsx/httpx | Fine | Fine |
| Headless Chrome / Katana | OK | OK |
| Network performance | Good | Slightly better for I/O heavy |

### WSL Recon Pattern

```powershell
# Pass Windows paths to WSL (WSL2 auto-converts)
wsl bash -c "cat /mnt/c/recon/urls.txt | sort -u | httpx -silent"

# Or run entire pipeline in WSL
wsl bash -c "
  subfinder -d target.com -silent | \
  dnsx -silent | \
  httpx -silent -json | \
  jq -r '.url' | \
  sort -u
"
```

### Mixed Native + WSL

```powershell
# Run tool natively, pipe to WSL for processing
$env:WSLENV = "FOO:p"
subfinder -d target.com -silent | wsl jq -r '.host' | sort -u
```

---

## JS Analysis on Windows

### Downloading JS Bundles

```powershell
# Download JS bundle
curl.exe -s https://target.com/static/js/main.abc123.js -o bundle.js

# From file list
Get-Content js-urls.txt | ForEach-Object {
  $name = ($_ -split '/')[-1]
  curl.exe -s $_ -o ".\js\$name"
}

# Download and beautify in one go
python LinkFinder.py -i https://target.com/app.js -d cli
```

### Python Tools on Windows

```powershell
# LinkFinder
python LinkFinder.py -i https://target.com/bundle.js -o endpoints.html

# SecretFinder
python SecretFinder.py -i https://target.com/bundle.js -o secrets.txt

# JSParser (needs bing.py dependency)
python JSParser.py -u https://target.com

# With GitHub-sourced tools
git clone https://github.com/m4ll0k/SecretFinder.git
cd SecretFinder
python secretfinder.py -h
```

### Automated JS Endpoint Extraction

```powershell
# One-liner: extract API patterns from JS
Get-Content js-urls.txt | ForEach-Object {
  $js = $_
  $content = curl.exe -s $js
  $content | Select-String -Pattern "https?://[a-zA-Z0-9._/-]+/api/[a-zA-Z0-9._/-]+" -AllMatches |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique
} | Set-Content js/api-endpoints.txt
```

---

## Burp Suite on Windows

### Starting Burp

```powershell
# Burp Community
& "C:\tools\burp\burpsuite_community.exe"

# Burp Pro
& "C:\tools\burp\burpsuite_pro.exe"

# With custom config
& "C:\tools\burp\burpsuite_community.exe" --project-file=C:\recon\burp-project.burp
```

### Headless Burp (Automation)

```powershell
# Burp Suite Headless for automated scanning
java -jar burpsuite_community.jar --headless -c burp-config.json

# Export findings
java -jar burpsuite_community.jar --headless --project-file=project.burp --export-report=html
```

### Burp Extension Directory

```powershell
# Set extension folder
$burpExtDir = "C:\tools\burp\extensions"

# Install extensions
Copy-Item *.py $burpExtDir

# Common extensions
# - Authorize.py (auth testing)
# - TurboIntruder.jar (race conditions)
```

---

## Batch Scripting for Recon

### Daily Recon Batch File

```batch
@echo off
setlocal enabledelayedexpansion

set TARGET=%1
set DATE=%date:~10,4%%date:~4,2%%date:~7,2%

echo [*] Starting recon for %TARGET%

:: Passive subdomain enum
echo [+] Running subfinder...
subfinder -d %TARGET% -silent -o subs-%DATE%.txt

:: Resolve
echo [+] Resolving subdomains...
dnsx -l subs-%DATE%.txt -a -resp -o resolved-%DATE%.txt

:: Live probe
echo [+] Probing live hosts...
httpx -l resolved-%DATE%.txt -title -tech-detect -status-code -o live-%DATE%.tsv

:: Wayback + GAU
echo [+] Collecting URLs...
echo %TARGET% | gau -o gau-%DATE%.txt
echo %TARGET% | waybackurls > wayback-%DATE%.txt 2>nul || echo "waybackurls not available"

:: Merge URLs
echo [+] Merging URLs...
type gau-%DATE%.txt wayback-%DATE%.txt | sort -u > urls-%DATE%.txt

:: Nuclei scan
echo [+] Running nuclei...
nuclei -u https://%TARGET% -severity critical,high -o nuclei-%DATE%.txt

echo [*] Recon complete. Output: recon-%TARGET%-%DATE%\
mkdir recon-%TARGET%-%DATE%
move *.txt recon-%TARGET%-%DATE%\
move *.tsv recon-%TARGET%-%DATE%\
```

### PowerAutoRecon Script

```powershell
<#
.SYNOPSIS
Automated recon workflow for Windows
#>
param(
  [Parameter(Mandatory=$true)]
  [string]$Domain
)

$date = Get-Date -Format "yyyyMMdd"
$outDir = "recon-$Domain-$date"

New-Item -ItemType Directory -Path $outDir -Force | Out-Null
Set-Location $outDir

# Phase 1: Subdomains
Write-Host "[1/6] Subdomain enumeration..." -ForegroundColor Cyan
subfinder -d $Domain -silent -o passive.txt
Get-Content passive.txt | Sort-Object -Unique | Set-Content passive.txt

# Phase 2: DNS resolution
Write-Host "[2/6] DNS resolution..." -ForegroundColor Cyan
dnsx -l passive.txt -a -cname -resp -o resolved.txt

# Phase 3: HTTP probing
Write-Host "[3/6] Live host discovery..." -ForegroundColor Cyan
httpx -l resolved.txt -title -tech-detect -status-code -o live-detailed.tsv

# Phase 4: URL collection
Write-Host "[4/6] URL collection..." -ForegroundColor Cyan
Get-Content passive.txt | ForEach-Object { $_ } | gau -o gau.txt 2>$null
gau $Domain -o gau-root.txt 2>$null
Get-Content gau.txt, gau-root.txt | Sort-Object -Unique | Set-Content urls.txt

# Phase 5: Nuclei scan
Write-Host "[5/6] Running nuclei..." -ForegroundColor Cyan
nuclei -u "https://$Domain" -severity critical,high -o nuclei-critical.txt

# Phase 6: Summary
Write-Host "[6/6] Generating summary..." -ForegroundColor Cyan
Write-Host "`n=== RECON SUMMARY ===" -ForegroundColor Green
Write-Host "Subdomains: $(Get-Content passive.txt | Measure-Object | Select-Object -ExpandProperty Count)"
Write-Host "Live hosts: $(Get-Content live-detailed.tsv | Measure-Object | Select-Object -ExpandProperty Count)"
Write-Host "URLs collected: $(Get-Content urls.txt | Measure-Object | Select-Object -ExpandProperty Count)"
Write-Host "Critical/High findings: $(Get-Content nuclei-critical.txt | Measure-Object | Select-Object -ExpandProperty Count)"

Write-Host "`nOutput: $outDir"
```

### Run the Script

```powershell
# Save as recon.ps1
.\recon.ps1 -Domain target.com

# With execution policy bypass
powershell -ExecutionPolicy Bypass -File recon.ps1 -Domain target.com
```

---

## WSL Recon Integration

### Full WSL Pipeline

```powershell
# Run everything in WSL
wsl bash -c '
  TARGET="target.com"
  DATE=$(date +%Y%m%d)
  mkdir -p ~/recon/$TARGET-$DATE

  subfinder -d $TARGET -silent > ~/recon/$TARGET-$DATE/subs.txt
  dnsx -l ~/recon/$TARGET-$DATE/subs.txt -a > ~/recon/$TARGET-$DATE/resolved.txt
  httpx -l ~/recon/$TARGET-$DATE/resolved.txt -title -tech-detect > ~/recon/$TARGET-$DATE/live.txt
  gau $TARGET > ~/recon/$TARGET-$DATE/urls.txt
  nuclei -l ~/recon/$TARGET-$DATE/live.txt -severity critical,high > ~/recon/$TARGET-$DATE/nuclei.txt

  echo "Recon complete: ~/recon/$TARGET-$DATE"
'

# Access results from Windows
wsl bash -c "cat ~/recon/target.com-*/live.txt" | clip
```

### Access WSL Files from Windows

```powershell
# WSL2 files are at \\wsl.localhost\Ubuntu\home\username\
# Or use explorer integration
explorer.exe \\wsl.localhost\Ubuntu\home\$env:USERNAME\recon

# Or from WSL, access Windows
# /mnt/c/Users/ADMIN/recon
```

---

## Common Windows Gotchas

### Path Separators

```powershell
# WRONG: single backslash is escape character
$path = "C:\tools\recon\wordlists\common.txt"

# RIGHT: verbatim string with @ or escape
$path = "C:\tools\recon\wordlists\common.txt"
$path = 'C:\tools\recon\wordlists\common.txt'
$path = "C:\\tools\\recon\\wordlists\\common.txt"
```

### Encoding Issues

```powershell
# Save output as UTF-8 without BOM
$output | Out-File -FilePath output.txt -Encoding utf8NoBOM

# Or use Set-Content which uses UTF-8 no BOM by default in PS 6+
Set-Content output.txt $output
```

### Output Capture

```powershell
# Capture tool output
$result = subfinder -d target.com -silent

# Capture with error stream
$result = subfinder -d target.com 2>&1

# Append to file
subfinder -d target.com -silent | Add-Content subs.txt
```

### ForEach-Object vs ForEach

```powershell
# ForEach-Object (pipeline, memory efficient)
Get-Content urls.txt | ForEach-Object { curl.exe -s $_ }

# foreach (standard PowerShell loop)
foreach ($url in Get-Content urls.txt) { curl.exe -s $url }
```

---

## Wordlists on Windows

### Default Locations

```
SecLists:
  C:\tools\SecLists\Discovery\Web-Content\
  C:\tools\SecLists\Discovery\DNS\

Custom wordlists:
  C:\tools\wordlists\

WSL wordlists:
  /usr/share/wordlists/SecLists/
```

### Using Wordlists from WSL

```powershell
# Access Linux wordlists from Windows
$linuxWordlist = "\\wsl.localhost\Ubuntu\usr\share\wordlists\SecLists\Discovery\Web-Content\common.txt"

ffuf -u https://target.com/FUZZ -w $linuxWordlist

# Or run ffuf in WSL
wsl ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
```

---

## Daily Recon Workflow (Windows)

```powershell
# morning-recon.ps1
param([string]$Domain)

# 1. Create output directory
$today = Get-Date -Format "yyyy-MM-dd"
$outDir = "recon\$Domain\$today"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

# 2. Recon script (use PowerAutoRecon.ps1 above)
.\PowerAutoRecon.ps1 -Domain $Domain | Tee-Object -FilePath "$outDir\session.log"

# 3. Compare with previous day
if (Test-Path "recon\$Domain\previous.txt") {
  $new = Compare-Object -ReferenceObject (Get-Content "recon\$Domain\previous.txt") -DifferenceObject (Get-Content "$outDir\subdomains\all.txt") | Where-Object SideIndicator -eq "=>"
  $new | ForEach-Object { $_.InputObject } | Set-Content "$outDir\new-assets.txt"
  Write-Host "New assets: $(($new | Measure-Object).Count)"
}

# 4. Update previous
Copy-Item "$outDir\subdomains\all.txt" "recon\$Domain\previous.txt"

# 5. Notify (optional)
if (Test-Path "$outDir\new-assets.txt" -PathType Leaf) {
  $newCount = (Get-Content "$outDir\new-assets.txt" | Measure-Object).Count
  Write-Host "!! $newCount new assets found for $Domain !!" -ForegroundColor Yellow
}
```

---

## Key Principles for Windows Recon

1. **Prefer native tools when available** — subfinder.exe, httpx.exe, ffuf.exe all work natively
2. **Fall back to WSL for complex pipelines** — jq, awk, grep are simpler in WSL
3. **curl.exe not curl** — Windows curl is curl.exe (different from PowerShell alias in PS 6+)
4. **Test WSL first** — if you can't install a tool natively, check if it's in WSL
5. **Scoop or Chocolatey** — easiest way to install Go-based recon tools on Windows
6. **PowerShell aliases conflict** — `curl` may be `Invoke-WebRequest` in PS; use `curl.exe`
7. **Encoding matters** — use UTF-8 without BOM for tool compatibility
8. **Performance: native > WSL for network** but **WSL > native for heavy text processing**
