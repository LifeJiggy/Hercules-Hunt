---
name: recon-scope-validator
description: Reconnaissance scope validation and OOS filtering. Covers wildcard matching, regex scope enforcement, CIDR validation, domain ownership verification, wildcard TLS certificate matching, asset type filtering (cdn, waf, acq), and program policy parsing. Use after broad recon to filter results to in-scope assets before hunting.
---

# Recon Scope Validator

## Purpose

Prevent wasted time hunting out-of-scope assets. Scope validation is a gate between recon and hunting. No finding from an out-of-scope asset goes forward. This file defines: scope parsing, wildcard matching, asset type filtering, regex enforcement, CIDR validation, and automated OOS removal from recon outputs.

---

## Scope Input Formats

A program's scope can appear as:

- **Wildcard domain:** `*.target.com`
- **Exact domain:** `app.target.com`, `target.com`
- **CIDR range:** `203.0.113.0/24`
- **IP:** `198.51.100.42`
- **Asset type qualifiers:** `*.target.com (excluding CDN, WAF)`
- **Acquisition targets:** `*.acq-target.com` (if in-scope)

---

## Scope Format Normalization

Place parsed scope into `scope.json`:

```json
{
  "program": "target.com",
  "domains": ["target.com", "api.target.com", "admin.target.com"],
  "wildcards": ["*.target.com"],
  "cidrs": ["203.0.113.0/24"],
  "ips": ["198.51.100.42"],
  "exclusions": {
    "domains": ["cdn.target.com", "assets.target.com"],
    "types": ["waf", "cdn"],
    "regex": [".*\. staging\.target\.com"]
  },
  "metadata": {
    "platform": "HackerOne",
    "safeHarbor": true
  }
}
```

---

## Domain Matching Rules

### Exact Match

```
Input host:  app.target.com
Scope:       app.target.com
Result:      IN SCOPE
```

### Wildcard Match

```
Input host:  api.target.com
Scope:       *.target.com
Result:      IN SCOPE

Input host:  target.com
Scope:       *.target.com
Result:      OUT OF SCOPE (* wildcard matches subdomains only, not apex)

Input host:  deeply.nested.target.com
Scope:       *.target.com
Result:      IN SCOPE (wildcard matches any depth)
```

### Substring / Suffix Match

```
Input host:  app.target.com
Scope:       target.com   (implicit suffix wildcard)
Result:      IN SCOPE (unless scope rule says exact-only)
```

### Edge Cases

```
Input host:  target.com.evil.com
Scope:       target.com
Result:      OUT OF SCOPE (suffix match without dot boundary)

Input host:  mytarget.com
Scope:       target.com
Result:      OUT OF SCOPE (no dot boundary)

Input host:  target.com.internal
Scope:       target.com
Result:      OUT OF SCOPE
```

---

## Wildcard Validation Regex

Valid wildcard patterns in scope definitions:
- `*.target.com` — single-level wildcard
- `target.*` — suffix wildcard
- `*.*.target.com` — multi-level (treat as separate rules)

**Invalid:** bare `*`, patterns with only wildcards, patterns missing TLD.

---

## Asset Type Filtering

### CDN Identification

CDN assets are often OOS via program policy (even if the domain is in-scope).

```
Identify CDN via:
1. CNAME pointing to: cdn.cloudflare.net, *.cloudfront.net, *.akam.net, *.fastly.net, *.edgekey.net
2. ASN belonging to: Cloudflare (AS13335), Akamai (AS20940), Fastly (AS54113), Amazon (AS16509)
3. Headers: Cf-Cache-Status, X-Cache, X-Served-By
4. IP reverse lookup: *.cdn.cloudflare.net
```

**Filter logic:**
```
if type == "cdn" and program excludes CDN:
  mark OOS
```

### WAF Identification

```
Identify WAF:
1. Headers: X-CDN, X-Cache, X-Served-By, CF-RAY, X-Akamai-Session-Info
2. Response behavior: blocking patterns return 403/503 on probe
3. CNAME: *.cloudflare.com, *.azure.com
```

### Acquisition Assets

Programs may list acquisitions separately. Parse scope for:
```
acquired: ["acq-target.com", "*.acq-target.com"]
```
If a subdomain resolves to `app.acq-target.com`, verify if the acquisition line is active. If OOS, filter.

---

## Scope Validation Pipeline

### Input
```
Recon output: subdomains/all.txt (raw, unfiltered)
Scope config: scope.json
```

### Steps

```
1. Load scope.json
2. For each subdomain in input:
   a. Check exact match against scoped domains
   b. Check wildcard match against wildcard rules
   c. Check CIDR match against CIDRs
   d. Check exclusion regexes
   e. Check exclusion type (cdn, waf)
   f. If no match -> mark OOS
3. Write in-scope to: subdomains/in-scope.txt
4. Write out-of-scope to: subdomains/out-of-scope.txt
5. Write ambiguous to: subdomains/ambiguous.txt (for manual review)
```

---

## Implementation

### PowerShell Scope Filter

```powershell
function Test-InScope {
  param(
    [string]$Hostname,
    [hashtable]$Scope
  )

  $h = $Hostname.Trim().ToLower()

  # Exact domain match
  if ($Scope.Domains -contains $h) {
    return $true
  }

  # Wildcard match
  foreach ($w in $Scope.Wildcards) {
    $pattern = '^' + ($w -replace '\.', '\.' -replace '\*', '[^.]+') + '$'
    if ($h -match $pattern) {
      # Check exclusions
      if ($Scope.Exclusions.Domains -contains $h) {
        return $false
      }
      # Check exclusion regexes
      foreach ($r in $Scope.Exclusions.Regex) {
        if ($h -match $r) {
          return $false
        }
      }
      return $true
    }
  }

  return $false
}

# Run filter
$scope = Get-Content scope.json | ConvertFrom-Json
$inScope = @()
$outOfScope = @()

Get-Content subdomains/all.txt | ForEach-Object {
  if (Test-InScope -Hostname $_ -Scope $scope) {
    $inScope += $_
  } else {
    $outOfScope += $_
  }
}

$inScope | Sort-Object -Unique | Set-Content subdomains/in-scope.txt
$outOfScope | Sort-Object -Unique | Set-Content subdomains/out-of-scope.txt

Write-Host "In scope: $($inScope.Count)"
Write-Host "Out of scope: $($outOfScope.Count)"
```

### Bash Scope Filter

```bash
#!/bin/bash
# filter-scope.sh
# Usage: bash filter-scope.sh scope.json input.txt in-scope.txt out-of-scope.txt

SCOPE_FILE="$1"
INPUT_FILE="$2"
OUT_IN="$3"
OUT_OOS="$4"

# Extract scoped domains and wildcards
DOMAINS=$(jq -r '.domains[]' "$SCOPE_FILE" | tr '\n' '|' | sed 's/|$//')
WILDCARDS=$(jq -r '.wildcards[]' "$SCOPE_FILE")

in_scope=0
oos=0
ambiguous=0

while IFS= read -r hostname; do
  hostname=$(echo "$hostname" | tr '[:upper:]' '[:lower:]' | xargs)
  matched=0

  # Exact match
  for d in $(jq -r '.domains[]' "$SCOPE_FILE"); do
    if [ "$hostname" = "$d" ]; then
      matched=1
      break
    fi
  done

  # Wildcard match
  if [ $matched -eq 0 ]; then
    for w in $(jq -r '.wildcards[]' "$SCOPE_FILE"); do
      pattern="^$(echo "$w" | sed 's/\./\\./g; s/\*/[^.]*/g')$"
      if [[ "$hostname" =~ $pattern ]]; then
        matched=1
        break
      fi
    done
  fi

  # Check exclusions
  if [ $matched -eq 1 ]; then
    for excl in $(jq -r '.exclusions.domains[]' "$SCOPE_FILE"); do
      if [ "$hostname" = "$excl" ]; then
        matched=0
        break
      fi
    done
  fi

  if [ $matched -eq 1 ]; then
    echo "$hostname" >> "$OUT_IN"
    ((in_scope++))
  else
    echo "$hostname" >> "$OUT_OOS"
    ((oos++))
  fi
done < "$INPUT_FILE"

echo "In scope: $in_scope"
echo "Out of scope: $oos"
```

---

## Scope Decisions and Edge Cases

### Apex vs Wildcard

```
Scope:  *.target.com
Hosts:  target.com, www.target.com, api.target.com

target.com    → OUT OF SCOPE (must be explicitly listed)
www.target.com → IN SCOPE (* wildcard matches www.target.com)
api.target.com → IN SCOPE
```

### Subdomain Depth

```
Scope:  *.target.com
Hosts:  sub.target.com vs sub.sub.target.com

Both are IN SCOPE. Wildcard at any depth.
```

### Wildcard Placement

```
Scope:   target.*
Match:  target.com, target.io, target.net
No match: subtarget.com
```

### Exclusions with Wildcards

```json
{
  "wildcards": ["*.target.com"],
  "exclusions": {
    "domains": ["cdn.target.com", "staging.target.com"],
    "types": ["waf", "cdn"]
  }
}
```

```
*.target.com in scope
cdn.target.com excluded by domain
staging.target.com excluded by domain
WAF hosts excluded by type after domain check
```

---

## CIDR Scope Validation

```bash
# Check if IP is in CIDR range
# Requires ipcalc or python

python3 -c "
import ipaddress, sys
ranges = ['203.0.113.0/24', '198.51.100.0/24']
ip = sys.argv[1]
for r in ranges:
    if ipaddress.ip_address(ip) in ipaddress.ip_network(r):
        print(f'{ip} IN {r}')
        sys.exit(0)
print(f'{ip} OUT OF SCOPE')
" 198.51.100.42
```

```powershell
# PowerShell CIDR check
$ranges = @([ipaddress]"203.0.113.0/24", [ipaddress]"198.51.100.0/24")
$ip = [ipaddress]"198.51.100.42"

foreach ($r in $ranges) {
  # Simplified; for production use IPNetwork2 library
  $ipInRange = $ip.Address -band $r.Netmask -eq $r.NetworkAddress
  if ($ipInRange) { Write-Host "IN SCOPE"; break }
}
```

---

## Regex-Based Scope Enforcement

Sometimes scope requires regex matching rather than exact/wildcard:

```json
{
  "scope_regex": [
    "^[a-z]+\.target\.com$",
    "^(api|admin|app)\.target\.com$",
    "^target\.(com|io|net)$"
  ],
  "exclusion_regex": [
    ".*\.staging\.target\.com",
    ".*\.internal\.target\.com",
    "^cdn\."
  ]
}
```

```bash
# Test hostname against regex
test_regex() {
  local hostname="$1"
  local include_regex="$2"
  local exclude_regex="$3"

  for r in $include_regex; do
    if echo "$hostname" | grep -qE "$r"; then
      for e in $exclude_regex; do
        if echo "$hostname" | grep -qE "$e"; then
          return 1  # excluded
        fi
      done
      return 0  # in scope
    fi
  done
  return 1  # no match
}
```

---

## Automated OOS Filtering Steps

### Step 1: Before httpx()

Apply scope to subdomains before probing:

```bash
# Filter subdomains before probing to save time
cat subdomains/all.txt | python3 filter-scope.py scope.json > subdomains/in-scope.txt
httpx -l subdomains/in-scope.txt -o hosts/live.txt
```

### Step 2: After httpx()

Apply scope to live hosts (some may have resolved on adjacent domains):

```bash
cat hosts/live.txt | python3 filter-scope.py scope.json > hosts/live-in-scope.txt
```

### Step 3: After URL Collection

Apply scope to URLs (some may point to third-party integrations):

```bash
# Extract domains from URLs and filter
cat urls/all-urls.txt | awk -F/ '{print $3}' | sort -u | python3 filter-subdomains.py scope.json > urls/in-scope-domains.txt

# Filter URLs by in-scope domain
grep -F -f urls/in-scope-domains.txt urls/all-urls.txt > urls/in-scope.txt
```

### Step 4: After nuclei

Filter nuclei findings (may hit OOS assets):

```bash
cat nuclei.json | jq -r "select(.host | test(\"target\\.com|api\\.target\\.com\"))" > nuclei-in-scope.json
```

---

## Scope Ambiguity Handling

Some results fall into grey areas. Create an ambiguity queue.

### Ambiguous Cases

| Situation | Action | Confidence |
|---|---|---|
| `target.com.evil.com` | OOS | High |
| `blog.target.com` when scope says `*.target.com` | In scope | High |
| `app.target.com` when scope says `*.target.com` but program says `excluding CDN` | Need type check | Medium |
| `203.0.113.42` when scope has `*.target.com` only | OOS (unless IP matches CIDR) | High |
| `target.co.uk` with `target.com` in scope | OOS | High |
| `www.target.com` when scope is `*.target.com` only | Depends on program policy | Low |

### Manual Review Queue

Write ambiguous results to `subdomains/ambiguous.txt` for human judgment:

```bash
# Example criteria for ambiguous:
# - Domain is one level deeper than wildcard
# - Domain prefix looks internal-only but resolves publicly
# - IP is in a known IP range but hostname isn't matching
```

---

## Scope Enforcement During Hunting

### Session Start Validation

Before any hunting session:

```powershell
function Start-HuntingSession {
  param([string]$ScopeFile)

  $scope = Get-Content $ScopeFile | ConvertFrom-Json

  Write-Host "=== Scope Check ===" -ForegroundColor Cyan
  Write-Host "In-scope domains: $($scope.domains -join ', ')"
  Write-Host "Wildcards: $($scope.wildcards -join ', ')"
  Write-Host "CIDRs: $($scope.cidrs -join ', ')"
  Write-Host "Exclusions: $($scope.exclusions.domains -join ', ')"

  $confirm = Read-Host "Confirm scope and proceed?"
  if ($confirm -notmatch '^[Yy]') {
    Write-Host "Aborted." -ForegroundColor Red
    exit 1
  }
}
```

### Per-Request Scope Guard

Wrap request functions with scope checks:

```powershell
function Invoke-ScopedRequest {
  param(
    [string]$Url,
    [hashtable]$Scope
  )

  $hostname = [uri]::new($Url).Host.ToLower()
  if (-not (Test-InScope -Hostname $hostname -Scope $scope)) {
    Write-Warning "SKIPPING OOS: $hostname"
    return
  }

  curl.exe -s $Url
}
```

---

## Program Policy Parsing

### Scope Extraction from HackerOne Program Page

```powershell
# Load program scope from HackerOne API (requires H1 API key)
$headers = @{ "Authorization" = "Bearer $env:H1_API_KEY" }
$program = Invoke-RestMethod -Uri "https://api.hackerone.com/v1/programs/target" -Headers $headers

# Parse structured scope
$program.relationships.structure_information.data.attributes.scope |
  Where-Object { $_.asset_type -eq "Domain" } |
  ForEach-Object { $_.asset_identifier } |
  Set-Content scope-domains.txt
```

### Scope Extraction from Raw Text

```
Program scope text:
  *.target.com
  *.target.io
  In scope: target.com
  Out of scope: *.staging.target.com, cdn.target.com
  CIDR: 203.0.113.0/24

Parse rules:
- Lines starting with wildcard -> wildcard rule
- Lines starting with "In scope:" -> domains list
- Lines starting with "Out of scope:" -> exclusions list
- Lines starting with CIDR: -> CIDR range
```

---

## Output and Reporting

### Scope Validation Report

```
SCOPE VALIDATION REPORT
========================

Subdomains found:                   1,247
In scope:                              412
Out of scope:                          821
Ambiguous:                              14

In-scope breakdown:
  *.target.com wildcard:              398
  Exact domain match:                   14

Out-of-scope top reasons:
  CDN hostname:                        412
  Acquisition (OOS):                   289
  Regex exclusion (staging):           120

Ambiguous items: (manual review)
  - app.target.com.vendor.com
  - www.target.com.internal
  - 203.0.113.42 (matches CIDR? unconfirmed)
```

### Re-validation After Asset Changes

```powershell
# Re-run scope validation after each recon phase
$phases = @("subdomains/all.txt", "hosts/live.txt", "urls/all-urls.txt")

foreach ($phase in $phases) {
  Write-Host "Validating: $phase"
  $content = Get-Content $phase
  $inScope = $content | Where-Object { Test-InScope -Hostname $_ -Scope $scope }
  $outOfScope = $content | Where-Object { -not (Test-InScope -Hostname $_ -Scope $scope) }

  $inScope | Set-Content "$phase.in-scope.txt"
  $outOfScope | Set-Content "$phase.out-of-scope.txt"
}
```

---

## Key Principles

1. **Never test OOS** — even for curiosity, every request is logged and audit-trailed.
2. **Filter before you probe.** httpx on 1,247 unfiltered subdomains wastes time on OOS assets.
3. **Re-validate after each phase.** New subdomains from permutations may be OOS.
4. **Log ambiguity** — if in doubt, flag for human judgment, don't silently drop.
5. **Wildcard ≠ apex** — `*.target.com` does not grant `target.com` unless explicitly listed.
6. **Respect acquisition clauses** — acquisitions may have their own separate scope.
7. **CIDR beats hostname** — if scope has both `*.target.com` and a CIDR, the CIDR is the stricter filter for IP-based hosts.
