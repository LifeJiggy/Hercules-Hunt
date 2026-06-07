#!/usr/bin/env bash
# =====================================================================
# recon-toolkit.sh — Recon Automation Pipeline for Linux/macOS
#
# 17 functions mirroring recon-toolkit.ps1 using curl, dig, jq, and
# standard Unix tools. Source this file from your shell.
#
# Requires: curl, dig (bind-utils), jq, whois
# Optional: subfinder, httpx, nuclei (for enhanced modes)
# =====================================================================

[ -z "$BASH_VERSION" ] && [ -z "$ZSH_VERSION" ] && echo "recon-toolkit.sh requires bash or zsh" && return 1

RECON_DIR="${RECON_DIR:-/tmp/recon-$(date +%Y%m%d)}"

# ─── helpers ─────────────────────────────────────────────────────
_recon_log() { echo "[$(date -u +%H:%M:%S)] $*"; }
_recon_save() { local f="$1"; shift; echo "$*" >> "$RECON_DIR/$f"; }

# ─── 1. Get-SubdomainsCrtSh — crt.sh certificate transparency ───
Get-SubdomainsCrtSh() {
  local domain="$1"
  _recon_log "Querying crt.sh for $domain"
  curl -sk "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' 2>/dev/null | \
    grep -v "\\*" | sort -u
}

# ─── 2. Get-SubdomainsSecurityTrails — SecurityTrails API ────────
Get-SubdomainsSecurityTrails() {
  local domain="$1" api_key="${SECURITYTRAILS_API_KEY:-}"
  [ -z "$api_key" ] && echo "Set SECURITYTRAILS_API_KEY" && return 1
  _recon_log "Querying SecurityTrails for $domain"
  curl -sk "https://api.securitytrails.com/v1/domain/$domain/subdomains" \
    -H "APIKEY: $api_key" | jq -r '.subdomains[]' 2>/dev/null | \
    awk -v d="$domain" '{print $0"."d}'
}

# ─── 3. Get-SubdomainsRapidDns — RapidDNS query ──────────────────
Get-SubdomainsRapidDns() {
  local domain="$1"
  _recon_log "Querying RapidDNS for $domain"
  curl -sk "https://rapiddns.io/subdomain/$domain?full=1" | \
    grep -oP '(?<=>)[a-zA-Z0-9.-]+\.'"$domain" | sort -u
}

# ─── 4. Get-SubdomainsDnsDumpster — DNS Dumpster ─────────────────
Get-SubdomainsDnsDumpster() {
  local domain="$1"
  _recon_log "Querying DNS Dumpster for $domain"
  curl -sk "https://dnsdumpster.com/" -c /tmp/dnsdumpster_cookie.txt > /dev/null 2>&1
  local csrf
  csrf=$(grep csrf /tmp/dnsdumpster_cookie.txt 2>/dev/null | awk '{print $NF}')
  [ -z "$csrf" ] && echo "DNS Dumpster unavailable" && return 1
  curl -sk "https://dnsdumpster.com/" \
    -b /tmp/dnsdumpster_cookie.txt \
    -d "csrfmiddlewaretoken=$csrf&targetip=$domain" | \
    grep -oP '([a-zA-Z0-9.-]+\.'"$domain"')' | sort -u
}

# ─── 5. Test-LiveHost — single-host liveliness ───────────────────
Test-LiveHost() {
  local host="$1"
  curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://$host" 2>/dev/null || \
  curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://$host" 2>/dev/null || echo "000"
}

# ─── 6. Invoke-BulkHostCheck — parallel bulk host check ──────────
Invoke-BulkHostCheck() {
  local file="$1" threads="${2:-10}"
  _recon_log "Checking ${threads} hosts in parallel from $file"
  xargs -P "$threads" -I{} sh -c 'echo "$1 $(Test-LiveHost "$1")"' _ {} < "$file"
}

# ─── 7. Get-HttpTitle — fetch HTTP page title ────────────────────
Get-HttpTitle() {
  local url="$1"
  curl -skL "$url" 2>/dev/null | grep -oP '<title>[^<]+</title>' | sed 's/<[/]*title>//g' || echo "(no title)"
}

# ─── 8. Get-TechStack — technology fingerprinting ────────────────
Get-TechStack() {
  local url="$1"
  _recon_log "Fingerprinting $url"
  local headers
  headers=$(curl -skI -L "$url" 2>/dev/null)
  echo "$headers" | while read -r line; do
    case "${line,,}" in
      *server:*)      echo "Server: $(echo "$line" | cut -d: -f2-)";;
      *x-powered-by*) echo "X-Powered-By: $(echo "$line" | cut -d: -f2-)";;
      *set-cookie*)   echo "Cookies: $(echo "$line" | cut -d: -f2- | cut -d= -f1)";;
    esac
  done
}

# ─── 9. Get-RobotsPaths — parse robots.txt ───────────────────────
Get-RobotsPaths() {
  local url="$1"
  curl -skL "${url%/}/robots.txt" 2>/dev/null | grep -i '^disallow' | awk '{print $2}' || echo "(no robots.txt)"
}

# ─── 10. Get-SitemapPaths — parse sitemap.xml ────────────────────
Get-SitemapPaths() {
  local url="$1"
  curl -skL "${url%/}/sitemap.xml" 2>/dev/null | grep -oP '<loc>[^<]+</loc>' | sed 's/<[/]*loc>//g' || echo "(no sitemap.xml)"
}

# ─── 11. Get-UrlFromWayback — Wayback Machine historical URLs ────
Get-UrlFromWayback() {
  local domain="$1"
  _recon_log "Fetching Wayback URLs for $domain"
  curl -sk "http://web.archive.org/cdx/search/cdx?url=*.$domain&output=json&fl=original&collapse=urlkey" | \
    jq -r '.[] | .[]' 2>/dev/null | sort -u
}

# ─── 12. Expand-WildcardScope — wildcard scope expansion ─────────
Expand-WildcardScope() {
  local pattern="$1"
  echo "Expanding $pattern — use Get-SubdomainsCrtSh for real data"
  echo "  (wildcard expansion requires external subdomain sources)"
}

# ─── 13. Get-DnsRecords — DNS record resolution ──────────────────
Get-DnsRecords() {
  local domain="$1"
  for type in A AAAA CNAME MX NS TXT SOA SRV; do
    local result
    result=$(dig +short "$domain" "$type" 2>/dev/null)
    [ -n "$result" ] && echo "=== $type ===" && echo "$result"
  done
}

# ─── 14. Test-PortOpen — TCP port scanning ───────────────────────
Test-PortOpen() {
  local host="$1" ports="${2:-80,443,8443,8080,8000,9090,3000,5000,22,21,23,25,53,110,143,993,995,3306,5432,6379,27017}"
  _recon_log "Scanning $host ports: $ports"
  IFS=',' read -ra PORT_ARRAY <<< "$ports"
  for port in "${PORT_ARRAY[@]}"; do
    timeout 2 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null && echo "  $port/tcp open" || true
  done
}

# ─── 15. Invoke-ReconPipeline — full orchestrating pipeline ──────
Invoke-ReconPipeline() {
  local domain="$1"
  mkdir -p "$RECON_DIR"
  _recon_log "=== Recon Pipeline: $domain ==="

  echo "--- DNS Records ---"
  Get-DnsRecords "$domain" | tee "$RECON_DIR/dns-$domain.txt"

  echo "--- crt.sh Subdomains ---"
  Get-SubdomainsCrtSh "$domain" | tee "$RECON_DIR/crtsh-$domain.txt"

  echo "--- Wayback URLs ---"
  Get-UrlFromWayback "$domain" | head -100 | tee "$RECON_DIR/wayback-$domain.txt"

  echo "--- Live Host Check ---"
  if [ -f "$RECON_DIR/crtsh-$domain.txt" ]; then
    while IFS= read -r host; do
      local status
      status=$(Test-LiveHost "$host")
      echo "$host → HTTP $status"
    done < "$RECON_DIR/crtsh-$domain.txt" | tee "$RECON_DIR/live-$domain.txt"
  fi

  _recon_log "Done. Output in $RECON_DIR/"
}

# ─── 16. Out-ReconReport — structured Markdown report ────────────
Out-ReconReport() {
  local domain="$1"
  local report="$RECON_DIR/report-$domain.md"
  cat > "$report" <<REPORT
# Recon Report: $domain

**Date:** $(date -u)
**Tools:** recon-toolkit.sh

## DNS Records
\`\`\`
$(cat "$RECON_DIR/dns-$domain.txt" 2>/dev/null || echo "N/A")
\`\`\`

## Subdomains (crt.sh)
$(while IFS= read -r s; do echo "- $s"; done < "$RECON_DIR/crtsh-$domain.txt" 2>/dev/null || echo "N/A")

## Wayback URLs (top 100)
$(while IFS= read -r u; do echo "- $u"; done < "$RECON_DIR/wayback-$domain.txt" 2>/dev/null || echo "N/A")

## Live Hosts
$(while IFS= read -r h; do echo "- $h"; done < "$RECON_DIR/live-$domain.txt" 2>/dev/null || echo "N/A")
REPORT
  echo "Report: $report"
}

# ─── 17. Export-ReconJson — JSON export of recon data ────────────
Export-ReconJson() {
  local domain="$1"
  local json="$RECON_DIR/recon-$domain.json"
  {
    echo "{"
    echo "\"domain\": \"$domain\","
    echo "\"timestamp\": \"$(date -u -Iseconds)\","
    echo "\"dns\": ["
    awk '{print "\""$0"\","}' "$RECON_DIR/dns-$domain.txt" 2>/dev/null | sed '$s/,//'
    echo "],"
    echo "\"subdomains\": ["
    awk '{print "\""$0"\","}' "$RECON_DIR/crtsh-$domain.txt" 2>/dev/null | sed '$s/,//'
    echo "]"
    echo "}"
  } > "$json"
  echo "JSON: $json"
}

echo "recon-toolkit.sh loaded — 17 functions available"
