#!/usr/bin/env bash
# =====================================================================
# lib.sh — Shared Bash Utility Library for Bug Bounty Hunting
#
# Core helpers for HTTP, strings, encoding, files, and output.
# Mirrors the essential functions from powershell-lib.ps1.
#
# Source this file before loading other toolkit scripts.
# =====================================================================

[ -z "$BASH_VERSION" ] && [ -z "$ZSH_VERSION" ] && echo "lib.sh requires bash or zsh" && return 1

# ─── Timestamp ───────────────────────────────────────────────────
Get-Timestamp() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# ─── Output helpers ──────────────────────────────────────────────
Write-Host()   { echo -e "\e[1;37m[*]\e[0m $*"; }
Write-Info()   { echo -e "\e[36m[i]\e[0m $*"; }
Write-Success(){ echo -e "\e[32m[+]\e[0m $*"; }
Write-Warning(){ echo -e "\e[33m[!]\e[0m $*"; }
Write-Error()  { echo -e "\e[31m[-]\e[0m $*"; }

# ─── HTTP helpers ────────────────────────────────────────────────
Set-Proxy() {
  local proxy="${1:-http://127.0.0.1:8080}"
  export HTTP_PROXY="$proxy" HTTPS_PROXY="$proxy"
  Write-Info "Proxy set: $proxy"
}
Clear-Proxy() {
  unset HTTP_PROXY HTTPS_PROXY
  Write-Info "Proxy cleared"
}
Invoke-Request() {
  local url="$1" method="${2:-GET}" data="$3"
  curl -sk -X "$method" ${data:+-d "$data"} \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64)" \
    -w "\n%{http_code}" "$url"
}

# ─── String/Regex tools ──────────────────────────────────────────
Search-String()   { grep -oP "$1" "$2" 2>/dev/null || echo "$1" | grep -oP "$2" 2>/dev/null; }
Select-String()   { grep -i "$1" "$2" 2>/dev/null; }
Remove-Duplicate(){ sort -u; }
Get-UrlParts()    { echo "$1" | grep -oP '(https?|ftp)://[^/\s]+/[^\s]*' || echo "$1"; }
Get-QueryParams() { echo "$1" | grep -oP '(?<=\?|&)[^=]+=[^&]+' | sort; }

# ─── Encoding ────────────────────────────────────────────────────
ConvertTo-Base64()  { echo -n "$1" | base64; }
ConvertFrom-Base64(){ echo "$1" | base64 -d 2>/dev/null; }
ConvertTo-UrlEncode(){
  python3 -c "import urllib.parse; print(urllib.parse.quote('$1'))" 2>/dev/null || echo "$1"
}
ConvertFrom-UrlEncode(){
  python3 -c "import urllib.parse; print(urllib.parse.unquote('$1'))" 2>/dev/null || echo "$1"
}
ConvertFrom-Jwt(){
  echo "$1" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "Invalid JWT"
}

# ─── File tools ──────────────────────────────────────────────────
Find-Files()      { find "${2:-.}" -name "$1" -type f 2>/dev/null; }
Find-InFiles()    { grep -rl "$1" "${2:-.}" 2>/dev/null; }
Get-FileLines()   { wc -l < "$1" 2>/dev/null; }
Split-File()      { split -l "${2:-1000}" "$1" "${1}_part_"; }

# ─── Wordlists ───────────────────────────────────────────────────
Get-Wordlist() {
  local name="${1:-common}"
  case "$name" in
    common)   echo "admin test debug api v1 v2 internal private backup config dev staging demo login admin panel dashboard";;
    dirs)     echo "admin api assets backup cache config css data db docs download etc files fonts img images includes js lib log logs media pages public resources src static templates test tmp uploads vendor views www";;
    params)   echo "id user_id admin role token api_key file path url redirect next return page q s search filter  email name action type limit offset order sort";;
    subs)     echo "www api app admin dev staging test mail blog cdn static assets images docs support help community forum status";;
    *)        echo "Unknown wordlist: $name (common|dirs|params|subs)";;
  esac
}

# ─── Session / state ─────────────────────────────────────────────
export BB_SESSION_DIR="${BB_SESSION_DIR:-/tmp/bb-session-$(date +%Y%m%d)}"
mkdir -p "$BB_SESSION_DIR"

New-Finding() {
  local title="$1" severity="${2:-Info}"
  local f="$BB_SESSION_DIR/findings.json"
  local entry
  entry=$(cat <<EOF
{"title":"$title","severity":"$severity","date":"$(date -u -Iseconds)"}
EOF
)
  if [ -f "$f" ]; then
    python3 -c "
import json
with open('$f') as fh: data = json.load(fh)
data.append($entry)
with open('$f', 'w') as fh: json.dump(data, fh, indent=2)
" 2>/dev/null || echo "$entry" >> "$f"
  else
    echo "[$entry]" > "$f"
  fi
  Write-Success "Finding logged: $title ($severity)"
}
Show-Findings() {
  local f="$BB_SESSION_DIR/findings.json"
  [ -f "$f" ] && python3 -m json.tool "$f" 2>/dev/null || echo "No findings yet"
}

echo "lib.sh loaded — utilities available"
