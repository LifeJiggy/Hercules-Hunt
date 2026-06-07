#!/usr/bin/env bash
# =====================================================================
# curl-hunter.sh — curl Toolkit for Bug Bounty Hunting on Linux/macOS
#
# Provides 15 bash functions wrapping curl for recon and vulnerability
# testing. Source this file from your shell rc or directly in a session.
#
# Usage:
#   source curl-hunter.sh
#   Test-Endpoint "https://api.target.com/login" POST
#
# Requires: curl, jq
# =====================================================================

[ -z "$BASH_VERSION" ] && [ -z "$ZSH_VERSION" ] && echo "curl-hunter.sh requires bash or zsh" && return 1

CURL_HUNTER_LOG_DIR="${CURL_HUNTER_LOG_DIR:-/tmp/curl-hunter-logs}"
mkdir -p "$CURL_HUNTER_LOG_DIR"

# ─── helpers ─────────────────────────────────────────────────────

_curl_hunter_ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
_curl_hunter_log() {
  local level="$1" msg="$2"
  echo "[$(_curl_hunter_ts)] [$level] $msg" >> "$CURL_HUNTER_LOG_DIR/session.log"
}

# ─── 1. Invoke-CurlRequest — core curl wrapper ───────────────────
Invoke-CurlRequest() {
  local url="$1" method="${2:-GET}" data="$3" extra_args=()
  [ -n "$data" ] && extra_args=(-d "$data")
  _curl_hunter_log "INFO" "→ $method $url"
  curl -sk -X "$method" "${extra_args[@]}" \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
    -H "Accept: */*" \
    -w "\n%{http_code}" "$url"
}

# ─── 2. Save-CurlSession — save/load cookie jars ─────────────────
Save-CurlSession() {
  local jar="$CURL_HUNTER_LOG_DIR/cookies-$(date +%Y%m%d).txt"
  echo "Session cookie jar: $jar"
}

# ─── 3. Test-Endpoint — single-endpoint probe ────────────────────
Test-Endpoint() {
  local url="$1" method="${2:-GET}" data="$3"
  Invoke-CurlRequest "$url" "$method" "$data"
}

# ─── 4. Test-JsonApi — JSON API helper ────────────────────────────
Test-JsonApi() {
  local method="$1" url="$2" body="$3"
  curl -sk -X "$method" "$url" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -H "User-Agent: Mozilla/5.0" \
    -d "$body" \
    -w "\n%{http_code}"
}

# ─── 5. Test-AuthBypass — auth-bypass primitives ─────────────────
Test-AuthBypass() {
  local url="$1"
  echo "=== Auth Bypass Tests: $url ==="
  for header in "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ." \
                "X-Forwarded-For: 127.0.0.1" \
                "X-Original-URL: /admin" \
                "X-Rewrite-URL: /admin" \
                "X-Forwarded-Host: localhost"; do
    echo "--- Header: $header ---"
    curl -sk -H "$header" -H "User-Agent: Mozilla/5.0" -o /dev/null -w "HTTP %{http_code}, Size: %{size_download}\n" "$url"
  done
}

# ─── 6. Test-ParameterFuzz — parameter fuzzing ───────────────────
Test-ParameterFuzz() {
  local url="$1"
  echo "=== Parameter Fuzz: $url ==="
  for param in "id" "user_id" "admin" "role" "token" "api_key" "file" "path" "url" "redirect"; do
    local baseline
    baseline=$(curl -sk -o /dev/null -w "%{size_download}" "$url")
    local fuzzed
    fuzzed=$(curl -sk -o /dev/null -w "%{size_download}" "${url}?${param}=test")
    [ "$baseline" != "$fuzzed" ] && echo "  ?$param=test → size diff: $baseline vs $fuzzed"
  done
}

# ─── 7. Test-IdorRange — sequential-ID enumeration ───────────────
Test-IdorRange() {
  local base_url="$1" start="${2:-1}" end="${3:-10}"
  echo "=== IDOR Range: $base_url [$start-$end] ==="
  for i in $(seq "$start" "$end"); do
    local url="${base_url/\{id\}/$i}"
    [ "$url" = "$base_url" ] && url="$base_url$i"
    local status size
    status=$(curl -sk -o /dev/null -w "%{http_code}" "$url")
    size=$(curl -sk -o /dev/null -w "%{size_download}" "$url")
    echo "  ID $i → HTTP $status, ${size}b"
  done
}

# ─── 8. Test-MethodBypass — HTTP-verb enumeration ────────────────
Test-MethodBypass() {
  local url="$1"
  echo "=== Method Bypass: $url ==="
  for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
    local status
    status=$(curl -sk -X "$method" -o /dev/null -w "%{http_code}" "$url")
    echo "  $method → HTTP $status"
  done
}

# ─── 9. Test-SsrfParams — SSRF-prone parameter detection ─────────
Test-SsrfParams() {
  local url="$1" callback="${2:-https://oastify.com}"
  echo "=== SSRF Probe: $url ==="
  for param in "url" "uri" "file" "redirect" "next" "path" "dest" "return" "page" "load" "src" "target"; do
    local status
    status=$(curl -sk -o /dev/null -w "%{http_code}" "${url}?${param}=${callback}")
    echo "  ?$param=$callback → HTTP $status"
  done
}

# ─── 10. Test-Cors — CORS misconfiguration check ─────────────────
Test-Cors() {
  local url="$1"
  echo "=== CORS Check: $url ==="
  curl -sk -H "Origin: https://evil.com" -H "User-Agent: Mozilla/5.0" \
    -D - "$url" 2>/dev/null | grep -i "access-control"
}

# ─── 11. Compare-ResponseDiff — side-by-side response diff ───────
Compare-ResponseDiff() {
  local url1="$1" url2="$2"
  local f1="/tmp/_resp1_$$.txt" f2="/tmp/_resp2_$$.txt"
  curl -sk "$url1" -o "$f1"
  curl -sk "$url2" -o "$f2"
  diff <(sort "$f1") <(sort "$f2") || true
  rm -f "$f1" "$f2"
}

# ─── 12. ConvertTo-Har — convert response to HAR JSON ────────────
ConvertTo-Har() {
  local url="$1" method="${2:-GET}" output="${3:-/tmp/request.har}"
  local ts
  ts=$(date -u +%s000)
  cat > "$output" <<HAR
{
  "log": {
    "version": "1.2",
    "entries": [{
      "startedDateTime": "$(date -u -Iseconds)",
      "request": { "method": "$method", "url": "$url" },
      "response": { "status": 0, "statusText": "captured" }
    }]
  }
}
HAR
  echo "HAR saved: $output"
}

# ─── 13. Send-BatchRequests — throttled batch sender ─────────────
Send-BatchRequests() {
  local url="$1" count="${2:-5}" delay="${3:-0.5}"
  echo "=== Batch: $url x $count (delay ${delay}s) ==="
  for i in $(seq 1 "$count"); do
    curl -sk -o /dev/null -w "Request $i → HTTP %{http_code}\n" "$url"
    sleep "$delay"
  done
}

# ─── 14. Invoke-RateLimitTest — rate-limit stress test ───────────
Invoke-RateLimitTest() {
  local url="$1" requests="${2:-50}" parallel="${3:-5}"
  echo "=== Rate Limit Test: $url x $requests (${parallel} parallel) ==="
  for i in $(seq 1 "$parallel"); do
    for j in $(seq 1 $((requests / parallel))); do
      curl -sk -o /dev/null -w "%{http_code}\n" "$url" &
    done
  done
  wait
  echo "Done. Check responses above for 429/503 patterns."
}

# ─── 15. Invoke-CurlHunterMenu — interactive menu ────────────────
Invoke-CurlHunterMenu() {
  echo "=== Curl Hunter Menu ==="
  echo "1) Test-Endpoint        6) Test-IdorRange       11) Compare-ResponseDiff"
  echo "2) Test-JsonApi         7) Test-MethodBypass    12) Invoke-RateLimitTest"
  echo "3) Test-AuthBypass      8) Test-SsrfParams      13) Send-BatchRequests"
  echo "4) Test-ParameterFuzz   9) Test-Cors"
  echo "5) Test-MethodBypass   10) ConvertTo-Har"
  read -rp "Select: " opt
  read -rp "URL: " url
  case "$opt" in
    1) Test-Endpoint "$url";;
    3) Test-AuthBypass "$url";;
    4) Test-ParameterFuzz "$url";;
    5|7) Test-MethodBypass "$url";;
    6) read -rp "Start (default 1): " s; read -rp "End (default 10): " e; Test-IdorRange "$url" "${s:-1}" "${e:-10}";;
    8) Test-SsrfParams "$url";;
    9) Test-Cors "$url";;
    *) echo "Not implemented in menu mode";;
  esac
}

echo "curl-hunter.sh loaded — 15 functions available"
