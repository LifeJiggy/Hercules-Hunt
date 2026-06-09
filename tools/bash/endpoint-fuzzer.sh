#!/usr/bin/env bash
# =====================================================================
# endpoint-fuzzer.sh — Endpoint Fuzzing and Discovery Tool
#
# Path fuzzing with wordlists, HTTP method fuzzing, extension fuzzing,
# and response analysis/filtering. Identifies hidden endpoints, backup
# files, and accessible resources through systematic fuzzing.
#
# Usage:
#   ./endpoint-fuzzer.sh -u https://target.com/api -w paths.txt
#   ./endpoint-fuzzer.sh -u https://target.com/FUZZ -w /usr/share/wordlists/common.txt
#   ./endpoint-fuzzer.sh -u https://target.com -x .bak,.old,.swp
# =====================================================================

set -euo pipefail

# ─── Constants ───────────────────────────────────────────────────
VERSION="1.0.0"
SCRIPT_NAME=$(basename "$0")
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; NC='\033[0m'

# Default wordlists (built-in)
DEFAULT_PATHS=(
  "admin" "api" "v1" "v2" "v3" "rest" "graphql" "soap"
  "login" "logout" "signup" "register" "auth" "oauth" "token"
  "user" "users" "profile" "account" "settings" "config"
  "admin" "administrator" "dashboard" "panel" "console"
  "upload" "uploads" "download" "downloads" "file" "files"
  "image" "images" "img" "media" "static" "assets" "public"
  "backup" "backups" "db" "database" "sql" "dump" "export"
  "debug" "test" "dev" "staging" "sandbox" "internal"
  "status" "health" "healthz" "readyz" "metrics" "info"
  "swagger" "api-docs" "openapi" "redoc" "graphiql" "voyager"
  "robots.txt" "sitemap.xml" "security.txt" "crossdomain.xml"
  "version" "changelog" "release" "readme" "license"
  "proxy" "cgi" "cgi-bin" "fcgi" "fastcgi"
  "phpinfo.php" "info.php" "test.php" "p.php"
  ".git" ".svn" ".hg" ".env" "composer.json" "package.json"
)

DEFAULT_EXTENSIONS=(
  "" ".html" ".htm" ".php" ".asp" ".aspx" ".jsp" ".do" ".action"
  ".json" ".xml" ".yaml" ".yml" ".txt" ".csv" ".tsv"
  ".bak" ".backup" ".old" ".orig" ".copy" ".save" ".swp" ".swo" ".swn"
  ".tar" ".tar.gz" ".gz" ".zip" ".7z" ".rar"
  ".log" ".error" ".debug"
  ".inc" ".class" ".jar" ".war"
  ".js" ".css" ".map" ".ts" ".jsx" ".vue"
  ".sql" ".dump" ".db" ".sqlite"
  ".env" ".config" ".cfg" ".conf" ".ini"
  ".ds_store" ".ds_Store" "thumbs.db"
)

DEFAULT_METHODS=("GET" "POST" "PUT" "PATCH" "DELETE" "OPTIONS" "HEAD" "TRACE" "CONNECT")

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
info()   { echo -e "${CYAN}[i]${NC} $*"; }
ok()     { echo -e "${GREEN}[+]${NC} $*"; }
warn()   { echo -e "${YELLOW}[!]${NC} $*" >&2; }
err()    { echo -e "${RED}[-]${NC} $*" >&2; }
found()  { echo -e "${GREEN}[FOUND]${NC} $*"; }
hit()    { echo -e "${MAGENTA}[HIT]${NC} $*"; }

# ─── Usage ───────────────────────────────────────────────────────
usage() {
  cat <<EOF
${CYAN}endpoint-fuzzer.sh${NC} v${VERSION} — Endpoint Fuzzing Tool

${YELLOW}Description:${NC}
  Systematic fuzzing for hidden endpoints, files, and directories.
  Supports path fuzzing, extension fuzzing, HTTP method fuzzing, and
  response filtering. Use FUZZ keyword in URL for precise placement.

${YELLOW}Usage:${NC}
  $SCRIPT_NAME -u https://target.com/FUZZ -w wordlist.txt
  $SCRIPT_NAME -u https://target.com/api                  (built-in paths)
  $SCRIPT_NAME -u https://target.com/file -x .bak,.old    (extensions)
  $SCRIPT_NAME -u https://target.com/endpoint --methods   (method fuzz)

${YELLOW}Modes:${NC}
  --paths        Fuzz URL paths (default: enabled)
  --extensions   Fuzz file extensions
  --methods      Fuzz HTTP methods
  --all          Run all fuzzing modes

${YELLOW}Options:${NC}
  -u <url>          Target URL (use FUZZ marker for injection point)
  -w <file>         Wordlist file
  -x <exts>         Comma-separated extensions to try
  -m <methods>      Comma-separated HTTP methods
  -o <file>         Output file
  -t <seconds>      Request timeout (default: 10)
  -c <num>          Concurrency (default: 5)
  --mc <codes>      Filter by status codes (comma-separated, default: 200,204,301,302,307,401,403,405,500)
  --ms <size>       Filter by response size
  --hide <size>     Hide responses of given size
  -q                Quiet mode (show only findings)
  -v                Verbose mode
  -h                Show help

${YELLOW}Examples:${NC}
  $SCRIPT_NAME -u https://target.com/FUZZ -w paths.txt
  $SCRIPT_NAME -u https://target.com/api/users -x .json,.xml
  $SCRIPT_NAME -u https://target.com/api --methods
  $SCRIPT_NAME -u https://target.com/FUZZ -w common.txt --mc 200,403
EOF
  exit 0
}

# ─── Options ─────────────────────────────────────────────────────
TARGET_URL=""
WORDLIST=""
EXTENSIONS=""
METHODS=""
OUTPUT_FILE=""
TIMEOUT=10
CONCURRENCY=5
FILTER_CODES="200,204,301,302,307,308,401,403,405,500,502,503"
FILTER_SIZE=""
HIDE_SIZE=""
QUIET=false
VERBOSE=false

RUN_PATHS=true
RUN_EXTENSIONS=false
RUN_METHODS=false

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help) usage ;;
      -u|--url) TARGET_URL="$2"; shift 2 ;;
      -w|--wordlist) WORDLIST="$2"; shift 2 ;;
      -x|--extensions) EXTENSIONS="$2"; shift 2 ;;
      -m|--methods) METHODS="$2"; shift 2 ;;
      -o|--output) OUTPUT_FILE="$2"; shift 2 ;;
      -t|--timeout) TIMEOUT="$2"; shift 2 ;;
      -c|--concurrency) CONCURRENCY="$2"; shift 2 ;;
      --mc) FILTER_CODES="$2"; shift 2 ;;
      --ms) FILTER_SIZE="$2"; shift 2 ;;
      --hide) HIDE_SIZE="$2"; shift 2 ;;
      -q|--quiet) QUIET=true; shift ;;
      -v|--verbose) VERBOSE=true; shift ;;
      --paths) RUN_PATHS=true; RUN_EXTENSIONS=false; RUN_METHODS=false; shift ;;
      --extensions) RUN_PATHS=false; RUN_EXTENSIONS=true; RUN_METHODS=false; shift ;;
      --methods) RUN_PATHS=false; RUN_EXTENSIONS=false; RUN_METHODS=true; shift ;;
      --all) RUN_PATHS=true; RUN_EXTENSIONS=true; RUN_METHODS=true; shift ;;
      *) err "Unknown: $1"; usage ;;
    esac
  done
  [ -z "$TARGET_URL" ] && { err "No target URL"; usage; }

  # Parse filter codes into array
  IFS=',' read -r -a FILTER_CODES_ARRAY <<< "$FILTER_CODES"
}

check_deps() {
  local missing=()
  for d in curl grep sed awk sort uniq; do
    command -v "$d" &>/dev/null || missing+=("$d")
  done
  [ ${#missing[@]} -gt 0 ] && { err "Missing: ${missing[*]}"; exit 1; }
}

# ─── HTTP probe ──────────────────────────────────────────────────
_http_probe() {
  local method="$1" url="$2"
  curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" -X "$method" \
    -o /dev/null -w "%{http_code}|||%{size_download}|||%{time_total}|||%{content_type}|||%{redirect_url}" "$url" 2>/dev/null || echo "FAIL|||0|||0|||unknown|||"
}

_should_show() {
  local status="$1" size="$2"
  # Check status code filter
  local matched=false
  for code in "${FILTER_CODES_ARRAY[@]}"; do
    [ "$status" = "$code" ] && matched=true && break
  done
  $matched || return 1

  # Check hide size
  if [ -n "$HIDE_SIZE" ]; then
    local hide_size_arr
    IFS=',' read -r -a hide_size_arr <<< "$HIDE_SIZE"
    for hs in "${hide_size_arr[@]}"; do
      [ "$size" = "$hs" ] && return 1
    done
  fi

  # Check filter size
  if [ -n "$FILTER_SIZE" ]; then
    [ "$size" != "$FILTER_SIZE" ] && return 1
  fi

  return 0
}

# ─── Substitute FUZZ marker ──────────────────────────────────────
_substitute_fuzz() {
  local url="$1" value="$2"
  if echo "$url" | grep -q 'FUZZ'; then
    echo "$url" | sed "s|FUZZ|${value}|g"
  else
    # Ensure no double slash
    local base="${url%/}"
    local val="$value"
    [[ "$val" == /* ]] && val="${val:1}"
    echo "${base}/${val}"
  fi
}

# ─── Load wordlist ───────────────────────────────────────────────
load_wordlist() {
  local tmp
  tmp=$(mktemp) && _cleanup_add "$tmp"

  if [ -n "$WORDLIST" ] && [ -f "$WORDLIST" ]; then
    cat "$WORDLIST" >> "$tmp"
  else
    for p in "${DEFAULT_PATHS[@]}"; do echo "$p" >> "$tmp"; done
  fi

  sort -u "$tmp" | grep -v '^\s*$'
}

# ─── Path fuzzing ────────────────────────────────────────────────
fuzz_paths() {
  local url="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[PATH FUZZ] Fuzzing paths on ${url}${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  local paths
  paths=$(load_wordlist)
  local total hits
  total=$(echo "$paths" | wc -l)
  hits=0

  info "Testing ${total} paths..."

  local counter=0
  while IFS= read -r path; do
    [ -z "$path" ] && continue
    counter=$((counter + 1))
    [ "$VERBOSE" = true ] && [ $((counter % 50)) -eq 0 ] && info "Progress: ${counter}/${total}"

    local test_url
    test_url=$(_substitute_fuzz "$url" "$path")
    local result
    result=$(_http_probe "GET" "$test_url")
    local status size
    status=$(echo "$result" | cut -d'|' -f1)
    size=$(echo "$result" | cut -d'|' -f3)
    
    if _should_show "$status" "$size"; then
      hits=$((hits + 1))
      found "HTTP ${status} | ${size}b | ${test_url}"
    fi
  done <<< "$paths"

  info "Path fuzz complete: ${hits} hits out of ${total}"
}

# ─── Extension fuzzing ───────────────────────────────────────────
fuzz_extensions() {
  local url="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[EXTENSION FUZZ] Fuzzing extensions on ${url}${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  local exts=()
  if [ -n "$EXTENSIONS" ]; then
    IFS=',' read -r -a exts <<< "$EXTENSIONS"
  else
    exts=("${DEFAULT_EXTENSIONS[@]}")
  fi

  local hits=0
  info "Testing ${#exts[@]} extensions..."

  for ext in "${exts[@]}"; do
    local test_url="${url}${ext}"
    local result
    result=$(_http_probe "GET" "$test_url")
    local status size
    status=$(echo "$result" | cut -d'|' -f1)
    size=$(echo "$result" | cut -d'|' -f3)

    if _should_show "$status" "$size"; then
      hits=$((hits + 1))
      found "HTTP ${status} | ${size}b | ${test_url}"
    fi
  done

  info "Extension fuzz complete: ${hits} hits"
}

# ─── Method fuzzing ──────────────────────────────────────────────
fuzz_methods() {
  local url="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[METHOD FUZZ] Fuzzing HTTP methods on ${url}${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  local methods=()
  if [ -n "$METHODS" ]; then
    IFS=',' read -r -a methods <<< "$METHODS"
  else
    methods=("${DEFAULT_METHODS[@]}")
  fi

  info "Testing ${#methods[@]} methods..."

  for method in "${methods[@]}"; do
    local result
    result=$(_http_probe "$method" "$url")
    local status size time
    status=$(echo "$result" | cut -d'|' -f1)
    size=$(echo "$result" | cut -d'|' -f3)
    time=$(echo "$result" | cut -d'|' -f5)

    if [ "$status" != "404" ] && [ "$status" != "405" ]; then
      hit "${method} → HTTP ${status} | ${size}b | ${time}s"
    elif [ "$status" = "405" ]; then
      info "${method} → HTTP 405 (Not Allowed)"
    fi
  done

  # Check for verb tampering
  local auth_bypass_headers=(
    "X-HTTP-Method-Override: GET"
    "X-HTTP-Method: GET"
    "X-Method-Override: GET"
    "X-HTTP-Method-Override: POST"
    "X-HTTP-Method-Override: PUT"
    "X-HTTP-Method-Override: DELETE"
  )

  echo ""
  info "Testing verb tampering headers..."
  for header in "${auth_bypass_headers[@]}"; do
    local status
    status=$(curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" -X POST \
      -H "$header" -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "FAIL")
    [ "$status" != "404" ] && [ "$status" != "405" ] && hit "Verb tamper: ${header} → HTTP ${status}"
  done
}

# ─── Recursive discovery ─────────────────────────────────────────
discover_recursive() {
  local base_url="$1" word="$2"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[RECURSIVE] Deep discovery from found paths${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  local found_paths=("$base_url")
  local depth=0 max_depth=2

  while [ "$depth" -lt "$max_depth" ]; do
    depth=$((depth + 1))
    local new_paths=()

    for url in "${found_paths[@]}"; do
      # Fetch the page
      local body
      body=$(curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" "$url" 2>/dev/null) || continue

      # Extract links
      local links
      links=$(echo "$body" | grep -oP 'href="[^"]*"' | sed 's/href="//;s/"$//' | sort -u)
      while IFS= read -r link; do
        [ -z "$link" ] && continue
        local abs_link
        if echo "$link" | grep -qE '^https?://'; then
          abs_link="$link"
        elif echo "$link" | grep -qE '^/'; then
          local domain; domain=$(echo "$base_url" | grep -oP 'https?://[^/]+')
          abs_link="${domain}${link}"
        else
          local dir; dir=$(dirname "$url")
          abs_link="${dir}/${link}"
        fi

        # Only same-domain
        local bd="${base_url%%/*}"
        local ad="${abs_link%%/*}"
        [ "$bd" != "$ad" ] && continue

        new_paths+=("$abs_link")
      done <<< "$links"
    done

    found_paths=("${new_paths[@]}")
  done

  info "Recursive discovery found ${#found_paths[@]} paths"
}

# ─── Output ──────────────────────────────────────────────────────
maybe_output() { [ -n "$OUTPUT_FILE" ] && info "Output file: ${OUTPUT_FILE}"; }

# ─── Main ────────────────────────────────────────────────────────
main() {
  check_deps
  echo ""
  echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║${NC}  ${GREEN}Endpoint Fuzzer v${VERSION}${NC}"
  echo -e "${CYAN}║${NC}  Target: ${YELLOW}${TARGET_URL}${NC}"
  echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"

  [ "$RUN_PATHS" = true ] && fuzz_paths "$TARGET_URL"
  [ "$RUN_EXTENSIONS" = true ] && fuzz_extensions "$TARGET_URL"
  [ "$RUN_METHODS" = true ] && fuzz_methods "$TARGET_URL"

  maybe_output
  echo ""
  ok "Fuzzing complete"
}

# ─── Response analysis utilities ─────────────────────────────────
classify_response() {
  local status="$1" size="$2" content_type="$3"

  if [ "$status" = "200" ] && [ "$size" -gt 0 ]; then
    echo "accessible"
  elif [ "$status" = "200" ] && [ "$size" -eq 0 ]; then
    echo "empty"
  elif [ "$status" = "204" ]; then
    echo "no_content"
  elif [ "$status" = "301" ] || [ "$status" = "302" ] || [ "$status" = "307" ] || [ "$status" = "308" ]; then
    echo "redirect"
  elif [ "$status" = "400" ]; then
    echo "bad_request"
  elif [ "$status" = "401" ]; then
    echo "unauthorized"
  elif [ "$status" = "403" ]; then
    echo "forbidden"
  elif [ "$status" = "404" ]; then
    echo "not_found"
  elif [ "$status" = "405" ]; then
    echo "method_not_allowed"
  elif [ "$status" = "429" ]; then
    echo "rate_limited"
  elif [ "$status" = "500" ]; then
    echo "server_error"
  else
    echo "other"
  fi
}

# ─── Smart filtering engine ──────────────────────────────────────
filter_results() {
  local results="$1" filter_mode="${2:-all}"
  local unique_urls unique_statuses

  case "$filter_mode" in
    all)
      echo "$results"
      ;;
    unique-url)
      echo "$results" | sort -t'|' -k3 -u
      ;;
    unique-status)
      echo "$results" | sort -t'|' -k1 -u
      ;;
    errors)
      echo "$results" | grep -E '^(5[0-9][0-9])'
      ;;
    accessible)
      echo "$results" | grep -E '^(200|201|202|204)'
      ;;
    redirects)
      echo "$results" | grep -E '^(301|302|303|307|308)'
      ;;
    restricted)
      echo "$results" | grep -E '^(401|403)'
      ;;
    large)
      echo "$results" | awk -F'|' '{if ($2 > 10000) print}'
      ;;
    small)
      echo "$results" | awk -F'|' '{if ($2 > 0 && $2 < 100) print}'
      ;;
    *)
      echo "$results"
      ;;
  esac
}

# ─── Generate report from fuzz results ───────────────────────────
generate_fuzz_report() {
  local target="$1" results="$2" mode="$3"
  local output="${OUTPUT_FILE:-/tmp/fuzz-report-$(date +%s).md}"

  cat > "$output" <<REPORT
# Endpoint Fuzzing Report

**Target:** ${target}
**Mode:** ${mode}
**Date:** $(date -u '+%Y-%m-%dT%H:%M:%SZ')
**Tool:** ${SCRIPT_NAME} v${VERSION}

## Summary

- Fuzzing mode: ${mode}
- Output filter: Status codes ${FILTER_CODES}
- Concurrency: ${CONCURRENCY}
- Timeout: ${TIMEOUT}s

## Discovered Endpoints

| Method | Status | Size | URL |
|--------|--------|------|-----|
$(echo "$results" | while IFS='|||' read -r status size time ct url; do
  echo "| GET | ${status} | ${size}b | ${url} |"
done)

---

*Generated by ${SCRIPT_NAME}*
REPORT
  ok "Report generated: ${output}"
}

# ─── Configuration validation ────────────────────────────────────
validate_target() {
  local url="$1"
  if [ -z "$url" ]; then
    err "Empty URL provided"
    return 1
  fi
  if ! echo "$url" | grep -qE '^https?://'; then
    err "URL must start with http:// or https://"
    return 1
  fi
  ok "URL validated: ${url}"
}

# ─── Outlier detection ──────────────────────────────────────────
detect_outliers() {
  local results="$1"
  local total statuses sizes

  total=$(echo "$results" | grep -c '|||' || true)
  [ "$total" -lt 3 ] && return

  statuses=$(echo "$results" | cut -d'|' -f1 | sort | uniq -c | sort -rn)
  sizes=$(echo "$results" | awk -F'|' '{print $2}' | sort -n | head -1)

  info "Status distribution:"
  echo "$statuses" | while IFS= read -r line; do
    [ -n "$line" ] && echo "  ${line}"
  done

  info "Smallest response: ${sizes}b"
}

# ─── Generate CSV output ────────────────────────────────────────
export_csv() {
  local results="$1" output="${2:-/tmp/fuzz-output.csv}"
  echo "method,status,size,time,content_type,url" > "$output"
  echo "$results" | while IFS='|||' read -r status size time ct url; do
    echo "GET,${status},${size},${time},${ct},${url}" >> "$output"
  done
  ok "CSV exported: ${output}"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  parse_args "$@"
  main
fi