#!/usr/bin/env bash
# =====================================================================
# extract-apis.sh — API Endpoint Discovery Tool
#
# Discovers API endpoints from HTML and JavaScript sources using curl,
# grep, sed, and pattern matching for REST, GraphQL, and SOAP endpoints.
# Outputs unique endpoints sorted by HTTP method with response analysis.
#
# Usage:
#   ./extract-apis.sh -u https://target.com
#   ./extract-apis.sh -f response.html
#   ./extract-apis.sh -u https://target.com -o endpoints.txt
# =====================================================================

set -euo pipefail

# ─── Constants ───────────────────────────────────────────────────
VERSION="1.0.0"
SCRIPT_NAME=$(basename "$0")
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ─── Temp file management ────────────────────────────────────────
CLEANUP_FILES=()
cleanup() {
  local exit_code=$?
  for f in "${CLEANUP_FILES[@]}"; do
    [ -f "$f" ] && rm -f "$f"
  done
  if [ $exit_code -ne 0 ] && [ $exit_code -ne 130 ]; then
    echo -e "${RED}[!]${NC} Script terminated with error code $exit_code" >&2
  fi
  exit $exit_code
}
trap cleanup EXIT INT TERM

_cleanup_add() { CLEANUP_FILES+=("$1"); }

# ─── Output helpers ──────────────────────────────────────────────
info()  { echo -e "${CYAN}[i]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*" >&2; }
err()   { echo -e "${RED}[-]${NC} $*" >&2; }

# ─── Usage ───────────────────────────────────────────────────────
usage() {
  cat <<EOF
${CYAN}extract-apis.sh${NC} v${VERSION} — API Endpoint Discovery Tool

${YELLOW}Description:${NC}
  Discovers REST, GraphQL, and SOAP API endpoints from HTML/JS sources.
  Analyzes URLs, links, scripts, and response bodies for API patterns.
  Outputs unique endpoints sorted by HTTP method.

${YELLOW}Usage:${NC}
  $SCRIPT_NAME -u <url>           Scan a live URL
  $SCRIPT_NAME -f <file>          Scan a local HTML/JS file
  $SCRIPT_NAME -d <directory>     Scan a directory of files
  $SCRIPT_NAME -h                 Show this help

${YELLOW}Options:${NC}
  -u <url>        Target URL to scan
  -f <file>       Local file to analyze
  -d <dir>        Directory of files to scan
  -o <file>       Output file for results (default: stdout)
  -m <method>     Filter by method (GET|POST|PUT|DELETE)
  -p <prefix>     URL prefix filter (e.g., https://api.target.com)
  -t <seconds>    Request timeout (default: 10)
  -c <file>       Cookie jar file
  -H <header>     Custom HTTP header (can be used multiple times)
  -q              Quiet mode (minimal output)
  --no-color      Disable color output
  -v              Verbose mode
  -h              Show this help

${YELLOW}Examples:${:-
  $SCRIPT_NAME -u https://example.com
  $SCRIPT_NAME -f index.html -o apis.txt
  $SCRIPT_NAME -u https://example.com -p https://api.example.com
EOF
  exit 0
}

# ─── Global options ──────────────────────────────────────────────
TARGET_URL=""
TARGET_FILE=""
TARGET_DIR=""
OUTPUT_FILE=""
METHOD_FILTER=""
PREFIX_FILTER=""
TIMEOUT=10
COOKIE_JAR=""
QUIET=false
NO_COLOR=false
VERBOSE=false
CUSTOM_HEADERS=()

# ─── Parse arguments ─────────────────────────────────────────────
parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help)
        usage
        ;;
      -u|--url)
        TARGET_URL="$2"; shift 2
        ;;
      -f|--file)
        TARGET_FILE="$2"; shift 2
        ;;
      -d|--directory)
        TARGET_DIR="$2"; shift 2
        ;;
      -o|--output)
        OUTPUT_FILE="$2"; shift 2
        ;;
      -m|--method)
        METHOD_FILTER="$2"; shift 2
        ;;
      -p|--prefix)
        PREFIX_FILTER="$2"; shift 2
        ;;
      -t|--timeout)
        TIMEOUT="$2"; shift 2
        ;;
      -c|--cookies)
        COOKIE_JAR="$2"; shift 2
        ;;
      -H|--header)
        CUSTOM_HEADERS+=("$2"); shift 2
        ;;
      -q|--quiet)
        QUIET=true; shift
        ;;
      --no-color)
        NO_COLOR=true
        RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
        shift
        ;;
      -v|--verbose)
        VERBOSE=true; shift
        ;;
      *)
        err "Unknown option: $1"
        usage
        ;;
    esac
  done

  if [ -z "$TARGET_URL" ] && [ -z "$TARGET_FILE" ] && [ -z "$TARGET_DIR" ]; then
    err "No target specified. Use -u, -f, or -d."
    usage
  fi

  if [ -n "$TARGET_URL" ] && [ -n "$TARGET_FILE" ]; then
    err "Specify either -u or -f, not both."
    exit 1
  fi
}

# ─── Dependency check ────────────────────────────────────────────
check_deps() {
  local deps=("curl" "grep" "sed" "awk" "sort" "uniq")
  local missing=()
  for d in "${deps[@]}"; do
    if ! command -v "$d" &>/dev/null; then
      missing+=("$d")
    fi
  done
  if [ ${#missing[@]} -gt 0 ]; then
    err "Missing dependencies: ${missing[*]}"
    exit 1
  fi
}

# ─── HTTP request helper ─────────────────────────────────────────
_http_get() {
  local url="$1"
  local tmpfile
  tmpfile=$(mktemp) && _cleanup_add "$tmpfile"

  local curl_args=(
    -sk
    --max-time "$TIMEOUT"
    -A "$USER_AGENT"
    -D "$tmpfile"
  )

  if [ -n "$COOKIE_JAR" ]; then
    curl_args+=(-b "$COOKIE_JAR" -c "$COOKIE_JAR")
  fi

  for h in "${CUSTOM_HEADERS[@]}"; do
    curl_args+=(-H "$h")
  done

  local body
  body=$(curl "${curl_args[@]}" "$url" 2>/dev/null) || {
    warn "Request failed: $url"
    echo ""
    return 1
  }

  local status_code
  status_code=$(head -1 "$tmpfile" | awk '{print $2}')
  local content_type
  content_type=$(grep -i '^content-type:' "$tmpfile" | sed 's/.*: //' | tr -d '\r')

  echo "$status_code|||$content_type|||$body"
}

# ─── URL normalization ───────────────────────────────────────────
_normalize_url() {
  local base="$1" rel="$2"
  # Remove fragment
  rel="${rel%%#*}"
  # If already absolute, return as-is
  if echo "$rel" | grep -qE '^https?://'; then
    echo "$rel"
    return
  fi
  # If protocol-relative
  if echo "$rel" | grep -qE '^//'; then
    local proto
    proto=$(echo "$base" | grep -oE '^https?')
    echo "${proto}:${rel}"
    return
  fi
  # Absolute path
  if echo "$rel" | grep -qE '^/'; then
    local base_url
    base_url=$(echo "$base" | grep -oE '^https?://[^/]+')
    echo "${base_url}${rel}"
    return
  fi
  # Relative path
  local base_dir
  base_dir=$(dirname "$base" | sed 's|/$||')
  echo "${base_dir}/${rel}"
}

# ─── Pattern compilation ─────────────────────────────────────────
_load_api_patterns() {
  # REST API patterns
  REST_PATTERNS=(
    '/api/'
    '/v1/'
    '/v2/'
    '/v3/'
    '/rest/'
    '/graphql'
    '/soap/'
    '/xmlrpc'
    '/jsonrpc'
    '/rpc/'
    '/service'
    '/services'
    '/endpoint'
    '/endpoints'
    '/_api'
    '/api-'
    '/swagger'
    '/openapi'
    '/docs'
    '/redoc'
    '/schema'
    '/graphiql'
    '/voyager'
    '/playground'
  )

  # Method keywords
  METHOD_KEYWORDS=(
    'GET'
    'POST'
    'PUT'
    'PATCH'
    'DELETE'
    'HEAD'
    'OPTIONS'
  )

  # Common API file extensions
  API_EXTENSIONS=(
    '.json'
    '.xml'
    '.yaml'
    '.yml'
    '.proto'
    '.graphql'
    '.gql'
    '.soap'
    '.wsdl'
    '.xsd'
  )

  # Secret/high-value patterns
  SECRET_PATTERNS=(
    'api[_-]?key'
    'api[_-]?secret'
    'api[_-]?token'
    'bearer'
    'jwt'
    'authorization'
    'x-api-key'
    'x-auth-token'
    'client[_-]?id'
    'client[_-]?secret'
    'access[_-]?token'
    'refresh[_-]?token'
  )
}

# ─── Extract endpoints from HTML content ─────────────────────────
extract_from_html() {
  local content="$1" base_url="$2"
  local tmp
  tmp=$(mktemp) && _cleanup_add "$tmp"

  # Extract from <a href="...">
  echo "$content" | grep -oP 'href="[^"]*"' | sed 's/href="//;s/"$//' >> "$tmp"

  # Extract from <form action="...">
  echo "$content" | grep -oP 'action="[^"]*"' | sed 's/action="//;s/"$//' >> "$tmp"

  # Extract from <script src="...">
  echo "$content" | grep -oP 'src="[^"]*"' | sed 's/src="//;s/"$//' >> "$tmp"

  # Extract from data-* attributes with URLs
  echo "$content" | grep -oP 'data-[a-z-]+="[^"]*"' | grep -oP 'https?://[^"]*' >> "$tmp"

  # Extract fetch/ajax calls
  echo "$content" | grep -oP "(fetch|axios|ajax|XMLHttpRequest)\(['\"][^'\"]*['\"]" | grep -oP "['\"][^'\"]*['\"]" | tr -d "'\"" >> "$tmp"

  # Extract $.ajax/$get/$post URLs
  echo "$content" | grep -oP '\$\.(get|post|ajax)\(['\"][^'\"]*['\"]' | grep -oP "['\"][^'\"]*['\"]" | tr -d "'\"" >> "$tmp"

  # Normalize URLs
  local normalized=""
  while IFS= read -r url; do
    [ -z "$url" ] && continue
    local abs
    abs=$(_normalize_url "$base_url" "$url")
    echo "$abs"
  done < "$tmp" | sort -u
}

# ─── Extract endpoints from JS content ───────────────────────────
extract_from_js() {
  local content="$1" base_url="$2"
  local tmp
  tmp=$(mktemp) && _cleanup_add "$tmp"

  # Extract string literals containing URLs
  echo "$content" | grep -oP "['\"](https?://[^'\"]*)['\"]" | tr -d "'\"" >> "$tmp"

  # Extract template literals with URLs
  echo "$content" | grep -oP '\`https?://[^\`]*\`' | sed 's/^`//;s/`$//' >> "$tmp"

  # Extract paths from API service definitions
  echo "$content" | grep -oP "path:\s*['\"][^'\"]*['\"]" | grep -oP "['\"][^'\"]*['\"]" | tr -d "'\"" >> "$tmp"

  # Extract from route definitions
  echo "$content" | grep -oP "route[s]?\s*[:=]\s*['\"][^'\"]*['\"]" | grep -oP "['\"][^'\"]*['\"]" | tr -d "'\"" >> "$tmp"

  # Extract URLs from object literals
  echo "$content" | grep -oP "(url|endpoint|baseURL|baseUrl|apiUrl):\s*['\"][^'\"]*['\"]" | grep -oP "['\"][^'\"]*['\"]" | tr -d "'\"" >> "$tmp"

  # Extract from axios/fetch config objects
  echo "$content" | grep -oP "method:\s*['\"][A-Z]*['\"]" >> "$tmp"

  # Extract GraphQL operations
  echo "$content" | grep -oP "(query|mutation|subscription)\s+\w+" >> "$tmp"

  # Extract endpoint patterns in strings
  echo "$content" | grep -oP "['\"]/[a-zA-Z0-9_/.-]*['\"]" | tr -d "'\"" | grep -E '^/' >> "$tmp"

  # Normalize
  local normalized=""
  while IFS= read -r url; do
    [ -z "$url" ] && continue
    local abs
    abs=$(_normalize_url "$base_url" "$url")
    echo "$abs"
  done < "$tmp" | sort -u
}

# ─── Classify endpoint type ──────────────────────────────────────
classify_endpoint() {
  local url="$1"

  if echo "$url" | grep -qi '/graphql\|/graphiql\|/voyager'; then
    echo "GraphQL"
  elif echo "$url" | grep -qi '/soap\|/wsdl\|\.wsdl\|\.xsd'; then
    echo "SOAP"
  elif echo "$url" | grep -qi '/api/\|/rest/\|/v[0-9]/'; then
    echo "REST"
  elif echo "$url" | grep -qi '/xmlrpc\|/jsonrpc\|/rpc/'; then
    echo "RPC"
  elif echo "$url" | grep -qi '/swagger\|/openapi\|/docs\|/redoc'; then
    echo "API-Docs"
  else
    echo "Unknown"
  fi
}

# ─── Guess HTTP method from context ──────────────────────────────
guess_method() {
  local url="$1" context="$2"

  # Check for mutation keywords in GraphQL
  if echo "$context" | grep -qi 'mutation'; then
    echo "POST"
    return
  fi

  # Check for write operations
  if echo "$url" | grep -qiE '/create|/add|/new|/insert|/post'; then
    echo "POST"
    return
  fi
  if echo "$url" | grep -qiE '/update|/edit|/modify|/change|/put'; then
    echo "PUT"
    return
  fi
  if echo "$url" | grep -qiE '/delete|/remove|/destroy|/del'; then
    echo "DELETE"
    return
  fi
  if echo "$url" | grep -qiE '/login|/auth|/token|/oauth|/refresh'; then
    echo "POST"
    return
  fi

  echo "GET"
}

# ─── Probe endpoint method support ───────────────────────────────
probe_methods() {
  local url="$1"
  local methods=("GET" "POST" "PUT" "PATCH" "DELETE" "HEAD" "OPTIONS")
  local supported=()
  local tmpfile
  tmpfile=$(mktemp) && _cleanup_add "$tmpfile"

  for m in "${methods[@]}"; do
    local status
    status=$(curl -sk --max-time "$TIMEOUT" -X "$m" -A "$USER_AGENT" \
      -o /dev/null -w "%{http_code}" "$url" 2>/dev/null) || continue
    [ "$status" != "405" ] && [ "$status" != "000" ] && supported+=("$m ($status)")
  done

  echo "${supported[*]:-None}"
}

# ─── Analyze response for endpoint info ──────────────────────────
analyze_response() {
  local url="$1"
  local result
  result=$(_http_get "$url") || return 1

  local status_code content_type body
  status_code=$(echo "$result" | head -1)
  content_type=$(echo "$result" | head -2 | tail -1)
  body=$(echo "$result" | cut -d'|' -f7-)

  # Detect response format
  local format="unknown"
  if echo "$content_type" | grep -qi 'json'; then
    format="JSON"
  elif echo "$content_type" | grep -qi 'xml'; then
    format="XML"
  elif echo "$content_type" | grep -qi 'html'; then
    format="HTML"
  elif echo "$content_type" | grep -qi 'text'; then
    format="Text"
  fi

  local body_len=${#body}
  local methods
  methods=$(probe_methods "$url")

  echo "$status_code|||$format|||$body_len|||$methods|||$content_type"
}

# ─── Scan a single source ────────────────────────────────────────
scan_content() {
  local content="$1" source="$2" base_url="$3"

  local html_endpoints js_endpoints combined
  html_endpoints=$(extract_from_html "$content" "$base_url")
  js_endpoints=$(extract_from_js "$content" "$base_url")

  combined=$( (echo "$html_endpoints"; echo "$js_endpoints") | sort -u )

  [ "$QUIET" = false ] && info "Found $(echo "$combined" | grep -cE 'https?://') unique URLs in $source"

  local endpoint_type matched=""

  while IFS= read -r url; do
    [ -z "$url" ] && continue

    # Apply prefix filter
    if [ -n "$PREFIX_FILTER" ]; then
      if ! echo "$url" | grep -q "^$PREFIX_FILTER"; then
        continue
      fi
    fi

    # Check if it matches API patterns
    endpoint_type=$(classify_endpoint "$url")
    [ "$endpoint_type" = "Unknown" ] && continue

    # Guess method
    local method
    method=$(guess_method "$url" "$content")

    # Apply method filter
    if [ -n "$METHOD_FILTER" ] && [ "$method" != "$METHOD_FILTER" ]; then
      continue
    fi

    echo "$method|||$endpoint_type|||$url"
    matched="yes"
  done <<< "$combined"

  if [ -z "$matched" ]; then
    [ "$QUIET" = false ] && warn "No API endpoints found in $source"
  fi
}

# ─── Scan a live URL ─────────────────────────────────────────────
scan_url() {
  local url="$1"
  info "Scanning URL: $url"

  local result
  result=$(_http_get "$url") || {
    err "Failed to fetch $url"
    return 1
  }

  local status_code content_type body
  status_code=$(echo "$result" | cut -d'|' -f1)
  content_type=$(echo "$result" | cut -d'|' -f3)
  body=$(echo "$result" | cut -d'|' -f7-)

  [ "$QUIET" = false ] && ok "HTTP $status_code | Content-Type: $content_type"

  # Scan the main page
  scan_content "$body" "$url" "$url"

  # If HTML, also find and scan linked JS files
  if echo "$content_type" | grep -qi 'html'; then
    local js_urls
    js_urls=$(echo "$body" | grep -oP 'src="[^"]*\.js[^"]*"' | sed 's/src="//;s/"$//')
    while IFS= read -r js_url; do
      [ -z "$js_url" ] && continue
      local abs_js_url
      abs_js_url=$(_normalize_url "$url" "$js_url")
      info "Scanning linked JS: $abs_js_url"
      local js_result
      js_result=$(_http_get "$abs_js_url") || continue
      local js_body
      js_body=$(echo "$js_result" | cut -d'|' -f7-)
      scan_content "$js_body" "$abs_js_url" "$url"
    done <<< "$js_urls"
  fi
}

# ─── Scan a local file ───────────────────────────────────────────
scan_file() {
  local file="$1"
  if [ ! -f "$file" ]; then
    err "File not found: $file"
    return 1
  fi

  local content
  content=$(cat "$file")
  info "Scanning file: $file ($(wc -c < "$file") bytes)"

  scan_content "$content" "$file" "file://$file"
}

# ─── Scan a directory ────────────────────────────────────────────
scan_dir() {
  local dir="$1"
  if [ ! -d "$dir" ]; then
    err "Directory not found: $dir"
    return 1
  fi

  info "Scanning directory: $dir"
  local files
  files=$(find "$dir" -type f \( -name '*.html' -o -name '*.js' -o -name '*.json' -o -name '*.xml' -o -name '*.htm' \) 2>/dev/null) || true

  local count=0
  while IFS= read -r file; do
    [ -z "$file" ] && continue
    count=$((count + 1))
    scan_file "$file"
  done <<< "$files"

  if [ "$count" -eq 0 ]; then
    warn "No HTML/JS/JSON/XML files found in $dir"
  else
    info "Scanned $count files"
  fi
}

# ─── Output results ──────────────────────────────────────────────
output_results() {
  local results="$1"

  if [ -n "$OUTPUT_FILE" ]; then
    echo "$results" > "$OUTPUT_FILE"
    ok "Results written to $OUTPUT_FILE"
  else
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Discovered API Endpoints${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

    # Count by type
    local rest_count gql_count soap_count rpc_count docs_count
    rest_count=$(echo "$results" | grep -c '|||REST|||' || true)
    gql_count=$(echo "$results" | grep -c '|||GraphQL|||' || true)
    soap_count=$(echo "$results" | grep -c '|||SOAP|||' || true)
    rpc_count=$(echo "$results" | grep -c '|||RPC|||' || true)
    docs_count=$(echo "$results" | grep -c '|||API-Docs|||' || true)

    echo -e "  ${YELLOW}REST:${NC}     $rest_count"
    echo -e "  ${YELLOW}GraphQL:${NC}  $gql_count"
    echo -e "  ${YELLOW}SOAP:${NC}     $soap_count"
    echo -e "  ${YELLOW}RPC:${NC}      $rpc_count"
    echo -e "  ${YELLOW}API-Docs:${NC} $docs_count"
    echo ""

    # Print results grouped by type
    local current_type=""
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      local method endpoint_type url
      method=$(echo "$line" | cut -d'|' -f1)
      endpoint_type=$(echo "$line" | cut -d'|' -f3)
      url=$(echo "$line" | cut -d'|' -f5)

      if [ "$endpoint_type" != "$current_type" ]; then
        current_type="$endpoint_type"
        echo -e "${CYAN}── ${endpoint_type} ──${NC}"
      fi

      # Color by method
      case "$method" in
        GET)    echo -e "  ${GREEN}GET${NC}     $url" ;;
        POST)   echo -e "  ${YELLOW}POST${NC}    $url" ;;
        PUT)    echo -e "  ${BLUE}PUT${NC}     $url" ;;
        DELETE) echo -e "  ${RED}DELETE${NC}  $url" ;;
        PATCH)  echo -e "  ${CYAN}PATCH${NC}   $url" ;;
        *)      echo -e "  $method  $url" ;;
      esac
    done <<< "$results"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    ok "Total: $(echo "$results" | grep -c '|||' || true) API endpoints discovered"
  fi
}

# ─── Main entry point ────────────────────────────────────────────
main() {
  check_deps
  _load_api_patterns

  local all_results=""

  if [ -n "$TARGET_URL" ]; then
    all_results=$(scan_url "$TARGET_URL")
  elif [ -n "$TARGET_FILE" ]; then
    all_results=$(scan_file "$TARGET_FILE")
  elif [ -n "$TARGET_DIR" ]; then
    all_results=$(scan_dir "$TARGET_DIR")
  fi

  # Sort and deduplicate results by URL
  local sorted_results
  sorted_results=$(echo "$all_results" | sort -t'|' -k5 -u | sort -t'|' -k1)

  output_results "$sorted_results"
}

# ─── Arguments passthrough ───────────────────────────────────────
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  parse_args "$@"
  main
fi
