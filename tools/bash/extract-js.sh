#!/usr/bin/env bash
# =====================================================================
# extract-js.sh — JavaScript Extraction and Analysis Tool
#
# Extracts inline JS from HTML pages, discovers external JS URLs,
# downloads JS files, and greps for secrets, API keys, and endpoints.
# Provides color-coded output for all findings.
#
# Usage:
#   ./extract-js.sh -u https://target.com
#   ./extract-js.sh -f bundle.js
#   ./extract-js.sh -u https://target.com -o results/
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
NC='\033[0m'

# Patterns for secret discovery
SECRET_PATTERNS=(
  'AIza[0-9A-Za-z\-_]{35}'            # Google API Key
  'AKIA[0-9A-Z]{16}'                   # AWS Access Key
  'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'  # JWT
  '-----BEGIN (RSA |EC )?PRIVATE KEY-----'  # Private key
  'sk_live_[0-9a-zA-Z]{10,}'           # Stripe live key
  'pk_live_[0-9a-zA-Z]{10,}'           # Stripe live publishable
  'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}'  # SendGrid
  'ghp_[a-zA-Z0-9]{36}'                # GitHub PAT
  'gho_[a-zA-Z0-9]{36}'                # GitHub OAuth
  'github_pat_[a-zA-Z0-9]{84}'         # GitHub Fine-grained PAT
  'xox[baprs]-[a-zA-Z0-9\-]{24}'      # Slack token
  'sk-[a-zA-Z0-9]{20,}'               # OpenAI key
  'api[_-]?key\s*[:=]\s*["'"'"'][a-zA-Z0-9_\-]{10,}["'"'"']'
  'secret\s*[:=]\s*["'"'"'][a-zA-Z0-9_\-]{10,}["'"'"']'
  'password\s*[:=]\s*["'"'"'][^"'"'"']{4,}["'"'"']'
  'token\s*[:=]\s*["'"'"'][a-zA-Z0-9_\-\.]{10,}["'"'"']'
  'bearer\s+[a-zA-Z0-9_\-\.]{10,}'
  'authorization\s*[:=]\s*["'"'"'][a-zA-Z0-9_\-\.]{10,}["'"'"']'
  'mongodb(?:\+srv)?://[^\s"'"'"']+'
  'postgresql://[^\s"'"'"']+'
  'mysql://[^\s"'"'"']+'
  'redis://[^\s"'"'"']+'
  'firebase(?:url|io)\s*[:=]\s*["'"'"'][^\s"'"'"']+["'"'"']'
  's3\.amazonaws\.com/[a-zA-Z0-9\-_]+'
  'storage\.googleapis\.com/[a-zA-Z0-9\-_]+'
  '\.blob\.core\.windows\.net/[a-zA-Z0-9\-_]+'
  'SUPABASE_[A-Z_]{3,}'
  'STRIPE_[A-Z_]{3,}'
  'process\.env\.(?:[A-Z_]{3,})'
  'import\.meta\.env\.(?:[A-Z_]{3,})'
)

ENDPOINT_PATTERNS=(
  "['\"]/api/[^'\"]*['\"]"
  "['\"]/v[0-9]/[^'\"]*['\"]"
  "['\"]/graphql['\"]"
  "['\"]/rest/[^'\"]*['\"]"
  "['\"]/service[^'\"]*['\"]"
  "['\"]/oauth[^'\"]*['\"]"
  "['\"]/auth[^'\"]*['\"]"
)

# ─── Temp file management ────────────────────────────────────────
CLEANUP_FILES=()
cleanup() {
  local exit_code=$?
  for f in "${CLEANUP_FILES[@]}"; do
    [ -f "$f" ] && rm -f "$f"
  done
  [ $exit_code -ne 0 ] && [ $exit_code -ne 130 ] && echo -e "${RED}[!]${NC} Script terminated (exit $exit_code)" >&2
  exit $exit_code
}
trap cleanup EXIT INT TERM
_cleanup_add() { CLEANUP_FILES+=("$1"); }

# ─── Output helpers ──────────────────────────────────────────────
info()   { echo -e "${CYAN}[i]${NC} $*"; }
ok()     { echo -e "${GREEN}[+]${NC} $*"; }
warn()   { echo -e "${YELLOW}[!]${NC} $*" >&2; }
err()    { echo -e "${RED}[-]${NC} $*" >&2; }
secret() { echo -e "${RED}[SECRET]${NC} $*"; }
endpt()  { echo -e "${GREEN}[ENDPOINT]${NC} $*"; }
jsinfo() { echo -e "${CYAN}[JS]${NC} $*"; }
danger() { echo -e "${RED}[CRITICAL]${NC} $*"; }

# ─── Usage ───────────────────────────────────────────────────────
usage() {
  cat <<EOF
${CYAN}extract-js.sh${NC} v${VERSION} — JavaScript Extraction and Analysis Tool

${YELLOW}Description:${NC}
  Extracts inline JavaScript from HTML pages, discovers external JS URLs,
  downloads JS files, and searches for secrets, API keys, and endpoints.
  Supports recursive crawling through linked JS files.

${YELLOW}Usage:${NC}
  $SCRIPT_NAME -u <url>           Analyze a web page
  $SCRIPT_NAME -f <js-file>       Analyze a local JS file
  $SCRIPT_NAME -l <url>           Download and analyze a JS file
  $SCRIPT_NAME -h                 Show this help

${YELLOW}Options:${NC}
  -u <url>        URL to analyze (HTML page with JS)
  -f <file>       Local JS file to analyze
  -l <url>        Download and analyze remote JS file
  -o <dir>        Output directory for downloaded files
  -r <url>        Referrer URL for JS downloads
  -d <depth>      Recursion depth for linked JS (default: 1)
  -t <seconds>    Request timeout (default: 10)
  -q              Quiet mode
  --no-color      Disable color output
  --no-download   Don't download external JS, only list
  --no-secrets    Skip secret scanning
  --no-endpoints  Skip endpoint scanning
  --only-critical Only show critical findings (secrets, keys)
  -v              Verbose mode
  -h              Show this help

${YELLOW}Examples:${NC}
  $SCRIPT_NAME -u https://example.com
  $SCRIPT_NAME -f app.bundle.js -o findings/
  $SCRIPT_NAME -u https://example.com --no-secrets
EOF
  exit 0
}

# ─── Global options ──────────────────────────────────────────────
TARGET_URL=""
TARGET_FILE=""
LINKED_JS_URL=""
OUTPUT_DIR=""
REFERRER=""
MAX_DEPTH=1
TIMEOUT=10
QUIET=false
NO_COLOR=false
NO_DOWNLOAD=false
NO_SECRETS=false
NO_ENDPOINTS=false
ONLY_CRITICAL=false
VERBOSE=false

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help) usage ;;
      -u|--url) TARGET_URL="$2"; shift 2 ;;
      -f|--file) TARGET_FILE="$2"; shift 2 ;;
      -l|--linked-js) LINKED_JS_URL="$2"; shift 2 ;;
      -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
      -r|--referrer) REFERRER="$2"; shift 2 ;;
      -d|--depth) MAX_DEPTH="$2"; shift 2 ;;
      -t|--timeout) TIMEOUT="$2"; shift 2 ;;
      -q|--quiet) QUIET=true; shift ;;
      --no-color) NO_COLOR=true; RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; shift ;;
      --no-download) NO_DOWNLOAD=true; shift ;;
      --no-secrets) NO_SECRETS=true; shift ;;
      --no-endpoints) NO_ENDPOINTS=true; shift ;;
      --only-critical) ONLY_CRITICAL=true; shift ;;
      -v|--verbose) VERBOSE=true; shift ;;
      *) err "Unknown option: $1"; usage ;;
    esac
  done
  if [ -z "$TARGET_URL" ] && [ -z "$TARGET_FILE" ] && [ -z "$LINKED_JS_URL" ]; then
    err "No target specified. Use -u, -f, or -l."
    usage
  fi
}

check_deps() {
  local deps=("curl" "grep" "sed" "awk" "sort" "uniq")
  local missing=()
  for d in "${deps[@]}"; do
    command -v "$d" &>/dev/null || missing+=("$d")
  done
  [ ${#missing[@]} -gt 0 ] && { err "Missing: ${missing[*]}"; exit 1; }
}

# ─── URL normalization ───────────────────────────────────────────
_normalize_url() {
  local base="$1" rel="$2"
  rel="${rel%%#*}"
  echo "$rel" | grep -qE '^https?://' && { echo "$rel"; return; }
  echo "$rel" | grep -qE '^//' && { local p; p=$(echo "$base" | grep -oE '^https?'); echo "${p}:${rel}"; return; }
  echo "$rel" | grep -qE '^/' && { local b; b=$(echo "$base" | grep -oE '^https?://[^/]+'); echo "${b}${rel}"; return; }
  local d; d=$(dirname "$base" | sed 's|/$||')
  echo "${d}/${rel}"
}

# ─── Fetch content ───────────────────────────────────────────────
_http_get() {
  local url="$1" tmpfile
  tmpfile=$(mktemp) && _cleanup_add "$tmpfile"
  local sc ct body
  curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" \
    ${REFERRER:+-e "$REFERRER"} \
    -D "$tmpfile" "$url" 2>/dev/null || { warn "Fetch failed: $url"; return 1; }
  sc=$(head -1 "$tmpfile" | awk '{print $2}')
  ct=$(grep -i '^content-type:' "$tmpfile" | sed 's/.*: //' | tr -d '\r')
  body=$(curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" "$url" 2>/dev/null)
  echo "$sc|||$ct|||$body"
}

# ─── Extract inline JS from HTML ─────────────────────────────────
extract_inline_js() {
  local html="$1" tmp
  tmp=$(mktemp) && _cleanup_add "$tmp"
  echo "$html" | grep -oP '<script[^>]*>\s*//<!\[CDATA\[([\s\S]*?)//\]\]>\s*</script>' | sed 's/<script[^>]*>//;s/<\/script>//' >> "$tmp"
  echo "$html" | grep -oP '<script[^>]*>(?!\s*//<!\[CDATA\[)([\s\S]*?)</script>' | sed 's/<script[^>]*>//;s/<\/script>//' >> "$tmp"
  echo "$html" | grep -oP 'on\w+="[^"]*"' >> "$tmp"
  echo "$html" | grep -oP 'href="javascript:[^"]*"' | sed 's/href="//;s/"$//' >> "$tmp"
  cat "$tmp" 2>/dev/null
}

# ─── Extract external JS URLs from HTML ──────────────────────────
extract_external_js() {
  local html="$1" base_url="$2" tmp
  tmp=$(mktemp) && _cleanup_add "$tmp"
  echo "$html" | grep -oP '<script[^>]+src="[^"]*"[^>]*>' | grep -oP 'src="[^"]*"' | sed 's/src="//;s/"$//' >> "$tmp"
  echo "$html" | grep -oP "src='[^']*'" | grep -oP "'[^']*'" | tr -d "'" >> "$tmp"
  local result=""
  while IFS= read -r url; do
    [ -z "$url" ] && continue
    _normalize_url "$base_url" "$url"
  done < "$tmp" | sort -u
}

# ─── Deobfuscation helpers ───────────────────────────────────────
deobfuscate_hex_strings() {
  local content="$1"
  echo "$content" | sed 's/\\x[0-9a-fA-F]\{2\}/ /g'
}

decode_base64_segments() {
  local content="$1" tmp
  tmp=$(mktemp) && _cleanup_add "$tmp"
  echo "$content" | grep -oP '"[a-zA-Z0-9+/]{20,}={0,2}"' | tr -d '"' | while IFS= read -r b64; do
    local decoded
    decoded=$(echo "$b64" | base64 -d 2>/dev/null) || continue
    [ ${#decoded} -gt 10 ] && echo "$decoded"
  done
}

# ─── Scan JS for secrets ─────────────────────────────────────────
scan_secrets() {
  local content="$1" source="$2" found=false
  for pattern in "${SECRET_PATTERNS[@]}"; do
    while IFS= read -r match; do
      [ -z "$match" ] && continue
      local display="${match:0:120}"
      secret "Found in ${source}: ${display}"
      found=true
    done < <(echo "$content" | grep -oP "$pattern" | sort -u || true)
  done
  # Also check base64-decoded content
  local decoded
  decoded=$(decode_base64_segments "$content")
  if [ -n "$decoded" ]; then
    for pattern in "${SECRET_PATTERNS[@]}"; do
      while IFS= read -r match; do
        [ -z "$match" ] && continue
        danger "Secret in base64 segment in ${source}: ${match:0:120}"
        found=true
      done < <(echo "$decoded" | grep -oP "$pattern" | sort -u || true)
    done
  fi
  $found
}

# ─── Scan JS for endpoints ───────────────────────────────────────
scan_endpoints() {
  local content="$1" source="$2" found=false
  for pattern in "${ENDPOINT_PATTERNS[@]}"; do
    while IFS= read -r match; do
      [ -z "$match" ] && continue
      local cleaned
      cleaned=$(echo "$match" | tr -d "'\"")
      endpt "Found in ${source}: ${cleaned}"
      found=true
    done < <(echo "$content" | grep -oP "$pattern" | sort -u || true)
  done
  $found
}

# ─── Scan for hardcoded strings ──────────────────────────────────
scan_hardcoded() {
  local content="$1" source="$2"
  local urls emails ips internal_paths

  urls=$(echo "$content" | grep -oP '(https?|ftp|wss?)://[a-zA-Z0-9./?=&#_\-~%]+' | sort -u | head -50)
  if [ -n "$urls" ]; then
    [ "$QUIET" = false ] && jsinfo "URLs found in ${source}:"
    while IFS= read -r u; do [ -n "$u" ] && echo "  $u"; done <<< "$urls"
  fi

  emails=$(echo "$content" | grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sort -u | head -20)
  if [ -n "$emails" ]; then
    [ "$QUIET" = false ] && jsinfo "Emails in ${source}:"
    while IFS= read -r e; do [ -n "$e" ] && echo "  $e"; done <<< "$emails"
  fi

  ips=$(echo "$content" | grep -oP '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -u | head -20)
  if [ -n "$ips" ]; then
    [ "$QUIET" = false ] && jsinfo "IPs in ${source}:"
    while IFS= read -r ip; do [ -n "$ip" ] && echo "  $ip"; done <<< "$ips"
  fi

  internal_paths=$(echo "$content" | grep -oP "['\"](/[a-zA-Z0-9_/.-]+)['\"]" | tr -d "'\"" | grep -vE '^/(https?://)' | sort -u | head -50)
  if [ -n "$internal_paths" ]; then
    [ "$QUIET" = false ] && jsinfo "Internal paths in ${source}:"
    while IFS= read -r p; do [ -n "$p" ] && echo "  $p"; done <<< "$internal_paths"
  fi
}

# ─── Analyze bundle structure ────────────────────────────────────
analyze_bundle() {
  local content="$1" source="$2" modules=""
  echo "$content" | grep -q 'define(' && modules="${modules} AMD"
  echo "$content" | grep -q 'require(' && modules="${modules} CommonJS"
  echo "$content" | grep -q 'import ' && modules="${modules} ES6"
  echo "$content" | grep -q '__webpack_require__' && modules="${modules} Webpack"
  echo "$content" | grep -q 'System\.register' && modules="${modules} SystemJS"
  [ -n "$modules" ] && [ "$QUIET" = false ] && jsinfo "${source} modules:${modules}"

  local func_count size
  func_count=$(echo "$content" | grep -cE '(function |=>|async )' || true)
  size=$(echo "$content" | wc -c)
  [ "$QUIET" = false ] && echo -e "  ${CYAN}Size:${NC} ${size}b, ${CYAN}Functions:${NC} ~${func_count}"

  if echo "$content" | grep -qE 'sourceMappingURL|sourceMap'; then
    jsinfo "${source}: Has source map"
  fi

  if echo "$content" | grep -qE '_0x[a-f0-9]{4,6}'; then
    warn "${source}: Likely obfuscated"
  fi

  local long_lines
  long_lines=$(echo "$content" | awk 'length > 1000' | wc -l)
  [ "$long_lines" -gt 20 ] && [ "$QUIET" = false ] && jsinfo "${source}: ${long_lines} long lines (minified)"

  # Detect eval usage
  local eval_count
  eval_count=$(echo "$content" | grep -cE '\beval\s*\(' || true)
  [ "$eval_count" -gt 0 ] && warn "${source}: eval() used ${eval_count} times"

  # Detect setTimeout with string argument (eval-like)
  local sto_count
  sto_count=$(echo "$content" | grep -cP 'setTimeout\s*\(\s*["'\'']' || true)
  [ "$sto_count" -gt 0 ] && warn "${source}: setTimeout() with string arg ${sto_count} times"

  # Detect Function constructor
  local func_ctor
  func_ctor=$(echo "$content" | grep -cP 'new\s+Function\s*\(' || true)
  [ "$func_ctor" -gt 0 ] && warn "${source}: Function() constructor used ${func_ctor} times"

  # Detect document.write
  local doc_write
  doc_write=$(echo "$content" | grep -cP 'document\.write\s*\(' || true)
  [ "$doc_write" -gt 0 ] && warn "${source}: document.write() used ${doc_write} times"

  # Detect innerHTML
  local inner_html
  inner_html=$(echo "$content" | grep -cP '\.innerHTML\s*=' || true)
  [ "$inner_html" -gt 0 ] && warn "${source}: innerHTML assignment ${inner_html} times"
}

# ─── Process JS content ──────────────────────────────────────────
process_js_content() {
  local content="$1" source="$2"
  analyze_bundle "$content" "$source"
  [ "$NO_SECRETS" = false ] && scan_secrets "$content" "$source"
  [ "$NO_ENDPOINTS" = false ] && scan_endpoints "$content" "$source"
  scan_hardcoded "$content" "$source"
  if [ -n "$OUTPUT_DIR" ] && [ -d "$OUTPUT_DIR" ]; then
    local safe_name
    safe_name=$(echo "$source" | sed 's|https\?://||;s|/|_|g;s|[^a-zA-Z0-9._-]|_|g')
    echo "$content" > "${OUTPUT_DIR}/${safe_name}"
    ok "Saved: ${OUTPUT_DIR}/${safe_name}"
  fi
}

# ─── Process a URL (HTML page) ───────────────────────────────────
process_url() {
  local url="$1" depth="${2:-1}"
  info "Fetching: $url"
  local result
  result=$(_http_get "$url") || return 1
  local status_code content_type body
  status_code=$(echo "$result" | cut -d'|' -f1)
  content_type=$(echo "$result" | cut -d'|' -f3)
  body=$(echo "$result" | cut -d'|' -f7-)
  ok "HTTP $status_code | $content_type"

  local inline_js
  inline_js=$(extract_inline_js "$body")
  [ -n "$inline_js" ] && process_js_content "$inline_js" "${url} (inline)"

  if [ "$NO_DOWNLOAD" = false ] && [ "$depth" -le "$MAX_DEPTH" ]; then
    local external_js
    external_js=$(extract_external_js "$body" "$url")
    if [ -n "$external_js" ]; then
      info "External JS:"
      echo "$external_js" | while IFS= read -r js_url; do
        [ -z "$js_url" ] && continue
        echo "  $js_url"
        process_linked_js "$js_url" "$url" $((depth + 1))
      done
    fi
  fi

  local event_handlers
  event_handlers=$(echo "$body" | grep -oP 'on\w+="[^"]{10,}"' | head -30)
  if [ -n "$event_handlers" ]; then
    local handler_js=""
    while IFS= read -r h; do [ -n "$h" ] && handler_js="${handler_js}${h}; "; done <<< "$event_handlers"
    process_js_content "$handler_js" "${url} (event handlers)"
  fi
}

# ─── Process linked JS ───────────────────────────────────────────
process_linked_js() {
  local js_url="$1" referrer="$2" depth="${3:-1}"
  [ "$depth" -gt "$MAX_DEPTH" ] && return
  jsinfo "Fetching JS: $js_url"
  local result
  result=$(_http_get "$js_url") || return 1
  local status_code content_type body
  status_code=$(echo "$result" | cut -d'|' -f1)
  content_type=$(echo "$result" | cut -d'|' -f3)
  body=$(echo "$result" | cut -d'|' -f7-)
  [ "$status_code" != "200" ] && { warn "HTTP $status_code for $js_url"; return; }
  process_js_content "$body" "$js_url"
  if [ "$depth" -lt "$MAX_DEPTH" ]; then
    local more_js
    more_js=$(echo "$body" | grep -oP "['\"]https?://[^'\"]*\.js[^'\"]*['\"]" | tr -d "'\"" | sort -u)
    if [ -n "$more_js" ]; then
      jsinfo "Nested JS in ${js_url}"
      while IFS= read -r nested_js; do
        [ -z "$nested_js" ] || [ "$nested_js" = "$js_url" ] && continue
        process_linked_js "$nested_js" "$js_url" $((depth + 1))
      done <<< "$more_js"
    fi
  fi
}

# ─── Process local file ──────────────────────────────────────────
process_local_file() {
  local file="$1"
  [ ! -f "$file" ] && { err "File not found: $file"; return 1; }
  info "Processing local file: $file"
  local content; content=$(cat "$file")
  process_js_content "$content" "$file"
}

# ─── Process direct JS URL ───────────────────────────────────────
process_direct_js() {
  local url="$1"
  info "Fetching JS URL: $url"
  process_linked_js "$url" ""
}

# ─── Module dependency analysis ──────────────────────────────────
analyze_dependencies() {
  local content="$1" source="$2"

  # Extract import statements
  local imports
  imports=$(echo "$content" | grep -oP 'import\s+(?:\{[^}]*\}|\*\s+as\s+\w+|\w+)\s+from\s+["'"'"']([^"'"'"']+)["'"'"']' | grep -oP '["'"'"'][^"'"'"']+["'"'"']' | tr -d "'\"'" | sort -u)
  if [ -n "$imports" ]; then
    [ "$QUIET" = false ] && jsinfo "Dependencies in ${source}:"
    while IFS= read -r imp; do [ -n "$imp" ] && echo "  ${imp}"; done <<< "$imports"
  fi

  # Extract require statements
  local requires
  requires=$(echo "$content" | grep -oP 'require\(["'"'"']([^"'"'"']+)["'"'"']\)' | sed 's/require(//;s/)//;s/["'"'"']//g' | sort -u)
  if [ -n "$requires" ]; then
    [ "$QUIET" = false ] && jsinfo "Requires in ${source}:"
    while IFS= read -r req; do [ -n "$req" ] && echo "  ${req}"; done <<< "$requires"
  fi
}

# ─── Generate JSON output ────────────────────────────────────────
generate_json_output() {
  local source="$1" content="$2"
  [ -z "$OUTPUT_DIR" ] && return
  local safe_name
  safe_name=$(echo "$source" | sed 's|https\?://||;s|/|_|g;s|[^a-zA-Z0-9._-]|_|g')
  local json_file="${OUTPUT_DIR}/${safe_name}.json"

  cat > "$json_file" <<JSON
{
  "source": "$source",
  "timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "size": $(echo "$content" | wc -c),
  "lines": $(echo "$content" | wc -l),
  "secrets_found": $( [ "$NO_SECRETS" = false ] && echo "true" || echo "false" ),
  "endpoints_found": $( [ "$NO_ENDPOINTS" = false ] && echo "true" || echo "false" )
}
JSON
  ok "JSON report: ${json_file}"
}

# ─── Summary ─────────────────────────────────────────────────────
generate_summary() {
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${GREEN}JavaScript Analysis Complete${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  local src=""
  [ -n "$TARGET_URL" ] && src="$TARGET_URL"
  [ -n "$TARGET_FILE" ] && src="$TARGET_FILE"
  [ -n "$LINKED_JS_URL" ] && src="$LINKED_JS_URL"
  echo -e "  ${YELLOW}Source:${NC}     $src"
  echo -e "  ${YELLOW}Secrets:${NC}    $([ "$NO_SECRETS" = false ] && echo 'Scanned' || echo 'Skipped')"
  echo -e "  ${YELLOW}Endpoints:${NC}  $([ "$NO_ENDPOINTS" = false ] && echo 'Scanned' || echo 'Skipped')"
  echo -e "  ${YELLOW}Download:${NC}   $([ "$NO_DOWNLOAD" = false ] && echo 'Yes' || echo 'No')"
  [ -n "$OUTPUT_DIR" ] && echo -e "  ${YELLOW}Output:${NC}     $OUTPUT_DIR"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
}

# ─── Main ────────────────────────────────────────────────────────
main() {
  check_deps
  [ -n "$OUTPUT_DIR" ] && mkdir -p "$OUTPUT_DIR" && ok "Output dir: $OUTPUT_DIR"

  if [ -n "$TARGET_URL" ]; then process_url "$TARGET_URL" 1
  elif [ -n "$LINKED_JS_URL" ]; then process_direct_js "$LINKED_JS_URL"
  elif [ -n "$TARGET_FILE" ]; then process_local_file "$TARGET_FILE"
  fi

  generate_summary
}

# ─── Inline execution guard ──────────────────────────────────────
# ─── Cookie security analysis from JS ─────────────────────────────
analyze_js_cookies() {
  local content="$1" source="$2"
  local cookie_uses
  cookie_uses=$(echo "$content" | grep -cP '(document\.cookie|\.cookie\s*=|cookieStore)' || true)
  if [ "$cookie_uses" -gt 0 ]; then
    warn "${source}: document.cookie used ${cookie_uses} times - possible XSS sink"
    local cookie_reads cookie_writes
    cookie_reads=$(echo "$content" | grep -cP 'document\.cookie[^=]' || true)
    cookie_writes=$(echo "$content" | grep -cP 'document\.cookie\s*=' || true)
    [ "$cookie_reads" -gt 0 ] && info "  Cookie reads: ${cookie_reads}"
    [ "$cookie_writes" -gt 0 ] && warn "  Cookie writes: ${cookie_writes} (possible session hijacking via XSS)"
  fi
}

# ─── Content security analysis ───────────────────────────────────
analyze_js_security() {
  local content="$1" source="$2"
  local issues=0

  # Check for dangerous functions
  local dangerous=(
    "eval" "execScript" "setTimeout(string)" "setInterval(string)"
    "new Function" "document.write" "innerHTML" "outerHTML"
    "insertAdjacentHTML" "document.open" "location=" "window.location="
    "postMessage" "importScripts" "ServiceWorker"
  )

  for func_name in "${dangerous[@]}"; do
    local count
    count=$(echo "$content" | grep -cF "$func_name" || true)
    [ "$count" -gt 0 ] && issues=$((issues + 1))
  done

  if [ "$issues" -gt 0 ]; then
    warn "${source}: ${issues} dangerous API usage pattern(s)"
  fi

  # Check for localStorage/sessionStorage usage
  local ls_count
  ls_count=$(echo "$content" | grep -cP '(localStorage|sessionStorage)' || true)
  [ "$ls_count" -gt 0 ] && info "${source}: Web Storage used ${ls_count} times"

  # Check for iframe/postMessage usage
  local pm_count
  pm_count=$(echo "$content" | grep -cP 'postMessage\s*\(' || true)
  [ "$pm_count" -gt 0 ] && warn "${source}: postMessage used ${pm_count} times"

  # Check for fetch/XHR with credentials
  local cred_count
  cred_count=$(echo "$content" | grep -cP 'credentials:\s*["'"'"']include["'"'"']' || true)
  [ "$cred_count" -gt 0 ] && warn "${source}: fetch with credentials:include ${cred_count} times"
}

# ─── Generate comprehensive JS report ────────────────────────────
generate_js_report() {
  local source="$1"
  [ -z "$OUTPUT_DIR" ] && return
  mkdir -p "$OUTPUT_DIR"
  local report_file="${OUTPUT_DIR}/js-analysis-summary.md"

  cat > "$report_file" <<REPORT
# JavaScript Analysis Summary

**Source:** ${source}
**Date:** $(date -u '+%Y-%m-%dT%H:%M:%SZ')
**Tool:** ${SCRIPT_NAME} v${VERSION}

## Configuration
- Secret Scanning: $([ "$NO_SECRETS" = false ] && echo 'Enabled' || echo 'Disabled')
- Endpoint Scanning: $([ "$NO_ENDPOINTS" = false ] && echo 'Enabled' || echo 'Disabled')
- External Download: $([ "$NO_DOWNLOAD" = false ] && echo 'Enabled' || echo 'Disabled')
- Max Depth: ${MAX_DEPTH}

## Results
See individual JS analysis files in ${OUTPUT_DIR} for detailed findings.

*Generated by ${SCRIPT_NAME}*
REPORT
  ok "Summary report: ${report_file}"
}

# ─── Inline execution guard ──────────────────────────────────────
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  parse_args "$@"
  main
fi
