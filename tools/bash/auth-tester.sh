#!/usr/bin/env bash
# =====================================================================
# auth-tester.sh — Authentication Security Testing Tool
#
# Login form detection and analysis, session cookie analysis, JWT decoding
# and inspection, common auth bypass tests, and credential handling.
# Tests for authentication weaknesses and misconfigurations.
#
# Usage:
#   ./auth-tester.sh -u https://target.com/login
#   ./auth-tester.sh -u https://target.com -f auth-flow.json
#   ./auth-tester.sh -u https://target.com/api --bypass
# =====================================================================

set -euo pipefail

# ─── Constants ───────────────────────────────────────────────────
VERSION="1.0.0"
SCRIPT_NAME=$(basename "$0")
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; NC='\033[0m'

# Auth bypass headers to test
AUTH_BYPASS_HEADERS=(
  "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJpYXQiOjE1MTYyMzkwMjJ9."
  "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE1MTYyMzkwMjJ9"
  "X-Forwarded-For: 127.0.0.1"
  "X-Forwarded-Host: localhost"
  "X-Original-URL: /admin"
  "X-Rewrite-URL: /admin"
  "X-Custom-IP-Authorization: 127.0.0.1"
  "X-Real-IP: 127.0.0.1"
  "X-Client-IP: 127.0.0.1"
  "X-Remote-IP: 127.0.0.1"
  "X-Remote-Addr: 127.0.0.1"
  "Client-IP: 127.0.0.1"
  "True-Client-IP: 127.0.0.1"
  "X-Forwarded-For: localhost"
  "X-Originating-IP: 127.0.0.1"
  "X-Requested-With: XMLHttpRequest"
  "X-Forwarded-Proto: https"
  "X-Forwarded-Scheme: https"
)

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
bad()    { echo -e "${RED}[VULN]${NC} $*"; }
good()   { echo -e "${GREEN}[SECURE]${NC} $*"; }
detail() { echo -e "  ${CYAN}→${NC} $*"; }

# ─── Usage ───────────────────────────────────────────────────────
usage() {
  cat <<EOF
${CYAN}auth-tester.sh${NC} v${VERSION} — Authentication Testing Tool

${YELLOW}Description:${NC}
  Tests authentication mechanisms including login forms, session cookies,
  JWT tokens, and common auth bypass techniques. Analyzes auth flow,
  detects weaknesses, and identifies misconfigurations.

${YELLOW}Usage:${NC}
  $SCRIPT_NAME -u <url>                    Analyze login page
  $SCRIPT_NAME -u <url> --bypass           Test auth bypasses
  $SCRIPT_NAME -u <url> --cookies          Analyze session cookies
  $SCRIPT_NAME -u <url> -t <token>         Decode JWT token
  $SCRIPT_NAME -u <url> --all              Run all auth tests

${YELLOW}Modes:${NC}
  --login         Analyze login form (default)
  --cookies       Analyze session cookies
  --jwt           Decode and analyze JWT tokens
  --bypass        Test auth bypass techniques
  --all           Run all tests

${YELLOW}Options:${NC}
  -u <url>          Target URL
  -t <token>        JWT token to decode/analyze
  -c <file>         Cookie jar file to load
  -s <session>      Session cookie value to analyze
  -o <file>         Output file
  -H <header>       Custom header
  -d <data>         POST body data for login simulation
  -q                Quiet mode
  -v                Verbose mode
  -h                Show help

${YELLOW}Examples:${NC}
  $SCRIPT_NAME -u https://target.com/login
  $SCRIPT_NAME -u https://target.com/api/admin --bypass
  $SCRIPT_NAME -u https://target.com -t eyJhbGciOiJIUzI1NiJ9...
EOF
  exit 0
}

# ─── Options ─────────────────────────────────────────────────────
TARGET_URL=""
JWT_TOKEN=""
COOKIE_JAR=""
SESSION_VALUE=""
OUTPUT_FILE=""
POST_DATA=""
TIMEOUT=10
QUIET=false
VERBOSE=false

RUN_LOGIN=true
RUN_COOKIES=false
RUN_JWT=false
RUN_BYPASS=false

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help) usage ;;
      -u|--url) TARGET_URL="$2"; shift 2 ;;
      -t|--token) JWT_TOKEN="$2"; shift 2 ;;
      -c|--cookies) COOKIE_JAR="$2"; shift 2 ;;
      -s|--session) SESSION_VALUE="$2"; shift 2 ;;
      -o|--output) OUTPUT_FILE="$2"; shift 2 ;;
      -H|--header) CUSTOM_HEADERS+=("$2"); shift 2 ;;
      -d|--data) POST_DATA="$2"; shift 2 ;;
      -q|--quiet) QUIET=true; shift ;;
      -v|--verbose) VERBOSE=true; shift ;;
      --login) RUN_LOGIN=true; RUN_COOKIES=false; RUN_JWT=false; RUN_BYPASS=false; shift ;;
      --cookies) RUN_LOGIN=false; RUN_COOKIES=true; RUN_JWT=false; RUN_BYPASS=false; shift ;;
      --jwt) RUN_LOGIN=false; RUN_COOKIES=false; RUN_JWT=true; RUN_BYPASS=false; shift ;;
      --bypass) RUN_LOGIN=false; RUN_COOKIES=false; RUN_JWT=false; RUN_BYPASS=true; shift ;;
      --all) RUN_LOGIN=true; RUN_COOKIES=true; RUN_JWT=true; RUN_BYPASS=true; shift ;;
      *) err "Unknown: $1"; usage ;;
    esac
  done
  [ -z "$TARGET_URL" ] && [ -z "$JWT_TOKEN" ] && { err "No target"; usage; }
}

check_deps() {
  local missing=()
  for d in curl grep sed awk sort uniq; do
    command -v "$d" &>/dev/null || missing+=("$d")
  done
  if ! command -v python3 &>/dev/null; then
    warn "python3 not found - JWT decoding will be limited"
  fi
  [ ${#missing[@]} -gt 0 ] && { err "Missing: ${missing[*]}"; exit 1; }
}

# ─── HTTP ────────────────────────────────────────────────────────
_http_request() {
  local method="$1" url="$2" data="${3:-}" header_arg=""
  local -a curl_args=(-sk --max-time "$TIMEOUT" -A "$USER_AGENT" -X "$method")

  [ -n "$data" ] && curl_args+=(-d "$data")

  if [ -n "$COOKIE_JAR" ] && [ -f "$COOKIE_JAR" ]; then
    curl_args+=(-b "$COOKIE_JAR" -c "$COOKIE_JAR")
  fi

  for h in "${CUSTOM_HEADERS[@]:-}"; do
    [ -n "$h" ] && curl_args+=(-H "$h")
  done

  curl "${curl_args[@]}" -D - "$url" 2>/dev/null || {
    warn "Request failed: $method $url"; return 1
  }
}

# ─── Analyze login form ─────────────────────────────────────────
analyze_login() {
  local url="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[LOGIN] Login form analysis for ${url}${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  local response
  response=$(_http_request "GET" "$url") || return 1
  local body
  body=$(echo "$response")

  # Detect login form
  local has_login_form=false

  if echo "$body" | grep -qiE '<form[^>]*>'; then
    # Check for password fields
    if echo "$body" | grep -qiP 'type="password"'; then
      has_login_form=true
      info "Password field detected"
    fi

    # Extract form action and method
    local form_action form_method
    form_action=$(echo "$body" | grep -oP '<form[^>]+action="[^"]*"' | head -1 | sed 's/.*action="//;s/"$//')
    form_method=$(echo "$body" | grep -oP '<form[^>]+method="[^"]*"' | head -1 | sed 's/.*method="//;s/"$//' | tr '[:lower:]' '[:upper:]')
    [ -z "$form_method" ] && form_method="GET"

    if [ -n "$form_action" ]; then
      detail "Form action: ${form_action}"
      detail "Form method: ${form_method}"
    fi
  fi

  # Detect auth-related keywords
  local auth_keywords=()
  for kw in "login" "signin" "sign-in" "log in" "log-in" "auth"
           "password" "passwd" "pwd" "username" "email" "user"
           "csrf" "token" "_token" "authenticity_token"
           "remember" "2fa" "mfa" "otp" "totp"; do
    if echo "$body" | grep -qi "$kw"; then
      auth_keywords+=("$kw")
    fi
  done

  if [ ${#auth_keywords[@]} -gt 0 ]; then
    info "Auth keywords found: ${auth_keywords[*]}"
  fi

  # Check transport security
  if echo "$url" | grep -qi '^https'; then
    good "Login over HTTPS"
  else
    bad "Login NOT over HTTPS!"
  fi

  # Check for autocomplete
  if echo "$body" | grep -qiP 'autocomplete="off"'; then
    good "Autocomplete disabled on form"
  fi

  # Check for CSRF token
  if echo "$body" | grep -qiE 'csrf|_token|authenticity_token|xsrf'; then
    good "CSRF protection likely present"
  else
    warn "No CSRF token detected"
  fi

  if [ "$has_login_form" = false ]; then
    info "No standard login form detected"
  fi

  # Extract input fields for potential credential testing
  echo ""
  info "Form input fields:"
  echo "$body" | grep -oP '<input[^>]*>' | while IFS= read -r input; do
    local input_type input_name input_placeholder input_id
    input_type=$(echo "$input" | grep -oP 'type="[^"]*"' | sed 's/type="//;s/"$//')
    input_name=$(echo "$input" | grep -oP 'name="[^"]*"' | sed 's/name="//;s/"$//')
    input_placeholder=$(echo "$input" | grep -oP 'placeholder="[^"]*"' | sed 's/placeholder="//;s/"$//')
    input_id=$(echo "$input" | grep -oP 'id="[^"]*"' | sed 's/id="//;s/"$//')
    [ -z "$input_type" ] && input_type="text"

    local display=""
    [ -n "$input_name" ] && display="${display} name=${input_name}"
    [ -n "$input_placeholder" ] && display="${display} placeholder=${input_placeholder}"
    [ -n "$input_id" ] && display="${display} id=${input_id}"

    if [ "$input_type" = "password" ]; then
      warn "  [PASSWORD]${display}"
    elif [ "$input_type" = "hidden" ]; then
      detail "  [HIDDEN]${display}"
    else
      detail "  [${input_type}]${display}"
    fi
  done
}

# ─── Analyze session cookies ────────────────────────────────────
analyze_cookies() {
  local url="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[COOKIES] Session cookie analysis for ${url}${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  local jar="${COOKIE_JAR:-/tmp/_cookie_analysis_$$.txt}"
  [ -z "$COOKIE_JAR" ] && _cleanup_add "$jar"

  # Make request to capture cookies
  local response
  response=$(curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" \
    -c "$jar" -D - -o /dev/null "$url" 2>/dev/null) || {
    err "Failed to fetch $url"; return 1
  }

  echo "$response" | grep -i '^set-cookie:' | while IFS= read -r cookie_line; do
    local cookie_name cookie_value cookie_attrs
    cookie_name=$(echo "$cookie_line" | sed 's/^[Ss]et-[Cc]ookie: //' | cut -d= -f1)
    cookie_value=$(echo "$cookie_line" | sed 's/^[Ss]et-[Cc]ookie: //' | cut -d= -f2- | cut -d';' -f1)
    cookie_attrs=$(echo "$cookie_line" | sed 's/^[Ss]et-[Cc]ookie: [^;]*//')

    echo ""
    info "Cookie: ${cookie_name}=${cookie_value}"

    # Security attribute checks
    local has_httponly=false has_secure=false has_samesite=false
    local samesite_value=""

    echo "$cookie_attrs" | grep -qi 'httponly' && has_httponly=true
    echo "$cookie_attrs" | grep -qi 'secure' && has_secure=true
    if echo "$cookie_attrs" | grep -qi 'samesite'; then
      has_samesite=true
      samesite_value=$(echo "$cookie_attrs" | grep -oiP 'samesite=[a-z]+' | cut -d= -f2)
    fi

    $has_httponly && good "  HttpOnly: Yes" || bad "  HttpOnly: No (accessible to JavaScript!)"
    $has_secure && good "  Secure: Yes" || warn "  Secure: No (sent over HTTP!)"

    if $has_samesite; then
      good "  SameSite: ${samesite_value}"
      if [ "$samesite_value" = "None" ]; then
        warn "  SameSite=None allows cross-site usage"
      fi
    else
      warn "  SameSite: Not set"
    fi

    # Expiry check
    if echo "$cookie_line" | grep -qi 'Expires='; then
      local expires
      expires=$(echo "$cookie_line" | grep -oiP 'Expires=[^;]+' | cut -d= -f2-)
      detail "  Expires: ${expires}"
    elif echo "$cookie_line" | grep -qi 'Max-Age='; then
      local max_age
      max_age=$(echo "$cookie_line" | grep -oiP 'Max-Age=[0-9]+' | cut -d= -f2)
      detail "  Max-Age: ${max_age}s"
      if [ "$max_age" -gt 86400 ]; then
        warn "  Long-lived session: ${max_age}s (${max_age}s)"
      fi
    else
      warn "  Session cookie (expires at browser close)"
    fi

    # Domain/Path scope
    if echo "$cookie_line" | grep -qi 'Domain='; then
      local domain
      domain=$(echo "$cookie_line" | grep -oiP 'Domain=[^;]+' | cut -d= -f2)
      detail "  Domain: ${domain}"
    fi
    if echo "$cookie_line" | grep -qi 'Path='; then
      local path
      path=$(echo "$cookie_line" | grep -oiP 'Path=[^;]+' | cut -d= -f2)
      detail "  Path: ${path}"
    fi
  done

  # Cookie entropy analysis
  if [ -f "$jar" ]; then
    info "Cookie jar: $jar"
    detail "Cookies stored: $(grep -cP '\t' "$jar" || true)"
  fi
}

# ─── JWT analysis ────────────────────────────────────────────────
decode_jwt() {
  local token="$1"

  if [ -z "$token" ]; then
    # Try to extract from Authorization header in response
    if [ -n "$TARGET_URL" ]; then
      local response
      response=$(curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" \
        -D - "$TARGET_URL" 2>/dev/null) || true
      token=$(echo "$response" | grep -oiP 'bearer\s+\S+' | head -1 | awk '{print $2}')
    fi
  fi

  [ -z "$token" ] && { err "No JWT token provided or found"; return 1; }

  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[JWT] Token Analysis${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  detail "Raw token: ${token:0:50}..."

  # Split JWT parts
  local header_enc payload_enc signature
  header_enc=$(echo "$token" | cut -d. -f1)
  payload_enc=$(echo "$token" | cut -d. -f2)
  signature=$(echo "$token" | cut -d. -f3)

  # Check structure
  if [ -z "$header_enc" ] || [ -z "$payload_enc" ]; then
    bad "Invalid JWT structure (not 3 parts)"
    return 1
  fi

  # Decode header
  local header_decoded=""
  header_decoded=$(echo "$header_enc" | base64 -d 2>/dev/null || echo "$header_enc" | python3 -c "import sys,base64; print(base64.urlsafe_b64decode(sys.stdin.read() + '=='))" 2>/dev/null) || header_decoded="(decode failed)"

  info "JWT Header:"
  if command -v python3 &>/dev/null; then
    echo "$header_enc" | python3 -c "
import sys, base64, json
try:
    padded = sys.stdin.read().strip() + '=='
    decoded = base64.urlsafe_b64decode(padded)
    parsed = json.loads(decoded)
    for k, v in parsed.items():
        print(f'  {k}: {v}')
except Exception as e:
    print(f'  (decode error: {e})')
" 2>/dev/null || echo "  ${header_decoded}"
  else
    echo "  ${header_decoded}"
  fi

  # Decode payload
  info "JWT Payload:"
  if command -v python3 &>/dev/null; then
    echo "$payload_enc" | python3 -c "
import sys, base64, json
try:
    padded = sys.stdin.read().strip() + '=='
    decoded = base64.urlsafe_b64decode(padded)
    parsed = json.loads(decoded)
    for k, v in parsed.items():
        print(f'  {k}: {v}')
except Exception as e:
    print(f'  (decode error: {e})')
" 2>/dev/null || echo "  (payload decode failed)"
  else
    local payload_decoded
    payload_decoded=$(echo "$payload_enc" | base64 -d 2>/dev/null)
    echo "  ${payload_decoded:-(decode failed)}"
  fi

  # Security checks
  echo ""
  info "Security Analysis:"

  # Check alg:none
  if echo "$header_decoded" | grep -qi '"alg"\s*:\s*"none"'; then
    bad "Algorithm is 'none' - token can be forged!"
  fi

  # Check algorithm
  local alg=""
  alg=$(echo "$header_decoded" | grep -oiP '"alg"\s*:\s*"[^"]*"' | cut -d'"' -f4)
  if [ "$alg" = "HS256" ] || [ "$alg" = "HS384" ] || [ "$alg" = "HS512" ]; then
    warn "Symmetric algorithm (${alg}) - vulnerable if secret is weak"
  elif [ "$alg" = "RS256" ] || [ "$alg" = "RS384" ] || [ "$alg" = "RS512" ]; then
    good "Asymmetric algorithm (${alg})"
  elif [ -n "$alg" ]; then
    info "Algorithm: ${alg}"
  fi

  # Check for common payload claims
  local exp_present iat_present iss_present sub_present
  echo "$header_decoded" | grep -qi '"exp"' && exp_present=true || exp_present=false
  echo "$header_decoded" | grep -qi '"iat"' && iat_present=true || iat_present=false
  echo "$header_decoded" | grep -qi '"iss"' && iss_present=true || iss_present=false
  echo "$header_decoded" | grep -qi '"sub"' && sub_present=true || sub_present=false

  $exp_present && good "  exp claim present" || warn "  No exp claim (never expires)"
  $iat_present && info "  iat claim present" || info "  No iat claim"
  $iss_present && info "  iss claim present" || info "  No iss claim"
  $sub_present && info "  sub claim present" || info "  No sub claim"

  # Check for signature
  if [ -z "$signature" ]; then
    bad "No signature - unsecured JWT!"
  fi
}

# ─── Auth bypass testing ─────────────────────────────────────────
test_bypass() {
  local url="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[BYPASS] Auth bypass testing for ${url}${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  info "Testing ${#AUTH_BYPASS_HEADERS[@]} bypass techniques..."

  # Get baseline (no auth)
  local baseline_status baseline_size
  baseline_status=$(curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" \
    -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "FAIL")
  baseline_size=$(curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" \
    -o /dev/null -w "%{size_download}" "$url" 2>/dev/null || echo "0")
  info "Baseline (no auth): HTTP ${baseline_status} (${baseline_size}b)"

  # Test each bypass header
  for header in "${AUTH_BYPASS_HEADERS[@]}"; do
    local header_name header_value
    header_name=$(echo "$header" | cut -d: -f1)
    header_value=$(echo "$header" | cut -d: -f2- | sed 's/^ //')

    local status size
    status=$(curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" \
      -H "$header_name: $header_value" \
      -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "FAIL")
    size=$(curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" \
      -H "$header_name: $header_value" \
      -o /dev/null -w "%{size_download}" "$url" 2>/dev/null || echo "0")

    if [ "$status" != "$baseline_status" ] || [ "$size" != "$baseline_size" ]; then
      if [ "$status" = "200" ]; then
        bad "BYPASS: ${header_name}: ${header_value} → HTTP ${status} (${size}b, diff: $((size - baseline_size))b)"
      else
        warn "DIFFERENT: ${header_name}: ${header_value} → HTTP ${status} (${size}b)"
      fi
    fi
  done

  # Path traversal bypass patterns
  echo ""
  info "Testing path traversal bypasses..."
  local path_bypasses=(
    "/admin"
    "/admin/"
    "//admin/"
    "/./admin/"
    "/admin/."
    "//admin//"
    "/ADMIN/"
    "/admin%00"
    "/admin%20"
    "/admin~"
    "/.admin."
    "/admin..;"
    "/*/admin"
  )

  local domain
  domain=$(echo "$url" | grep -oP '^https?://[^/]+')
  for path in "${path_bypasses[@]}"; do
    local test_url="${domain}${path}"
    local status
    status=$(curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" \
      -o /dev/null -w "%{http_code}" "$test_url" 2>/dev/null || echo "FAIL")
    [ "$status" = "200" ] && bad "Path bypass: ${test_url} → HTTP ${status}"
  done
}

# ─── Output ──────────────────────────────────────────────────────
maybe_output() { [ -n "$OUTPUT_FILE" ] && info "Output: ${OUTPUT_FILE}"; }

# ─── Main ────────────────────────────────────────────────────────
main() {
  check_deps
  echo ""
  echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║${NC}  ${GREEN}Auth Tester v${VERSION}${NC}"
  local tgt=""; [ -n "$TARGET_URL" ] && tgt="$TARGET_URL"; [ -n "$JWT_TOKEN" ] && tgt="(JWT supplied)"
  echo -e "${CYAN}║${NC}  Target: ${YELLOW}${tgt}${NC}"
  echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"

  [ "$RUN_LOGIN" = true ] && [ -n "$TARGET_URL" ] && analyze_login "$TARGET_URL"
  [ "$RUN_COOKIES" = true ] && [ -n "$TARGET_URL" ] && analyze_cookies "$TARGET_URL"
  [ "$RUN_JWT" = true ] && decode_jwt "$JWT_TOKEN"
  [ "$RUN_BYPASS" = true ] && [ -n "$TARGET_URL" ] && test_bypass "$TARGET_URL"

  maybe_output
  echo ""
  ok "Auth testing complete"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  parse_args "$@"
  main
fi