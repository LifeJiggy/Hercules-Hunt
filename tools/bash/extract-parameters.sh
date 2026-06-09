#!/usr/bin/env bash
# =====================================================================
# extract-parameters.sh — Parameter Extraction and Analysis Tool
#
# URL query string parsing, form parameter extraction from HTML, common
# parameter name fuzzing, and parameter reflection detection. Identifies
# hidden/disabled form fields and JavaScript parameter usage.
#
# Usage:
#   ./extract-parameters.sh -u https://target.com/page
#   ./extract-parameters.sh -f page.html
#   ./extract-parameters.sh -u https://target.com/api -p id,user_id,role
# =====================================================================

set -euo pipefail

# ─── Constants ───────────────────────────────────────────────────
VERSION="1.0.0"
SCRIPT_NAME=$(basename "$0")
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; NC='\033[0m'

# Common parameter names for fuzzing
COMMON_PARAMS=(
  "id" "user_id" "userid" "uid" "customer_id" "client_id" "account_id"
  "admin" "is_admin" "role" "user_role" "access_level" "permission"
  "token" "api_key" "api_token" "access_token" "auth_token" "session"
  "file" "path" "url" "redirect" "next" "return" "return_url" "return_to"
  "page" "page_id" "section" "module" "component" "tab"
  "q" "s" "search" "query" "keyword" "term" "filter"
  "name" "email" "phone" "username" "first_name" "last_name"
  "password" "pass" "secret" "confirm" "verify"
  "action" "method" "mode" "type" "format" "output" "view"
  "limit" "offset" "count" "page_size" "page_number" "skip" "take"
  "order" "sort" "sort_by" "sort_order" "direction"
  "status" "state" "active" "enabled" "visible" "published"
  "lang" "locale" "language" "region" "country"
  "callback" "jsonp" "jsoncallback"
  "debug" "test" "dry_run" "validate" "preview"
  "source" "ref" "referer" "referrer" "from" "origin"
  "timestamp" "date" "time" "expires" "expiry" "ttl"
  "sig" "signature" "hash" "hmac" "nonce" "challenge"
  "width" "height" "size" "quality" "thumbnail"
  "title" "description" "body" "content" "text"
  "group" "team" "org" "organization" "company"
  "key" "value" "data" "config" "setting"
  "host" "hostname" "server" "domain" "site"
  "port" "protocol" "scheme" "version" "v"
  "include" "exclude" "scope" "fields" "expand"
  "meta" "_method" "x-http-method-override"
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
param()  { echo -e "${GREEN}[PARAM]${NC} $*"; }
hidden() { echo -e "${MAGENTA}[HIDDEN]${NC} $*"; }

# ─── Usage ───────────────────────────────────────────────────────
usage() {
  cat <<EOF
${CYAN}extract-parameters.sh${NC} v${VERSION} — Parameter Extraction & Analysis

${YELLOW}Description:${NC}
  Extracts and analyzes URL parameters from web pages. Discovers query
  string parameters, form fields (including hidden/disabled), JavaScript
  parameter usage, and tests for parameter reflection.

${YELLOW}Usage:${NC}
  $SCRIPT_NAME -u <url>              Extract params from URL
  $SCRIPT_NAME -f <file>             Extract from local HTML
  $SCRIPT_NAME -u <url> -p id,role   Fuzz specific params
  $SCRIPT_NAME -u <url> --fuzz       Fuzz with common params

${YELLOW}Modes:${NC}
  --extract       Extract parameters from page (default)
  --fuzz          Fuzz for hidden parameters
  --reflect       Test parameter reflection
  --all           Run all modes

${YELLOW}Options:${NC}
  -u <url>          Target URL
  -f <file>         Local HTML file
  -p <params>       Comma-separated params to test
  -w <file>         Custom parameter wordlist
  -o <file>         Output file
  -t <seconds>      Request timeout (default: 10)
  -q                Quiet mode
  -v                Verbose mode
  -h                Show help

${YELLOW}Examples:${NC}
  $SCRIPT_NAME -u https://target.com/page?q=test&id=5
  $SCRIPT_NAME -f login.html
  $SCRIPT_NAME -u https://target.com/api --fuzz
EOF
  exit 0
}

# ─── Options ─────────────────────────────────────────────────────
TARGET_URL=""
TARGET_FILE=""
CUSTOM_PARAMS=""
WORDLIST=""
OUTPUT_FILE=""
TIMEOUT=10
QUIET=false
VERBOSE=false

RUN_EXTRACT=true
RUN_FUZZ=false
RUN_REFLECT=false

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help) usage ;;
      -u|--url) TARGET_URL="$2"; shift 2 ;;
      -f|--file) TARGET_FILE="$2"; shift 2 ;;
      -p|--params) CUSTOM_PARAMS="$2"; shift 2 ;;
      -w|--wordlist) WORDLIST="$2"; shift 2 ;;
      -o|--output) OUTPUT_FILE="$2"; shift 2 ;;
      -t|--timeout) TIMEOUT="$2"; shift 2 ;;
      -q|--quiet) QUIET=true; shift ;;
      -v|--verbose) VERBOSE=true; shift ;;
      --extract) RUN_EXTRACT=true; RUN_FUZZ=false; RUN_REFLECT=false; shift ;;
      --fuzz) RUN_EXTRACT=false; RUN_FUZZ=true; RUN_REFLECT=false; shift ;;
      --reflect) RUN_EXTRACT=false; RUN_FUZZ=false; RUN_REFLECT=true; shift ;;
      --all) RUN_EXTRACT=true; RUN_FUZZ=true; RUN_REFLECT=true; shift ;;
      *) err "Unknown: $1"; usage ;;
    esac
  done
  if [ -z "$TARGET_URL" ] && [ -z "$TARGET_FILE" ]; then
    err "No target. Use -u or -f."
    usage
  fi
}

check_deps() {
  local missing=()
  for d in curl grep sed awk sort uniq; do
    command -v "$d" &>/dev/null || missing+=("$d")
  done
  [ ${#missing[@]} -gt 0 ] && { err "Missing: ${missing[*]}"; exit 1; }
}

# ─── HTTP helper ─────────────────────────────────────────────────
_http_get() {
  local url="$1"
  curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" \
    -w "\n%{http_code}|||%{size_download}|||%{content_type}" "$url" 2>/dev/null || {
    warn "Fetch failed: $url"; return 1
  }
}

# ─── Extract query string parameters ─────────────────────────────
extract_query_params() {
  local url="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[QUERY PARAMS] Extracting from URL${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  if ! echo "$url" | grep -q '?'; then
    info "No query string in URL"
    return
  fi

  local query_string
  query_string=$(echo "$url" | grep -oP '\?.*' | sed 's/^?//')

  # Split by &
  echo "$query_string" | tr '&' '\n' | while IFS= read -r param_eq; do
    [ -z "$param_eq" ] && continue
    local pname pvalue
    pname=$(echo "$param_eq" | cut -d= -f1)
    pvalue=$(echo "$param_eq" | cut -d= -f2-)

    if [ -n "$pvalue" ]; then
      param "${pname} = ${pvalue}"
    else
      param "${pname} = (empty)"
    fi
  done

  local count
  count=$(echo "$query_string" | tr '&' '\n' | grep -c . || true)
  info "Found ${count} query parameters"
}

# ─── Extract form parameters from HTML ───────────────────────────
extract_form_params() {
  local content="$1" source="$2"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[FORM PARAMS] Extracting from ${source}${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  # Extract all forms
  local form_count=0
  local tmp_forms
  tmp_forms=$(mktemp) && _cleanup_add "$tmp_forms"

  echo "$content" | grep -oP '<form[^>]*>[\s\S]*?</form>' > "$tmp_forms" 2>/dev/null || true

  if [ ! -s "$tmp_forms" ]; then
    info "No forms found"
    return
  fi

  form_count=$(grep -c '<form' "$tmp_forms" || true)
  info "Found ${form_count} form(s)"

  # Process each form
  local form_index=0
  while IFS= read -r form_html; do
    [ -z "$form_html" ] && continue
    form_index=$((form_index + 1))

    # Form action
    local form_action
    form_action=$(echo "$form_html" | grep -oP 'action="[^"]*"' | sed 's/action="//;s/"$//')
    local form_method
    form_method=$(echo "$form_html" | grep -oP 'method="[^"]*"' | sed 's/method="//;s/"$//' | tr '[:lower:]' '[:upper:]')
    [ -z "$form_method" ] && form_method="GET"
    [ -z "$form_action" ] && form_action="(same page)"

    echo ""
    echo -e "  ${CYAN}[Form ${form_index}]${NC} ${form_method} → ${form_action}"

    # Extract input fields
    echo "$form_html" | grep -oP '<input[^>]*>' | while IFS= read -r input_tag; do
      local input_type input_name input_value input_id disabled_attr readonly_attr
      input_type=$(echo "$input_tag" | grep -oP 'type="[^"]*"' | sed 's/type="//;s/"$//')
      input_name=$(echo "$input_tag" | grep -oP 'name="[^"]*"' | sed 's/name="//;s/"$//')
      input_value=$(echo "$input_tag" | grep -oP 'value="[^"]*"' | sed 's/value="//;s/"$//')
      disabled_attr=$(echo "$input_tag" | grep -oi 'disabled' || true)
      readonly_attr=$(echo "$input_tag" | grep -oi 'readonly' || true)

      [ -z "$input_type" ] && input_type="text"
      [ -z "$input_name" ] && continue

      local flags=""
      [ -n "$disabled_attr" ] && flags="${flags} [DISABLED]"
      [ -n "$readonly_attr" ] && flags="${flags} [READONLY]"

      if [ "$input_type" = "hidden" ]; then
        hidden "  ${input_name} = ${input_value}${flags}"
      else
        param "  ${input_name} = ${input_value} (type: ${input_type})${flags}"
      fi
    done

    # Extract select fields
    echo "$form_html" | grep -oP '<select[^>]*>[\s\S]*?</select>' | while IFS= read -r select_tag; do
      local select_name
      select_name=$(echo "$select_tag" | grep -oP 'name="[^"]*"' | sed 's/name="//;s/"$//')
      [ -z "$select_name" ] && continue

      local options
      options=$(echo "$select_tag" | grep -oP '<option[^>]*>[^<]*</option>' | sed 's/<option[^>]*>//;s/<\/option>//' | tr '\n' ',' | sed 's/,$//')
      param "  ${select_name} (select) options: ${options}"
    done

    # Extract textarea fields
    echo "$form_html" | grep -oP '<textarea[^>]*>[\s\S]*?</textarea>' | while IFS= read -r ta_tag; do
      local ta_name
      ta_name=$(echo "$ta_tag" | grep -oP 'name="[^"]*"' | sed 's/name="//;s/"$//')
      local ta_value
      ta_value=$(echo "$ta_tag" | sed 's/<textarea[^>]*>//;s/<\/textarea>//')
      [ -n "$ta_name" ] && param "  ${ta_name} = ${ta_value:0:50}"
    done

    # Extract button fields
    echo "$form_html" | grep -oP '<button[^>]*>[\s\S]*?</button>' | while IFS= read -r btn_tag; do
      local btn_name btn_value
      btn_name=$(echo "$btn_tag" | grep -oP 'name="[^"]*"' | sed 's/name="//;s/"$//')
      btn_value=$(echo "$btn_tag" | sed 's/<button[^>]*>//;s/<\/button>//' | head -c 30)
      [ -n "$btn_name" ] && param "  ${btn_name} = ${btn_value} (button)"
    done
  done < "$tmp_forms"
}

# ─── Extract JS parameter usage ──────────────────────────────────
extract_js_params() {
  local content="$1" source="$2"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[JS PARAMS] Extracting from ${source}${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  local param_uses=0
  local js_params=("id" "userId" "user_id" "token" "apiKey" "api_key"
    "session" "role" "admin" "status" "type" "mode" "action" "method"
    "page" "limit" "offset" "filter" "sort" "order" "file" "path"
    "url" "redirect" "callback" "data" "config" "settings")

  for p in "${js_params[@]}"; do
    local count
    count=$(echo "$content" | grep -co "\"${p}\"" 2>/dev/null || true)
    count=$((count + $(echo "$content" | grep -co "'${p}'" 2>/dev/null || true)))
    if [ "$count" -gt 0 ]; then
      param "  \"${p}\" used ${count}x in JS"
      param_uses=$((param_uses + 1))
    fi
  done

  # Extract fetch/ajax URL patterns
  echo "$content" | grep -oP '(fetch|axios|ajax|XMLHttpRequest)\(['\''"][^'\''"]*['\''"]' | while IFS= read -r call; do
    local found_url
    found_url=$(echo "$call" | grep -oP "['\''\"][^'\''\"]+['\''\"]" | tr -d "'\''\"")
    [ -n "$found_url" ] && info "  API call: ${found_url}"
  done

  info "Found ${param_uses} unique parameter names in JS"
}

# ─── Parameter fuzzing ───────────────────────────────────────────
fuzz_parameters() {
  local url="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[PARAM FUZZ] Testing concealed parameters on ${url}${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  # Build param list
  local params_to_test=()

  if [ -n "$CUSTOM_PARAMS" ]; then
    IFS=',' read -ra params_to_test <<< "$CUSTOM_PARAMS"
  elif [ -n "$WORDLIST" ] && [ -f "$WORDLIST" ]; then
    while IFS= read -r line; do
      [ -n "$line" ] && params_to_test+=("$line")
    done < "$WORDLIST"
  else
    params_to_test=("${COMMON_PARAMS[@]}")
  fi

  local total=${#params_to_test[@]}
  info "Testing ${total} parameters against ${url}"

  # Get baseline
  local baseline_resp
  baseline_resp=$(curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" \
    -w "\n%{size_download}|||%{http_code}" -o /dev/null "$url" 2>/dev/null) || {
    err "Baseline request failed"; return 1
  }
  local baseline_size baseline_status
  baseline_status=$(echo "$baseline_resp}" | rev | cut -d'|' -f1 | rev)
  baseline_size=$(echo "$baseline_resp}" | rev | cut -d'|' -f3 | rev)
  [ -z "$baseline_size" ] && baseline_size=0

  info "Baseline: HTTP ${baseline_status} | ${baseline_size}b"

  local interesting_found=0
  local param_index=0

  for p in "${params_to_test[@]}"; do
    param_index=$((param_index + 1))

    # Construct test URL (preserving existing params)
    local test_url
    if echo "$url" | grep -q '?'; then
      test_url="${url}&${p}=test"
    else
      test_url="${url}?${p}=test"
    fi

    local response
    response=$(curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" \
      -w "\n%{size_download}|||%{http_code}|||%{time_total}" -o /tmp/_param_response_$$.txt "$test_url" 2>/dev/null) || continue
    _cleanup_add "/tmp/_param_response_$$.txt"
    local size status time
    size=$(echo "$response}" | rev | cut -d'|' -f5 | rev)
    status=$(echo "$response}" | rev | cut -d'|' -f3 | rev)
    time=$(echo "$response}" | rev | cut -d'|' -f1 | rev)

    [ -z "$size" ] && size=0
    [ -z "$status" ] && status=0

    # Check for differences
    if [ "$size" -ne "$baseline_size" ] && [ "$size" -gt 0 ]; then
      local size_diff=$((size - baseline_size))
      [ "${size_diff#-}" -gt 50 ] && {
        info "  ?${p}=test → HTTP ${status} | ${size}b (diff: ${size_diff}b) | ${time}s"
        interesting_found=$((interesting_found + 1))
      }
    fi

    if [ "$VERBOSE" = true ] && [ "$param_index" -le 20 ]; then
      echo "  [${param_index}/${total}] ?${p}=test → HTTP ${status} | ${size}b"
    fi
  done

  info "Found ${interesting_found} interesting parameter(s)"
}

# ─── Parameter reflection detection ──────────────────────────────
test_reflection() {
  local url="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[REFLECT TEST] Testing parameter reflection${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  local test_values=("REFLECTED_VALUE_12345" "<test123>" "';alert(1);//" "${RANDOM}${RANDOM}")

  # Extract existing params from URL
  local existing_params=()
  if echo "$url" | grep -q '?'; then
    local qs
    qs=$(echo "$url" | grep -oP '\?.*' | sed 's/^?//')
    IFS='&' read -ra params <<< "$qs"
    for p in "${params[@]}"; do
      local name
      name=$(echo "$p" | cut -d= -f1)
      existing_params+=("$name")
    done
  fi

  if [ ${#existing_params[@]} -eq 0 ]; then
    # Try common reflection-prone params
    existing_params=("q" "s" "search" "query" "name" "page" "id" "error" "msg" "message" "redirect" "url")
  fi

  for param_name in "${existing_params[@]}"; do
    for test_val in "${test_values[@]}"; do
      local test_url
      if echo "$url" | grep -q '?'; then
        test_url=$(echo "$url" | sed "s/[?&]${param_name}=[^&]*/?${param_name}=${test_val}/")
      else
        test_url="${url}?${param_name}=${test_val}"
      fi

      # If URL construction resulted in the same URL, skip
      [ "$test_url" = "$url" ] && continue

      local body
      body=$(curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" "$test_url" 2>/dev/null) || continue

      if echo "$body" | grep -qF "$test_val"; then
        finding "  ?${param_name}=${test_val} → REFLECTED in response"
        break
      fi
    done
  done
}

# ─── Analyze parameter names ─────────────────────────────────────
analyze_param_names() {
  local params="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[PARAM ANALYSIS] Parameter name categorization${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  local id_count=0 auth_count=0 page_count=0 file_count=0
  local debug_count=0 action_count=0 filter_count=0 misc_count=0

  while IFS= read -r p; do
    case "$p" in
      id|user_id|userId|uid|customer_id|client_id|account_id|item_id|product_id|order_id|profile_id)
        id_count=$((id_count + 1)) ;;
      token|api_key|apiKey|session|auth|authorization|secret|password|pass|jwt|access_token|refresh_token)
        auth_count=$((auth_count + 1)) ;;
      page|page_id|section|module|tab|component|view)
        page_count=$((page_count + 1)) ;;
      file|path|url|redirect|return|upload|download|src|href|link)
        file_count=$((file_count + 1)) ;;
      debug|test|dry_run|preview|validate|mock|dev)
        debug_count=$((debug_count + 1)) ;;
      action|method|mode|type|format|output|_method)
        action_count=$((action_count + 1)) ;;
      filter|sort|order|search|q|s|keyword|term|query)
        filter_count=$((filter_count + 1)) ;;
      *)
        misc_count=$((misc_count + 1)) ;;
    esac
  done <<< "$params"

  echo "  ID/Reference:    ${id_count}"
  echo "  Auth/Security:   ${auth_count}"
  echo "  Navigation:      ${page_count}"
  echo "  File/Path:       ${file_count}"
  echo "  Debug/Test:      ${debug_count}"
  echo "  Action/Method:   ${action_count}"
  echo "  Filter/Search:   ${filter_count}"
  echo "  Other:           ${misc_count}"

  echo ""
  if [ "$auth_count" -gt 0 ]; then
    bad "Auth-related parameters found - potential attack surface"
  fi
  if [ "$debug_count" -gt 0 ]; then
    bad "Debug/test parameters found - potential info disclosure"
  fi
  if [ "$file_count" -gt 0 ]; then
    warn "File/path parameters found - potential path traversal / SSRF"
  fi
}

# ─── Output ──────────────────────────────────────────────────────
maybe_output() {
  [ -z "$OUTPUT_FILE" ] && return
  # We'll just redirect output; for now, note it
  info "Output file: ${OUTPUT_FILE}"
}

# ─── Main ────────────────────────────────────────────────────────
main() {
  check_deps
  echo ""
  echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║${NC}  ${GREEN}Parameter Extraction Tool v${VERSION}${NC}"
  local src=""
  [ -n "$TARGET_URL" ] && src="$TARGET_URL"
  [ -n "$TARGET_FILE" ] && src="$TARGET_FILE"
  echo -e "${CYAN}║${NC}  Target: ${YELLOW}${src}${NC}"
  echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"

  local content=""
  local source=""

  if [ -n "$TARGET_URL" ]; then
    info "Fetching: ${TARGET_URL}"
    local resp
    resp=$(_http_get "$TARGET_URL") || { err "Fetch failed"; exit 1; }
    # Extract body (before the appended metadata)
    content=$(echo "$resp" | sed '$d' | sed '$d')
    source="$TARGET_URL"
    ok "Content retrieved"
  elif [ -n "$TARGET_FILE" ]; then
    [ ! -f "$TARGET_FILE" ] && { err "File not found: $TARGET_FILE"; exit 1; }
    content=$(cat "$TARGET_FILE")
    source="$TARGET_FILE"
    ok "File loaded: $TARGET_FILE ($(wc -c <<< "$content") bytes)"
  fi

  [ "$RUN_EXTRACT" = true ] && {
    extract_query_params "$TARGET_URL"
    extract_form_params "$content" "$source"
    extract_js_params "$content" "$source"
  }

  [ "$RUN_FUZZ" = true ] && fuzz_parameters "$TARGET_URL"
  [ "$RUN_REFLECT" = true ] && test_reflection "$TARGET_URL"

  maybe_output

  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${GREEN}Parameter extraction complete${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
}

# ─── Parameter mutation testing ──────────────────────────────────
test_parameter_mutations() {
  local url="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[MUTATION] Parameter value mutations${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  # Common value mutations that might trigger different behavior
  local mutations=(
    "null" "undefined" "0" "-1" "1" "true" "false"
    "admin" "administrator" "root" "test" "demo"
    "<script>alert(1)</script>" "'; DROP TABLE users; --"
    "../../../etc/passwd" "http://evil.com" "file:///etc/passwd"
  )

  # Get existing params from URL
  local existing_params=()
  if echo "$url" | grep -q '?'; then
    local qs
    qs=$(echo "$url" | grep -oP '\?.*' | sed 's/^?//')
    IFS='&' read -ra params <<< "$qs"
    for p in "${params[@]}"; do
      local name
      name=$(echo "$p" | cut -d= -f1)
      existing_params+=("$name")
    done
  fi

  if [ ${#existing_params[@]} -eq 0 ]; then
    info "No params to mutate (use --fuzz first)"
    return
  fi

  info "Testing ${#mutations[@]} mutations against ${#existing_params[@]} params..."

  for param_name in "${existing_params[@]}"; do
    for mutation in "${mutations[@]}"; do
      local encoded_mutation
      encoded_mutation=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$mutation'))" 2>/dev/null || echo "$mutation")
      local test_url
      if echo "$url" | grep -q '?'; then
        test_url=$(echo "$url" | sed "s/[?&]${param_name}=[^&]*/?${param_name}=${encoded_mutation}/")
      else
        test_url="${url}?${param_name}=${encoded_mutation}"
      fi

      local body
      body=$(curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" "$test_url" 2>/dev/null) || continue

      # Check for interesting responses
      if echo "$body" | grep -qi "error\|exception\|stack trace\|warning\|debug"; then
        warn "Error disclosure: ${param_name}=${mutation} at ${test_url:0:80}..."
      fi
      if echo "$body" | grep -qi "admin\|root\|bypass\|unauthorized"; then
        local status
        status=$(curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" -o /dev/null -w "%{http_code}" "$test_url" 2>/dev/null || echo "000")
        if [ "$status" = "200" ]; then
          finding "Access change: ${param_name}=${mutation} → HTTP ${status}"
        fi
      fi
    done
  done
}

# ─── Mass assignment detection ───────────────────────────────────
test_mass_assignment() {
  local url="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[MASS ASSIGN] Mass assignment parameter testing${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  local mass_assign_params=(
    "is_admin=true" "admin=true" "role=admin" "user_role=admin"
    "permission=admin" "access_level=admin" "privilege=admin"
    "is_active=true" "active=true" "enabled=true"
    "verified=true" "is_verified=true" "email_verified=true"
    "is_premium=true" "premium=true" "subscription=premium"
    "is_owner=true" "owner=true"
    "balance=999999" "wallet=999999" "credit=999999"
    "is_deleted=false" "hidden=false" "visible=true"
  )

  info "Testing ${#mass_assign_params[@]} mass assignment vectors..."

  for param in "${mass_assign_params[@]}"; do
    local param_name param_value
    param_name=$(echo "$param" | cut -d= -f1)
    param_value=$(echo "$param" | cut -d= -f2)

    local test_url="${url}?${param_name}=${param_value}"
    local status size
    status=$(curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" -X POST \
      -d "${param}" -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "FAIL")
    size=$(curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" -X POST \
      -d "${param}" -o /dev/null -w "%{size_download}" "$url" 2>/dev/null || echo "0")

    if [ "$status" = "200" ] || [ "$status" = "201" ] || [ "$status" = "204" ]; then
      finding "Mass assignment: POST ${param} → HTTP ${status} (${size}b) at ${url}"
    fi
  done
}

# ─── Generate param report ──────────────────────────────────────
generate_param_report() {
  local url="$1"
  [ -z "$OUTPUT_FILE" ] && return
  local output="$OUTPUT_FILE"

  cat > "$output" <<REPORT
# Parameter Analysis Report

**Target:** ${url}
**Date:** $(date -u '+%Y-%m-%dT%H:%M:%SZ')
**Tool:** ${SCRIPT_NAME} v${VERSION}

## Summary

- Extract analysis: $([ "$RUN_EXTRACT" = true ] && echo 'Yes' || echo 'No')
- Fuzz testing: $([ "$RUN_FUZZ" = true ] && echo 'Yes' || echo 'No')
- Reflection testing: $([ "$RUN_REFLECT" = true ] && echo 'Yes' || echo 'No')

## Discovered Parameters

| Parameter | Source | Value |
|-----------|--------|-------|
| ... | ... | ... |

*Generated by ${SCRIPT_NAME}*
REPORT
  ok "Report: ${output}"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  parse_args "$@"
  main
fi