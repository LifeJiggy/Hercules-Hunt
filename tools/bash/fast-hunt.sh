#!/usr/bin/env bash
# =====================================================================
# fast-hunt.sh — Fast Surface Vulnerability Hunter
#
# Quick probes for common misconfigurations: default paths, debug pages,
# backup files, exposed configs, directory listings. Status code and header
# analysis with color-coded triage output.
#
# Usage:
#   ./fast-hunt.sh -u https://target.com
#   ./fast-hunt.sh -u https://target.com -w paths.txt
#   ./fast-hunt.sh -u https://target.com -o fast-hunt-results.txt
# =====================================================================

set -euo pipefail

# ─── Constants ───────────────────────────────────────────────────
VERSION="1.0.0"
SCRIPT_NAME=$(basename "$0")
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
CONCURRENCY=10
REDIRECT_FOLLOW=false

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; NC='\033[0m'

# Critical/Sensitive paths to check
CRITICAL_PATHS=(
  "/admin" "/administrator" "/admin.php" "/wp-admin" "/manager"
  "/.env" "/.git/config" "/.git/HEAD" "/.svn/entries" "/.DS_Store"
  "/backup" "/backups" "/db_backup" "/database" "/sql" "/dump"
  "/phpinfo.php" "/info.php" "/test.php" "/p.php"
  "/config" "/config.php" "/configuration.php" "/settings"
  "/api/" "/api/v1" "/api/v2" "/graphql" "/rest"
  "/swagger.json" "/swagger.yaml" "/openapi.json" "/api-docs"
  "/crossdomain.xml" "/clientaccesspolicy.xml" "/robots.txt"
  "/sitemap.xml" "/sitemap_index.xml" "/security.txt"
  "/server-status" "/server-info" "/status" "/health" "/healthz"
  "/actuator" "/actuator/health" "/actuator/info" "/actuator/env"
  "/.aws/credentials" "/.azure/credentials" "/.gcp/credentials"
  "/npm-debug.log" "/yarn-debug.log" "/composer.json" "/package.json"
  "/Dockerfile" "/docker-compose.yml" "/.dockerignore"
  "/.htaccess" "/nginx.conf" "/web.config" "/.htpasswd"
  "/error_log" "/access_log" "/debug.log" "/error.log"
  "/tmp" "/temp" "/test" "/dev" "/debug" "/internal"
  "/console" "/monitor" "/dashboard" "/panel"
  "/login" "/signin" "/auth" "/oauth" "/token"
  "/upload" "/uploads" "/files" "/download" "/downloads"
  "/.idea/workspace.xml" "/.vscode/settings.json"
  "/elmah.axd" "/trace.axd" "/_vti_inf.html"
  "/WEB-INF/web.xml" "/META-INF/MANIFEST.MF"
  "/cgi-bin/" "/cgi-bin/test.cgi"
  "/phpmyadmin" "/phpMyAdmin" "/mysql" "/pma"
  "/.well-known/security.txt" "/.well-known/assetlinks.json"
  "/apple-app-site-association" "/.well-known/apple-app-site-association"
)

BACKUP_EXTENSIONS=(".bak" ".backup" ".old" ".orig" ".copy" ".save"
  ".swp" ".swo" ".swn" "~" ".tmp" ".temp" ".txt" ".1" ".2024" ".2025"
  ".2026" "-bak" "-backup" "-old" "-copy")

COMMON_CONFIG_FILES=(
  "config.json" "config.yaml" "config.yml" "config.xml" "config.php"
  "settings.json" "settings.py" "settings.rb" "settings.cfg"
  "database.yml" "database.json" "db.yml" "db.json"
  ".env" ".env.local" ".env.dev" ".env.prod" ".env.staging"
  "credentials.json" "credentials.yml" "secrets.json" "secrets.yml"
  "app.json" "app.yaml" "app.yml" "application.yml"
  "docker-compose.yml" "docker-compose.override.yml"
  "package.json" "package-lock.json" "yarn.lock" "composer.lock"
  "Gemfile" "Gemfile.lock" "requirements.txt" "Pipfile"
  "Makefile" "Rakefile" "Gruntfile.js" "gulpfile.js"
  "webpack.config.js" "vite.config.js" "rollup.config.js"
  "tsconfig.json" ".babelrc" ".eslintrc" ".prettierrc"
  "nginx.conf" "httpd.conf" ".htaccess" "web.config"
  "Dockerfile" "docker-compose.yml" "Makefile"
)

COMMON_METHODS=("GET" "POST" "PUT" "PATCH" "DELETE" "OPTIONS" "HEAD" "TRACE")

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
info()       { echo -e "${CYAN}[i]${NC} $*"; }
ok()         { echo -e "${GREEN}[+]${NC} $*"; }
warn()       { echo -e "${YELLOW}[!]${NC} $*" >&2; }
err()        { echo -e "${RED}[-]${NC} $*" >&2; }
finding()    { echo -e "${MAGENTA}[FINDING]${NC} $*"; }
critical()   { echo -e "${RED}[CRITICAL]${NC} $*"; }
interesting(){ echo -e "${YELLOW}[INFO]${NC} $*"; }

# ─── Usage ───────────────────────────────────────────────────────
usage() {
  cat <<EOF
${CYAN}fast-hunt.sh${NC} v${VERSION} — Fast Surface Vulnerability Hunter

${YELLOW}Description:${NC}
  Quick probes for common misconfigurations: default paths, debug pages,
  backup files, exposed configs, directory listings. Status code and header
  analysis with color-coded triage output. Designed for rapid surface-level
  assessment before deep hunting.

${YELLOW}Usage:${NC}
  $SCRIPT_NAME -u <url>                Quick scan a target
  $SCRIPT_NAME -u <url> -w <file>      Custom path wordlist
  $SCRIPT_NAME -u <url> --methods      Test HTTP methods
  $SCRIPT_NAME -u <url> --backups      Check backup files
  $SCRIPT_NAME -u <url> --headers      Analyze security headers

${YELLOW}Modes:${NC}
  --paths         Test common paths (default: enabled)
  --methods       Test HTTP method verbs
  --backups       Check backup file extensions
  --config        Check config file exposure
  --headers       Analyze security headers
  --crawl         Crawl and find more paths
  --all           Run all checks (default)

${YELLOW}Options:${NC}
  -u <url>          Target URL (required)
  -w <file>         Custom wordlist file
  -o <file>         Output file
  -t <seconds>      Request timeout (default: 10)
  -j <num>          Concurrency (default: 10)
  --no-redirect     Don't follow redirects
  -q                Quiet mode
  -v                Verbose mode
  -h                Show help

${YELLOW}Examples:${NC}
  $SCRIPT_NAME -u https://target.com
  $SCRIPT_NAME -u https://target.com -w custom-paths.txt
  $SCRIPT_NAME -u https://target.com --methods --headers
EOF
  exit 0
}

# ─── Options ─────────────────────────────────────────────────────
TARGET_URL=""
WORDLIST=""
OUTPUT_FILE=""
TIMEOUT=10
QUIET=false
VERBOSE=false

RUN_PATHS=true
RUN_METHODS=false
RUN_BACKUPS=false
RUN_CONFIG=false
RUN_HEADERS=false
RUN_CRAWL=false

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help) usage ;;
      -u|--url) TARGET_URL="$2"; shift 2 ;;
      -w|--wordlist) WORDLIST="$2"; shift 2 ;;
      -o|--output) OUTPUT_FILE="$2"; shift 2 ;;
      -t|--timeout) TIMEOUT="$2"; shift 2 ;;
      -j|--jobs) CONCURRENCY="$2"; shift 2 ;;
      --no-redirect) REDIRECT_FOLLOW=false; shift ;;
      -q|--quiet) QUIET=true; shift ;;
      -v|--verbose) VERBOSE=true; shift ;;
      --paths) RUN_PATHS=true; RUN_METHODS=false; RUN_BACKUPS=false; RUN_CONFIG=false; RUN_HEADERS=false; RUN_CRAWL=false; shift ;;
      --methods) RUN_PATHS=false; RUN_METHODS=true; RUN_BACKUPS=false; RUN_CONFIG=false; RUN_HEADERS=false; RUN_CRAWL=false; shift ;;
      --backups) RUN_PATHS=false; RUN_METHODS=false; RUN_BACKUPS=true; RUN_CONFIG=false; RUN_HEADERS=false; RUN_CRAWL=false; shift ;;
      --config) RUN_PATHS=false; RUN_METHODS=false; RUN_BACKUPS=false; RUN_CONFIG=true; RUN_HEADERS=false; RUN_CRAWL=false; shift ;;
      --headers) RUN_PATHS=false; RUN_METHODS=false; RUN_BACKUPS=false; RUN_CONFIG=false; RUN_HEADERS=true; RUN_CRAWL=false; shift ;;
      --crawl) RUN_CRAWL=true; shift ;;
      --all) RUN_PATHS=true; RUN_METHODS=true; RUN_BACKUPS=true; RUN_CONFIG=true; RUN_HEADERS=true; RUN_CRAWL=false; shift ;;
      *) err "Unknown: $1"; usage ;;
    esac
  done
  [ -z "$TARGET_URL" ] && { err "No target URL"; usage; }
}

check_deps() {
  local deps=("curl" "grep" "sed" "awk" "sort" "uniq")
  local missing=()
  for d in "${deps[@]}"; do command -v "$d" &>/dev/null || missing+=("$d"); done
  [ ${#missing[@]} -gt 0 ] && { err "Missing: ${missing[*]}"; exit 1; }
}

# ─── HTTP request ────────────────────────────────────────────────
_http_probe() {
  local method="$1" url="$2"
  local -a curl_args=(-sk --max-time "$TIMEOUT")
  $REDIRECT_FOLLOW || curl_args+=(-L)
  curl_args+=(-A "$USER_AGENT" -X "$method" -o /dev/null -w "%{http_code}|||%{size_download}|||%{time_total}|||%{content_type}|||%{redirect_url}" "$url")
  curl "${curl_args[@]}" 2>/dev/null || echo "FAIL|||0|||0|||unknown|||"
}

# ─── Probe a single path ─────────────────────────────────────────
probe_path() {
  local base="$1" path="$2"
  local url="${base}${path}"
  local result
  result=$(_http_probe "GET" "$url")
  local status size time content_type redirect
  status=$(echo "$result" | cut -d'|' -f1)
  size=$(echo "$result" | cut -d'|' -f3)
  time=$(echo "$result" | cut -d'|' -f5)
  content_type=$(echo "$result" | cut -d'|' -f7)
  redirect=$(echo "$result" | cut -d'|' -f9)

  # Classify response
  local label=""
  case "$status" in
    200|201|202|203|204)
      if [ "$size" -gt 0 ]; then
        label="${GREEN}EXPOSED${NC}"
        finding "${label} HTTP ${status} | ${size}b | ${time}s | ${path} (${content_type})"
      else
        label="${YELLOW}EMPTY${NC}"
        interesting "${label} HTTP ${status} | ${size}b | ${path}"
      fi
      ;;
    301|302|303|307|308)
      label="${CYAN}REDIRECT${NC}"
      interesting "${label} HTTP ${status} | → ${redirect} | ${path}"
      ;;
    400|401|403)
      label="${YELLOW}RESTRICTED${NC}"
      [ "$VERBOSE" = true ] && interesting "${label} HTTP ${status} | ${size}b | ${path}"
      ;;
    404)
      ;;
    405)
      label="${CYAN}METHOD NOT ALLOWED${NC}"
      [ "$VERBOSE" = true ] && interesting "${label} HTTP ${status} | ${path}"
      ;;
    429)
      label="${RED}RATE LIMITED${NC}"
      warn "${label} HTTP ${status} | ${path}"
      ;;
    500|502|503)
      label="${RED}SERVER ERROR${NC}"
      critical "${label} HTTP ${status} | ${path}"
      ;;
    *)
      [ -n "$result" ] && [ "$result" != "FAIL" ] && interesting "HTTP ${status} | ${path}"
      ;;
  esac
}

# ─── Load paths (wordlist + built-in) ────────────────────────────
load_paths() {
  local tmp
  tmp=$(mktemp) && _cleanup_add "$tmp"

  # Always include critical paths
  for p in "${CRITICAL_PATHS[@]}"; do echo "$p" >> "$tmp"; done

  # Wordlist if provided
  if [ -n "$WORDLIST" ] && [ -f "$WORDLIST" ]; then
    while IFS= read -r line; do
      [ -n "$line" ] && echo "$line" >> "$tmp"
    done < "$WORDLIST"
  fi

  sort -u "$tmp" | grep -v '^\s*$'
}

# ─── Path scanning ───────────────────────────────────────────────
scan_paths() {
  local base="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[PATH SCAN] Probing common paths on ${base}${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  local paths
  paths=$(load_paths)
  local total found=0
  total=$(echo "$paths" | wc -l)
  info "Testing ${total} paths..."

  while IFS= read -r path; do
    [ -z "$path" ] && continue
    probe_path "$base" "$path"
  done <<< "$paths"

  ok "Path scan complete"
}

# ─── HTTP method testing ─────────────────────────────────────────
scan_methods() {
  local url="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[METHOD SCAN] Testing HTTP methods on ${url}${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  for method in "${COMMON_METHODS[@]}"; do
    local result
    result=$(_http_probe "$method" "$url")
    local status size
    status=$(echo "$result" | cut -d'|' -f1)
    size=$(echo "$result" | cut -d'|' -f3)

    case "$method" in
      GET)     [ "$status" = "200" ] && ok "GET     → HTTP ${status} (${size}b)" || echo "  GET     → HTTP ${status} (${size}b)" ;;
      POST)    [[ "$status" != "405" && "$status" != "404" ]] && finding "POST    → HTTP ${status} (${size}b) - Possibly enabled" || echo "  POST    → HTTP ${status}" ;;
      PUT)     [[ "$status" != "405" && "$status" != "404" ]] && critical "PUT     → HTTP ${status} (${size}b) - Upload vector!" || echo "  PUT     → HTTP ${status}" ;;
      PATCH)   [[ "$status" != "405" && "$status" != "404" ]] && finding "PATCH   → HTTP ${status} (${size}b)" || echo "  PATCH   → HTTP ${status}" ;;
      DELETE)  [[ "$status" != "405" && "$status" != "404" ]] && critical "DELETE  → HTTP ${status} (${size}b) - Deletion vector!" || echo "  DELETE  → HTTP ${status}" ;;
      OPTIONS) echo "  OPTIONS → HTTP ${status} (${size}b)" ;;
      HEAD)    echo "  HEAD    → HTTP ${status} (${size}b)" ;;
      TRACE)   [ "$status" = "200" ] && critical "TRACE   → HTTP ${status} - XST vector!" || echo "  TRACE   → HTTP ${status}" ;;
    esac
  done
}

# ─── Backup file scanning ────────────────────────────────────────
scan_backups() {
  local url="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[BACKUP SCAN] Checking for backup/leaked files${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  # Get base path components
  local base_path
  base_path=$(echo "$url" | grep -oP '^https?://[^/]+')
  local url_path
  url_path=$(echo "$url" | sed 's|^https\?://[^/]*||')

  # If URL has a path, try backup variants of that path
  if [ -n "$url_path" ] && [ "$url_path" != "/" ]; then
    local filename
    filename=$(basename "$url_path")
    local dirpath
    dirpath=$(dirname "$url_path")

    for ext in "${BACKUP_EXTENSIONS[@]}"; do
      local backup_url="${base_path}${dirpath}/${filename}${ext}"
      local result
      result=$(_http_probe "GET" "$backup_url")
      local status size
      status=$(echo "$result" | cut -d'|' -f1)
      size=$(echo "$result" | cut -d'|' -f3)
      if [ "$status" = "200" ] && [ "$size" -gt 0 ]; then
        critical "Backup found: ${backup_url} (HTTP ${status}, ${size}b)"
      fi
    done

    # Try .filename.swp pattern (vim swap)
    local swp_url="${base_path}${dirpath}/.${filename}.swp"
    local result
    result=$(_http_probe "GET" "$swp_url")
    local status
    status=$(echo "$result" | cut -d'|' -f1)
    [ "$status" = "200" ] && critical "Vim swap: ${swp_url}"
  fi

  # Check common backup names on root
  for name in "backup" "db_backup" "dump" "database" "site_backup" "www_backup" "htdocs_backup"; do
    for ext in "${BACKUP_EXTENSIONS[@]:0:5}"; do
      local bkp_url="${base_path}/${name}${ext}"
      local result
      result=$(_http_probe "GET" "$bkp_url")
      local status size
      status=$(echo "$result" | cut -d'|' -f1)
      size=$(echo "$result" | cut -d'|' -f3)
      [ "$status" = "200" ] && [ "$size" -gt 0 ] && critical "Backup: ${bkp_url}"
    done
  done
}

# ─── Config file scanning ────────────────────────────────────────
scan_configs() {
  local url="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[CONFIG SCAN] Checking for exposed config files${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  local base
  base=$(echo "$url" | grep -oP '^https?://[^/]+')

  for cfg in "${COMMON_CONFIG_FILES[@]}"; do
    local config_url="${base}/${cfg}"
    local result
    result=$(_http_probe "GET" "$config_url")
    local status size content_type
    status=$(echo "$result" | cut -d'|' -f1)
    size=$(echo "$result" | cut -d'|' -f3)
    content_type=$(echo "$result" | cut -d'|' -f7)

    if [ "$status" = "200" ] && [ "$size" -gt 0 ]; then
      # Try to detect if it's actual config content vs 404 page
      local body
      body=$(curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" "$config_url" 2>/dev/null | head -20)
      if echo "$body" | grep -qiE '(password|secret|api_key|token|database|username)'; then
        critical "Config with secrets: ${config_url} (HTTP ${status}, ${size}b)"
      elif [ "$size" -gt 100 ]; then
        finding "Config exposed: ${config_url} (HTTP ${status}, ${size}b)"
        [ "$VERBOSE" = true ] && echo "  First line: $(echo "$body" | head -1)"
      fi
    fi
  done
}

# ─── Security header analysis ────────────────────────────────────
analyze_headers() {
  local url="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[HEADER ANALYSIS] Security headers on ${url}${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  local tmpfile
  tmpfile=$(mktemp) && _cleanup_add "$tmpfile"
  curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" -D "$tmpfile" -o /dev/null "$url" 2>/dev/null || {
    err "Failed to fetch headers"; return 1
  }

  local headers
  headers=$(cat "$tmpfile" | tr -d '\r')

  # Server info
  local server
  server=$(echo "$headers" | grep -i '^server:' | sed 's/[Ss]erver: //')
  [ -n "$server" ] && echo -e "  ${YELLOW}Server:${NC} $server"

  # X-Powered-By
  local powered
  powered=$(echo "$headers" | grep -i '^x-powered-by:' | sed 's/[Xx]-[Pp]owered-[Bb]y: //')
  [ -n "$powered" ] && echo -e "  ${YELLOW}X-Powered-By:${NC} $powered"

  echo ""

  # Analyze security headers
  local security_headers=(
    "Strict-Transport-Security:HSTS"
    "Content-Security-Policy:CSP"
    "X-Content-Type-Options:Content-Type-Options"
    "X-Frame-Options:Frame-Options"
    "X-XSS-Protection:XSS-Protection"
    "Referrer-Policy:Referrer-Policy"
    "Permissions-Policy:Permissions-Policy"
    "Access-Control-Allow-Origin:CORS"
    "Set-Cookie:Cookies"
    "Feature-Policy:Feature-Policy"
    "Cross-Origin-Embedder-Policy:COEP"
    "Cross-Origin-Opener-Policy:COOP"
    "Cross-Origin-Resource-Policy:CORP"
    "Cache-Control:Cache-Control"
    "Pragma:Pragma"
    "Expires:Expires"
  )

  for header_entry in "${security_headers[@]}"; do
    local header_name header_label
    header_name=$(echo "$header_entry" | cut -d: -f1)
    header_label=$(echo "$header_entry" | cut -d: -f2)
    if echo "$headers" | grep -qi "^${header_name}:"; then
      local value
      value=$(echo "$headers" | grep -i "^${header_name}:" | head -1 | sed "s/^${header_name}: //I")
      ok "${header_label}: ${value}"
    else
      warn "MISSING: ${header_label}"
    fi
  done

  echo ""
  info "Cookies analysis:"
  while IFS= read -r cookie_line; do
    local cookie_name cookie_value
    cookie_name=$(echo "$cookie_line" | sed 's/^[Ss]et-[Cc]ookie: //' | cut -d= -f1)
    cookie_value=$(echo "$cookie_line" | sed 's/^[Ss]et-[Cc]ookie: //' | cut -d= -f2 | cut -d';' -f1)

    local flags=""
    echo "$cookie_line" | grep -qi 'httponly' && flags="${flags} HttpOnly"
    echo "$cookie_line" | grep -qi 'secure' && flags="${flags} Secure"
    echo "$cookie_line" | grep -qi 'samesite' && flags="${flags} $(echo "$cookie_line" | grep -oi 'samesite=[a-z]*' | tr '[:upper:]' '[:lower:]')"

    if echo "$flags" | grep -q 'HttpOnly'; then
      ok "  ${cookie_name}=${cookie_value} ${flags}"
    else
      warn "  ${cookie_name}=${cookie_value} ${flags} (Missing HttpOnly)"
    fi
  done < <(echo "$headers" | grep -i '^set-cookie:')
}

# ─── Crawl-based discovery ───────────────────────────────────────
crawl_discover() {
  local url="$1" depth="${2:-1}" max_pages="${3:-20}"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[CRAWL] Crawling ${url} for path discovery${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  local visited=() to_visit=("$url")
  local discovered_paths=""

  for ((i=0; i<max_pages && ${#to_visit[@]} > 0; i++)); do
    local current="${to_visit[0]}"
    to_visit=("${to_visit[@]:1}")

    # Skip visited
    local skip=false
    for v in "${visited[@]}"; do [ "$v" = "$current" ] && skip=true && break; done
    $skip && continue
    visited+=("$current")

    local body
    body=$(curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" "$current" 2>/dev/null) || continue

    # Extract links
    local links
    links=$(echo "$body" | grep -oP 'href="[^"]*"' | sed 's/href="//;s/"$//' | sort -u)
    while IFS= read -r link; do
      [ -z "$link" ] && continue

      # Normalize
      local abs_link
      if echo "$link" | grep -qE '^https?://'; then abs_link="$link"
      elif echo "$link" | grep -qE '^//'; then abs_link="https:${link}"
      elif echo "$link" | grep -qE '^/'; then
        local base_domain; base_domain=$(echo "$current" | grep -oP '^https?://[^/]+')
        abs_link="${base_domain}${link}"
      else
        local base_dir; base_dir=$(dirname "$current" | sed 's|/$||')
        abs_link="${base_dir}/${link}"
      fi

      # Only keep same-domain links
      local domain1; domain1=$(echo "$url" | grep -oP 'https?://[^/]+')
      local domain2; domain2=$(echo "$abs_link" | grep -oP 'https?://[^/]+')
      if [ "$domain1" = "$domain2" ]; then
        # Extract path
        local path; path=$(echo "$abs_link" | sed "s|${domain1}||")
        [ -n "$path" ] && [ "$path" != "/" ] && discovered_paths="${discovered_paths}${path}"$'\n'
        to_visit+=("$abs_link")
      fi
    done <<< "$links"
  done

  local unique_paths
  unique_paths=$(echo "$discovered_paths" | sort -u | grep -v '^\s*$')
  local count
  count=$(echo "$unique_paths" | wc -l)
  info "Crawl discovered ${count} unique paths"
  echo "$unique_paths" | while IFS= read -r p; do
    [ -n "$p" ] && probe_path "$url" "$p"
  done
}

# ─── Output to file ──────────────────────────────────────────────
maybe_output() {
  [ -z "$OUTPUT_FILE" ] && return
  info "Output will be written to: $OUTPUT_FILE"
}

# ─── Summary ─────────────────────────────────────────────────────
show_summary() {
  local url="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${GREEN}Fast Hunt Complete for ${url}${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "  ${YELLOW}Paths:${NC}    $([ "$RUN_PATHS" = true ] && echo 'Scan' || echo 'Skip')"
  echo -e "  ${YELLOW}Methods:${NC}  $([ "$RUN_METHODS" = true ] && echo 'Scan' || echo 'Skip')"
  echo -e "  ${YELLOW}Backups:${NC}  $([ "$RUN_BACKUPS" = true ] && echo 'Scan' || echo 'Skip')"
  echo -e "  ${YELLOW}Configs:${NC}  $([ "$RUN_CONFIG" = true ] && echo 'Scan' || echo 'Skip')"
  echo -e "  ${YELLOW}Headers:${NC}  $([ "$RUN_HEADERS" = true ] && echo 'Analyzed' || echo 'Skip')"
  echo -e "  ${YELLOW}Crawl:${NC}    $([ "$RUN_CRAWL" = true ] && echo 'Enabled' || echo 'Disabled')"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
}

# ─── Main ────────────────────────────────────────────────────────
main() {
  check_deps
  echo ""
  echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║${NC}  ${GREEN}Fast Surface Hunter v${VERSION}${NC}"
  echo -e "${CYAN}║${NC}  Target: ${YELLOW}${TARGET_URL}${NC}"
  echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"

  [ "$RUN_PATHS" = true ] && scan_paths "$TARGET_URL"
  [ "$RUN_METHODS" = true ] && scan_methods "$TARGET_URL"
  [ "$RUN_BACKUPS" = true ] && scan_backups "$TARGET_URL"
  [ "$RUN_CONFIG" = true ] && scan_configs "$TARGET_URL"
  [ "$RUN_HEADERS" = true ] && analyze_headers "$TARGET_URL"
  [ "$RUN_CRAWL" = true ] && crawl_discover "$TARGET_URL"

  show_summary "$TARGET_URL"
  maybe_output
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  parse_args "$@"
  main
fi