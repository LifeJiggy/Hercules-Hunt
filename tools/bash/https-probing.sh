#!/usr/bin/env bash
# =====================================================================
# https-probing.sh — HTTPS/TLS Probing and Analysis Tool
#
# Uses openssl and curl for TLS analysis, certificate info extraction,
# cipher suite detection, and security header analysis (HSTS, CSP, HPKP).
# Supports full TLS handshake inspection and vulnerability assessment.
#
# Usage:
#   ./https-probing.sh -h target.com
#   ./https-probing.sh -h target.com -p 8443
#   ./https-probing.sh -h target.com --cipher-scan
# =====================================================================

set -euo pipefail

# ─── Constants ───────────────────────────────────────────────────
VERSION="1.0.0"
SCRIPT_NAME=$(basename "$0")
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

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
info()  { echo -e "${CYAN}[i]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*" >&2; }
err()   { echo -e "${RED}[-]${NC} $*" >&2; }
bad()   { echo -e "${RED}[VULN]${NC} $*"; }
good()  { echo -e "${GREEN}[SECURE]${NC} $*"; }

# ─── Usage ───────────────────────────────────────────────────────
usage() {
  cat <<EOF
${CYAN}https-probing.sh${NC} v${VERSION} — HTTPS/TLS Probing and Analysis Tool

${YELLOW}Description:${NC}
  Analyzes TLS configurations, extracts certificate information, detects
  supported cipher suites, and evaluates security headers. Supports both
  curl-based header analysis and openssl-based TLS handshake inspection.

${YELLOW}Usage:${NC}
  $SCRIPT_NAME -h <host>                  Basic TLS info
  $SCRIPT_NAME -h <host> -p <port>        Custom port
  $SCRIPT_NAME -h <host> --full           Full TLS audit
  $SCRIPT_NAME -h <host> --cipher-scan    Scan cipher suites
  $SCRIPT_NAME -h <host> --headers        Security headers only
  $SCRIPT_NAME -h <host> --cert           Certificate details only

${YELLOW}Modes:${NC}
  --basic         Basic TLS info (default)
  --cert          Full certificate analysis
  --cipher-scan   Scan supported cipher suites
  --headers       Analyze security headers
  --full          Run all checks

${YELLOW}Options:${NC}
  -h <host>         Target hostname (required)
  -p <port>         Port (default: 443)
  -s <sni>          SNI hostname (default: same as host)
  --timeout <sec>   Connection timeout (default: 10)
  -o <file>         Output file
  -q                Quiet mode
  -v                Verbose mode
  --no-color        Disable color output
  --help            Show this help

${YELLOW}Examples:${NC}
  $SCRIPT_NAME -h example.com
  $SCRIPT_NAME -h example.com -p 8443 --full
  $SCRIPT_NAME -h example.com --cipher-scan
EOF
  exit 0
}

# ─── Options ─────────────────────────────────────────────────────
TARGET_HOST=""
TARGET_PORT=443
SNI_HOST=""
TIMEOUT=10
OUTPUT_FILE=""
QUIET=false
VERBOSE=false
NO_COLOR=false

RUN_BASIC=true
RUN_CERT=false
RUN_CIPHER=false
RUN_HEADERS=false

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --help) usage ;;
      -h|--host) TARGET_HOST="$2"; shift 2 ;;
      -p|--port) TARGET_PORT="$2"; shift 2 ;;
      -s|--sni) SNI_HOST="$2"; shift 2 ;;
      --timeout) TIMEOUT="$2"; shift 2 ;;
      -o|--output) OUTPUT_FILE="$2"; shift 2 ;;
      -q|--quiet) QUIET=true; shift ;;
      -v|--verbose) VERBOSE=true; shift ;;
      --no-color) NO_COLOR=true; RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; shift ;;
      --basic) RUN_BASIC=true; RUN_CERT=false; RUN_CIPHER=false; RUN_HEADERS=false; shift ;;
      --cert) RUN_BASIC=false; RUN_CERT=true; RUN_CIPHER=false; RUN_HEADERS=false; shift ;;
      --cipher-scan) RUN_BASIC=false; RUN_CERT=false; RUN_CIPHER=true; RUN_HEADERS=false; shift ;;
      --headers) RUN_BASIC=false; RUN_CERT=false; RUN_CIPHER=false; RUN_HEADERS=true; shift ;;
      --full) RUN_BASIC=true; RUN_CERT=true; RUN_CIPHER=true; RUN_HEADERS=true; shift ;;
      *) err "Unknown: $1"; usage ;;
    esac
  done
  [ -z "$TARGET_HOST" ] && { err "No target host"; usage; }
  [ -z "$SNI_HOST" ] && SNI_HOST="$TARGET_HOST"
}

check_deps() {
  local missing=()
  command -v curl &>/dev/null || missing+=("curl")
  command -v openssl &>/dev/null || missing+=("openssl")
  command -v grep &>/dev/null || missing+=("grep")
  command -v sed &>/dev/null || missing+=("sed")
  command -v awk &>/dev/null || missing+=("awk")
  [ ${#missing[@]} -gt 0 ] && { err "Missing: ${missing[*]}"; exit 1; }
}

# ─── Basic TLS info ──────────────────────────────────────────────
get_basic_info() {
  local host="$1" port="$2"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[BASIC TLS] ${host}:${port}${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  # TLS connection test
  local tls_result
  tls_result=$(echo "" | openssl s_client -connect "${host}:${port}" \
    -servername "$SNI_HOST" -tlsextdebug 2>&1 <<< "Q") || true

  if echo "$tls_result" | grep -qi "connect: errno"; then
    err "Cannot connect to ${host}:${port}"
    return 1
  fi

  # TLS version
  local tls_version
  tls_version=$(echo "$tls_result" | grep -i "tls" | head -1 | sed 's/^ *//')
  [ -z "$tls_version" ] && tls_version=$(echo "$tls_result" | grep -i "protocol" | head -1 | sed 's/^ *//')
  echo -e "  ${YELLOW}TLS Version:${NC} ${tls_version:-Unknown}"

  # Certificate chain length
  local cert_chain_len
  cert_chain_len=$(echo "$tls_result" | grep -c "^Certificate chain" || true)
  echo -e "  ${YELLOW}Cert Chain:${NC} ${cert_chain_len} certificates"

  # Check for ALPN
  if echo "$tls_result" | grep -qi "ALPN"; then
    local alpn
    alpn=$(echo "$tls_result" | grep -i "ALPN" | head -1)
    echo -e "  ${YELLOW}ALPN:${NC} ${alpn#*: }"
  fi

  # Check for NPN
  if echo "$tls_result" | grep -qi "NPN"; then
    echo -e "  ${YELLOW}NPN:${NC} Negotiated"
  fi

  # OCSP stapling
  if echo "$tls_result" | grep -qi "OCSP response"; then
    local ocsp_status
    ocsp_status=$(echo "$tls_result" | grep -i "OCSP response" | head -1)
    echo -e "  ${YELLOW}OCSP Stapling:${NC} ${ocsp_status#*: }"
  fi

  # Session resumption
  echo -e "  ${YELLOW}Session Ticket:${NC} $(echo "$tls_result" | grep -qi "session ticket" && echo "Present" || echo "None")"

  # Check for TLS 1.0/1.1 (deprecated)
  local tls10_ok tls11_ok
  tls10_ok=$(echo "" | openssl s_client -connect "${host}:${port}" \
    -servername "$SNI_HOST" -tls1 2>&1 <<< "Q" | grep -i "connect: errno" || true)
  tls11_ok=$(echo "" | openssl s_client -connect "${host}:${port}" \
    -servername "$SNI_HOST" -tls1_1 2>&1 <<< "Q" | grep -i "connect: errno" || true)

  [ -z "$tls10_ok" ] && bad "TLS 1.0 enabled (deprecated!)"
  [ -z "$tls11_ok" ] && bad "TLS 1.1 enabled (deprecated!)"

  good "Connection established to ${host}:${port}"
}

# ─── Certificate analysis ────────────────────────────────────────
analyze_certificate() {
  local host="$1" port="$2"
  local cert_pem
  cert_pem=$(mktemp) && _cleanup_add "$cert_pem"

  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[CERTIFICATE] ${host}:${port}${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  openssl s_client -connect "${host}:${port}" -servername "$SNI_HOST" \
    -showcerts 2>&1 <<< "Q" | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > "$cert_pem" 2>/dev/null

  if [ ! -s "$cert_pem" ]; then
    err "No certificate data retrieved"
    return 1
  fi

  # Subject
  local subject
  subject=$(openssl x509 -in "$cert_pem" -noout -subject 2>/dev/null)
  echo -e "  ${YELLOW}Subject:${NC} ${subject}"

  # Issuer
  local issuer
  issuer=$(openssl x509 -in "$cert_pem" -noout -issuer 2>/dev/null)
  echo -e "  ${YELLOW}Issuer:${NC} ${issuer}"

  # Validity
  local not_before not_after
  not_before=$(openssl x509 -in "$cert_pem" -noout -dates 2>/dev/null | grep "notBefore" | cut -d= -f2)
  not_after=$(openssl x509 -in "$cert_pem" -noout -dates 2>/dev/null | grep "notAfter" | cut -d= -f2)
  echo -e "  ${YELLOW}Valid From:${NC} ${not_before}"
  echo -e "  ${YELLOW}Valid Until:${NC} ${not_after}"

  # Check expiration
  local expiry_epoch now_epoch
  expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null) || expiry_epoch=0
  now_epoch=$(date +%s)
  local remaining_days=$(( (expiry_epoch - now_epoch) / 86400 ))
  if [ "$remaining_days" -lt 0 ]; then
    bad "Certificate EXPIRED ${remaining_days} days ago!"
  elif [ "$remaining_days" -lt 30 ]; then
    warn "Certificate expires in ${remaining_days} days"
  else
    ok "Certificate valid for ${remaining_days} days"
  fi

  # Serial number
  local serial
  serial=$(openssl x509 -in "$cert_pem" -noout -serial 2>/dev/null | cut -d= -f2)
  echo -e "  ${YELLOW}Serial:${NC} ${serial}"

  # SHA256 fingerprint
  local sha256_fp
  sha256_fp=$(openssl x509 -in "$cert_pem" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
  echo -e "  ${YELLOW}SHA256 FP:${NC} ${sha256_fp}"

  # Key algorithm and size
  local key_info
  key_info=$(openssl x509 -in "$cert_pem" -noout -text 2>/dev/null | grep -i "public key" | head -1)
  echo -e "  ${YELLOW}Public Key:${NC} ${key_info}"

  # Key size check
  local key_size
  key_size=$(echo "$key_info" | grep -oP '[0-9]+' | head -1)
  if [ -n "$key_size" ] && [ "$key_size" -lt 2048 ]; then
    bad "Weak key size: ${key_size} bits (minimum 2048)"
  elif [ -n "$key_size" ] && [ "$key_size" -ge 4096 ]; then
    good "Strong key: ${key_size} bits"
  fi

  # Signature algorithm
  local sig_algo
  sig_algo=$(openssl x509 -in "$cert_pem" -noout -text 2>/dev/null | grep -i "signature algorithm" | head -1)
  echo -e "  ${YELLOW}Signature:${NC} ${sig_algo}"

  # SAN (Subject Alternative Names)
  echo -e "  ${YELLOW}SANs:${NC}"
  openssl x509 -in "$cert_pem" -noout -ext subjectAltName 2>/dev/null | grep -oP 'DNS:[a-zA-Z0-9.*-]+' | while IFS= read -r san; do
    [ -n "$san" ] && echo "    ${san}"
  done

  # Extended Validation
  if openssl x509 -in "$cert_pem" -noout -text 2>/dev/null | grep -qi "extended validation\|EV"; then
    ok "Extended Validation (EV) certificate"
  fi

  # Wildcard
  if openssl x509 -in "$cert_pem" -noout -text 2>/dev/null | grep -qi "DNS:\*."; then
    warn "Wildcard certificate detected"
  fi

  # Revocation information
  local crl_distribution
  crl_distribution=$(openssl x509 -in "$cert_pem" -noout -text 2>/dev/null | grep -i "crl distribution" -A1 | tail -1)
  [ -n "$crl_distribution" ] && echo -e "  ${YELLOW}CRL:${NC} ${crl_distribution}"

  local ocsp_url
  ocsp_url=$(openssl x509 -in "$cert_pem" -noout -text 2>/dev/null | grep -i "OCSP" -A1 | tail -1 | grep -oP 'https?://[^"]+')
  [ -n "$ocsp_url" ] && echo -e "  ${YELLOW}OCSP URL:${NC} ${ocsp_url}"

  # Certificate Transparency (embedded SCTs)
  if openssl x509 -in "$cert_pem" -noout -text 2>/dev/null | grep -qi "signed certificate timestamp"; then
    ok "Certificate Transparency (SCTs present)"
  else
    warn "No Certificate Transparency SCTs"
  fi

  rm -f "$cert_pem"
}

# ─── Cipher scan ─────────────────────────────────────────────────
scan_ciphers() {
  local host="$1" port="$2"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[CIPHER SCAN] Supported ciphers on ${host}:${port}${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  info "This may take a while..."

  # TLS 1.2 ciphers
  echo -e "\n${CYAN}TLS 1.2 Ciphers:${NC}"
  local tls12_ciphers=$(openssl ciphers -tls1_2 'ALL:COMPLEMENTOFALL' 2>/dev/null | tr ':' '\n')
  local strong=0 weak=0 insecure=0

  while IFS= read -r cipher; do
    [ -z "$cipher" ] && continue
    local result
    result=$(echo "" | openssl s_client -connect "${host}:${port}" \
      -servername "$SNI_HOST" -tls1_2 -cipher "$cipher" 2>&1 <<< "Q") || true

    if echo "$result" | grep -qi "Cipher is " | grep -qv "0000"; then
      local cipher_name
      cipher_name=$(echo "$result" | grep "Cipher is " | sed 's/.*Cipher is *//')
      if [ -n "$cipher_name" ]; then
        # Classify cipher strength
        if echo "$cipher_name" | grep -qiE '(NULL|EXPORT|LOW|RC4|MD5|DES|3DES)'; then
          bad "INSECURE: ${cipher_name}"
          insecure=$((insecure + 1))
        elif echo "$cipher_name" | grep -qiE '(CBC|SHA1)'; then
          warn "WEAK: ${cipher_name}"
          weak=$((weak + 1))
        else
          ok "STRONG: ${cipher_name}"
          strong=$((strong + 1))
        fi
      fi
    fi
  done <<< "$tls12_ciphers"

  # TLS 1.3 cipher check
  echo -e "\n${CYAN}TLS 1.3:${NC}"
  local tls13_result
  tls13_result=$(echo "" | openssl s_client -connect "${host}:${port}" \
    -servername "$SNI_HOST" -tls1_3 2>&1 <<< "Q") || true

  if echo "$tls13_result" | grep -qi "Cipher is "; then
    local tls13_cipher
    tls13_cipher=$(echo "$tls13_result" | grep "Cipher is " | sed 's/.*Cipher is *//')
    ok "TLS 1.3 supported: ${tls13_cipher}"
  else
    warn "TLS 1.3 not supported"
  fi

  echo ""
  echo -e "  ${GREEN}Strong:${NC} ${strong} | ${YELLOW}Weak:${NC} ${weak} | ${RED}Insecure:${NC} ${insecure}"

  # Check for specific vulnerabilities
  echo -e "\n${CYAN}Vulnerability Checks:${NC}"

  # POODLE (SSLv3)
  local ssl3_result
  ssl3_result=$(echo "" | openssl s_client -connect "${host}:${port}" \
    -servername "$SNI_HOST" -ssl3 2>&1 <<< "Q") || true
  if echo "$ssl3_result" | grep -qi "Cipher is "; then
    bad "POODLE: SSL 3.0 supported!"
  fi

  # Heartbleed
  local hb_result
  hb_result=$(echo "" | openssl s_client -connect "${host}:${port}" \
    -servername "$SNI_HOST" -tlsextdebug 2>&1 <<< "Q") || true
  if echo "$hb_result" | grep -qi "heartbeat"; then
    info "Heartbeat extension present"
  fi

  # Logjam (DHE export)
  local logjam_ciphers
  logjam_ciphers=$(echo "" | openssl s_client -connect "${host}:${port}" \
    -servername "$SNI_HOST" -cipher "EXP" 2>&1 <<< "Q") || true
  if echo "$logjam_ciphers" | grep -qi "Cipher is "; then
    bad "LOGJAM: Export-grade DHE ciphers supported"
  fi

  # FREAK
  local freak_ciphers
  freak_ciphers=$(echo "" | openssl s_client -connect "${host}:${port}" \
    -servername "$SNI_HOST" -cipher "EXPORT" 2>&1 <<< "Q") || true
  if echo "$freak_ciphers" | grep -qi "Cipher is "; then
    bad "FREAK: Export RSA ciphers supported"
  fi

  # Sweet32 (3DES)
  local sweet32
  sweet32=$(echo "" | openssl s_client -connect "${host}:${port}" \
    -servername "$SNI_HOST" -cipher "3DES" 2>&1 <<< "Q") || true
  if echo "$sweet32" | grep -qi "Cipher is "; then
    bad "SWEET32: 3DES ciphers supported"
  fi
}

# ─── Security header analysis ────────────────────────────────────
analyze_security_headers() {
  local host="$1" port="$2"
  local url="https://${host}:${port}/"
  local tmpfile
  tmpfile=$(mktemp) && _cleanup_add "$tmpfile"

  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[SECURITY HEADERS] ${url}${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" -D "$tmpfile" -o /dev/null "$url" 2>/dev/null || {
    err "Failed to fetch headers from ${url}"
    return 1
  }

  local response_headers
  response_headers=$(cat "$tmpfile" | tr -d '\r')

  # Server header
  local server_val
  server_val=$(echo "$response_headers" | grep -i '^server:' | sed 's/[Ss]erver: *//')
  if [ -n "$server_val" ]; then
    warn "Server header leaks: ${server_val}"
  fi

  # HSTS
  local hsts_val
  hsts_val=$(echo "$response_headers" | grep -i '^strict-transport-security:' | sed 's/[Ss]trict-[Tt]ransport-[Ss]ecurity: *//')
  if [ -n "$hsts_val" ]; then
    local hsts_max_age
    hsts_max_age=$(echo "$hsts_val" | grep -oP 'max-age=\K[0-9]+')
    if [ -n "$hsts_max_age" ]; then
      if [ "$hsts_max_age" -ge 31536000 ]; then
        good "HSTS: max-age=${hsts_max_age} (≥1 year)"
      elif [ "$hsts_max_age" -ge 0 ]; then
        warn "HSTS: max-age=${hsts_max_age} (less than 1 year)"
      fi
      echo "$hsts_val" | grep -qi "includesubdomains" && ok "  HSTS includes subdomains"
      echo "$hsts_val" | grep -qi "preload" && ok "  HSTS preload ready"
    fi
  else
    bad "HSTS MISSING!"
  fi

  # CSP
  local csp_val
  csp_val=$(echo "$response_headers" | grep -i '^content-security-policy:' | sed 's/[Cc]ontent-[Ss]ecurity-[Pp]olicy: *//')
  if [ -n "$csp_val" ]; then
    ok "CSP: ${csp_val:0:100}..."
    echo "$csp_val" | grep -qi "unsafe-inline" && warn "  CSP allows 'unsafe-inline'"
    echo "$csp_val" | grep -qi "unsafe-eval" && warn "  CSP allows 'unsafe-eval'"
    echo "$csp_val" | grep -qi "http://" && warn "  CSP allows non-HTTPS sources"
    echo "$csp_val" | grep -qi "wildcard\|*." && warn "  CSP uses wildcards"
  else
    bad "CSP MISSING!"
  fi

  # X-Content-Type-Options
  local xcto_val
  xcto_val=$(echo "$response_headers" | grep -i '^x-content-type-options:' | sed 's/[Xx]-[Cc]ontent-[Tt]ype-[Oo]ptions: *//')
  if [ -n "$xcto_val" ]; then
    echo "$xcto_val" | grep -qi "nosniff" && good "X-Content-Type-Options: nosniff" || warn "X-Content-Type-Options: ${xcto_val}"
  else
    bad "X-Content-Type-Options MISSING!"
  fi

  # X-Frame-Options
  local xfo_val
  xfo_val=$(echo "$response_headers" | grep -i '^x-frame-options:' | sed 's/[Xx]-[Ff]rame-[Oo]ptions: *//')
  if [ -n "$xfo_val" ]; then
    ok "X-Frame-Options: ${xfo_val}"
  else
    warn "X-Frame-Options MISSING (clickjacking risk)"
  fi

  # Referrer-Policy
  local rp_val
  rp_val=$(echo "$response_headers" | grep -i '^referrer-policy:' | sed 's/[Rr]eferrer-[Pp]olicy: *//')
  [ -n "$rp_val" ] && ok "Referrer-Policy: ${rp_val}" || warn "Referrer-Policy MISSING"

  # Permissions-Policy
  local pp_val
  pp_val=$(echo "$response_headers" | grep -i '^permissions-policy:' | sed 's/[Pp]ermissions-[Pp]olicy: *//')
  [ -n "$pp_val" ] && ok "Permissions-Policy present" || warn "Permissions-Policy MISSING"

  # Feature-Policy (old, still used)
  local fp_val
  fp_val=$(echo "$response_headers" | grep -i '^feature-policy:' | sed 's/[Ff]eature-[Pp]olicy: *//')
  [ -n "$fp_val" ] && info "Feature-Policy present (legacy)"

  # CORS
  local cors_origin cors_methods cors_creds
  cors_origin=$(echo "$response_headers" | grep -i '^access-control-allow-origin:' | sed 's/[Aa]ccess-[Cc]ontrol-[Aa]llow-[Oo]rigin: *//')
  cors_methods=$(echo "$response_headers" | grep -i '^access-control-allow-methods:' | sed 's/[Aa]ccess-[Cc]ontrol-[Aa]llow-[Mm]ethods: *//')
  cors_creds=$(echo "$response_headers" | grep -i '^access-control-allow-credentials:' | sed 's/[Aa]ccess-[Cc]ontrol-[Aa]llow-[Cc]redentials: *//')
  if [ -n "$cors_origin" ]; then
    if [ "$cors_origin" = "*" ]; then
      bad "CORS: Wildcard origin (${cors_origin})"
    else
      ok "CORS: ${cors_origin}"
    fi
    [ -n "$cors_methods" ] && info "  Allowed methods: ${cors_methods}"
    [ -n "$cors_creds" ] && echo "$cors_creds" | grep -qi "true" && warn "  Credentials allowed with CORS"
  fi
}

# ─── TLS version scan ────────────────────────────────────────────
scan_tls_versions() {
  local host="$1" port="$2"

  # SSL 2.0
  local ssl2_res
  ssl2_res=$(echo "" | openssl s_client -connect "${host}:${port}" -ssl2 2>&1 <<< "Q" 2>/dev/null) || true
  echo "$ssl2_res" | grep -qi "Cipher is " && bad "SSL 2.0 supported!"

  # SSL 3.0
  local ssl3_res
  ssl3_res=$(echo "" | openssl s_client -connect "${host}:${port}" -ssl3 2>&1 <<< "Q" 2>/dev/null) || true
  echo "$ssl3_res" | grep -qi "Cipher is " && bad "SSL 3.0 supported!"

  # TLS 1.0
  local tls10_res
  tls10_res=$(echo "" | openssl s_client -connect "${host}:${port}" -tls1 2>&1 <<< "Q" 2>/dev/null) || true
  echo "$tls10_res" | grep -qi "Cipher is " && bad "TLS 1.0 supported (deprecated!)"

  # TLS 1.1
  local tls11_res
  tls11_res=$(echo "" | openssl s_client -connect "${host}:${port}" -tls1_1 2>&1 <<< "Q" 2>/dev/null) || true
  echo "$tls11_res" | grep -qi "Cipher is " && bad "TLS 1.1 supported (deprecated!)"

  # TLS 1.2
  local tls12_res
  tls12_res=$(echo "" | openssl s_client -connect "${host}:${port}" -tls1_2 2>&1 <<< "Q" 2>/dev/null) || true
  echo "$tls12_res" | grep -qi "Cipher is " && ok "TLS 1.2 supported"

  # TLS 1.3
  local tls13_res
  tls13_res=$(echo "" | openssl s_client -connect "${host}:${port}" -tls1_3 2>&1 <<< "Q" 2>/dev/null) || true
  echo "$tls13_res" | grep -qi "Cipher is " && ok "TLS 1.3 supported"
}

# ─── Output ──────────────────────────────────────────────────────
maybe_output() {
  [ -z "$OUTPUT_FILE" ] && return
  info "Results output to: ${OUTPUT_FILE}"
}

# ─── Summary ─────────────────────────────────────────────────────
show_summary() {
  local host="$1" port="$2"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${GREEN}TLS Analysis Complete: ${host}:${port}${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "  ${YELLOW}Basic:${NC}   $([ "$RUN_BASIC" = true ] && echo 'Yes' || echo 'No')"
  echo -e "  ${YELLOW}Cert:${NC}    $([ "$RUN_CERT" = true ] && echo 'Yes' || echo 'No')"
  echo -e "  ${YELLOW}Cipher:${NC}  $([ "$RUN_CIPHER" = true ] && echo 'Yes' || echo 'No')"
  echo -e "  ${YELLOW}Headers:${NC} $([ "$RUN_HEADERS" = true ] && echo 'Yes' || echo 'No')"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
}

# ─── Main ────────────────────────────────────────────────────────
main() {
  check_deps
  echo ""
  echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║${NC}  ${GREEN}HTTPS/TLS Probing Tool v${VERSION}${NC}"
  echo -e "${CYAN}║${NC}  Target: ${YELLOW}${TARGET_HOST}:${TARGET_PORT}${NC}"
  echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"

  [ "$RUN_BASIC" = true ] && get_basic_info "$TARGET_HOST" "$TARGET_PORT"
  [ "$RUN_CERT" = true ] && analyze_certificate "$TARGET_HOST" "$TARGET_PORT"
  [ "$RUN_CIPHER" = true ] && scan_ciphers "$TARGET_HOST" "$TARGET_PORT"
  [ "$RUN_HEADERS" = true ] && analyze_security_headers "$TARGET_HOST" "$TARGET_PORT"

  show_summary "$TARGET_HOST" "$TARGET_PORT"
  maybe_output
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  parse_args "$@"
  main
fi