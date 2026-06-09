#!/usr/bin/env bash
# =====================================================================
# extract-functionalities.sh — User Functionality Extraction Tool
#
# HTML form detection and analysis, link/button extraction from pages,
# JavaScript event handler discovery, and interactive element mapping.
# Provides a comprehensive map of user-accessible functionality.
#
# Usage:
#   ./extract-functionalities.sh -u https://target.com
#   ./extract-functionalities.sh -f page.html
#   ./extract-functionalities.sh -u https://target.com -o map.json
# =====================================================================

set -euo pipefail

# ─── Constants ───────────────────────────────────────────────────
VERSION="1.0.0"
SCRIPT_NAME=$(basename "$0")
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; NC='\033[0m'

# Tags and attributes for interactive elements
FORM_TAGS="form input select textarea button"
INTERACTIVE_TAGS="a button input select textarea details summary"
EVENT_ATTRIBUTES=(
  "onclick" "onchange" "onsubmit" "onfocus" "onblur" "onmouseover"
  "onmouseout" "onkeydown" "onkeyup" "onkeypress" "onload" "onerror"
  "onabort" "onscroll" "onresize" "oninput" "onreset"
  "onsearch" "onselect" "ontoggle" "onwheel" "ondrag" "ondrop"
  "onpointerdown" "onpointerup" "onpointermove"
  "ontouchstart" "ontouchend" "ontouchmove"
  "v-on:click" "@click" "v-on:submit" "@submit" "v-on:change" "@change"
  "ng-click" "ng-submit" "ng-change" "ng-model"
  "on:click" "on:submit" "on:change"
  "bind" "model" "ref"
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
func()   { echo -e "${GREEN}[FUNC]${NC} $*"; }
event()  { echo -e "${MAGENTA}[EVENT]${NC} $*"; }
link()   { echo -e "${CYAN}[LINK]${NC} $*"; }

# ─── Usage ───────────────────────────────────────────────────────
usage() {
  cat <<EOF
${CYAN}extract-functionalities.sh${NC} v${VERSION} — Functionality Extraction

${YELLOW}Description:${NC}
  Extracts and maps user-interactive functionality from web pages.
  Discovers forms, links, buttons, JavaScript event handlers, and
  interactive elements to build a functionality map.

${YELLOW}Usage:${NC}
  $SCRIPT_NAME -u <url>              Analyze a live URL
  $SCRIPT_NAME -f <file>             Analyze a local HTML file
  $SCRIPT_NAME -u <url> -o map.txt   Output functionality map
  $SCRIPT_NAME -u <url> -d 2         Crawl depth 2

${YELLOW}Options:${NC}
  -u <url>          Target URL
  -f <file>         Local HTML file
  -o <file>         Output file for functionality map
  -d <depth>        Crawl depth (default: 1)
  -t <seconds>      Request timeout (default: 10)
  -a                Include all elements (not just interactive)
  -q                Quiet mode
  -v                Verbose mode
  -h                Show help

${YELLOW}Examples:${NC}
  $SCRIPT_NAME -u https://target.com
  $SCRIPT_NAME -f login.html
  $SCRIPT_NAME -u https://target.com -d 2 -o functions.txt
EOF
  exit 0
}

# ─── Options ─────────────────────────────────────────────────────
TARGET_URL=""
TARGET_FILE=""
OUTPUT_FILE=""
CRAWL_DEPTH=1
TIMEOUT=10
QUIET=false
VERBOSE=false
INCLUDE_ALL=false

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help) usage ;;
      -u|--url) TARGET_URL="$2"; shift 2 ;;
      -f|--file) TARGET_FILE="$2"; shift 2 ;;
      -o|--output) OUTPUT_FILE="$2"; shift 2 ;;
      -d|--depth) CRAWL_DEPTH="$2"; shift 2 ;;
      -t|--timeout) TIMEOUT="$2"; shift 2 ;;
      -a|--all) INCLUDE_ALL=true; shift ;;
      -q|--quiet) QUIET=true; shift ;;
      -v|--verbose) VERBOSE=true; shift ;;
      *) err "Unknown: $1"; usage ;;
    esac
  done
  [ -z "$TARGET_URL" ] && [ -z "$TARGET_FILE" ] && { err "No target"; usage; }
}

check_deps() {
  local missing=()
  for d in curl grep sed awk sort uniq; do
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

# ─── Fetch ───────────────────────────────────────────────────────
_http_get() {
  local url="$1"
  curl -sk --max-time "$TIMEOUT" -A "$USER_AGENT" \
    -w "\n%{http_code}|||%{size_download}" "$url" 2>/dev/null || {
    warn "Fetch failed: $url"; return 1
  }
}

# ─── Extract all links ───────────────────────────────────────────
extract_links() {
  local content="$1" base_url="$2"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[LINKS] All hyperlinks found${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  local tmp
  tmp=$(mktemp) && _cleanup_add "$tmp"

  # Extract <a href="...">
  echo "$content" | grep -oP '<a[^>]+href="[^"]*"[^>]*>' | while IFS= read -r tag; do
    local href text rel_type
    href=$(echo "$tag" | grep -oP 'href="[^"]*"' | sed 's/href="//;s/"$//')
    text=$(echo "$tag" | grep -oP '>[^<]*<' | tr -d '><' | head -c 60)
    [ -z "$href" ] && continue

    local abs_href
    abs_href=$(_normalize_url "$base_url" "$href")

    # Classify link type
    if echo "$abs_href" | grep -qiE '\.(pdf|doc|docx|xls|xlsx|zip|tar|gz)'; then
      rel_type="download"
    elif echo "$abs_href" | grep -qiE '(login|signin|auth)'; then
      rel_type="auth"
    elif echo "$abs_href" | grep -qiE '(logout|signout)'; then
      rel_type="logout"
    elif echo "$abs_href" | grep -qiE '(admin|dashboard|panel|manage)'; then
      rel_type="admin"
    elif echo "$abs_href" | grep -qiE '(api|rest|graphql|v[0-9]/)'; then
      rel_type="api"
    elif echo "$abs_href" | grep -qE '^https?://' && ! echo "$abs_href" | grep -q "$(echo "$base_url" | grep -oP 'https?://[^/]+')"; then
      rel_type="external"
    elif echo "$abs_href" | grep -qE '^(mailto:|tel:)'; then
      rel_type="contact"
    elif echo "$abs_href" | grep -qE '^javascript:'; then
      rel_type="javascript"
    else
      rel_type="internal"
    fi

    echo "${rel_type}|||${abs_href}|||${text}"
  done | sort -u > "$tmp"

  # Categorize
  local internal external auth api download js contact
  internal=$(grep -c '^internal' "$tmp" || true)
  external=$(grep -c '^external' "$tmp" || true)
  auth=$(grep -c '^auth' "$tmp" || true)
  api=$(grep -c '^api' "$tmp" || true)
  download=$(grep -c '^download' "$tmp" || true)
  js=$(grep -c '^javascript' "$tmp" || true)
  contact=$(grep -c '^contact' "$tmp" || true)

  echo "  Internal: ${internal} | External: ${external} | Auth: ${auth} | API: ${api} | Download: ${download} | JS: ${js} | Contact: ${contact}"

  # Show interesting ones
  if [ "$auth" -gt 0 ]; then
    echo ""
    info "Auth-related links:"
    grep '^auth' "$tmp" | while IFS='|||' read -r type url text; do
      func "  ${url} (${text})"
    done
  fi

  if [ "$api" -gt 0 ]; then
    echo ""
    info "API links:"
    grep '^api' "$tmp" | while IFS='|||' read -r type url text; do
      func "  ${url} (${text})"
    done
  fi
}

# ─── Extract forms ───────────────────────────────────────────────
extract_forms() {
  local content="$1" base_url="$2"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[FORMS] Form discovery and analysis${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  local form_count=0
  local tmp_forms
  tmp_forms=$(mktemp) && _cleanup_add "$tmp_forms"
  echo "$content" | grep -oP '<form[^>]*>[\s\S]*?</form>' > "$tmp_forms" 2>/dev/null || true

  form_count=$(grep -c '<form' "$tmp_forms" || true)
  info "Found ${form_count} form(s)"

  local form_idx=0
  while IFS= read -r form_html; do
    [ -z "$form_html" ] && continue
    form_idx=$((form_idx + 1))

    local action method
    action=$(echo "$form_html" | grep -oP 'action="[^"]*"' | sed 's/action="//;s/"$//')
    method=$(echo "$form_html" | grep -oP 'method="[^"]*"' | sed 's/method="//;s/"$//' | tr '[:lower:]' '[:upper:]')
    [ -z "$action" ] && action="(self)"
    [ -z "$method" ] && method="GET"

    # Resolve action URL
    [ "$action" != "(self)" ] && action=$(_normalize_url "$base_url" "$action")

    echo -e "\n  ${CYAN}Form #${form_idx}:${NC} ${method} → ${action}"

    # Inspect form attributes
    local form_id form_name form_class form_enctype form_target
    form_id=$(echo "$form_html" | grep -oP 'id="[^"]*"' | sed 's/id="//;s/"$//')
    form_name=$(echo "$form_html" | grep -oP 'name="[^"]*"' | sed 's/name="//;s/"$//')
    form_class=$(echo "$form_html" | grep -oP 'class="[^"]*"' | sed 's/class="//;s/"$//')
    form_enctype=$(echo "$form_html" | grep -oP 'enctype="[^"]*"' | sed 's/enctype="//;s/"$//')
    form_target=$(echo "$form_html" | grep -oP 'target="[^"]*"' | sed 's/target="//;s/"$//')

    [ -n "$form_id ] && echo "    ID: ${form_id}"
    [ -n "$form_name" ] && echo "    Name: ${form_name}"
    [ -n "$form_class" ] && echo "    Class: ${form_class}"
    [ -n "$form_enctype" ] && {
      echo -n "    Encoding: ${form_enctype}"
      if echo "$form_enctype" | grep -qiE 'multipart|form-data'; then
        echo " (file upload!)"
      else
        echo ""
      fi
    }
    [ -n "$form_target" ] && echo "    Target: ${form_target}"

    # Check for CSRF tokens
    if echo "$form_html" | grep -qiE 'csrf|token|_token|authenticity_token'; then
      info "  CSRF token likely present"
    else
      warn "  No obvious CSRF protection"
    fi

    # Count fields
    local field_count
    field_count=$(echo "$form_html" | grep -cP '<input|<select|<textarea' || true)
    echo "    Fields: ${field_count}"
  done < "$tmp_forms"
}

# ─── Extract buttons ─────────────────────────────────────────────
extract_buttons() {
  local content="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[BUTTONS] Button and submit elements${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  local btn_count=0

  # <button> elements
  echo "$content" | grep -oP '<button[^>]*>[\s\S]*?</button>' | while IFS= read -r btn_tag; do
    btn_count=$((btn_count + 1))
    local btn_id btn_name btn_value btn_type btn_class btn_text
    btn_id=$(echo "$btn_tag" | grep -oP 'id="[^"]*"' | sed 's/id="//;s/"$//')
    btn_name=$(echo "$btn_tag" | grep -oP 'name="[^"]*"' | sed 's/name="//;s/"$//')
    btn_value=$(echo "$btn_tag" | grep -oP 'value="[^"]*"' | sed 's/value="//;s/"$//')
    btn_type=$(echo "$btn_tag" | grep -oP 'type="[^"]*"' | sed 's/type="//;s/"$//')
    btn_class=$(echo "$btn_tag" | grep -oP 'class="[^"]*"' | sed 's/class="//;s/"$//')
    btn_text=$(echo "$btn_tag" | sed 's/<button[^>]*>//;s/<\/button>//' | head -c 50)

    [ -z "$btn_type" ] && btn_type="submit"

    local details=""
    [ -n "$btn_id" ] && details="${details} id=${btn_id}"
    [ -n "$btn_name" ] && details="${details} name=${btn_name}"
    [ -n "$btn_class" ] && details="${details} class=${btn_class}"

    func "  <button type='${btn_type}'> ${btn_text:-(no text)}${details}"
  done

  # <input type="submit"> and <input type="button">
  echo "$content" | grep -oP '<input[^>]+(type="submit"|type="button"|type="reset")[^>]*>' | while IFS= read -r input_tag; do
    btn_count=$((btn_count + 1))
    local input_type input_name input_value input_id
    input_type=$(echo "$input_tag" | grep -oP 'type="[^"]*"' | sed 's/type="//;s/"$//')
    input_name=$(echo "$input_tag" | grep -oP 'name="[^"]*"' | sed 's/name="//;s/"$//')
    input_value=$(echo "$input_tag" | grep -oP 'value="[^"]*"' | sed 's/value="//;s/"$//')
    input_id=$(echo "$input_tag" | grep -oP 'id="[^"]*"' | sed 's/id="//;s/"$//')

    local details=""
    [ -n "$input_id" ] && details="${details} id=${input_id}"
    [ -n "$input_name" ] && details="${details} name=${input_name}"

    func "  <input type='${input_type}'> ${input_value}${details}"
  done

  info "Total buttons/submits: ${btn_count}"
}

# ─── Extract JavaScript event handlers ───────────────────────────
extract_events() {
  local content="$1" source="$2"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[EVENTS] JavaScript event handlers in ${source}${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  local event_count=0
  for attr in "${EVENT_ATTRIBUTES[@]}"; do
    # Find elements with this event attribute
    local matches
    matches=$(echo "$content" | grep -oP "<[^>]+${attr}=['\"][^'\"]*['\"][^>]*>" || true)
    if [ -n "$matches" ]; then
      while IFS= read -r match; do
        [ -z "$match" ] && continue
        event_count=$((event_count + 1))

        # Extract the handler code
        local handler
        handler=$(echo "$match" | grep -oP "${attr}=['\"]([^'\"]+)['\"]" | sed "s/${attr}=//" | tr -d "'\"")
        local element_tag
        element_tag=$(echo "$match" | grep -oP '<\w+' | head -1 | tr -d '<')

        # Truncate long handlers
        if [ ${#handler} -gt 80 ]; then
          event "  <${element_tag} ${attr}='${handler:0:80}...'"
        else
          event "  <${element_tag} ${attr}='${handler}'"
        fi
      done <<< "$matches"
    fi
  done

  if [ "$event_count" -eq 0 ]; then
    info "  No event handlers found"
  else
    info "  Total event handlers: ${event_count}"
  fi
}

# ─── Extract data attributes (framework bindings) ───────────────
extract_data_attrs() {
  local content="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[DATA ATTRS] Framework data attributes${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  # Angular
  local ng_count
  ng_count=$(echo "$content" | grep -cP 'ng-\w+' || true)
  [ "$ng_count" -gt 0 ] && info "  Angular: ${ng_count} bindings"

  # Vue
  local vue_count
  vue_count=$(echo "$content" | grep -cP 'v-[\w:-]+' || true)
  [ "$vue_count" -gt 0 ] && info "  Vue: ${vue_count} directives"

  # React (data-reactid, etc.)
  local react_count
  react_count=$(echo "$content" | grep -cP 'data-react\w*' || true)
  [ "$react_count" -gt 0 ] && info "  React: ${react_count} attributes"

  # Alpine.js
  local alpine_count
  alpine_count=$(echo "$content" | grep -cP 'x-[\w:]+' || true)
  [ "$alpine_count" -gt 0 ] && info "  Alpine.js: ${alpine_count} directives"

  # HTMX
  local htmx_count
  htmx_count=$(echo "$content" | grep -cP 'hx-\w+' || true)
  [ "$htmx_count" -gt 0 ] && info "  HTMX: ${htmx_count} attributes"

  # Stimulus
  local stimulus_count
  stimulus_count=$(echo "$content" | grep -cP 'data-controller|data-action|data-target' || true)
  [ "$stimulus_count" -gt 0 ] && info "  Stimulus: ${stimulus_count} attributes"

  # Custom data attributes
  local custom_data
  custom_data=$(echo "$content" | grep -oP 'data-\w+="[^"]*"' | sort -u | head -30)
  if [ -n "$custom_data" ]; then
    info "  Custom data attributes:"
    while IFS= read -r d; do
      [ -n "$d" ] && echo "    ${d}"
    done <<< "$custom_data"
  fi
}

# ─── Interactive element summary ─────────────────────────────────
summarize_interactive() {
  local content="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${GREEN}Interactive Element Summary${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  local a_count form_count input_count btn_count select_count textarea_count
  a_count=$(echo "$content" | grep -cP '<a[\s>]' || true)
  form_count=$(echo "$content" | grep -cP '<form[\s>]' || true)
  input_count=$(echo "$content" | grep -cP '<input[\s>]' || true)
  btn_count=$(echo "$content" | grep -cP '<button[\s>]' || true)
  select_count=$(echo "$content" | grep -cP '<select[\s>]' || true)
  textarea_count=$(echo "$content" | grep -cP '<textarea[\s>]' || true)
  script_count=$(echo "$content" | grep -cP '<script[\s>]' || true)
  iframe_count=$(echo "$content" | grep -cP '<iframe[\s>]' || true)

  echo "  Links:     ${a_count}"
  echo "  Forms:     ${form_count}"
  echo "  Inputs:    ${input_count}"
  echo "  Buttons:   ${btn_count}"
  echo "  Selects:   ${select_count}"
  echo "  Textareas: ${textarea_count}"
  echo "  Scripts:   ${script_count}"
  echo "  Iframes:   ${iframe_count}"

  local total=$((a_count + form_count + input_count + btn_count + select_count + textarea_count + script_count + iframe_count))
  echo "  Total:     ${total} interactive elements"
}

# ─── Analyze a single content source ─────────────────────────────
analyze_content() {
  local content="$1" source="$2" base_url="$3"

  extract_links "$content" "$base_url"
  extract_forms "$content" "$base_url"
  extract_buttons "$content"
  extract_events "$content" "$source"
  extract_data_attrs "$content"
  summarize_interactive "$content"
}

# ─── Process a URL ───────────────────────────────────────────────
process_url() {
  local url="$1"
  info "Fetching: ${url}"
  local resp
  resp=$(_http_get "$url") || return 1
  local content
  content=$(echo "$resp" | sed '$d' | sed '$d')
  ok "Content retrieved ($(echo "$content" | wc -c) bytes)"
  analyze_content "$content" "$url" "$url"

  # Recursive crawling
  if [ "$CRAWL_DEPTH" -gt 1 ]; then
    local links
    links=$(echo "$content" | grep -oP '<a[^>]+href="[^"]*"[^>]*>' | grep -oP 'href="[^"]*"' | sed 's/href="//;s/"$//' | sort -u | head -20)
    local depth=1
    while [ "$depth" -lt "$CRAWL_DEPTH" ]; do
      depth=$((depth + 1))
      while IFS= read -r link; do
        [ -z "$link" ] && continue
        local abs_link
        abs_link=$(_normalize_url "$url" "$link")
        # Only crawl same-domain
        local domain1 domain2
        domain1=$(echo "$url" | grep -oP 'https?://[^/]+')
        domain2=$(echo "$abs_link" | grep -oP 'https?://[^/]+')
        [ "$domain1" != "$domain2" ] && continue
        # Avoid recursing back to the same page
        [ "$abs_link" = "$url" ] && continue
        info "Crawling (depth ${depth}): ${abs_link}"
        local sub_resp
        sub_resp=$(_http_get "$abs_link") || continue
        local sub_content
        sub_content=$(echo "$sub_resp" | sed '$d' | sed '$d')
        analyze_content "$sub_content" "$abs_link" "$url"
      done <<< "$links"
    done
  fi
}

# ─── Process a file ──────────────────────────────────────────────
process_file() {
  local file="$1"
  [ ! -f "$file" ] && { err "File not found: $file"; return 1; }
  local content; content=$(cat "$file")
  info "Analyzing file: $file ($(wc -c <<< "$content") bytes)"
  analyze_content "$content" "$file" "file://$file"
}

# ─── Output ──────────────────────────────────────────────────────
maybe_output() { [ -n "$OUTPUT_FILE" ] && info "Output will be saved to: ${OUTPUT_FILE}"; }

# ─── Main ────────────────────────────────────────────────────────
main() {
  check_deps
  echo ""
  echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║${NC}  ${GREEN}Functionality Extraction Tool v${VERSION}${NC}"
  local src=""; [ -n "$TARGET_URL" ] && src="$TARGET_URL"; [ -n "$TARGET_FILE" ] && src="$TARGET_FILE"
  echo -e "${CYAN}║${NC}  Target: ${YELLOW}${src}${NC}"
  echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"

  if [ -n "$TARGET_URL" ]; then process_url "$TARGET_URL"
  elif [ -n "$TARGET_FILE" ]; then process_file "$TARGET_FILE"
  fi

  maybe_output
  echo ""
  ok "Functionality extraction complete"
}

# ─── Extract navigation structure ────────────────────────────────
extract_navigation() {
  local content="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[NAVIGATION] Navigation and menu structure${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  # Detect nav elements
  local nav_elements
  nav_elements=$(echo "$content" | grep -oP '<nav[^>]*>[\s\S]*?</nav>' || true)
  if [ -n "$nav_elements" ]; then
    local nav_count
    nav_count=$(echo "$nav_elements" | grep -c '<nav' || true)
    info "Navigation elements: ${nav_count}"

    # Extract menu items
    echo "$nav_elements" | grep -oP '<a[^>]+href="[^"]*"[^>]*>[^<]*</a>' | while IFS= read -r item; do
      local item_href item_text
      item_href=$(echo "$item" | grep -oP 'href="[^"]*"' | sed 's/href="//;s/"$//')
      item_text=$(echo "$item" | sed 's/<a[^>]*>//;s/<\/a>//' | head -c 40)
      func "  ${item_text} → ${item_href}"
    done
  else
    info "No explicit <nav> elements found"
  fi

  # Detect dropdowns/menus
  local dropdowns
  dropdowns=$(echo "$content" | grep -oP '<select[^>]*>[\s\S]*?</select>' || true)
  local dd_count=0
  if [ -n "$dropdowns" ]; then
    while IFS= read -r select_html; do
      dd_count=$((dd_count + 1))
      local sel_name sel_id
      sel_name=$(echo "$select_html" | grep -oP 'name="[^"]*"' | sed 's/name="//;s/"$//')
      sel_id=$(echo "$select_html" | grep -oP 'id="[^"]*"' | sed 's/id="//;s/"$//')
      local options
      options=$(echo "$select_html" | grep -oP '<option[^>]*>[^<]*</option>' | sed 's/<option[^>]*>//;s/<\/option>//')
      [ -n "$sel_name" ] && info "  Dropdown #${dd_count}: name=${sel_name} id=${sel_id}"
    done <<< "$dropdowns"
  fi

  # Detect tab interfaces
  local tab_count
  tab_count=$(echo "$content" | grep -cP 'role="tab"' || true)
  [ "$tab_count" -gt 0 ] && info "Tab interfaces: ${tab_count}"

  # Detect accordion
  local accordion_count
  accordion_count=$(echo "$content" | grep -cP 'role="accordion"|class="[^"]*accordion' || true)
  [ "$accordion_count" -gt 0 ] && info "Accordion elements: ${accordion_count}"

  # Detect modals
  local modal_count
  modal_count=$(echo "$content" | grep -cP 'role="dialog"|class="[^"]*modal[^"]*"' || true)
  [ "$modal_count" -gt 0 ] && info "Modal/dialog elements: ${modal_count}"

  # Detect carousels
  local carousel_count
  carousel_count=$(echo "$content" | grep -cP 'class="[^"]*carousel[^"]*"' || true)
  [ "$carousel_count" -gt 0 ] && info "Carousel elements: ${carousel_count}"
}

# ─── API endpoint extraction from HTML ───────────────────────────
extract_api_calls() {
  local content="$1" source="$2"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[API CALLS] API call patterns in ${source}${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  local fetch_calls
  fetch_calls=$(echo "$content" | grep -oP "(fetch|axios|ajax|XMLHttpRequest)\s*\(\s*['\"][^'\"]*['\"]" | grep -oP "['\"][^'\"]*['\"]" | tr -d "'\"" | sort -u)
  if [ -n "$fetch_calls" ]; then
    info "Data fetching calls:"
    while IFS= read -r call; do
      [ -n "$call" ] && func "  ${call}"
    done <<< "$fetch_calls"
  fi

  # WebSocket endpoints
  local ws_endpoints
  ws_endpoints=$(echo "$content" | grep -oP "(wss?://[a-zA-Z0-9./?=&#_\-~%]+)" | sort -u)
  if [ -n "$ws_endpoints" ]; then
    info "WebSocket endpoints:"
    while IFS= read -r ws; do
      [ -n "$ws" ] && func "  ${ws}"
    done <<< "$ws_endpoints"
  fi

  # SSE endpoints
  local sse_endpoints
  sse_endpoints=$(echo "$content" | grep -oP "EventSource\s*\(\s*['\"][^'\"]*['\"]" | grep -oP "['\"][^'\"]*['\"]" | tr -d "'\"")
  if [ -n "$sse_endpoints" ]; then
    info "SSE endpoints:"
    while IFS= read -r sse; do
      [ -n "$sse" ] && func "  ${sse}"
    done <<< "$sse_endpoints"
  fi
}

# ─── detect SPA framework ───────────────────────────────────────
detect_framework() {
  local content="$1"
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}[FRAMEWORK] Frontend framework detection${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  local framework=""

  # Check for common frameworks
  echo "$content" | grep -qi 'ng-app\|ng-controller\|ng-model\|angular' && framework="${framework} Angular"
  echo "$content" | grep -qi 'vue-app\|v-bind\|v-model\|v-if\|v-for\|:src\|@click' && framework="${framework} Vue"
  echo "$content" | grep -qi 'react-root\|data-reactroot\|react-dom\|__NEXT_DATA__' && framework="${framework} React"
  echo "$content" | grep -qi 'svelte' && framework="${framework} Svelte"
  echo "$content" | grep -qi 'ember-app\|Ember\.' && framework="${framework} Ember"
  echo "$content" | grep -qi 'backbone' && framework="${framework} Backbone"
  echo "$content" | grep -qi 'jQuery\|jquery\|$\.' && framework="${framework} jQuery"
  echo "$content" | grep -qi 'alpine' && framework="${framework} Alpine.js"
  echo "$content" | grep -qi 'htmx\|hx-get\|hx-post\|hx-put\|hx-delete' && framework="${framework} HTMX"
  echo "$content" | grep -qi 'stimulus' && framework="${framework} Stimulus"
  echo "$content" | grep -qi 'turbo-frame\|turbo-stream\|turbo_' && framework="${framework} Turbo"
  echo "$content" | grep -qi 'livewire' && framework="${framework} Livewire"
  echo "$content" | grep -qi 'bootstrap' && framework="${framework} Bootstrap"
  echo "$content" | grep -qi 'tailwind' && framework="${framework} Tailwind"

  if [ -n "$framework" ]; then
    info "Detected:${framework}"
  else
    info "No specific SPA framework detected"
  fi
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  parse_args "$@"
  main
fi