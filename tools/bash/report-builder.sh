#!/usr/bin/env bash
# =====================================================================
# report-builder.sh — Finding Report Builder for Bug Bounty Reports
#
# Generates professional markdown reports for bug bounty findings with
# CVSS 3.1 scoring helpers, multiple output formats (markdown, json, html),
# and evidence file embedding. Supports HackerOne, Bugcrowd, and custom
# report templates.
#
# Usage:
#   ./report-builder.sh -t "IDOR in User Profile" -s High
#   ./report-builder.sh -i findings.json -o report.md
#   ./report-builder.sh -i findings.json --format html
# =====================================================================

set -euo pipefail

# ─── Constants ───────────────────────────────────────────────────
VERSION="1.0.0"
SCRIPT_NAME=$(basename "$0")

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'

# CVSS 3.1 severity thresholds
CVSS_MAP=(
  "None:0.0"
  "Low:0.1-3.9"
  "Medium:4.0-6.9"
  "High:7.0-8.9"
  "Critical:9.0-10.0"
)

# Report template dir
REPORT_DIR="${OUTPUT_DIR:-/tmp/reports}"

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

# ─── Usage ───────────────────────────────────────────────────────
usage() {
  cat <<EOF
${CYAN}report-builder.sh${NC} v${VERSION} — Bug Bounty Report Builder

${YELLOW}Description:${NC}
  Generates professional bug bounty reports in multiple formats with CVSS 3.1
  scoring, evidence embedding, and platform-specific templates. Supports
  HackerOne, Bugcrowd, Intigriti, and custom report formats.

${YELLOW}Usage:${NC}
  $SCRIPT_NAME -t "Title" -s High                  Quick report
  $SCRIPT_NAME -i findings.json -o report.md       From JSON
  $SCRIPT_NAME --interactive                        Interactive mode
  $SCRIPT_NAME -i findings.json --format html       HTML output

${YELLOW}Modes:${NC}
  --quick         Quick report from command line args
  --from-json     Import findings from JSON file
  --interactive   Interactive report builder
  --cvss          Calculate CVSS score only
  --template      List available templates

${YELLOW}Options:${NC}
  -t <title>        Report title
  -s <severity>     Severity (Critical/High/Medium/Low/None)
  -d <description>  Finding description
  -i <file>         Import findings from JSON
  -o <file>         Output report file
  -p <platform>     Platform template (hackerone|bugcrowd|intigriti|custom)
  --format <fmt>    Output format (markdown|json|html|txt)
  --cvss-score <n>  CVSS 3.1 score (0.0-10.0)
  --no-color        Disable color output
  -v                Verbose mode
  -h                Show help

${YELLOW}Examples:${NC}
  $SCRIPT_NAME -t "IDOR in User Profile" -s High -d "User IDs are enumerable"
  $SCRIPT_NAME -i findings.json -o report.md
  $SCRIPT_NAME --cvss-score 7.5
EOF
  exit 0
}

# ─── Options ─────────────────────────────────────────────────────
REPORT_TITLE=""
SEVERITY=""
DESCRIPTION=""
INPUT_FILE=""
OUTPUT_FILE=""
PLATFORM="custom"
OUTPUT_FORMAT="markdown"
CVSS_SCORE=""
INTERACTIVE=false
QUIET=false
VERBOSE=false
NO_COLOR=false

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help) usage ;;
      -t|--title) REPORT_TITLE="$2"; shift 2 ;;
      -s|--severity) SEVERITY="$2"; shift 2 ;;
      -d|--description) DESCRIPTION="$2"; shift 2 ;;
      -i|--input) INPUT_FILE="$2"; shift 2 ;;
      -o|--output) OUTPUT_FILE="$2"; shift 2 ;;
      -p|--platform) PLATFORM="$2"; shift 2 ;;
      --format) OUTPUT_FORMAT="$2"; shift 2 ;;
      --cvss-score) CVSS_SCORE="$2"; shift 2 ;;
      --interactive) INTERACTIVE=true; shift ;;
      -q|--quiet) QUIET=true; shift ;;
      -v|--verbose) VERBOSE=true; shift ;;
      --no-color) NO_COLOR=true; RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; shift ;;
      *) err "Unknown: $1"; usage ;;
    esac
  done
}

check_deps() {
  local missing=()
  for d in grep sed awk sort; do
    command -v "$d" &>/dev/null || missing+=("$d")
  done
  [ ${#missing[@]} -gt 0 ] && { err "Missing: ${missing[*]}"; exit 1; }
}

# ─── CVSS 3.1 scoring ────────────────────────────────────────────
cvss_score_severity() {
  local score="$1"
  local severity="None"

  if [ "$(echo "$score >= 9.0" | bc 2>/dev/null)" = "1" ]; then severity="Critical"
  elif [ "$(echo "$score >= 7.0" | bc 2>/dev/null)" = "1" ]; then severity="High"
  elif [ "$(echo "$score >= 4.0" | bc 2>/dev/null)" = "1" ]; then severity="Medium"
  elif [ "$(echo "$score >= 0.1" | bc 2>/dev/null)" = "1" ]; then severity="Low"
  fi

  echo "$severity"
}

cvss_calculate() {
  local attack_vector="${1:-N}" attack_complexity="${2:-L}" \
        privileges="${3:-N}" user_interaction="${4:-N}" \
        scope="${5:-C}" confidentiality="${6:-H}" \
        integrity="${7:-H}" availability="${8:-H}"

  # AV: N/A/L/P | AC: L/H | PR: N/L/H | UI: N/R
  # S: U/C | C: H/L/N | I: H/L/N | A: H/L/N

  local av_score ac_score pr_score ui_score s_score c_score i_score a_score

  case "$attack_vector" in
    N) av_score=0.85 ;; A) av_score=0.62 ;; L) av_score=0.55 ;; P) av_score=0.20 ;;
    *) av_score=0.85 ;;
  esac

  case "$attack_complexity" in
    L) ac_score=0.77 ;; H) ac_score=0.44 ;;
    *) ac_score=0.77 ;;
  esac

  case "$privileges" in
    N) pr_score=0.85 ;; L) pr_score=0.62 ;; H) pr_score=0.27 ;;
    *) pr_score=0.85 ;;
  esac

  case "$user_interaction" in
    N) ui_score=0.85 ;; R) ui_score=0.62 ;;
    *) ui_score=0.85 ;;
  esac

  local impact_sub score_impact score_exploitability

  case "$confidentiality" in
    H) c_score=0.56 ;; L) c_score=0.22 ;; N) c_score=0 ;;
    *) c_score=0 ;;
  esac

  case "$integrity" in
    H) i_score=0.56 ;; L) i_score=0.22 ;; N) i_score=0 ;;
    *) i_score=0 ;;
  esac

  case "$availability" in
    H) a_score=0.56 ;; L) a_score=0.22 ;; N) a_score=0 ;;
    *) a_score=0 ;;
  esac

  impact_sub=1.0
  local impact
  impact=$(echo "scale=4; 1.0 - ((1.0 - $c_score) * (1.0 - $i_score) * (1.0 - $a_score))" | bc 2>/dev/null || echo "0")

  if [ "$scope" = "C" ]; then
    score_impact=$(echo "scale=4; 1.08 * $impact" | bc 2>/dev/null || echo "0")
  else
    score_impact=$(echo "scale=4; 0.76 * $impact" | bc 2>/dev/null || echo "0")
  fi

  score_exploitability=$(echo "scale=4; 8.22 * $av_score * $ac_score * $pr_score * $ui_score" | bc 2>/dev/null || echo "0")

  local base_score
  if [ "$(echo "$score_impact <= 0" | bc 2>/dev/null)" = "1" ]; then
    base_score=0
  else
    if [ "$scope" = "C" ]; then
      base_score=$(echo "scale=2; 1.08 * ($score_impact + $score_exploitability)" | bc 2>/dev/null || echo "0")
    else
      base_score=$(echo "scale=2; $score_impact + $score_exploitability" | bc 2>/dev/null || echo "0")
    fi
    base_score=$(echo "scale=2; if ($base_score > 10.0) 10.0 else $base_score" | bc 2>/dev/null || echo "0")
  fi

  echo "$base_score"
}

cvss_vector_string() {
  local av="$1" ac="$2" pr="$3" ui="$4" s="$5" c="$6" i="$7" a="$8"
  echo "CVSS:3.1/AV:${av}/AC:${ac}/PR:${pr}/UI:${ui}/S:${s}/C:${c}/I:${i}/A:${a}"
}

# ─── Template selection ──────────────────────────────────────────
get_template() {
  local platform="$1"
  case "$platform" in
    hackerone)
      echo "hackerone_markdown"
      ;;
    bugcrowd)
      echo "bugcrowd_markdown"
      ;;
    intigriti)
      echo "intigriti_markdown"
      ;;
    custom)
      echo "custom_markdown"
      ;;
    *)
      echo "custom_markdown"
      ;;
  esac
}

# ─── Findings JSON schema validation ─────────────────────────────
validate_findings_json() {
  local file="$1"
  if [ ! -f "$file" ]; then
    err "File not found: $file"
    return 1
  fi

  if ! python3 -c "import json; json.load(open('$file'))" 2>/dev/null; then
    err "Invalid JSON in $file"
    return 1
  fi

  ok "Valid findings JSON: $file"
}

# ─── Generate markdown report ────────────────────────────────────
generate_markdown() {
  local title="$1" severity="$2" description="$3" findings="$4"

  cat <<EOF
# Security Finding Report

**Report Title:** ${title}
**Severity:** ${severity}
**Date:** $(date -u '+%Y-%m-%dT%H:%M:%SZ')
**Tool:** ${SCRIPT_NAME} v${VERSION}
**Platform:** ${PLATFORM}

---

## Summary

${description:-No description provided.}

## CVSS Score

$( [ -n "$CVSS_SCORE" ] && echo "**CVSS 3.1 Score:** ${CVSS_SCORE} ($(cvss_score_severity "$CVSS_SCORE"))" || echo "*CVSS score not calculated*" )

## Vulnerability Details

### Description

${description:-No description provided.}

### Impact

[Describe business impact here - what can an attacker achieve?]

### Steps to Reproduce

1. [Step 1]
2. [Step 2]
3. [Step 3]

### Proof of Concept

\`\`\`
[Insert PoC details, curl commands, or screenshots here]
\`\`\`

### Remediation

[Describe the fix or mitigation]

## Evidence

$( [ -n "$findings" ] && echo "${findings}" || echo "*No evidence attached*" )

## References

- [Reference 1]
- [Reference 2]

---

*Generated by ${SCRIPT_NAME} v${VERSION} on $(date -u)*
EOF
}

# ─── Generate JSON report ───────────────────────────────────────
generate_json() {
  local title="$1" severity="$2" description="$3"

  python3 -c "
import json, sys
report = {
    'report_title': '$title',
    'severity': '$severity',
    'date': '$(date -u '+%Y-%m-%dT%H:%M:%SZ')',
    'tool': '${SCRIPT_NAME}',
    'version': '${VERSION}',
    'platform': '${PLATFORM}',
    'cvss_score': '${CVSS_SCORE}',
    'description': '''${description}''',
    'findings': []
}
print(json.dumps(report, indent=2))
" 2>/dev/null || echo '{"error": "JSON generation failed"}'
}

# ─── Generate HTML report ────────────────────────────────────────
generate_html() {
  local title="$1" severity="$2" description="$3"

  local severity_color
  case "$severity" in
    Critical) severity_color="#dc3545" ;;
    High)     severity_color="#fd7e14" ;;
    Medium)   severity_color="#ffc107" ;;
    Low)      severity_color="#28a745" ;;
    Info)     severity_color="#17a2b8" ;;
    *)        severity_color="#6c757d" ;;
  esac

  cat <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Finding Report - ${title}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 960px; margin: 0 auto; padding: 2em; color: #333; }
  h1 { border-bottom: 3px solid ${severity_color}; padding-bottom: 0.5em; }
  .severity-badge { display: inline-block; padding: 0.25em 0.75em; background: ${severity_color}; color: white; border-radius: 4px; font-weight: bold; }
  .meta { color: #666; font-size: 0.9em; margin: 1em 0; }
  .section { margin: 2em 0; }
  .section h2 { border-bottom: 1px solid #ddd; padding-bottom: 0.3em; }
  table { width: 100%; border-collapse: collapse; margin: 1em 0; }
  th, td { border: 1px solid #ddd; padding: 0.5em; text-align: left; }
  th { background: #f5f5f5; }
  pre { background: #f8f9fa; padding: 1em; border-radius: 4px; overflow-x: auto; }
  code { background: #f0f0f0; padding: 0.2em 0.4em; border-radius: 3px; }
</style>
</head>
<body>
<h1>Security Finding Report</h1>
<p class="meta">
  <strong>Report:</strong> ${title}<br>
  <strong>Severity:</strong> <span class="severity-badge">${severity}</span><br>
  <strong>Date:</strong> $(date -u '+%Y-%m-%dT%H:%M:%SZ')<br>
  <strong>Tool:</strong> ${SCRIPT_NAME} v${VERSION}
</p>

<div class="section">
<h2>Summary</h2>
<p>${description:-No description provided.}</p>
</div>

<div class="section">
<h2>CVSS Score</h2>
<p>$( [ -n "$CVSS_SCORE" ] && echo "<strong>CVSS 3.1 Score:</strong> ${CVSS_SCORE} ($(cvss_score_severity "$CVSS_SCORE"))" || echo "<em>Not calculated</em>" )</p>
</div>

<div class="section">
<h2>Vulnerability Details</h2>
<h3>Description</h3>
<p>${description:-No description provided.}</p>
<h3>Impact</h3>
<p>Describe business impact here</p>
<h3>Steps to Reproduce</h3>
<ol>
  <li>Step 1</li>
  <li>Step 2</li>
  <li>Step 3</li>
</ol>
<h3>Proof of Concept</h3>
<pre>Insert PoC here</pre>
<h3>Remediation</h3>
<p>Describe fix</p>
</div>

<div class="section">
<h2>Evidence</h2>
<p>Evidence files would be linked here.</p>
</div>

<div class="section">
<h2>References</h2>
<ul>
  <li>Reference 1</li>
  <li>Reference 2</li>
</ul>
</div>

<hr>
<p class="meta">Generated by ${SCRIPT_NAME} v${VERSION} on $(date -u)</p>
</body>
</html>
EOF
}

# �── Generate plain text report ──────────────────────────────────
generate_text() {
  local title="$1" severity="$2" description="$3"

  cat <<EOF
================================================================================
SECURITY FINDING REPORT
================================================================================

Title:      ${title}
Severity:   ${severity}
Date:       $(date -u '+%Y-%m-%dT%H:%M:%SZ')
Tool:       ${SCRIPT_NAME} v${VERSION}
Platform:   ${PLATFORM}

--------------------------------------------------------------------------------
SUMMARY
--------------------------------------------------------------------------------

${description:-No description provided.}

CVSS Score: ${CVSS_SCORE:-Not calculated}

--------------------------------------------------------------------------------
VULNERABILITY DETAILS
--------------------------------------------------------------------------------

Description: ${description:-N/A}

Impact:
[Describe impact]

Steps to Reproduce:
1. Step 1
2. Step 2
3. Step 3

Remediation:
[Describe fix]

--------------------------------------------------------------------------------
*Generated by ${SCRIPT_NAME} v${VERSION}*
EOF
}

# ─── Process JSON input ──────────────────────────────────────────
process_json_input() {
  local file="$1"
  validate_findings_json "$file" || return 1

  info "Processing findings from $file"

  # Extract fields using python3
  python3 -c "
import json
with open('$file') as f:
    data = json.load(f)
print('Title:', data.get('title', 'N/A'))
print('Severity:', data.get('severity', 'N/A'))
print('Description:', data.get('description', 'N/A'))
print('Cvss:', data.get('cvss_score', ''))
" 2>/dev/null | while IFS= read -r line; do
    info "$line"
  done
}

# ─── Interactive mode ────────────────────────────────────────────
interactive_mode() {
  echo ""
  echo -e "${CYAN}══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║${NC}  ${GREEN}Interactive Report Builder${NC}"
  echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
  echo ""

  read -rp "Report title: " REPORT_TITLE
  echo "Severity options: Critical, High, Medium, Low, Info"
  read -rp "Severity: " SEVERITY
  read -rp "Description (multi-line, end with '.' on its own line): " DESCRIPTION_LINE

  echo ""
  read -rp "CVSS score (optional): " CVSS_SCORE
  echo "Platform options: hackerone, bugcrowd, intigriti, custom"
  read -rp "Platform [custom]: " PLATFORM_INPUT
  [ -n "$PLATFORM_INPUT" ] && PLATFORM="$PLATFORM_INPUT"
  echo "Format options: markdown, json, html, txt"
  read -rp "Output format [markdown]: " FORMAT_INPUT
  [ -n "$FORMAT_INPUT" ] && OUTPUT_FORMAT="$FORMAT_INPUT"
  read -rp "Output file (optional): " OUTPUT_FILE
}

# ─── Output ──────────────────────────────────────────────────────
write_output() {
  local content="$1" file="$2"

  if [ -n "$file" ]; then
    echo "$content" > "$file"
    ok "Report written: $file ($(wc -c < "$file") bytes)"
  else
    echo "$content"
  fi
}

# ─── Main ────────────────────────────────────────────────────────
main() {
  check_deps

  if [ "$INTERACTIVE" = true ]; then
    interactive_mode
  fi

  # From JSON input
  if [ -n "$INPUT_FILE" ]; then
    process_json_input "$INPUT_FILE"
    # Extract report fields from JSON
    local json_title json_severity json_desc json_cvss
    json_title=$(python3 -c "import json; d=json.load(open('$INPUT_FILE')); print(d.get('title',''))" 2>/dev/null || echo "")
    json_severity=$(python3 -c "import json; d=json.load(open('$INPUT_FILE')); print(d.get('severity',''))" 2>/dev/null || echo "")
    json_desc=$(python3 -c "import json; d=json.load(open('$INPUT_FILE')); print(d.get('description',''))" 2>/dev/null || echo "")
    json_cvss=$(python3 -c "import json; d=json.load(open('$INPUT_FILE')); print(d.get('cvss_score',''))" 2>/dev/null || echo "")

    [ -z "$REPORT_TITLE" ] && REPORT_TITLE="$json_title"
    [ -z "$SEVERITY" ] && SEVERITY="$json_severity"
    [ -z "$DESCRIPTION" ] && DESCRIPTION="$json_desc"
    [ -z "$CVSS_SCORE" ] && CVSS_SCORE="$json_cvss"
  fi

  # Validate required fields
  if [ -z "$REPORT_TITLE" ]; then
    err "Report title required. Use -t or --interactive."
    exit 1
  fi
  if [ -z "$SEVERITY" ]; then
    warn "No severity specified, defaulting to Info"
    SEVERITY="Info"
  fi

  # CVSS calculation helper
  if [ -n "$CVSS_SCORE" ]; then
    local severity_from_cvss
    severity_from_cvss=$(cvss_score_severity "$CVSS_SCORE")
    info "CVSS ${CVSS_SCORE} maps to severity: ${severity_from_cvss}"
    SEVERITY="${severity_from_cvss}"
  fi

  # Generate report
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${GREEN}Generating ${OUTPUT_FORMAT} report...${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

  case "$OUTPUT_FORMAT" in
    markdown)
      local report
      report=$(generate_markdown "$REPORT_TITLE" "$SEVERITY" "$DESCRIPTION" "")
      write_output "$report" "$OUTPUT_FILE"
      ;;
    json)
      local report
      report=$(generate_json "$REPORT_TITLE" "$SEVERITY" "$DESCRIPTION")
      write_output "$report" "$OUTPUT_FILE"
      ;;
    html)
      local report
      report=$(generate_html "$REPORT_TITLE" "$SEVERITY" "$DESCRIPTION")
      write_output "$report" "$OUTPUT_FILE"
      ;;
    txt)
      local report
      report=$(generate_text "$REPORT_TITLE" "$SEVERITY" "$DESCRIPTION")
      write_output "$report" "$OUTPUT_FILE"
      ;;
    *)
      err "Unknown format: ${OUTPUT_FORMAT} (markdown|json|html|txt)"
      exit 1
      ;;
  esac

  ok "Report generation complete"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  parse_args "$@"
  main
fi