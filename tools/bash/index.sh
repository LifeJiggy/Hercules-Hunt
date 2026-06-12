#!/usr/bin/env bash
# ============================================================================
# Hercules-Hunt Bash Tool Index Loader
# Version: 3.0.0
# Description: Centralized loader for all 18 bash hunting tools.
# Usage:
#   source index.sh --list       List all available tools
#   source index.sh --load <tool> Load a specific tool by name
#   source index.sh --all        Load all tools
# ============================================================================

set -o errexit
set -o pipefail

if [[ -z "$BASH_VERSION" ]]; then
  echo "[!] index.sh must be sourced in bash, not sh or other shells." >&2
  return 1 2>/dev/null || exit 1
fi

_HERCULES_INDEX_VERSION="3.0.0"
_HERCULES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

declare -A _HERCULES_TOOLS
_HERCULES_TOOLS=(
  ["extract-apis"]="extract-apis.sh|API endpoint discovery – extracts REST/GraphQL endpoints from responses and JS"
  ["extract-js"]="extract-js.sh|JS extraction and secret scanning – finds hardcoded keys, tokens, internal paths"
  ["deep-hunt"]="deep-hunt.sh|Multi-pass systematic hunting – runs layered probes for deep coverage"
  ["fast-hunt"]="fast-hunt.sh|Quick surface-level probes – rapid checks for low-hanging vulnerabilities"
  ["https-probing"]="https-probing.sh|TLS/certificate/header analysis – inspects security headers, cert chains, ciphers"
  ["extract-parameters"]="extract-parameters.sh|Parameter extraction – collects query, body, and header parameters"
  ["extract-functionalities"]="extract-functionalities.sh|User function extraction – maps application features and workflows"
  ["endpoint-fuzzer"]="endpoint-fuzzer.sh|Path/method/extension fuzzing – discovers hidden endpoints and verbs"
  ["auth-tester"]="auth-tester.sh|Auth bypass testing – probes auth flows, JWT, session, role enforcement"
  ["report-builder"]="report-builder.sh|CVSS 3.1 report generation – builds structured findings with severity scoring"
  ["curl-hunter"]="curl-hunter.sh|Curl-based hunting – raw HTTP probe toolkit for lightweight testing"
  ["evidence-toolkit"]="evidence-toolkit.sh|Evidence collection – captures PoC screenshots, HAR files, request logs"
  ["fuzzer-toolkit"]="fuzzer-toolkit.sh|Advanced fuzzing engine – wordlist-based fuzzing with custom payloads"
  ["js-analyzer"]="js-analyzer.sh|JavaScript analysis – extracts endpoints, secrets, and logic from JS bundles"
  ["recon-toolkit"]="recon-toolkit.sh|Reconnaissance – subdomain enum, DNS resolution, port scanning"
  ["jiggy"]="jiggy.sh|Main dispatcher – orchestrates multi-tool hunting workflows"
  ["lib"]="lib.sh|Shared library – utility functions, logging, colors, helpers"
  ["scope-validator"]="scope-validator.sh|Scope validation – checks targets against program scope rules"
)

_hercules_list_tools() {
  local max_len=0 name
  for name in "${!_HERCULES_TOOLS[@]}"; do
    if [[ ${#name} -gt $max_len ]]; then
      max_len=${#name}
    fi
  done
  printf "  %-${max_len}s  %s\n" "NAME" "DESCRIPTION"
  printf "  %-${max_len}s  %s\n" "----" "-----------"
  for name in "${!_HERCULES_TOOLS[@]}"; do
    local file desc
    IFS='|' read -r file desc <<< "${_HERCULES_TOOLS[$name]}"
    printf "  %-${max_len}s  %s\n" "$name" "$desc"
  done
}

_hercules_load_tool() {
  local tool_name="$1"
  if [[ -z "$tool_name" ]]; then
    echo "[!] Usage: source index.sh --load <tool-name>" >&2
    return 1
  fi
  if [[ -z "${_HERCULES_TOOLS[$tool_name]:-}" ]]; then
    echo "[!] Unknown tool: '$tool_name'. Use --list to see available tools." >&2
    return 1
  fi
  local file desc
  IFS='|' read -r file desc <<< "${_HERCULES_TOOLS[$tool_name]}"
  local tool_path="$_HERCULES_DIR/$file"
  if [[ ! -f "$tool_path" ]]; then
    echo "[!] Tool file not found: $tool_path" >&2
    return 1
  fi
  # shellcheck source=/dev/null
  source "$tool_path"
  echo "[+] Loaded: $tool_name ($file)"
}

_hercules_load_all() {
  local loaded=0 failed=0 name
  for name in "${!_HERCULES_TOOLS[@]}"; do
    local file desc
    IFS='|' read -r file desc <<< "${_HERCULES_TOOLS[$name]}"
    local tool_path="$_HERCULES_DIR/$file"
    if [[ ! -f "$tool_path" ]]; then
      echo "[!] Missing: $tool_path" >&2
      ((failed++))
      continue
    fi
    # shellcheck source=/dev/null
    source "$tool_path"
    ((loaded++))
  done
  echo "[+] Loaded $loaded tools successfully."
  if [[ $failed -gt 0 ]]; then
    echo "[!] $failed tools failed to load." >&2
  fi
}

_hercules_usage() {
  cat <<EOF
Hercules-Hunt Bash Tool Index v$_HERCULES_INDEX_VERSION

Usage: source index.sh <option>

Options:
  --list              List all available tools and descriptions
  --load <tool-name>  Load a specific tool by name
  --all               Load all 18 tools

Examples:
  source index.sh --list
  source index.sh --load extract-apis
  source index.sh --all

Tool index directory: $_HERCULES_DIR
EOF
}

if [[ $# -eq 0 ]]; then
  _hercules_usage
  return 0 2>/dev/null || exit 0
fi

case "${1:-}" in
  --list|-l)
    _hercules_list_tools
    ;;
  --load|-s)
    _hercules_load_tool "${2:-}"
    ;;
  --all|-a)
    _hercules_load_all
    ;;
  --help|-h)
    _hercules_usage
    ;;
  *)
    echo "[!] Unknown option: $1. Use --help for usage." >&2
    return 1 2>/dev/null || exit 1
    ;;
esac
