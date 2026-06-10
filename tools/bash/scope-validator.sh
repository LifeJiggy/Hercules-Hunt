#!/usr/bin/env bash
# scope-validator.sh — Recon scope validation for bash toolkit
# Filters subdomains, hosts, and URLs against program scope.
# Usage:
#   bash scope-validator.sh --scope scope.json --input subs.txt --output in-scope.txt
#   bash scope-validator.sh --scope scope.json --input urls.txt --mode hostname --output in-scope.txt
#   bash scope-validator.sh --scope scope.json --input live.txt --mode ip --output in-scope.txt

set -euo pipefail

SCOPE_FILE=""
INPUT_FILE=""
OUTPUT_FILE=""
MODE="hostname"  # hostname | ip | url

usage() {
  cat <<EOF
scope-validator.sh — Filter recon outputs to in-scope assets.

Usage:
  bash scope-validator.sh --scope scope.json --input <file> --output <file> [--mode hostname|ip|url]

Options:
  --scope <file>    Path to scope.json (required)
  --input <file>    Input file (one item per line) (required)
  --output <file>   Output file for in-scope items (required)
  --mode <type>     Input type: hostname (default), ip, url
  --help            Show this help
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scope) SCOPE_FILE="$2"; shift 2 ;;
    --input) INPUT_FILE="$2"; shift 2 ;;
    --output) OUTPUT_FILE="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --help) usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

if [[ -z "$SCOPE_FILE" || -z "$INPUT_FILE" || -z "$OUTPUT_FILE" ]]; then
  echo "Error: --scope, --input, and --output are required"
  usage
fi

if [[ ! -f "$SCOPE_FILE" ]]; then
  echo "Error: Scope file not found: $SCOPE_FILE"
  exit 1
fi

if ! command -v jq &>/dev/null; then
  echo "Error: jq is required but not installed"
  exit 1
fi

SCOPE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATOR_PY="$SCOPE_DIR/../python/scope_validator.py"

if [[ -f "$VALIDATOR_PY" ]]; then
  python3 "$VALIDATOR_PY" \
    --scope "$SCOPE_FILE" \
    --input "$INPUT_FILE" \
    --output "$OUTPUT_FILE" \
    --mode "$MODE"
  echo "[scope-validator] Done. In-scope results written to: $OUTPUT_FILE"
else
  echo "Error: scope_validator.py not found at $VALIDATOR_PY"
  exit 1
fi
