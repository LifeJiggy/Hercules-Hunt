#!/usr/bin/env bash
# =====================================================================
# jiggy.sh — Hercules-Hunt CLI Launcher for Linux/macOS
#
# Unified dispatcher to all bash toolkit modules. Source once, use all.
#
# Usage:
#   source jiggy.sh
#   jiggy recon example.com
#   jiggy curl https://api.target.com/login POST '{"user":"test"}'
#   jiggy fuzz https://target.com/api/users
#   jiggy js https://target.com/bundle.js
#   jiggy idor https://target.com/api/users/{id}/orders 1 100
#   jiggy cors https://target.com/api/
#   jiggy ssrf https://target.com/api/proxy
#   jiggy method https://target.com/api/endpoint
#   jiggy secret bundle.js
#   jiggy evidence https://target.com/api/endpoint
#   jiggy help
# =====================================================================

[ -z "$BASH_VERSION" ] && [ -z "$ZSH_VERSION" ] && echo "jiggy.sh requires bash or zsh" && return 1

JIGGY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Auto-source all toolkit modules
for mod in lib.sh curl-hunter.sh recon-toolkit.sh fuzzer-toolkit.sh \
           js-analyzer.sh evidence-toolkit.sh; do
  if [ -f "$JIGGY_DIR/$mod" ]; then
    source "$JIGGY_DIR/$mod"
  else
    echo "Warning: $mod not found in $JIGGY_DIR"
  fi
done

jiggy() {
  local cmd="${1:-help}" arg1="${2}" arg2="${3}" arg3="${4}"

  case "$cmd" in
    help|--help|-h)
      cat <<HELP
Hercules-Hunt CLI (jiggy.sh)

Usage:
  jiggy recon   <domain>          — Full recon pipeline
  jiggy curl    <url> [method] [body] — Test endpoint
  jiggy fuzz    <url>             — Fuzz pipeline
  jiggy js      <url|file>        — JS bundle analysis
  jiggy idor    <url> [start] [end] — IDOR range enum
  jiggy cors    <url>             — CORS misconfiguration
  jiggy ssrf    <url>             — SSRF parameter probe
  jiggy method  <url>             — HTTP method brute
  jiggy secret  <file>            — Secret scan
  jiggy evidence <url>            — Evidence capture
  jiggy help                      — This help
HELP
;;
    recon)
      [ -z "$arg1" ] && echo "Usage: jiggy recon <domain>" && return 1
      Invoke-ReconPipeline "$arg1"
;;
    curl)
      [ -z "$arg1" ] && echo "Usage: jiggy curl <url> [method] [body]" && return 1
      Test-Endpoint "$arg1" "${arg2:-GET}" "$arg3"
;;
    fuzz)
      [ -z "$arg1" ] && echo "Usage: jiggy fuzz <url>" && return 1
      Invoke-FullFuzzPipeline "$arg1"
;;
    js)
      [ -z "$arg1" ] && echo "Usage: jiggy js <url|file>" && return 1
      if [[ "$arg1" == http* ]]; then
        Invoke-FullJsScan "$arg1"
      else
        Find-ApiEndpoints "$arg1"
        Find-Secrets "$arg1"
      fi
;;
    idor)
      [ -z "$arg1" ] && echo "Usage: jiggy idor <url> [start] [end]" && return 1
      Invoke-IdorRange "$arg1" "${arg2:-1}" "${arg3:-20}"
;;
    cors)
      [ -z "$arg1" ] && echo "Usage: jiggy cors <url>" && return 1
      Test-Cors "$arg1"
;;
    ssrf)
      [ -z "$arg1" ] && echo "Usage: jiggy ssrf <url>" && return 1
      Test-SsrfParams "$arg1"
;;
    method)
      [ -z "$arg1" ] && echo "Usage: jiggy method <url>" && return 1
      Test-MethodBypass "$arg1"
;;
    secret)
      [ -z "$arg1" ] && echo "Usage: jiggy secret <file>" && return 1
      Find-Secrets "$arg1"
;;
    evidence)
      [ -z "$arg1" ] && echo "Usage: jiggy evidence <url>" && return 1
      Invoke-FullEvidencePipeline "$arg1"
;;
    *)
      echo "Unknown command: $cmd"
      jiggy help
;;
  esac
}

echo "jiggy.sh loaded — type 'jiggy help' for usage"
