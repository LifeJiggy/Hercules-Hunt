#!/usr/bin/env bash
# =====================================================================
# js-analyzer.sh — JS Bundle Analysis Toolkit for Linux/macOS
#
# 12 functions mirroring js-analyzer.ps1. Source this file.
#
# Requires: curl, jq, python3 (for beautifier)
# Optional: node, npx js-beautify
# =====================================================================

[ -z "$BASH_VERSION" ] && [ -z "$ZSH_VERSION" ] && echo "js-analyzer.sh requires bash or zsh" && return 1

JS_CACHE="${JS_CACHE:-/tmp/js-cache}"
mkdir -p "$JS_CACHE"

_js_log() { echo "[$(date -u +%H:%M:%S)] $*"; }

# ─── 1. Get-JsBundle — download JS bundle ────────────────────────
Get-JsBundle() {
  local url="$1" outdir="${2:-$JS_CACHE}"
  local fname
  fname=$(basename "$url" | cut -d? -f1)
  [ -z "$fname" ] && fname="bundle-$(date +%s).js"
  _js_log "Downloading $url"
  curl -skL "$url" -o "$outdir/$fname" 2>/dev/null && echo "$outdir/$fname" || echo "FAIL"
}

# ─── 2. Invoke-JsBeautify — beautify/pretty-print JS ─────────────
Invoke-JsBeautify() {
  local infile="$1" outfile="${2:-${infile%.js}.beautified.js}"
  if command -v npx &>/dev/null; then
    npx -y js-beautify "$infile" > "$outfile" 2>/dev/null && echo "$outfile"
  elif command -v python3 &>/dev/null; then
    python3 -c "
import sys, json
try:
    with open('$infile') as f: js = f.read()
    # basic indent
    depth = 0
    out = []
    for ch in js:
        if ch in '}]:': depth = max(0, depth-1)
        out.append(ch)
        if ch in '{[': depth += 1
    with open('$outfile', 'w') as f: f.write(''.join(out))
    print('$outfile')
except: print('FAIL')
"
  else
    cp "$infile" "$outfile" && echo "$outfile (unformatted)"
  fi
}

# ─── 3. Find-ApiEndpoints — extract API endpoint patterns ────────
Find-ApiEndpoints() {
  local file="$1"
  _js_log "Extracting endpoints from $file"
  grep -oP '["'\'']?(/[a-zA-Z0-9_./-]+(api|v[0-9]|rest|graphql)[a-zA-Z0-9_./-]*)["'\'']?' "$file" 2>/dev/null | \
    sed 's/^["'\'']//;s/["'\'']$//' | sort -u
  grep -oP '["'\''](https?://[^"'\'']*)["'\'']' "$file" 2>/dev/null | \
    sed 's/^["'\'']//;s/["'\'']$//' | sort -u
}

# ─── 4. Find-Secrets — scan for hardcoded secrets ────────────────
Find-Secrets() {
  local file="$1"
  _js_log "Scanning for secrets in $file"
  echo "=== API Keys ==="
  grep -oP '(?i)(api[_-]?key|apikey|secret|token|sk-[a-zA-Z0-9]+|ghp_[a-zA-Z0-9]+)[=:]["'\'']?[a-zA-Z0-9_\-+=/]{16,}' "$file" 2>/dev/null | head -20
  echo "=== JWTs ==="
  grep -oP 'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+' "$file" 2>/dev/null | head -10
  echo "=== URLs/Credentials ==="
  grep -oP '(https?://[^:]+:[^@]+@[^"'\'' ]+)' "$file" 2>/dev/null | head -10
  echo "=== Base64 (potential secrets) ==="
  grep -oP '[A-Za-z0-9+/]{40,}={0,2}' "$file" 2>/dev/null | head -10
}

# ─── 5. Find-FeatureFlags — detect feature flags ─────────────────
Find-FeatureFlags() {
  local file="$1"
  _js_log "Extracting feature flags"
  grep -oiP '(feature[_:-]?flag|is_enabled|is_active|show_feature|enable_|disable_|flag_|FF_)[a-zA-Z0-9_]+' "$file" 2>/dev/null | sort -u
  grep -oiP '["'\''](new_|beta_|experimental_|coming_soon|v2|v3)["'\'']' "$file" 2>/dev/null | sort -u
}

# ─── 6. Find-InternalRoutes — recover internal route paths ───────
Find-InternalRoutes() {
  local file="$1"
  _js_log "Extracting internal routes"
  grep -oP '["'\''](/internal/|/private/|/admin/|/backoffice/|/staff/|/partner/|/vendor/|/dashboard/|/manage/|/console/)[a-zA-Z0-9_./-]*["'\'']' "$file" 2>/dev/null | \
    sed 's/^["'\'']//;s/["'\'']$//' | sort -u
}

# ─── 7. Find-ConfigLeaks — detect configuration leaks ────────────
Find-ConfigLeaks() {
  local file="$1"
  _js_log "Scanning for config leaks"
  for pattern in 'AWS_ACCESS_KEY|AWS_SECRET_KEY|AWS_SESSION_TOKEN' \
                  'AZURE_CLIENT_ID|AZURE_CLIENT_SECRET|AZURE_TENANT' \
                  'GCP_PROJECT|GCP_PRIVATE_KEY|GCP_CLIENT_EMAIL' \
                  'STRIPE_KEY|STRIPE_SECRET|STRIPE_PUBLIC' \
                  'SENTRY_DSN|DATADOG_API|NEW_RELIC' \
                  'NODE_ENV=production|NODE_ENV=development' \
                  'MONGO_|MYSQL_|POSTGRES_|REDIS_'; do
    grep -oP "$pattern" "$file" 2>/dev/null | sort -u | while read -r match; do
      echo "  $match"
    done
  done
}

# ─── 8. Find-HardcodedCreds — extract hardcoded credentials ─────
Find-HardcodedCreds() {
  local file="$1"
  _js_log "Scanning for hardcoded credentials"
  grep -oiP '(password|passwd|pwd|secret|token|credential)[=:]["'\'']?[^"'\'']{4,}["'\'']' "$file" 2>/dev/null | head -20
  grep -oiP '(username|login|user|email)[=:]["'\'']?[^"'\'']+["'\'']' "$file" 2>/dev/null | head -20
}

# ─── 9. Get-SourceMap — source map analysis ─────────────────────
Get-SourceMap() {
  local url="$1"
  local sm_url="${url%.js}.js.map"
  _js_log "Fetching source map: $sm_url"
  local out
  out=$(curl -skL "$sm_url" -o "$JS_CACHE/$(basename "$sm_url")" -w "%{http_code}" 2>/dev/null)
  [ "$out" = "200" ] && echo "Source map saved: $JS_CACHE/$(basename "$sm_url")" || echo "No source map ($out)"
}

# ─── 10. Compare-JsBundles — diff two bundle versions ────────────
Compare-JsBundles() {
  local old="$1" new="$2"
  _js_log "Diffing $old vs $new"
  if command -v diff &>/dev/null; then
    diff <(grep -oP '(https?://[^"'\'']+)' "$old" | sort -u) \
         <(grep -oP '(https?://[^"'\'']+)' "$new" | sort -u) 2>/dev/null || true
  fi
}

# ─── 11. Invoke-FullJsScan — full orchestrating scan ──────────────
Invoke-FullJsScan() {
  local url="$1"
  local outfile
  outfile=$(Get-JsBundle "$url")
  [ "$outfile" = "FAIL" ] && echo "Download failed" && return 1
  echo "=== Full JS Scan: $outfile ==="
  Find-ApiEndpoints "$outfile"
  Find-Secrets "$outfile" 2>/dev/null
  Find-FeatureFlags "$outfile"
  Find-InternalRoutes "$outfile"
  Find-ConfigLeaks "$outfile"
  Find-HardcodedCreds "$outfile"
  Get-SourceMap "$url"
}

# ─── 12. Out-JsReport — structured markdown report ──────────────
Out-JsReport() {
  local input="$1"
  local report="$JS_CACHE/report-$(basename "$input" | cut -d. -f1).md"
  cat > "$report" <<REPORT
# JS Analysis Report

**File:** $input
**Date:** $(date -u)

## API Endpoints
\`\`\`
$(Find-ApiEndpoints "$input" 2>/dev/null | head -50)
\`\`\`

## Secrets Found
\`\`\`
$(Find-Secrets "$input" 2>/dev/null | head -30)
\`\`\`

## Feature Flags
\`\`\`
$(Find-FeatureFlags "$input" 2>/dev/null | head -20)
\`\`\`

## Internal Routes
\`\`\`
$(Find-InternalRoutes "$input" 2>/dev/null | head -20)
\`\`\`
REPORT
  echo "Report: $report"
}

echo "js-analyzer.sh loaded — 12 functions available"
