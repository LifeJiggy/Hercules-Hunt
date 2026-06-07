#!/usr/bin/env bash
# =====================================================================
# evidence-toolkit.sh — Evidence Capture & PoC Tool for Linux/macOS
#
# 15 functions mirroring evidence-toolkit.ps1. Source this file.
#
# Requires: curl, jq
# =====================================================================

[ -z "$BASH_VERSION" ] && [ -z "$ZSH_VERSION" ] && echo "evidence-toolkit.sh requires bash or zsh" && return 1

EVI_DIR="${EVI_DIR:-/tmp/evidence-$(date +%Y%m%d)}"
mkdir -p "$EVI_DIR"

_evi_ts() { date -u +"%Y%m%dT%H%M%SZ"; }

# ─── 1. Invoke-CurlCapture — capture curl request/response ───────
Invoke-CurlCapture() {
  local url="$1" method="${2:-GET}" data="$3" label="${4:-req}"
  local ts f_req f_res f_meta
  ts=$(_evi_ts)
  f_req="$EVI_DIR/${label}-${ts}-request.txt"
  f_res="$EVI_DIR/${label}-${ts}-response.txt"
  f_meta="$EVI_DIR/${label}-${ts}-meta.txt"

  cat > "$f_req" <<REQ
# Request: $method $url
# Timestamp: $ts
# ---
$method $url HTTP/1.1
Host: $(echo "$url" | sed 's|https\?://||;s|/.*||')
User-Agent: Mozilla/5.0

${data:+Body: $data}
REQ

  curl -sk -X "$method" \
    ${data:+-d "$data"} \
    -D "$f_meta" \
    -o "$f_res" \
    -w "\n# HTTP %{http_code}\n# Size: %{size_download}b\n# Time: %{time_total}s\n" \
    "$url" 2>/dev/null >> "$f_meta"

  echo "Captured: $f_req $f_res"
}

# ─── 2. Save-RequestResponse — save to structured files ─────────
Save-RequestResponse() {
  local url="$1" response="$2" label="${3:-finding}"
  local ts=$(_evi_ts)
  echo "$url" > "$EVI_DIR/${label}-${ts}-url.txt"
  echo "$response" > "$EVI_DIR/${label}-${ts}-body.txt"
  echo "Saved: $EVI_DIR/${label}-${ts}-*"
}

# ─── 3. Redact-Cookies — redact cookie headers ───────────────────
Redact-Cookies() {
  local file="$1"
  sed -i 's/\(Cookie:\).*/\1 [REDACTED]/' "$file" 2>/dev/null
  sed -i 's/\(Set-Cookie:\)[^;]*\(;.*\)/\1 [REDACTED]\2/' "$file" 2>/dev/null
  echo "Cookies redacted: $file"
}

# ─── 4. Redact-AuthHeaders — redact authorization headers ────────
Redact-AuthHeaders() {
  local file="$1"
  sed -i 's/\(Authorization:\) .*/\1 [REDACTED]/' "$file" 2>/dev/null
  sed -i 's/\(Bearer\) [a-zA-Z0-9._-]*/\1 [REDACTED]/' "$file" 2>/dev/null
  echo "Auth headers redacted: $file"
}

# ─── 5. Redact-Pii — redact PII from evidence ────────────────────
Redact-Pii() {
  local file="$1"
  # emails
  sed -i 's/[a-zA-Z0-9._%+-]\+@[a-zA-Z0-9.-]\+\.[a-zA-Z]\{2,\}/[EMAIL REDACTED]/g' "$file" 2>/dev/null
  # IPs
  sed -i 's/[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}/[IP REDACTED]/g' "$file" 2>/dev/null
  # phone numbers
  sed -i 's/+\?[0-9]\{7,15\}/[PHONE REDACTED]/g' "$file" 2>/dev/null
  echo "PII redacted: $file"
}

# ─── 6. ConvertTo-Har — convert to HAR format ───────────────────
ConvertTo-Har() {
  local url="$1" method="${2:-GET}" status="${3:-200}" output="${4:-$EVI_DIR/request.har}"
  cat > "$output" <<HAR
{
  "log": {
    "version": "1.2",
    "entries": [{
      "startedDateTime": "$(date -u -Iseconds)",
      "request": { "method": "$method", "url": "$url", "headers": [] },
      "response": { "status": $status, "statusText": "OK", "headers": [] }
    }]
  }
}
HAR
  echo "HAR: $output"
}

# ─── 7. New-EvidenceFolder — create evidence directory structure ─
New-EvidenceFolder() {
  local name="${1:-engagement}"
  local dir="$EVI_DIR/$name"
  mkdir -p "$dir/requests" "$dir/responses" "$dir/screenshots" "$dir/har"
  echo "Created: $dir/{requests,responses,screenshots,har}"
}

# ─── 8. New-FindingRecord — build structured finding record ──────
New-FindingRecord() {
  local title="$1" severity="${2:-Medium}" endpoint="$3"
  local finding="$EVI_DIR/finding-$(date +%Y%m%d-%H%M%S).json"
  cat > "$finding" <<FINDING
{
  "title": "$title",
  "severity": "$severity",
  "endpoint": "$endpoint",
  "date": "$(date -u -Iseconds)",
  "status": "lead",
  "reproduction": [],
  "evidence": []
}
FINDING
  echo "Finding record: $finding"
}

# ─── 9. Export-FindingReport — export finding to markdown ────────
Export-FindingReport() {
  local finding_json="$1"
  local report="${finding_json%.json}.md"
  jq -r '"- **Title:** \(.title)\n- **Severity:** \(.severity)\n- **Endpoint:** \(.endpoint)\n- **Date:** \(.date)\n- **Status:** \(.status)"' "$finding_json" 2>/dev/null > "$report"
  echo "Report: $report"
}

# ─── 10. Test-EvidencePackage — validate evidence completeness ───
Test-EvidencePackage() {
  local dir="${1:-$EVI_DIR}"
  local missing=0
  echo "=== Evidence Check: $dir ==="
  for ext in req res meta; do
    local count
    count=$(find "$dir" -name "*.$ext" -o -name "*request*" -o -name "*response*" 2>/dev/null | wc -l)
    echo "  $ext files: $count"
    [ "$count" -eq 0 ] && missing=$((missing + 1))
  done
  [ "$missing" -gt 0 ] && echo "  ⚠  Missing evidence types: $missing" || echo "  ✓ All evidence types present"
}

# ─── 11. Compress-EvidencePackage — zip evidence directory ───────
Compress-EvidencePackage() {
  local dir="${1:-$EVI_DIR}"
  local out="${dir}.tar.gz"
  tar -czf "$out" -C "$(dirname "$dir")" "$(basename "$dir")" 2>/dev/null && echo "Compressed: $out"
}

# ─── 12. Sanitize-HarFile — sanitize HAR file of sensitive data ─
Sanitize-HarFile() {
  local infile="$1" outfile="${2:-${infile%.har}.sanitized.har}"
  cp "$infile" "$outfile"
  sed -i 's/"Cookie": "[^"]*"/"Cookie": "[REDACTED]"/g' "$outfile" 2>/dev/null
  sed -i 's/"Authorization": "[^"]*"/"Authorization": "[REDACTED]"/g' "$outfile" 2>/dev/null
  sed -i 's/"Set-Cookie": "[^"]*"/"Set-Cookie": "[REDACTED]"/g' "$outfile" 2>/dev/null
  echo "Sanitized: $outfile"
}

# ─── 13. Generate-PoCDescription — generate PoC description ──────
Generate-PoCDescription() {
  local url="$1" method="$2" summary="$3"
  cat <<POC
## Proof of Concept

### Request
\`\`\`
$method $url HTTP/1.1
Host: $(echo "$url" | sed 's|https\?://||;s|/.*||')
\`\`\$

### Summary
$summary

### Impact
[Describe real-world harm here]
POC
}

# ─── 14. Invoke-FullEvidencePipeline — full pipeline ─────────────
Invoke-FullEvidencePipeline() {
  local url="$1" label="${2:-pipeline}"
  New-EvidenceFolder "$label"
  Invoke-CurlCapture "$url" GET "" "$label"
  local latest_res
  latest_res=$(ls -t "$EVI_DIR/$label/"*response* 2>/dev/null | head -1)
  [ -n "$latest_res" ] && Redact-Cookies "$latest_res" && Redact-AuthHeaders "$latest_res" && Redact-Pii "$latest_res"
  Test-EvidencePackage "$EVI_DIR/$label"
  echo "Evidence pipeline complete: $EVI_DIR/$label/"
}

# ─── 15. Out-EvidenceReport — evidence collection report ─────────
Out-EvidenceReport() {
  local dir="${1:-$EVI_DIR}"
  local report="$dir/evidence-report.md"
  {
    echo "# Evidence Report"
    echo "**Date:** $(date -u)"
    echo ""
    echo "## Files"
    find "$dir" -type f | sort | while read -r f; do echo "- $f"; done
  } > "$report"
  echo "Report: $report"
}

echo "evidence-toolkit.sh loaded — 15 functions available"
