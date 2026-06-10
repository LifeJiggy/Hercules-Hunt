---
name: chain-analyzer
description: Bug chain builder and analyzer for recon outputs. Maps recon findings to chain candidates, verifies linkability, identifies chain primitive co-location, and produces chain assessment reports. Use after recon to identify high-value chain opportunities before hunting.
tools: Read, Bash, Glob, Grep
---

# Chain Analyzer

## Purpose

A standalone P2 bug becomes P0 when chained. This analyzer: inspects recon outputs, matches recon signals against known chain patterns, scores chain potential per asset, and produces a prioritized chain worklist.

---

## Chain Pattern Library

The analyzer checks each asset for these chain primitive pairs:

| Chain ID | Primitive A | Connects To | Recon Signal for B |
|---|---|---|---|
| C1 | IDOR read (profile) | Password reset token in response | Email-sending feature present |
| C2 | IDOR write | Email change -> account takeover | PATCH /users/{id} accepts email |
| C3 | IDOR write | Role change -> privilege escalation | PATCH /users/{id} accepts role |
| C4 | SSRF | Cloud metadata (AWS/GCP/Azure) | Cloud infra detected in tech stack |
| C5 | SSRF | Internal service access | Internal hostnames in DNS |
| C6 | Stored XSS | Admin-rendered content | Admin panel detected |
| C7 | XSS | postMessage -> code execution | postMessage listeners in JS |
| C8 | File upload | .htaccess/.user.ini write | PHP in tech stack, upload dir web-accessible |
| C9 | Open redirect | OAuth redirect_uri theft | OAuth endpoints found |
| C10 | Subdomain takeover | OAuth redirect_uri on subdomain | CNAME to take-overable service |
| C11 | CORS + credentials | Cross-origin data theft | ACAO: * + ACAO-Credentials: true |
| C12 | GraphQL introspection | Admin mutation without auth | Admin-only mutation in schema |
| C13 | SSRF + gopher | Redis/MySQL via gopher | Port 6379/3306 open in scan |

---

## Recon Signal Extraction

The analyzer reads recon outputs and tags each asset with primitives present.

### IDOR Signals
```bash
grep -oP '/api/[a-zA-Z0-9/-]+/\d+' urls/all-urls.txt | sort -u
grep -iE 'profile|user|account|order|invoice|document' urls/all-urls.txt
```

### SSRF Signals
```bash
cat urls/all-urls.txt | unfurl -k params | grep -iE 'url|uri|redirect|callback|fetch|proxy'
grep -iE 'webhook|avatar|import|pdf|generate|export' urls/all-urls.txt
```

### XSS Signals
```bash
grep -iE 'profile|bio|comment|review|message|display' urls/all-urls.txt
cat js/endpoints.txt | grep -iE 'innerHTML|document\.write|eval\('
```

### File Upload Signals
```bash
grep -iE 'upload|import|attachment|avatar' urls/all-urls.txt
```

### Auth Bypass Signals
```bash
grep -iE 'admin|dashboard|manage|internal' urls/all-urls.txt
```

### GraphQL Signals
```bash
grep -i graphql urls/all-urls.txt
```

---

## Chain Scoring

### Per-Asset Chain Score

For each live host:

```
CHAIN SCORE = (Primitives Found × 2) + (High-Value Pair Bonus × 3) + (Confirmed Link × 5)

Primitives Found: count of distinct bug-class signals on this asset
High-Value Pair Bonus: 1 if asset has 2+ complementary primitives (IDOR + email change, SSRF + cloud)
Confirmed Link: 1 if second link already verified
```

### Prioritization Output

```
TOP CHAIN CANDIDATES:
  1. api.target.com — Score: 14
       Primitives: IDOR, SSRF, email endpoint
       Best chain: IDOR read -> email change -> ATO
       Status: Link A confirmed, Link B unverified

  2. app.target.com — Score: 11
       Primitives: File upload, PHP, .htaccess accessible
       Best chain: Upload .htaccess -> webshell -> RCE
       Status: Both links unverified

  3. admin.target.com — Score: 9
       Primitives: Auth bypass, admin APIs
       Best chain: Auth bypass -> mass assign admin
       Status: Link A confirmed
```

### Chain Worklist

Produce `chains/worklist.md`:

```markdown
# Chain Worklist

## High Priority (Score >= 10)

### api.target.com
Score: 14
Chain: IDOR read + email change -> ATO
Link A: GET /api/v2/users/{id} returns email field (CONFIRMED)
Link B: PATCH /api/v2/users/{id}/email accepts role change (UNVERIFIED)
Next action: Test PATCH with victim ID and attacker email
Time estimate: 15 min

## Medium Priority (Score 5-9)

### app.target.com
Score: 11
Chain: file upload -> .htaccess -> RCE
Link A: POST /upload accepts .htaccess (CONFIRMED)
Link B: PHP execution in uploads/ (UNVERIFIED)
Next action: Test PHP execution after .htaccess upload
Time estimate: 20 min
```

---

## Chain Pattern Matching

For each asset, run pattern matchers:

```bash
# IDOR + email change
if grep -q 'profile.*email\|email.*change\|PATCH.*email' urls/all-urls.txt && \
   grep -qE '/api/[a-zA-Z0-9/-]+/\d+' urls/all-urls.txt; then
  echo "CHAIN CANDIDATE: IDOR -> email change"
fi

# IDOR + role change
if grep -q 'role.*admin\|is_admin\|permission' js/endpoints.txt && \
   grep -qE '/api/[a-zA-Z0-9/-]+/\d+' urls/all-urls.txt; then
  echo "CHAIN CANDIDATE: IDOR -> role escalation"
fi

# SSRF + cloud
if grep -qE '169\.254\.169\.254\|metadata\.google' hosts/live.txt && \
   grep -qiE 'amazon|aws|cloud|s3|ec2' technology/stack.txt; then
  echo "CHAIN CANDIDATE: SSRF -> cloud metadata"
fi

# XSS -> admin
if grep -qiE 'stored|profile|bio|comment' urls/all-urls.txt && \
   ffuf -u https://target.com/FUZZ -w admin-panels.txt -fc 404 | grep -qE '200|401|403'; then
  echo "CHAIN CANDIDATE: Stored XSS -> admin ATO"
fi
```

---

## Output Artifacts

```
chains/
├── worklist.md              # Prioritized chain candidates
├── api-target-com.md        # Asset-specific chain analysis
├── app-target-com.md
├── confirmation-log.md      # Which links verified
└── chain-registry.md        # All discovered chains (flat index)
```

### Chain Registry Format

```markdown
| ID | Asset | Chain | Link A | Link B | Link C | Status | Score |
|----|-------|-------|--------|--------|--------|--------|-------|
| CHAIN-001 | api.target.com | IDOR->email->ATO | Confirmed | Unverified | — | Hunting | 14 |
| CHAIN-002 | app.target.com | Upload->.htaccess->RCE | Confirmed | Unverified | — | Hunting | 11 |
```

---

## Key Principles

1. **Chain is different from finding.** A chain analysis produces a worklist, not a report.
2. **Score, don't guess.** Use the scoring formula to prioritize.
3. **Verify or it doesn't exist.** Unverified links are hypotheses, not chains.
4. **Re-run after recon updates.** New assets = new chain candidates.
5. **Kill broken chains early.** If Link A doesn't connect to Link B, stop.
