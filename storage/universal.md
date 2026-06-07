---
name: storage-universal
description: Universal storage architecture and index for Hercules-Hunt. Defines the complete storage structure — how evidence, findings, credentials, tool outputs, session logs, and configuration backups are organized, named, searched, cross-referenced, and maintained across all targets and sessions.
---

# Universal Storage Architecture

This file defines the complete storage system for Hercules-Hunt. Every file created during recon, hunting, validation, reporting, and submission has a defined home in this structure. Consistent storage discipline ensures nothing is lost and everything is findable.

---

## 1. Storage Architecture Overview

```
storage/
├── universal.md           ← THIS FILE — master storage index
├── persistence.md         ← Data lifecycle, retention, backup/restore
├── credentials-vault.md   ← Test accounts, session tokens, API keys
├── tool-outputs.md        ← Raw tool outputs organized by tool
├── hunt-logs.md           ← Session execution logs and timelines
├── config-backups.md      ← Tool configuration snapshots
├── evidence-packages.md   ← Captured PoC evidence by finding
├── findings-archive.md    ← Submitted findings and outcomes
├── scope-records.md       ← Scope verification records
└── sessions-index.md      ← Session-to-storage cross-reference
```

Every write to storage follows three rules:
1. **Index it** — every file created must be referenced in the relevant index
2. **Name it** — follow the naming convention
3. **Timestamp it** — every entry must have a timestamp

---

## 2. Naming Convention

### File Naming
```
Format: {prefix}-{target}-{date}-{descriptor}.{ext}

Prefixes:
  evd  → Evidence package
  out  → Tool output
  log  → Hunt log  
  cfg  → Config backup
  crd  → Credential record
  fnd  → Finding record
  scp  → Scope record

Examples:
  evd-target.com-20260315-invoice-idor.json
  out-target.com-20260315-ffuf-dirs.txt
  log-target.com-20260315-session-001.md
  cfg-target.com-20260315-httpx-config.yaml
  crd-target.com-20260315-test-accounts.json
```

### Section Naming (within files)
```
Format: [YYYY-MM-DD] Target :: Description

Examples:
  [2026-03-15] target.com :: IDOR on GET /api/v2/invoices/{id}
  [2026-03-15] target.com :: Auth bypass on POST /admin/users
  [2026-03-16] target.com :: SSRF avatar import — DNS callback confirmed
```

---

## 3. Storage Index

### Current Target: target.com

| Category | File | Last Updated | Size | Notes |
|----------|------|-------------|------|-------|
| Evidence | evidence-packages.md | — | — | — |
| Findings | findings-archive.md | — | — | — |
| Credentials | credentials-vault.md | — | — | — |
| Tool Outputs | tool-outputs.md | — | — | — |
| Hunt Logs | hunt-logs.md | — | — | — |
| Config | config-backups.md | — | — | — |
| Scope | scope-records.md | — | — | — |
| Sessions | sessions-index.md | — | — | — |

### All Targets

| Target | Evidence | Findings | Logs | Scope | Last Updated |
|--------|----------|----------|------|-------|-------------|
| — | — | — | — | — | — |

---

## 4. Evidence Organization

### Evidence Package Structure

Each confirmed finding gets a dedicated evidence entry in `evidence-packages.md`:

```
=== Evidence: INV-IDOR-001 ===
Title: IDOR on GET /api/v2/invoices/{id}
Target: target.com
Severity: High
Date: 2026-03-15
Status: CAPTURED

Requests:
  1. GET /api/v2/invoices/1001 (attacker's own invoice)
     Headers: Authorization: Bearer <attacker_jwt>
     Response: 200 — {"id":1001,"customer_name":"Attacker","amount":"$250.00"}
     
  2. GET /api/v2/invoices/2002 (victim's invoice)
     Headers: Authorization: Bearer <attacker_jwt> (SAME TOKEN)
     Response: 200 — {"id":2002,"customer_name":"Jane Smith","amount":"$4,200.00","card_last4":"4242"}

Screenshots:
  - screenshot-01.png — Burp showing both requests/responses
  - screenshot-02.png — Victim's invoice data in attacker's browser

Files:
  - evd-target.com-20260315-invoice-idor.txt — raw request/response dump
  - evd-target.com-20260315-invoice-idor.burp — Burp export

Chain References:
  - Links to Lead-002 (PDF IDOR)
  - Links to Lead-003 (DELETE IDOR)
```

### Evidence Quality Standards

```
HTTP Requests:
  [✓] Full URL with method
  [✓] All headers (Auth, Cookie, Content-Type)
  [✓] Request body (if applicable)
  [✓] Full response body
  [✓] Status code
  [✓] Response headers (relevant ones)

Screenshots:
  [✓] URL bar visible
  [✓] Full impact shown
  [✓] Annotated (arrows, circles)
  [✓] No PII of other real users (redacted)
  [✓] Timestamp visible (system clock or tool)

Two-Account Proof:
  [✓] Request A — own data (baseline)
  [✓] Request B — other user's data (proof)
  [✓] Same session/token used for both (proves no privilege)
```

---

## 5. Findings Archive Organization

### Per-Program Structure

```
=== Program: target.com (HackerOne) ===

Finding 1:
  Title: IDOR in /api/v2/invoices/{id} allows authenticated user to read all invoices
  Submitted: 2026-03-16
  Status: SUBMITTED — Awaiting triage
  Bounty: TBD
  Report #: H1-1234567

Finding 2:
  Title: Missing authentication on POST /api/admin/users allows unauthenticated admin creation
  Submitted: 2026-03-16
  Status: SUBMITTED — Triaged as Critical
  Bounty: TBD
  Report #: H1-1234568

=== Program: another-target.com (Bugcrowd) ===

Finding 1:
  Title: ...
```

### Finding Status Values
- `DRAFT` — Report being written
- `READY` — Report ready to submit
- `SUBMITTED` — Sent to program
- `TRIAGED` — Acknowledged by triager
- `PAID` — Bounty received
- `DUPLICATE` — Already reported
- `NA` — Not applicable (rejected)
- `WONTFIX` — Program chose not to fix
- `INFORMATIVE` — Triaged but no bounty eligibility
- `DISCLOSED` — Report made public

---

## 6. Tool Output Storage

### Per-Tool Organization in tool-outputs.md

```
=== subfinder ===
Date: 2026-03-15
Target: target.com
Command: subfinder -d target.com -all -o subfinder-output.txt
Output summary: 1,247 subdomains found
Notable: admin.target.com, api.target.com, dev.target.com, staging.target.com
Full output: storage/tool-outputs/subfinder-target.com-20260315.txt

=== httpx ===
Date: 2026-03-15
Target: target.com (from subfinder output)
Command: httpx -l subdomains.txt -title -tech-detect -status-code
Output summary: 312 live hosts
Notable tech: React 18, Express 4, Cloudflare, AWS
Full output: storage/tool-outputs/httpx-target.com-20260315.txt

=== ffuf ===
Date: 2026-03-15
Target: https://target.com
Command: ffuf -u https://target.com/FUZZ -w common.txt -mc 200,204,301,302,403
Output summary: 45 directories discovered
Notable: /admin, /api, /graphql, /health, /metrics
Full output: storage/tool-outputs/ffuf-target.com-20260315.txt
```

### Output Retention
- Tool outputs are kept for the duration of active hunting on the target
- After target is archived, raw outputs are summarized and moved to archive
- Config files (tool configs) are kept permanently in config-backups.md

---

## 7. Cross-Reference System

### Finding ↔ Evidence Cross-Reference
```
Finding: IDOR on GET /api/v2/invoices/{id}
  → Evidence Package: INV-IDOR-001
  → Screenshots: screenshot-01.png, screenshot-02.png
  → Tool Output: ffuf output (invoice endpoints discovered)
  → Session Log: log-target.com-20260315-session-001.md
  → Chain: Links to INV-IDOR-002 (PDF), INV-IDOR-003 (DELETE)
```

### Lead ↔ Finding Cross-Reference
```
Lead-001 (IDOR Read) → Finding INV-IDOR-001
Lead-002 (IDOR PDF) → Finding INV-IDOR-002  
Lead-003 (IDOR Delete) → Finding INV-IDOR-003
Lead-004 (Auth Bypass) → Finding AUTH-BYPASS-001
```

### Session ↔ Storage Cross-Reference
```
Session JGY-20260315-143022-4a7f:
  → Evidence created: INV-IDOR-001, INV-IDOR-002, INV-IDOR-003
  → Tool outputs: subfinder, httpx, ffuf
  → Findings submitted: H1-1234567, H1-1234568
```

---

## 8. Search and Retrieval

### Finding Evidence by Target
```
1. Look up target in storage index (§3)
2. Navigate to evidence-packages.md → search for target entries
3. Follow cross-references to specific evidence files
```

### Finding Evidence by Bug Class
```
1. Navigate to evidence-packages.md
2. Grep for bug class: grep "IDOR" evidence-packages.md
3. Collect all matching evidence packages
```

### Finding Evidence by Date
```
1. Evidence is organized chronologically within evidence-packages.md
2. Each entry has a date stamp
3. Session logs in hunt-logs.md also reference evidence by date
```

### Quick Reference (grep patterns)
```bash
# Find all evidence for a target
grep "target.com" storage/evidence-packages.md

# Find all critical findings
grep "Critical" storage/findings-archive.md

# Find all IDOR evidence
grep -i "idor" storage/*.md

# Find all sessions on a specific date
grep "2026-03-15" storage/hunt-logs.md

# Find all submitted reports
grep "SUBMITTED" storage/findings-archive.md
```

---

## 9. Storage Lifecycle

### Creation
```
1. Tool output generated → save to tool-outputs.md
2. Finding confirmed → create evidence package in evidence-packages.md
3. Session ends → write summary to hunt-logs.md
4. Credential created → save to credentials-vault.md
```

### Active Use
```
1. Evidence is referenced during report writing
2. Findings are updated as they move through triage
3. Tool outputs are consulted for new leads
4. Credentials are checked before each session
```

### Archival
```
1. Target completed → archive all associated storage
2. Old tool outputs → summarize and archive raw files
3. Evidence for paid findings → keep permanently
4. Evidence for killed findings → archive after 90 days
```

### Cleanup
```
1. Raw tool outputs older than 30 days → archive
2. Temp credentials → delete after use
3. Stale session logs → archive after target completion
4. Orphaned evidence → review and consolidate
```

---

## 10. Storage Standards

### File Format
- All storage files are Markdown (.md) with YAML frontmatter
- Evidence code blocks use ```http for requests/responses
- JSON responses use ```json
- Screenshots referenced as relative paths: `assets/screenshots/screenshot-01.png`
- All timestamps in ISO 8601: `2026-03-15T14:30:22Z`

### Maximum Sizes
- Individual evidence entry: < 50 KB
- Individual tool output entry: < 100 KB (truncate raw outputs)
- Individual file: < 10 MB
- Total storage: no limit (archival recommended over deletion)

### Prohibited Content
- Real user PII (use test accounts, redact real data)
- Session tokens after use (rotate and remove)
- Production credentials (never commit to git)
- Internal infrastructure details (unless needed for PoC)
- Large binary files (store separately, reference by path)

---

## 11. Git Integration

### .gitignore Rules for storage/
```
# Never commit sensitive data
storage/credentials-vault.md
storage/evidence-packages.md  # if contains real PII

# Consider ignoring large outputs
storage/tool-outputs/*
!storage/tool-outputs.md

# Always keep
storage/universal.md
storage/persistence.md
storage/findings-archive.md
storage/scope-records.md
```

### Recommended Practice
- Keep `storage/*.md` in git (the index files)
- Keep raw evidence files OUT of git (too large, sensitive)
- Use git LFS for screenshots if needed
- Never commit credentials vault to any repo

---

## 12. Storage Consistency Checks

### Automated Check (Run at Session Start)
```
1. [CHECK] Do all storage files have valid YAML frontmatter?
2. [CHECK] Is storage/index up to date with actual files?
3. [CHECK] Are all credentials in the vault still valid?
4. [CHECK] Are any evidence packages orphaned (no finding reference)?
5. [CHECK] Is .gitignore properly excluding sensitive files?
6. [CHECK] Is disk space sufficient for new evidence?
7. [CHECK] Do all cross-references resolve?
```

### Manual Cleanup (Monthly)
```
1. Archive completed targets
2. Consolidate duplicate evidence
3. Prune expired credentials
4. Update storage index
5. Backup storage directory
```

---

## 13. Storage Anti-Patterns

| Anti-Pattern | Why It Fails | Fix |
|-------------|-------------|-----|
| Evidence in random filenames | Can't find when needed | Use naming convention |
| Screenshots without context | Don't prove the bug | Annotate and caption |
| Storing everything in one file | File becomes unwieldy | Split by category |
| No cross-references | Evidence disconnected from findings | Use reference IDs |
| Raw tool outputs without summary | Can't parse results | Add summary line |
| Credentials committed to git | Security leak | .gitignore the vault |
| No timestamps | Can't establish timeline | Timestamp everything |
| Deleting evidence for killed findings | Lose data for future | Archive, don't delete |
| Mixing targets in same section | Cross-contamination | Separate by target |
| Binary files in markdown | Bloat | Reference external files |

---

## 14. Storage Architecture Rules

### Rule 1: Index Everything
Every file created, every piece of evidence captured, every finding submitted must be indexed in this file. If it's not indexed, it doesn't exist.

### Rule 2: Name Consistently
Every file follows the naming convention. Every entry follows the section format. Consistency is what makes storage searchable.

### Rule 3: Cross-Reference
Evidence links to findings. Findings link to leads. Leads link to sessions. Sessions link to evidence. Everything connects.

### Rule 4: Clean As You Go
Delete temp files when done. Archive completed targets. Update indexes immediately. Storage debt compounds.

### Rule 5: Never Delete Evidence
Archive instead of delete. Evidence from killed findings may become relevant later. Evidence from paid findings is permanent proof of work.

### Rule 6: Protect Credentials
Credentials vault never enters git. Tokens are rotated after each session. Test accounts are restored after use.

### Rule 7: Timestamp Everything
Every entry, every file, every update must have a timestamp. Without timestamps, storage has no order.

---

## 15. Quick Reference

### Storage File Paths
```
storage/universal.md              ← THIS FILE
storage/persistence.md            ← Data lifecycle rules
storage/credentials-vault.md      ← Test accounts
storage/tool-outputs.md           ← Tool command outputs
storage/hunt-logs.md              ← Session execution logs
storage/config-backups.md         ← Tool config snapshots
storage/evidence-packages.md      ← PoC evidence
storage/findings-archive.md       ← Submitted findings
storage/scope-records.md          ← Scope verification
storage/sessions-index.md         ← Session cross-reference
```

### Storage Flow
```
Discovery → Tool output → tool-outputs.md
  ↓
Lead created → discoveries.md (memory/)
  ↓
Testing → Evidence → evidence-packages.md
  ↓
Confirmed → Finding → universal.md (memory/) + findings-archive.md
  ↓
Report → Submit → Update findings-archive.md
  ↓
Outcome → Log to lessons-log.md (memory/)

---

## 16. Storage File Templates

### Evidence Package Template
```markdown
=== Evidence: [FINDING-ID] ===
Title: [brief description]
Target: [domain]
Severity: [Critical/High/Medium/Low]
Date: [YYYY-MM-DD]
Status: [CAPTURED/SUBMITTED/ARCHIVED]

Requests:
  1. [METHOD] [URL] ([description])
     Headers: [relevant headers]
     Response: [status] — [brief description of response body]

  2. [METHOD] [URL] ([description])
     Headers: [relevant headers]
     Response: [status] — [brief description]

Screenshots:
  - [filename] — [description]

Files:
  - [filename] — [description]

Chain References:
  - Links to [other finding/lead IDs]
```

### Finding Record Template
```markdown
=== Finding: [FINDING-ID] ===
Title: [report title]
Target: [domain]
Program: [platform]
Bug Class: [IDOR/SSRF/XSS/etc.]
Severity: [Critical/High/Medium/Low]
CVSS: [vector string]
Submitted: [YYYY-MM-DD]
Status: [SUBMITTED/TRIAGED/PAID/NA/DUP]
Report #: [platform report ID]
Bounty: [$ amount or TBD]
Evidence IDs: [list of evidence package IDs]
Chain: [chain ID if part of a chain]
```

### Hunt Log Entry Template
```markdown
=== Session: [SESSION-ID] ===
Date: [YYYY-MM-DD]
Target: [domain]
Start: [HH:MM] — End: [HH:MM] — Duration: [Xh Ym]
Phase: [phase]
Findings: [N] new, [N] confirmed, [N] killed

=== Activity ===
[HH:MM] [endpoint] [method] [test type] [result]

=== Key Results ===
- [finding description]
- [finding description]

=== Next Actions ===
1. [action]
2. [action]
```

---

## 17. Storage Conflict Resolution

### Evidence with Same Finding ID
```
Conflict: Two evidence packages with ID EVD-001
Resolution: 
  1. Compare timestamps — most recent is current
  2. Compare content — is one a superset? (keep superset)
  3. If identical → deduplicate, keep one
  4. If different findings same ID → assign new ID to one
```

### Finding Referenced But No Evidence
```
Conflict: Finding references evidence EVD-003 but it doesn't exist
Resolution:
  1. Search all storage files for EVD-003
  2. Check evidence-packages.md for the entry
3. If truly missing → flag as orphaned reference
4. Recreate evidence from session logs or tool outputs
5. If unrecoverable → note in finding record

---

## 18. Storage Search Index

Quick-reference index for finding data fast.

### By Finding ID
```
FINDING-ID → evidence-packages.md → [section] → [line numbers]
```

### By Target
```
target.com → evidence-packages.md → [section range]
target.com → findings-archive.md → [section range]
target.com → hunt-logs.md → [session IDs]
target.com → tool-outputs.md → [section range]
```

### By Bug Class
```
IDOR → evidence-packages.md → [list of finding IDs]
SSRF → evidence-packages.md → [list of finding IDs]
XSS → evidence-packages.md → [list of finding IDs]
```

### By Date
```
2026-03-15 → hunt-logs.md → [session IDs]
2026-03-15 → evidence-packages.md → [finding IDs]
2026-03-15 → tool-outputs.md → [sections]
```

---

## 19. Storage Migration Guide

If storage needs to be migrated to a new system:

```
1. [FREEZE] — Stop all active testing
2. [BACKUP] — Full backup of storage/ directory
3. [EXPORT] — Copy all raw evidence files
4. [VERIFY] — Integrity check on all files
5. [TRANSFER] — Copy to new location
6. [VERIFY AGAIN] — Confirm all files transferred correctly
7. [UPDATE PATHS] — Update references in memory/universal.md
8. [UNFREEZE] — Resume testing
9. [KEEP OLD] — Keep old storage for 30 days as fallback
```

---

## 20. Storage Integration Points

### Integration with memory/universal.md
```
universal.md §3 (Target Index) → Links to storage per-target sections
universal.md §5 (Findings) → Links to findings-archive.md
universal.md §9 (Tools) → Links to tool-outputs.md configurations
```

### Integration with memory/session-state.md
```
session-state.md §4 (Endpoint Queue) → Tool outputs for discovery
session-state.md §5 (Test Results) → Evidence for confirmation
session-state.md §10 (Findings) → Cross-reference to archive
```

### Integration with memory/discoveries.md
```
discoveries.md §2 (Active Leads) → Evidence for confirmed leads
discoveries.md §5 (Killed) → Tool outputs showing refutation
```

### Integration with memory/technical-notes.md
```
technical-notes.md §2 (Endpoints) → Tool outputs confirming architecture
technical-notes.md §3 (Auth) → Evidence from auth testing
```

```

### Target Referenced But Not in Registry
```
Conflict: Hunt logs reference target "unknown.com" but no scope record
Resolution:
  1. Check if it's an alias for a known target
  2. Check program scope documentation
  3. If valid target not registered → add to target-registry.md
  4. If out of scope → flag the logs and remove references
```

### Conflicting Severity Assessments
```
Conflict: Same finding rated HIGH in memory but MEDIUM in storage
Resolution:
  1. Re-run CVSS calculation with evidence
  2. The most recent assessment wins
  3. Update both files to match
  4. Log the disagreement in lessons-log.md
```

```
