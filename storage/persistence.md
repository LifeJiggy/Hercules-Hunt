---
name: storage-persistence
description: Storage data lifecycle, retention policies, backup/recovery, archival procedures, and cross-session persistence for Hercules-Hunt storage layer. Governs every byte stored: when it's created, how long it lives, when it's archived, and when it's deleted.
---

# Storage Persistence & Data Lifecycle

This file defines the complete data lifecycle for every byte stored in the Hercules-Hunt storage system. From creation through active use, archival, and cleanup — every piece of data has a defined path.

---

## 1. Data Lifecycle Model

```
CREATION → ACTIVE → [ARCHIVE] → CLEANUP
              ↓
          USE
              ↓
          REFERENCE (permanent)
```

### Stage Definitions

| Stage | Description | Duration |
|-------|-------------|----------|
| CREATION | Data is first written to storage | Instant |
| ACTIVE | Data is in active use — referenced, queried, modified | Target-dependent |
| ARCHIVE | Data is no longer actively needed but kept for reference | Indefinite |
| CLEANUP | Data is deleted or pruned | At end of lifecycle |
| REFERENCE | Permanent reference — never deleted | Forever |

---

## 2. Data Persistence by Category

### Evidence (evidence-packages.md)

| Stage | Retention | Trigger | Action |
|-------|-----------|---------|--------|
| ACTIVE | Until finding is submitted | Finding confirmed | Store evidence |
| ARCHIVE | 90 days after submission | Finding accepted/paid | Compress and move to archive |
| REFERENCE | Permanent | Finding paid | Keep summary, archive raw files |
| CLEANUP | N/A (if finding killed) | Finding killed after 30 days | Remove evidence |

**Special Rules:**
- Evidence for PAID findings: PERMANENT — never delete
- Evidence for KILLED findings: Archive for 30 days, then cleanup
- Evidence with real PII: Archive for 7 days, then permanent delete
- Duplicate evidence: Remove when duplicate confirmed

### Findings (findings-archive.md)

| Stage | Retention | Trigger | Action |
|-------|-----------|---------|--------|
| ACTIVE | Until outcome known | Finding created | Record finding |
| REFERENCE | Permanent | Finding resolved (any outcome) | Keep in archive forever |

**Special Rules:**
- Submitted findings: PERMANENT — includes report number, date, outcome
- N/A findings: PERMANENT — learn from rejection reasons
- Duplicate findings: PERMANENT — reference to original report

### Credentials (credentials-vault.md)

| Stage | Retention | Trigger | Action |
|-------|-----------|---------|--------|
| ACTIVE | Until account expires | Credential created | Store securely |
| ARCHIVE | 30 days after expiry | Account banned/expired | Move to archive section |
| CLEANUP | Immediate after expiry cleanup | Expired > 30 days | Delete permanently |

**Special Rules:**
- NEVER commit to git
- Rotate after each target completion
- Clear session tokens immediately after use
- Backup critical accounts (email-accessible recovery)

### Tool Outputs (tool-outputs.md)

| Stage | Retention | Trigger | Action |
|-------|-----------|---------|--------|
| ACTIVE | While target is active | Output generated | Store with summary |
| ARCHIVE | 30 days after target archived | Target completed | Archive raw files |
| CLEANUP | 30 days after archive | Archived > 30 days | Delete raw files |

**Special Rules:**
- Summaries remain forever (what was found, commands used)
- Raw output files are candidates for earliest cleanup
- Config files and tool configurations are KEPT permanently
- Large outputs (>10 MB) are truncated with a note

### Hunt Logs (hunt-logs.md)

| Stage | Retention | Trigger | Action |
|-------|-----------|---------|--------|
| ACTIVE | While target is active | Session runs | Log activity |
| ARCHIVE | 90 days after target archived | Target completed | Move to archive section |
| REFERENCE | 1 year | Archived > 90 days | Keep summary, remove detail |

**Special Rules:**
- Session summaries (start, end, duration, findings) are PERMANENT
- Detailed activity logs are archived after target completion
- Heartbeat entries are removed from active log after archival

### Config Backups (config-backups.md)

| Stage | Retention | Trigger | Action |
|-------|-----------|---------|--------|
| ACTIVE | While tool configs in use | Config backed up | Store in index |
| REFERENCE | Permanent | Any state | Never delete config backups |

**Special Rules:**
- Never deleted — configs don't take much space
- Only prune if explicitly requested
- Keep a "last known good" marker for rollback

### Scope Records (scope-records.md)

| Stage | Retention | Trigger | Action |
|-------|-----------|---------|--------|
| ACTIVE | While target is active | Scope verified | Record scope |
| REFERENCE | Permanent | Any state | Never delete scope records |

**Special Rules:**
- Scope records are permanent — they prove you tested authorized targets
- Update scope if program changes mid-hunt
- Keep both the verified scope and the original program scope text

### Sessions Index (sessions-index.md)

| Stage | Retention | Trigger | Action |
|-------|-----------|---------|--------|
| ACTIVE | While any session exists | Session starts | Add to index |
| REFERENCE | Permanent | Session ends | Keep entry forever |

**Special Rules:**
- One line per session — never delete
- Links to evidence, findings, and logs
- Used for billing, reporting, and personal analytics

---

## 3. Retention Schedule Summary

| Data Type | Active | Archive | Total Lifetime |
|-----------|--------|---------|---------------|
| Evidence (paid) | Until paid | Permanent | Permanent |
| Evidence (killed) | Until killed | 30 days | 30 days |
| Evidence (duplicate) | Until confirmed | None | Removed on confirmation |
| Findings (any) | Until resolved | Permanent | Permanent |
| Credentials (active) | Until expiry | 30 days | Account lifetime + 30 days |
| Credentials (tokens) | Session duration | None | Deleted on session end |
| Tool outputs (raw) | Target active | 30 days | Target lifetime + 30 days |
| Tool outputs (summary) | Target active | Permanent | Permanent |
| Hunt logs (detailed) | Target active | 90 days | ~1 year |
| Hunt logs (summary) | Target active | Permanent | Permanent |
| Config backups | Infinite | Permanent | Permanent |
| Scope records | Infinite | Permanent | Permanent |
| Session index | Infinite | Permanent | Permanent |

---

## 4. Backup Architecture

### What Gets Backed Up

| Priority | Data | Frequency | Method |
|----------|------|-----------|--------|
| CRITICAL | Scope records | Every change | Copy to config-backups.md |
| CRITICAL | Submitted findings | Every change | Copy to config-backups.md |
| HIGH | Evidence packages | Every creation | Auto-save to evidence dir |
| HIGH | Credentials vault | Every change | Encrypted backup |
| MEDIUM | Tool configs | Every change | Copy to config-backups.md |
| MEDIUM | Session logs | Every session end | Copy to config-backups.md |
| LOW | Raw tool outputs | Weekly | Archive old outputs |

### Backup Types

**1. Inline Backup (config-backups.md)**
Critical data is backed up inline within the config-backups.md file. This includes scope records, config files, and submitted findings references. This is the FIRST backup layer — always available, always in sync.

**2. Filesystem Backup**
Full storage directory backup. Run this weekly or before major changes.

```powershell
function Backup-JiggyStorage {
    param([string]$BackupRoot = "$env:USERPROFILE\.jiggy-backups")
    
    $date = Get-Date -Format "yyyyMMdd-HHmmss"
    $backupPath = Join-Path $BackupRoot "jiggy-storage-$date"
    
    # Backup storage directory
    Copy-Item -Path ".\storage" -Destination $backupPath -Recurse -Force
    
    # Backup memory directory (linked data)
    Copy-Item -Path ".\memory" -Destination "$backupPath\..\jiggy-memory-$date" -Recurse -Force
    
    Write-Host "Backup saved to: $backupPath"
    return $backupPath
}
```

**3. Git Backup (Optional)**
For users comfortable with git:

```bash
cd jiggy-2026
git add storage/*.md memory/*.md
git commit -m "Storage backup $(date +%Y-%m-%d)"
git push  # to private repo
```

**Warning:** Never commit credentials-vault.md or evidence with real PII to any git repo, even private ones.

### Backup Retention

| Backup Type | Retention | Cleanup |
|-------------|-----------|---------|
| Inline (config-backups.md) | Permanent | Manual cleanup only |
| Filesystem backup | 90 days | Auto-pruned after 90 days |
| Git backup | Permanent | Git history |

---

## 5. Recovery Procedures

### Partial Recovery (Single File)

```
1. [FILE CORRUPTED] — evidence-packages.md is unreadable
2. Check config-backups.md for last known good version
3. Restore last good version from backup entry
4. Identify gap between corrupted version and backup
5. If gap contains unrecoverable data → note loss in lessons-log.md
6. Update universal.md: "evidence-packages.md restored from backup"
```

### Full Recovery (All Storage)

```
1. [DISASTER] — storage/ directory deleted or corrupted
2. Locate most recent backup
3. Restore entire storage/ from backup
4. Check consistency: do all cross-references still work?
5. Check timestamps: is anything missing?
6. If gap exists → note in universal.md what was lost
7. Verify: can all active targets be resumed?
8. Update universal.md: "Full storage recovery from backup [date]"
```

### Partial Data Loss (Specific Entry)

```
1. [ENTRY LOST] — specific evidence package for paid finding is gone
2. Check findings-archive.md for the report reference
3. If report was on HackerOne/Bugcrowd → can re-download from platform
4. If local-only evidence → note loss in lessons-log.md
5. Re-create minimal evidence from memory if possible
```

---

## 6. Archival Procedures

### When to Archive

| Trigger | What to Archive |
|---------|----------------|
| Target completed (all findings submitted) | All storage for that target |
| No activity on target for 30 days | Flag for archival review |
| Finding received outcome (paid/NA/dup) | Evidence and logs |
| Tool outputs older than 30 days | Raw output files |
| Credentials expired | Test accounts |

### Archive Format

```
Archive entry format:
---
name: archive-{target}-{date}
description: Archived storage for target [target]. Completed [date]. [N] findings submitted, [N] findings paid.

## Archive Summary
Target: [target]
Active Period: [start date] → [end date]
Total Sessions: [N]
Total Findings Submitted: [N]
Total Findings Paid: [N]
Total Bounty: [$X]

## Storage Contents
- Evidence packages: [N] entries preserved
- Tool outputs: [N] summaries preserved, raw files pruned
- Hunt logs: [N] session summaries preserved, detail pruned
- Credentials: Cleared (accounts expired)
- Config: Preserved
- Scope: Preserved
```

### Archive Command

```powershell
function Invoke-JiggyArchive {
    param([string]$Target)
    
    Write-Host "Archiving $Target..." -ForegroundColor Cyan
    
    # Create archive section in each storage file
    $date = Get-Date -Format "yyyy-MM-dd"
    
    # Summarize tool outputs, prune raw files
    # Archive evidence (keep reference, compress raw)
    # Archive logs (keep summary, prune detail)
    # Clear credentials
    # Mark target as archived in target-registry.md
    
    Write-Host "Target $Target archived." -ForegroundColor Green
}
```

---

## 7. Cleanup Procedures

### Automatic Cleanup Schedule

| Frequency | Action |
|-----------|--------|
| Every session start | Clear temp tokens |
| Every session end | Save and rotate credentials |
| Weekly | Prune tool outputs older than 30 days |
| Monthly | Archive inactive targets |
| Monthly | Prune killed evidence older than 30 days |
| Quarterly | Full storage audit and cleanup |

### Cleanup Rules

```
1. NEVER delete evidence for paid findings
2. NEVER delete findings archive entries
3. NEVER delete scope records
4. NEVER delete session index entries
5. NEVER delete config backups
6. ALWAYS archive before deleting
7. ALWAYS log cleanup in universal.md
8. ALWAYS verify after cleanup
```

### Cleanup Command

```powershell
function Invoke-JiggyCleanup {
    param([switch]$DryRun)
    
    Write-Host "Storage cleanup starting..." -ForegroundColor Cyan
    $today = Get-Date
    
    if ($DryRun) {
        Write-Host "DRY RUN — would clean:" -ForegroundColor Yellow
        # Check tool outputs older than 30 days
        # Check killed evidence older than 30 days
        # Check expired credentials
        # Check inactive targets
    } else {
        # Execute cleanup
        Write-Host "Cleaning up..." -ForegroundColor Green
        # Prune, archive, delete as per rules
        Write-Host "Cleanup complete." -ForegroundColor Green
    }
}
```

---

## 8. Cross-Session Handoff

When switching between sessions (same day, different tools or different days, same tool):

```
=== Session A → Session B ===

1. Session A ends normally:
   - All evidence saved to storage/
   - Findings updated in findings-archive.md
   - Session logged in hunt-logs.md
   - Session indexed in sessions-index.md
   - universal.md updated with latest state

2. Session B starts:
   - Loads storage index from universal.md
   - Checks findings-archive.md for submitted findings
   - Reviews evidence-packages.md for unsubmitted findings
   - Loads credentials-vault.md for test accounts
   - Continues from Session A's last state
```

If Session A was interrupted:

```
1. Session B detects interrupted session
2. Check hunt-logs.md for Session A's last heartbeat
3. Check evidence-packages.md for partial evidence
4. Check tool-outputs.md for any outputs generated
5. Resume from last known good state
```

---

## 9. Storage Limits and Safeguards

### File Size Limits

| File | Soft Limit | Hard Limit | Action at Limit |
|------|-----------|-----------|-----------------|
| evidence-packages.md | 5 MB | 10 MB | Archive old entries |
| findings-archive.md | 2 MB | 5 MB | Archive old entries |
| tool-outputs.md | 5 MB | 10 MB | Prune raw outputs |
| hunt-logs.md | 3 MB | 5 MB | Prune detailed logs |
| credentials-vault.md | 1 MB | 2 MB | Remove expired |

### Disk Space Warning
```powershell
# Check remaining space
$drive = (Get-PSDrive (Split-Path -Qualifier (Get-Location).Path)).Free
$freeGB = [math]::Round($drive / 1GB, 2)
if ($freeGB -lt 1) {
    Write-Host "WARNING: Less than 1GB free disk space. Run cleanup." -ForegroundColor Red
}
```

### Data Integrity Checks

```powershell
function Test-JiggyStorageIntegrity {
    $errors = @()
    
    # Check all files exist
    $required = @(
        "storage/universal.md",
        "storage/persistence.md", 
        "storage/credentials-vault.md",
        "storage/tool-outputs.md",
        "storage/hunt-logs.md",
        "storage/config-backups.md",
        "storage/evidence-packages.md",
        "storage/findings-archive.md",
        "storage/scope-records.md",
        "storage/sessions-index.md"
    )
    
    foreach ($file in $required) {
        if (-not (Test-Path $file)) {
            $errors += "MISSING: $file"
        }
    }
    
    # Check YAML frontmatter
    # Check cross-references
    # Check timestamps
    
    if ($errors.Count -eq 0) {
        Write-Host "Storage integrity: OK" -ForegroundColor Green
    } else {
        Write-Host "Storage integrity: $($errors.Count) issues" -ForegroundColor Yellow
        $errors | ForEach-Object { Write-Host "  $_" }
    }
}
```

---

## 10. Persistence Anti-Patterns (Storage-Specific)

| Anti-Pattern | Why It Fails | Fix |
|-------------|-------------|-----|
| Storing everything in one file forever | File becomes GB-sized, unsearchable | Archive regularly |
| Never archiving completed targets | Storage bloat, hard to find current data | Archive immediately on completion |
| Keeping raw screenshots in markdown | File bloat | Reference external files |
| No backup before major cleanup | Can't undo mistakes | Backup before every cleanup |
| Manual retention management | Forgotten until disk full | Use schedule and automation |
| Deleting instead of archiving | Lose data permanently | Archive first, delete after retention |
| Not rotating credentials | Account bans if reused too long | Rotate per target |
| Ignoring .gitignore for sensitive files | Credentials leaked to git | Check .gitignore before every commit |
| Storing evidence without cross-reference | Can't find what belongs to which finding | Use evidence IDs linked to findings |
| Keeping expired tokens | Security risk | Clear immediately after expiry |

---

## 11. Persistence Checklist

### Daily
```
[ ] Save all new evidence to evidence-packages.md
[ ] Update findings status if changed
[ ] Log session activity to hunt-logs.md
[ ] Update sessions-index.md with new session IDs
[ ] Backup if critical data was created today
```

### Weekly
```
[ ] Prune tool outputs > 30 days old
[ ] Archive any completed targets
[ ] Rotate credentials for active targets
[ ] Check disk space
[ ] Run storage integrity check
```

### Monthly
```
[ ] Full storage audit
[ ] Archive inactive targets
[ ] Prune killed evidence > 30 days
[ ] Backup entire storage directory
[ ] Review and update .gitignore
[ ] Clean up expired credentials
```

### Quarterly
```
[ ] Full backup of all memory + storage
[ ] Review archive for potential cleanup
[ ] Update retention policies if needed
[ ] Audit cross-references for consistency
[ ] Check for orphaned evidence
```
