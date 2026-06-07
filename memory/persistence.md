---
name: memory-persistence
description: Session persistence and state management for Hercules-Hunt memory. Defines how hunt state survives between sessions, across tool restarts, and between different AI coding CLIs. Covers save/restore protocols, conflict resolution, data retention, garbage collection, backup/recovery, and cross-platform persistence strategies.
---

# Memory Persistence

This file defines how Hercules-Hunt memory persists between sessions. Without persistence, every session starts from zero — no target knowledge, no findings, no lessons. This file is the rulebook for keeping memory alive across time, tools, and platforms.

---

## 1. Persistence Architecture

```
Session A (Tool X)
   │
   ├── Writes to memory/*.md
   ├── Writes to storage/*.md  
   └── Updates universal.md index
          │
          ▼
   [Filesystem — persistent storage]
          │
          ▼
Session B (Tool Y — next day)
   │
   ├── Reads memory/*.md
   ├── Reads universal.md for state
   └── Continues from where A stopped
```

### Key Principle

Memory files ARE the persistence layer. There is no separate database, no hidden state, no binary cache. Everything that matters lives in plain markdown files in `memory/` and `storage/`. If the files exist, the state exists. If they don't, the state is lost.

---

## 2. What Persists Between Sessions

### Persists (Always)

| Data | File | Why |
|------|------|-----|
| Target registry | memory/target-registry.md | Never lose target metadata |
| Lessons learned | memory/lessons-log.md | Cross-hunt knowledge accumulation |
| Technical notes | memory/technical-notes.md | Deep research that stays relevant |
| Discoveries/leads | memory/discoveries.md | Unfinished business follows you |
| Submitted findings | storage/findings-archive.md | Proof of work and outcomes |
| Scope records | storage/scope-records.md | Scope verification is permanent |
| Evidence packages | storage/evidence-packages.md | Evidence must survive for appeals |
| Credentials vault | storage/credentials-vault.md | Test accounts are reusable |
| Config backups | storage/config-backups.md | Tool configs don't change per session |
| Universal index | memory/universal.md | Master index updates every session |

### Persists With Conditions

| Data | File | Condition |
|------|------|-----------|
| Session state | memory/session-state.md | Only if session was interrupted (not completed) |
| Tool outputs | storage/tool-outputs.md | Until next cleanup cycle |
| Hunt logs | storage/hunt-logs.md | Until next cleanup cycle |
| Active findings | memory/universal.md (§5) | Until submitted or killed |

### Does NOT Persist

| Data | Why |
|------|-----|
| HTTP response bodies in memory | Too large, stored in evidence packages |
| Temporary tool state | Rebuilt on tool load |
| Authentication tokens | Security — re-authenticate each session |
| Curl/Python REPL history | Session-specific |
| Terminal scrollback | Session-specific |
| Browser DevTools state | Session-specific |

---

## 3. Session Lifecycle

### Session Start

```
[START]
   │
   1. Load universal.md → restore master index
   2. Verify timestamps → check for stale state
   3. Load target-registry.md → restore target context
   4. Check session-state.md → detect interrupted session
   5. Load discoveries.md → restore active leads
   6. Load technical-notes.md → restore tech context
   7. Verify consistency → all files agree on current state
   8. Generate session ID → UUID v4
   9. Update universal.md → new session entry
  10. [READY]
```

### Session Heartbeat

Every 5 minutes (or after every significant action), write to persistence:

```
1. Update session-state.md with latest progress
2. Update universal.md with latest findings, leads, decisions
3. Save any new evidence to storage/evidence-packages.md
4. Log time spent to hunt-logs
5. Verify — files can be read back correctly
```

### Session End (Normal)

```
[END]
   │
   1. Write final state to session-state.md
   2. Update all leads in discoveries.md
   3. Commit any new technical notes
   4. Update target status in target-registry.md
   5. Update master index in universal.md
   6. Write final session summary
   7. [DONE]
```

### Session End (Interrupted — Crash / Timeout / Network Loss)

```
[INTERRUPTED]
   │
   1. On next session start → detect interrupted state
   2. Read session-state.md → find last heartbeat
   3. Identify gap between last heartbeat and interruption
   4. Prompt: "Session was interrupted at [time]. 
      Last known state: [phase] on [endpoint]. 
      Resume from last checkpoint? (Y/N)"
   5. If Y: reload from last heartbeat
   6. If N: mark session as abandoned, start fresh
```

### Session End (Force — User Kills Process)

```
[FORCE END]
   │
   1. If user kills process (Ctrl+C, taskkill):
      → Last heartbeat is recovery point
   2. On next start:
      → Detect incomplete session
      → Ask to resume or abandon
   3. No data loss if heartbeats were regular
```

---

## 4. Session ID Format

Every session gets a unique ID for tracking and correlation.

```
Format: JGY-YYYYMMDD-HHMMSS-XXXX
  JGY        = Jiggy prefix
  YYYYMMDD   = Date
  HHMMSS     = Time
  XXXX       = Random hex suffix

Example: JGY-20260315-143022-4a7f
```

### Session ID Usage

- Written to universal.md when session starts
- Appended to every hunt log entry
- Used as prefix for evidence filenames
- Stored in persistence.md for cross-reference
- Indexed in storage/sessions-index.md

---

## 5. Heartbeat Protocol

### When to Write a Heartbeat

| Trigger | Action |
|---------|--------|
| Every 5 minutes | Update session-state.md with current state |
| Every endpoint tested | Log to hunt-logs with result |
| Every finding validated | Update findings pipeline in universal.md |
| Every lead created | Update discoveries.md |
| Every decision made | Log to decision log in universal.md |
| Tool state change | Update tooling state |
| Phase change | Update phase in universal.md |

### Heartbeat Payload

```
Timestamp: 2026-03-15 14:30:22 UTC
Session: JGY-20260315-143022-4a7f
Phase: HUNT
Target: target.com
Current Endpoint: /api/v2/invoices/{id}
Action: Testing IDOR — invoice 1001 vs 2002 cross-account
Result: CONFIRMED — IDOR on GET /api/v2/invoices/{id}
Next Action: Test DELETE /api/v2/invoices/{id} for write IDOR
Time Budget Remaining: 15 min
```

---

## 6. Conflict Resolution

### Scenario: Two Sessions on Same Target

```
Session A writes to session-state.md at 14:30
Session B writes to session-state.md at 14:35 (same target, different focus)
```

**Resolution Protocol:**
1. Both sessions write to `session-state.md` — the section format supports parallel entries
2. Each entry is prefixed with its session ID
3. The `active-session` field in universal.md tracks which session is CURRENT
4. If both sessions claim current — flag for manual resolution
5. Manual resolution: user picks which session to continue

### Scenario: Conflicting Findings

```
Session A reports IDOR as HIGH severity
Session B reports same IDOR as MEDIUM severity
```

**Resolution Protocol:**
1. The finding appears once in the findings pipeline (deduplicated by endpoint + bug class)
2. Both severity assessments are recorded
3. The higher severity is used for the report (conservative for the hunter, aggressive for payout)
4. The CVSS is recalculated independently before submission

### Scenario: Stale State Detected

```
Last heartbeat: 7 days ago
Current time: new session starting
```

**Resolution Protocol:**
1. Flag as stale
2. Ask user: "Target was last active 7 days ago. Resume or archive?"
3. If resume: re-verify scope, re-probe live hosts, continue from last phase
4. If archive: move to archived targets in target-registry.md, clear session-state.md

---

## 7. Data Retention Policy

### Short-Term (Session → Session)

| Data | Retention | Cleanup |
|------|-----------|---------|
| Session state | 30 days or until next session | Cleared on session DONE |
| Tool outputs | 7 days | Cleanup on recon completion |
| Hunt logs | 30 days | Archive on target completion |
| Temporary credentials | End of session | Cleared on session END |

### Medium-Term (Target → Target)

| Data | Retention | Cleanup |
|------|-----------|---------|
| Discoveries/leads | Until resolved or archived | Archived with target |
| Technical notes | Permanent | Never cleaned |
| Evidence (unsubmitted) | 90 days | Archived with target |
| Active findings | Until submitted | Moved to findings archive |

### Long-Term (Permanent)

| Data | Retention | Cleanup |
|------|-----------|---------|
| Submitted findings | Permanent | Never cleaned |
| Lessons learned | Permanent | Never cleaned |
| Target registry | Permanent | Never cleaned |
| Scope records | Permanent | Never cleaned |
| Credentials vault | Until account invalidated | Never auto-cleaned |
| Config backups | Permanent | Never cleaned |

---

## 8. Backup and Recovery

### Automatic Backups

Every session start:
1. Check if `memory/` has been modified since last backup
2. If modified: create a backup of all memory files
3. Backup location: `storage/config-backups.md` (appended)
4. Backup format: timestamped snapshot

### Manual Backup

```powershell
function Backup-JiggyMemory {
    param([string]$TargetDir = ".\backups")
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backup = "$TargetDir\jiggy-memory-$stamp"
    Copy-Item -Path ".\memory\*" -Destination $backup -Recurse
    Write-Host "Memory backed up to $backup"
}
```

### Recovery Protocol

```
1. [RESTORE REQUESTED]
2. List available backups (from storage/config-backups.md)
3. User selects restore point
4. Copy backup files back to memory/
5. Verify — all files are consistent
6. Update universal.md: "Restored from backup [timestamp]"
7. [READY]
```

### Disaster Recovery

If memory files are corrupted or deleted:

```
1. STOP — all testing stops immediately
2. ASSESS — what is corrupted? What is recoverable?
3. RECOVER FROM BACKUP — restore closest backup
4. FILL GAPS — last session's discoveries may be lost
5. REBUILD — start from backup + any remaining artifacts in storage/
6. LESSON — write to lessons-log.md about the failure
7. PREVENT — increase backup frequency
```

---

## 9. Garbage Collection

### Automatic GC Triggers

| Trigger | Action |
|---------|--------|
| Target archived | Archive all associated memory |
| Finding submitted | Move from active to submitted |
| Lead resolved | Move from active to resolved |
| Session interrupted > 7 days | Flag for archive |
| Evidence older than 90 days | Flag for archive |

### GC Process

```
1. Scan memory/ for stale entries
2. Scan discoveries/ for unresolved leads > 30 days
3. Scan session-state/ for interrupted sessions > 7 days
4. Flag items for review
5. User approves or rejects each flag
6. Move approved items to archive
7. Update universal.md with GC summary
```

### Manual GC

```powershell
function Invoke-JiggyGC {
    param([switch]$DryRun)
    
    Write-Host "Scanning memory for stale entries..." -ForegroundColor Cyan
    
    # Check discoveries > 30 days
    $staleLeads = @()  # Logic to find stale leads
    
    # Check interrupted sessions > 7 days
    $staleSessions = @()  # Logic to find stale sessions
    
    if ($DryRun) {
        Write-Host "DRY RUN — would archive:" -ForegroundColor Yellow
        $staleLeads | ForEach-Object { Write-Host "  LEAD: $_" }
        $staleSessions | ForEach-Object { Write-Host "  SESSION: $_" }
    } else {
        # Archive flagged items
        Write-Host "Archiving stale items..." -ForegroundColor Green
        # Archive logic here
    }
}
```

---

## 10. Cross-Platform Persistence

### Windows
- Path: `%USERPROFILE%\.jiggy\memory\`
- PowerShell native access
- File locking: None needed (sequential writes)
- Backup: `Copy-Item` to `%USERPROFILE%\.jiggy\backups\`

### macOS / Linux
- Path: `~/.jiggy/memory/`
- Bash native access
- File locking: None needed
- Backup: `cp -r` to `~/.jiggy/backups/`

### Git-Based Persistence (Optional)
For advanced users: store `memory/` in a dedicated git repo.

```
1. cd jiggy-2026/memory
2. git init
3. git add .
4. git commit -m "Session JGY-20260315-143022 checkpoint"
5. git push  # to private repo
```

Benefits:
- Full version history of all memory
- Rollback to any point
- Sync between machines
- Branch for parallel hunts

### Cloud Sync (Optional)
For multi-machine setups: sync memory/ via Dropbox, Google Drive, or Syncthing.

**Warning:** Never sync credentials-vault.md or evidence with sensitive PII to unencrypted cloud storage.

---

## 11. File Locking Strategy

Since Hercules-Hunt runs in single-user, single-process mode, explicit file locking is not required. However, to prevent corruption:

### Write Protocol
1. Read current file content
2. Modify content in memory
3. Write entire file atomically
4. Verify write succeeded

### Read Protocol
1. Read file
2. Validate YAML frontmatter
3. Validate section structure
4. If corrupted → restore from backup

### Atomic Write (PowerShell)
```powershell
function Write-JiggyFile {
    param(
        [string]$Path,
        [string]$Content
    )
    $tempPath = "$Path.tmp"
    $Content | Out-File -FilePath $tempPath -Encoding UTF8
    Move-Item -Path $tempPath -Destination $Path -Force
}
```

---

## 12. Persistence Verification

### Self-Check Protocol

Run this at the start of every session:

```
1. [CHECK] Can all memory files be read?
2. [CHECK] Does universal.md have valid YAML frontmatter?
3. [CHECK] Do all discovered targets exist in target-registry.md?
4. [CHECK] Does session-state.md match universal.md's session section?
5. [CHECK] Are all submitted findings also in findings archive?
6. [CHECK] Is the current timestamp later than all session entries?
7. [CHECK] Is credentials-vault.md encrypted or in .gitignore?
8. [CHECK] Is there enough disk space for new evidence?
```

### Repair Protocol

If any check fails:

```
1. Identify which files are inconsistent
2. Determine which version is correct (by timestamp, content integrity)
3. Fix the incorrect file to match the correct version
4. Log the repair to lessons-log.md
5. Flag in universal.md: "Repair performed on [date] — [issue]"
```

---

## 13. Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `JIGGY_MEMORY_DIR` | Override memory directory | `./memory/` |
| `JIGGY_STORAGE_DIR` | Override storage directory | `./storage/` |
| `JIGGY_SESSION_TIMEOUT` | Session heartbeat interval (min) | `5` |
| `JIGGY_BACKUP_INTERVAL` | Backup frequency (min) | `60` |
| `JIGGY_GC_DAYS` | Stale data threshold (days) | `30` |
| `JIGGY_MAX_HEARTBEAT_GAP` | Max gap before flagging (min) | `15` |

---

## 14. Persistence Anti-Patterns

| Anti-Pattern | Why It Fails | Fix |
|-------------|-------------|-----|
| Writing state only at session end | Crash loses everything | Use heartbeats |
| Editing memory files directly while running | Race conditions | Follow write protocol |
| Storing binary data in memory files | Bloat | Use storage/ for binary |
| Infinite retention of tool outputs | Disk bloat | Run GC regularly |
| Manual backups only | Forgotten until disaster | Automate |
| No timestamps on entries | Can't order events | Always timestamp |
| Editing same file from two tools | Conflict | One session per target |
| Storing credentials in plaintext git | Leakage | .gitignore memory/ |
| Assuming persistence across machines | Sync issues | Use git or cloud sync |

---

## 15. Persistence Checklist

### Before Session End
```
[ ] All active findings documented in findings pipeline
[ ] All decisions logged with rationale
[ ] All time spent recorded
[ ] All evidence saved to storage/evidence-packages.md
[ ] Target status updated in target-registry.md
[ ] Lessons learned written to lessons-log.md
[ ] universal.md index updated with final state
[ ] Session ID recorded in persistence.md
[ ] Backup created if modified since last backup
[ ] Heartbeat written before final close
```

### Before Session Start (Resume)
```
[ ] Check for interrupted session
[ ] Verify last heartbeat timestamp
[ ] Confirm session ID matches
[ ] Run persistence self-check
[ ] Validate target scope still valid
[ ] Check for backup if corruption detected
[ ] Verify credentials vault accessible
[ ] Confirm storage/.gitignore is correct
[ ] Check disk space for new evidence
[ ] Read last entry in lessons-log.md
```
