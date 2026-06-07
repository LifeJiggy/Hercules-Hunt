# Tasks — Maintenance Tasks

System maintenance, tool updates, wordlist management, configuration
backups, and general upkeep tasks. Keeping the hunting environment in
top shape ensures efficient sessions and reliable evidence capture.

---

## Table of Contents

1. [Maintenance Overview](#1-maintenance-overview)
2. [Tool Updates](#2-tool-updates)
3. [Wordlist Management](#3-wordlist-management)
4. [Configuration Maintenance](#4-configuration-maintenance)
5. [Evidence Cleanup](#5-evidence-cleanup)
6. [Account Management](#6-account-management)
7. [Token Rotation](#7-token-rotation)
8. [Backup Verification](#8-backup-verification)
9. [System Health](#9-system-health)
10. [Learning Tasks](#10-learning-tasks)
11. [Maintenance History](#11-maintenance-history)
12. [Maintenance Templates](#12-maintenance-templates)
13. [Maintenance Schedule](#13-maintenance-schedule)

---

## 1. Maintenance Overview

### 1.1 Summary

```
TOTAL MAINTENANCE TASKS: [N]
  Completed: [N]
  Overdue: [N]
  Scheduled: [N]

LAST MAINTENANCE: YYYY-MM-DD
NEXT SCHEDULED: YYYY-MM-DD
SYSTEM HEALTH: [Good / Warning / Critical]

OVERDUE TASKS: [N]
  Critical: [N]
  Normal: [N]
```

### 1.2 Task ID Format

```
MAINT ID: MTASK-{category}-{YYMMDD}-{XXX}
  category: TOOL (tool updates), WORD (wordlists), 
            CONFIG (config), EVIDENCE (evidence cleanup),
            ACCT (accounts), TOKEN (token rotation),
            BACKUP (backup), HEALTH (system health),
            LEARN (learning)

Example: MTASK-TOOL-240607-001
```

---

## 2. Tool Updates

### 2.1 Tool Version Check

```
| Tool | Current Version | Latest Version | Update Needed |
|------|----------------|---------------|---------------|
| powershell-lib.ps1 | v2.3 | v2.3 | No |
| curl-hunter.ps1 | v2.1 | v2.2 | Yes |
| recon-toolkit.ps1 | v1.8 | v1.9 | Yes |
| fuzzer-toolkit.ps1 | v1.5 | v1.5 | No |
| js-analyzer.ps1 | v2.0 | v2.0 | No |
| python-hunter.py | v2.2 | v2.2 | No |
| evidence-toolkit.ps1 | v1.3 | v1.3 | No |
| jiggy.ps1 | v1.9 | v1.9 | No |
```

### 2.2 Tool Update Tasks

```
MTASK-TOOL-240607-001: Update curl-hunter.ps1 v2.1 -> v2.2
  Changes in v2.2:
    - Added SSRF IP bypass functions
    - Fixed rate limiting bug
    - Added new parameter fuzzing modes
    
  [ ] Review changelog
  [ ] Download/update file
  [ ] Test update
  [ ] Verify backward compatibility

MTASK-TOOL-240607-002: Update recon-toolkit.ps1 v1.8 -> v1.9
  Changes in v1.9:
    - Added Chaos API integration
    - Improved httpx output parsing
    - Added automated subdomain takeover detection

  [ ] Review changelog
  [ ] Download/update file
  [ ] Test update
  [ ] Verify recon pipeline works
```

### 2.3 Externally Installed Tools

```
TOOLS REQUIRING SEPARATE INSTALLATION:
  [ ] subfinder — Check version, update via go install
  [ ] httpx — Check version, update via go install
  [ ] dnsx — Check version, update via go install
  [ ] katana — Check version, update via go install
  [ ] ffuf — Check version, download latest binary
  [ ] waybackurls — Check version, go install
  [ ] gau — Check version, go install
  [ ] naabu — Check version, go install (optional)
  [ ] amass — Check version, go install (optional)
  [ ] Burp Suite — Check for updates, download JAR
  [ ] Python packages — pip list --outdated
  [ ] Node tools — npm outdated (if used)
```

### 2.4 Tool Update Log

```
| Date | Tool | From | To | Status |
|------|------|------|-----|--------|
| 2026-06-07 | curl-hunter.ps1 | v2.1 | v2.2 | Complete |
| 2026-06-05 | recon-toolkit.ps1 | v1.7 | v1.8 | Complete |
| 2026-06-01 | python-hunter.py | v2.0 | v2.2 | Complete |
```

---

## 3. Wordlist Management

### 3.1 Wordlist Inventory

```
| Wordlist | Entries | Last Updated | Source | Status |
|----------|---------|-------------|--------|--------|
| wordlists/common.txt | 5,000 | 2026-06-01 | SecLists | Active |
| wordlists/api.txt | 1,500 | 2026-06-01 | Custom | Active |
| wordlists/admin.txt | 2,000 | 2026-06-01 | SecLists | Active |
| wordlists/params.txt | 500 | 2026-06-01 | Custom | Active |
| wordlists/s3-bucket-names.txt | 1,000 | 2026-06-01 | Custom | Active |
| wordlists/ssrf-payloads.txt | 100 | 2026-06-01 | Custom | Active |
| wordlists/jwt-secrets.txt | 500 | 2026-06-01 | Custom | Active |
| wordlists/idor-ids.txt | 10,000 | 2026-06-01 | Generated | Active |
| wordlists/subdomains-top.txt | 100,000 | 2026-06-01 | SecLists | Active (git LFS) |
```

### 3.2 Wordlist Tasks

```
MTASK-WORD-240607-001: Update common.txt wordlist
  [ ] Fetch latest SecLists
  [ ] Merge with custom entries
  [ ] Deduplicate
  [ ] Test with ffuf against test target

MTASK-WORD-240607-002: Create new API wordlist
  [ ] Extract endpoints from recent JS bundles
  [ ] Add common framework paths
  [ ] Sort and deduplicate
  [ ] Validate format
```

### 3.3 Custom Wordlist Creation

```powershell
# Extract endpoints from discovered URLs
Get-Content urls-total.txt | 
  ForEach-Object { 
    $uri = [System.Uri]$_ 
    $uri.AbsolutePath 
  } | 
  Sort-Object -Unique > wordlists/custom-api-endpoints.txt

# Generate IDOR ID ranges
1..10000 | ForEach-Object { $_ } > wordlists/idor-ids.txt

# Generate user IDs (UUID-like)
for ($i = 1; $i -le 1000; $i++) {
    [guid]::NewGuid().ToString()
} > wordlists/uuid-list.txt
```

---

## 4. Configuration Maintenance

### 4.1 Configuration Tasks

```
MTASK-CONFIG-240607-001: Update Burp Suite configuration
  [ ] Export current Burp config
  [ ] Review scope settings (any new OOS?)
  [ ] Update macros if login flow changed
  [ ] Update session handling rules
  [ ] Save updated config backup

MTASK-CONFIG-240607-002: Update environment variables
  [ ] Check all required vars are set
  [ ] Update expired tokens
  [ ] Add new vars if needed
  [ ] Test environment validation script
```

### 4.2 Configuration Review Schedule

```
DAILY:
  [ ] Session configuration (scope, accounts)
  [ ] Token verification (test before session)

WEEKLY:
  [ ] Burp Suite configuration review
  [ ] Script configuration review
  [ ] Environment variable check

MONTHLY:
  [ ] Full configuration audit
  [ ] Remove stale configurations
  [ ] Update default parameters
  [ ] Test configuration restore from backup
```

### 4.3 Configuration Backup Rotation

```
KEEP LAST: 5 backups
DELETE OLDER THAN: 30 days

CURRENT BACKUPS:
  V20260607 — 2026-06-07 — 12.5MB
  V20260606 — 2026-06-06 — 11.8MB
  V20260605 — 2026-06-05 — 11.2MB
  V20260604 — 2026-06-04 — 10.5MB
  V20260603 — 2026-06-03 — 10.1MB

NEXT ROTATION: V20260530 (delete if > 30 days)
```

---

## 5. Evidence Cleanup

### 5.1 Evidence Cleanup Tasks

```
MTASK-EVID-240607-001: Clean up old evidence packages
  [ ] Archive resolved findings
  [ ] Delete draft screenshots (failed captures)
  [ ] Remove unused HAR files
  [ ] Compress large evidence directories

EVIDENCE FOLDERS:
  evidence/PKG-20260607-001/ — Active (keep)
  evidence/PKG-20260606-001/ — Submitted (keep)
  evidence/PKG-20260605-001/ — Submitted (keep)
  evidence/draft/ — Contains failed captures (DELETE)
```

### 5.2 Evidence Size Management

```
EVIDENCE STORAGE:
  Total: [N] MB
  Active: [N] MB
  Archived: [N] MB
  Draft (delete): [N] MB

TARGET BUDGET: 500MB
CURRENT: [N] MB
REMAINING: [N] MB

LARGEST PACKAGES:
  PKG-20260605-001 (SSRF): 45MB (many screenshots)
  PKG-20260606-001 (IDOR): 28MB
  PKG-20260607-001 (SSRF): 12MB
```

### 5.3 Cleanup Schedule

```
DAILY:
  [ ] Clear temp directory
  [ ] Remove duplicate screenshots

WEEKLY:
  [ ] Review evidence directories
  [ ] Delete drafts and failed captures
  [ ] Compress large packages (>20MB)

MONTHLY:
  [ ] Archive submitted packages
  [ ] Delete evidence older than 90 days
  [ ] Update storage usage statistics
```

---

## 6. Account Management

### 6.1 Account Inventory

```
| Account | Type | Service | Status | Created | Last Used |
|---------|------|---------|--------|---------|-----------|
| attacker+1@test.com | Attacker | example.com | Active | 2026-06-02 | 2026-06-07 |
| victim+1@test.com | Victim | example.com | Active | 2026-06-02 | 2026-06-07 |
| admin+1@test.com | Admin | example.com | Active | 2026-06-02 | 2026-06-05 |
| attacker@testcorp.com | Attacker | test.com | Active | 2026-06-04 | 2026-06-04 |
```

### 6.2 Account Tasks

```
MTASK-ACCT-240607-001: Rotate all test account passwords
  [ ] attacker+1@test.com — Password changed
  [ ] victim+1@test.com — Password changed
  [ ] admin+1@test.com — Password changed
  [ ] Verify all accounts still work
  [ ] Update stored tokens

MTASK-ACCT-240607-002: Create new test accounts for next target
  [ ] Register attacker account
  [ ] Register victim account
  [ ] Register admin account (if applicable)
  [ ] Verify email verification links
  [ ] Save account credentials
```

### 6.3 Account Wellness

```
ACCOUNT HEALTH:
  attacker+1@test.com: OK — token valid until 2026-06-08
  victim+1@test.com: OK — token valid until 2026-06-08
  admin+1@test.com: OK — last verified 2026-06-05

EXPIRING SOON:
  attacker+1@test.com — Token expires 2026-06-08 (1 day)
  victim+1@test.com — Token expires 2026-06-08 (1 day)
```

---

## 7. Token Rotation

### 7.1 Token Inventory

```
| Token | Service | Expires | Rotated | Status |
|-------|---------|---------|---------|--------|
| ATTACKER_TOKEN | example.com | 2026-06-08 | 2026-06-07 | Active |
| VICTIM_TOKEN | example.com | 2026-06-08 | 2026-06-07 | Active |
| ADMIN_TOKEN | example.com | 2026-06-07 | — | Expired (rotate) |
| BURP_COLLAB | Burp Suite | — | 2026-06-07 | Active |
| INTERACTSH | interact.sh | — | 2026-06-07 | Active |
```

### 7.2 Token Rotation Tasks

```
MTASK-TOKEN-240607-001: Rotate expired tokens
  [ ] Login to admin+1@test.com (example.com)
  [ ] Extract new JWT token
  [ ] Update environment variable
  [ ] Verify token works

MTASK-TOKEN-240607-002: Generate new Burp Collaborator URL
  [ ] Start new Burp project
  [ ] Copy collaborator URL
  [ ] Update in session context
```

### 7.3 Token Security

```
TOKEN BEST PRACTICES:
  [x] Tokens stored in environment variables (not in files)
  [x] Tokens never committed to git
  [x] .env.local in .gitignore
  [x] Tokens rotated before expiry
  [ ] Test accounts have unique passwords
  [ ] Test accounts use email aliases (not personal)

ROTATION POLICY:
  - Rotate before expiry (24h JWT = rotate daily)
  - Rotate immediately if token is exposed
  - Rotate after each session for long-lived tokens
  - Burp Collaborator: new URL for each session
  - interact.sh: new URL for each session
```

---

## 8. Backup Verification

### 8.1 Backup Tasks

```
MTASK-BACKUP-240607-001: Verify all backups
  [ ] Check backup files exist
  [ ] Verify file sizes match expected
  [ ] Test restore one configuration file
  [ ] Test restore Burp config
  [ ] Verify backup dates are current

MTASK-BACKUP-240607-002: Create full system backup
  [ ] Export Burp settings
  [ ] Save Burp project file
  [ ] Back up tool configurations
  [ ] Back up environment template
  [ ] Back up wordlists (skip if git LFS)
  [ ] Back up all evidence
  [ ] Record backup in config-backups.md
```

### 8.2 Backup Health Check

```
BACKUP HEALTH:
  config-backups/: [OK / FAILED]
  Burp projects/: [OK / FAILED]
  evidence/: [OK / FAILED]
  .env.local: [OK / FAILED]

LAST BACKUP: 2026-06-07 15:00
BACKUP SIZE: 12.5MB
BACKUP LOCATION: storage/config-backups/

NEXT BACKUP: 2026-06-08
```

---

## 9. System Health

### 9.1 System Check Tasks

```
MTASK-HEALTH-240607-001: Full system health check
  TOOLS:
    [x] PowerShell 5.1 available
    [x] Python 3 available
    [x] curl available
    [x] Burp Suite available
    [x] jq available
    [x] git available

  NETWORK:
    [x] Internet connectivity
    [x] Target reachable (example.com)
    [x] Proxy: 127.0.0.1:8080 (Burp)
    [x] Collaborator callback works
    [x] interact.sh reachable

  STORAGE:
    [x] Disk space: [N] GB free
    [x] Evidence directory exists
    [x] Output directory writable
    [x] Temp directory clean

  ACCOUNTS:
    [x] Attacker token valid
    [x] Victim token valid
    [x] Admin token valid (if needed)

  GIT:
    [x] Working tree clean
    [x] No unstaged changes
    [x] On branch: main
    [x] Up to date with origin
```

### 9.2 System Requirements

```
MINIMUM REQUIREMENTS:
  OS: Windows 10/11, macOS 12+, Linux (Ubuntu 20.04+)
  Shell: PowerShell 5.1+, or bash
  Python: 3.8+
  Memory: 8GB RAM (16GB recommended)
  Storage: 10GB free (50GB for full wordlists)
  Network: Broadband internet
  Proxy: Burp Suite running on 127.0.0.1:8080

RECOMMENDED:
  Memory: 16GB RAM
  Storage: 50GB+ free
  CPU: 4+ cores
  Monitor: 1920x1080 or higher
  Browser: Firefox + Chrome (both with hunt profiles)
```

### 9.3 Health Log

```
| Check | Result | Date | Notes |
|-------|--------|------|-------|
| Network connectivity | PASS | 2026-06-07 | All services reachable |
| Burp Suite | PASS | 2026-06-07 | v2025.x running on 8080 |
| Collaborator | PASS | 2026-06-07 | Callbacks received |
| Attacker token | PASS | 2026-06-07 | Valid until 2026-06-08 |
| Victim token | PASS | 2026-06-07 | Valid until 2026-06-08 |
| Admin token | FAIL | 2026-06-07 | Expired, needs rotation |
| Disk space | PASS | 2026-06-07 | 50GB free |
| Git status | PASS | 2026-06-07 | Clean |
```

---

## 10. Learning Tasks

### 10.1 Learning Task List

```
MTASK-LEARN-240607-001: Study GraphQL hunting methodology
  TOPICS:
    [ ] Introspection queries
    [ ] Batching attacks
    [ ] Rate limit bypass via batching
    [ ] IDOR in nested queries
    [ ] Depth-based DoS
  RESOURCES:
    - "GraphQL Hacking Methodology" (skill)
  TIMEBOX: 1 hour (evening)

MTASK-LEARN-240607-002: Study disclosed SSRF reports
  TOPICS:
    [ ] Read 5 disclosed H1 SSRF reports
    [ ] Note testing techniques
    [ ] Note bypass methods
    [ ] Note impact descriptions
    [ ] Note payout amounts
  RESOURCES:
    - HackerOne disclosed reports
  TIMEBOX: 1 hour (evening)

MTASK-LEARN-240607-003: Review new JWT attack techniques
  TOPICS:
    [ ] JWK injection (beyond alg:none)
    [ ] Key confusion attacks
    [ ] JWT header injection
    [ ] Cross-service token confusion
  RESOURCES:
    - Recent security research
    - portswigger Research
  TIMEBOX: 30 min
```

### 10.2 Skill Development Tracking

```
SKILLS TO DEVELOP:
  [ ] GraphQL security testing
  [ ] Advanced JWT attacks (beyond alg:none)
  [ ] Race condition testing with Turbo Intruder
  [ ] SAML attacks
  [ ] OAuth 2.0 deep security
  [ ] HTTP request smuggling
  [ ] Cache poisoning / web cache deception
  [ ] XXE (advanced)
  [ ] Server-side template injection
  [ ] Deserialization attacks
  [ ] API security (mass assignment, prototype pollution)
```

### 10.3 Learning Log

```
| Date | Topic | Duration | Notes |
|------|-------|----------|-------|
| 2026-06-05 | JWT alg:none | 30 min | Confirmed on example.com |
| 2026-06-04 | SSRF bypass techniques | 45 min | Tested hex/decimal/DNS bypass |
| 2026-06-03 | IDOR methodology | 30 min | Reviewed 5 disclosed reports |
| 2026-06-02 | XSS non-self validation | 20 min | How to confirm non-self XSS |
```

---

## 11. Maintenance History

### 11.1 Recent Maintenance

```
| Date | Task | Category | Completed | Notes |
|------|------|----------|-----------|-------|
| 2026-06-07 | Tool updates | TOOL | Yes | curl-hunter v2.2 |
| 2026-06-07 | Token rotation | TOKEN | Yes | Admin token fixed |
| 2026-06-06 | Backup verification | BACKUP | Yes | All OK |
| 2026-06-05 | System health check | HEALTH | Yes | All passed |
| 2026-06-04 | Wordlist update | WORD | Yes | Added API endpoints |
| 2026-06-03 | Evidence cleanup | EVID | Yes | Deleted drafts |
```

### 11.2 Overdue Maintenance

```
| Task | Category | Due | Overdue |
|------|----------|-----|---------|
| Python package update | TOOL | 2026-06-01 | 6 days |
| Full system backup | BACKUP | 2026-06-05 | 2 days |
| Wordlist deduplication | WORD | 2026-06-03 | 4 days |
```

---

## 12. Maintenance Templates

### 12.1 Tool Update Template

```
=== TOOL UPDATE ===
Tool: [tool name]
Current version: [vX.X]
New version: [vX.X]
Changelog:
  - [change 1]
  - [change 2]

Steps:
[ ] Download/update tool
[ ] Verify version
[ ] Test basic functionality
[ ] Test integration with other tools
[ ] Update version in tool inventory

Status: [Pending / In Progress / Complete]
```

### 12.2 System Health Template

```
=== SYSTEM HEALTH CHECK ===
Date: YYYY-MM-DD

PowerShell:     [OK / FAIL] — [version]
Python:         [OK / FAIL] — [version]
curl:           [OK / FAIL] — [version]
Burp Suite:     [OK / FAIL] — [version]
git:            [OK / FAIL] — [version]

Network:        [OK / FAIL]
Proxy (8080):   [OK / FAIL]
Collaborator:   [OK / FAIL]
Target:         [OK / FAIL]

Disk Space:     [N] GB free
Memory:         [N] GB free
CPU:            [N]% idle

Accounts:
  Attacker:     [OK / FAIL]
  Victim:       [OK / FAIL]
  Admin:        [OK / FAIL]

Git:            [Clean / Dirty]
```

---

## 13. Maintenance Schedule

### 13.1 Daily Tasks

```
[ ] Verify test accounts and tokens
[ ] Check Burp Suite is running
[ ] Verify target is reachable
[ ] Quick system health check
[ ] Start session logging
```

### 13.2 Weekly Tasks

```
[ ] Tool updates and version checks
[ ] Wordlist updates (merge new endpoints)
[ ] Evidence directory cleanup
[ ] Configuration review
[ ] Backup verification
[ ] Account wellness check
[ ] Learning task (1 hour)
```

### 13.3 Monthly Tasks

```
[ ] Full system health check
[ ] Complete tool update cycle
[ ] Full wordlist audit
[ ] Evidence archive and cleanup
[ ] Full backup and restore test
[ ] Token rotation for all accounts
[ ] Configuration audit
[ ] Skill development review
[ ] Review maintenance statistics
```

### 13.4 Quarterly Tasks

```
[ ] Full tool replacement audit
[ ] Wordlist overhaul (recreate from scratch)
[ ] Archive old evidence packages
[ ] Full system restore test
[ ] Review and update all templates
[ ] Update methodology based on new research
[ ] Review and update all documentation
```

---

*End of maintenance-tasks.md*
