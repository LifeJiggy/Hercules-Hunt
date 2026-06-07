# Storage — Configuration Backups

Central registry for backing up and restoring all tool configurations,
settings files, environment variables, and custom configurations used
during hunting sessions. Protects against data loss when tools are
reinstalled, machines are swapped, or configurations need rollback.

---

## Table of Contents

1. [Backup Overview](#1-backup-overview)
2. [Tool Configurations](#2-tool-configurations)
3. [Burp Suite Configs](#3-burp-suite-configs)
4. [Script Settings](#4-script-settings)
5. [Environment Files](#5-environment-files)
6. [Browser Profiles](#6-browser-profiles)
7. [Restore Procedures](#7-restore-procedures)
8. [Version History](#8-version-history)
9. [Maintenance](#9-maintenance)

---

## 1. Backup Overview

### 1.1 Summary

```
TOTAL BACKUPS: [N]
LAST BACKUP: YYYY-MM-DD HH:MM
TOTAL SIZE: [N] MB
BACKUP LOCATION: [path]

CONFIGURATIONS BACKED UP:
  [x] Burp Suite settings
  [x] Script configuration files
  [x] Environment variables
  [x] Browser profiles
  [ ] Python virtual environment (re-creatable)
  [ ] Wordlists (too large — git LFS)
  [x] Custom payload files
```

### 1.2 Backup Frequency

```
AUTOMATIC BACKUPS:
  Tool configs: On change
  Environment files: Daily
  Burp projects: After each session

MANUAL BACKUPS:
  Full system config: Weekly
  Burp extensions: Weekly
```

### 1.3 File Naming Convention

```
CONFIG BACKUP: config-{tool}-{date}-{version}.{ext}
  tool:   burp, curl, python, browser, env
  date:   YYYYMMDD
  version: 001, 002, etc.
  ext:    json, xml, txt, ps1, conf

Example: config-burp-20260607-001.json
```

---

## 2. Tool Configurations

### 2.1 Configuration File Index

```
| Tool | Config File | Last Backed Up | Version | Size |
|------|-------------|----------------|---------|------|
| Burp Suite | config-burp-20260607-001.json | 2026-06-07 | 001 | 2.3MB |
| curl-hunter | config-curl-20260606-001.ps1 | 2026-06-06 | 001 | 45KB |
| python-hunter | config-python-20260606-001.json | 2026-06-06 | 001 | 12KB |
| jiggy.ps1 | config-jiggy-20260605-001.json | 2026-06-05 | 001 | 8KB |
| fuzzer-toolkit | config-fuzzer-20260605-001.json | 2026-06-05 | 001 | 15KB |
| js-analyzer | config-js-20260605-001.ps1 | 2026-06-05 | 001 | 22KB |
| recon-toolkit | config-recon-20260605-001.json | 2026-06-05 | 001 | 18KB |
| evidence-toolkit | config-evidence-20260605-001.json | 2026-06-05 | 001 | 10KB |
```

### 2.2 Tool Configuration Details

#### Burp Suite Configuration

```
BACKUP: config-burp-20260607-001.json
SCOPE: Full Burp Suite settings
SIZE: 2.3MB
CONTENTS:
  - Project options (all tabs)
  - User options (all tabs)
  - Extensions installed and configured
  - Session handling rules
  - Scope configuration
  - Target scope (in-scope URLs)
  - Proxy listener config (port 8080)
  - TLS/SSL pass-through options
  - Match and replace rules
  - Macros and session handling
  - Collaborator configuration
  - Inspector display options
  - Repeater settings (follow redirects, update CL)
  - Intruder presets and payload sets
  - Scanner configuration
  - Live audit scope
  - Extensions list with BApp Store references

RESTORE INSTRUCTIONS:
  1. Burp Suite -> User Options -> Misc -> Load settings
  2. Select config-burp-YYYYMMDD-NNN.json
  3. Verify all configurations loaded correctly
  4. Check extensions reloaded
  5. Verify scope and proxy settings
```

#### curl-hunter Configuration

```
BACKUP: config-curl-20260606-001.ps1
SIZE: 45KB
CONTENTS:
  - Default headers
  - User agent strings
  - Proxy configuration
  - Target API endpoints
  - Authentication tokens (redacted)
  - Rate limiting defaults
  - Timeout values
  - Retry logic configuration
  - Output format preferences
  - Default output path
  - Wordlist path references
  - Custom function aliases
  - Imported module paths
```

#### python-hunter Configuration

```
BACKUP: config-python-20260606-001.json
SIZE: 12KB
CONTENTS:
  - Secret pattern definitions
  - API endpoint patterns
  - Rate limit settings
  - Proxy configuration
  - Output format
  - Color scheme
  - Default scan depth
  - Timeout values
  - Logging level
  - Excluded file patterns
  - Custom secret patterns
  - Bundle analysis options
```

### 2.3 Custom Payload Files

```
| File | Description | Size | Last Updated |
|------|-------------|------|--------------|
| payloads/ssrf-cloud.txt | Cloud metadata SSRF payloads | 5KB | 2026-06-05 |
| payloads/ssrf-internal.txt | Internal service SSRF payloads | 8KB | 2026-06-05 |
| payloads/jwt-attacks.txt | JWT attack payloads | 3KB | 2026-06-05 |
| payloads/xss-polyglots.txt | XSS polyglot payloads | 12KB | 2026-06-04 |
| payloads/sqli-time.txt | Time-based SQLi payloads | 6KB | 2026-06-03 |
| payloads/idor-id-list.txt | IDOR ID enumeration lists | 15KB | 2026-06-06 |
```

---

## 3. Burp Suite Configs

### 3.1 Burp Project Files

```
| File | Size | Last Session | Status |
|------|------|-------------|--------|
| projects/example-com-20260607.burp | 5.2MB | 2026-06-07 | Active |
| projects/example-com-20260606.burp | 3.8MB | 2026-06-06 | Archived |
| projects/example-com-20260605.burp | 4.1MB | 2026-06-05 | Archived |
| projects/test-com-20260604.burp | 2.0MB | 2026-06-04 | Archived |
```

### 3.2 Burp Extensions

```
| Extension | BApp Store | Version | Config Backup |
|-----------|-----------|---------|---------------|
| JSON Decoder | Yes | 1.3 | Bundled in config |
| HTTP Request Smuggler | Yes | 2.1 | Bundled in config |
| JS Miner | Yes | 1.0 | Bundled in config |
| Autorize | Yes | 1.5 | Bundled in config |
| Auth Matrix | Yes | 1.2 | Bundled in config |
| Turbo Intruder | Yes | 2.0 | Bundled in config |
| Collaborator Everywhere | Yes | 1.1 | Bundled in config |
| Backspace Password | Yes | 1.0 | Bundled in config |
| Active Scan++ | Yes | 1.1 | Bundled in config |
| Content Type Converter | Yes | 1.0 | Bundled in config |
| Custom Logger | Yes | 1.2 | Bundled in config |
| Decoder Improved | Yes | 1.0 | Bundled in config |
| Flow | Yes | 2.5 | Bundled in config |
| HTTP Headers | Yes | 1.0 | Bundled in config |
| InQL (GraphQL) | Yes | 2.0 | Bundled in config |
| JWT Editor | Yes | 1.0 | Bundled in config |
| Param Miner | Yes | 2.1 | Bundled in config |
| Req Smuggler | Yes | 1.0 | Bundled in config |
| SAML Raider | Yes | 1.1 | Bundled in config |
| Scan GraphQL | Yes | 1.0 | Bundled in config |
| Software Vulnerability Scanner | Yes | 1.0 | Bundled in config |
| Upload Scanner | Yes | 1.0 | Bundled in config |
```

### 3.3 Burp Scope Configuration

```
TARGET SCOPE:
  Include:
    ^https?://.*\.example\.com.*
    ^https?://example\.com.*
  Exclude:
    ^https?://.*\.blog\.example\.com.*
    ^https?://.*\.status\.example\.com.*

PROXY INTERCEPT:
  Intercept requests: On
  Intercept responses: Off
  Intercept based on scope: On (only in-scope)
  Intercept Client Requests: Enabled
  Intercept Server Responses: Disabled
```

### 3.4 Burp Macros

```
MACRO: Login (example.com)
  1. POST /api/auth/login
     Body: {"email":"%email%","password":"%password%"}
     Extract: From response header — Authorization: Bearer (.*)
  2. Update cookie jar from response

MACRO: Get CSRF Token
  1. GET /api/csrf-token
     Extract: From response body — "csrfToken":"(.*?)"
```

---

## 4. Script Settings

### 4.1 Script Configuration Details

#### powershell-lib Settings

```powershell
# Target configuration
$Global:DefaultTarget = "example.com"
$Global:DefaultProxy = "http://127.0.0.1:8080"
$Global:DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
$Global:RateLimitDelayMs = 200
$Global:RequestTimeoutSec = 30
$Global:OutputPath = ".\storage\output"

# Account configuration (test accounts only)
$Global:AttackerEmail = "attacker+1@example.com"
$Global:VictimEmail = "victim+1@example.com"
$Global:AdminEmail = "admin+1@example.com"

# API keys and tokens are stored in environment variables
# NOT in configuration files. Load via:
#   $token = $env:ATTACKER_TOKEN
#   $victimToken = $env:VICTIM_TOKEN
```

#### curl-hunter Settings

```powershell
# Default parameters
$DefaultHeaders = @{
    "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    "Accept" = "application/json"
    "Content-Type" = "application/json"
}

# Proxy (Burp Suite)
$ProxyUri = "http://127.0.0.1:8080"

# Rate limiting
$RequestsPerSecond = 3
$BurstMax = 10
$CooldownSeconds = 60

# Timeouts
$ConnectTimeoutSec = 10
$TotalTimeoutSec = 30
```

#### python-hunter Settings

```python
# config.json
{
    "proxy": {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"},
    "rate_limit": {"requests_per_second": 3, "burst": 10, "cooldown": 60},
    "timeout": {"connect": 10, "total": 30},
    "output": {"path": "./storage/output", "format": "json"},
    "scan": {"depth": 2, "exclude_patterns": [".min.js", ".map"]},
    "logging": {"level": "INFO", "file": "./storage/logs/hunter.log"}
}
```

### 4.2 Script Version History

```
| Script | Current Version | Last Updated | Update Description |
|--------|----------------|--------------|-------------------|
| powershell-lib.ps1 | v2.3 | 2026-06-05 | Added SSRF functions |
| curl-hunter.ps1 | v2.1 | 2026-06-04 | Added rate limiting |
| recon-toolkit.ps1 | v1.8 | 2026-06-03 | Added subfinder wrapper |
| fuzzer-toolkit.ps1 | v1.5 | 2026-06-02 | Added wordlist manager |
| js-analyzer.ps1 | v2.0 | 2026-06-01 | New secret patterns |
| python-hunter.py | v2.2 | 2026-06-05 | Bundle depth analysis |
| evidence-toolkit.ps1 | v1.3 | 2026-06-06 | HAR sanitization added |
| jiggy.ps1 | v1.9 | 2026-06-04 | New CLI shortcuts |
```

---

## 5. Environment Files

### 5.1 Environment Variable Backup

Environment variables containing secrets are NOT backed up in plaintext.
Instead, we store a template with placeholder values:

```powershell
# ===== TOOL ENVIRONMENT VARIABLES =====
# Copy this template and fill in your actual values
# Save as: .env.local (DO NOT COMMIT TO GIT)

# === Test Account Tokens ===
$env:ATTACKER_TOKEN="<your_attacker_jwt_token>"
$env:VICTIM_TOKEN="<your_victim_jwt_token>"
$env:ADMIN_TOKEN="<your_admin_jwt_token>"  # if applicable

# === API Keys (example only — use test/proxy) ===
$env:BURP_COLLABORATOR_URL="<your_burp_collab_url>"
$env:INTERACTSH_URL="<your_interactsh_url>"

# === Proxy Settings (Burp Suite default) ===
$env:HTTP_PROXY="http://127.0.0.1:8080"
$env:HTTPS_PROXY="http://127.0.0.1:8080"

# === Tool Settings ===
$env:HUNTER_TARGET="<target_domain>"
$env:HUNTER_OUTPUT=".\storage"

# === Optional ===
$env:CHAOS_API_KEY="<chaos_api_key>"  # for subdomain enumeration
$env:GITHUB_TOKEN="<github_token>"     # for GitHub recon
$env:SHODAN_API_KEY="<shodan_api_key>" # for Shodan recon
```

### 5.2 .env.local Template

```
# .env.local — Copy this to .env and fill in values
# NEVER commit .env or .env.local to git

ATTACKER_TOKEN=
VICTIM_TOKEN=
ADMIN_TOKEN=
BURP_COLLABORATOR_URL=
INTERACTSH_URL=
CHAOS_API_KEY=
GITHUB_TOKEN=
SHODAN_API_KEY=
```

### 5.3 Environment Validation Script

```powershell
# Test-Environment.ps1 — Run to verify all required env vars are set
function Test-Environment {
    $required = @('ATTACKER_TOKEN', 'BURP_COLLABORATOR_URL')
    $optional = @('VICTIM_TOKEN', 'ADMIN_TOKEN', 'INTERACTSH_URL',
                  'CHAOS_API_KEY', 'GITHUB_TOKEN', 'SHODAN_API_KEY')

    Write-Host "=== Environment Check ===" -ForegroundColor Cyan
    $allPresent = $true

    foreach ($var in $required) {
        if ([string]::IsNullOrEmpty($env:$var)) {
            Write-Host "[MISSING] $var" -ForegroundColor Red
            $allPresent = $false
        } else {
            Write-Host "[OK]      $var" -ForegroundColor Green
        }
    }

    foreach ($var in $optional) {
        if ([string]::IsNullOrEmpty($env:$var)) {
            Write-Host "[EMPTY]   $var (optional)" -ForegroundColor Yellow
        } else {
            Write-Host "[OK]      $var" -ForegroundColor Green
        }
    }

    if ($allPresent) {
        Write-Host "`nAll required variables present. Ready to hunt." -ForegroundColor Green
    } else {
        Write-Host "`nSome required variables are missing!" -ForegroundColor Red
    }
}
```

---

## 6. Browser Profiles

### 6.1 Profile Backups

```
| Browser | Profile | Last Backed Up | Size | Extensions |
|---------|---------|----------------|------|------------|
| Firefox | hunt-profile | 2026-06-07 | 45MB | FoxyProxy, Cookie Editor, Wappalyzer |
| Chrome | hunt-profile | 2026-06-07 | 52MB | Proxy SwitchyOmega, EditThisCookie |
```

### 6.2 Browser Extension List

```
FIREFOX HUNT PROFILE:
  - FoxyProxy Standard (proxy switching)
  - Cookie Quick Manager (cookie editing)
  - Wappalyzer (tech stack detection)
  - HackBar (quick request builder)
  - NoScript (JS toggle for testing)
  - User-Agent Switcher
  - Multi-Account Containers

CHROME HUNT PROFILE:
  - Proxy SwitchyOmega (proxy management)
  - EditThisCookie (cookie inspection)
  - Wappalyzer (tech stack)
  - Built-in DevTools
  - JSON Formatter
  - ClearUrls
```

### 6.3 Profile Restore Instructions

```
FIREFOX:
  1. Close Firefox
  2. Copy hunt-profile directory to:
     %APPDATA%\Mozilla\Firefox\Profiles\
  3. Edit profiles.ini to reference the profile
  4. Restart Firefox
  5. Verify extensions loaded and proxy configured

CHROME:
  1. Close Chrome
  2. Copy hunt-profile directory to:
     %LOCALAPPDATA%\Google\Chrome\User Data\
  3. Start Chrome with --profile-directory="hunt-profile"
  4. Verify extension and proxy configuration
```

---

## 7. Restore Procedures

### 7.1 Full Restore Checklist

```
FULL RESTORE FROM BACKUP:
  [ ] 1. Clone repository
  [ ] 2. Load Burp Suite settings from backup
  [ ] 3. Load Burp project file
  [ ] 4. Load script configuration files
  [ ] 5. Set environment variables from .env.local
  [ ] 6. Restore browser hunt profiles
  [ ] 7. Verify proxy is configured (127.0.0.1:8080)
  [ ] 8. Test authentication tokens
  [ ] 9. Verify tools load correctly
  [ ] 10. Run a test request through Burp
  [ ] 11. Verify collaborator callback works
  [ ] 12. Check scope configurations
```

### 7.2 Quick Restore

```
QUICK RESTORE (new machine in <5 min):
  1. Git clone
  2. git pull
  3. .\install.ps1
  4. Copy .env.local and fill in tokens
  5. . .\tools\powershell-lib.ps1
  6. Start Burp Suite
  7. Run Test-Environment
```

### 7.3 Rollback Procedure

When a config change breaks something:

```
ROLLBACK STEPS:
  1. Identify the broken change (git diff)
  2. Git revert the config change
  3. OR restore from storage/config-backups/
  4. Restart affected tools
  5. Test functionality
  6. Log the issue in lessons-log.md
```

---

## 8. Version History

### 8.1 Backup Versions

```
| Backup ID | Date | Tools | Size | Notes |
|-----------|------|-------|------|-------|
| V20260607 | 2026-06-07 | All tools | 12.5MB | Added SSRF payloads |
| V20260606 | 2026-06-06 | All tools | 11.8MB | Updated wordlists |
| V20260605 | 2026-06-05 | All tools | 11.2MB | JWT attack configs |
| V20260604 | 2026-06-04 | All tools | 10.5MB | Initial backup |
```

### 8.2 Changelog

```
V20260607 (2026-06-07):
  - Added SSRF IP bypass payloads (hex, octal, decimal, DNS)
  - Updated Burp scope configuration
  - Added new collaborator URLs
  - Updated environment template
  - Added HAR sanitization config

V20260606 (2026-06-06):
  - Updated wordlists for IDOR fuzzing
  - Added new Burp extension configs
  - Fixed proxy timeout settings
  - Added evidence-toolkit config
```

---

## 9. Maintenance

### 9.1 Backup Schedule

```
DAILY:
  [ ] Backup Burp project at end of session
  [ ] Save current configuration snapshots

WEEKLY:
  [ ] Full configuration backup
  [ ] Verify backup integrity (compare file sizes)
  [ ] Clean up old backups (keep last 5)

MONTHLY:
  [ ] Review configuration files for stale settings
  [ ] Update environment variable templates
  [ ] Test restore from backup
  [ ] Archive very old backups
```

### 9.2 Backup Health

```
LAST BACKUP: YYYY-MM-DD HH:MM
BACKUP INTEGRITY: [OK / FAILED]
TOTAL BACKUP SIZE: [N] MB
BACKUPS THIS MONTH: [N]
OLDEST BACKUP: [YYYY-MM-DD]

BACKUP LOCATIONS:
  Primary: storage/config-backups/
  Secondary: [external drive / cloud]
```

### 9.3 Security Notes

```
CONFIG BACKUP SECURITY:
  - Tokens and secrets are NEVER stored in config files
  - Secrets are loaded from environment variables (.env.local
    is in .gitignore and never committed)
  - Burp project files may contain request/response data with
    tokens — store securely
  - Browser profiles may contain cached credentials — store
    securely
  - Backup files should be encrypted when stored off-device
```

---

*End of config-backups.md*
