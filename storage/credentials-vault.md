---
name: storage-credentials-vault
description: Test account and credential management vault for Jiggy-2026. Stores test accounts, session tokens, API keys, and access credentials for all bug bounty targets. Includes account provisioning workflows, rotation policies, token hygiene, and scope restrictions.
---

# Credentials Vault

This file manages all test accounts, session tokens, API keys, and access credentials used across bug bounty targets. NEVER commit this file to any git repository. ALWAYS rotate credentials between targets. ALWAYS restore test accounts after use.

---

## 1. Credential Management Principles

1. **One target, one account set** — never reuse test accounts across programs
2. **Rotate per target** — new accounts for each new target, clear after completion
3. **Session tokens are ephemeral** — capture for current session, discard after
4. **Restore after testing** — reset account state to pre-test baseline
5. **Email aliases** — use platform aliases (e.g., Bugcrowdninja) for traceability
6. **Never commit** — this file must be in .gitignore
7. **Backup recovery emails** — know how to recover each account
8. **Rate limit aware** — don't trigger locks on shared account pools

---

## 2. Active Accounts by Target

### target.com (HackerOne)

```
=== Account 1: Attacker ===
Platform: HackerOne
Email: attacker+bounty@bugcrowdninja.com
Password: [GENERATED]
Role: Free user (default)
Created: 2026-03-10
Status: ACTIVE
Notes: Primary attack account, access to all public features

=== Account 2: Victim ===
Platform: HackerOne
Email: victim+bounty@bugcrowdninja.com
Password: [GENERATED]
Role: Premium user
Created: 2026-03-10
Status: ACTIVE
Notes: Has premium features, invoices, coupons. Used as victim in IDOR tests.

=== Account 3: Admin (Created via exploit) ===
Platform: HackerOne (via target.com)
Email: hacker@evil.com
Password: Pwned123!
Role: Admin
Created: 2026-03-15 (via auth bypass exploit)
Status: ACTIVE — test use only
Notes: Created via POST /api/admin/users without auth. Do not use for anything outside PoC.
Restore: Account must be deleted after testing confirmed.
```

### another-target.com (Bugcrowd)

```
=== Account 1: Attacker ===
Platform: Bugcrowd
Email: attacker+another@bugcrowdninja.com
Password: [GENERATED]
Role: Basic
Created: 2026-03-01
Status: ACTIVE
Notes: Standard test account
```

---

## 3. Session Token Storage

### Current Session Tokens

| Target | Account | Token Type | Token (Truncated) | Created | Expires | Status |
|--------|---------|-----------|-------------------|---------|---------|--------|
| target.com | attacker | JWT | eyJhbGciOi... | 2026-03-15 14:30 | 2026-03-15 16:30 | ACTIVE |
| target.com | attacker | Session Cookie | sess_abc123... | 2026-03-15 14:30 | 2026-03-22 14:30 | ACTIVE |
| target.com | victim | JWT | eyJhbGciOi... | 2026-03-15 14:35 | 2026-03-15 16:35 | ACTIVE |
| target.com | admin | JWT | eyJhbGciOi... | 2026-03-15 15:10 | 2026-03-15 17:10 | ACTIVE |

### Token Capture Format

```
=== target.com — attacker JWT ===
Captured: 2026-03-15 14:30
Method: POST /api/v2/auth/login
From: Login page (browser DevTools Network tab)

Header:
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyX2FiYzEyMyIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzEwNTEyMzQ1LCJleHAiOjE3MTA1MTU5NDV9.abc123signature

Payload:
{
  "sub": "user_abc123",
  "role": "user",
  "iat": 1710512345,
  "exp": 1710515945,
  "jti": "unique-token-id",
  "session": "sess_xyz789"
}
Signature Algorithm: HS256
Key ID: key-2026-01

=== target.com — attacker Session Cookie ===
Name: session
Value: sess_xyz789
Domain: .target.com
Path: /
HttpOnly: true
Secure: true
SameSite: Lax
Expires: 2026-03-22 14:30

=== target.com — admin JWT (via auth bypass) ===
Header:
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyX2FkbWluMTIzIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzEwNTE1NDUwLCJleHAiOjE3MTA1MTkwNTB9.signature

Payload:
{
  "sub": "user_admin123",
  "role": "admin",
  "iat": 1710515450,
  "exp": 1710519050,
  "jti": "unique-admin-token-id",
  "session": "sess_admin789"
}
```

### Token Usage Rules
1. Use tokens only for the current session
2. Never share tokens between users/sessions
3. Never include full tokens in written reports (redact all but first/last 4 chars)
4. Delete tokens from this file at session end
5. If a token is compromised (leaked to log, exposed in screenshot), rotate immediately

---

## 4. API Keys and Secrets

### Target API Keys

| Target | Service | Key Name | Key (Truncated) | Purpose | Status |
|--------|---------|----------|-----------------|---------|--------|
| target.com | Stripe (Test) | pk_test | pk_test_51abc... | Testing payment flows | ACTIVE |
| target.com | Google OAuth | Client ID | 123456-abc.apps.googleusercontent.com | Testing OAuth flows | ACTIVE |
| target.com | GitHub OAuth | Client ID | Iv1.abc123... | Testing OAuth flows | ACTIVE |

### Discovered Keys (From Recon)

| Source | Key Type | Key (Truncated) | Purpose | Action |
|--------|----------|-----------------|---------|--------|
| JS Bundle (main.js) | Stripe Publishable | pk_live_xxxxx | Payment processing | Monitor only (public key) |
| JS Bundle (main.js) | Sentry DSN | https://xxxxx@sentry.io/123456 | Error tracking | Test SSRF to Sentry? |
| JS Bundle (main.js) | LaunchDarkly | 5def789abc123 | Feature flags | Test feature flag manipulation |
| JS Bundle (admin.js) | Mixpanel | abc123def456 | Analytics | Informational only |
| JS Bundle (admin.js) | Intercom | xyz789 | Customer chat | Test chat injection |
| Source Map | Algolia | xxxxxx | Search | Test search API access |

### Key Usage Rules
1. Publishable keys are safe to use (Stripe pk_live, Google Client ID)
2. Secret keys should NEVER appear in JS bundles (if found, it's a finding)
3. Test API keys don't affect production — use freely
4. Production API keys that appear in bundles = immediate report
5. Never use discovered keys beyond PoC scope

---

## 5. Account Provisioning Workflow

### Creating a New Test Account

```
1. Determine required role/privilege level:
   - Free/basic: Any email registration
   - Premium/paid: May require payment method
   - Admin: Usually only via exploit (document this)

2. Create email alias:
   - HackerOne: test+bounty@hackerone.com
   - Bugcrowd: user+bounty@bugcrowdninja.com
   - Private program: Follow program's registration process

3. Generate password:
   - Minimum 16 characters
   - Mix of upper, lower, numbers, symbols
   - Example: [GENERATED] (stored in password manager)

4. Register account:
   - Use dedicated test email alias
   - Complete any email verification
   - Complete any onboarding steps
   - Note required permissions/features

5. Record in vault:
   - Email, password, role
   - Date created
   - Target and platform
   - Any special features or access
```

### Bulk Account Management

For targets requiring multiple accounts:

```
Account Pool: target.com
Purpose: Rate limit testing, parallel testing
Created: 2026-03-10

Pool:
  Account A: attacker+pool1@bugcrowdninja.com [GENERATED]
  Account B: attacker+pool2@bugcrowdninja.com [GENERATED]
  Account C: attacker+pool3@bugcrowdninja.com [GENERATED]
  Account D: attacker+pool4@bugcrowdninja.com [GENERATED]
  Account E: attacker+pool5@bugcrowdninja.com [GENERATED]

Status: 5/5 active
Notes: All basic accounts, no special features. Use for parallel requests.
```

---

## 6. Account State Tracking

Each test account has a state. After testing, the account should be restored to pre-test state.

### State Tracking Table

| Account | Target | Initial State | Current State | Needs Restore? | Restore Actions |
|---------|--------|--------------|---------------|----------------|-----------------|
| attacker@target.com | target.com | Fresh account, no invoices | Has 3 invoices, 1 support ticket | YES | Delete invoices, close tickets |
| victim@target.com | target.com | Premium, has 50 invoices | Invoice 2002 modified | YES | Restore invoice 2002 to original |
| admin@evil.com | target.com | Does not exist (created via exploit) | Admin account exists | YES | Delete admin account, remove user |
| attacker@another.com | another-target.com | Fresh account | No changes | NO | No changes made |

### Restore Checklist

```
For each modified account:
[ ] Revert any profile changes (name, bio, email, avatar)
[ ] Delete any created resources (invoices, tickets, orders)
[ ] Close any opened sessions (logout from all devices)
[ ] Verify account appears as it did before testing
[ ] If admin account was created via exploit → delete it
[ ] If data was modified → return to original state
[ ] Confirm no lingering permissions or access
```

---

## 7. Credential Rotation Policy

### When to Rotate

| Trigger | Action |
|---------|--------|
| Target completed | Close all accounts, delete tokens |
| Target changed scope | New accounts for new scope |
| Account locked/banned | Create replacement, document ban |
| Session token leaked | Rotate immediately |
| 30 days without use | Rotate or deactivate |
| Tool compromised | Rotate ALL accounts |

### Rotation Workflow

```
1. Create new accounts for the target
2. Verify new accounts work (login, access features)
3. Capture new session tokens
4. Update credentials-vault.md with new accounts
5. Mark old accounts as DEPRECATED
6. Log out of old accounts on all devices
7. After 7 days: delete old accounts
8. Update scope-records.md with new account info
```

---

## 8. Security Rules

### NEVER

```
[NEVER] Commit this file to any git repository
[NEVER] Include full tokens or passwords in bug reports
[NEVER] Share accounts with other researchers
[NEVER] Use production credentials for testing
[NEVER] Store credentials in cloud-synced unencrypted files
[NEVER] Use your personal accounts for testing
[NEVER] Leave sessions logged in on shared machines
[NEVER] Post screenshots with visible full tokens
[NEVER] Use accounts beyond scope of the target
[NEVER] Perform unauthorized actions with admin accounts
```

### ALWAYS

```
[ALWAYS] Generate unique passwords per account
[ALWAYS] Use email aliases per platform
[ALWAYS] Restore accounts after testing
[ALWAYS] Rotate credentials between targets
[ALWAYS] Clear tokens at session end
[ALWAYS] Verify scope before using any account
[ALWAYS] Use separate accounts for attacker and victim roles
[ALWAYS] Log account creation and all changes
[ALWAYS] Keep backup recovery info for critical accounts
[ALWAYS] Check .gitignore before any commit
```

---

## 9. Emergency Procedures

### Account Banned/Locked

```
1. [BANNED] — Test account is banned by target
2. Check reason: rate limit abuse, suspicious behavior, password wrong
3. If rate limit: wait for cooldown (usually 15 min — 1 hour)
4. If suspicious: change IP, change User-Agent, change behavior pattern
5. If password wrong: Use recovery email to reset
6. If permanently banned: Create new account, document ban
7. Update vault: mark old account as BANNED
```

### Credential Leak

```
1. [LEAK DETECTED] — Token or password exposed in screenshot/log/report
2. IMMEDIATELY: Log out of all sessions (rotate session)
3. If password was leaked: Change password immediately
4. If token was leaked: Wait for token expiry or force-rotate
5. If report was sent with leaked token: Contact triager (token already expired likely)
6. Document the leak in lessons-log.md
7. Update vault: invalidate the compromised credential
```

### Vault File Compromise

```
1. [VAULT LEAKED] — credentials-vault.md file exposed (git push, screenshot, etc.)
2. IMMEDIATELY: Reset passwords for ALL accounts in the vault
3. IMMEDIATELY: Invalidate ALL tokens in the vault
4. Close all active sessions
5. Recover accounts via recovery emails
6. If recovery emails compromised: Close accounts permanently
7. Add the vault to .gitignore (verify with git check-ignore)
8. Document in lessons-log.md — this should never happen
```

---

## 10. Account Index

### All Active Accounts

| # | Target | Email | Role | Created | Last Used | Status |
|---|--------|-------|------|---------|-----------|--------|
| 1 | target.com | attacker+bounty@bugcrowdninja.com | User | 2026-03-10 | 2026-03-15 | ACTIVE |
| 2 | target.com | victim+bounty@bugcrowdninja.com | Premium | 2026-03-10 | 2026-03-15 | ACTIVE |
| 3 | target.com | hacker@evil.com | Admin (exploit) | 2026-03-15 | 2026-03-15 | TO_DELETE |
| 4 | another-target.com | attacker+another@bugcrowdninja.com | Basic | 2026-03-01 | 2026-03-10 | ACTIVE |

### Deprecated Accounts

| # | Target | Email | Reason | Deprecated | Data? |
|---|--------|-------|--------|-----------|-------|
| — | — | — | — | — | — |

### Banned Accounts

| # | Target | Email | Reason | Date | Replacement |
|---|--------|-------|--------|------|-------------|
| — | — | — | — | — | — |

---

## 11. Password Policy

### For Generated Passwords
```
Length: 16+ characters
Complexity: Upper + Lower + Number + Symbol
Generation: Use password manager or Python secrets module
Storage: NEVER in plaintext, only in this vault (which is .gitignored)
```

### Python Password Generator
```python
import secrets
import string

def generate_password(length=20):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(chars) for _ in range(length))

# Example: dB!7kL@p9*Qw2#xY5&zA
```

---

## 12. Vault Maintenance

### Weekly Tasks
```
[ ] Verify all active accounts still work
[ ] Rotate tokens older than 24 hours
[ ] Check for banned/locked accounts
[ ] Update status of accounts in testing
[ ] Verify .gitignore excludes this file
```

### Monthly Tasks
```
[ ] Prune accounts for completed targets
[ ] Rotate passwords for long-lived accounts
[ ] Archive old account data
[ ] Restore any remaining test state
[ ] Full audit of all entries

---

## 13. Multi-Platform Account Mapping

Some targets have multiple authentication paths. Track which accounts work with which auth mechanisms.

| Target | Account | Email Auth | OAuth (Google) | OAuth (GitHub) | SSO/SAML | API Key | Notes |
|--------|---------|-----------|---------------|----------------|----------|---------|-------|
| target.com | attacker | ✓ | — | — | — | — | Standard login |
| target.com | victim | ✓ | ✓ | ✓ | — | — | All methods |
| — | — | — | — | — | — | — | — |

---

## 14. Account Feature Matrix

Track what features/permissions each test account has. This helps identify privilege escalation paths.

| Feature | attacker (user) | victim (premium) | admin (exploit) |
|---------|----------------|------------------|-----------------|
| Create invoices | ✓ | ✓ | ✓ |
| View own invoices | ✓ | ✓ | ✓ |
| View other's invoices | ✗ | ✗ | ✓ |
| Delete invoices | ✓ (own only) | ✓ (own only) | ✓ (any) |
| Create admin users | ✗ | ✗ | ✓ |
| Access admin panel | ✗ | ✗ | ✓ |
| Redeem coupons | ✓ (one per code) | ✓ (one per code) | ✓ (unlimited?) |
| Create support tickets | ✓ | ✓ | ✓ |
| Export data | ✗ | ✓ (CSV export) | ✓ (full export) |
| MFA | ✗ | ✗ | ✓ (can enable) |

---

## 15. Account Lifecycle Management

### Creation Date Tracking
| Account | Created | Age | Expiry Policy | Days Until Expiry |
|---------|---------|-----|---------------|-------------------|
| attacker@target.com | 2026-03-10 | 5 days | Target completion | N/A (delete on target done) |
| victim@target.com | 2026-03-10 | 5 days | Target completion | N/A |

### Usage Statistics
| Account | Sessions Used | Total Requests | Last Error | Status |
|---------|-------------|---------------|------------|--------|
| attacker@target.com | 3 | 450 | None | Healthy |
| victim@target.com | 2 | 120 | None | Healthy |

### Deletion Checklist
```
When deleting an account after target completion:
[ ] Log out of all sessions
[ ] Revoke all API keys/tokens
[ ] Remove any PII from the account (name, bio, avatar)
[ ] Delete any created resources (invoices, tickets, etc.)
[ ] Cancel any subscriptions or premium features
[ ] Unlink any third-party OAuth connections
[ ] Close the account via account settings
[ ] Verify account is no longer accessible
[ ] Update vault: mark as DELETED
[ ] Remove from active account pool
```

---

## 16. Security Incident Response for Credentials

### Credential-Related Incident Types

| Incident | Severity | Response Time | Actions |
|----------|----------|--------------|---------|
| Credential leaked in screenshot | Critical | Immediate | Rotate, re-capture screenshot |
| Credential pushed to git | Critical | Immediate | Rotate all, remove from git, .gitignore |
| Account banned by target | High | Within 1 hour | Create replacement, document reason |
| Token expired mid-session | Low | Immediate | Re-authenticate |
| Rate limit exceeded | Low | Wait for cooldown | Adjust timing |

### Git Push Prevention
```powershell
# Add to pre-commit hook
$vault = "storage/credentials-vault.md"
if (Test-Path $vault) {
    $diff = git diff --cached -- "$vault"
    if ($diff) {
        Write-Host "BLOCKED: credentials-vault.md is staged for commit!" -ForegroundColor Red
        Write-Host "Remove it from staging: git reset HEAD $vault" -ForegroundColor Yellow
        exit 1
    }
}
```

```
