# Storage — Scope Records

Tracking scope boundaries, safe harbor confirmations, program rules,
and authorized testing boundaries for all targets and programs.

---

## Table of Contents

1. [Scope Overview](#1-scope-overview)
2. [Active Programs](#2-active-programs)
3. [Scope Boundaries](#3-scope-boundaries)
4. [Safe Harbor Records](#4-safe-harbor-records)
5. [Out-of-Scope Tracking](#5-out-of-scope-tracking)
6. [Program Rules](#6-program-rules)
7. [Scope Violation Log](#7-scope-violation-log)
8. [Target Authorization](#8-target-authorization)
9. [Maintenance](#9-maintenance)

---

## 1. Scope Overview

### 1.1 Summary

```
ACTIVE PROGRAMS: [N]
  Public (HackerOne): [N]
  Public (Bugcrowd):  [N]
  Private:            [N]
  Invite-only:        [N]

TOTAL DOMAINS IN SCOPE: [N]
TOTAL DOMAINS OUT OF SCOPE: [N]
TARGETS ACTIVELY HUNTING: [N]

Safe Harbor Confirmed: [Yes / No — all programs]
Scope Documents Saved: [Yes / No]
Last Scope Review: [YYYY-MM-DD]
```

### 1.2 Active Targets

```
| Target | Program | Scope Type | In Scope | Out of Scope | Status |
|--------|---------|------------|----------|--------------|--------|
| *.example.com | HackerOne | Wildcard | All subdomains | *.blog.example.com | Active |
| api.test.com | Bugcrowd | Specific | api.test.com, app.test.com | *.dev.test.com | Active |
| app.other.com | Private | Agreement | Full application | Third-party services | Active |
```

---

## 2. Active Programs

### 2.1 Program Profile

#### HackerOne — Example Corp

```
PROGRAM:        Example Corp
PLATFORM:       HackerOne
PROGRAM TYPE:   Public
BOUNTY RANGE:   $500 — $5,000
SAFE HARBOR:    Yes
SCOPE POLICY:   Standard H1
POLICY URL:     https://hackerone.com/examplecorp

SCOPE:
  In Scope:
    *.example.com
    *.api.example.com
    *.app.example.com
  Out of Scope:
    *.blog.example.com
    *.status.example.com
    *.docs.example.com
    Third-party services

EXCLUDED BUG CLASSES:
  - Rate limiting issues
  - Self-XSS
  - Missing HTTP headers
  - Banner grabbing
  - Clickjacking (no sensitive action)
  - CSRF on logout

TESTING RESTRICTIONS:
  - No automated scanning without prior approval
  - No social engineering
  - No physical access attempts
  - No DoS/DDoS
  - Max 10 req/second (rate limit)
  - Only test accounts (no real user data)
```

#### Bugcrowd — Test Corp

```
PROGRAM:        Test Corp
PLATFORM:       Bugcrowd
PROGRAM TYPE:   Public
BOUNTY RANGE:   $250 — $2,500
SAFE HARBOR:    Yes
SCOPE POLICY:   VRT-based
POLICY URL:     https://bugcrowd.com/testcorp

SCOPE:
  In Scope:
    *.testcorp.com
    api.testcorp.com
  Out of Scope:
    *.dev.testcorp.com
    *.staging.testcorp.com
    *.admin.testcorp.com (requires approval)

EXCLUDED BUG CLASSES:
  - VRT informational only
  - Self-XSS
  - Missing CSP/Security headers
  - Rate limiting

TESTING RESTRICTIONS:
  - No scanning with aggressive tools
  - No automated SQLi testing
  - No phishing
  - Only test credentials
```

### 2.2 Program Comparison

```
| Criteria | HackerOne (Example) | Bugcrowd (Test) | Private (Other) |
|----------|--------------------|-----------------|-----------------|
| Payout Range | $500-$5,000 | $250-$2,500 | $1,000-$10,000 |
| Safe Harbor | Yes | Yes | Yes |
| SLA | 30 days | 14 days | 90 days |
| RT | 24h | 48h | 72h |
| Automated scan | Prohibited | Restricted | Allowed |
| Reporting interface | H1 | Bugcrowd | Direct email |
```

---

## 3. Scope Boundaries

### 3.1 Wildcard Scope Analysis

```
TARGET: *.example.com

WILDCARD COVERAGE:
  [x] *.example.com — all subdomains
  [x] example.com — apex domain
  [ ] *.blog.example.com — explicitly excluded

IMPLICATIONS:
  - Subdomain takeover: In scope for all *.example.com
    except *.blog.example.com
  - IDOR on api.example.com: In scope
  - XSS on blog.example.com: Out of scope
  - SSRF from app to blog: In scope if originating from
    in-scope asset

CONFIRMED SUBDOMAINS:
  In scope:
    app.example.com
    api.example.com
    admin.example.com
    cdn.example.com
    www.example.com
    mail.example.com
    static.example.com
  Out of scope:
    blog.example.com
    status.example.com
    docs.example.com
  Unknown (verify):
    dev.example.com
    staging.example.com
    test.example.com
```

### 3.2 Specific Domain Scope

```
TARGET: api.test.com

SCOPE: Specific domains only
  In scope:
    api.test.com
    app.test.com
    login.test.com
  Not mentioned:
    www.test.com (treat as out of scope unless confirmed)
    admin.test.com (treat as out of scope unless confirmed)
    cdn.test.com (treat as out of scope unless confirmed)
```

### 3.3 Scope Verification Checklist

```
BEFORE TESTING ANY TARGET:
  [ ] 1. Read the full program scope policy
  [ ] 2. Check for scope changes since last session
  [ ] 3. Verify each subdomain against in-scope list
  [ ] 4. Note any testing restrictions (rate limits, automation)
  [ ] 5. Confirm safe harbor is stated in policy
  [ ] 6. Check for excluded bug classes
  [ ] 7. Review disclosure/preference terms
  [ ] 8. Save a copy of the scope policy
  [ ] 9. Check for special instructions (PII handling, etc.)
  [ ] 10. Document scope boundaries in target-registry
```

---

## 4. Safe Harbor Records

### 4.1 Safe Harbor Confirmations

```
PROGRAM: HackerOne — Example Corp
  Safe Harbor: Yes
  Confirmed in policy: Yes
  Policy clause:
    "Researchers who comply with our policy are protected by
    our safe harbor terms. We will not pursue legal action
    against researchers who make good-faith efforts to comply
    with our policy."
  Last verified: 2026-06-01

PROGRAM: Bugcrowd — Test Corp
  Safe Harbor: Yes
  Confirmed in policy: Yes
  Policy clause:
    "Bugcrowd provides safe harbor to researchers who comply
    with the VRP scope and testing guidelines."
  Last verified: 2026-06-01
```

### 4.2 Safe Harbor Checklist

```
BEFORE SUBMITTING ANY FINDING:
  [ ] 1. Finding is within scope
  [ ] 2. Testing was within defined boundaries
  [ ] 3. No automated scanning (if prohibited)
  [ ] 4. Only test accounts used
  [ ] 5. No real user data accessed
  [ ] 6. Data was not modified/deleted (read-only for sensitive)
  [ ] 7. No social engineering performed
  [ ] 8. Proof of concept is minimal (demonstrates, does not exploit)
  [ ] 9. All evidence sanitized (no PII, no tokens)
  [ ] 10. Report filed through official channel
```

### 4.3 Safe Harbor Protection Limits

Safe harbor does NOT protect against:

```
1. Testing outside scope boundaries
2. Automated scanning (when prohibited)
3. Social engineering / phishing
4. Physical security testing
5. DoS / DDoS attacks
6. Data exfiltration beyond PoC minimum
7. Public disclosure before program resolves
8. Violation of applicable laws
9. Testing third-party services without their authorization
10. Accessing real user data (use test accounts only)
```

---

## 5. Out-of-Scope Tracking

### 5.1 Out-of-Scope Assets

```
| Asset | Program | Reason OOS | Discovered | Action |
|-------|---------|------------|------------|--------|
| blog.example.com | HackerOne | Explicitly excluded | 2026-06-02 | Skipped |
| *.dev.example.com | HackerOne | Assumed OOS | 2026-06-02 | Confirm with program |
| status.test.com | Bugcrowd | Not listed in scope | 2026-06-03 | Skipped |
| admin.other.com | Private | Requires approval | 2026-06-04 | Requesting approval |
```

### 5.2 Assets Requiring Authorization

```
| Asset | Program | Required Authorization | Contact | Status |
|-------|---------|----------------------|---------|--------|
| admin.example.com | HackerOne | None (in wildcard) | N/A | Auto-authorized |
| admin.test.com | Bugcrowd | Prior approval needed | @triager | Pending |
| *.staging.example.com | Private | Written authorization | security@example.com | Request sent 2026-06-05 |
```

### 5.3 Scope Gray Area Log

When scope boundaries are unclear, document the ambiguity and resolution:

```
GRAY AREA: Does *.example.com include subdomain.example.com?

Discovered: 2026-06-02
Description: Subdomain subdomain.example.com is reachable but
not explicitly mentioned in scope. The scope says *.example.com
which implies all subdomains.

Resolution: Wildcard *.example.com covers all subdomains
including nested ones. Confirmed by program FAQ.
Resolution date: 2026-06-02
Status: In scope

GRAY AREA: Is api.example.com on blog.example.com subdomain in scope?

Discovered: 2026-06-03
Description: There is an API endpoint at api.blog.example.com.
The blog subdomain is OOS, but the API subdomain pattern is in
scope.

Resolution: blog.example.com is OOS, so all subdomains of
blog.example.com are OOS. Even though it starts with 'api',
the subdomain is under the excluded blog.* namespace.
Resolution date: 2026-06-03
Status: Out of scope
```

---

## 6. Program Rules

### 6.1 Testing Restrictions

```
RESTRICTIONS BY PROGRAM:

HackerOne — Example Corp:
  [ ] Automated scanning: Prohibited (request approval)
  [ ] Social engineering: Prohibited
  [ ] Physical access: Prohibited
  [ ] DoS/DDoS: Prohibited
  [ ] Rate limiting: Max 10 req/second
  [ ] Account creation: Unlimited test accounts
  [ ] Data access: Read-only where possible
  [ ] Third-party services: Out of scope
  [ ] Reporting window: 30 days
  [ ] Disclosure: 90-day embargo

Bugcrowd — Test Corp:
  [ ] Automated scanning: Restricted (no SQLi automation)
  [ ] Social engineering: Prohibited
  [ ] Physical access: Prohibited
  [ ] DoS/DDoS: Prohibited
  [ ] Rate limiting: Be reasonable
  [ ] Account creation: 5 test accounts max
  [ ] Data access: Read-only where possible
  [ ] Third-party services: Out of scope
  [ ] Reporting window: 14 days
  [ ] Disclosure: Program disclosure policy
```

### 6.2 Payout Ranges by Severity

```
HackerOne — Example Corp:
  Critical: $3,000 — $5,000
  High:     $1,000 — $3,000
  Medium:   $500 — $1,000
  Low:      $250 — $500

Bugcrowd — Test Corp:
  P1 (Critical): $1,500 — $2,500
  P2 (High):     $750 — $1,500
  P3 (Medium):   $350 — $750
  P4 (Low):      $100 — $350

Private Program:
  Critical: $5,000 — $10,000
  High:     $2,500 — $5,000
  Medium:   $1,000 — $2,500
  Low:      $500 — $1,000
```

### 6.3 Disclosure / Embargo Terms

```
| Program | Embargo | Disclosure Policy | Notes |
|---------|---------|------------------|-------|
| Example Corp | 90 days | Program must approve | Standard H1 |
| Test Corp | Varies | Per-finding basis | Check with triager |
| Private | 120 days | Mutual agreement | NDA signed |
```

### 6.4 Program Contact Information

```
HackerOne — Example Corp:
  Emergency Contact: security@example.com
  Response Time (SLA): 24h
  Preferred Reporting: HackerOne dashboard

Bugcrowd — Test Corp:
  Emergency Contact: security@testcorp.com
  Response Time (SLA): 48h
  Preferred Reporting: Bugcrowd dashboard

Private Program:
  Direct Contact: security@other.com (PGP encrypted)
  Response Time: 72h
  Preferred Reporting: Email with PGP
```

---

## 7. Scope Violation Log

### 7.1 Near-Miss Log

Situations where testing almost went out of scope but was caught:

```
DATE: 2026-06-03
TARGET: api.example.com
SITUATION: Found endpoint pointing to blog.example.com
ACTION: Checked scope — blog subdomain is OOS. Stopped testing.
LESSON: Always verify the subdomain in the URL before testing.
```

### 7.2 Scope Violations

If a scope violation occurs (even accidental), log it:

```
DATE: [YYYY-MM-DD]
PROGRAM: [name]
VIOLATION: [description]
CAUSE: [how it happened]
DETECTION: [how it was caught]
IMPACT: [what was accessed/affected]
ACTION TAKEN: [remediation steps]
REPORTED: [Yes/No — to program]
OUTCOME: [program response]
LESSON: [how to prevent recurrence]
```

### 7.3 Scope Discipline Reminders

```
DAILY REMINDERS:
  1. Check the URL before sending each request
  2. When in doubt, don't test it
  3. Scope boundaries exist for a reason
  4. A finding outside scope is a waste of time
  5. A scope violation can get you banned from the program
  6. Save scope policy screenshots for reference
  7. If scope is ambiguous, ask the program
  8. Subdomain takeover only if the subdomain is in scope
  9. SSRF target is the in-scope origin, not the SSRF destination
  10. Chained findings still need to originate from in-scope assets
```

---

## 8. Target Authorization

### 8.1 Authorization Records

```
TARGET: example.com
PROGRAM: HackerOne
AUTHORIZATION TYPE: Public program agreement
AUTHORIZATION DATE: 2026-06-01 (start of engagement)
AUTHORIZATION REF: HackerOne program terms
EXPIRY: Continuous (active program)
STATUS: Authorized
```

### 8.2 Authorization Checklist

Before engaging any target:

```
  [ ] 1. Target is listed in program scope
  [ ] 2. Program has active bounty pool
  [ ] 3. Safe harbor is explicitly stated
  [ ] 4. Testing restrictions are understood
  [ ] 5. Test accounts are created (not real user accounts)
  [ ] 6. Scope boundaries are documented
  [ ] 7. Excluded bug classes are noted
  [ ] 8. Emergency contact is saved
  [ ] 9. Disclosure terms are understood
  [ ] 10. This is documented in target-registry
```

### 8.3 Third-Party Authorization

Testing third-party services that are integrated with the target:

```
SERVICE: Cloudflare (CDN)
STATUS: Authorized — CDN is part of target's infrastructure
RESTRICTIONS: Only test through the target, not Cloudflare directly

SERVICE: AWS (Cloud Infrastructure)
STATUS: Authorized — testing through SSRF within scope
RESTRICTIONS: Only access metadata through SSRF from target.
Do not directly attack AWS infrastructure.

SERVICE: Stripe (Payments)
STATUS: NOT authorized — third-party payment processor
RESTRICTIONS: Do not test Stripe directly. Stripe keys found
in target's code are in scope only if they affect the target.
```

---

## 9. Maintenance

### 9.1 Scope Update Log

```
| Date | Program | Change | Impact |
|------|---------|--------|--------|
| 2026-06-01 | Example Corp | Added new scope item: *.v2.example.com | New testing surface |
| 2026-06-05 | Test Corp | Removed admin.test.com from scope | Lost admin testing surface |
```

### 9.2 Maintenance Tasks

```
DAILY:
  [ ] Verify scope of any new subdomains found during recon
  [ ] Check for program scope updates

WEEKLY:
  [ ] Review scope boundaries for actively hunted targets
  [ ] Check for new excluded bug classes
  [ ] Save updated scope policy snapshots

MONTHLY:
  [ ] Full scope audit for all active programs
  [ ] Verify safe harbor terms unchanged
  [ ] Review scope violation log
  [ ] Update payout estimates based on scope changes
```

### 9.3 Quick Reference Card

```
ESSENTIAL RULES:
  1. If scope says *.example.com, ALL subdomains are in scope
     UNLESS explicitly excluded
  2. Exclusions are listed separately — check both in-scope
     and out-of-scope lists
  3. When scope says "wildcard," subdomain takeover is in scope
  4. SSRF to internal services is valid if the SSRF origin is
     in scope
  5. Third-party integrations are OOS unless specifically
     included
  6. `scope: not defined` means OOS — do not test it
  7. Always check VRT exclusions for Bugcrowd programs
  8. Private programs may have custom scope rules
  9. Changes to scope mid-engagement are possible — check
     program announcements
  10. When in doubt, ask. Don't risk a scope violation
```

---

*End of scope-records.md*
