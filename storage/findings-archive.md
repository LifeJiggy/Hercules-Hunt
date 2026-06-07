# Storage — Findings Archive

Permanent archive of all findings discovered across all targets. Each finding
is logged here when discovered and updated through its lifecycle (validated,
submitted, resolved, paid, rejected). This is the canonical record of what
you found and what happened with it.

---

## Table of Contents

1. [Archive Overview](#1-archive-overview)
2. [Paid Findings](#2-paid-findings)
3. [Submitted — Awaiting Triage](#3-submitted--awaiting-triage)
4. [Finding Detail Cards](#4-finding-detail-cards)
5. [Finding Statistics](#5-finding-statistics)
6. [Rejected Findings](#6-rejected-findings)
7. [Killed Findings](#7-killed-findings)
8. [Payout Log](#8-payout-log)
9. [Maintenance](#9-maintenance)

---

## 1. Archive Overview

### 1.1 Summary

```
TOTAL FINDINGS: [N]
  Critical: [N]
  High:     [N]
  Medium:   [N]
  Low:      [N]
  Info:     [N]

STATUS BREAKDOWN:
  Paid:         [N]
  Triaged:      [N] (awaiting payout)
  Submitted:    [N] (awaiting triage)
  In Progress:  [N] (not yet submitted)
  Killed:       [N] (failed validation)
  Rejected:     [N] (N/Ad by program)

TOTAL PAID: $[N]
AVERAGE PAYOUT: $[N]
BEST PAYOUT: $[N]
PROGRAMS WITH PAYOUTS: [N]
```

### 1.2 Finding ID Format

```
FINDING ID FORMAT: FIND-YYYYMMDD-XXX
  YYYYMMDD: Date of discovery
  XXX:      Sequential number

Example: FIND-20260607-001

REFERENCED AS: FIND-001 (short form)
```

### 1.3 Finding Lifecycle

```
DISCOVERED → VALIDATED → SUBMITTED → TRIAGED → BOUNTIED
                                         └→ REJECTED
              └→ KILLED (failed validation)
              └→ KILLED (always-rejected list)
              └→ KILLED (scope issue)
```

---

## 2. Paid Findings

### 2.1 Payout Summary

```
| Finding | Bug Class | Severity | Program | Payout | Date Paid |
|---------|-----------|----------|---------|--------|-----------|
| FIND-001 | SSRF | High | HackerOne | $1,500 | 2026-06-15 |
| FIND-002 | JWT | Critical | HackerOne | $3,000 | 2026-06-20 |
| FIND-003 | IDOR | High | Bugcrowd | $800 | 2026-06-25 |
```

### 2.2 Best Paying Findings

```
CRITICAL: JWT Signature Bypass (alg:none) — $3,000 — HackerOne
HIGH:     SSRF Cloud Metadata Access — $1,500 — HackerOne
HIGH:     IDOR Write -> ATO — $800 — Bugcrowd
```

### 2.3 Payout Over Time

```
MONTHLY TOTALS:
  June 2026: $5,300 (3 findings)
  July 2026: $2,100 (2 findings)
  August 2026: $0 (0 findings)
  September 2026: $4,200 (3 findings)

YEARLY TOTAL: $11,600
MONTHLY AVERAGE: $2,900
```

---

## 3. Submitted — Awaiting Triage

### 3.1 Pending Submissions

```
| Finding | Bug Class | Severity | Program | Submitted | Status |
|---------|-----------|----------|---------|-----------|--------|
| FIND-004 | SSRF | High | HackerOne | 2026-06-30 | Awaiting Triage |
| FIND-005 | IDOR | Critical | Bugcrowd | 2026-07-01 | In Triage |
```

### 3.2 Submission Timeline

```
FIND-004 — SSRF on api.example.com
  Discovered:    2026-06-28
  Validated:     2026-06-29
  Submitted:     2026-06-30
  Last Update:   2026-07-05 (Status: Awaiting Triage)
  Days Waiting:  8

FIND-005 — IDOR Write -> ATO on app.example.com
  Discovered:    2026-06-29
  Validated:     2026-06-30
  Submitted:     2026-07-01
  Last Update:   2026-07-03 (Status: In Triage)
  Days Waiting:  5
```

---

## 4. Finding Detail Cards

### 4.1 FIND-NNN Template

```
╔══════════════════════════════════════════════════════════════╗
║ FIND-NNN: [Bug Class] — [Short Description]                ║
╚══════════════════════════════════════════════════════════════╝

## Status
- Status: [Paid / Triaged / Submitted / In Progress / Killed / Rejected]
- Severity: [Critical / High / Medium / Low]
- CVSS 3.1: [Score] ([Vector])

## Target
- Program: [HackerOne / Bugcrowd / Intigriti / Immunefi]
- Domain: [target.com]
- Endpoint: [full URL with method]
- Parameter: [vulnerable parameter]

## Timeline
- Discovered: YYYY-MM-DD
- Validated:  YYYY-MM-DD
- Submitted:  YYYY-MM-DD
- Triaged:    YYYY-MM-DD
- Bounty:     YYYY-MM-DD
- Payout:     $[amount]

## Technical Detail
[Detailed description of the vulnerability]

## Reproduction Steps
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Payload
```http
METHOD /path HTTP/1.1
Host: target.com
[Headers]

[Body]
```

## Impact
[Clear description of what an attacker can achieve]

## Evidence Package
- Package: PKG-YYYYMMDD-XXX
- Screenshots: [N]
- HAR Files: [N]

## Chain Potential
[If applicable: what this could chain with]

## Lessons Learned
[What to do differently next time]

## Notes
[Any additional context]
```

### 4.2 FIND-001: SSRF Cloud Metadata Access (Paid)

```
╔══════════════════════════════════════════════════════════════╗
║ FIND-001: SSRF — Cloud Metadata via Avatar Upload          ║
╚══════════════════════════════════════════════════════════════╝

## Status
- Status: Paid
- Severity: High
- CVSS 3.1: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

## Target
- Program: HackerOne
- Domain: api.example.com
- Endpoint: POST /api/avatar
- Parameter: url (JSON body)

## Timeline
- Discovered: 2026-06-05
- Validated: 2026-06-06
- Submitted: 2026-06-07
- Triaged: 2026-06-10
- Bounty: 2026-06-15
- Payout: $1,500

## Technical Detail
The avatar upload endpoint accepts a URL parameter to download
an image from. The URL parameter is not validated against
RFC 1918 addresses, allowing SSRF to internal and cloud
metadata endpoints.

## Reproduction Steps
1. Login as any user
2. POST /api/avatar with {"url":"http://169.254.169.254/latest/meta-data/"}
3. The server downloads and returns the AWS metadata content
4. Further exploration reveals IAM credentials are accessible

## Payload
POST /api/avatar HTTP/1.1
Host: api.example.com
Authorization: Bearer [attacker_token]
Content-Type: application/json

{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}

## Impact
An attacker can retrieve AWS IAM temporary credentials for the
EC2 instance running the API server. With these credentials,
the attacker can access S3 buckets, RDS databases, and other
AWS resources.

## Evidence Package
- Package: PKG-20260605-001
- Screenshots: 4
- HAR Files: 1
```

### 4.3 FIND-002: JWT alg:none Signature Bypass (Paid)

```
╔══════════════════════════════════════════════════════════════╗
║ FIND-002: JWT — alg:none Signature Verification Bypass     ║
╚══════════════════════════════════════════════════════════════╝

## Status
- Status: Paid
- Severity: Critical
- CVSS 3.1: 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

## Target
- Program: HackerOne
- Domain: api.example.com
- Endpoint: ALL authenticated endpoints
- Parameter: JWT in Authorization header

## Timeline
- Discovered: 2026-06-05
- Validated: 2026-06-06
- Submitted: 2026-06-07
- Triaged: 2026-06-08
- Bounty: 2026-06-20
- Payout: $3,000

## Technical Detail
The JWT library does not enforce a specific algorithm. By
setting the JWT header's algorithm to "none" and removing
the signature, the server accepts the forged token as valid.

## Reproduction Steps
1. Create a JWT with header {"alg":"none"} and payload {"role":"admin"}
2. Set the signature to empty (trailing dot)
3. Send this token as the Authorization: Bearer header
4. Server returns 200 OK with admin data

## Payload
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.

(decoded header: {"alg":"none","typ":"JWT"}
 decoded payload: {"sub":"admin","role":"admin"})

## Impact
An attacker can forge arbitrary JWT tokens with any user ID
and any role. This leads to complete account takeover of any
user, including administrators. Full read/write access to all
API endpoints.

## Evidence Package
- Package: PKG-20260605-002
- Screenshots: 4
- HAR Files: 1
```

### 4.4 FIND-003: IDOR Write — Email Takeover (Paid)

```
╔══════════════════════════════════════════════════════════════╗
║ FIND-003: IDOR Write — Profile Email Takeover              ║
╚══════════════════════════════════════════════════════════════╝

## Status
- Status: Paid
- Severity: High
- CVSS 3.1: 8.8 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)

## Target
- Program: Bugcrowd
- Domain: app.example.com
- Endpoint: PUT /api/v2/users/{user_id}/profile
- Parameter: user_id (path)

## Timeline
- Discovered: 2026-06-06
- Validated: 2026-06-06
- Submitted: 2026-06-07
- Triaged: 2026-06-10
- Bounty: 2026-06-25
- Payout: $800

## Technical Detail
The profile update endpoint uses a user-provided ID to update
profiles without verifying that the authenticated user owns
that profile. By changing the user_id to a victim's ID, an
attacker can change the victim's email address.

## Reproduction Steps
1. Login as user A (attacker)
2. PUT /api/v2/users/{victim_user_id}/profile with
   {"email":"attacker-controlled@evil.com"}
3. The victim's email is changed
4. Attacker uses password reset to take over the victim's account

## Payload
PUT /api/v2/users/4242/profile HTTP/1.1
Host: app.example.com
Authorization: Bearer [attacker_token]
Content-Type: application/json

{"email":"attacker@evil.com"}

## Impact
Full account takeover of any user. Attacker can change email,
trigger password reset, and access all victim data.

## Evidence Package
- Package: PKG-20260606-001
- Screenshots: 4
- HAR Files: 1
```

---

## 5. Finding Statistics

### 5.1 Bug Class Distribution

```
| Bug Class | Total | Paid | Avg Payout | Success Rate |
|-----------|-------|------|------------|--------------|
| SSRF | 3 | 2 | $1,250 | 67% |
| IDOR | 2 | 1 | $800 | 50% |
| JWT | 1 | 1 | $3,000 | 100% |
| XSS | 2 | 0 | $0 | 0% |
| Auth Bypass | 1 | 0 | $0 | 0% |
| Business Logic | 1 | 0 | $0 | 0% |

PAID BY CLASS:
  JWT:      $3,000 (1 finding) — $3,000 avg
  SSRF:     $2,500 (2 findings) — $1,250 avg
  IDOR:     $800 (1 finding) — $800 avg
  XSS:      $0
  Auth:     $0
```

### 5.2 Severity Distribution

```
| Severity | Total | Paid | Avg Payout |
|----------|-------|------|------------|
| Critical | 2 | 1 | $3,000 |
| High     | 4 | 2 | $1,150 |
| Medium   | 2 | 0 | $0 |
| Low      | 1 | 0 | $0 |

PAID BY SEVERITY:
  Critical: $3,000 avg
  High: $1,150 avg
```

### 5.3 Program Distribution

```
| Program | Submissions | Paid | Total Payout | Best Payout |
|---------|-------------|------|--------------|-------------|
| HackerOne | 4 | 3 | $5,500 | $3,000 |
| Bugcrowd | 2 | 1 | $800 | $800 |
| Intigriti | 0 | 0 | $0 | $0 |
| Immunefi | 0 | 0 | $0 | $0 |
```

### 5.4 Time-Based Metrics

```
DISCOVERY TO SUBMISSION:
  Average: 2.3 days
  Best:    0 days (same day, IDOR)
  Worst:   5 days (JWT, needed validation)

SUBMISSION TO TRIAGE:
  Average: 4.5 days
  Best:    1 day (JWT)
  Worst:   8 days (SSRF)

SUBMISSION TO PAYOUT:
  Average: 14 days
  Best:    10 days (JWT)
  Worst:   18 days (SSRF)

BOUNTY PER HOUR OF HUNTING:
  Total hunting hours: 25h
  Total bounty: $6,300
  Rate: $252/hour
```

### 5.5 Killed Finding Rate

```
TOTAL KILLED: 3
KILLED BY REASON:
  Scope issue: 1 (33%)
  Cannot reproduce: 1 (33%)
  Low impact: 1 (33%)

KILL RATE: 33% (3 killed out of 9 total)
TARGET KILL RATE: < 50%
```

---

## 6. Rejected Findings

### 6.1 Rejected List

```
| Finding | Bug Class | Program | Submitted | Reason |
|---------|-----------|---------|-----------|--------|
| FIND-006 | XSS | HackerOne | 2026-06-20 | Informative — self-XSS |
| FIND-007 | Auth Bypass | Bugcrowd | 2026-06-22 | Expected behavior |
```

### 6.2 Rejection Reasons Analysis

```
REJECTION REASONS:
  Informative only: 1
  Expected behavior: 1
  Duplicate: 0
  Out of scope: 0
  Cannot reproduce: 0

Key lesson from rejections:
  - Always validate XSS as non-self (check XSS doesn't require
    victim to paste URL)
  - Auth bypass needs clear security boundary crossing
```

---

## 7. Killed Findings

### 7.1 Killed List

Findings that passed initial discovery but failed validation:

```
| Finding | Bug Class | Reason Killed | Date |
|---------|-----------|---------------|------|
| FIND-008 | XSS | Self-XSS only | 2026-06-15 |
| FIND-009 | Rate Limit | Always-rejected bug class | 2026-06-16 |
| FIND-010 | Info Disclosure | Low impact, no sensitive data | 2026-06-18 |
```

### 7.2 Kill Reasons

```
KILL BREAKDOWN:
  Failed 7-Question Gate:    1 (FIND-008 — Q6: requires victim action)
  Always-rejected list:      1 (FIND-009 — rate limiting)
  Low impact / N/As itself:  1 (FIND-010 — non-sensitive info disclosure)
  Scope issue:               0
  Cannot reproduce:          0

Lessons:
  - For XSS, always confirm it fires without user interaction
  - Filter out rate-limit issues before investing time
```

### 7.3 Kill Detail

```
FIND-008: Reflected XSS in search parameter
  Discovery: Search endpoint reflects 'q' parameter in page title
  Validation failure: XSS only fires when victim clicks attacker's URL
  (self-XSS)
  Kill reason: Q6 of 7-Question Gate — requires victim to knowingly
  paste or click a crafted URL
  Lesson: Check for self-XSS vs reflected XSS early

FIND-009: No rate limit on password reset
  Discovery: POST /api/forgot-password has no rate limiting
  Validation failure: Always-rejected list — rate limiting without
  demonstrable account compromise is not a finding
  Kill reason: Always-rejected bug class
  Lesson: Check always-rejected list before investing time

FIND-010: Debug endpoint returns server info
  Discovery: GET /api/debug returns Python version and installed
  packages
  Validation failure: Information is non-sensitive and already
  detectable via headers and error messages
  Kill reason: Bug bounty programs consider this informative only
  Lesson: Always ask "can attacker do something with this?"
```

---

## 8. Payout Log

### 8.1 All Payouts

```
| Date | Finding | Program | Amount | Running Total |
|------|---------|---------|--------|---------------|
| 2026-06-15 | FIND-001 | HackerOne | $1,500 | $1,500 |
| 2026-06-20 | FIND-002 | HackerOne | $3,000 | $4,500 |
| 2026-06-25 | FIND-003 | Bugcrowd | $800 | $5,300 |

TOTAL: $5,300
```

### 8.2 Monthly Breakdown

```
JUNE 2026
  Week 1 (Jun 1-7):   $0 (all submitted)
  Week 2 (Jun 8-14):  $0 (awaiting triage)
  Week 3 (Jun 15-21): $4,500 (FIND-001 + FIND-002)
  Week 4 (Jun 22-28): $800 (FIND-003)
  Total: $5,300
```

### 8.3 Payout Goal Tracking

```
ANNUAL GOAL: $50,000
CURRENT: $5,300 (10.6% of goal)
MONTHLY TARGET: $4,167
MONTHLY AVERAGE: $5,300 (above target)

QUARTER TARGET: Q2 — $12,500
QUARTER CURRENT: $5,300 (42.4% of Q2 target)

ON TRACK: Yes / No
PROJECTED ANNUAL: $63,600 (at current rate)
```

---

## 9. Maintenance

### 9.1 Archive Tasks

```
DAILY:
  [ ] Register new findings when discovered
  [ ] Update finding status when changed
  [ ] Log kills when they happen

WEEKLY:
  [ ] Review rejected findings for patterns
  [ ] Update payout log
  [ ] Check finding statistics

MONTHLY:
  [ ] Review finding success rate by bug class
  [ ] Update payout goal tracking
  [ ] Adjust hunting priorities based on stats
  [ ] Clean up duplicate entries
```

### 9.2 Archive Health

```
REGISTERED FINDINGS: [N]
  - Active/In Progress: [N]
  - Submitted: [N]
  - Triaged: [N]
  - Paid: [N]
  - Killed: [N]
  - Rejected: [N]

LAST UPDATED: YYYY-MM-DD HH:MM
TOTAL PAID: $[N]
```

### 9.3 Lessons for Future Hunting

Derived from the findings archive:

```
1. SSRF is consistently valuable — always test cloud metadata
   first. Even if the immediate response is limited, chain with
   IAM enumeration for maximum impact.

2. JWT alg:none is still surprisingly common — test it on every
   target regardless of tech stack or presumed maturity.

3. IDOR write operations are gold — changing user IDs in PUT/
   PATCH/DELETE endpoints yields ATO chains. Prioritize these
   over read-only IDORs.

4. Kill findings fast — the 7-Question Gate saves time. If a
   finding fails any question, move on immediately.

5. Submit findings quickly — average 2.3 days from discovery to
   submission is good but could be faster. Aim for same-day
   submission for high-severity findings.

6. XSS is hard to get paid for — require clear non-self execution
   path. Self-XSS and DOM-XSS requiring user interaction are
   usually informative only.
```

---

*End of findings-archive.md*
