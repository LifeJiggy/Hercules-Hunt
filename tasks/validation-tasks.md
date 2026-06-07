# Tasks — Validation & Reporting Tasks

Task definitions for validating findings and writing reports. Each task
guides the hunter through the full validation process (7-Question Gate,
4-Gate Checklist) and report writing process (CVSS scoring, impact
statements, evidence packaging).

---

## Table of Contents

1. [Validation Overview](#1-validation-overview)
2. [Active Validation Tasks](#2-active-validation-tasks)
3. [7-Question Gate](#3-7-question-gate)
4. [4-Gate Checklist](#4-gate-checklist)
5. [CVSS Score Guide](#5-cvss-score-guide)
6. [Report Writing Tasks](#6-report-writing-tasks)
7. [Submission Tasks](#7-submission-tasks)
8. [Validation History](#8-validation-history)
9. [Validation Templates](#9-validation-templates)
10. [Reporting Templates](#10-reporting-templates)
11. [Maintenance](#11-maintenance)

---

## 1. Validation Overview

### 1.1 Summary

```
TOTAL VALIDATIONS: [N]
  Pass: [N] (submitted)
  Kill: [N] (failed validation)
  Downgrade: [N] (severity reduced)
  Chain Required: [N] (needs chaining)

TOTAL REPORTS WRITTEN: [N]
  Submitted: [N]
  Pending submission: [N]
  Triaged: [N]
  Bountied: [N]
```

### 1.2 Task ID Format

```
VALIDATION TASK ID: VTASK-{finding_id}
  finding_id: The FINDING ID from findings-archive

REPORT TASK ID: WTASK-{finding_id}
  finding_id: The FINDING ID from findings-archive

Example: VTASK-FIND-001, WTASK-FIND-001
```

---

## 2. Active Validation Tasks

### 2.1 Currently Active

```
| Task ID | Finding | Bug Class | Severity | Validation Status | Report Status |
|---------|---------|-----------|----------|-------------------|---------------|
| VTASK-FIND-001 | SSRF cloud metadata | SSRF | High | In Progress | Pending |
| VTASK-FIND-002 | JWT alg:none | JWT | Critical | Complete | Pending |
| VTASK-FIND-003 | IDOR write -> ATO | IDOR | High | Complete | Complete |
```

### 2.2 Validation Task Details

```
VTASK-FIND-001: SSRF Cloud Metadata

FINDING: FIND-001
BUG CLASS: SSRF
PROPOSED SEVERITY: High
TARGET: api.example.com
ENDPOINT: POST /api/avatar (url parameter)
DESCRIPTION: Avatar endpoint downloads URLs without validation
  of internal IPs, allowing SSRF to cloud metadata endpoints.

VALIDATION PROGRESS:
  [x] 7-Question Gate — all questions passed
  [ ] Impact confirmation — IAM credentials retrieved
  [ ] Reproduction — Tested 3x with different sessions
  [ ] Evidence — Screenshots captured
  [ ] Always-rejected list — Checked, not rejected
  [ ] Chain potential — SSRF -> IAM -> cloud access -> Critical
  [ ] Final verdict: VALID (High, Critical if IAM chain works)
```

---

## 3. 7-Question Gate

Every finding must pass all 7 questions. If any question is answered
with a clear "No" (not theoretical), the finding is killed immediately.

### 3.1 The 7 Questions

```
QUESTION 1: Is this finding in scope?
  OUT OF SCOPE EXAMPLES:
    - Third-party service not owned by target
    - Subdomain explicitly excluded
    - Bug class excluded by program policy
    - Testing on production without authorization

  PASS: Yes — endpoint is *.example.com which is in scope
  FAIL: No — blog.example.com is explicitly OOS

QUESTION 2: Can an attacker trigger this without user interaction?
  NON-INTERACTION EXAMPLES:
    - Automated scan or script
    - Victim visits a page (but doesn't click/paste)
    - Server-side automation triggers the issue
    - Crawler/bot can trigger it

  REQUIRES INTERACTION:
    - Victim must click a specific link
    - Victim must paste crafted data
    - Victim must login and perform specific actions
    - Requires social engineering

  PASS: Yes — attacker can send the request directly
  FAIL: No — victim must click a crafted link (self-XSS)

QUESTION 3: Does this finding have a demonstrable security impact?
  IMPACT EXAMPLES:
    - Data exposure (PII, credentials, internal data)
    - Account takeover
    - Privilege escalation
    - Code execution
    - Financial loss

  LOW/NON-IMPACT:
    - Theoretical impact requiring multiple unknowns
    - Information disclosure of non-sensitive data
    - Rate limiting bypass (without ATO)
    - Missing security headers
    - Banner grabbing

  PASS: Yes — attacker can read cloud metadata with IAM creds
  FAIL: No — reveals only public server information

QUESTION 4: Is this finding reproducible?
  REPRODUCIBLE:
    - Same payload produces same result every time
    - Can be reproduced with different accounts
    - Can be reproduced from different IPs
    - Not dependent on race conditions (unless race finding)

  NOT REPRODUCIBLE:
    - Works 1/10 times
    - Only works on specific account
    - Only works from specific network
    - Time-dependent behavior

  PASS: Yes — sent payload 3x, same result each time
  FAIL: No — only worked once out of 10 attempts

QUESTION 5: Is this finding unique (not a duplicate)?
  NOT DUPLICATE:
    - Checked disclosed reports for similar findings
    - Different endpoint, parameter, or technique
    - Different impact level
    - Program hasn't fixed this yet

  DUPLICATE:
    - Known and already reported
    - Same endpoint, same parameter, same technique
    - Already fixed (try to reproduce before submitting)

  PASS: Yes — searched disclosed reports, no match found
  FAIL: No — reported 3 times in last month according to known

QUESTION 6: Does the impact chain make sense?
  IMPACT CHAIN:
    - Step A leads to Step B leads to Step C
    - All steps are realistic (no theoretical hops)
    - Each step has been demonstrated
    - Chain doesn't require privileged access

  BROKEN CHAIN:
    - Requires privileged access attacker doesn't have
    - Depends on unverified assumptions
    - "If [unlikely thing] happens, then..."
    - Multiple unknown conditions must align

  PASS: Yes — SSRF -> metadata -> IAM creds -> cloud access
  FAIL: No — requires victim to be admin AND click the link

QUESTION 7: Would you want to receive a bounty for this finding?
  If you hesitate on this question, that's a red flag.

  PASS: Yes — this is a clear, impactful vulnerability
  FAIL: No — it feels like a stretch, or the impact is weak
```

### 3.2 Gate Results Log

```
VTASK-FIND-001 — SSRF Cloud Metadata
  Q1 (Scope):         PASS — api.example.com is in scope
  Q2 (Interaction):   PASS — attacker sends request directly
  Q3 (Impact):        PASS — IAM credentials = cloud compromise
  Q4 (Reproducible):  PASS — reproduced 3x
  Q5 (Unique):        PASS — no disclosed report found
  Q6 (Chain):         PASS — SSRF -> IAM -> cloud access
  Q7 (Bounty):        PASS — would be happy to receive bounty
  FINAL:              PASS — VALID FINDING

VTASK-FIND-002 — JWT alg:none
  Q1 (Scope):         PASS — api.example.com is in scope
  Q2 (Interaction):   PASS — attacker sends request directly
  Q3 (Impact):        PASS — full admin API access
  Q4 (Reproducible):  PASS — reproduced with different tokens
  Q5 (Unique):        PASS — no disclosed report found
  Q6 (Chain):         PASS — alg:none -> admin token -> full access
  Q7 (Bounty):        PASS — critical finding, clear bounty
  FINAL:              PASS — VALID FINDING
```

---

## 4. 4-Gate Checklist

After passing the 7-Question Gate, run the 4-Gate Checklist.

### 4.1 Gate 1: Severity Check

```
CURRENT SEVERITY: [Critical / High / Medium / Low / Info]

VALIDATION:
  [ ] Severity matches CVSS score
  [ ] Severity matches bug class expectations
  [ ] Not overrated (downgrade if needed)
  [ ] Not underrated (upgrade if needed)

SEVERITY GUIDELINES:
  Critical: ATO, RCE, SQLi with data dump, SSRF -> IAM -> full cloud
  High:     SSRF, IDOR with sensitive data, auth bypass to sensitive
  Medium:   XSS (non-self), CSRF on sensitive action, IDOR with limited data
  Low:      Missing security headers, info disclosure without sensitive data
  Info:     Banner, stack trace in debug mode
```

### 4.2 Gate 2: Always-Rejected Check

```
Check the always-rejected list. If your finding matches any of these,
KILL it immediately.

ALWAYS-REJECTED LIST:
  [ ] Rate limiting issues (without ATO demonstration)
  [ ] Missing HTTP security headers
  [ ] Self-XSS
  [ ] Clickjacking on non-sensitive actions
  [ ] CSRF on logout
  [ ] Missing autocomplete on password fields
  [ ] Password policy without practice bypass
  [ ] Email enumeration (subtle timing differences)
  [ ] Server version disclosure in banners
  [ ] Stack traces in error messages (without sensitive data)
  [ ] Directory listing on non-sensitive directories
  [ ] OPTIONS/TRACE methods enabled
  [ ] Man-in-the-middle on non-sensitive pages
  [ ] Open ports without service exploitation
  [ ] SSL/TLS configuration issues (weak cipher, etc.)
```

### 4.3 Gate 3: Chain Potential Check

```
Check if this finding can be chained with another primitive
for higher severity.

CHAIN MAPPING:
  SSRF -> Cloud metadata -> IAM credentials -> Cloud access
  IDOR write -> Email change -> Password reset -> ATO
  XSS -> CSRF -> Admin action -> Full compromise
  Open redirect -> OAuth redirect_uri -> Auth code theft -> ATO
  Subdomain takeover -> OAuth callback -> Auth code -> ATO

CURRENT FINDING CHAIN POTENTIAL:
  [ ] Can be PREY (used by another finding to escalate)
  [ ] Can be PREDATOR (escalates using another finding)
  [ ] Standalone finding (no chain needed)
  [ ] INCOMPLETE — needs another primitive to be useful
```

### 4.4 Gate 4: Evidence Readiness

```
EVIDENCE CHECKLIST:
  [ ] At least 2 clear screenshots
  [ ] Screenshots show the URL bar
  [ ] Screenshots show full browser window
  [ ] Request and response visible
  [ ] Impact demonstrated
  [ ] No PII visible
  [ ] No session tokens visible
  [ ] Annotations highlight the vulnerability
  [ ] HAR file captured (if applicable)
  [ ] HAR file sanitized (tokens removed)
  [ ] Reproduction steps written
  [ ] Reproduction steps verified
```

---

## 5. CVSS Score Guide

### 5.1 CVSS 3.1 Scoring Template

```
CVSS 3.1 VECTOR:
  AV:[N/A/L/P]  — Attack Vector (Network/Adjacent/Local/Physical)
  AC:[L/H]      — Attack Complexity (Low/High)
  PR:[N/L/H]    — Privileges Required (None/Low/High)
  UI:[N/R]      — User Interaction (None/Required)
  S:[U/C]       — Scope (Unchanged/Changed)
  C:[N/L/H]     — Confidentiality (None/Low/High)
  I:[N/L/H]     — Integrity (None/Low/High)
  A:[N/L/H]     — Availability (None/Low/High)

EXAMPLE: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical)
```

### 5.2 Common Finding Scores

```
CRITICAL:
  RCE: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)
  ATO: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)
  SQLi (full): AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)

HIGH:
  SSRF (cloud): AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)
  IDOR write: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H (8.8)
  Auth bypass: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)

MEDIUM:
  Reflected XSS: AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N (5.4)
  CSRF: AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N (4.3)
  IDOR read: AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N (4.3)

LOW:
  Missing headers: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N (0.0)
  Banner: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N (0.0)
```

### 5.3 Severity Decision Guide

```
IS IT CRITICAL?
  [ ] Remote code execution
  [ ] Full account takeover (any user)
  [ ] SQL injection with data extraction
  [ ] Authentication bypass to admin
  [ ] SSRF to cloud metadata (IAM chain)
  [ ] Complete access to all user data
  If ANY of these: CRITICAL

IS IT HIGH?
  [ ] SSRF (any internal access)
  [ ] IDOR write (modify another user's data)
  [ ] Authentication bypass (partial)
  [ ] Stored XSS (non-admin)
  [ ] Business logic with financial impact
  [ ] Sensitive data exposure (PII, credentials)
  If ANY of these: HIGH

IS IT MEDIUM?
  [ ] Reflected XSS (non-self)
  [ ] IDOR read (limited data)
  [ ] CSRF on sensitive action
  [ ] Open redirect
  [ ] Subdomain takeover (with demonstrable impact)
  [ ] Race condition (limited impact)
  If ANY of these: MEDIUM

IS IT LOW?
  [ ] Missing security headers
  [ ] Information disclosure (non-sensitive)
  [ ] Path traversal (read only, non-sensitive)
  If ANY of these: LOW

IS IT INFORMATIVE?
  [ ] Banner/version disclosure
  [ ] Missing autocomplete
  [ ] Stack trace without sensitive data
  [ ] OPTIONS/TRACE enabled
  If ANY of these: INFORMATIVE (do NOT submit)
```

---

## 6. Report Writing Tasks

### 6.1 Active Reports

```
| Task ID | Finding | Severity | Report Status | Submission Status |
|---------|---------|----------|---------------|-------------------|
| WTASK-FIND-001 | SSRF cloud metadata | High | Drafting | Not submitted |
| WTASK-FIND-002 | JWT alg:none | Critical | Complete | Pending submission |
| WTASK-FIND-003 | IDOR write -> ATO | High | Complete | Submitted |
```

### 6.2 Report Task Details

```
WTASK-FIND-003: IDOR Write -> ATO

FINDING: FIND-003
SEVERITY: High
STATUS: Complete
ASSIGNED: Self

REPORT COMPONENTS:
  [x] Title: IDOR Write on Profile Update Allows Account Takeover
  [x] Summary
  [x] Impact statement
  [x] Reproduction steps
  [x] Technical detail
  [x] Payload/request
  [x] Screenshots (4)
  [x] HAR file
  [x] CVSS: 8.8 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
  [x] Affected endpoint: PUT /api/v2/users/{user_id}/profile

  Report file: reporting/reports/IDOR-ATO-20260607.md
  Submitted: Yes
  Submission URL: https://hackerone.com/reports/NNNNNN
```

---

## 7. Submission Tasks

### 7.1 Submission Queue

```
| Finding | Program | Platform | Ready? | Submitted | Report ID |
|---------|---------|----------|--------|-----------|-----------|
| FIND-001 | Example Corp | HackerOne | [x] | 2026-06-07 | H1-123456 |
| FIND-002 | Example Corp | HackerOne | [] | Pending | — |
| FIND-003 | Test Corp | Bugcrowd | [x] | 2026-06-07 | BC-789012 |
```

### 7.2 Pre-Submission Checklist

```
For each submission:
  [ ] 1. Report written in clear, human language
  [ ] 2. Impact-first structure
  [ ] 3. Reproduction steps are numbered and clear
  [ ] 4. Technical detail is included
  [ ] 5. Payload/request included
  [ ] 6. Screenshots attached and sanitized
  [ ] 7. HAR file attached and sanitized (if applicable)
  [ ] 8. CVSS score included
  [ ] 9. Chain information (if applicable)
  [ ] 10. Program-specific fields filled (VRT, etc.)
  [ ] 11. No PII visible
  [ ] 12. Test account info included (not real users)
```

### 7.3 Program-Specific Submission Notes

```
HACKERONE:
  - Title format: [Bug Class] in [Endpoint] leads to [Impact]
  - Use the report template
  - Include severity and CVSS
  - CWE ID recommended
  - Attach screenshots

BUGGROWD:
  - VRT-based vulnerability search
  - Select correct VRT category
  - Manual severity override if VRT default is wrong
  - Include severity rationale in first body paragraph
  - Remind triager of VRT override if applicable
  - Attach screenshots and HAR
```

### 7.4 Post-Submission Tasks

```
AFTER SUBMISSION:
  [ ] Record submission in findings-archive.md
  [ ] Record submission in target-registry.md
  [ ] Wait for triage (check daily)
  [ ] If rejected: review rejection reason, kill or improve
  [ ] If triaged: wait for bounty
  [ ] If duplicated: close report gracefully
  [ ] If paid: celebrate, log payout, update statistics
```

---

## 8. Validation History

### 8.1 Validated Findings

```
| Finding | Bug Class | Proposed Sev | Final Sev | Result | Date |
|---------|-----------|-------------|-----------|--------|------|
| FIND-001 | SSRF | High | High | VALID | 2026-06-07 |
| FIND-002 | JWT | Critical | Critical | VALID | 2026-06-07 |
| FIND-003 | IDOR | High | High | VALID | 2026-06-06 |
```

### 8.2 Killed Findings

```
| Finding | Bug Class | Proposed Sev | Kill Reason | Date |
|---------|-----------|-------------|-------------|------|
| FIND-004 | XSS | Medium | Self-XSS (Q2 fail) | 2026-06-05 |
| FIND-005 | Rate Limit | Low | Always-rejected | 2026-06-05 |
| FIND-006 | Info Disc | Low | No sensitive data | 2026-06-04 |
```

### 8.3 Validation Statistics

```
TOTAL VALIDATED: [N]
  Valid: [N] ([N]%)
  Killed: [N] ([N]%)
  Downgraded: [N] ([N]%)
  Upgraded: [N] ([N]%)

COMMON KILL REASONS:
  Self-XSS: [N]
  Always-rejected: [N]
  Low impact: [N]
  Not reproducible: [N]
  Duplicate: [N]

VALIDATION PASS RATE: [N]%
TARGET: > 50% pass rate after validation
```

---

## 9. Validation Templates

### 9.1 Full Validation Template

```
===== FINDING VALIDATION REPORT =====

FINDING ID: FIND-NNN
BUG CLASS: [SSRF / IDOR / JWT / XSS / etc.]
ENDPOINT: [URL]
PARAMETER: [vulnerable parameter]

===== 1. 7-QUESTION GATE =====
Q1 (Scope):     [PASS / FAIL] — [justification]
Q2 (Interaction): [PASS / FAIL] — [justification]
Q3 (Impact):    [PASS / FAIL] — [justification]
Q4 (Reproducible): [PASS / FAIL] — [justification]
Q5 (Unique):    [PASS / FAIL] — [justification]
Q6 (Chain):     [PASS / FAIL] — [justification]
Q7 (Bounty):    [PASS / FAIL] — [justification]
RESULT: [PASS / FAIL]

===== 2. 4-GATE CHECKLIST =====
Gate 1 (Severity): [PASS / ADJUST] — [proposed/confirmed severity]
Gate 2 (Rejected): [PASS / KILL] — [always-rejected check]
Gate 3 (Chain):    [PASS / CHAIN REQUIRED] — [chain notes]
Gate 4 (Evidence): [PASS / FAIL] — [evidence notes]

===== 3. FINAL VERDICT =====
Verdict: [VALID / KILL / DOWNGRADE / CHAIN REQUIRED]
Final Severity: [severity]
CVSS: [score and vector]
Notes: [additional notes]
```

### 9.2 Quick Validation Template

```
----- 7-QUESTION GATE -----
Q1: [P/F]
Q2: [P/F]
Q3: [P/F]
Q4: [P/F]
Q5: [P/F]
Q6: [P/F]
Q7: [P/F]
RESULT: [PASS / KILL]

----- 4-GATES -----
Severity: [P/A]
Rejected: [P/K]
Chain: [P/CR]
Evidence: [P/F]

----- FINAL -----
Verdict: [VALID / KILL / DOWNGRADE / CHAIN REQ]
Severity: [sev]
```

---

## 10. Reporting Templates

### 10.1 HackerOne Report Template

```
# Summary
[2-3 sentences describing the vulnerability and impact]

# Impact
[Clear statement of what an attacker can achieve. Start with
the impact, not the technical details.]

# Reproduction Steps
1. [Step 1 — login, navigate, etc.]
2. [Step 2 — specific action]
3. [Step 3 — observe result]

# Technical Details
[Detailed explanation of the vulnerability including root cause]

# Request/Response
```
METHOD /path HTTP/1.1
Host: target.com
...
```

# Screenshots
[Attached]

# CVSS Score
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical)
```

### 10.2 Bugcrowd Report Template

```
# Vulnerability Description
[2-3 sentences]

# Severity Rationale
[Explain why this exceeds the default VRT severity. If VRT
defaults to P3, explain why it should be P1/P2.]

# Steps to Reproduce
1.
2.
3.

# Technical Details
[Detailed explanation]

# Supporting Material
[screenshots, HAR, request/response]

# VRT Category
[Selected category]
[Requested severity override, if applicable]
```

---

## 11. Maintenance

```
DAILY:
  [ ] Update validation task status
  [ ] Submit completed reports
  [ ] Log validation results

WEEKLY:
  [ ] Review killed findings for patterns
  [ ] Update severity guidelines with new data
  [ ] Check for stale validation tasks
  [ ] Archive old validation reports

MONTHLY:
  [ ] Review validation statistics
  [ ] Update templates based on program feedback
  [ ] Study new validation techniques
```

---

*End of validation-tasks.md*
