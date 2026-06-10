# Tasks — Report Generation Pipeline

Convert verified findings into submission-ready reports for HackerOne, Bugcrowd, Intigriti, and internal triage. Includes CVSS scoring, impact statements, evidence packaging, and platform-specific formatting.

---

## Table of Contents

1. [Report Overview](#1-report-overview)
2. [Finding Aggregation](#2-finding-aggregation)
3. [Evidence Sanitization](#3-evidence-sanitization)
4. [CVSS 4.0 Scoring](#4-cvss-40-scoring)
5. [Impact Statement Writing](#5-impact-statement-writing)
6. [Report Structuring](#6-report-structuring)
7. [Platform-Specific Formatting](#7-platform-specific-formatting)
8. [Triage Defense Preparation](#8-triage-defense-preparation)
9. [Report Templates](#9-report-templates)
10. [Submission Workflow](#10-submission-workflow)
11. [Post-Submission Tasks](#11-post-submission-tasks)
12. [Maintenance](#12-maintenance)

---

## 1. Report Overview

### 1.1 Summary

```
REPORTS GENERATED: [N]
  Submitted: [N]
  Pending: [N]
  Draft: [N]

BY PLATFORM:
  HackerOne: [N]
  Bugcrowd: [N]
  Intigriti: [N]
  Internal: [N]

BY SEVERITY:
  Critical: [N]
  High: [N]
  Medium: [N]
  Low: [N]

BOUNTY EARNED: $[N]
SUBMISSION SUCCESS RATE: [N]%
AVERAGE TRIAGE TIME: [N] days
```

### 1.2 Task ID Format

```
REPORT TASK ID: RPT-{target_short}-{YYMMDD}-{XXX}
  target_short: First 5 chars of target domain
  YYMMDD: Date of report creation
  XXX: Sequential number

Example: RPT-exampl-240607-001
```

### 1.3 Report Generation Lifecycle

```
FINDINGS VERIFIED → EVIDENCE SANITIZED → CVSS SCORED
    → IMPACT STATEMENTS → REPORT STRUCTURED
    → PLATFORM FORMAT → TRIAGE DEFENSE
    → REVIEW → SUBMISSION
```

---

## 2. Finding Aggregation

### 2.1 Task: Aggregate Verified Findings

```
TASK ID: RPT-AGGREGATE-001
INPUT: findings/verified/*.json
OUTPUT: reports/{target}-{date}-findings.json

AGGREGATION STEPS:
  [ ] Load all verified findings
  [ ] Sort by severity (Critical → Low)
  [ ] Group by bug class
  [ ] Group by affected endpoint
  [ ] Identify chainable findings
  [ ] Check for duplicates

AGGREGATION COMMANDS:
  # Load and sort findings
  $findings = Get-ChildItem findings/verified/*.json | ForEach-Object { Get-Content $_.FullName | ConvertFrom-Json }
  $sorted = $findings | Sort-Object { switch($_.severity) { "Critical" { 4 } "High" { 3 } "Medium" { 2 } "Low" { 1 } } } -Descending

  # Group by bug class
  $byClass = $sorted | Group-Object bug_class

  # Group by endpoint
  $byEndpoint = $sorted | Group-Object endpoint

  # Save aggregated report
  $sorted | ConvertTo-Json -Depth 5 | Set-Content "reports/{target}-{date}-findings.json"
```

### 2.2 Finding Aggregation Template

```json
{
  "target": "example.com",
  "report_date": "2026-06-07",
  "total_findings": 5,
  "findings": [
    {
      "finding_id": "FIND-001",
      "bug_class": "SSRF",
      "endpoint": "POST /api/avatar",
      "severity": "High",
      "cvss_score": 7.5,
      "chain_id": "CHAIN-001",
      "status": "ready_for_report"
    },
    {
      "finding_id": "FIND-002",
      "bug_class": "IDOR",
      "endpoint": "PUT /api/v2/users/{id}/profile",
      "severity": "Critical",
      "cvss_score": 9.8,
      "chain_id": "CHAIN-002",
      "status": "ready_for_report"
    }
  ],
  "chains": [
    {
      "chain_id": "CHAIN-001",
      "findings": ["FIND-001"],
      "final_severity": "Critical",
      "description": "SSRF to AWS metadata with IAM chain"
    }
  ]
}
```

---

## 3. Evidence Sanitization

### 3.1 Task: Sanitize All Evidence

```
TASK ID: RPT-SANITIZE-001
INPUT: evidence/PKG-FIND-*
OUTPUT: reports/sanitized/{finding_id}/

SANITIZATION REQUIREMENTS:
  [ ] Remove all cookies
  [ ] Remove all Authorization headers
  [ ] Remove all API keys and tokens
  [ ] Remove all PII (emails, names, phone numbers)
  [ ] Remove internal IP addresses
  [ ] Replace internal hostnames
  [ ] Remove session identifiers

SANITIZATION PATTERNS:
  Cookies: Set-Cookie:.* → [REDACTED]
  Authorization: Bearer [REDACTED]
  API Keys: [A-Za-z0-9]{32,} → [REDACTED]
  Emails: [a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,} → [REDACTED]
  IPs: \b(?:\d{1,3}\.){3}\d{1,3}\b → [INTERNAL_IP] or [REDACTED]
  Internal hostnames: *.internal.*, *.local.* → [INTERNAL_HOST]

SANITIZATION COMMANDS:
  # Sanitize HAR file
  $har = Get-Content "evidence/PKG-FIND-001/capture.har" -Raw | ConvertFrom-Json
  $har.log.entries | ForEach-Object {
    $_.request.headers | Where-Object { $_.name -match "Cookie|Authorization|X-Api-Key|X-Token" } | ForEach-Object {
      $_.value = "[REDACTED]"
    }
    $_.request.url = $_.request.url -replace '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[REDACTED]'
  }
  $har | ConvertTo-Json -Depth 10 | Set-Content "reports/sanitized/FIND-001/capture.har"

  # Sanitize curl command
  $curl = Get-Content "evidence/PKG-FIND-001/request.curl" -Raw
  $sanitized = $curl -replace '-H "Authorization: Bearer [^"]+"', '-H "Authorization: Bearer [REDACTED]"'
  $sanitized = $sanitized -replace '-H "Cookie: [^"]+"', '-H "Cookie: [REDACTED]"'
  $sanitized | Set-Content "reports/sanitized/FIND-001/request.curl"
```

### 3.2 Sanitization Checklist

```
PER-FINDING SANITIZATION:
  [ ] HAR file sanitized
  [ ] Request body sanitized
  [ ] Response body sanitized
  [ ] Screenshots checked for PII
  [ ] Curl command sanitized
  [ ] URLs with tokens removed or redacted
  [ ] Internal IPs replaced
  [ ] Internal hostnames replaced
  [ ] Email addresses replaced
  [ ] Phone numbers replaced
  [ ] Real user names replaced

FINAL CHECK:
  [ ] Open each file in sanitized folder
  [ ] Verify no sensitive data visible
  [ ] Verify report still reproducible
  [ ] Have second person review if possible
```

---

## 4. CVSS 4.0 Scoring

### 4.1 Task: Calculate CVSS Score

```
TASK ID: RPT-CVSS-001
INPUT: findings/verified/{finding_id}.json
OUTPUT: reports/scored/{finding_id}.json

CVSS 4.0 VECTOR:
  AV:[N/A/L/P] - Attack Vector
  AC:[L/H]     - Attack Complexity
  PR:[N/L/H]   - Privileges Required
  UI:[N/R]     - User Interaction
  S:[U/C]      - Scope
  C:[N/L/H]    - Confidentiality
  I:[N/L/H]    - Integrity
  A:[N/L/H]    - Availability

CVSS CALCULATION:
  Critical: 9.0-10.0
  High: 7.0-8.9
  Medium: 4.0-6.9
  Low: 0.1-3.9
  None: 0.0

COMMON VECTORS:
  SSRF (cloud metadata): AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5 (High)
  IDOR write (ATO): AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8 (High)
  RCE: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 (Critical)
  ATO: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 (Critical)
  Reflected XSS: AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N = 5.4 (Medium)
```

### 4.2 CVSS Calculator

```powershell
function Calculate-CVSS {
  param(
    [string]$AV,
    [string]$AC,
    [string]$PR,
    [string]$UI,
    [string]$S,
    [string]$C,
    [string]$I,
    [string]$A
  )
  
  $scores = @{
    "AV:N" = 0.85; "AV:A" = 0.62; "AV:L" = 0.55; "AV:P" = 0.20
    "AC:L" = 0.77; "AC:H" = 0.44
    "PR:U/N" = 0.85; "PR:U/L" = 0.62; "PR:U/H" = 0.27
    "PR:C/N" = 0.85; "PR:C/L" = 0.68; "PR:C/H" = 0.50
    "UI:N" = 0.85; "UI:R" = 0.62
    "S:U" = 1.0; "S:C" = 1.0
    "C:H" = 0.56; "C:L" = 0.22; "C:N" = 0.00
    "I:H" = 0.56; "I:L" = 0.22; "I:N" = 0.00
    "A:H" = 0.56; "A:L" = 0.22; "A:N" = 0.00
  }
  
  # Simplified calculation (use online calculator for exact score)
  $baseScore = 1.0
  foreach ($key in $scores.Keys) {
    if ($key -match "^$($AV):|^$($AC):|^$($PR):|^$($UI):|^$($S):|^$($C):|^$($I):|^$($A):") {
      $baseScore *= $scores[$key]
    }
  }
  
  return [math]::Round($baseScore, 1)
}

# Example: SSRF cloud metadata
$score = Calculate-CVSS -AV "N" -AC "L" -PR "N" -UI "N" -S "U" -C "H" -I "N" -A "N"
Write-Host "CVSS Score: $score"
```

---

## 5. Impact Statement Writing

### 5.1 Task: Write Impact Statements

```
TASK ID: RPT-IMPACT-001
INPUT: findings/verified/{finding_id}.json
OUTPUT: reports/drafts/{finding_id}-impact.md

IMPACT STATEMENT REQUIREMENTS:
  [ ] Specific, not vague
  [ ] Quantified where possible
  [ ] Business impact included
  [ ] Technical accuracy maintained
  [ ] No theoretical language ("could potentially")
  [ ] Clear severity justification

IMPACT STATEMENT EXAMPLES:

GOOD (Specific):
  "An attacker can access AWS IAM credentials via SSRF to
   169.254.169.254. This grants temporary access to the
   AWS account with the permissions of the example-role,
   which includes S3 read access to customer data buckets."

BAD (Vague):
  "An attacker could potentially access internal resources
   which might lead to data exposure depending on the
   internal network configuration."

GOOD (Quantified):
  "The PUT endpoint allows modifying any user's email
   address. Combined with the password reset flow, this
   enables full account takeover of any user in the system
   (estimated 100,000+ accounts affected)."

BAD (Unquantified):
  "An attacker can modify user data which is bad."
```

### 5.2 Impact Statement Templates

```
SSRF IMPACT:
  "The {endpoint} endpoint is vulnerable to Server-Side
   Request Forgery (SSRF). An unauthenticated attacker can
   make the server request arbitrary URLs, including internal
   services and cloud metadata endpoints. This has been
   confirmed by retrieving {specific_data} from
   {internal_target}. Impact: {severity}."

IDOR IMPACT:
  "The {endpoint} endpoint allows accessing/modifying
   {resource_type} belonging to other users by manipulating
   the {id_parameter} parameter. An attacker with a valid
   account can access sensitive data from any user account,
   including {data_types}. Impact: {severity}."

JWT IMPACT:
  "The JWT implementation accepts tokens with
   {vulnerability_type}, allowing an attacker to forge
   arbitrary tokens. By forging a token with
   {privileged_claims}, an attacker gains {access_level}.
   Impact: {severity}."
```

---

## 6. Report Structuring

### 6.1 Task: Structure Report

```
TASK ID: RPT-STRUCTURE-001
INPUT: Aggregated findings + sanitized evidence
OUTPUT: reports/{target}-{date}.md

REPORT STRUCTURE:
  1. Title
  2. Summary/Overview
  3. Vulnerability Details (per finding)
     a. Title
     b. Severity
     c. CVSS Score
     d. Affected Endpoint
     e. Description
     f. Impact
     g. Reproduction Steps
     h. Evidence References
     i. Remediation
  4. Appendix (raw requests/responses)

REPORT COMPONENTS CHECKLIST:
  [ ] Title is clear and descriptive
  [ ] Summary explains overall security posture
  [ ] Each finding has all required sections
  [ ] CVSS score included for each finding
  [ ] Reproduction steps are numbered
  [ ] Technical detail is sufficient
  [ ] Impact is clearly stated
  [ ] Remediation is actionable
```

### 6.2 Report Template

```markdown
# Security Assessment Report: example.com

**Date:** 2026-06-07
**Assessor:** [Your Name]
**Target:** example.com
**Scope:** *.example.com
**Total Findings:** 5 (2 Critical, 2 High, 1 Medium)

## Executive Summary

During the security assessment of example.com, [N] vulnerabilities
were identified across [N] bug classes. The most severe findings
include [brief description of critical findings].

## Vulnerability Details

### [1] SSRF on /api/avatar Leads to AWS Metadata Access

**Severity:** High
**CVSS:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
**Endpoint:** POST /api/avatar (url parameter)

**Description:**
The avatar endpoint accepts a URL parameter and makes server-side
HTTP requests without validating the destination. This allows
Server-Side Request Forgery (SSRF) to internal services and cloud
metadata endpoints.

**Impact:**
An unauthenticated attacker can access AWS instance metadata at
169.254.169.254, retrieving IAM role credentials. This grants
temporary access to AWS services with the permissions of the
compromised IAM role.

**Reproduction Steps:**
1. Send POST request to /api/avatar with url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
2. Observe IAM role credentials in response
3. Use credentials to access AWS API

**Evidence:**
- Screenshot 1: AWS metadata response
- Screenshot 2: IAM credentials highlighted
- HAR: capture.har
- Curl: request.curl

**Remediation:**
1. Implement URL allowlist for avatar service
2. Block RFC1918 and link-local IP ranges
3. Block cloud metadata endpoints (169.254.169.254)
4. Use network segmentation
```

---

## 7. Platform-Specific Formatting

### 7.1 HackerOne Format

```
HACKERONE FORMAT:

TITLE FORMAT:
  [Bug Class] in [Endpoint] leads to [Impact]
  Example: SSRF in /api/avatar leads to AWS Metadata Access

REQUIRED SECTIONS:
  - Summary
  - Description (what, where, how)
  - Steps To Reproduce (numbered)
  - Impact (what can attacker do)
  - CVSS (include vector string)

CWE: Include CWE ID (e.g., CWE-918 for SSRF)

ATTACHMENTS:
  - Screenshots (PNG, JPG)
  - HAR files
  - Curl commands (in code blocks)
```

### 7.2 Bugcrowd Format

```
BUGCROWD FORMAT:

VRT CATEGORY:
  Select appropriate VRT category
  - Server-Side Request Forgery (SSRF) → Code Injection
  - IDOR → Access Control
  - JWT → Authentication

TITLE FORMAT:
  [Bug Class] - [Endpoint] - [Impact]

REQUIRED SECTIONS:
  - Severity (with VRT override rationale if needed)
  - Description
  - Steps to Reproduce
  - Impact
  - Supporting Materials

SEVERITY OVERRIDE:
  If VRT default is wrong, include in first paragraph:
  "Note: The VRT suggests [severity], but this finding should
   be [correct severity] because [rationale]."

ATTACHMENTS:
  - Screenshots
  - Video (if applicable)
  - Curl/PoC scripts
```

### 7.3 Intigriti Format

```
INTIGRITI FORMAT:

TITLE FORMAT:
  [Bug Class] on [Target] via [Endpoint]

REQUIRED SECTIONS:
  - Summary
  - Description
  - Reproduction
  - Impact
  - Remediation
  - CVSS

ATTACHMENTS:
  - Screenshots
  - Proof of concept
```

---

## 8. Triage Defense Preparation

### 8.1 Task: Prepare Triage Defense

```
TASK ID: RPT-TRIAGE-001
INPUT: Report draft
OUTPUT: reports/{target}-{date}-triage-defense.md

COMMON TRIAGE OBJECTIONS:
  1. "This is out of scope"
     Defense: Reference scope rules, show in-scope domain

  2. "This is a duplicate"
     Defense: Show difference in endpoint/parameter/technique

  3. "Severity is too high"
     Defense: Show CVSS calculation, justify impact

  4. "User interaction required"
     Defense: Show attacker can trigger directly

  5. "This is a configuration issue, not a bug"
     Defense: Reference OWASP, CWE classification

  6. "This affects test data only"
     Defense: Show production impact, data sensitivity

  7. "We don't consider this a vulnerability"
     Defense: Reference CWE, OWASP, industry standards

TRIAGE DEFENSE TEMPLATE:
  OBJECTION: "[Common objection]"
  RESPONSE: "[Your defense with evidence]"
  EVIDENCE: "[Reference to report section]"
```

### 8.2 Triage Defense Commands

```powershell
# Generate triage defense document
$findingId = "FIND-001"
$triageDefense = @"
# Triage Defense: $findingId

## Potential Objections

### "Out of Scope"
**Defense:** api.example.com is explicitly listed in the in-scope
domains as part of the *.example.com wildcard.

### "Duplicate of previous report"
**Defense:** Previous report (H1-123456) covered /api/fetch with
basic SSRF. This finding is on /api/avatar with cloud metadata
access, which is a different endpoint with higher impact.

### "Severity is too high"
**Defense:** CVSS 7.5 (High) is justified by confirmed cloud
metadata access. If IAM role has broad permissions, this escalates
to Critical. See impact demonstration section.
"@

$triageDefense | Set-Content "reports/$findingId-triage-defense.md"
```

---

## 9. Report Templates

### 9.1 Standard Report Template

```markdown
# [Bug Class] in [Endpoint] Leads to [Impact]

**Reporter:** [Name]
**Target:** [Domain]
**Severity:** [Critical/High/Medium/Low]
**CVSS:** [Score] ([Vector])
**CWE:** [CWE-ID]

## Summary

[One paragraph summary of the vulnerability and its impact.]

## Description

[Detailed description of the vulnerability, affected component,
and root cause.]

## Steps To Reproduce

1. [First step]
2. [Second step]
3. [Third step]

## Impact

[Clear statement of what an attacker can achieve.]

## Supporting Materials

- [Screenshot description]
- [HAR file]
- [Curl command]

## Remediation

[Specific, actionable remediation steps.]

## Timeline

- [Date]: Vulnerability discovered
- [Date]: Report submitted
- [Date]: Triaged
- [Date]: Fixed
- [Date]: Bounty awarded
```

---

## 10. Submission Workflow

### 10.1 Pre-Submission Checklist

```
PRE-SUBMISSION CHECKLIST:
  [ ] Report written in clear, human language
  [ ] Impact-first structure
  [ ] Reproduction steps are numbered and clear
  [ ] Technical detail is included
  [ ] Payload/request included
  [ ] Screenshots attached and sanitized
  [ ] HAR file attached and sanitized (if applicable)
  [ ] CVSS score included
  [ ] Chain information (if applicable)
  [ ] Program-specific fields filled (VRT, etc.)
  [ ] No PII visible
  [ ] Test account info included (not real users)
  [ ] Triage defense prepared
  [ ] Peer reviewed (if possible)
```

### 10.2 Submission Commands

```powershell
# HackerOne submission
$report = Get-Content "reports/FIND-001.md" -Raw
gh api graphql -f query='
mutation {
  reportSubmission(input: {
    report_id: "REPORT_ID"
    content: "' + $report.Replace('"', '\"') + '"
    attachments: []
  }) {
    id
  }
}
'

# Bugcrowd submission
$submission = @{
  target = "example.com"
  vrt_category = "SSRF"
  severity = "High"
  title = "SSRF in /api/avatar leads to AWS Metadata"
  description = (Get-Content "reports/FIND-001.md" -Raw)
} | ConvertTo-Json
Invoke-RestMethod -Uri "https://api.bugcrowd.com/submissions" -Method POST -Body $submission -ContentType "application/json"
```

---

## 11. Post-Submission Tasks

### 11.1 Task: Track Submission

```
TASK ID: RPT-TRACK-001
INPUT: Submission confirmation
OUTPUT: findings-archive.md, target-registry.md

POST-SUBMISSION:
  [ ] Record submission in findings-archive.md
  [ ] Record submission in target-registry.md
  [ ] Note submission URL/reference
  [ ] Set reminder for triage follow-up (7 days)
  [ ] Update report status

FOLLOW-UP SCHEDULE:
  Day 3: Check if triaged
  Day 7: If not triaged, send polite follow-up
  Day 14: If still not triaged, escalate if needed
  Day 30: If unresolved, consider program quality

IF REJECTED:
  [ ] Review rejection reason carefully
  [ ] Determine if finding can be improved
  [ ] If kill reason valid: learn and move on
  [ ] If kill reason invalid: prepare rebuttal
  [ ] Document lesson learned
```

---

## 12. Maintenance

### 12.1 Report Quality Maintenance

```
DAILY:
  [ ] Archive submitted reports
  [ ] Update submission tracker
  [ ] Review triage feedback

WEEKLY:
  [ ] Review report success rate
  [ ] Update report templates based on feedback
  [ ] Improve impact statement quality
  [ ] Review rejection reasons for patterns

MONTHLY:
  [ ] Full report quality review
  [ ] Update templates based on platform changes
  [ ] Review bounty statistics
  [ ] Archive old reports
```

### 12.2 Report Success Tracking

```
| Report ID | Target | Bug Class | Severity | Submitted | Triaged | Bounty | Status |
|-----------|--------|-----------|----------|-----------|---------|--------|-------|
| RPT-001 | example.com | SSRF | High | 2026-06-07 | 2026-06-10 | $500 | Triaged |
| RPT-002 | example.com | IDOR | Critical | 2026-06-07 | 2026-06-09 | $2000 | Triaged |
| RPT-003 | test.com | XSS | Medium | 2026-06-06 | — | — | Pending |

SUCCESS METRICS:
  Triaged: [N]%
  Bountied: [N]%
  Rejected: [N]%
  Average bounty: $[N]
```

---

*End of report-generation.md*
