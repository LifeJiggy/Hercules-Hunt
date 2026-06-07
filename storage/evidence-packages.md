# Storage — Evidence Packages

Central registry for all evidence packages created during hunting sessions.
Each evidence package contains screenshots, HAR files, request/response pairs,
and supporting materials for a submitted or in-progress finding.

---

## Table of Contents

1. [Package Overview](#1-package-overview)
2. [Active Packages](#2-active-packages)
3. [Package Standards](#3-package-standards)
4. [Screenshot Inventory](#4-screenshot-inventory)
5. [HAR File Index](#5-har-file-index)
6. [Request/Response Archive](#6-requestresponse-archive)
7. [Package Validation](#7-package-validation)
8. [Archive & Cleanup](#8-archive--cleanup)
9. [Templates](#9-templates)

---

## 1. Package Overview

### 1.1 Current State

```
TOTAL PACKAGES: [N]
  - Complete & Submitted: [N]
  - In Progress: [N]
  - Pending Validation: [N]
  - Failed Validation: [N]

TOTAL SCREENSHOTS: [N]
TOTAL HAR FILES: [N]
TOTAL STORAGE SIZE: [N] MB
```

### 1.2 Package ID Format

```
PACKAGE ID FORMAT: PKG-YYYYMMDD-XXX
  YYYYMMDD: Date of package creation
  XXX:      Sequential number

Example: PKG-20260607-001
```

### 1.3 Package Structure

Every evidence package follows this directory structure:

```
evidence/PKG-YYYYMMDD-XXX/
├── screenshots/
│   ├── 001-request.png
│   ├── 002-response.png
│   ├── 003-auth-proof.png
│   └── 004-impact.png
├── har/
│   └── finding-request.har
├── requests/
│   ├── request-1.txt
│   └── request-2.txt
├── responses/
│   ├── response-1.json
│   └── response-2.json
├── README.md
└── validation-checklist.md
```

---

## 2. Active Packages

### 2.1 Currently Active

```
| Package ID | Finding | Target | Status | Created | Screenshots |
|------------|---------|--------|--------|---------|-------------|
| PKG-20260607-001 | SSRF cloud metadata | example.com | In Progress | 2026-06-07 | 2/4 |
| PKG-20260606-001 | IDOR write ATO | example.com | Validating | 2026-06-06 | 4/4 |
| PKG-20260605-001 | JWT alg:none | example.com | Pending | 2026-06-05 | 1/4 |
```

### 2.2 Active Package Details

```
PACKAGE PKG-20260607-001
  Finding: SSRF via /api/avatar — cloud metadata access
  Target:  api.example.com
  Severity: High (potential Critical if IAM chain)
  Status:  In Progress
  Created: 2026-06-07 10:30

  Screenshots:
    [x] 001 — Request showing SSRF payload to 169.254.169.254
    [x] 002 — Response showing metadata received (200 OK with data)
    [ ] 003 — Burp Repeater showing full request/response
    [ ] 004 — Impact demonstration (IAM credentials in response)

  HAR Files:
    [ ] 001 — Full request/response chain

  Validation:
    [ ] 7-Question Gate passed
    [ ] Reproduced 3x with different sessions
    [ ] Non-replayable (token requires victim context)
    [ ] Impact demonstrated

  Package File: evidence/PKG-20260607-001/
```

---

## 3. Package Standards

### 3.1 Screenshot Standards

Each screenshot must meet these quality standards:

```
STANDARD                   | REQUIREMENT                          | CHECK
---------------------------|--------------------------------------|------
Resolution                 | 1920x1080 minimum                    | [ ]
URL bar visible            | Full URL with protocol and domain    | [ ]
Full browser window        | Not cropped to hide context          | [ ]
Burp/DevTools visible      | Response and request visible         | [ ]
Timestamps                 | Shows when PoC was performed         | [ ]
Redaction                  | PII, cookies, tokens covered         | [ ]
Annotations                | Key findings highlighted              | [ ]
No blur                    | Only solid black bars for redaction  | [ ]
Readable text              | Font size must be readable           | [ ]
Color                     | Not grayscale (unless intentional)    | [ ]
```

### 3.2 Screenshot Naming Convention

```
NNN-description.ext

  001 — 009:  Request setup/configuration
  010 — 019:  Request sent
  020 — 029:  Response received
  030 — 039:  Impact demonstration
  040 — 049:  Auth/user context proof
  050 — 059:  Chain/primitive evidence
  060 — 069:  Validation/reproduction
  070 — 079:  Tool configuration
  080 — 089:  Environment/scope proof
  090 — 099:  Miscellaneous

Examples:
  001-request-burp-repeater.png
  010-request-ssrf-payload.png
  020-response-metadata.png
  030-impact-iam-credentials.png
  040-auth-attacker-token.png
```

### 3.3 HAR File Standards

```
HAR FILE NAMING: finding-description.har

HAR REQUIREMENTS:
  [ ] Only relevant requests included
  [ ] Sensitive headers redacted (Cookie, Authorization)
  [ ] File size < 5MB
  [ ] Valid JSON format
  [ ] Request and response bodies included
  [ ] Timing information preserved
  [ ] Can be replayed in Burp Repeater
```

### 3.4 Cookie Redaction Protocol

When capturing evidence with authenticated sessions:

```
BEFORE CAPTURE:
  1. Set browser to Incognito/Private mode
  2. Login with test account
  3. Verify DevTools Console is clean
  4. Clear any previous session traces

IN SCREENSHOTS:
  1. Cookie values: Cover with black rectangle
  2. Authorization headers: Cover with black rectangle
  3. JWT tokens: Cover with black rectangle
  4. Session IDs: Cover with black rectangle
  5. Do NOT blur — use solid black bars only

HAR FILE REDACTION (using jq):
  jq 'del(.log.entries[].request.cookies[]?.value) |
    del(.log.entries[].response.cookies[]?.value) |
    del(.log.entries[].request.headers[] | select(.name == "Cookie" or .name == "Authorization" | .value))'
    input.har > sanitized.har
```

### 3.5 PII Redaction Guidelines

```
MASK WITH BLACK BAR:
  - Other user email addresses
  - Other user names
  - Phone numbers
  - Credit card numbers
  - Personal addresses
  - Profile photos containing faces
  - API keys / tokens

SAFE TO LEAVE (NOT PII):
  - Usernames (test accounts)
  - Trace IDs
  - Request IDs
  - Server names
  - IP addresses (public)
  - Error messages
  - Stack traces
  - Timestamps
```

---

## 4. Screenshot Inventory

### 4.1 All Screenshots

```
| File | Package | Finding | Date | Status |
|------|---------|---------|------|--------|
| PKG-20260607-001/001-request.png | PKG-20260607-001 | SSRF proof | 2026-06-07 | Captured |
| PKG-20260607-001/002-response.png | PKG-20260607-001 | SSRF proof | 2026-06-07 | Captured |
| PKG-20260606-001/001-request.png | PKG-20260606-001 | IDOR proof | 2026-06-06 | Submitted |
| PKG-20260606-001/002-response.png | PKG-20260606-001 | IDOR proof | 2026-06-06 | Submitted |
| PKG-20260606-001/003-auth.png | PKG-20260606-001 | Auth context | 2026-06-06 | Submitted |
| PKG-20260606-001/004-impact.png | PKG-20260606-001 | Impact demo | 2026-06-06 | Submitted |
```

### 4.2 Screenshot Quality Review

Before submission, each screenshot must pass this review:

```
SCREENSHOT PKG-20260607-001/001-request.png
  Resolution:        [x] 1920x1080
  URL visible:       [x] Yes — shows api.example.com
  Full window:       [x] Yes
  Burp visible:      [x] Yes — Repeater tab
  Timestamps:        [x] Yes
  PII redacted:      [x] Yes — token covered
  Annotations:       [x] Yes — SSRF payload highlighted
  Blur used:         [ ] No — solid bars only
  Final check:       [x] PASS

SCREENSHOT PKG-20260607-001/002-response.png
  Resolution:        [x] 1920x1080
  URL visible:       [x] Yes
  Full window:       [x] Yes
  Burp visible:      [x] Yes
  Timestamps:        [x] Yes
  PII redacted:      [x] Yes
  Annotations:       [x] Yes — metadata content circled
  Blur used:         [ ] No
  Final check:       [x] PASS
```

### 4.3 Screenshot Dimensions Reference

```
PLATFORM       | OS/SCREEN      | RESOLUTION      | ASPECT RATIO
---------------|----------------|-----------------|-------------
Windows        | 1920x1080      | Full HD         | 16:9
Windows        | 2560x1440      | QHD             | 16:9
Windows        | 3840x2160      | 4K UHD          | 16:9
macOS          | 1440x900       | Standard        | 16:10
macOS          | 2880x1800      | Retina          | 16:10
Linux          | 1920x1080      | Full HD         | 16:9

MINIMUM: 1920x1080 — lower resolutions may be rejected
PREFERRED: 1920x1080 (most common, safest)
```

### 4.4 Burp Suite Screenshot Tips

```
BURP REPEATER SCREENSHOT:
  1. Ensure Request and Response panels are both visible
  2. Resize panels to show full payload in request
  3. Highlight vulnerability-relevant portion of response
  4. Hide request body if not relevant (less clutter)
  5. Confirm the URL at top shows full target
  6. Check that the HTTP method and path are visible
  7. Capture the response status code clearly
  8. Include response headers if relevant

BURP INTRUDER SCREENSHOT:
  1. Show the Results table (not the request/response)
  2. Sort by Status or Length to highlight anomalies
  3. Limit to first 10-15 results (scrolling makes it hard to read)
  4. Annotate the anomalous result with a red box
```

### 4.5 Chrome DevTools Screenshot Tips

```
DEVTOOLS NETWORK TAB:
  1. Ensure Preserve Log is checked if redirects are involved
  2. Clear the log before capturing the target request
  3. Click on the request to show Headers + Preview/Response
  4. Check that cookies are properly included in the request
  5. Use console.log() with labels for key data points
  6. Include credentials in the request so cookies don't need
     to be echoed separately

DEVTOOLS CONSOLE TAB:
  1. Clear console before the PoC
  2. Use console.log("Label:", data) for clear output
  3. Show the same data from multiple angles if needed
  4. Capture full console output, not just the relevant line
```

---

## 5. HAR File Index

### 5.1 HAR Files

```
| File | Package | Finding | Size | Sanitized |
|------|---------|---------|------|-----------|
| evidence/PKG-20260606-001/har/idor-write.har | PKG-20260606-001 | IDOR ATO | 245KB | Yes |
| evidence/PKG-20260605-001/har/ssrf-callback.har | PKG-20260605-001 | SSRF | 180KB | Yes |
```

### 5.2 HAR Sanitization Log

```
HAR: idor-write.har
  Original size: 312KB
  Sanitized size: 245KB
  Sanitized by: jq filter
  Headers redacted:
    - Cookie (3 entries)
    - Authorization (1 entry)
    - X-CSRF-Token (1 entry)
  Verification: HAR re-imported to Burp — functions correctly
```

### 5.3 HAR Sanitization Commands

```powershell
# Basic cookie/authorization redaction
jq 'del(.log.entries[].request.cookies[]?.value) |
    del(.log.entries[].response.cookies[]?.value) |
    del(.log.entries[].request.headers[] | select(.name == "Cookie" or .name == "Authorization") .value) |
    del(.log.entries[].response.headers[] | select(.name == "Set-Cookie") .value)' 
    input.har > sanitized.har

# Aggressive — remove all request header values (preserves structure)
jq 'del(.log.entries[].request.headers[].value) | 
    del(.log.entries[].request.cookies[].value) |
    del(.log.entries[].response.cookies[].value)' 
    input.har > sanitized.har

# Validate JSON after sanitization
jq '.' sanitized.har > /dev/null 2>&1 && echo "Valid HAR" || echo "Invalid HAR"
```

---

## 6. Request/Response Archive

### 6.1 Stored Requests

```
| File | Package | Method | URL | Status |
|------|---------|--------|-----|--------|
| requests/idor-put.txt | PKG-20260606-001 | PUT | /api/v2/users/4242/profile | Submitted |
| requests/ssrf-post.txt | PKG-20260607-001 | POST | /api/avatar | Active |
| requests/jwt-none.txt | PKG-20260605-001 | GET | /api/admin/dashboard | Pending |
```

### 6.2 Request Format

Stored requests follow this format for reproducibility:

```
### Request: [Description]
### Package: PKG-YYYYMMDD-XXX
### Date: YYYY-MM-DD HH:MM
### Tool: Burp Repeater / curl / Python

METHOD /path HTTP/1.1
Host: target.com
Authorization: Bearer [TOKEN]
Content-Type: application/json
User-Agent: Mozilla/5.0 [...]
Accept: application/json

{"key": "value"}
```

### 6.3 Response Format

```
### Response: [Description]
### Package: PKG-YYYYMMDD-XXX
### Date: YYYY-MM-DD HH:MM
### Status: 200 OK

{
  "key": "value",
  "sensitive_data": "HERE IS THE PROOF"
}
```

---

## 7. Package Validation

### 7.1 Pre-Submission Checklist

Before submitting any evidence package:

```
PACKAGE PKG-20260607-001 VALIDATION:
  [ ] 1. At least 2 screenshots showing the vulnerability
  [ ] 2. Screenshots include the URL bar
  [ ] 3. Screenshots include the full browser window
  [ ] 4. Request and response both clearly visible
  [ ] 5. No PII visible in any screenshot
  [ ] 6. No session tokens visible in any screenshot
  [ ] 7. Annotations highlight the vulnerable parameter
  [ ] 8. Impact is demonstrated in at least one screenshot
  [ ] 9. HAR file is sanitized (no tokens/cookies)
  [ ] 10. HAR file can be replayed
  [ ] 11. Finding passes 7-Question Gate
  [ ] 12. Finding passes 4-Gate Checklist
  [ ] 13. Bug class is not on the always-rejected list
  [ ] 14. Chain potential is documented (if applicable)
  [ ] 15. Reproduction steps are written and verified
  [ ] 16. Screenshots are in PNG format
  [ ] 17. File names follow naming convention
  [ ] 18. Package README is complete

FINAL VERDICT: [PASS / FAIL — reason]
```

### 7.2 Package README Template

```
# Evidence Package: PKG-YYYYMMDD-XXX

## Finding Summary
- Bug Class: [SSRF / IDOR / XSS / etc.]
- Severity: [Critical / High / Medium / Low]
- Target: [domain]
- Endpoint: [URL]

## Contents
- screenshots/: [N] screenshots
- har/: [N] HAR files
- requests/: [N] request files
- responses/: [N] response files

## Reproduction
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Impact
[Description of impact]

## Validation
- [x] 7-Question Gate passed
- [x] 4-Gate Checklist passed
- [x] Reproduced 3x

## Notes
[Any additional context]
```

### 7.3 Package Repair Log

When a package fails validation, log the fix:

```
PACKAGE PKG-20260605-001 — REPAIR LOG
  Issue: Missing impact screenshot
  Fix: Captured screenshot showing admin dashboard access
  Date: 2026-06-06
  Status: Resolved

PACKAGE PKG-20260605-001 — REPAIR LOG
  Issue: HAR file contained unredacted token
  Fix: Re-sanitized with jq filter
  Date: 2026-06-06
  Status: Resolved
```

---

## 8. Archive & Cleanup

### 8.1 Archive Process

Packages are archived when the finding is resolved (paid, rejected, or withdrawn):

```
ARCHIVE RULES:
  - Paid findings: Archive immediately after payout
  - Rejected findings: Keep for 30 days, then archive
  - Withdrawn: Keep for 7 days, then archive
  - Triaged (pending): Keep active until resolved

ARCHIVE STORAGE: storage/evidence-archive/
```

### 8.2 Cleanup Schedule

```
DAILY:
  [ ] Remove temporary screenshots (failed captures)
  [ ] Compress large HAR files (>10MB)

WEEKLY:
  [ ] Review package quality (self-audit)
  [ ] Delete duplicate screenshots
  [ ] Update package statuses

MONTHLY:
  [ ] Archive resolved packages
  [ ] Compress old packages to ZIP
  [ ] Delete unreferenced evidence
  [ ] Update total storage size
```

### 8.3 Storage Budget

```
TOTAL BUDGET: 500MB
CURRENT USAGE: [N]MB
REMAINING: [N]MB

PACKAGE SIZE LIMITS:
  Per package: 50MB max
  Per screenshot: 5MB max
  Per HAR file: 10MB max
```

---

## 9. Templates

### 9.1 New Package Template

```
PACKAGE REGISTRATION:
  ID:       PKG-YYYYMMDD-XXX
  Finding:  [bug class] — [brief description]
  Target:   [domain]
  Severity: [Critical / High / Medium / Low]
  Created:  YYYY-MM-DD HH:MM
  Status:   New

  Required Screenshots:
    [ ] 001 — Request setup
    [ ] 002 — Response showing vulnerability
    [ ] 003 — Auth/user context
    [ ] 004 — Impact demonstration

  Required Files:
    [ ] HAR file of the request/response
    [ ] Request text file
    [ ] Response text file
```

### 9.2 Package Completion Certificate

```
EVIDENCE PACKAGE COMPLETION CERTIFICATE
========================================

Package ID:   PKG-YYYYMMDD-XXX
Finding:      [bug class] — [description]
Target:       [domain]
Severity:     [severity]
Created:      YYYY-MM-DD
Completed:    YYYY-MM-DD
Submitted:    YYYY-MM-DD

Contents Verification:
  [x] 4 screenshots captured and reviewed
  [x] HAR file captured and sanitized
  [x] Request file saved
  [x] Response file saved
  [x] Validation checklist completed
  [x] Pre-submission checklist completed
  [x] All PII redacted
  [x] All tokens redacted

Final Size:   [N]MB
Validator:    [name]

STATUS: [COMPLETE / INCOMPLETE]
```

---

*End of evidence-packages.md*
