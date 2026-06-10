# Task Persistence — Finding Dossier

Per-finding lifecycle tracker. Each confirmed or in-progress finding gets one dossier that tracks state from discovery through submission and triage, with all evidence, validation, and reporting artifacts linked.

---

## 1. Dossier Structure

```
task-presistence/finding-dossiers/
├── FIND-001-ssrf-cloud-metadata.md
├── FIND-002-jwt-alg-none.md
├── FIND-003-idor-write-ato.md
└── ...
```

Create one file per finding. Name format: `FIND-NNN-bug-class-short-description.md`

---

## 2. Finding Lifecycle

```
DISCOVERY → CONFIRMATION → VALIDATION → EVIDENCE → REPORT → SUBMISSION → TRIAGE → CLOSE
      ↑           ↑            ↑          ↑         ↑         ↑          ↑        ↑
   suspected    confirmed    passed      complete   written   submitted   paid   final
```

### Lifecycle Stages

| Stage | Description | Exit Criteria |
|---|---|---|
| DISCOVERY | Initial signal observed | Reproduced at least once |
| CONFIRMATION | Reproduced consistently | 3 successful runs |
| VALIDATION | 7-Question Gate applied | All questions answered YES |
| EVIDENCE | All screenshots, requests, responses saved | Package complete + redacted |
| REPORT | Report drafted and reviewed | Meets program policy |
| SUBMISSION | Submitted to platform | Ticket number received |
| TRIAGE | Awaiting triage response | Triaged |
| CLOSE | Resolved / paid / N/A | Final status recorded |

---

## 3. Dossier Template

Use this template for each finding:

```markdown
---
id: FIND-NNN
bug_class: [SSRF / IDOR / JWT / XSS / ...]
severity: [Critical / High / Medium / Low]
target: [domain]
program: [platform name]
status: [discovery / confirmation / validation / evidence / report / submission / triage / closed]
created: YYYY-MM-DD
submitted: [YYYY-MM-DD or null]
triage_status: [pending / triaged / paid / N/A / dup]
estimated_value: $[N]
actual_value: $[N or null]
researcher: [your handle]
---

# FIND-NNN: [Title]

## Summary

[One paragraph: what you found, how, impact]

## Bug Class

[SSRF / IDOR / JWT / XSS / ...]

## Severity

[CVSS 4.0 score + rating, e.g., 9.3 Critical]

## Target

- Domain: [domain]
- Program: [name]
- Scope status: [in-scope confirmed]

## Timeline

| Date | Event |
|---|---|
| YYYY-MM-DD | Discovered during [session/recon] |
| YYYY-MM-DD | Confirmed (3x reproduction) |
| YYYY-MM-DD | Validation passed (7-Question Gate) |
| YYYY-MM-DD | Evidence captured |
| YYYY-MM-DD | Report written |
| YYYY-MM-DD | Submitted (H1-XXXXX / BC-XXXX / etc.) |
| YYYY-MM-DD | Triaged [severity] |
| YYYY-MM-DD | Paid $[N] |

## Reproduction Steps

1. [step 1]
2. [step 2]
3. [step 3]

## Request

```
[raw request text]
```

## Response

```
[raw response text]
```

## Evidence Package

Package ID: PKG-YYYYMMDD-NNN

- [ ] Request saved: `requests/[id].txt`
- [ ] Response saved: `responses/[id].json`
- [ ] Screenshot 1: [description] — `evidence/[id]-01.png`
- [ ] Screenshot 2: [description] — `evidence/[id]-02.png`
- [ ] Screenshot 3: [description] — `evidence/[id]-03.png`
- [ ] Screenshot 4: [description] — `evidence/[id]-04.png`
- [ ] HAR: [yes/no]
- [ ] Video: [yes/no]

## 7-Question Gate Results

| Question | Answer | Notes |
|---|---|---|
| Q1: Reproducible 3 times? | YES / NO | |
| Q2: Real impact, not theoretical? | YES / NO | |
| Q3: In scope? | YES / NO | |
| Q4: No PII exfiltrated? | YES / NO | |
| Q5: No service disruption? | YES / NO | |
| Q6: Not already reported? | YES / NO | Checked H1 Hacktivity |
| Q7: Meets program policy? | YES / NO | |

RESULT: [PASS / KILL / DOWNGRADE / CHAIN REQUIRED]

## Impact

[What an attacker can do with this. Concrete, not theoretical.]

- Impact 1: [specific harm]
- Impact 2: [specific harm]
- Blast radius: [number of users / systems affected]

## Remediation

[What the target should fix — keep brief]

1. [fix 1]
2. [fix 2]

## Report

Report file: `reports/FIND-NNN-report.md`
HackerOne ticket: H1-XXXXX
Status: [draft / submitted / triaged / paid / closed]

## Notes

[Free-form notes, lessons learned, similar endpoints to check, etc.]
```

---

## 4. Finding Status Rules

### Status Definitions

| Status | Meaning | Allowed Next Statuses |
|---|---|---|
| `discovery` | Initial signal, needs confirmation | confirmation, killed |
| `confirmation` | Reproduced once or twice | validation, killed |
| `validation` | 7-Question Gate applied | evidence, killed, downgraded |
| `evidence` | Capturing evidence package | report, validation (if missing evidence) |
| `report` | Report drafted | submission, evidence (if screenshots missing) |
| `submission` | Submitted to platform | triage, report (if submission rejected) |
| `triage` | Awaiting / received triage | closed |
| `closed` | Final state | none |

### Killed Findings

```
KILLED: FIND-NNN
  Reason: [why it was killed]
  Killed at stage: [which stage]
  Lessons: [what to remember for next time]
```

Still archive the dossier. Killed findings teach pattern recognition.

---

## 5. Evidence Package Standards

Each finding must have:

| Artifact | Required | Location |
|---|---|---|
| Raw request | Yes | `requests/FIND-NNN.txt` |
| Raw response | Yes | `responses/FIND-NNN.json` |
| Screenshot request | Yes | `evidence/FIND-NNN-01.png` |
| Screenshot response | Yes | `evidence/FIND-NNN-02.png` |
| Screenshot impact | Yes | `evidence/FIND-NNN-03.png` |
| Screenshot context | Yes | `evidence/FIND-NNN-04.png` |
| HAR | Conditional | `evidence/FIND-NNN.har` |
| Video | Optional | `evidence/FIND-NNN.webm` |

### Redaction Rules

```
MUST REDACT (100% black bar):
  - API keys, tokens, secrets
  - Passwords, credentials
  - PII: names, emails, phone numbers, addresses
  - Session cookies
  - Internal IPs not part of the vulnerability

MAY KEEP:
  - Target domain name
  - Public endpoint paths
  - Status codes
  - Error messages not containing secrets
```

---

## 6. Validation Checklist (7-Question Gate)

Before any finding moves to evidence/report stage:

```
Q1: REPRODUCIBLE
  [ ] Reproduced 3 times from clean state
  [ ] Each reproduction used fresh session
  [ ] Same result every time

Q2: REAL IMPACT
  [ ] Impact is concrete (data accessed, account taken over, etc.)
  [ ] NOT "could potentially" or "might allow"
  [ ] Demonstrated with real data

Q3: IN SCOPE
  [ ] Target confirmed in program scope
  [ ] Asset type is in-scope (not excluded CDN/WAF)
  [ ] Testing was within safe-harbor terms

Q4: NO PII EXFILTRATION
  [ ] No real user PII in evidence
  [ ] No real credentials stored
  [ ] Test accounts used only

Q5: NO SERVICE DISRUPTION
  [ ] No DoS, no data deletion beyond PoC scope
  [ ] No rate-limit testing that blocked real users
  [ ] No social engineering of employees

Q6: NOT ALREADY REPORTED
  [ ] Checked HackerOne Hacktivity for target
  [ ] Checked program disclosed reports
  [ ] No public writeup of same vector

Q7: PROGRAM POLICY
  [ ] Meets VRT criteria for claimed severity
  [ ] Not excluded by program policy
  [ ] No testing of out-of-scope assets
```

PASS = all 7 YES
KILL = any NO with no fix possible
DOWNGRADE = some NO but severity can be reduced
CHAIN REQUIRED = standalone impact low, but chains to something stronger

---

## 7. Chaining Decision in Dossier

When a finding is a chain primitive:

```
CHAIN STATUS: [standalone / chain_primitive / chain_complete]

IF standalone:
  Impact: [assessed severity]
  Submit as-is if passes 7-Question Gate

IF chain_primitive:
  Primary bug: [what this finding is]
  Chain target: [what it connects to]
  Estimated chain severity: [higher severity if chained]
  Action: Hunt for second link before submitting

IF chain_complete:
  Chain: [A → B → C]
  Primary: [A]
  Secondary: [B, C]
  Final impact: [P0 / Critical]
  Submit complete chain as single report
```

---

## 8. Triage Tracking

### Expected vs Actual

```
TRIAGE RECORD:
  Submitted:     YYYY-MM-DD
  Platform:      [HackerOne / Bugcrowd / Intigriti]
  Ticket:        H1-XXXXX
  Claimed severity: [Critical / High / Medium / Low]
  Estimated bounty: $[N]

  Triaged:       YYYY-MM-DD (or null)
  Actual severity: [Critical / High / Medium / Low / N/A]
  Actual bounty:  $[N or null]

  Discrepancy:
    Severity delta: [same / downgraded / upgraded]
    Bounty delta:   $[diff]
    Lessons:        [what to adjust in future CVSS]
```

---

## 9. Finding Dossier Index

Keep a `task-presistence/finding-registry.md` as a flat index:

```
FINDING REGISTRY
================

| ID | Bug Class | Severity | Target | Status | Submitted | Value |
|----|-----------|----------|--------|--------|-----------|-------|
| FIND-001 | SSRF | Critical | example.com | triage | 2026-06-08 | $1,500 est |
| FIND-002 | JWT | Critical | example.com | report | null | $3,000 est |
| FIND-003 | IDOR | High | example.com | closed | 2026-06-06 | $800 est |
| FIND-004 | XSS | Medium | test.com | triage | 2026-06-03 | $500 est |
```

---

## 10. Maintenance

```
FOR EACH FINDING:
  [ ] Update status after every session
  [ ] Update evidence checklist as artifacts are captured
  [ ] Update timeline with new events
  [ ] Close dossier when finding reaches final state

WHEN FINDING IS CLOSED:
  [ ] Mark final status and date
  [ ] Record actual bounty paid
  [ ] Record triage lessons
  [ ] Link to final report URL if public
  [ ] Archive dossier to finding-dossiers/archive/ if desired
```

---

*End of finding-dossier.md*
