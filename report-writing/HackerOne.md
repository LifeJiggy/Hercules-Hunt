---
name: HackerOne
description: HackerOne-specific report writing guide. Platform rules, triage patterns, severity mapping, bounty expectations, and submission optimization for HackerOne bug bounty programs.
---

# HackerOne Report Writing Guide

## Platform Overview

HackerOne is the largest bug bounty platform. Reports are reviewed by HackerOne triagers first, then escalated to program teams. Quality and reproducibility are the #1 factors that determine payout.

---

## Report Format on HackerOne

### Required Fields
- **Title** — displayed in list view (~80 char limit)
- **Vulnerability Type** — dropdown selection
- **CVSS Severity** — auto-calculated or manual vector
- **Description** — main report body (markdown)
- **Attachments** — screenshots, HAR files, Burp exports

### HackerOne Markdown Tips
- Use `###` headers for sections (Summary, Steps, Impact)
- Code blocks with language tags for HTTP requests
- Attach Burp export `.json` for complex multi-step bugs
- Screenshots inline with `![alt](url)` or drag-drop

---

## Severity Mapping

| H1 Severity | CVSS Range | Typical Bugs |
|-------------|-----------|--------------|
| Critical | 9.0-10.0 | Auth bypass → admin, SSRF → cloud metadata, RCE |
| High | 7.0-8.9 | SQLi, IDOR with write/delete, GraphQL auth bypass |
| Medium | 4.0-6.9 | IDOR read PII, stored XSS, CSRF with impact |
| Low | 1.0-3.9 | Open redirect, info disclosure, missing headers |
| None | 0.0 | Informational, out of scope |

**Tip:** HackerOne allows manual CVSS. Always include the full vector string (e.g., `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`) — it gives triagers confidence you understand the impact.

---

## Triage Process

1. **Submitted** → queued for review
2. **Triaged** → HackerOne team confirms validity
3. **Needs More Info** → triager asks questions (respond within 24h)
4. **Escalated** → sent to program team for bounty decision
5. **Resolved** → fixed or marked as informative
6. **Duplicate** → previously reported
7. **Not Applicable** → closed as invalid

### Timelines
- First response: usually 24-72 hours
- Bounty decision: 7-30 days depending on program
- Some programs pay on triage, some on fix

---

## Handling Common H1 Scenarios

### Duplicate Reports
- Search Hacktivity BEFORE submitting
- Search the specific program's disclosed reports
- If marked duplicate but your report covers different impact, explain clearly

### Needs More Info
- Respond within 24 hours or report auto-closes
- Paste exact request/response they ask for
- Keep response concise — don't dump extra info

### Severity Downgrade
- Programs often downgrade (e.g., IDOR High→Medium)
- Counter once with specific evidence, then accept
- Reference similar disclosed reports at same program

### Informational / Won't Fix
- Re-read your report objectively
- If genuinely valuable, counter once with business impact
- If they disagree, move on — N/As hurt your ratio

---

## Bounty Optimization

### Programs That Pay Well
- **VDP** (Vulnerability Disclosure Program) — no bounty, swag only
- **Standard** — bounties based on severity
- **Featured/Premium** — higher bounties, faster triage
- **Private invites** — usually best bounties, less competition

### Factors That Increase Bounty
- Clear, reproducible PoC with two accounts
- Impact quantified (N users, $ amount, data types)
- Smart chain (A→B→C in one report)
- Clear remediation suggestion
- No theoretical claims

### Factors That Decrease Bounty
- Vague impact statements
- Missing HTTP requests
- One account only (no cross-user proof)
- Duplicate of existing report
- Wrong severity claim

---

## CWE Mapping (Add at Bottom of Report)

| Bug Class | CWE |
|-----------|-----|
| IDOR | CWE-639 |
| SSRF | CWE-918 |
| XSS | CWE-79 |
| SQLi | CWE-89 |
| Auth Bypass | CWE-862 |
| CSRF | CWE-352 |
| Race Condition | CWE-362 |
| Open Redirect | CWE-601 |
| Path Traversal | CWE-22 |

---

## HackerOne-Specific Tips

- **Private programs** — higher bounties, less competition, stricter NDA
- **Retesting** — some programs ask you to retest after fix (small bonus)
- **Hall of Fame** — some programs don't pay but offer recognition
- **Bounty negotiation** — generally not recommended unless severely undervalued
- **Signal-to-noise ratio** — HackerOne tracks your signal (accepted/submitted). Low signal = fewer invites.
- **Hacktivity** — search before submitting to avoid duplicates

---

## Submission Checklist (H1-Specific)

```
[ ] Title fits in 80 chars for list view
[ ] Vulnerability type matches the bug class
[ ] CVSS vector string included
[ ] Markdown formatted with ### headers
[ ] Two accounts demonstrated (attacker + victim)
[ ] HTTP requests are complete with all headers
[ ] Impact quantified (N users, data types, $)
[ ] Screenshots show URL bar (proves it's live target)
[ ] CWE number at bottom of report
[ ] Scope verified against program policy
[ ] Searched Hacktivity for duplicates
[ ] Under 500 words
```

---

## When to Escalate

Escalate only when:
- Report is validated but not acted on for 90+ days
- Program violates HackerOne's disclosed policies
- Bounty is significantly below similar programs' payouts

Contact HackerOne support via the report page, not via external channels.
