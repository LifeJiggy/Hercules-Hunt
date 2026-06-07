---
name: Intigriti
description: Intigriti-specific report writing guide. CVSS 3.1 mandatory requirements, impact statement format, pre-submission validation, and platform-specific submission optimization.
---

# Intigriti Report Writing Guide

## Platform Overview

Intigriti is a European bug bounty platform with strong emphasis on report quality and CVSS accuracy. Pre-submission validation helps researchers avoid rejections. Impact statements are required as a separate field from the description.

---

## Mandatory Requirements

### CVSS 3.1 (Always Required)
- Every report MUST include a CVSS 3.1 vector string
- Intigriti validates CVSS against the described impact
- Mismatch between CVSS and impact = rejection risk
- Use the official CVSS calculator: https://www.first.org/cvss/calculator/3.1

### Impact Statement (Separate From Description)
Intigriti requires the impact as a distinct field, not buried in the description.

**Format:**
```
[Attacker access level] can [exact action] by [method].
This results in [concrete harm] and affects [scope].
[Optional: financial/regulatory/reputation impact]
```

**Example:**
```
An authenticated user can read any customer's invoice by changing one ID in the URL.
This exposes names, addresses, and payment card data for all 50,000 customers.
Regulatory impact: GDPR violation for EU customer data.
```

---

## Report Structure on Intigriti

### Fields
- **Title** — concise, includes endpoint and impact
- **Vulnerability Type** — dropdown (OWASP-aligned)
- **CVSS 3.1** — vector string and score
- **Description** — technical details, steps, evidence
- **Impact Statement** — standalone impact description (see above)
- **Remediation** — specific fix suggestion
- **Attachments** — screenshots, videos, PoC code

### Target Selection
- Some programs allow choosing between multiple targets
- Verify target is in scope before submitting
- Intigriti shows bounty ranges per target

---

## Severity Guidelines

| Intigriti Level | CVSS Range | Description |
|----------------|-----------|-------------|
| Critical | 9.0-10.0 | Immediate threat to system integrity |
| High | 7.0-8.9 | Significant security impact |
| Medium | 4.0-6.9 | Notable but limited impact |
| Low | 1.0-3.9 | Minor security improvement |
| Informational | 0.0 | No direct security impact |

Intigriti expects you to justify your CVSS score in the report. A score without justification is grounds for rejection.

---

## Triage Process

1. **Submitted** → queued for Intigriti triage
2. **Under Review** → Intigriti team evaluates validity and CVSS
3. **Needs More Info** — triager asks for clarification
4. **Validated** → sent to customer for bounty
5. **Rejected** → closed as invalid or out of scope
6. **Duplicate** → previously reported

### Timelines
- First response: typically 48-72 hours
- Customer review: 7-21 days
- Bounty paid after customer validation

---

## Pre-Submission Validation

Intigriti offers a pre-submission validation feature for some programs.

### How It Works
1. Draft your report with all required fields
2. Submit for pre-validation (not a real submission)
3. Intigriti gives feedback on quality, CVSS, and completeness
4. Fix issues based on feedback
5. Submit the final report

### Why Use It
- Catches missing evidence before real submission
- Validates your CVSS score against impact
- Reduces rejection rate
- Shows good-faith effort to submit quality reports

**Note:** Not all programs support pre-submission validation. Check the program page.

---

## Intigriti-Specific Tips

### European Focus
- GDPR compliance is a strong impact multiplier
- Mention GDPR explicitly if EU user data is involved
- European triagers may be more strict on report structure

### Report Quality Expectations
- No typos in technical terms or endpoint paths
- CVSS justification is mandatory
- Screenshots must show the URL bar
- Video PoC is helpful for complex bugs but not required
- Proof of concept code (Python/Bash) adds credibility

### Language
- Reports in English are preferred
- Some programs accept French or Dutch (check program page)
- Keep technical terms in English regardless of report language

---

## Handling Feedback

### CVSS Correction
If triager adjusts your CVSS:
- Read their justification carefully
- If they're right, accept and update
- If they missed context, respond once with evidence

### Needs More Info
- Respond within 48 hours
- Provide exactly what was requested, no more
- Use the report reply, not external channels

### Rejection
- Read the rejection reason carefully
- If it's a scope issue, verify against program policy
- If it's a validity issue, re-test before appealing
- One appeal per report — make it count

---

## Pre-Submit Checklist (Intigriti-Specific)

```
[ ] CVSS 3.1 vector string included AND justified
[ ] Impact statement written as separate field (not in description)
[ ] Impact statement starts with concrete harm, not "I found..."
[ ] Vulnerability type matches the bug class (OWASP dropdown)
[ ] Target correctly selected from available options
[ ] Screenshots show URL bar (proves target)
[ ] CVSS score matches impact description
[ ] Under 500 words total
[ ] GDPR mentioned if EU user data affected
[ ] Pre-submission validation used if available
[ ] No theoretical claims ("could potentially")
[ ] All HTTP requests are complete with headers
[ ] Two accounts demonstrated for auth-related bugs
```

---

## Common Rejection Reasons

| Reason | How to Avoid |
|--------|-------------|
| Missing CVSS | Always include vector string + score |
| Impact mismatch | CVSS must match described impact |
| No impact statement | Use separate field, not buried in description |
| Theoretical claim | Prove it or drop it |
| Wrong scope | Verify target is in scope before writing |
| Duplicate | Check disclosed reports and program hacktivity |
| Poor evidence | Include full HTTP requests, not paraphrased |
