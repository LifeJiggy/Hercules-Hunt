---
name: Bugcrowd
description: Bugcrowd-specific report writing guide. VRT-based severity, P-rating system, submission best practices, target selection, and triage navigation for Bugcrowd programs.
---

# Bugcrowd Report Writing Guide

## Platform Overview

Bugcrowd uses a Vulnerability Rating Taxonomy (VRT) to determine severity. Reports are triaged by Bugcrowd's internal team, then forwarded to the customer. Understanding the VRT is essential for accurate severity claims.

---

## Severity: P-Rating System

| Rating | CVSS Range | Label | Typical Bugs |
|--------|-----------|-------|-------------|
| P1 | 9.0-10.0 | Critical | RCE, SQLi with exfil, auth bypass → admin, SSRF → cloud metadata |
| P2 | 7.0-8.9 | High | IDOR with write/delete, stored XSS in admin panel, business logic abuse |
| P3 | 4.0-6.9 | Medium | IDOR read PII, reflected XSS, CSRF with impact, open redirect |
| P4 | 1.0-3.9 | Low | Info disclosure, missing security headers, minor UX issues |
| P5 | 0.0 | Informational | Best practice suggestions, theoretical issues |

### Bugcrowd VRT Notes
- VRT is the **default** — you can suggest a different severity with justification
- If VRT says P3 but your bug has higher impact, explain why
- Severity-request paragraph should be the FIRST body section after summary
- Reference specific VRT categories when possible

---

## Report Structure on Bugcrowd

### Required Fields
- **Title** — concise, includes endpoint and impact
- **Bug Type** — dropdown matching VRT category
- **Target** — URL or component name
- **Description** — main body
- **Severity** — P1-P5
- **Attachments** — screenshots, video, HAR

### Bug Type Dropdown Strategy
1. Search VRT for the closest match
2. If no exact match exists, pick the closest parent category
3. In the description, explain why this category applies
4. Never pick "Other" unless truly uncategorizable

---

## Triage Process

1. **Submitted** → queued for Bugcrowd triage
2. **Triaging** → Bugcrowd team reviews validity
3. **Unresolved** → needs more info from researcher
4. **Resolved** → sent to customer for bounty decision
5. **Duplicate** → previously reported
6. **Not Applicable** → closed as invalid

### Timelines
- First response: usually 48-96 hours (slower than H1)
- Customer review: 7-30 days
- Bugcrowd mediates if customer is unresponsive

---

## Target Selection Tips

### Production vs QA
- QA targets are usually lower bounty or no bounty
- Check program scope carefully — some have separate QA programs
- Bugs in production are always preferred

### Program Types
- **Public programs** — open to all researchers, more competition
- **Private programs** — invite-only, typically better bounties
- **Crowdstream / On-demand** — time-boxed, higher urgency

---

## Bugcrowd-Specific Tips

### Evidence Requirements
- Private programs often request PoC videos
- Screenshots must show the URL bar
- Burp Suite exports are helpful but not required
- HAR files are acceptable for complex chains

### Researcher Hygiene (Bugcrowd Ninja)
- Use Bugcrowdninja email alias for test accounts
- Restore any test accounts to original state after testing
- Maintain friendly-tester posture in communications
- Never test outside defined scope

### When VRT Default Seems Wrong
- Include a "Severity Rationale" paragraph after the summary
- Explain why the business impact exceeds the VRT default
- Reference specific program guidelines if they exist
- Expect pushback — be ready to counter

---

## Handling Triage Outcomes

### Out of Scope (OOS) Rebuttal Templates

**Rate limiting on auth endpoints:**
> "Rate limiting on authentication endpoints is a security control, not a feature. When rate limiting is absent, attackers can brute-force passwords, enumerate valid accounts, and perform credential stuffing. OWASP ASVS requires rate limiting on auth endpoints (V2.2.1)."

**Debug information disclosure:**
> "Debug endpoints that expose internal path information, environment variables, or SQL queries assist attackers in crafting targeted exploits. This is classified as Information Exposure (CWE-200) and is valid under the VRT."

**User enumeration with PII:**
> "The response difference reveals valid email addresses combined with user PII (name, avatar, join date). This is not 'theoretical' — confirmed by testing 50 accounts. User enumeration with PII is a valid medium-severity finding."

### Severity Downgrade
- Respond once with evidence, then accept
- Reference specific VRT language
- Keep it under 150 words

### Duplicate
- Verify the referenced report exists
- If different impact or different endpoint, explain the distinction
- If truly duplicate, accept and move on

---

## P-Rating Escalation Guide

| VRT Rate | Your Claim | Your Argument |
|----------|-----------|---------------|
| P3 IDOR | P2 | "Mass enumeration confirmed: 50K records accessible via iterable IDs. Data includes PII (name, email, address, phone). This exceeds 'limited data access' threshold in VRT." |
| P3 XSS | P2 | "Executes in admin panel. Demonstrated session cookie theft → full admin access. VRT defines admin panel XSS as P2." |
| P4 Info | P3 | "Exposed internal IP, hostname, and software versions. Attacker uses this to fingerprint vulnerabilities. CWE-200 with operational security impact." |

---

## Pre-Submit Checklist (Bugcrowd-Specific)

```
[ ] VRT category selected (closest match or justified override)
[ ] Severity set as P1-P5 (not CVSS number)
[ ] Target URL/component correctly specified
[ ] Severity rationale included if overriding VRT
[ ] Screenshots show URL bar (proves target)
[ ] Test accounts use Bugcrowdninja alias
[ ] Accounts restored to original state after testing
[ ] Private program: video PoC attached if requested
[ ] Scope verified (production vs QA)
[ ] No OOS clauses triggered
[ ] Under 500 words
[ ] Impact quantified in business terms
```

---

## Communicating With Triagers

- Be professional and concise
- Respond to questions within 24-48 hours
- Never argue about scope after a submission is closed
- If Bugcrowd mediation is needed, use the report page
- Build a positive reputation — it leads to more private invites
