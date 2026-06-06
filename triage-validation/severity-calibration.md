---
name: severity-calibration
description: Severity assignment guide for bug bounty hunters. Covers CVSS 3.1 metric mapping, program-specific severity definitions, severity upgrade/downgrade rules, and how to justify severity in reports. Use when deciding severity for a finding, mapping CVSS scores, or arguing severity with triagers. Chinese trigger: 严重程度、severity、CVSS、严重级别、high severity、critical severity
---

# Severity Calibration

Assigning and justifying severity for bug bounty reports.

---

## SEVERITY PHILOSOPHY

```
SEVERITY DECISION FLOW:
1. IDENTIFY — What vuln class is this?
2. IMPACT — What is the worst-case outcome?
3. ACCESS — What privileges does the attacker need?
4. INTERACTION — Does the victim need to do anything?
5. SCOPE — Does this affect anything beyond the vulnerable component?
6. PROBABILITY — How likely is successful exploitation?
7. ASSIGN — Map to program's severity scale
```

### Severity vs Risk

| Dimension | Definition | Example |
|---|---|---|
| Severity | Technical impact — what CAN happen | SQLi with no auth = HIGH severity |
| Risk | Likelihood × Impact — what IS likely to happen | Reflected XSS on 1-user admin page = HIGH severity, LOW risk |

**Rule:** Argue severity based on technical impact, not probability. Triagers downgrade based on likelihood; your job is to establish the maximum possible damage.

---

## CVSS 3.1 METRIC MAPPING

### Attack Vector (AV)

| Value | Meaning | When to use |
|---|---|---|
| Network (N) | Exploitable over internet/local network | 99% of web findings |
| Adjacent (A) | Same shared network segment (Bluetooth, Zigbee, VLAN) | IoT, local network attacks |
| Local (L) | Requires local access or installed application | Desktop app, local file read |
| Physical (P) | Requires physical device access | USB attack, physical theft |

### Attack Complexity (AC)

| Value | Meaning | When to use |
|---|---|---|
| Low (L) | No special conditions; consistent exploitation | Standard web vulns |
| High (H) | Race conditions, timing, special config | Race conditions, blind injection |

### Privileges Required (PR)

| Value | Meaning | When to use |
|---|---|---|
| None (N) | No account needed | Auth bypass, anonymous SSRF |
| Low (L) | Basic user account (free account) | IDOR, CSRF, stored XSS |
| High (H) | Admin or privileged account | Admin-only features |

### User Interaction (UI)

| Value | Meaning | When to use |
|---|---|---|
| None (N) | Attack completes without victim action | Auth bypass, SQLi, SSRF |
| Required (R) | Victim must click/load page | Reflected XSS, CSRF, phishing |

### Scope (S)

| Value | Meaning | When to use |
|---|---|---|
| Unchanged (U) | Impact only the vulnerable component | Standard web vulns |
| Changed (C) | Impacts other systems/cloud/browser | SSRF to cloud, XSS in chrome context |

### Confidentiality (C)

| Value | Meaning | When to use |
|---|---|---|
| High (H) | Full data exposure or all users affected | Full DB dump, mass PII |
| Low (L) | Partial data or some users affected | Single user PII |
| None (N) | No data exposure | DoS, pure integrity |

### Integrity (I)

| Value | Meaning | When to use |
|---|---|---|
| High (H) | Full modification or all data affected | Mass data modification, RCE |
| Low (L) | Partial modification or some data affected | Single user data modified |
| None (N) | No modification | Read-only vulns |

### Availability (A)

| Value | Meaning | When to use |
|---|---|---|
| High (H) | Full service disruption | DoS, RCE, ransomware |
| Low (L) | Partial degradation | Slowdowns, partial DoS |
| None (N) | No availability impact | Most data-focused vulns |

---

## VULN CLASS TO CVSS TEMPLATES

### IDOR / BOLA

| Scenario | CVSS | Vector |
|---|---|---|
| IDOR read PII, any user, auth required | 6.5 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |
| IDOR read sensitive PII (financial/health) | 7.5 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| IDOR write/delete, any user | 7.5 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| IDOR admin data, no admin privileges needed | 8.1 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| IDOR with mass enumeration (>1000 users) | 8.6 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |

**IDOR severity modifiers:**
- Mass enumeration (1000+ records): +1.0
- Financial data exposed: +0.5
- Auth not required at all: +1.0 (becomes auth bypass level)
- Admin data accessible: +1.0
- Write vs read: +1.0 for write

### XSS

| Scenario | CVSS | Vector |
|---|---|---|
| Reflected XSS, self-only | 5.4 | AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N |
| Reflected XSS, all users (unauthenticated) | 7.1 | AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N |
| Stored XSS, own account | 4.3 | AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:N |
| Stored XSS, all users, no auth required | 8.8 | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N |
| Stored XSS, admin context → session theft | 9.8 | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H |
| DOM XSS, self-only | 4.7 | AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N |

**XSS severity modifiers:**
- Admin/chrome context: +1.0
- No authentication required: +1.5
- Stored vs reflected: +1.0
- Self-XSS only: max CVSS 4.3 (usually N/A)

### SSRF

| Scenario | CVSS | Vector |
|---|---|---|
| SSRF DNS callback only | 3.7 | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L |
| SSRF to internal service, data returned | 7.5 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| SSRF to AWS metadata, no chaining | 7.5 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| SSRF → AWS credentials → S3 exfil | 9.1 | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N |
| SSRF → internal admin panel, no auth | 8.6 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |

### SQLi

| Scenario | CVSS | Vector |
|---|---|---|
| SQLi error-based only | 6.5 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N |
| SQLi boolean-based, no data exfil | 6.5 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N |
| SQLi time-based, data exfil possible | 7.5 | AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N |
| SQLi union-based, credentials extracted | 8.6 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| SQLi with RCE via xp_cmdshell | 9.8 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |

### Authentication/Authorization

| Scenario | CVSS | Vector |
|---|---|---|
| JWT none algorithm, admin endpoint access | 9.1 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| JWT weak secret cracked | 8.6 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| Session fixation | 7.5 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| Auth bypass, no account needed | 9.8 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| OAuth state bypass → account linking | 8.1 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |

### Race Conditions

| Scenario | CVSS | Vector |
|---|---|---|
| Race on login (parallel OTP) | 7.5 | AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N |
| Race on coupon → unlimited discount | 7.5 | AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N |
| Race on transfer → double spend | 8.2 | AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H |
| Race on account creation → duplicate bypass | 7.1 | AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N |

### File Upload

| Scenario | CVSS | Vector |
|---|---|---|
| Unrestricted file upload → RCE | 9.8 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| File upload with path traversal | 7.5 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| SVG upload → stored XSS | 7.1 | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N |
| Image upload with polyglot execution | 8.6 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |

---

## PROGRAM-SPECIFIC CALIBRATION

### HackerOne severity definitions

| Severity | CVSS range | Typical bounty |
|---|---|---|
| Critical | 9.0-10.0 | $2,500 – $20,000+ |
| High | 7.0-8.9 | $500 – $5,000 |
| Medium | 4.0-6.9 | $100 – $500 |
| Low | 0.1-3.9 | $50 – $200 |
| Informative | None | $0 |

Program-specific nuances:
- Facebook/Meta: Heavy weighting on RCE and auth bypass
- Google: High weight on SSRF and cloud metadata
- GitHub: High weight on repo-level RCE, token exfil
- Shopify: Business logic chains valued highly

### Bugcrowd VRT mapping

| VRT category | Severity | Mapping notes |
|---|---|---|
| Account Takeover | P1 Critical | 9.0+ |
| Mass PII Disclosure | P2 Major | 7.5-8.9 |
| IDOR on non-critical data | P3 Medium | 6.5 |
| XSS on login page | P3 Medium | 6.5 |
| Missing security header | P4 Minor / P5 Informative | 3.0-4.0 |

### Intigriti severity mapping

Intigriti uses CVSS 3.1 with program-specific adjustments:
- Default: CVSS score maps directly to severity
- Some programs cap at High for specific vuln classes
- Always check program's "Severity Assessment" section

---

## Severity adjustment rules

### Downgrade triggers

| Trigger | Adjustment | Reason |
|---|---|---|
| Victim interaction required but unlikely | CVSS -1.0 | Reduces risk score |
| Auth required (PR=L) with no admin data | CVSS -0.5 | Realistic attacker scope |
| Single-user impact, not mass | CVSS -0.5 | Reduced blast radius |
| Race condition, not 100% reliable | AC: L → H | Reflects exploitation uncertainty |
| Partial data exposure, not full dump | C: H → L | Reduced confidentiality impact |
| Own-account only | Max CVSS 4.3 | Usually self-XSS; kill or Informative |

### Upgrade triggers

| Trigger | Adjustment | Reason |
|---|---|---|
| Admin/chrome context (stole admin session) | +1.0 CVSS | Scope change to browser |
| No authentication required at all | +1.5 CVSS | Widest attacker pool |
| Scope changed (cloud metadata → cloud account) | S metric → Changed | Broader impact |
| Mass enumeration (>10,000 users) | +1.0 CVSS | Scale of impact |
| Financial data directly exfiltrated | +0.5 CVSS | Direct monetary impact |
| Chain completed end-to-end | Upgrade to chain severity | Multi-stage impact |

---

## Severity calibration decision tree

```
START: What can the attacker DO?

Can they access admin functions?
├── YES → Is auth bypassed?
│   ├── YES → CRITICAL (9.0+)
│   └── NO (auth required) → HIGH (7.5-8.5)
└── NO → Continue

Can they access OTHER USERS' data?
├── YES → How many users? What type?
│   ├── 1 user, non-sensitive → MEDIUM (5.0-6.0)
│   ├── 1 user, PII/financial → HIGH (7.0-7.5)
│   ├── All users, non-sensitive → MEDIUM-HIGH (6.5)
│   ├── All users, PII/financial → HIGH (7.5-8.5)
│   └── All users, no auth → CRITICAL (8.5-9.5)
├── NO → Continue

Is there a proven chain to higher impact?
├── YES (end-to-end) → Upgrade chain severity
└── NO → Submit at primitive severity

Final: Compare with program scope; if program caps severity,
submit at program cap with full justification.
```

---

## Justifying severity in reports

### Good severity justification

**High severity, IDOR on payment data:**
```
Severity: HIGH
CVSS: 7.5
Vector: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N

Any authenticated user can access other users' payment methods by
modifying the userId parameter. This affects 50,000+ users with
stored payment methods. Data retrieved includes last 4 digits of
cards and billing addresses.
```

**Critical severity, SSRF → AWS metadata:**
```
Severity: CRITICAL
CVSS: 9.1
Vector: AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N

SSRF on /api/analyze allows fetching AWS EC2 instance metadata,
returning IAM role credentials. Attacker can list all S3 buckets
owned by the account including customer PII backups. Impact
extends beyond the web application to the company's AWS cloud
environment (S=Changed).
```

### Bad severity justification

```
BAD: "This is HIGH because IDORs are high severity."
GOOD: "HIGH because it exposes payment card tokens for 50,000 users
       and enables targeted phishing at scale."

BAD: "CVSS 9.5 because SSRF is bad."
GOOD: "CVSS 9.1 because SSRF reaches 169.254.169.254, retrieves AWS
       credentials, and grants access to S3 containing PII backups."

BAD: "Critical because admin panel is accessible."
GOOD: "Critical because JWT alg:none forgery grants unauthenticated
       access to admin user management, enabling full ATO."
```

---

## Severity anti-patterns

### Overclaiming

```
Overclaim: Submit every IDOR as HIGH/Critical
Result: Triager downgrades; you lose credibility

Fix: Calibrate against disclosed reports from same program.
If IDOR on non-sensitive data paid Medium, yours on PII is High.
```

### Underclaiming

```
Underclaim: Submit a proven RCE as "Medium just to be safe"
Result: Program pays Medium bounty; you left money on table

Fix: If program scope explicitly pays for RCE, submit at full severity.
Triagers don't upgrade after the fact.
```

### Severity inflation via CVSS padding

```
Dishonest: Padding CVSS to 9.0+ by setting Scope=Changed without justification
Honest: Scope=Changed only when impact genuinely crosses boundary (cloud, browser, OS)

Programs track CVSS accuracy over time. Inflated scores that get
downgraded hurt your researcher reputation.
```

---

## Program-specific severity quirks

### Programs that cap severity

| Program | Cap | Notes |
|---|---|---|
| Many private programs | High | Critical reserved for RCE/ATO only |
| Some bug bounty platforms | High | Requires explicit program approval for Critical |
| Government programs | High | Political sensitivity caps at High |

### Programs with custom severity language

| Program | Custom wording | Mapping |
|---|---|---|
| HackerOne | "Severity" dropdown | CVSS 3.1 + program definitions |
| Bugcrowd | VRT + priority | P1-P5, maps to CVSS |
| Intigriti | "Severity" + CVSS | CVSS 3.1 + program overlay |
| Synack | Custom levels | Follow program guide exactly |

---

## Severity negotiation with triagers

### When triager downgrades

```
Triager: "Downgrading to Medium. Impact is limited to one user."

Response options:
1. Accept: "Understood, thank you for the review."
2. Clarify: "The 200 response contains the victim's full PII including
   payment data. This affects all 50,000 users via enumeration.
   Can you reconsider based on mass impact?"

Option 2 works when:
- You have evidence of mass enumeration
- The triager missed the data sensitivity
- The program's scope explicitly includes this impact class

Option 1 works when:
- The downgrade is reasonable
- You want to preserve relationship for future reports
- The bounty difference isn't worth arguing
```

### When triager upgrades

```
Rare but happens. If triager upgrades:
- Thank them
- Update your mental model for future reports
- Note the reasoning for calibration reference
- Do not argue the downgrade of a different finding based on this upgrade
```

---

## Severity checklist per report

Before submitting severity label:

- [ ] CVSS score calculated with accurate metrics
- [ ] All CVSS metrics justify the claim (no padding)
- [ ] Severity matches program's stated definitions
- [ ] Impact section quantifies the damage (users affected, data type)
- [ ] Worst-case scenario described (not best-case)
- [ ] Chain severity applied if proven end-to-end
- [ ] Downgrade triggers checked and addressed
- [ ] Upgrade triggers checked and applied if present

---

## Final severity rules

1. **Score the vuln, not the hunter** — severity is technical, not personal
2. **Program scope caps your ceiling** — respect their definitions
3. **Justify with data** — user count, data type, attack path
4. **One severity per finding** — no "Medium to High" ambiguity
5. **Downgrade over N/A** — a downgrade pays something; N/A pays nothing
6. **Chain severity wins** — proven chain > any primitive
7. **Document your calibration** — note comparisons to similar disclosed reports
8. **Triager relationship matters** — accuracy builds trust; trust gets faster approvals
9. **Update your templates** — refine CVSS vectors as you learn program preferences
10. **When in doubt, submit lower** — triagers can upgrade; they rarely upgrade after N/A
