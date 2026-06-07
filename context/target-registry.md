# Target Registry

Registry of all active, completed, and archived targets with scope details,
account information, and notes. Single source of truth for what targets
have been worked and their status.

---

## Table of Contents

1. [Active Targets](#1-active-targets)
2. [Pipeline Targets](#2-pipeline-targets)
3. [Completed Targets](#3-completed-targets)
4. [Archived Targets](#4-archived-targets)
5. [Target Template](#5-target-template)
6. [Cross-Target Notes](#6-cross-target-notes)

---

## 1. Active Targets

*(No active targets — register when starting new hunt)*

## 2. Pipeline Targets

*(No queued targets — add when identified)*

## 3. Completed Targets

| Target | Program | Scope | Findings | Total Payout | Last Active |
|--------|---------|-------|----------|--------------|-------------|
| — | — | — | — | — | — |

## 4. Archived Targets

| Target | Program | Reason | Notes |
|--------|---------|--------|-------|
| — | — | — | — |

## 5. Target Template

To register a new target, copy and fill this template:

```markdown
## [domain.com]

### Overview
- **Program:** [HackerOne / Bugcrowd / Intigriti / Immunefi / Private]
- **Program URL:** [link]
- **Status:** Active / Stalled / Completed / Archived
- **Tech Stack:** [React / Vue / Node / Django / Rails / PHP / Go / etc.]
- **Added:** [date]
- **Last Active:** [date]

### Scope
- **In-Scope:** [list of domains, wildcards]
- **Out-of-Scope:** [list of excluded assets]
- **Sensitive:** [PII handling, rate limits, special rules]

### Accounts
- **Account A (victim):** email / password / 2FA
- **Account B (attacker):** email / password / 2FA
- **Account C (admin):** email / password / 2FA

### Findings Overview
| # | Type | Status | Severity | Payout | Date |
|---|------|--------|----------|--------|------|
| — | — | — | — | — | — |

### Session History
| Session | Date | Duration | Focus | Findings |
|---------|------|----------|-------|----------|
| — | — | — | — | — |

### Notes
- [key observations, techniques that worked, etc.]
```

## 6. Cross-Target Notes

*(Patterns observed across multiple targets)*

---

*End of target-registry.md*
