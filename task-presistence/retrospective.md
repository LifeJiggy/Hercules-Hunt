# Task Persistence — Retrospective

Post-session and weekly review framework. Converts raw hunting history into actionable improvement without heavy ceremony. Covers session scorecard, mistake taxonomy, speed/accuracy trends, and a lightweight cadence.

---

## 1. Purpose

Retrospectives convert experience into improvement. Without them, sessions blur together and mistakes repeat.

- What actually happened vs what I planned?
- Where did I waste time?
- What patterns emerge across sessions?
- What should change in the next plan?

---

## 2. Session Scorecard

Fill in at the end of each session:

```
SESSION SCORECARD: YYYY-MM-DD
TARGET:  [domain]
DURATION: [N]h [N]min

PLANNED TASKS:   [N]
COMPLETED:       [N]
COMPLETION %:    [N]%

FINDINGS:
  Confirmed:   [N]
  Submitted:   [N]
  Killed:      [N]

TIME USE:
  Hunting:    [N] min (planned: [N])
  Evidence:   [N] min
  Reporting:  [N] min
  Recon:      [N] min
  Distracted: [N] min

EFFICIENCY:
  Tasks/hour:        [N]
  Findings/hour:     [N]
  Planned vs actual: [over / on / under]

OBSTRUCTIONS:
  WAF/429 blocks: [N]
  Token expirations: [N]
  Tool failures: [N]
```

### What Went Well
```
- [specific positive item]
- [specific positive item]
```

### What Went Poorly
```
- [specific negative item]
- [specific negative item]
```
Categorize by cause: scope error, WAF/block, wrong technique, focus loss, weak payload, tool issue.

### Time Wasted
```
| Wasted On | Min | Why |
|---|---|---|
| OOS assets | [N] | Did not validate scope before probing |
| Weak payloads | [N] | Should have switched earlier |
| Context re-read | [N] | Should have hydrated before start |
| TOTAL | [N] | |
```

---

## 3. Mistake Taxonomy

Track recurring mistakes to break them.

```
MISTAKE LOG:

| Date | Mistake | Impact | Fix |
|---|---|---|---|
| YYYY-MM-DD | [what happened] | [N] min / [finding lost] | [preventive action] |
```

Top fixes to track this month:
1. [mistake 1] → [fix]
2. [mistake 2] → [fix]
3. [mistake 3] → [fix]

---

## 4. Speed and Accuracy Trends

### Finding Speed by Bug Class
```
BUG CLASS       AVG TIME (recon to confirmed)
SSRF            [N] min
IDOR            [N] min
JWT             [N] min
XSS             [N] min
Auth bypass     [N] min
TREND: [faster / same / slower] than last period
```

### Accuracy
```
THIS PERIOD:
  Confirmed: [N]  Killed: [N]  Survival rate: [N]%

ALL TIME:
  Confirmed: [N]  Killed: [N]  Survival rate: [N]%

TREND: [improving / stable / declining]
```

### Productivity
```
| Week | Findings | Tasks/Hour | Efficiency |
|---|---|---|---|
| W[NN]  | [N] | [N] | [High/Med/Low] |
```

---

## 5. Weekly Review

### Weekly Summary

```
WEEKLY REVIEW: YYYY-MM-DD to YYYY-MM-DD

SESSIONS:  [N]
HOURS:     [N]

FINDINGS:
  Confirmed: [N]
  Submitted: [N]
  Killed:    [N]

TOP ACHIEVEMENT:
  - [specific win]

BIGGEST MISTAKE:
  - [specific loss]

LESSONS LEARNED:
  1. [lesson]
  2. [lesson]
  3. [lesson]

NEXT WEEK FOCUS:
  1. [priority 1]
  2. [priority 2]
  3. [priority 3]

SKILL PROGRESSION:
  [skill]: [before] → [after]
```

### Pattern Spotting (every 5 sessions)

```
PATTERNS TO CHECK:
  - Wasted time pattern: [e.g., always wastes 15 min on setup]
  - Successful pattern:  [e.g., IDOR finds happen early]
  - Avoid pattern:       [e.g., never test stored XSS last]
  - Repeat mistakes:     [e.g., forgot token refresh twice]
```

### Improvement Actions

Each weekly review must produce concrete actions:
```
IMPROVEMENT ACTIONS:
  [ ] [action 1] — by YYYY-MM-DD
  [ ] [action 2] — by YYYY-MM-DD
  [ ] [action 3] — by YYYY-MM-DD
```

---

## 6. Retrospective Triggers

| Trigger | Action |
|---|---|
| Every session | Fill scorecard (Section 2) |
| End of week | Weekly review (Section 5) |
| Every 5 sessions | Pattern spot + improvement actions |
| 5 kills in a row | Bug-class specific retro |
| No progress in 3 sessions | Full retro + plan reset |
| Monthly | Full speed/accuracy review + goal check |

---

## 7. Maintenance

```
AFTER EVERY SESSION:
  [ ] Fill session scorecard
  [ ] Note 2-3 positives and negatives
  [ ] Log any mistakes

AFTER EVERY WEEK:
  [ ] Weekly review completed
  [ ] Improvement actions created

MONTHLY:
  [ ] Full retrospective
  [ ] Top fixes review
  [ ] Speed and accuracy review
  [ ] Goal alignment check
```

---

*End of retrospective.md*
