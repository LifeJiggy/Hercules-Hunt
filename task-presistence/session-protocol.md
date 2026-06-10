# Task Persistence — Session Protocol

Standard operating procedure for starting, running, and ending a hunting session. Use this to keep sessions consistent, evidence complete, and handoff clean.

---

## 1. Before the Session (15 min)

### 1.1 Environment Check

```
SESSION START CHECKLIST:
  [ ] Workstation is ready (VPN off if testing external targets)
  [ ] All testing tools installed and working
  [ ] Burp Suite installed and licensed (Community or Pro)
  [ ] Browser hunt profile ready (Firefox/Chrome separate profile)
  [ ] Screenshot tool ready (ShareX / Flameshot / Snipping Tool)
  [ ] Notes editor ready (VS Code / Obsidian / Notepad++)
  [ ] Hydration script ready: python task-presistence/hydrate.py --tree
```

### 1.2 Load Context

```bash
# Option A: hydrate.py (recommended)
python task-presistence/hydrate.py --list
# Manually read:
#   task-presistence/active-tasks.md
#   task-presistence/continuity-log.md
#   task-presistence/session-states.md
#   task-presistence/progress-tracker.md

# Option B: direct load
python task-presistence/hydrate.py --load
```

### 1.3 Scope and Target Confirmation

```
CONFIRM BEFORE TESTING:
  [ ] Target is IN SCOPE (verified against program policy)
  [ ] Safe harbor terms accepted
  [ ] No outstanding legal or program restrictions
  [ ] Target has not moved to closed/resolved state
  [ ] No duplicate findings already submitted for this vector
```

### 1.4 Tool Bootstrap

Load in order:

```powershell
# Windows
. .\tools\powershell\powershell-lib.ps1
. .\tools\powershell\curl-hunter.ps1

# Start Burp: create/open project named <target>-<YYYYMMDD>.burp
# Start browser with proxy set to 127.0.0.1:8080
```

```bash
# Linux/macOS equivalent
source tools/bash/recon-toolkit.sh
# Start Burp and browser proxy as above
```

### 1.5 Account and Token Setup

```
ACCOUNT SETUP:
  [ ] Attacker account: token valid
  [ ] Victim account:  token valid
  [ ] Admin account:   token valid (if applicable)
  [ ] Tokens refreshed if needed
  [ ] Token expiry times recorded
  [ ] env vars set: $env:ATTACKER_TOKEN, $env:VICTIM_TOKEN, $env:ADMIN_TOKEN
```

### 1.6 Define This Session

Fill in or update:

```
SESSION: YYYY-MM-DD
TARGET:  [domain]
PROGRAM: [name]
DURATION: [N] hours planned

FOCUS BUG CLASSES:
  1. [bug class]
  2. [bug class]
  3. [bug class]

THIS SESSION GOALS:
  1. [task 1] — [timebox]
  2. [task 2] — [timebox]
  3. [task 3] — [timebox]

SUCCESS CRITERIA:
  - At least 1 finding confirmed OR 1 task completed
  - All pending callbacks checked
  - Handoff note written
```

---

## 2. During the Session

### 2.1 Time Boxing

```
SESSION TIMELINE:
  Block 1 — Warm up / recon (15 min)
  Block 2 — Active hunting   (45-90 min)
  Block 3 — Evidence capture (15-30 min)
  Block 4 — Report / submit  (15-30 min)
  Block 5 — Cleanup / handoff (10-15 min)
```

### 2.2 Active Work Rules

- One bug class at a time until timebox expires or finding is confirmed.
- Switch bug classes only at planned boundaries.
- Do not start a new finding while evidence for the previous one is still incomplete.
- Stop testing a vector after 10 minutes with no signal; move on and revisit later if needed.

### 2.3 Evidence Capture (as you go)

Do not rely on memory. Capture immediately:

```
REQUIRED EVIDENCE PER FINDING:
  [ ] Request (Burp Repeater saved or raw text)
  [ ] Response (full response with status, headers, body)
  [ ] Screenshot(s) showing:
      - Setup (clean state)
      - Request
      - Before impact
      - Exploit
      - After impact (verify)
  [ ] HAR if needed for complex flows
  [ ] Notes: what you changed, why, what it proved
```

### 2.4 State Updates (lightweight, in-place)

Use inline updates in `session-states.md` and `active-tasks.md`:

```
MINIMAL IN-SESSION UPDATE:
  - Mark task checkbox as completed when done.
  - Note new payloads and responses in CONTEXT NOTES.
  - Do not rewrite full file; append short bullet entries.
```

### 2.5 Break and Block Management

| Signal | Action |
|---|---|
| 10 min no progress on one vector | Switch bug class or target feature |
| WAF / rate limit response | Record pattern, back off, switch target or technique |
| Callback expected but not received | Log, set reminder, continue other work |
| Token expired | Refresh, update state, continue |
| Finding confirmed | Capture all evidence before moving to the next vector |

---

## 3. After the Session (10-15 min)

### 3.1 Evidence Package Assembly

```
PACKAGE CHECKLIST:
  [ ] Requests saved to requests/
  [ ] Responses saved to responses/
  [ ] Screenshots saved to evidence/
  [ ] Redaction applied (PII, cookies, secrets 100% black bars)
  [ ] HAR sanitized if used
  [ ] Evidence package id recorded (PKG-YYYYMMDD-NNN)
```

### 3.2 State Persistence

Update these files in order:

1. `session-states.md` — final STATE DUMP
2. `active-tasks.md` — mark completed, carry incomplete
3. `continuity-log.md` — Hnadoff block for next session
4. `task-history.md` — daily timeline entry
5. `progress-tracker.md` — findings, financials, skill levels

### 3.3 Handoff Note (mandatory)

Copy/paste and fill:

```
=== HANDOFF: End of Session YYYY-MM-DD ===

TARGET: [domain]
PROGRAM: [name]
SESSION DURATION: [N]h [N]min

LAST TESTED:
  Endpoint: [URL]
  Method: [GET/POST/PUT/DELETE]
  Payload: [payload]
  Response: [status code — summary]
  Status: [VULN / Not vuln / Pending]

PENDING TESTS (next session):
  1. [test 1]
  2. [test 2]
  3. [test 3]

PENDING FINDINGS:
  [finding 1]: [status] — [next action]
  [finding 2]: [status] — [next action]

TOOLS STATE:
  Burp project: [filename]
  Collaborator URL: [URL]
  Tokens expire: [time/date]

NEXT SESSION PRIORITIES:
  1. [priority 1]
  2. [priority 2]
  3. [priority 3]

ESTIMATED RESUME TIME: [N] min
```

### 3.4 Git Commit

```
COMMIT COMMAND:
  git add -A
  git commit -m "End of session YYYY-MM-DD [target] [findings count]"
```

Only if explicitly requested by user. Do not push unless asked.

### 3.5 Session Rating

Rate the session:

```
SESSION: YYYY-MM-DD
RATING: [1-5]
FINDINGS: [N] confirmed
TASKS COMPLETED: [N]
EFFICIENCY: [High / Medium / Low]

WHAT WENT WELL:
  - [item]

WHAT DID NOT WORK:
  - [item]

LESSON LEARNED:
  - [item]

NEXT SESSION FOCUS:
  - [item]
```

---

## 4. Quality Gates

### 4.1 Session Start Gate

Never start without:

- [ ] Target confirmed in scope
- [ ] Tokens valid or refresh procedure ready
- [ ] Burp project opened
- [ ] Context hydrated
- [ ] Session goal defined

### 4.2 Session End Gate

Never end without:

- [ ] Handoff note written
- [ ] State dumped in session-states.md
- [ ] Active tasks updated
- [ ] Evidence package status recorded
- [ ] Tokens noted as valid/expired
- [ ] Session rating filled

### 4.3 Evidence Gate

Never submit a finding without:

- [ ] 3 reproducible runs (7-Question Gate)
- [ ] Full request and response captured
- [ ] Screenshots for each step (setup / before / exploit / verify)
- [ ] PII and secrets redacted
- [ ] Impact clearly demonstrated, not theoretical

---

## 5. Common Session Types

### 5.1 Deep Focus Session (1 target, 1 bug class)

```
Planning:
  - Target: example.com
  - Bug class: SSRF
  - Time: 2h
  - Goal: Find SSRF + cloud metadata

Flow:
  1. Recon on target for SSRF-prone endpoints (10 min)
  2. Test each endpoint with OOB callback (45 min)
  3. Verify cloud metadata (20 min)
  4. Capture evidence (20 min)
  5. Write and submit (25 min)
```

### 5.2 Broad Scan Session (1 target, multiple bug classes)

```
Planning:
  - Target: example.com
  - Bug classes: IDOR, auth bypass, SSRF
  - Time: 2h

Flow:
  1. IDOR first (highest payoff) — 40 min
  2. Auth bypass — 30 min
  3. SSRF quick check — 30 min
  4. Pick best finding, validate — 20 min
```

### 5.3 Multi-Target Session

```
Planning:
  - Targets: A, B, C
  - Time: 2h

Flow:
  1. 20 min on A (recon + quick test)
  2. 20 min on B
  3. 20 min on C
  4. Return to most promising — deep focus remaining time
```

### 5.4 Evidence and Reporting Session

```
Planning:
  - Close out 2 pending findings
  - Time: 2h

Flow:
  1. Refresh tokens (5 min)
  2. Capture remaining evidence for finding A (30 min)
  3. Capture remaining evidence for finding B (30 min)
  4. Write report A (25 min)
  5. Write report B (25 min)
  6. Submit A (5 min)
```

---

## 6. Maintenance

```
AFTER EVERY SESSION:
  [ ] Handoff note written
  [ ] State dump updated
  [ ] Active tasks updated
  [ ] Evidence package status recorded
  [ ] Git committed (if enabled)

AFTER EVERY WEEK:
  [ ] Session quality review completed
  [ ] Productivity patterns noted
  [ ] Handoff quality rated

ONCE PER MONTH:
  [ ] Protocol reviewed and updated if needed
  [ ] Tool setup and bootstrap verified
  [ ] New session templates created if workflow changed
```

---

*End of session-protocol.md*
