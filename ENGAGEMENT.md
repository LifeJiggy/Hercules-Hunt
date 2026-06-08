# Engagement: <target>

**Target:** <target>
**Started:** <YYYY-MM-DD>
**Platform:** [TBD — Bugcrowd / HackerOne / Intigriti / Immunefi / private]
**Program URL:** [paste the program page URL here]

## Hunter's Foundation

Before you start, internalize the three forces from `soul.md`:

1. **Curiosity** — Why does this feature work this way? What shortcut did the developer take?
2. **Discipline** — Stop when the signal is gone. 10-20 min per test. Rotate.
3. **Integrity** — Prove it or drop it. No theoretical findings.

Read the full philosophy: `cat ~/.jiggy/soul.md`

## Purpose (from `purpose.md`)

> "The best bug bounty hunters are not the ones who run the most tools.
> They are the ones who understand the deepest."

See: `cat ~/.jiggy/purpose.md`

## North Star (from `goal.md`)

**Every session produces one of two outcomes: a verified finding or a documented dead end.**

See all 10 goals: `cat ~/.jiggy/goal.md`

## Engagement context

This folder is the working directory for a single bug-bounty engagement.
Files in this folder:

- `scope.md` — parsed scope, OOS list, focus areas, bounty bands
- `findings/` — one markdown file per finding (naming: `finding-<NN>-<short-name>.md`)
- `submissions.txt` — submission IDs tracker (for chain cross-references)
- `evidence/` — screenshots, HARs, raw transcripts (gitignored)
- `notes.md` — running notes, leads, dead ends

---

## Pre-Engagement Checklist

Complete this checklist BEFORE sending a single request:

### Scope Verification
- [ ] Program page opened and scope copied to `scope.md`
- [ ] In-scope assets categorized (web, API, mobile, cloud)
- [ ] Out-of-scope assets noted
- [ ] Bug class exclusions read and understood
- [ ] Focus areas noted
- [ ] Bounty bands recorded
- [ ] Wildcards expanded (if applicable)
- [ ] Wildcard subdomains verified as target-owned
- [ ] No OOS assets in the target's infrastructure

### Account & Environment
- [ ] Test account created (if required)
- [ ] Test account email/uid saved in `scope.md`
- [ ] Production vs QA determined
- [ ] Mobile builds downloaded (if applicable)
- [ ] MFA enrollment completed (if required for the test)
- [ ] Authentication flow documented (SSO, OAuth, email+password, etc.)

### Tool Readiness
- [ ] Burp Suite running with target-scoped proxy
- [ ] Interact.sh callback URL configured
- [ ] Subfinder, nuclei, httpx, ffuf installed
- [ ] Python tools available (`pip install -r requirements.txt`)
- [ ] MCP servers started (for MCP-enabled AI workflows)
- [ ] Evidence capture tools ready (screenshot, HAR, curl)

### Session Planning
- [ ] Session time-box set (recommended: 90-120 minutes)
- [ ] Bug class rotation order determined
- [ ] Focus area selected for primary testing
- [ ] Backup focus area identified (for rotation)
- [ ] End-of-session callback set (for technique capture)

---

## Workflow

1. **Plan** — fill in `scope.md` from the program page. Note Focus Areas and Bounty bands.
2. **Recon** — subdomain enumeration, tech fingerprinting, JS analysis, cloud asset discovery.
3. **Hunt** — per-class bug hunting (IDOR, SSRF, XSS, auth bypass, business logic, chains).
4. **Validate** — run the 7-Question Gate on every lead BEFORE drafting a report.
5. **Capture evidence** — redact cookies/PII in screenshots before attaching.
6. **Report** — impact-first writing, CVSS 3.1 scoring.
7. **Track** — append every submitted finding's UUID to `submissions.txt`.

## Deep Dive: Each Workflow Step

### 1. Plan (30 minutes)

**Activities:**
- Read the program page completely, including FAQ and policy documents
- Read 3+ disclosed reports for this target (search HackerOne/Bugcrowd for the program name)
- Identify the target's tech stack (Wappalyzer, builtwith.com, job postings)
- Read the target's engineering blog and changelog (what features are new or recently changed?)
- Fill in `scope.md` completely
- Read `scope.md` one more time before the first probe

**Output:** Complete `scope.md`, session plan in `notes.md`

### 2. Recon (1-2 hours)

**Activities:**
- Subdomain enumeration: subfinder, amass, chaos, certificate transparency
- Live host discovery: httpx on enumerated subdomains
- Technology fingerprinting: Wappalyzer, whatweb, nuclei tech-detect
- URL crawling: Katana, waybackurls, gau on in-scope domains
- JS analysis: download and scan JS bundles for endpoints, secrets, API paths
- Cloud discovery: S3/GCS/Azure bucket enumeration, DNS TXT records for cloud services
- Technology-specific: check for known CVEs in discovered stack

**Output:** List of live endpoints with tech fingerprints; JS bundle findings; cloud asset inventory

### 3. Hunt (3-6 hours per session)

**Bug class rotation order (prioritized by likelihood of payout):**
1. IDOR — most common high-value bug, easy to test, high payout
2. SSRF — rare but Critical when found, medium effort to test
3. Auth bypass — varies by target, high-impact when found
4. Business logic — requires understanding the app, unique findings
5. XSS — common but reduced payouts on many programs
6. Race conditions — time-intensive but high-ROI on specific endpoints
7. File upload / RCE — rare, extreme payout

**Testing rhythm:**
```
10 min: Initial probe of endpoint
10 min: Deeper test if signal detected
10 min: Alternative approach if first attempt failed
→ Rotate to new endpoint or bug class after 30 min without confirmed signal
```

### 4. Validate (10 minutes per finding)

**The 7-Question Gate:**
1. Is the asset in scope? (yes = continue, no = kill)
2. Can I reproduce this consistently across multiple attempts? (yes = continue, no = kill)
3. Is there a realistic victim action required? (none/minimal = continue, unrealistic = kill)
4. Can I demonstrate actual harm, not just theoretical? (yes = continue, no = kill)
5. Is the severity accurate? (no inflation = continue, inflated = adjust or kill)
6. Is this a chain candidate? If so, what primitives pair with it?
7. Would I want to receive this report as a triager? Does it respect their time?

**Validation must produce:**
- The exact HTTP request that triggers the bug
- The exact HTTP response that demonstrates the bug
- A screenshot or HAR showing the exploit
- A test account confirmation (if applicable)

### 5. Capture Evidence (10 minutes per finding)

**Per-finding evidence:**
- Screenshot of the exploit (Burp Repeater response, browser dev tools)
- HAR export of the session (filtered to relevant requests only)
- Raw request/response as curl commands or text files
- Chain documentation (if applicable) — what A, what B, what condition C

**Redaction protocol:**
- Cookies: blur the cookie value, leave the cookie name
- Session tokens: blur completely
- Other user's PII: blur names, emails, phone numbers, addresses
- Internal IPs: blur, note "internal IP" as the value
- Authentication headers: blur completely

**Evidence naming:**
```
evidence/IDOR-user-profile/
  screenshot-request.png
  screenshot-response.png
  request-raw.txt
  response-raw.txt
  chain-notes.md
```

### 6. Report (30 minutes per finding)

**Structure:**
```
Title: [Bug Class] on [Endpoint] leads to [Impact]
Severity: P1/P2/P3/P4 (with CVSS 3.1 vector)
Impact: One-sentence summary of real harm
Description: 2-3 paragraphs explaining the bug
Steps to Reproduce: Numbered steps from clean browser state
PoC: Exact curl command or request/response pair
Evidence: Screenshot/HAR attachment
Chain: (if applicable) Chain primitives and combined impact
```

**Writing discipline:**
- First paragraph = the impact (not the endpoint description)
- No "could potentially" language — prove it or don't report it
- Every step is reproducible from a clean state
- Attachments are named and referenced in the text

### 7. Track (2 minutes)

**After submission:**
- Find the submission UUID/ID from the platform
- Append to `submissions.txt`:
  ```
  2026-06-08 | IDOR-user-profile | P3 | submitted | <UUID>
  ```
- If chain: add chain reference in square brackets:
  ```
  2026-06-08 | IDOR-user-profile | P3 | submitted | <UUID> [chains with SSRF-cloud-metadata]
  ```

---

## Daily Session Rhythm

### Session Timebox: 90-120 minutes

```
0:00 - 0:05  — Scope check (re-read scope.md, verify no OOS changes)
0:05 - 0:30  — Recon (subdomain/tech/JS/cloud)
0:30 - 1:30  — Hunt (bug class rotation on identified endpoints)
1:30 - 1:40  — Validate any leads (7-Question Gate)
1:40 - 1:50  — Capture evidence (if finding confirmed)
1:50 - 2:00  — Technique capture + dead end logging
```

### Anti-Pattern: The Open-Ended Session

"Let me just check one more endpoint" is how 3-hour sessions become 6-hour sessions.
Set a timer. When it fires, the session is over. No exceptions.

### Anti-Pattern: Multiple Browser Tabs

Opening multiple endpoints in parallel tabs = context switching in disguise.
Test one endpoint. Close it. Test the next. The browser shows your focus.

---

## Engagement Rules

- All testing on accounts I own.
- Stop on encountering other-user PII; document and report.
- No public disclosure until program explicitly approves.
- Burp proxy capturing through all browser sessions for this target.

---

## Evidence Capture Protocol Per Finding Type

### IDOR
- Screenshot: Burp Repeater showing the request with modified ID and the response with another user's data
- Highlight: the modified parameter and the leaked data
- Include: the original (authorized) request for comparison

### SSRF
- Screenshot: Burp Collaborator or Interact.sh showing the callback
- Include: the redirect chain (if URL-based SSRF)
- Include: the cloud metadata response (if metadata endpoint accessible)

### XSS
- Screenshot: Browser alert() dialog or console.log of document.cookie
- Include: the payload in the source code view
- Chain: If stored XSS, show the stored payload persisting across page loads

### Auth Bypass
- Screenshot: Two browser windows — non-admin window accessing admin endpoint
- Include: the request/response that demonstrates the bypass
- Include: cookie or header modification that enabled the bypass

### Business Logic
- Screenshot: The unexpected outcome (negative price, deleted data, transferred balance)
- Include: step-by-step of the normal flow vs the exploited flow
- Include: any error messages or unexpected responses

### Race Condition
- Screenshot: Burp Turbo Intruder or Python script showing concurrent requests
- Include: the successful double-redemption or double-action result
- Include: the timing window (millisecond precision if possible)

---

## Chain Documentation Standards

When chaining primitives A + B → C, document:

```
# Chain: [Short Name]

## Primitive A: [Type]
- Endpoint: 
- Method: 
- Request: 
- Response: 

## Primitive B: [Type]
- Endpoint: 
- Method: 
- Request: 
- Response: 

## Condition C (if applicable):
- What must be true for the chain to work?

## Combined Exploit:
- Step-by-step from clean state
- Exact requests

## Combined Impact:
- What does the chain achieve that neither primitive achieves alone?
- Why is this Critical/High when each primitive alone is Low/Medium?

## Evidence:
- Screenshots of each step
- Chain diagram (text-based):
  [A: IDOR on user_id] → leaks session_token
  [B: session_token] → authenticates as victim
  → Full account takeover
```

---

## Submission Tracker

Maintain `submissions.txt` in this format:

```
# Submissions for <target>

Date       | Finding                     | Severity | Status    | UUID
-----------|-----------------------------|----------|-----------|--------------------------------------
2026-06-08 | IDOR-user-profile           | P3       | submitted | 550e8400-e29b-41d4-a716-446655440000
2026-06-08 | SSRF-cloud-metadata         | P2       | submitted | 6ba7b810-9dad-11d1-80b4-00c04fd430c8
2026-06-08 | Chain: IDOR+SSRF->creds     | P1       | submitted | f47ac10b-58cc-4372-a567-0e02b2c3d479 [chains 550e8400 and 6ba7b810]

# Stats
Total submissions: 3
Chains: 1 (33%)
Pending response: 3
Accepted: 0
N/A: 0
N/A rate: 0%
```

---

## Post-Engagement Review

After the engagement ends (target dropped or completed):

### Retrospective Format

```
# Retro: <target>

## What worked
- [ ] Bug class rotation was effective
- [ ] Scope parsing was accurate
- [ ] Disclosed report reading was valuable
- [ ] Evidence capture was clean
- [ ] Report writing was fast

## What didn't work
- [ ] What approach was wasted time?
- [ ] What would I skip next time?
- [ ] What did I misunderstand about the target?

## What I learned
- Techniques discovered:
- Dead ends that future-me should know about:
- Tool improvements needed:

## Would I hunt this target again?
- Yes, if: [conditions]
- No, because: [reasons]

## Next target priority:
1. 
2. 
3. 
```

### Metrics to Track

| Metric | This Target | Running Average |
|--------|------------|-----------------|
| Hours spent | | |
| Findings submitted | | |
| Findings accepted | | |
| N/A rate | | |
| Average severity | | |
| Techniques discovered | | |
| Session count | | |

---

## Time Management

### Session Budget

| Activity | Budget | Override |
|----------|--------|----------|
| Recon | 60 min | +30 if new subdomains found |
| IDOR testing | 30 min | +15 if signal detected |
| SSRF testing | 20 min | +10 if callback received |
| Auth bypass | 30 min | +15 if bypass partially works |
| Business logic | 30 min | +15 if understanding deepens |
| Reporting | 30 min per finding | Never rush reporting |
| Technique capture | 10 min | Always do this |

### Weekly Budget

| Day | Activity |
|-----|----------|
| Monday | New target recon + first hunt session |
| Tuesday | Hunt session 2 + evidence cleanup |
| Wednesday | Hunt session 3 + report writing |
| Thursday | Hunt session 4 + submission |
| Friday | Rest / technique capture / system maintenance |
| Weekend | Disclosed report reading + skill building |

---

## Energy Management

Hunting is cognitively demanding. Your brain is the most important tool.

### Signs of Cognitive Fatigue
- Reading the same response three times
- Forgetting what parameter you just modified
- Opening the same URL in Burp Repeater twice
- Feeling annoyed at normal responses
- Checking the submission platform obsessively

### Recovery Protocol
1. Stand up. Walk away from the computer.
2. 10 minutes minimum — no screens, no reading, no thinking about the target
3. Drink water. Eat something if hungry.
4. When you return: review what you were doing before the break. Do not resume mid-flow — re-read the last 5 requests.

### Peak Performance Hours
Hunt during YOUR peak cognitive hours, not arbitrary hours:
- Morning person: Hunt 7am-10am
- Night owl: Hunt 8pm-11pm
- No preference: Hunt whenever you're most alert

Do NOT hunt when tired, hungover, distracted, or emotionally upset. Your judgment is impaired. You will make mistakes that waste hours.

---

## What to Do When Stuck

### The Stuck Protocol

Level 1: No signal on current endpoint after 30 minutes.
→ Rotate to a different endpoint on the same target.

Level 2: No signal on current target after 3 hours.
→ Read 3 disclosed reports for the same bug class on similar tech stacks.

Level 3: No signal on current target after 2 sessions.
→ Pause. Read the target's API documentation, engineering blog, and changelog thoroughly. Map the data flow.

Level 4: No signal on current target after 4 sessions.
→ Consider switching targets. This target may not be a good fit for your current methodology. Come back after you've learned a new technique.

Level 5: No signal across 3 consecutive targets.
→ Take a week off. Read methodology-heavy books/papers. Study disclosed reports from elite hunters. The problem is probably your approach, not the targets.

### When You Find Something But Can't Exploit It

1. Document everything — the endpoint, the parameters, the response, why you think it's exploitable, and what you tried.
2. Take a break. Come back with fresh eyes.
3. If still stuck: research the specific technology involved. There's probably a write-up for that framework/library.
4. If STILL stuck: ask in a private community. Share the technique you've tried, not the target-specific details.
5. If you cannot fully exploit: submit what you have with clear documentation of what you proved. Some programs accept partial exploitation if the impact is demonstrated.

---

## Break Protocols

### Between Tests (2-5 minutes)
- Stretch. Look at something 20+ feet away. Close your eyes for 30 seconds.

### Between Sessions (10-30 minutes)
- Walk. Get sunlight. Do not check submission platforms during breaks.

### Between Days (minimum 8 hours)
- Do not think about the target. Do not check the platform. Do not read security content.

### Weekly (1 full day)
- No hunting. No platform checking. No security reading. Rest your brain.

---

## End-of-Session Checklist

Every session must end with:

- [ ] All leads documented in `notes.md`
- [ ] Any confirmed findings passed through 7-Question Gate
- [ ] Evidence captured and redacted
- [ ] Techniques discovered added to technique library
- [ ] Dead ends documented (save future-me from repeating them)
- [ ] Burp project saved
- [ ] MCP servers stopped (if applicable)
- [ ] `submissions.txt` updated (if submissions were made)
- [ ] Next session's plan noted in `notes.md`

---

## Escalation Paths

### What to Do When...

**...you accidentally access PII:**
1. Stop testing immediately
2. Document what you accessed (for the report)
3. Do NOT download, save, or exfiltrate the data
4. Report it to the program as an information disclosure finding
5. Do not continue testing until the program responds

**...a test causes a service disruption:**
1. Stop testing immediately
2. Note what request caused the disruption
3. Report it to the program with full transparency
4. Do not test that endpoint again

**...you find a bug that's clearly being actively exploited:**
1. Document everything
2. Do NOT share publicly
3. Submit through the program's emergency contact or the platform's vulnerability disclosure channel
4. If no emergency channel exists, submit normally but flag as urgent

**...a program is unresponsive (90+ days with no response):**
1. Send one follow-up via the platform
2. If still unresponsive after 30 more days: follow the program's disclosure policy
3. If no policy exists: wait 120 days total from submission, then consider disclosure
4. NEVER publicly disclose without due diligence — this is the fastest way to get banned

**...you're not sure if something is a bug:**
1. Document it anyway (in `notes.md`)
2. Test it with a fresh perspective in the next session
3. If still unsure: flesh out a proof of concept and test it end-to-end
4. If the PoC shows real harm: submit. If not: kill it.
