# Lessons Log

Persistent record of every learning event — kills, N/As, paid submissions, triager
feedback, and pattern discoveries. This is how you get better: by systematically
analyzing what works and what doesn't.

---

## Table of Contents

1. [How to Use This Log](#1-how-to-use-this-log)
2. [Killed Findings Log](#2-killed-findings-log)
3. [N/A Submissions Log](#3-na-submissions-log)
4. [Paid Submissions Log](#4-paid-submissions-log)
5. [Triager Feedback Analysis](#5-triager-feedback-analysis)
6. [Personal Improvement Tracking](#6-personal-improvement-tracking)
7. [Pattern Discovery Log](#7-pattern-discovery-log)
8. [Chain Breakthroughs](#8-chain-breakthroughs)
9. [Time Management Reflections](#9-time-management-reflections)
10. [Tool & Workflow Improvements](#10-tool--workflow-improvements)
11. [External Lessons (Disclosed Reports)](#11-external-lessons-disclosed-reports)
12. [Common Mistakes Tracker](#12-common-mistakes-tracker)
13. [Skill Development Plan](#13-skill-development-plan)
14. [Quarterly Retrospectives](#14-quarterly-retrospectives)
15. [Annual Summary](#15-annual-summary)

---

## 1. How to Use This Log

### Entry Types

| Type | Prefix | When to Write |
|------|--------|---------------|
| Kill | `KILL:` | When a finding is killed before submission |
| N/A | `NA:` | When a submitted finding is rejected as N/A |
| Pay | `PAY:` | When a submission is accepted and paid |
| Feedback | `FB:` | When triager gives specific feedback |
| Pattern | `PAT:` | When you notice a recurring pattern |
| Chain | `CHAIN:` | When a chain breakthrough happens |
| Tool | `TOOL:` | When you improve a tool or workflow |
| Lesson | `LESSON:` | General learning from any source |

### Entry Structure

```
## YYYY-MM-DD: [TYPE] — [Brief Description]

### Context
- Target: [domain]
- Bug Class: [IDOR/XSS/SSRF/etc.]
- What Happened: [Detailed description]
- Why It Happened: [Root cause analysis]

### Analysis
- What went right: [What you did correctly]
- What went wrong: [What could have been better]
- What to do differently: [Actionable change for next time]

### Rules Implications
- Does this suggest a new rule? [Yes/No — if yes, draft rule]
- Does this suggest a rule change? [Yes/No — if yes, what change]
- What would have prevented this? [Earlier application of which rule?]

### Tags
[#target #{target} #bug {bug-type} #lesson {lesson-type}]
```

### Monthly Review Process

At the end of each month:
1. Read all entries from the month
2. Identify top 3 patterns (what worked, what didn't)
3. Update rules based on findings
4. Update technique library with new techniques
5. Update improvement tracker

---

## 2. Killed Findings Log

### What Counts as a Kill

A finding is "killed" when it is discovered during hunting but determined to be
not worth submitting. Reasons include:
- Fails one of the 7-Question Gates
- Is on the Always-Rejected list
- Cannot be reproduced reliably
- The impact is too low to justify report writing time

Kills are not failures — they are learning opportunities. Each kill teaches you
what to avoid next time and often reveals chain primitives.

### Kill Entry Template

```
## YYYY-MM-DD: KILL — [Bug Class] in [Feature]

### The Finding
- Target: [domain]
- Endpoint: [URL]
- What it does: [Description of the finding]
- Why it looked promising: [What made you think it was worth testing]

### Kill Decision
- Kill Reason: [Which gate it failed / why it's not submittable]
- Kill Gate:
  [ ] Q1 — Not externally exploitable
  [ ] Q2 — Affects too few users
  [ ] Q3 — No reliable PoC
  [ ] Q4 — Intended behavior
  [ ] Q5 — Unclear business impact
  [ ] Q6 — Out of scope
  [ ] Q7 — Already reported / public
  [ ] Always-Rejected List
  [ ] Reproducibility issues
  [ ] Impact too low

### Could This Become a Finding?
- Chainable with: [What other primitive would make this valid]
- Required change: [What would need to change]
- Priority for chaining: [High/Medium/Low]

### What I Learned
- [Key takeaway]
- [How to detect similar situations faster]
- [What to do differently next time]

### Tags
#kill #{bug-class} #gate{gate-number}
```

### Kill Entries

```
## 2026-06-05: KILL — Missing CSP Headers on CoinDesk Sandbox

### The Finding
- Target: coinmarketcap.sandbox
- Endpoint: Multiple API endpoints
- What it does: Content-Security-Policy header is missing from responses
- Why it looked promising: Without CSP, any XSS can exfiltrate data without restriction

### Kill Decision
- Kill Reason: Always-Rejected List (item #1 — Missing CSP/HSTS/X-Frame-Options)
- Kill Gate: Always-Rejected List

### Could This Become a Finding?
- Chainable with: XSS finding on the same endpoint
- Required change: CSP missing + stored XSS with admin impact
- Priority for chaining: Medium (we have JWT bypass already, XSS would need separate discovery)

### What I Learned
- Missing security headers are always rejected alone — never waste time writing these up
- But note them for later: if we find stored XSS, CSP absence becomes relevant
- This took 5 minutes to consider — good kill decision, minimal time wasted

### Tags
#kill #csp #always-rejected
```

```
## 2026-06-05: KILL — API Key in CoachDesk JS Bundle

### The Finding
- Target: coinmarketcap.sandbox
- Endpoint: Static JS bundle file
- What it does: An API key was found in a JS bundle during URL/secret extraction
- Why it looked promising: Could be a valid API key for internal service access

### Kill Decision
- Kill Reason: Could not verify the key was active or sensitive
- Kill Gate: Q3 — No reliable PoC (could not demonstrate the key worked)

### Could This Become a Finding?
- Chainable with: API endpoint that accepts this key
- Required change: Need to find the service this key authenticates to
- Priority for chaining: Low

### What I Learned
- Not all API keys in JS bundles are sensitive — many are public-facing keys (Stripe publishable, Google Maps, etc.)
- To prove a key is sensitive, you must demonstrate actual access it grants
- JS bundle secret extraction is useful but always verify before reporting
- Add a step to the JS analysis workflow: test discovered keys against their suspected services before cataloguing

### Tags
#kill #js-analysis #secret-scanning #gate-q3
```

```
## 2026-06-05: KILL — Open Redirect on Partner Routing Endpoint

### The Finding
- Target: coinmarketcap.sandbox
- Endpoint: GET /api/v3/partner/routing?url=https://attacker.com
- What it does: The partner routing endpoint accepts a URL parameter and redirects
- Why it looked promising: Open redirect alone is always rejected, but could chain

### Kill Decision
- Kill Reason: Always-Rejected List (item #4 — Open Redirect Alone)
- Kill Gate: Always-Rejected List

### Could This Become a Finding?
- Chainable with: OAuth redirect_uri validation bypass
- Required change: Need to find an OAuth flow that uses redirect_uri, then chain
- Priority for chaining: Medium (OAuth providers ARE configured according to /auth/providers)

### What I Learned
- Open redirect is a chain primitive, not a finding
- Always save open redirect details for potential OAuth chaining
- The partner routing endpoint has OAuth providers configured (Google, Apple, Facebook) — potential chain
- Added to chain primitives list

### Tags
#kill #open-redirect #chain-primitive #always-rejected
```

### Kill Log Summary

| # | Date | Target | Bug Class | Kill Reason | Could Chain? |
|---|------|--------|-----------|-------------|--------------|
| 1 | 2026-06-05 | coinmarketcap.sandbox | Missing CSP | Always Rejected | With XSS (Medium) |
| 2 | 2026-06-05 | coinmarketcap.sandbox | API Key in JS | Q3 — No PoC | Unlikely |
| 3 | 2026-06-05 | coinmarketcap.sandbox | Open Redirect | Always Rejected | With OAuth (Medium) |

---

## 3. N/A Submissions Log

N/A submissions are the most painful learning experiences. Each one hurts your
validity ratio. Log every one to prevent repeats.

### N/A Entry Template

```
## YYYY-MM-DD: NA — [Bug Class] in [Feature]

### The Submission
- Target: [domain]
- Program: [program]
- Bug Class: [bug class]
- Severity Claimed: [CVSS]
- Date Submitted: [date]
- Date NA'd: [date]

### What the Program Said
[Exact triager response, ideally quoted]

### Root Cause Analysis
- Why was it N/A?
  [ ] Not actually exploitable
  [ ] Intended behavior
  [ ] Already known/fixed
  [ ] Out of scope
  [ ] Impact too low
  [ ] Lack of evidence
  [ ] Wrong bug class / VRT category
- What did I miss?
- What should I have checked before submitting?

### Impact on Validity Ratio
- Validity ratio before: [X%]
- Validity ratio after: [Y%]
- Programs affected: [List]

### Rule Update Required?
[ ] Yes — add a rule to prevent this from happening again
[ ] No — this was a one-off mistake

If yes, describe the rule: [description]

### What I Will Do Differently
- [Actionable change 1]
- [Actionable change 2]

### Tags
#na #{bug-class} #na-reason
```

### N/A Entry Format (for quick reference when no full analysis is needed)

```
## YYYY-MM-DD: NA — Brief
Target: [domain]
Bug: [description]
Why N/A: [reason]
Lesson: [one-sentence lesson]
```

### N/A Log Summary

| # | Date | Target | Bug Class | NA Reason | Impact on Ratio | Lesson |
|---|------|--------|-----------|-----------|-----------------|--------|
| — | — | — | — | — | — | — |

---

## 4. Paid Submissions Log

Paid submissions are what this is all about. Log every one to understand what works.

### Paid Entry Template

```
## YYYY-MM-DD: PAY — [Bug Class] in [Feature]

### The Submission
- Target: [domain]
- Program: [program]
- Bug Class: [bug class]
- CVSS Score: [score]
- Severity: [Critical/High/Medium/Low]
- Payout: [amount]
- Date Submitted: [date]
- Date Triaged: [date]
- Date Paid: [date]
- Total Days: [submission to payment]

### The Finding
- Endpoint: [URL]
- Method: [GET/POST/PUT/etc.]
- Auth Required: [Yes/No — what level]
- Description: [What the bug was]
- Impact: [What an attacker can do]

### What Worked
- Technique used: [Which technique from the library]
- How I found it: [The exact process that led to discovery]
- Why it passed triage: [What made this report successful]
- Evidence quality: [What evidence made the difference]

### What I Would Do Differently
- Even though it paid, what could have been better?

### Chain Opportunities
- Does this finding chain with anything? Yes/No
- Chain possibilities: [description]

### Tags
#pay #{bug-class} #{severity} #${amount}
```

### 4.1 Report Quality Self-Assessment

For every paid submission, rate your report quality:

| Criterion | Rating (1-5) | Notes |
|-----------|-------------|-------|
| Title clarity | — | Does it describe the bug and impact? |
| Summary impact | — | One sentence that makes triager care? |
| PoC completeness | — | Can triager reproduce from screenshots alone? |
| CVSS accuracy | — | Does it match actual impact? |
| Evidence quality | — | Screenshots, HAR, all redacted? |
| Business impact | — | Clear translation of technical impact? |
| Fix suggestion | — | Actionable and correct? |

### 4.2 Paid Finding Patterns

After multiple paid submissions, analyze what they have in common:

| Finding | Endpoint Type | Auth Required | How Found | Time to Find | Differentiator |
|---------|---------------|---------------|-----------|-------------|---------------|
| — | — | — | — | — | — |

Patterns to look for:
- Are most paid findings in API endpoints? (usually yes)
- Are most findings found via parameter tampering? (usually yes)
- Do most findings require authentication? (depends on the target)
- What is the most common bug class in paid findings?

### 4.3 Paid Submission Log

| # | Date | Target | Bug Class | Severity | Payout | Time to Find | Time to Report | Tags |
|---|------|--------|-----------|----------|--------|-------------|----------------|------|
| — | — | — | — | — | — | — | — | — |

---

## 5. Triager Feedback Analysis

### 5.1 Feedback Collection

Every interaction with a triager is a learning opportunity. Record all feedback here:

```
## YYYY-MM-DD: FB — [Program/Target]

### Feedback Context
- Target: [domain]
- Finding: [bug class]
- Triager: [name if known, otherwise "anonymous"]
- Feedback Method: [comment / email / phone / platform message]

### Feedback Received
[Exact text of the feedback]

### Analysis
- What was the triager's perspective?
- What did they value in the report?
- What did they criticize?
- Was the feedback fair?

### Action Items
- [ ] [Action 1]
- [ ] [Action 2]

### Tags
#feedback #{program}
```

### 5.2 Feedback Patterns

Track common themes in triager feedback:

| Pattern | Frequency | What Triagers Want | How to Adapt |
|---------|-----------|-------------------|--------------|
| Too theoretical | — | Concrete PoC, demonstrated impact | Never use weasel words, show data |
| Insufficient evidence | — | Clear screenshots, full request/response | Follow evidence.md strictly |
| Wrong severity | — | CVSS must match actual impact | Use CVSS calculator, be conservative |
| Already reported | — | Check disclosed reports before submitting | Run Q7 more carefully |
| Out of scope | — | Read scope carefully | Verify scope before testing |
| Intended behavior | — | Check documentation, API specs | Test with intended behavior in mind |

### 5.3 Triager Communication Tips

Based on feedback patterns, these approaches work:

**DO:**
- Be professional and concise
- Thank the triager for their time
- Accept feedback gracefully
- Provide exactly what they ask for
- Be patient with triage delays

**DON'T:**
- Argue severity unless it's clearly wrong
- Get defensive about N/A'd findings
- Submit the same finding to multiple programs
- Pester triagers for status updates
- Threaten to disclose publicly

---

## 6. Personal Improvement Tracking

### 6.1 Skill Self-Assessment

Periodically rate your skills on a 1-5 scale:

| Skill | Rating (1-5) | Notes | Target Rating | Improvement Plan |
|-------|-------------|-------|---------------|------------------|
| IDOR Detection | 3 | Comfortable with sequential, need practice with UUID patterns | 5 | Study disclosed IDOR reports |
| Auth Bypass | 2 | Know the basics, need X-Forwarded-For techniques | 4 | Dedicated auth bypass session |
| SSRF | 2 | Basic cloud metadata, need internal service discovery | 4 | Practice with SSRF labs |
| JWT Attacks | 3 | alg:none works, need JWK injection practice | 4 | Read more JWT attack reports |
| XSS | 3 | Stored/reflected, need blind XSS setup | 4 | Set up blind XSS infrastructure |
| SQLi | 2 | Classic error-based, need blind/time-based | 4 | SQLMap practice |
| Business Logic | 2 | Coupon stacking works, need more patterns | 4 | Study business logic writeups |
| File Upload | 2 | Basic webshell, need more bypass techniques | 3 | File upload challenge practice |
| API Misconfig | 2 | Mass assignment, need prototype pollution | 4 | Node.js security research |
| Race Conditions | 1 | Understand theory, need practical setup | 3 | Turbo Intruder practice |
| Subdomain Takeover | 1 | Know theory, need scanning setup | 3 | Run on test targets |
| GraphQL | 2 | Introspection, need batching attacks | 4 | GraphQL security labs |
| CORS | 3 | Reflected origin, need more bypasses | 4 | Practice edge cases |
| SSTI | 1 | Know detection, need exploitation | 3 | SSTI labs |
| SAML/SSO | 1 | No experience | 2 | Study SAML attack fundamentals |
| Mobile API | 1 | No experience | 2 | Set up mobile testing |
| Chain Building | 2 | Understand theory, need practical chains | 4 | Study chain writeups |
| Report Writing | 3 | Good structure, need more impact focus | 5 | Use report templates always |

### 6.2 Goal Tracking

| Goal | Target Date | Status | Notes |
|------|-------------|--------|-------|
| First paid finding | — | Not started | Need to submit CoinDesk JWT |
| Validity ratio > 80% | — | Not started | Requires careful pre-submit validation |
| 5 paid findings | — | Not started | — |
| $10,000 total payout | — | Not started | — |
| Private program invitation | — | Not started | Build reputation on public first |
| Master SSRF chains | — | Not started | Labs + practice |
| Learn prototype pollution | — | Not started | Node.js security study |
| Set up blind XSS infrastructure | — | Not started | Choose collaborator/interact.sh |

### 6.3 Session Self-Review Template

After every hunting session, complete this review:

```
### Session Review: YYYY-MM-DD
Target: [domain]
Duration: [hours]

Productivity Score: [1-10]
- Findings found: [N]
- Findings killed: [N]
- Findings submitted: [N]

Time Efficiency Score: [1-10]
- Time wasted on: [what]
- Time well spent on: [what]
- Should have spent more time on: [what]

Skills Used: [list]
Skills to Improve: [list]

Lesson Learned: [one sentence]
```

---

## 7. Pattern Discovery Log

### 7.1 Pattern Entry Template

```
## PAT: [YY-MM-DD] — [Pattern Description]

### Pattern
- Category: [Tech Stack Pattern / Developer Mistake / Program Behavior / Bug Class Trend]
- Description: [What pattern was observed]

### Evidence
- Observation 1: [When/where this was seen]
- Observation 2: [When/where this was seen]
- Confidence: [High/Medium/Low]

### Implications
- How to exploit this pattern: [What to do when you see this pattern]
- What to test first: [Specific technique to use]
- Expected success rate: [Based on frequency]

### Cross-Reference
- Related techniques: [technique names]
- Related targets: [target names]
- Related rules: [rule references]

### Tags
#pattern #{category}
```

### 7.2 Pattern Entries

```
## PAT: [26-06-06] — Next.js API Routes Frequently Miss Auth

### Pattern
- Category: Tech Stack Pattern
- Description: Next.js applications commonly have API routes in `/api/`
  that are not behind authentication middleware. The developer creates a
  serverless function at `/api/users/list` and forgets to add auth middleware
  because the route is "just an internal API."

### Evidence
- Observation 1: CoinDesk Sandbox JWT is self-issued (client-side creates the JWT)
- Observation 2: Multiple disclosed reports on H1 for Next.js API auth bypass
- Confidence: High

### Implications
- When you see Next.js (look for `_next/static`, `__NEXT_DATA__`), immediately test:
  - `/api/` routes without auth headers
  - `getServerSideProps` data exposure
  - `__NEXT_DATA__` JSON for leaked data
- Expected success rate: ~50% of Next.js targets have at least one unprotected API route

### Cross-Reference
- Related techniques: JWT alg:none, Direct Navigation Auth Bypass
- Related targets: coinmarketcap.sandbox
- Related rules: hunting.md — Phase 3 priority order

### Tags
#pattern #tech-stack #nextjs
```

```
## PAT: [26-06-06] — JWT alg:none on Self-Issued Tokens

### Pattern
- Category: Developer Mistake Pattern
- Description: Applications that issue JWTs client-side (in the browser JavaScript)
  frequently have alg:none vulnerabilities. The developer writes code like
  `jwt.sign(payload, 'secret')` and the verification is server-side. But many
  JWT libraries accept `alg: none` by default.

### Evidence
- Observation 1: CoinDesk Sandbox JWT is created in the browser with `jsonwebtoken` library
- Observation 2: 15+ disclosed H1 reports for alg:none on self-issued JWT systems
- Confidence: High

### Implications
- When you see a JWT in a JS bundle that is created client-side, ALWAYS test alg:none
- This is a 2-minute test that pays High/Critical
- Expected success rate: ~30% of client-side JWT implementations
- Look for `jwt.sign`, `jsonwebtoken`, `jose` in JS bundle analysis

### Cross-Reference
- Related techniques: JWT alg:none Attack, JWK Header Injection
- Related targets: coinmarketcap.sandbox
- Related rules: hunting.md — JWT Attacks section

### Tags
#pattern #jwt #developer-mistake
```

```
## PAT: [26-06-06] — Registration Disabled = Unusual Auth Model

### Pattern
- Category: Developer Mistake / Business Decision Pattern
- Description: When a target has registration disabled, it suggests one of:
  a) The application is invitation-only (prev. test accounts)
  b) The application is in beta/pre-release
  c) The application is meant to be a companion to a paid service
  d) The application was meant to be internal but was exposed externally

### Evidence
- Observation 1: Boozt has disableSignup='1' — registration disabled globally
- Observation 2: Multiple apps with disabled registration still have public API endpoints
- Confidence: High

### Implications
- Registration disabled means most researchers skip this target — less competition
- But also means you must find an alternative account creation path
- Common alternatives: OAuth social login, partner access, invite abuse, mobile app registration
- When registration is disabled, focus on: unauthenticated endpoints, password reset flows,
  OAuth flows, mobile app API

### Cross-Reference
- Related techniques: OAuth flow testing, host header injection (password reset)
- Related targets: boozt.com
- Related rules: hunting.md — Account creation strategies

### Tags
#pattern #registration #auth-model
```

### 7.3 Pattern Index

| # | Date | Pattern | Category | Confidence | Technique |
|---|------|---------|----------|------------|-----------|
| 1 | 2026-06-06 | Next.js API routes miss auth | Tech Stack | High | Test /api/ without auth |
| 2 | 2026-06-06 | Self-issued JWT = alg:none likely | Developer Mistake | High | Test alg:none |
| 3 | 2026-06-06 | Registration disabled = auth model | Business Decision | High | Find alternative auth path |

---

## 8. Chain Breakthroughs

### 8.1 Chain Entry Template

```
## CHAIN: [YY-MM-DD] — [Primitive A] + [Primitive B] = [Result]

### The Chain
- Primitive A: [description]
- Primitive B: [description]
- Result: [what the chain achieves]

### How It Was Discovered
- Were you looking for this specific chain?
- What prompted the idea?
- How long did it take to construct?

### Technical Details
[Step-by-step chain construction]

### Would This Have Paid?
- Estimated severity: [CVSS]
- Estimated payout: [amount]
- Would it pass the 7-Question Gate? Yes/No

### Related Disclosed Reports
[Links to similar chains that paid]

### Tags
#chain #{primitive-a}-#{primitive-b}
```

### 8.2 Chain Thinking Log

Not every chain attempt works. Document failed attempts too.

```
## CHAIN: [YY-MM-DD] — ATTEMPT: Open Redirect + OAuth = ???

### Chain Attempt
Tried to chain the open redirect on coinmarketcap.sandbox
with the OAuth providers (Google, Apple, Facebook).

### What Was Tried
1. Found open redirect on /api/v3/partner/routing?url=
2. Found OAuth providers at /api/v3/auth/providers
3. Tried to craft OAuth redirect_uri: {target}/partner/routing?url={attacker}
4. Result: Could not find OAuth authorization endpoint in sandbox

### Why It Failed
- The sandbox does not have OAuth login fully implemented
- The /auth/providers endpoint lists providers but no OAuth flow exists in sandbox
- Open redirect to OAuth chain requires a functioning OAuth authorization endpoint

### What Would Make It Work
- If production has a live OAuth flow
- If the redirect_uri validation allows paths (like /partner/routing)
- Open redirect must be a path on the same domain as the OAuth endpoint

### Next Steps
- Check if production coinmarketcap.com has a working OAuth flow
- If yes, the same open redirect may chain to auth code theft

### Tags
#chain #attempt-failed #open-redirect #oauth
```

### 8.3 Chain Idea Incubator

Ideas for chains that haven't been attempted yet:

| Idea | Primitives Needed | Target | Priority | Status |
|------|------------------|--------|----------|--------|
| IDOR -> ATO via email change | IDOR on /api/user/{id}/email | Any | High | Need IDOR write first |
| JWT bypass -> Stored XSS | JWT bypass to access admin panel + stored XSS in profile | coinmarketcap | Medium | Need stored XSS |
| Open redirect -> OAuth token | Open redirect + OAuth redirect_uri | coinmarketcap (prod) | Medium | Need prod OAuth flow |
| Password reset -> ATO | Host header injection + password reset flow | Boozt | High | Need to test reset flow |

---

## 9. Time Management Reflections

### 9.1 Session Efficiency Log

Track how you actually spend time vs how you planned to spend it:

```
## Session Efficiency: YYYY-MM-DD
Target: [domain]
Planned Duration: [hours]
Actual Duration: [hours]

### Planned Time Allocation
| Activity | Planned | Actual | Difference |
|----------|---------|--------|------------|
| Recon | 15m | 20m | +5m |
| Pre-hunt research | 15m | 10m | -5m |
| IDOR testing | 30m | 45m | +15m |
| Auth bypass testing | 30m | 15m | -15m |
| SSRF testing | 30m | 0m | -30m |
| XSS testing | 30m | 0m | -30m |
| Report writing | 30m | 0m | -30m |

### Observations
- Spent too much time on: [what]
- Should have spent more on: [what]
- Distractions: [what pulled focus]

### Adjustment for Next Session
- [Change 1]
- [Change 2]
```

### 9.2 Time Waster Analysis

Common time wasters to avoid:

| Time Waster | Cost | Solution |
|-------------|------|----------|
| Testing an obviously blocked endpoint | 5-10 min | Skip after 2 attempts |
| Perfecting a PoC before confirming the bug | 15-30 min | Confirm first, then capture evidence |
| Reading long API documentation | 20-60 min | Read summaries, test endpoints directly |
| Debugging tool issues | 15-60 min | Use simpler tools, fix first |
| Researching a tech stack you don't know | 20-60 min | Jump to testing, learn as you go |
| Obsessing over getting everything right | 30+ min | 80% is enough, move on |
| Testing an endpoint for every bug class | 60+ min | Test top 3 bug classes, come back later |
| Writing a report for a borderline finding | 30-60 min | Kill it and move on |



## 10. Tool & Workflow Improvements

### 10.1 Improvement Entry Template

```
## TOOL: [YY-MM-DD] — [Improvement Description]

### What Was the Problem?
[Description of the workflow bottleneck / tool limitation]

### What Was Improved?
[Description of the improvement]

### Impact
- Time saved: [estimation]
- Quality improved: [how]
- Errors reduced: [what errors]

### Implementation
- File(s) changed: [paths]
- Migration needed: [yes/no]
- Rollback plan: [if needed]

### Tags
#tool #{tool-name}
```

### 10.2 Improvement Log

| # | Date | Tool/Process | Improvement | Impact |
|---|------|-------------|-------------|--------|
| — | — | — | — | — |

### 10.3 Future Improvement Ideas

| Idea | Expected Impact | Difficulty | Priority |
|------|----------------|------------|----------|
| Automate JWT alg:none testing | 2 min instead of 5 | Easy | High |
| Create a "quick check" script (tests top 5 bug classes) | 10 min for full sweep | Medium | High |
| Automate subdomain takeover scanning | 5 min per target | Medium | Medium |
| Template for session logging | 2 min to start logging | Easy | High |
| Python script for automated IDOR enumeration | Instant vs 10 min manual | Medium | Medium |

---

## 11. External Lessons (Disclosed Reports)

### 11.1 Lesson Entry Template

```
## LESSON: [YY-MM-DD] — [Source] — [Lesson Description]

### Source
- Platform: [HackerOne Hacktivity / Bugcrowd / Blog / Conference Talk]
- URL: [link]
- Title: [report title]
- Author: [researcher name if known]

### The Bug
- Target: [target if disclosed]
- Bug Class: [bug class]
- Payout: [amount if disclosed]

### Key Insight
[What made this bug interesting or unique]

### How They Found It
[Process description]

### How to Apply This
[How to replicate this approach on your targets]

### Rule Implication
[Does this suggest a new rule or technique update?]

### Tags
#lesson #{bug-class} #{source-type}
```

### 11.2 Disclosed Report Log

| # | Date | Target | Bug Class | Payout | Key Takeaway | Applied? |
|---|------|--------|-----------|--------|-------------|----------|
| — | — | — | — | — | — | — |

---

## 12. Common Mistakes Tracker

### 12.1 Personal Mistake Log

Track mistakes you keep making to identify patterns:

```
## MISTAKE: [YY-MM-DD] — [Mistake Description]

### What I Did
- Target: [domain]
- Context: [what was happening]
- The mistake: [description]

### Why It Happened
- Root cause: [why]
- Was I rushing? [yes/no]
- Did I skip a step? [which one]

### What It Cost Me
- Time wasted: [minutes]
- Missed finding: [yes/no — what]
- Validity ratio impact: [yes/no]

### How to Prevent
- New rule needed? [yes/no]
- Checkpoint to add? [yes/no — where]
- Habit to change? [which habit]

### Tags
#mistake #{type}
```

### 12.2 Personal Mistake Log Entries

```
## MISTAKE: [26-06-06] — Spending too long on Boozt registration bypass

### What I Did
- Target: boozt.com
- Context: Registration is disabled (disableSignup='1'), and I spent 2 hours trying 
  alternate account creation paths (OAuth, invite abuse, mobile API, regional stores)
- The mistake: I should have recognized this as a block earlier and either found 
  test credentials from the program or moved on

### Why It Happened
- Root cause: Over-optimism that I could find a bypass
- Was I rushing? No — the opposite, I was too thorough
- Did I skip a step? I skipped the "check if program provides test accounts" step

### What It Cost Me
- Time wasted: 2 hours
- Missed finding: Possibly — could have been hunting other targets
- Validity ratio impact: No (never submitted anything)

### How to Prevent
- New rule needed: Yes — if registration is disabled after 30 min of trying bypasses,
  kill the target or request test credentials from the program
- Checkpoint to add: Add a "registration blocked?" check at 30 min mark
- Habit to change: When hitting a wall, move on faster

### Tags
#mistake #time-management #registration
```

### 12.3 Mistake Patterns

| Mistake | Frequency | Cost | Prevention |
|---------|-----------|------|------------|
| Testing without confirming scope first | — | Medium — wasted time | Always run /scope first |
| Spending too long on a dead end | — | High — lost productivity | Use 10-minute rule strictly |
| Forgetting to save session logs | — | Low — lost learning | Use session template |
| Not checking for dupes before testing | — | High — wasted effort | Check program activity first |
| Writing reports for borderline findings | — | High — N/A ratio impact | 7-Question Gate more strictly |

---

## 13. Skill Development Plan

### 13.1 Learning Roadmap

| Month | Skill to Learn | Resources | Practice Target |
|-------|---------------|-----------|-----------------|
| June 2026 | SSRF fundamentals | SSRF Bible, PortSwigger labs | Any target with URL fetch |
| July 2026 | Blind XSS | Blind XSS methodology | Support/feedback forms |
| August 2026 | Prototype Pollution | Node.js security research | Node.js targets |
| September 2026 | Race Conditions | Turbo Intruder, asyncio | E-commerce targets |
| October 2026 | SAML Attacks | SAML Raider extension | SSO-enabled targets |
| November 2026 | Mobile API Testing | Android emulator, Burp | Targets with mobile apps |
| December 2026 | Chain Construction | Chain writeups, methodology | All targets |

### 13.2 Study Resources

| Resource | Skill | Format | Status |
|----------|-------|--------|--------|
| PortSwigger Web Security Academy | All web | Labs | Active |
| HackerOne Hacktivity (disclosed reports) | All | Reading | Active |
| PentesterLab | All | Labs | Not started |
| Bugcrowd University | All | Videos | Not started |
| OWASP Testing Guide | All | Documentation | Reference |
| JWT.io | JWT | Tool | Active |
| PayloadsAllTheThings | All | Cheatsheets | Active |
| HackTricks | All | Cheatsheets | Active |
| The Bug Hunter's Methodology | All | Book | Not started |
| Real World Bug Hunting | All | Book | Active |

---

## 14. Quarterly Retrospectives

### 14.0 Retrospective Methodology

Quarterly retrospectives are the most important review process. They force you to
step back from the day-to-day and see the big picture. Each retro covers:
1. **What happened** — raw data (sessions, hours, findings, payouts)
2. **What worked** — techniques, workflows, tools that produced results
3. **What didn't work** — time wasters, wrong approaches, dead ends
4. **What to change** — specific rule or workflow changes for next quarter
5. **Goals for next quarter** — measurable, achievable targets

### 14.1 Retrospective Entry Template

```
## RETRO: [Q1/Q2/Q3/Q4] [YEAR]

### Summary Statistics
- Total sessions: [N]
- Total hours: [N]
- Targets hunted: [N]
- Targets completed: [N]
- Targets archived: [N]
- Findings discovered: [N]
- Findings killed: [N]
- Findings submitted: [N]
- Findings paid: [N]
- N/A submissions: [N]
- Total payout: [$]

### Targets Hunted
| Target | Sessions | Hours | Findings Found | Findings Submitted | Findings Paid | Payout |
|--------|----------|-------|---------------|-------------------|---------------|--------|
| — | — | — | — | — | — | — |

### Bug Class Breakdown
| Bug Class | Found | Killed | Submitted | Paid | Payout |
|-----------|-------|--------|-----------|------|--------|
| IDOR | — | — | — | — | — |
| Auth Bypass | — | — | — | — | — |
| SSRF | — | — | — | — | — |
| XSS | — | — | — | — | — |
| SQLi | — | — | — | — | — |
| Business Logic | — | — | — | — | — |
| JWT Attacks | — | — | — | — | — |
| API Misconfig | — | — | — | — | — |
| File Upload | — | — | — | — | — |
| Race Conditions | — | — | — | — | — |
| Subdomain Takeover | — | — | — | — | — |
| Other | — | — | — | — | — |

### What Went Well
1. [Success 1]
2. [Success 2]
3. [Success 3]

### What Didn't Go Well
1. [Failure 1]
2. [Failure 2]
3. [Failure 3]

### Key Lessons
1. [Lesson 1]
2. [Lesson 2]
3. [Lesson 3]

### Technique Library Updates
- [New techniques added]
- [Techniques retired / updated]

### Rule Changes
- [Hunting rules updated]
- [Reporting rules updated]
- [Evidence rules updated]

### Goals for Next Quarter
- [ ] Goal 1
- [ ] Goal 2
- [ ] Goal 3
- [ ] Goal 4
- [ ] Goal 5

### System / Tool Improvements Needed
- [Improvement 1]
- [Improvement 2]
- [Improvement 3]
```

### 14.1 Q2 2026 Retro

```
## RETRO: Q2 2026 (Apr-Jun)

### Summary
- Total sessions: 1
- Total hours: 12
- Targets hunted: 2 (CoinDesk Sandbox, Boozt)
- Findings submitted: 0
- Findings killed: 3
- Findings paid: 0
- Total payout: $0

### What Went Well
- JS bundle analysis was effective (45+ API endpoints catalogued)
- JWT alg:none discovery in first session
- Report structure is solid

### What Didn't Go Well
- Only 2 targets explored in 3 months
- No submissions yet
- Boozt stalled due to blocked registration

### Lessons Learned
1. JWT alg:none is a quick win on any target using client-side JWTs
2. Registration-disabled targets need alternate account strategies
3. SKILL.md and rules files are comprehensive but need better discoverability
4. The adapter system (18 CLI targets) is a differentiator but needs validation

### Goals for Q3 2026
- [ ] Submit CoinDesk JWT finding
- [ ] Find and submit at least 3 more findings
- [ ] Achieve first payout
- [ ] Hunt 5 new targets
- [ ] Complete SSRF labs on PortSwigger
- [ ] Set up blind XSS infrastructure

### System Improvements Needed
- [ ] Better login/account creation workflow documentation
- [ ] Quick-start script that runs top 3 bug class checks
- [ ] Integration with Burp for automated testing
```

---

## 15. Annual Summary

### 15.1 2026 Year-to-Date

```
## SUMMARY: 2026 (Jan-Jun)

### Hunting Statistics
- Targets hunted: 2
- Total sessions: 1
- Total hours: 12
- Endpoints catalogued: 70+
- JS bundles analyzed: 8+

### Finding Statistics
- Findings discovered: 4 (3 killed, 0 submitted, 1 ready to submit)
- Findings submitted: 0
- Findings paid: 0
- Kill rate: 75%
- Submit rate: 0% (pending JWT submission)

### Payout Statistics
- Total payout: $0
- Average payout per finding: $0
- Best payout: $0
- Platforms used: HackerOne (studied), Bugcrowd (account created)

### System Building
- Agents: 17
- Rules: 13
- Tools: 7
- Plugin configs: 7
- Adapter targets: 18
- Total system lines: ~47,000+

### Key Accomplishments
1. Built comprehensive bug bounty skill system (Hercules-Hunt)
2. Successfully extracted 45+ API endpoints from CoinDesk JS bundles
3. Discovered JWT alg:none bypass on live target
4. Created universal adapter for 18 CLI platforms
5. Documented full hunting workflow (6 rule files, 1200+ lines each)

### Areas for Improvement
1. Need to submit more findings (0 submissions in 6 months)
2. Need more targets hunted (2 targets only)
3. Need more efficient session time utilization
4. Need better account creation strategies for auth-gated targets

### Priorities for H2 2026
1. SUBMIT FINDINGS — CoinDesk JWT goes first
2. Hunt 10+ new targets
3. Achieve $10,000+ in total payout
4. Get at least one Critical finding approved
5. Get invited to at least one private program
6. Continue building Hercules-Hunt based on real hunting feedback
```

---

### 15.1 Lessons Log Usage Guide

This log is only valuable if you use it. Here is the recommended workflow:

**After Every Session (5 minutes):**
1. Log any killed findings with kill reason
2. Log any paid findings with payout details
3. Log any triager feedback received
4. Complete a quick session self-review

**After Every Kill (2 minutes):**
1. Open the Kill entry template
2. Fill in target, bug class, kill reason
3. Note if it could chain with anything
4. One-sentence lesson learned

**Weekly Review (15 minutes):**
1. Review all entries from the week
2. Identify any emerging patterns
3. Update the pattern discovery log
4. Check chain primitives for new opportunities

**Monthly Review (30 minutes):**
1. Full pattern analysis
2. Skill self-assessment update
3. Goal progress check
4. Technique library review

**Quarterly Retro (1 hour):**
1. Full retrospective as documented above
2. Goal setting for next quarter
3. Major workflow or rule changes
4. System improvements planning

**Annual Summary (2 hours):**
1. Year-in-review analysis
2. Long-term trend identification
3. Major skill development planning
4. Career progression review (if applicable)

## Lessons Log Admin

- **Last Updated:** [YYYY-MM-DD]
- **Total Entries:** 0
- **Kill Entries:** 3
- **NA Entries:** 0
- **Pay Entries:** 0
- **Feedback Entries:** 0
- **Pattern Entries:** 3
- **Chain Entries:** 1
- **Tool Improvement Entries:** 0

### Maintenance Tasks
- [ ] Add entry after every hunting session
- [ ] Review all entries at end of each month
- [ ] Update pattern analysis after every 10 entries
- [ ] Update skill assessment quarterly
- [ ] Update goals monthly
- [ ] Review chain primitives quarterly
