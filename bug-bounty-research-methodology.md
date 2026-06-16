# Bug Bounty Research Methodology

The capstone document — Part 10 of a 10-part bug bounty methodology series. This document ties together all prior parts into a coherent overall research methodology and workflow, from target selection through post-submission learning.

## Table of Contents

1. [The Complete Bug Hunter's Mindset](#the-complete-bug-hunters-mindset)
2. [Phase-Based Hunting Workflow](#phase-based-hunting-workflow)
3. [Non-Linear Hunting](#non-linear-hunting)
4. [Target Selection](#target-selection)
5. [Session Management](#session-management)
6. [Tool Integration](#tool-integration)
7. [Research Efficiency](#research-efficiency)
8. [The Critical Thinking Framework](#the-critical-thinking-framework)
9. [Post-Bug Workflow](#post-bug-workflow)
10. [Continuous Learning](#continuous-learning)
11. [Burnout Prevention](#burnout-prevention)
12. [The Complete Master Checklist](#the-complete-master-checklist)

---

## The Complete Bug Hunter's Mindset

### Critical Thinking Framework

Every finding starts as a question. The quality of your questions determines the quality of your findings. This framework codifies the five cognitive lenses that separate top-tier hunters from everyone else.

#### Developer Psychology

Ask at every endpoint: *"What did the developer assume would never happen?"*

Developers operate under constraints — tight deadlines, incomplete requirements, inherited code, and an implicit trust model that assumes users follow the happy path. Your job is to find every place that trust model breaks.

```
Common developer assumptions:
- "Users will only send well-formed JSON"
- "The client will respect the field allowlist"
- "UUIDs are unguessable"
- "Internal endpoints are unreachable from the internet"
- "Rate limiting blocks automated attacks"
- "The ORM handles SQL injection"
- "CORS is a security boundary"
- "Authentication implies authorization"
```

Every assumption is a potential vulnerability. List the assumptions the developer made about each feature, then systematically violate them.

**Practical exercise:** Before testing any feature, write down 3 things the developer assumed would be true. Then test each one.

#### Anomaly Detection

Train yourself to notice what doesn't fit the pattern:

```
Normal:   POST /api/document → 201 Created
Normal:   GET  /api/document/123 → 200 OK
Normal:   POST /api/document/999 → 404 Not Found

Anomaly:  POST /api/document → 202 Accepted   (async processing — queue race?)
Anomaly:  GET  /api/document/123 → 301 Redirect (external redirect — open redirect?)
Anomaly:  POST /api/document → 500 Internal    (stack trace — information disclosure?)
Anomaly:  GET  /api/document/123 → 204 No Content (exists but no content — timing oracle?)
```

**What to look for:**

| Anomaly | What It Might Mean |
|---------|-------------------|
| Different status code than expected | WAF block, auth bypass, rate limiting hit |
| Response time spike | Database slow query, SSRF timing side-channel |
| Extra response headers | Technology fingerprint, debug mode enabled |
| Missing response headers | Different server handling the request |
| Different response size | Varying data returned, cache hit vs miss |
| Error message with data | SQL error, stack trace, internal path disclosure |
| Redirect to unexpected URL | Open redirect, SSRF trigger |
| Async processing (202) | Queue race condition, async IDOR |
| WebSocket messages you shouldn't see | Broadcast misconfiguration |

**Train the pattern:** Spend 10 minutes per session skimming responses for anything that doesn't match the expected pattern. Don't analyze — just notice. Then investigate anomalies.

#### What-If Experiments

For every feature, ask "What if I change one thing?":

```python
what_if_scenarios = [
    "What if I send a negative number?",
    "What if I send a string instead of an integer?",
    "What if I send an empty array instead of an object?",
    "What if I omit the authentication header?",
    "What if I send two authentication headers?",
    "What if I send the request twice at the same time?",
    "What if I change the HTTP method?",
    "What if I add a query parameter that doesn't exist?",
    "What if I send a very long string?",
    "What if I send Unicode/special characters?",
    "What if I nest objects 10 levels deep?",
    "What if I reference another user's ID in my request?",
    "What if I complete only half of a multi-step flow?",
    "What if I replay an old request with a new session?",
    "What if I send the response back as a request?",
]
```

Apply this to every endpoint, every parameter, every state transition. The "What-If" experiment is the single most productive technique for discovering logic flaws and implementation bugs.

#### Occam's Razor for Bugs

The simplest path to impact is usually the right one:

```
Question: "Is this an SSRF that requires complex DNS rebinding?"

Simpler answer: "Is it just a blind SSRF that calls back to my server?"
Even simpler: "Does the endpoint just follow redirects to external URLs?"
Simplest: "Can I just change the URL parameter to http://169.254.169.254/?"
```

Complex exploit chains are for when simple attacks fail. Start with the simplest possible test for each bug class. Escalate complexity only when the simple test proves the vector is filtered.

**The 3-Question Gate for every potential finding:**

1. What is the simplest way to demonstrate this?
2. What is the simplest way to prove impact?
3. What is the simplest way to explain this to a triager?

If you can't answer all three, you don't understand the finding well enough to submit.

#### Adversarial Thinking

Ask: *"If I were the defender, where would I put my security controls?"*

Then look everywhere else:

```
Defenders focus on:
- Authentication (login pages)
- Input validation (form fields)
- Rate limiting (API endpoints)
- WAF rules (common attack patterns)
- Session management (cookies, tokens)

Defenders miss:
- Business logic flows (multi-step operations)
- Async processing (queues, workers)
- Third-party integrations (webhooks, OAuth)
- Deprecated endpoints (v1 vs v2)
- Error handling (stack traces, debug modes)
- Export/import functions (bulk data access)
- Admin interfaces (assumed internal-only)
- Mobile APIs (less scrutiny than web)
- GraphQL resolvers (REST mindset applied to GraphQL)
```

The best findings come from the gap between what the defender protected and what the application actually does.

---

## Phase-Based Hunting Workflow

The complete hunting lifecycle has 11 phases. Each phase has a clear goal, time estimate, and exit criteria.

### Phase 1: Recon & Preparation

**Document:** [recon-and-prep.md] (Part 1 of series)
**Goal:** Map the attack surface and identify high-value targets
**Time estimate:** 2-4 hours (large target), 30 min (small target)

**Activities:**

```
□ Subdomain enumeration (passive + active)
□ Live host discovery
□ Technology fingerprinting
□ Scope confirmation
□ Account creation (2+ accounts)
□ JS bundle analysis
□ API endpoint discovery
□ Directory brute-force
□ Wayback machine / URL history mining
```

**Exit criteria:** You have a list of live subdomains, know the tech stack, have created test accounts, and have identified 10-20 high-value API endpoints to test.

**Key insight from Part 1:** Recon is not data collection — it is attack surface discovery. Every piece of recon data must answer "what can I attack?" If it doesn't, it's noise.

### Phase 2: Data Flow Mapping

**Document:** [understanding-user-data-flow.md] (Part 2 of series)
**Goal:** Trace user data through the application to find trust-boundary violations
**Time estimate:** 2-6 hours per feature

**Activities:**

```
□ Catalog every endpoint that accepts user data
□ Identify storage patterns (DB, cache, queue, object storage)
□ Map authorization checkpoints
□ Identify multi-tenancy model
□ Test list endpoints for cross-user data
□ Test direct object access across users
□ Test export/import data boundaries
□ Test GraphQL resolver authorization
□ Test WebSocket channel isolation
Test data flow through async processing
```

**Exit criteria:** You have a data flow diagram for at least one critical feature, and you've identified 2-5 potential data isolation failures to investigate.

**Key insight from Part 2:** The core question is always: "Where does user A's data flow to a place where user B can reach it?" Every critical bug comes from a failure in data flow isolation.

### Phase 3: Vulnerability Research

**Document:** [0-day-deep-analysis.md] (Part 3 of series)
**Goal:** Find known and unknown vulnerabilities in the target's tech stack
**Time estimate:** 1-4 hours per technology

**Activities:**

```
□ Identify all third-party components and versions
□ Research CVEs for each component
□ Check patch history for incomplete fixes
□ Review disclosed reports for similar targets
□ Analyze dependencies for known vulns
□ Research 0-day patterns in the tech stack
□ Check for default credentials
□ Review changelogs for security-relevant changes
```

**Exit criteria:** You have a list of 3-5 vulnerability classes that are likely to exist based on the tech stack, version history, and disclosed reports.

**Key insight from Part 3:** In bug bounty, a "0-day" often means a novel application-level logic flaw that no other hunter has reported — not a binary-level exploit. The highest-value bugs are unique to the application's business logic.

### Phase 4: Anti-Duplicate Strategy

**Document:** [Enhanced-Triage-Anti-Duplicate.md] (Part 4 of series)
**Goal:** Ensure every finding is novel before investing time in exploitation
**Time estimate:** 30 min per potential finding

**Activities:**

```
□ Search disclosed reports for similar findings
□ Check program's known-issues page / changelog
□ Search HackerOne / Bugcrowd / Intigriti archives
□ Check GitHub issues / commit messages for fixes
□ Review program's past bounty payouts for patterns
□ Search Twitter / Discord / Telegram for discussions
□ Use program's duplicate DB (if accessible via API)
□ Check if the finding is a variant of a known issue
```

**Exit criteria:** You have high confidence (80%+) that the finding has not been previously reported.

**Key insight from Part 4:** On mature programs, duplicates account for 40-60% of N/As. The pre-hunt duplicate check is the highest-ROI activity you can do — it saves 6-10 hours per duplicate finding.

### Phase 5: Finding Validation

**Document:** [finding-checklist.md] (Part 5 of series)
**Goal:** Validate the finding through the 7-Question Gate and 4 validation gates
**Time estimate:** 10-15 minutes per finding

**Activities:**

```
□ Run the 7-Question Gate
□ Run the 4 Validation Gates (Reproducibility, Impact, Scope, Novelty)
□ Test on a clean session (fresh login)
□ Confirm scope inclusion
□ Assess real security impact (not theoretical)
□ Check for preconditions (auth, specific data, specific state)
□ Determine CVSS score
□ Decide: submit, chain, or discard
```

**Exit criteria:** The finding passes all validation gates, or you've identified why it fails and have moved on.

**Key insight from Part 5:** "If you can't prove it, don't report it." The validation checkpoint is between "I think I found something" and "Let me write the report." Skipping it costs hours.

### Phase 6: WAF Identification & Bypass

**Document:** [waf-identification-bypass.md] (Part 6 of series)
**Goal:** Identify WAF rules and bypass them to reach the actual application
**Time estimate:** 30 min - 2 hours per blocked vector

**Activities:**

```
□ Fingerprint WAF vendor (Cloudflare, Akamai, AWS WAF, ModSecurity)
□ Identify blocked vs allowed payload patterns
□ Collect blocked responses for analysis
□ Test encoding bypasses (URL, Unicode, double URL)
□ Test case manipulation
□ Test comment insertion
□ Test parameter pollution
□ Test HTTP method conversion
□ Test protocol downgrade (HTTP/2 → HTTP/1.1)
□ Test origin spoofing (X-Forwarded-For, X-Real-IP)
```

**Exit criteria:** You have 2-3 reliable bypass techniques for the identified WAF, or you've confirmed no WAF is present.

**Key insight from Part 6:** A WAF block is not a dead end — it's information. The WAF tells you what the defender considers dangerous, which tells you what parameters they didn't secure properly.

### Phase 7: Sanitization Testing

**Document:** [sanitization-validation.md] (Part 7 of series)
**Goal:** Test input sanitization (server-side validation, encoding, escaping)
**Time estimate:** 1-3 hours per target

**Activities:**

```
□ Identify all input filters and sanitizers
□ Test filter evasion (nested payloads, split payloads)
□ Test multi-byte character bypass
□ Test null byte injection
□ Test filter via alternate encoding
□ Test second-order injection (stored then retrieved)
□ Test client-side-only validation bypass
□ Test server-side validation depth (is it applied everywhere?)
□ Test validation consistency across endpoints
```

**Exit criteria:** You understand the sanitization model and have identified 2-3 bypass patterns.

**Key insight from Part 7:** Client-side validation is not security. Server-side validation applied inconsistently is not security. The only validation that matters is server-side validation applied at every entry point with the same rules.

### Phase 8: Advanced Bypass Techniques

**Document:** [advanced-bypass-techniques.md] (Part 8 of series)
**Goal:** Chain multiple bypass techniques for high-confidence exploitation
**Time estimate:** 2-4 hours per complex bypass

**Activities:**

```
□ Identify all layers of defense (WAF → app → framework → DB)
□ Test control characters in input
□ Test alternate content types (JSON, XML, form-data, multipart)
□ Test polyglot payloads (works across multiple contexts)
□ Test race condition on validation (TOCTOU)
□ Test cached validation bypass (validate once, reuse result)
□ Test unicode normalization differences (UTF-8 vs UTF-16)
□ Test newline / line-feed injection
□ Test zero-width character insertion
```

**Exit criteria:** You have a working end-to-end exploit that bypasses all layers of defense.

**Key insight from Part 8:** Each security layer has different assumptions about what constitutes valid input. The bypass comes from the gap between these assumptions — send something that passes Layer 1 but exploits Layer 2.

### Phase 9: Exploit Chain Construction

**Document:** [exploit-chain-construction.md] (Part 9 of series)
**Goal:** Chain multiple low/medium findings into a critical exploit
**Time estimate:** 2-8 hours per chain

**Activities:**

```
□ Identify available primitives (info leak, weak auth, XSS, etc.)
□ Map possible chain combinations
□ Test each link independently
□ Test links in sequence for stability
□ Validate the chain demonstrates real impact
□ Document each link with separate PoC
□ Test chain reliability across retries
```

**Exit criteria:** You have a working end-to-end chain that demonstrates critical impact from low-severity primitives.

**Key insight from Part 9:** A single medium finding is worth $500-2000. A chain of three mediums that leads to ATO is worth $5000-15000. The multiplier comes from the severity multiplication of the chain.

### Phase 10: Report Writing & Submission

**Document:** [report-writing.md] (Part 10 resources)
**Goal:** Write a clear, impact-focused report that survives triage
**Time estimate:** 30 min - 1 hour per finding

**Activities:**

```
□ Write impact statement first
□ Write clear reproduction steps
□ Include curl commands for each step
□ Include screenshots with redacted cookies
□ Include HAR file (sanitized)
□ Calculate CVSS score
□ Explain business impact
□ Note any chain potential
□ Submit through the platform
```

**Exit criteria:** A clean, well-documented submission has been sent.

**Key insight:** Write the impact statement first. If you can't articulate the impact in 2 sentences, you don't understand the finding well enough to submit.

### Phase 11: Post-Submission & Learning

**Goal:** Learn from every submission outcome and improve your process
**Time estimate:** 15 min per outcome

**Activities:**

```
□ Monitor submission status
□ If duplicate: analyze what you missed in prior-art search
□ If N/A: categorize the reason and update your personal checklist
□ If triaged: study what made it through
□ If paid: celebrate briefly, then analyze why it paid well
□ Update your personal methodology based on the outcome
□ Log findings and lessons in your personal tracker
```

**Exit criteria:** You have extracted maximum learning value from every submission outcome.

**Key insight:** Every N/A is a lesson. Categorize it, understand it, and update your methodology to prevent repeating it.

---

## Non-Linear Hunting

### When to Jump Between Phases

The 11-phase workflow is not a rigid waterfall. Real hunting is non-linear — you jump between phases based on what you discover.

**Signals that trigger a phase jump:**

| Current Phase | Signal | Jump To |
|---------------|--------|---------|
| Recon | Discovered legacy API endpoint | Phase 7 (Sanitization Testing) |
| Data Flow Mapping | Found potential cache leak | Phase 9 (Exploit Chain) |
| Vulnerability Research | Found CVE with known exploit | Phase 6 (WAF Bypass) |
| Anti-Duplicate | Found disclosed report with similar pattern | Phase 3 (Vulnerability Research) |
| Finding Validation | Finding fails impact gate | Phase 9 (Chain Construction) |
| WAF Bypass | Bypass works | Phase 8 (Sanitization Testing) |
| Exploit Chain | Link 1 works, need link 2 | Phase 2 (Data Flow Mapping) |

**The rule of thumb:** When you're blocked in one phase, switch to another. Momentum is more important than completeness. You can always come back.

### Recognizing When You're Stuck

**Signs you're stuck and need to switch:**

```
You've sent the same request 20 times with minor variations
You're reading documentation instead of sending requests
You're re-running the same tools expecting different results
You've been in Burp for 2 hours without a new finding
You're tired, hungry, or distracted
You're "enhancing" your methodology instead of hunting
You find yourself saying "I need to finish X before I can test Y"
```

**When stuck, try one of these switches:**

```
High energy, need direction → Switch targets
Low energy, need creativity → Switch to passive recon
Frustrated with complexity → Switch to a simpler bug class
Bored with the current target → Switch to a different target
Overwhelmed by data → Switch to manual testing on one endpoint
```

### The 25-Minute Block Methodology

Hunting productivity follows a predictable curve: 25 minutes of deep focus, then diminishing returns.

**The workflow:**

```
0-25 min: Deep focus on one task (one endpoint, one bug class, one feature)
25-30 min: Stand up, stretch, look away from screen
30-55 min: Second focus block (different endpoint or approach)
55-60 min: Log progress, note findings, plan next blocks
```

**Block types:**

| Block Type | Focus Area | Example |
|------------|------------|---------|
| Recon block | Asset discovery | Run subfinder + httpx on new domain |
| Data flow block | Trace one feature | Map document upload → storage → retrieval |
| Testing block | Test one endpoint | Fuzz all params on POST /api/document |
| Chain block | Build exploit chain | Test primitives in sequence |
| Validation block | Validate one finding | Run 7-Question Gate |
| Report block | Write one report | Write up finding with PoC |
| Learning block | Study disclosed reports | Read 3 H1 disclosed reports |

**Session structure (ideal 4-hour session):**

```
Hour 1: 2 testing blocks (one endpoint, deep fuzzing)
Hour 2: 1 data flow block + 1 validation block
Hour 3: 1 exploitation block + 1 chain block
Hour 4: 1 report block + 1 learning block (or recon for next session)
```

Adjust based on energy levels, findings, and session goals.

### Energy Management During Long Sessions

**The energy curve:**

```
Hour 1-2: Peak creativity and pattern recognition → Deep testing, complex exploitation
Hour 3-4: Good for mechanical work → Validation, reporting, recon
Hour 5-6: Diminishing returns → Documentation, learning, planning
Hour 7+: Likely making mistakes → STOP
```

**Rules:**

```
- Never submit a report written after hour 4 of a session — review it fresh
- Never skip the validation gate when tired — you'll miss something
- Never run automated tools unattended — they WILL cause problems
- Log your progress before you start to fatigue — you won't remember later
- The last finding of a long session is usually wrong — verify it tomorrow
```

---

## Target Selection

### Program Evaluation Matrix

Not all programs are worth equal time. Evaluate using this matrix:

| Factor | Weight | Score 1-5 | Weighted |
|--------|--------|-----------|----------|
| Bounty range | 20% | | |
| Scope quality | 20% | | |
| Tech stack intimacy | 15% | | |
| Competition level | 15% | | |
| Response time | 10% | | |
| Disclosed report volume | 10% | | |
| Personal interest | 10% | | |

**Bounty range scoring:**

| Score | Criteria |
|-------|----------|
| 5 | Critical bounties > $5,000, medium > $1,000 |
| 4 | Critical > $2,000, medium > $500 |
| 3 | Critical > $1,000, medium > $250 |
| 2 | Critical < $1,000, medium < $250 |
| 1 | VDP only (no monetary rewards) |

**Scope quality scoring:**

| Score | Criteria |
|-------|----------|
| 5 | Wildcard domains, API, mobile, web, cloud |
| 4 | Wildcard domains, API, web |
| 3 | Specific subdomains, web only |
| 2 | Limited endpoints, heavy restrictions |
| 1 | Rate-limited, no auth testing allowed, narrow scope |

### Disclosed Report Ratio Analysis

The ratio of disclosed reports to total reports tells you how much you can learn from prior art.

| Ratio | What It Means |
|-------|---------------|
| >50% disclosed | Excellent — can learn from every submission |
| 25-50% disclosed | Good — partial visibility into program history |
| 10-25% disclosed | Limited — program selectively discloses |
| <10% disclosed | Poor — operating blind on duplicate landscape |

**Action:** For programs with <25% disclosure, allocate 2x time to anti-duplicate research.

### Tech Stack Prioritization

**High-priority stacks (most bugs found per hour):**

```
Ruby on Rails       → High IDOR rate (scaffolding defaults)
Node.js/Express     → High prototype pollution rate
Python/Django       → High mass assignment rate (DRF defaults)
PHP/Laravel         → High SQLi + type juggling rate
Java/Spring         → High deserialization rate
Go/Gin              → Lower bug density but high severity
.NET/C#             → High ViewState + deserialization rate
```

**Low-priority stacks (less buggy per hour):**

```
Rust (Actix, Rocket) → Memory safety reduces class of bugs
Elixir/Phoenix       → Functional patterns reduce state bugs
Clojure              → Immutability reduces mutation bugs
```

**Action:** Prioritize targets using stacks you already know. A Ruby expert will find 5x more bugs/hour on a Rails app than a Go app.

### Competition Estimation

**Signal of high competition:**

```
- Program has >500 disclosed reports
- Program has been running >2 years
- Program is mentioned in top 10 "best bounty programs" list
- The target is a Fortune 500 company
- The target has a prominent bug bounty badge
- Average time-to-first-response < 24 hours (means many submissions)
```

**Signal of low competition:**

```
- Program is < 6 months old
- Program has < 50 disclosed reports
- Target is a B2B SaaS (less visibility than consumer)
- Target is not in English (gated by language)
- Target requires specialized knowledge (healthcare, fintech)
- Target has low bounty range (deters casual hunters)
- Target is on a less popular platform (Intigriti, OpenBugBounty)
```

**Rule of thumb:** If it feels like everyone is hunting the same target, they are. Switch to a less competitive target and find unique bugs.

### Time-to-Payout Analysis

**Calculate expected bounty per hour for each target:**

```
Expected = (avg_bounty * success_rate) / hours_per_finding

Where:
- avg_bounty = average bounty for found-by-me bug class on similar programs
- success_rate = your historical acceptance rate on this bug class
- hours_per_finding = your average time to find + validate + report this class
```

**Example calculation:**

```
Target: SaaS platform
Bug class: IDOR
- Avg IDOR bounty on similar programs: $1,500
- Your IDOR success rate: 80%
- Your time to find + report IDOR: 4 hours

Expected = ($1500 * 0.8) / 4 = $300/hour
```

If expected bounty per hour is below your minimum threshold (e.g., $50/hour), move on.

### Past Researcher Experience Reports

Before investing heavily in a target, check:

```
- Twitter: "target.com bounty" "target.com review"
- Reddit: /r/bugbounty "target.com"
- Discord: Program-specific channels
- HackerOne/Bugcrowd: Researcher reviews
- Personal network: Ask other hunters
```

**What to look for:**

```
Positive signals: "Great communication", "Fair triage", "Fast payments"
Negative signals: "N/A on everything", "Slow response", "Hostile triage"
Red flags: "Banned for testing", "Threatened legal", "Scope issues"
```

---

## Session Management

### Per-Target Workspace

Every target gets its own workspace:

```
targets/
  target.com/
    recon/
      subdomains.txt       # All discovered subdomains
      live-hosts.txt       # Live hosts from httpx
      tech-stack.txt       # Technology fingerprinting
      endpoints.txt        # Discovered API endpoints
      js-files.txt         # JavaScript file URLs
      wayback-urls.txt     # Historical URLs
    hunting/
      account-1.json       # Account 1 credentials + state
      account-2.json       # Account 2 credentials + state
      findings.md          # All findings (confirmed + unconfirmed)
      notes.md             # Session notes, observations
      payloads/            # Target-specific payloads
    waf/
      waf-fingerprint.txt  # WAF vendor + rules
      bypasses.txt         # Working bypass techniques
    data-flow/
      endpoints.txt        # Categorized endpoints
      diagrams/            # Data flow diagrams
    burp/
      target-project.json  # Burp project file
      config.json          # Target-specific Burp config
```

**Why this matters:** A target-specific workspace lets you resume sessions instantly, avoids redoing recon, and provides a complete history for post-submission analysis.

### Burp Project Management

**Per-target Burp project settings:**

```
Scope: Target-specific (avoid capturing out-of-scope traffic)
Session handling rules: Auto-reauth, CSRF token extraction
Match/replace rules: Auto-update auth headers
SSL pass through: Known application servers
Target scope color: Unique color per target
```

**Session notes in Burp:**

```
- Comments on interesting requests
- Highlighted test requests
- Repeater tabs organized by endpoint
- Intruder configurations saved per attack
- Extender outputs per target
```

### Session Logging

Log every session — what you did, what you found, what you learned:

```markdown
# Session Log: 2026-06-16
## Target: api.target.com
## Duration: 4 hours (1400-1800)

### Activities
- [x] Recon: Subdomain enumeration on *.target.com → 45 subdomains
- [x] Data Flow: Mapped document upload flow → potential IDOR at /api/documents/{id}
- [x] Testing: Fuzzed GET /api/documents/{id} with User B's token → 200 OK on ID 1-100
- [x] Validation: Ran 7-Question Gate on document IDOR → PASS
- [x] Report: Wrote and submitted document IDOR finding

### Findings
- F001: Document IDOR (critical) — Confirmed, submitted
- F002: Rate limiting gap on password reset (low) — Noted, may chain later

### Lessons
- The document IDOR was hiding in plain sight — I assumed it was protected because the UI only shows own documents
- Wayback machine revealed /api/v1/documents endpoint that's unfiltered — old API
- Need to check if v1 endpoints have the same auth as v2

### Next Session
- F002: Investigate rate limiting gap → check for race condition
- F003: Test document upload endpoint for file upload bugs
```

**Save session logs to:** `targets/target.com/hunting/notes.md`

### Progress Tracking

Track overall progress across sessions:

```
# Target: api.target.com
# Sessions: 6 (24 hours total)
# Findings Submitted: 4
# Findings Accepted: 3
# Findings Paid: 3 (avg $1,200)
# Pending: 1
# N/A: 1 (duplicate)

# Phase Completion
[==========] Recon (100%)
[========  ] Data Flow Mapping (80%)
[====      ] Vulnerability Research (40%)
[==========] Anti-Duplicate (100%)
[==========] Finding Validation (100%)
[===       ] WAF Bypass (30%)
[===       ] Sanitization Testing (30%)
[=         ] Advanced Bypass (10%)
[          ] Exploit Chain (0%)
[========= ] Report Writing (90%)
[==========] Post-Submission (100%)
```

### Time-Boxing Each Phase

| Phase | Max Time | When to Stop |
|-------|----------|--------------|
| Recon | 4 hours | Have 20+ endpoints to test |
| Data Flow Mapping | 6 hours | Identified 3+ potential violations |
| Vulnerability Research | 4 hours | Have 5+ bug classes to test |
| Anti-Duplicate | 30 min per finding | Confirmed novel or confirmed duplicate |
| Finding Validation | 15 min per finding | Pass or fail decision made |
| WAF Bypass | 2 hours | Have 2+ working bypasses |
| Sanitization Testing | 3 hours | Identified 2+ bypass patterns |
| Advanced Bypass | 4 hours | Have working end-to-end exploit |
| Exploit Chain | 8 hours | Links work in sequence end-to-end |
| Report Writing | 1 hour per finding | Report written and submitted |
| Post-Submission | 15 min per outcome | Lesson documented |

**Hard stop rule:** If you exceed 150% of the max time without a breakthrough, force a phase switch. You can come back later with fresh eyes.

### Break Discipline

**The Pomodoro for hunting:**

```
1 session (25 min) → 5 min break
2 sessions → 10 min break
4 sessions → 30 min+ break (meal, walk, exercise)
```

**What to do during breaks:**

```
- Stand up and walk away from the screen
- Do NOT check other targets during breaks (context contamination)
- Do NOT check email, social media, or messages (cognitive load)
- Drink water, stretch, look at something 20+ feet away (eye strain)
- Quick walk improves pattern recognition on return
```

**Signs you need a real break (not just a Pomodoro):**

```
- You're reading the same paragraph 3 times
- You're making typos in curl commands
- You forgot what you were testing
- You're getting frustrated at the application
- You're considering "just one more test" before stopping
```

---

## Tool Integration

### End-to-End Tool Workflow

The complete toolchain from recon to exploitation:

```
Phase 1: Recon
  subfinder       → Passive subdomain enumeration
  chaos           → Chaos API for subdomains
  httpx           → Live host discovery
  nuclei          → Technology fingerprinting + CVE scanning
  katana          → URL crawling
  waybackurls     → Historical URL extraction
  gau             → URL gathering (alternative to waybackurls)
  LinkFinder      → JS endpoint extraction
  SecretFinder    → JS secret extraction

Phase 2: Data Flow Mapping
  Burp Suite      → Manual endpoint exploration
  Autorize        → Auth bypass testing in Burp
  AuthMatrix      → Role-based access testing
  Flow           → Visual HTTP flow mapping

Phase 3: Vulnerability Research
  GitHub search   → Disclosed reports by target
  HackerOne API   → HackerOne disclosed reports
  exploit-db      → Known exploit patterns
  nuclei          → Template-based vulnerability scanning
  grep/app        → Tech-stack-specific searches

Phase 4: Finding Validation
  Burp compare    → Response comparison
  custom scripts  → 7-Question Gate automation
  CVSS calculator → Severity assessment

Phase 5: WAF Bypass
  WAFW00F         → WAF fingerprinting
  custom bypass scripts → Encoding, payload mutation
  Burp Intruder   → Payload fuzzing

Phase 6: Sanitization Testing
  Burp Repeater   → Manual payload testing
  custom fuzzers  → Filter bypass fuzzing
  SQLMap          → SQL injection testing (with WAF bypass)

Phase 7: Advanced Bypass
  Burp Intruder   → Complex payload chains
  custom scripts  → Multi-layer bypass construction

Phase 8: Exploit Chain
  Burp Repeater   → Chain step testing
  custom scripts  → Chain automation
  curl            → Chain reproduction for PoC

Phase 9: Reporting
  custom templates → Report generation
  screenshot tools → Evidence capture
  jq              → HAR sanitization
```

### API Integrations

**HackerOne API:**

```bash
# Fetch disclosed reports for a target
curl -s -u "$H1_USERNAME:$H1_API_KEY" \
  "https://api.hackerone.com/v1/hackers/programs/target/reports" \
  | jq '.data[] | select(.attributes.public == true)'
```

```python
import requests

class HackerOneAPI:
    def __init__(self, username, api_key):
        self.auth = (username, api_key)
        self.base = "https://api.hackerone.com/v1"
    
    def get_disclosed_reports(self, program):
        """Get all disclosed reports for a program."""
        reports = []
        page = 1
        while True:
            resp = requests.get(
                f"{self.base}/hackers/programs/{program}/reports",
                auth=self.auth,
                params={"page[number]": page, "page[size]": 25}
            )
            data = resp.json().get("data", [])
            if not data:
                break
            for r in data:
                if r["attributes"].get("public"):
                    reports.append({
                        "id": r["id"],
                        "title": r["attributes"]["title"],
                        "severity": r["attributes"]["severity"],
                        "created_at": r["attributes"]["created_at"]
                    })
            page += 1
        return reports
    
    def get_submission_history(self, program):
        """Get your own submission history for a program."""
        resp = requests.get(
            f"{self.base}/hackers/me/reports",
            auth=self.auth,
            params={"filter[program][]": program}
        )
        return resp.json().get("data", [])
```

**Bugcrowd API:**

```python
class BugcrowdAPI:
    def __init__(self, token):
        self.headers = {"Authorization": f"Bearer {token}"}
        self.base = "https://api.bugcrowd.com"
    
    def get_program_scope(self, program_code):
        """Get scope for a program by code."""
        resp = requests.get(
            f"{self.base}/programs/{program_code}",
            headers=self.headers
        )
        return resp.json()
    
    def get_submissions(self, program_code):
        """Get your submissions for a program."""
        resp = requests.get(
            f"{self.base}/submissions",
            headers=self.headers,
            params={"filter[program]": program_code}
        )
        return resp.json().get("data", [])
```

### Automation with jiggy-adapter.py

The jiggy-adapter integrates tools into a single workflow:

```python
#!/usr/bin/env python3
"""
jiggy-adapter.py — Unified tool coordinator for bug bounty workflow.
Integrates recon, scanning, and reporting tools.
"""

import subprocess
import json
import os
from pathlib import Path

class JiggyAdapter:
    def __init__(self, target, workspace):
        self.target = target
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)
    
    def run_recon(self):
        """Run initial recon pipeline."""
        print(f"[*] Starting recon on {self.target}")
        
        # Subdomain enumeration
        subprocess.run([
            "subfinder", "-d", self.target, "-o",
            str(self.workspace / "subdomains.txt")
        ])
        
        # Live host discovery
        subprocess.run([
            "httpx", "-l", str(self.workspace / "subdomains.txt"),
            "-o", str(self.workspace / "live-hosts.txt"),
            "-status-code", "-title", "-tech-detect"
        ])
        
        # Technology fingerprinting
        subprocess.run([
            "nuclei", "-l", str(self.workspace / "live-hosts.txt"),
            "-o", str(self.workspace / "nuclei-results.txt")
        ])
        
        print(f"[+] Recon complete. Results in {self.workspace}")
    
    def run_url_crawl(self):
        """Crawl URLs from wayback and live crawling."""
        with open(self.workspace / "all-urls.txt", "w") as f:
            # Wayback
            subprocess.run([
                "waybackurls", self.target
            ], stdout=f)
            
            # Live crawl
            subprocess.run([
                "katana", "-list", str(self.workspace / "live-hosts.txt"),
                "-o", str(self.workspace / "katana-urls.txt")
            ])
        
        # Extract API endpoints
        self._extract_endpoints()
    
    def _extract_endpoints(self):
        """Extract unique API endpoints from URL list."""
        endpoints = set()
        with open(self.workspace / "all-urls.txt") as f:
            for line in f:
                parts = line.strip().split("/")
                for i, part in enumerate(parts):
                    if part.endswith((".php", ".aspx", ".do", ".action", ".json")):
                        endpoints.add("/".join(parts[:i+2]))
                    elif part in ("api", "v1", "v2", "v3", "rest", "graphql"):
                        endpoints.add("/".join(parts[:i+2]))
        
        with open(self.workspace / "endpoints.txt", "w") as f:
            for ep in sorted(endpoints):
                f.write(f"{ep}\n")
    
    def run_burp_automation(self, project_path):
        """Launch Burp with target-specific project."""
        subprocess.run([
            "BurpSuiteCmd", project_path,
            "--scope-include", f"*.{self.target}",
            "--config-file", str(self.workspace / "burp-config.json")
        ])
    
    def build_workspace(self):
        """Create the full workspace structure."""
        dirs = [
            "recon", "hunting", "waf", "data-flow", "burp",
            "payloads", "reports", "evidence"
        ]
        for d in dirs:
            (self.workspace / d).mkdir(exist_ok=True)
        
        # Create base files
        (self.workspace / "hunting" / "findings.md").write_text("# Findings\n\n")
        (self.workspace / "hunting" / "notes.md").write_text("# Session Notes\n\n")
        (self.workspace / "reports" / "submissions.md").write_text("# Submissions\n\n")
        
        print(f"[+] Workspace created at {self.workspace}")

# Example usage
if __name__ == "__main__":
    jiggy = JiggyAdapter("target.com", "./targets/target.com")
    jiggy.build_workspace()
    jiggy.run_recon()
    jiggy.run_url_crawl()
```

---

## Research Efficiency

### Most Impactful Time Investments (Ranked)

| Rank | Activity | ROI | Why |
|------|----------|-----|-----|
| 1 | Data flow mapping | **Very High** | Finds IDORs, auth bypasses, mass assignment — the highest-paying bug classes |
| 2 | Prior art search | **Very High** | Prevents 40-60% of N/A submissions — saves 6-10 hours per duplicate |
| 3 | Disclosed report study | **High** | Learn exactly what pays on this program and what's already found |
| 4 | WAF bypass research | **Medium-High** | Unblocks access to the real application behind the WAF |
| 5 | JS bundle analysis | **Medium** | Finds hidden endpoints, secrets, API keys |
| 6 | Directory fuzzing | **Medium** | Discovers hidden endpoints, admin panels, backup files |
| 7 | Parameter fuzzing | **Medium** | Finds hidden parameters that modify behavior |
| 8 | Complex exploit dev | **Low-Medium** | High payout but very high time investment — only if chain potential |
| 9 | Rate limiting testing | **Low** | Almost never pays as standalone finding |
| 10 | Low-info disclosures | **Low** | Missing headers, verbose errors, directory listing — rarely paid |

### Minimizing Time on Low-Value Activities

**Rate limiting testing:**

```
Check: 10 requests in 1 second → blocked?
If yes, note it and move on (5 minutes max)
If no, try 100 requests → blocked?
If yes, note "rate limit at 100/sec" and move on
If no, not worth further investigation unless chaining
```

**Low-info disclosures:**

```
Missing X-Frame-Options: Check for clickjacking → 5 min
If clickjacking + sensitive action = chain primitive → note and move on
If standalone → skip entirely
```

**Brute force without wordlist optimization:**

```
Use a small, targeted wordlist (not the biggest one)
Common admin paths: admin, api, dev, test, staging, backup
Common backup files: .bak, .old, .orig, ~
Common config files: .env, .git/config, config.json, wp-config.php
```

**The 5-minute rule:**

If you spend 5 minutes on a low-value activity and haven't found anything interesting, stop. Move to higher-value activity. You can always come back.

### High-Value Automation

**Things worth automating:**

```
- URL collection (waybackurls, gau, katana)
- Endpoint extraction from JS files (LinkFinder, custom scripts)
- Response comparison (Burp Comparer, custom diff scripts)
- Payload mutation (custom fuzzers for WAF bypass)
- Report template generation (markdown from structured data)
```

**Things NOT worth automating:**

```
- Data flow mapping (requires human understanding of application logic)
- Finding validation (requires human judgment of impact)
- Exploit chain construction (requires creative combination of primitives)
- Business logic testing (requires understanding of the application domain)
- Anti-duplicate research (requires nuanced interpretation of disclosed reports)
```

---

## The Critical Thinking Framework

### Apply These Questions at Every Step

Every action during a hunt should be guided by five questions:

#### 1. "What would a developer do here?"

```
Apply when: Testing any feature for the first time
Purpose: Understand the developer's mental model to find the gaps

Questions to ask:
- What trust assumptions did the developer make?
- What edge cases did they not consider?
- What contexts (admin, mobile, batch) did they not test?
- What error handling did they implement (or not implement)?
- What shortcuts did they take (copy-paste code, library defaults)?
```

#### 2. "What's weird about this response?"

```
Apply when: Every time you receive a response
Purpose: Train anomaly detection to spot vulnerabilities

Questions to ask:
- Is the status code what I expected?
- Is the response body the right size?
- Are there any unexpected headers?
- Is the response time unusual?
- Is there data in the response I shouldn't see?
- Is there data missing from the response I should see?
```

#### 3. "What if I change this one thing?"

```
Apply when: You understand the baseline behavior
Purpose: Systematically explore the attack surface

Questions to ask:
- What if I change the HTTP method?
- What if I add/remove a header?
- What if I send a different content type?
- What if I change the parameter name?
- What if I send an array instead of a string?
- What if I send a negative number?
- What if I send a very large number?
- What if I skip a step in a multi-step flow?
- What if I repeat a step in a multi-step flow?
- What if I send the request from a different IP?
```

#### 4. "What's the simplest path to impact?"

```
Apply when: Evaluating a potential finding
Purpose: Focus on provable impact, not theoretical risk

Questions to ask:
- What can I actually read, modify, or delete?
- Can I demonstrate this from a clean session?
- What data exposure or privilege escalation does this enable?
- Is there a simpler way to demonstrate the same impact?
- Would a triager understand the impact from my description?
```

#### 5. "What would I do if I were the defender?"

```
Apply when: Planning your attack strategy
Purpose: Identify where security controls are and where they're not

Questions to ask:
- Where would I put authentication checks?
- Where would I add input validation?
- What parameters would I block?
- What would I log and monitor?
- What endpoints would I restrict to internal networks?
- What would I consider "too unlikely to bother protecting"?
```

### The 5-Question Loop in Practice

```
You find a POST /api/document endpoint:

Q1: "What would a developer do?"
A: They'd validate the document content, check auth, store it, return the ID.

Q2: "What's weird about the response?"
A: The response includes a `document_id` that's sequential. The response time is 200ms for small docs and 5s for large ones.

Q3: "What if I change..."
- The auth header? → 401 expected
- The document_id in a subsequent GET? → Let me try
- The content-type to XML? → Let me see if XXE works
- The step order? → Let me skip the document upload and call process directly

Q4: "Simplest path to impact?"
A: The sequential document_id suggests other users' documents are accessible. Let me create as User A, get ID 100, then as User B try GET /api/document/100.

Q5: "What would the defender do?"
A: They probably check auth on upload but may have forgotten to check ownership on retrieval. The response includes owner_id but it's not validated.
```

---

## Post-Bug Workflow

### The 8-Step Post-Discovery Protocol

After you confirm a finding, follow this exact sequence:

```
Step 1: REPRODUCE ON FRESH SESSION
  Log out completely
  Clear cookies, local storage, session storage
  Log in as the affected user
  Reproduce the finding from scratch
  ✅ Finding confirmed from clean state

Step 2: VALIDATE SCOPE
  Check the finding against program scope
  Check OOS rules (rate limiting, third-party, etc.)
  Check for any scope restrictions on your method
  ✅ Finding is clearly in-scope

Step 3: SEARCH PRIOR ART
  Search disclosed reports (H1, Bugcrowd, Intigriti)
  Search program changelog / known issues
  Search GitHub issues for similar patterns
  Search Twitter, Discord, Telegram for mentions
  ✅ Finding appears to be novel

Step 4: CAPTURE EVIDENCE
  Screenshot the PoC (with redacted cookies)
  Save curl commands for each step
  Save request/response pairs
  Note the application state (accounts, data, timestamps)
  Prepare HAR file (sanitized)
  ✅ Evidence is complete and reproducible

Step 5: WRITE REPORT
  Impact statement first (2 sentences max)
  Steps to reproduce (numbered, clear)
  Technical details (endpoints, parameters, payloads)
  Impact assessment (what can attacker do with this?)
  CVSS score with vector string
  Remediation suggestion
  ✅ Report is clear and complete

Step 6: SUBMIT
  Final review of the report
  Upload evidence (screenshots, HAR, curl commands)
  Submit through the platform
  Take a screenshot of the submission confirmation
  ✅ Finding is submitted

Step 7: MONITOR
  Note submission ID and timestamp
  Expected response time (check program SLA)
  Check for status changes daily
  Respond promptly to triage questions
  If duplicate: learn and move on
  If N/A: understand why and update methodology
  ✅ Finding is being triaged

Step 8: LEARN
  If accepted: analyze why it paid (bug class, impact, presentation)
  If rejected: categorize the rejection reason
  Update your personal methodology
  Update your anti-duplicate database
  Log the lesson in your personal tracker
  ✅ You've extracted maximum value from this finding
```

### The Post-Submission Decision Tree

```
                     ┌─────────────────┐
                     │  Finding Submitted │
                     └────────┬────────┘
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
              ┌──────────┐      ┌──────────────┐
              │  Triaged  │      │   N/A/Closed  │
              └────┬─────┘      └──────┬───────┘
                   │                   │
          ┌────────┴────────┐  ┌───────┴────────┐
          ▼                 ▼  ▼                 ▼
    ┌──────────┐    ┌────────────┐  ┌──────────┐  ┌──────────┐
    │  Bounty   │    │  Informational │  Duplicate │  OOS/Bug  │
    └────┬─────┘    └──────┬─────┘  └─────┬────┘  └────┬─────┘
         │                │              │            │
         ▼                ▼              ▼            ▼
  ✓ Celebrate       ✓ Note for        ✓ Update      ✓ Update
  ✓ Note what       future chains     anti-dupe     methodology
  made it work                         database     
  ✓ Log in your                                       ✓ Move on
  personal tracker
```

---

## Continuous Learning

### Every N/A Is a Lesson

**N/A Reason Categorization:**

```
N/A Category 1: Duplicate
  → Lesson: Your prior-art search needs improvement
  → Fix: Spend more time on disclosed report research
  → Fix: Use program-specific duplicate search techniques from Part 4

N/A Category 2: Out of Scope
  → Lesson: You didn't read the scope carefully enough
  → Fix: Re-read scope before every session
  → Fix: Create a scope checklist and run it before starting

N/A Category 3: Not a Security Bug
  → Lesson: You confused a feature behavior with a vulnerability
  → Fix: Study the difference between intended behavior and security flaws
  → Fix: Run the 7-Question Gate before submitting

N/A Category 4: Cannot Reproduce
  → Lesson: Your PoC was incomplete or the state wasn't preserved
  → Fix: Always reproduce from a clean session
  → Fix: Document every precondition (accounts, data, state)

N/A Category 5: Already Fixed
  → Lesson: You tested an old version or the fix was already deployed
  → Fix: Verify current version before testing
  → Fix: Use fresh test accounts
```

### Personal Weak Area Tracking

```
# Personal Weak Area Tracker
# Every time you get N/A, log it here.

Date     | Bug Class  | N/A Reason           | Lesson Learned
---------|------------|----------------------|----------------
2026-06-01| XSS        | No impact (self-XSS) | Don't submit self-XSS unless chained
2026-06-05| IDOR       | Duplicate            | Need to check disclosed reports more thoroughly
2026-06-10| Race Cond  | Cannot reproduce     | Need to use better tooling for race conditions
2026-06-15| Business   | Not a security bug   | Study business logic vs security flaw more
```

### Study Disclosed Reports from Top Hunters

**What to learn from each disclosed report:**

```
- How did the hunter FIND this bug? (methodology)
- What was the attack vector? (endpoint, parameter, technique)
- What was the root cause? (developer mistake, missing check, misconfig)
- How did they EXPLOIT it? (chaining, escalation, impact demonstration)
- How did they WRITE it up? (impact statement, PoC, evidence)
- What was the PAYOUT? (severity, bounty, program response)
```

**The N/1 reading protocol:**

```
1 report → Note 3 things you learned
5 reports → You see a pattern in the bug class
20 reports → You understand the program's vulnerability profile
50 reports → You can predict where bugs will be found
```

### Practice Specific Vulnerability Classes

**Weekly practice routine:**

```
Monday:    IDOR practice (2 hours on a dedicated target)
Tuesday:   XSS practice (2 hours on XSS-focused lab)
Wednesday: Business logic practice (2 hours on complex workflow)
Thursday:  Auth bypass practice (2 hours on auth-focused target)
Friday:    Free practice (whatever you found interesting this week)
Weekend:   Report writing + disclosed report study
```

**Building muscle memory for bypasses:**

```
Each bypass technique needs 10+ repetitions to become automatic:
- 10 IDOR bypasses (UUID → int, param name fuzzing, batch operations)
- 10 XSS bypasses (WAF evasions, context-specific payloads)
- 10 SSRF bypasses (DNS rebinding, redirect chains, protocol handlers)
- 10 SQLi bypasses (encoding, comment insertion, case mutation)
- 10 Auth bypass techniques (JWT none alg, forced browsing, cache-based)
```

---

## Burnout Prevention

### Session Limits

| Level | Max Daily Hours | Max Weekly Hours | Max Consecutive Days |
|-------|-----------------|------------------|---------------------|
| Casual | 4 hours | 20 hours | 5 days |
| Part-time | 6 hours | 30 hours | 5 days |
| Full-time | 8 hours | 40 hours | 6 days |
| Intense | 10 hours | 50 hours | 6 days |

**Hard rules:**

```
- Take at least 1 full day off per week
- No more than 10 hours in a single day
- No more than 6 consecutive days
- If you feel burnout symptoms, take 3 days minimum off
```

### Target Rotation

**Why rotation matters:**

Hunting the same target for weeks creates cognitive blind spots. You stop noticing anomalies because everything looks normal. You develop "learned helplessness" where you assume everything is secured.

**Rotation schedule:**

```
Primary target:   70% of time (deep focus)
Secondary target: 20% of time (variety keeps you sharp)
Tertiary target:  10% of time (recon only, prepare for later)
```

**Rotation triggers:**

```
- No findings in 3 consecutive sessions → rotate primary to secondary
- Feeling frustrated with the target → rotate immediately
- Completely blocked on all endpoints → rotate to a different bug class
- Confirmed a significant bug → rotate as celebration while you wait for triage
```

### Life Balance

**The 40/40/20 rule for full-time hunters:**

```
40 hours: Hunting (work)
40 hours: Sleep + personal care
20 hours: Family, friends, hobbies, exercise
  (The remaining hours are transitions, errands, and slack)
```

**Non-negotiable activities:**

```
- 7+ hours of sleep per night (cognitive performance drops 30% at 6 hours)
- 30+ minutes of exercise per day (stress management)
- 1+ hour of non-screen time before bed (sleep quality)
- Regular meals (blood sugar swings affect decision-making)
```

### Celebrating Wins

**Why celebration matters:**

Bug bounty is a negative-reinforcement activity — most of your requests get blocked, most of your findings get N/A'd, and most of your time feels unproductive. Deliberate celebration counteracts this negativity bias.

**Celebration protocol:**

```
Every confirmed finding:
- 5 minutes: Log what you did right (the technique, the observation, the breakthrough)
- Tell someone who will be happy for you (spouse, friend, Discord channel)
- Take a screenshot of the submission for your personal "wall of wins"

Every paid bounty:
- 30 minutes: No work, just enjoy the feeling
- Transfer a portion to savings (financial security)
- Spend a portion on something you enjoy (guilt-free)
- Log the lesson in your "what made this pay" file

Every milestone (10, 50, 100 submissions, $X total earnings):
- Take a day off to celebrate
- Reflect on your growth as a hunter
- Share your lessons with the community
```

### Learning from Losses

**Every N/A is a data point, not a failure:**

```
- N/A for duplicate → you identified a gap in your prior-art search
- N/A for OOS → you learned a scope boundary lesson
- N/A for no impact → you learned a lesson about impact assessment
- N/A for cannot reproduce → you learned a lesson about evidence quality
```

**The 5-minute post-N/A reflection:**

```
1. What was the N/A reason? (exact words from triager)
2. Why did I think this was a bug? (what did I miss?)
3. What would have prevented this N/A? (methodology change)
4. What did I learn from this? (one-sentence lesson)
5. Do I need to update my tools, checklists, or process? (action item)
```

### Community Engagement

**Why community matters:**

```
- Shared knowledge: Other hunters have solved problems you're facing
- Motivation: Seeing other people's wins keeps you engaged
- Feedback: Community review of findings catches blind spots
- Collaboration: Chain opportunities with other hunters
- Support: Burnout is lower when you're part of a community
```

**Community activities (low time investment):**

```
- Read 2 disclosed reports per week and note what you learned
- Share 1 technique per month on Twitter or a blog
- Answer 1 question per week in a bug bounty Discord
- Attend 1 bug bounty meetup or conference per quarter
```

### When to Take a Break

**Signs you need a break (not just a day off):**

```
- You dread opening Burp Suite
- You haven't submitted a finding in 2+ weeks despite regular sessions
- You're getting angry at applications for being "secure"
- You're skipping meals, sleep, or exercise for hunting
- Your non-hunting relationships are suffering
- You find yourself rationalizing unhealthy habits
- The thought of starting a new target exhausts you
- You're no longer learning from sessions
```

**Break protocol:**

```
1. Complete any in-progress submissions (don't abandon half-written reports)
2. Archive your current workspace with notes for resuming
3. Delete hunting tools from your quick-launch bar (reduce temptation)
4. Take a minimum of 1 week completely off (no targets, no tools, no research)
5. During the break: exercise, socialize, sleep, and do non-security hobbies
6. After the break: start with a new target (not the one you were stuck on)
7. Ease back in: 2-hour sessions for the first week
```

---

## The Complete Master Checklist

This is the end-to-end checklist for a complete bug bounty engagement, from target selection through post-submission learning. It integrates all 10 documents in this series.

### Phase 0: Target Selection (30 min - 2 hours)

```
Documents: Part 10 (this document, §4)

□ Research the program scope and rules
□ Evaluate bounty ranges against your time investment
□ Check disclosed report volume and quality
□ Assess tech stack familiarity
□ Estimate competition level
□ Read researcher experience reports
□ Calculate expected bounty per hour
□ Evaluate scope quality (wildcards, specific subdomains, narrow)
□ Decide: invest or move on
□ If investing: register accounts on the program platform

Time box: 30 min for known programs, 2 hours for new programs
Success metric: You have 2-3 targets selected for the week
When stuck: Pick the target with the most favorable scope/competition ratio
```

### Phase 1: Recon & Preparation (2-4 hours)

```
Documents: Part 1 — recon-and-prep.md
           Part 10 (this document, §2 Phase 1)

Pre-Recon:
□ Read program rules again (scope boundaries, testing policies, safe harbor)
□ Create 2+ test accounts on the target
□ Set up per-target workspace (directories, files, configs)
□ Configure Burp project per target

Passive Recon:
□ Run subfinder for passive subdomain enumeration
□ Check Certificate Transparency logs (crt.sh)
□ Query Chaos API for known subdomains
□ Collect historical URLs (waybackurls, gau)
□ Download and analyze JS bundles
□ Search for API keys / secrets in JS

Active Recon:
□ Filter subdomains to live hosts (httpx)
□ Fingerprint technology stack (nuclei, wappalyzer)
□ Run directory brute-force on discovered hosts
□ Crawl live hosts for endpoint discovery
□ Test discovered endpoints for accessibility

Output Checklist:
□ Subdomains list (50-200)
□ Live hosts list (10-50)
□ Technology stack fingerprint
□ API endpoint list (20-100)
□ JS files with endpoint extraction
□ 2+ test accounts with known credentials

Time box: 4 hours max
Success metric: You have 20+ API endpoints to test
When stuck: Narrow scope to one subdomain or one API version
```

### Phase 2: Data Flow Mapping (2-6 hours per feature)

```
Documents: Part 2 — understanding-user-data-flow.md
           Part 10 (this document, §2 Phase 2)

Entry Points:
□ Catalog all endpoints that accept user data
□ Group endpoints by function (profile, documents, payments, admin)
□ Identify all data input channels (REST, GraphQL, WebSocket, file upload)
□ Map every field that carries a user identifier

Storage Tracing:
□ Identify database tables with user data
□ Check for tenant column (user_id, owner_id, account_id)
□ Check cache key patterns for user scoping
□ Check queue messages for user context
□ Check object storage keys for user scoping

Retrieval Testing:
□ Test direct object access across users (IDOR)
□ Test list endpoints with parameter injections
□ Test search endpoints for cross-user results
□ Test export endpoints for scope bypass
□ Test admin endpoints for horizontal access
□ Test GraphQL resolvers for unfiltered access

Authorization Analysis:
□ Map authorization checkpoints in the data flow
□ Test each checkpoint individually
□ Identify gaps between checkpoints

Output Checklist:
□ Data flow diagram for 1-2 critical features
□ 2-5 potential data isolation failures
□ Test accounts with cross-user resources
□ Notebook of interesting parameters

Time box: 6 hours per critical feature
Success metric: You've found at least one potential trust-boundary violation
When stuck: Focus on one data type (documents, payments, profiles) and trace it end-to-end
```

### Phase 3: Vulnerability Research (1-4 hours)

```
Documents: Part 3 — 0-day-deep-analysis.md
           Part 10 (this document, §2 Phase 3)

Tech Stack Analysis:
□ Identify all third-party components and versions
□ Search CVEs for each component
□ Check patch history for incomplete fixes
□ Review changelogs for security-relevant changes

Disclosed Report Study:
□ Search HackerOne disclosed reports for similar targets
□ Search Bugcrowd disclosed reports (if available)
□ Study 5+ disclosed reports on this target or similar targets
□ Note patterns in what was found and what paid

Application-Specific Research:
□ Understand application domain (SaaS, e-commerce, healthcare, fintech)
□ Research domain-specific vulnerabilities
□ Check for domain-specific compliance requirements

Output Checklist:
□ 3-5 vulnerability classes likely to exist
□ List of known CVEs affecting the tech stack
□ Notes from 5+ disclosed reports
□ Priority list: highest-likelihood bug classes first

Time box: 4 hours max
Success metric: You have a prioritized list of bug classes to test
When stuck: Focus on the most common bug class for the tech stack
```

### Phase 4: Anti-Duplicate Strategy (30 min per finding)

```
Documents: Part 4 — Enhanced-Triage-Anti-Duplicate.md
           Part 10 (this document, §2 Phase 4)

Before Testing:
□ Check program changelog / known issues page
□ Search HackerOne for similar findings on this target
□ Review program's past payout patterns
□ Check GitHub issues / commit messages
□ Search Twitter / Discord / Telegram for mentions

During Testing:
□ Document every finding with unique characteristics
□ Note the exact endpoint, parameter, and technique
□ Record the root cause (not just the symptom)

Before Submission:
□ Run pre-submission deep search protocol
□ Search for identical endpoint + parameter combinations
□ Search for identical root cause descriptions
□ Search for identical impact statements
□ Check if finding is a known variant

Output Checklist:
□ 80%+ confidence that finding is novel
□ Documentation of why you believe it's not a duplicate
□ Alternative exploitation paths that differentiate your finding

Time box: 30 min per potential finding
Success metric: Your N/A rate due to duplicates is <20%
When stuck: If you can't find similar reports, it's likely novel — proceed
```

### Phase 5: Finding Validation (10-15 min per finding)

```
Documents: Part 5 — finding-checklist.md
           Part 10 (this document, §2 Phase 5)

The 7-Question Gate:
□ Q1: Can I reproduce this from a clean session?
□ Q2: Is this clearly in scope?
□ Q3: Does this have real security impact?
□ Q4: Can I demonstrate the impact to a non-technical person?
□ Q5: Is this different from already-reported issues?
□ Q6: Can I provide clear, step-by-step reproduction steps?
□ Q7: Am I confident enough to defend this to a triager?

The 4 Validation Gates:
□ Gate 1: Reproducibility (3 consecutive successful reproductions)
□ Gate 2: Impact assessment (data exposure, privilege escalation, code execution)
□ Gate 3: Scope & rules (confirmed in-scope, no rule violations)
□ Gate 4: Novelty & prior art (no matching disclosed reports)

Class-Specific Checks:
□ Run the class-specific checklist for your finding type
□ Check for false positive patterns in your bug class

Output Checklist:
□ Finding passes all 7 questions
□ Finding passes all 4 validation gates
□ Finding passes class-specific checks
□ Decision: SUBMIT, CHAIN, or DISCARD

Time box: 15 min per finding
Success metric: Every submitted finding passes first-line triage
When stuck: The finding is likely too weak — consider discarding or chaining
```

### Phase 6: WAF Identification & Bypass (30 min - 2 hours)

```
Documents: Part 6 — waf-identification-bypass.md
           Part 10 (this document, §2 Phase 6)

WAF Fingerprinting:
□ Identify WAF vendor (Cloudflare, Akamai, AWS WAF, ModSecurity, F5)
□ Check response headers for WAF signatures
□ Check blocked response characteristics
□ Test with common attack payloads to trigger blocks

WAF Rule Mapping:
□ Identify blocked vs allowed payload patterns
□ Characterize what triggers the WAF
□ Test each bypass technique:
  □ URL encoding variations
  □ Case manipulation
  □ Comment insertion
  □ Parameter pollution
  □ HTTP method conversion
  □ Protocol downgrade
  □ Origin spoofing
  □ Unicode normalization

Bypass Confirmation:
□ 2+ reliable bypass techniques
□ Working exploit payload through WAF
□ Documented bypass technique

Output Checklist:
□ WAF vendor identified
□ 2+ working bypass techniques
□ Documented blocked vs allowed patterns

Time box: 2 hours per blocked vector
Success metric: You can reliably deliver attack payloads to the application
When stuck: Try encoding-based bypasses first (most common WAF weakness)
```

### Phase 7: Sanitization Testing (1-3 hours)

```
Documents: Part 7 — sanitization-validation.md
           Part 10 (this document, §2 Phase 7)

Input Filter Mapping:
□ Identify all input filter types (blocklist, allowlist, encoding, escaping)
□ Test filter presence on all input channels
□ Test filter consistency across endpoints

Filter Bypass Testing:
□ Test encoding bypasses (URL, Unicode, double, mixed)
□ Test case manipulation
□ Test null byte injection
□ Test nest payloads
□ Test split payloads
□ Test second-order injection (stored → retrieved)
□ Test multi-byte character bypass

Validation Consistency:
□ Test same input through different endpoints
□ Test same input through different content types
□ Test same input through different HTTP methods
□ Test validated field vs unvalidated field behavior

Output Checklist:
□ Understanding of the sanitization model
□ 2-3 working bypass patterns
□ Documented filter boundaries

Time box: 3 hours per target
Success metric: You can bypass input sanitization for your target bug class
When stuck: Focus on content-type switching (XML vs JSON vs form data) — often has different filters
```

### Phase 8: Advanced Bypass Techniques (2-4 hours)

```
Documents: Part 8 — advanced-bypass-techniques.md
           Part 10 (this document, §2 Phase 8)

Multi-Layer Bypass Construction:
□ Identify all layers of defense (WAF → app server → framework → DB)
□ Map each layer's input parsing assumptions
□ Construct payload that passes each layer's checks

Advanced Techniques:
□ Control character injection
□ Alternate content type attack
□ Polyglot payload construction
□ TOCTOU on validation
□ Cached validation bypass
□ Unicode normalization confusion
□ Zero-width character insertion

End-to-End Testing:
□ Test payload through all layers
□ Verify payload reaches the vulnerable code
□ Verify payload triggers the vulnerability
□ Document the full bypass chain

Output Checklist:
□ Working end-to-end exploit through all defense layers
□ Documented bypass chain (layer 1 bypass + layer 2 bypass + ...)
□ Reproducible from clean state

Time box: 4 hours per complex bypass
Success metric: Full exploit chain works through all defense layers
When stuck: Isolate which layer is blocking you and focus on bypassing that layer only
```

### Phase 9: Exploit Chain Construction (2-8 hours)

```
Documents: Part 9 — exploit-chain-construction.md
           Part 10 (this document, §2 Phase 9)

Primitive Identification:
□ List all confirmed primitives
□ List all partial/incomplete findings (potential chain components)
□ Assess what each primitive gives you (data read, auth bypass, code exec)

Chain Mapping:
□ Identify possible A→B→C chains
□ Map chain primitives to required conditions
□ Identify the "linchpin" primitive (the hardest link to find)

Implementation:
□ Test each link independently (3+ successful reproductions)
□ Test links in sequence
□ Test chain stability across retries
□ Verify chain demonstrates significant impact
□ Document each link with separate PoC

Output Checklist:
□ Working end-to-end chain
□ Each link independently reproducible
□ Chain demonstrates critical impact
□ Separate PoC for each link

Time box: 8 hours per chain (max)
Success metric: Chain demonstrates critical impact from low-severity primitives
When stuck: Focus on making link 1 work reliably first, then chain the next
```

### Phase 10: Report Writing & Submission (30 min - 1 hour per finding)

```
Documents: Part 10 — report-writing template
           Part 10 (this document, §2 Phase 10)

Report Structure:
□ Impact statement (2 sentences, non-technical audience)
□ Technical summary (1 paragraph)
□ Steps to reproduce (numbered, exact)
□ Endpoints and parameters used
□ Payloads and request examples (curl commands)
□ Impact assessment (data exposure, privilege escalation, code execution)
□ CVSS score with vector string
□ Remediation suggestion

Evidence Preparation:
□ Screenshots with redacted cookies/PII
□ HAR file (sanitized of auth tokens)
□ curl commands for each step
□ Video PoC if applicable (for complex chains)

Pre-Submit Checklist:
□ Reproduce from clean session (one more time)
□ Verify scope inclusion (one more time)
□ Verify no rule violations (rate limits, testing policy)
□ Check evidence for exposed credentials or PII
□ Check report clarity (would a non-technical person understand?)
□ Check report completeness (nothing missing)

Output Checklist:
□ Report written and reviewed
□ Evidence prepared and sanitized
□ Pre-submit checklist completed
□ Finding submitted
□ Submission confirmation noted

Time box: 1 hour per finding
Success metric: Submission is clear, complete, and survives triage
When stuck: If writer's block hits, write the impact statement first — everything else flows from it
```

### Phase 11: Post-Submission & Learning (15 min per outcome)

```
Documents: Part 4 — Enhanced-Triage-Anti-Duplicate (post-submission monitoring)
           Part 10 (this document, §2 Phase 11, §10 Continuous Learning)

Monitoring:
□ Note submission ID and timestamp
□ Set expectation for response time (check program SLA)
□ Check status daily (no more than once per day)
□ Respond promptly to triage questions

Outcome Analysis:
If ACCEPTED:
□ Note what made it successful (bug class, impact, presentation)
□ Study the triage notes for future improvement
□ Update your "what pays" reference

If DUPLICATE:
□ Identify what you missed in prior-art search
□ Update your anti-duplicate database
□ Consider: were there signals you should have noticed?

If N/A (not a bug):
□ Categorize the N/A reason
□ Update your methodology to prevent recurrence
□ Update your personal checklist

If N/A (cannot reproduce):
□ Strengthen your evidence-capture process
□ Always reproduce from clean session before submission

Continuous Learning:
□ Log the lesson in your personal tracker
□ Study 1-2 disclosed reports from your session
□ Update your bug-class-specific checklist based on the outcome
□ Share the lesson with the community (optional)

Output Checklist:
□ Outcome logged in personal tracker
□ Lesson extracted and documented
□ Methodology updated based on lesson
□ Checklist updated based on outcome

Time box: 15 min per outcome
Success metric: You never make the same mistake twice
When stuck: Focus on one actionable lesson — "what will I do differently next time?"
```

### Phase 12: Session Review & Meta-Learning (15 min per session)

```
Documents: Part 10 (this document, §11 Burnout Prevention)

Session Review:
□ Log total time spent
□ Log findings found, submitted, accepted, rejected
□ Note what worked well (techniques, tools, approaches)
□ Note what didn't work (time wastes, dead ends)
□ Rate your energy level during the session (1-5)

Progress Check:
□ Update progress tracker for the current target
□ Check if target rotation is needed
□ Check if phase switch is needed
□ Check if break is needed

Meta-Learning:
□ What new technique did you try this session?
□ What did you learn about the target?
□ What did you learn about your own methodology?
□ What would you do differently next session?

Burnout Check:
□ Are you enjoying the hunt? (1-5)
□ Are you sleeping and eating properly?
□ Are you taking breaks?
□ Are you maintaining relationships outside of bug bounty?
□ Do you need a break?

Output Checklist:
□ Session logged
□ Progress tracker updated
□ Lessons documented
□ Burnout check passed
□ Next session planned

Time box: 15 min per session
Success metric: You maintain consistent productivity without burnout
When stuck: If any burnout check question scores low, take a break immediately
```

---

## The Methodology Series — Complete Reference

| Part | Document | Focus |
|------|----------|-------|
| 1 | recon-and-prep.md | Reconnaissance and preparation |
| 2 | understanding-user-data-flow.md | Data flow mapping and trust boundary analysis |
| 3 | 0-day-deep-analysis.md | Vulnerability research and 0-day discovery |
| 4 | Enhanced-Triage-Anti-Duplicate.md | Anti-duplicate strategy and triage readiness |
| 5 | finding-checklist.md | Pre-submission validation and the 7-Question Gate |
| 6 | waf-identification-bypass.md | WAF fingerprinting and bypass techniques |
| 7 | sanitization-validation.md | Input sanitization testing and filter evasion |
| 8 | advanced-bypass-techniques.md | Multi-layer bypass construction |
| 9 | exploit-chain-construction.md | Vulnerability chaining methodology |
| 10 | bug-bounty-research-methodology.md | Capstone — unified workflow and methodology |

---

*End of Part 10. This document concludes the 10-part bug bounty methodology series. The methodology is a living document — update it based on your personal experience, disclosed report study, and evolving techniques. The hunter who stops learning has already reached their ceiling.*
