# Goals of Hercules-Hunt

## North Star Metric

> **Every session produces one of two outcomes: a verified finding or a documented dead end.**

No wasted sessions. Every hour of hunting either advances a finding toward submission or narrows the attack surface by ruling something out.

---

## Tier 1: Core Goals (Non-Negotiable)

### G1. Impact-First Validation
Every finding must pass the 7-Question Gate before any report writing begins. Theoretical bugs are killed instantly. Only findings with demonstrated real-world harm reach submission.

**Signal:** N/A ratio < 10% across all submissions.

**Why this matters:** Your N/A ratio is the single strongest signal of your quality as a researcher on any platform. An N/A ratio above 20% signals to triagers that you're wasting their time. Above 30% and you risk platform restrictions.

**Sub-goals:**
- G1a: Every agent has the 7-Question Gate accessible within the first 50 lines of its definition
- G1b: Pre-submit checklist executed for every report file without exception
- G1c: After every N/A, document the root cause in memory to prevent recurrence

**Milestones:**
- M1 (30 days): N/A ratio below 20%
- M2 (60 days): N/A ratio below 15%
- M3 (90 days): N/A ratio below 10%

**Measurement methodology:**
- Track per-platform N/A ratio in a spreadsheet
- After each N/A, categorize the root cause: scope miss / validation failure / duplicate / informational
- Review the root cause distribution monthly

### G2. Chain Before Report
Single low-severity bugs are not submitted alone. Every finding is evaluated for chain potential — can this A pair with a B to create critical impact? Chains are submitted as one report, not separate lows.

**Signal:** At least 30% of submissions involve 2+ chained primitives.

**Why this matters:** Chain submissions signal to triagers that you understand the application's security holistically, not just in isolated endpoints. Chains are harder to dismiss, more likely to get higher severity, and more valuable to the program.

**Sub-goals:**
- G2a: Every agent includes chain-candidate detection in its PostToolUse hooks
- G2b: Chain-builder agent is invoked automatically when any finding passes the 7-Question Gate
- G2c: Chain documentation includes: A's endpoint, B's endpoint, condition C, and demonstrable impact of the combined exploit

**Milestones:**
- M1 (30 days): Identify chain potential on 2 findings
- M2 (60 days): Submit 1 chain
- M3 (90 days): 30%+ of submissions are chains

**Chain evaluation framework:**
For every finding, ask:
1. Does this primitive give me access to data I shouldn't have? → Chain with privilege escalation
2. Does this primitive let me send arbitrary requests? → Chain with SSRF, XSS, or CSRF
3. Does this primitive let me bypass a security control? → Chain with the control it bypasses
4. Does this primitive require user interaction? → Chain with social engineering or XSS
5. Does this primitive only work under specific conditions? → Chain with condition trigger

### G3. Scope Discipline
Every asset tested is verified against program scope before a single request is sent. OOS violations are not just bad practice — they destroy platform standing and waste triager trust.

**Signal:** Zero OOS submissions.

**Why this matters:** One OOS violation can get your account suspended on some platforms. Even a warning damages your reputation with triagers who remember your handle. Scope discipline is non-negotiable, not aspirational.

**Sub-goals:**
- G3a: scope.md is filled for every target before first request
- G3b: Wildcard scope patterns are expanded and checked against DNS before testing
- G3c: Bug class exclusions are noted and the exclusion list is read before each hunt session

**Milestones:**
- M1 (30 days): Zero OOS incidents
- M2 (60 days): Zero OOS incidents
- M3 (90 days): Zero OOS incidents
(Every milestone is the same because this goal is binary.)

**Scope verification protocol:**
1. Copy scope from the program page verbatim into scope.md
2. Expand wildcards: `*.target.com` → enumerate subdomains, verify each resolves to a target-owned IP
3. Check exclusions: identify excluded asset types (mobile, cloud, third-party), excluded bug classes (DoS, clickjacking, etc.)
4. Check focus areas: note what the program WANTS tested (these are highest-ROI targets)
5. Save scope.md and reference it before every session

### G4. Evidence Hygiene
Every finding has a redacted PoC — screenshot, HAR, or request/response pair — attached at submission time. No finding is submitted with "steps to reproduce" alone.

**Signal:** Every submission includes at least one evidence artifact.

**Why this matters:** A finding without evidence is a story, not a bug. Triagers need to see the exploit working to validate it. Programs that require PoC screenshots won't even open a text-only report. Evidence is the difference between "I think there's a bug" and "here is the bug."

**Sub-goals:**
- G4a: Screenshots are captured with the evidence-toolkit, not manually (manual screenshots miss context)
- G4b: All screenshots are redacted before attachment (cookies, PII, internal IPs)
- G4c: HAR exports include only the relevant requests, not the full session

**Milestones:**
- M1 (30 days): Every submission has at least one evidence artifact (screenshot, HAR, or curl transcript)
- M2 (60 days): Every submission has redacted evidence with labeled fields
- M3 (90 days): Evidence capture is fully automated via evidence-toolkit

**Evidence capture workflow:**
1. Reproduce the finding from a clean state
2. Capture the exploit as a screenshot (Burp Repeater response, browser dev tools)
3. Capture the raw request/response (Burp copy as curl, HAR export)
4. Redact: blur all cookies, PII, internal hostnames, and authentication tokens
5. Save with naming convention: `evidence/<finding-id>/<type>-<description>.png`
6. Attach to report before submission

---

## Tier 2: Growth Goals (Session-to-Session)

### G5. Target Depth Over Breadth
One target deeply understood > ten targets shallowly scanned. Minimum 2 hours of active learning (using the app as a real user, reading disclosed reports, mapping the attack surface) before the first probe.

**Signal:** Average 4+ hours per target across all sessions.

**Why this matters:** The first hour on a target produces surface-level reconnaissance — subdomain lists, tech stack fingerprints, WAF detection. The third hour produces understanding — data flow, business logic, trust boundaries. The fifth hour produces bugs — you know the app well enough to find where the shortcuts were taken.

**Sub-goals:**
- G5a: Read at least 3 disclosed reports for the target before testing
- G5b: Create a threat model (in notes.md or memory) before the first probe
- G5c: Spend at least 1 hour using the app as a real user before sending a single modified request

**Milestones:**
- M1 (30 days): Average 2 hours per target
- M2 (60 days): Average 3 hours per target
- M3 (90 days): Average 4+ hours per target

**Target depth protocol:**
```
Phase 1 (2 hours): Learning
  - Read program page, scope, bounty bands
  - Read 3+ disclosed reports for this target
  - Use the app as a real user — register, set up profile, use features
  - Map the attack surface: endpoints, parameters, auth flows

Phase 2 (2 hours): Reconnaissance
  - Subdomain enumeration
  - Technology fingerprinting
  - JS bundle analysis
  - Cloud asset discovery

Phase 3 (2+ hours): Hunting
  - Bug class rotation
  - Chain primitive identification
  - Deep dive on high-value targets (auth, payments, admin, data export)
```

### G6. Technique Library Growth
After every session, at least one technique, payload, or bypass is added to the technique library. The system grows because you grow.

**Signal:** Technique library grows by at least 1 entry per session.

**Why this matters:** If you don't capture what you learn, you pay the rediscovery tax on every future session. A technique library entry takes 5 minutes to write and saves 30 minutes of rediscovery.

**Sub-goals:**
- G6a: End-of-session hook prompts for technique capture
- G6b: Technique entries include: class, target pattern, payload/command, and one real example
- G6c: Dead ends are also captured — they save time on future targets

**Milestones:**
- M1 (30 days): 15 technique entries (1 per session)
- M2 (60 days): 40 technique entries
- M3 (90 days): 75+ technique entries

**Technique entry template:**
```markdown
## [Bug Class] — [Technique Name]

**Target pattern:** [When to use this technique]
**Payload / Command:** [The exact request or command]
**Detection:** [What to look for in the response]
**Example:** [One real example from a disclosed report or personal finding]
**Discovered:** [Date]
```

### G7. Time-Boxed Rotation
10-20 minutes per test per endpoint. No rabbit holes beyond 30 minutes without a confirmed signal. When stuck, rotate — switch target, switch bug class, switch approach.

**Signal:** No single test exceeds 30 minutes without producing a lead.

**Why this matters:** The biggest difference between productive and unproductive sessions is rotation discipline. Rabbit holes consume hours and produce nothing. The first 10 minutes of testing an endpoint produce 80% of the signal. After that, diminishing returns set in rapidly.

**Sub-goals:**
- G7a: A timer runs during all testing phases
- G7b: When the timer fires without signal, the agent automatically logs the dead end and rotates
- G7c: Rotation targets are predefined — you rotate TO something, not just AWAY from something

**Milestones:**
- M1 (30 days): Average test duration per endpoint < 25 minutes
- M2 (60 days): Average test duration per endpoint < 20 minutes
- M3 (90 days): Average test duration per endpoint < 15 minutes

**Rotation cheat sheet:**
```
Test 1: IDOR on user profile endpoints (10 min)
Test 2: SSRF on URL/import/webhook endpoints (10 min)
Test 3: XSS on search/comment/profile endpoints (10 min)
→ Rotate to new bug class if no signal after 30 min on this endpoint
→ Rotate to new endpoint if no signal after 3 tests on this one
→ Rotate to new target if no signal after 3 endpoints
```

---

## Tier 3: System Goals (Platform Health)

### G8. Cross-Platform Compatibility
Hercules-Hunt works identically on Windows (PowerShell), macOS (zsh), and Linux (bash). All agents load, all rules apply, all tools run.

**Signal:** `install.ps1` and `install.sh` both tested clean on their respective platforms.

**Why this matters:** Bug bounty hunters use different operating systems. A Windows user should not be a second-class citizen. A macOS user should not have to rewrite PowerShell scripts. Cross-platform support means methodology, not OS, defines the hunter's capability.

**Sub-goals:**
- G8a: All PS tools have bash equivalents in `tools/bash/`
- G8b: `install.sh` passes shellcheck on Ubuntu, macOS, and WSL
- G8c: `install.ps1` passes script analysis on Windows 10 and Windows 11

**Milestones:**
- M1 (30 days): Linux and macOS install via `install.sh` with all 7 bash tools
- M2 (60 days): Windows and cross-platform install fully tested
- M3 (90 days): CI pipeline tests install on all 3 platforms

### G9. Language-Agnostic Tools
Tools are written in the best language for the job — PowerShell for Windows-native workflows, Python for cross-platform scanning, JavaScript for browser-based analysis. The agent layer abstracts the language choice.

**Signal:** All 17 agents can call tools in any language without adapter changes.

**Why this matters:** Language agnosticism prevents tool rewriting. When a new tool is needed, the hunter writes it in the language they know, not the language the system dictates. The agent layer handles the dispatch — the hunter focuses on the tool's function, not its integration.

**Sub-goals:**
- G9a: Agent definitions reference capabilities, not specific tool paths
- G9b: A dispatch layer maps capability → appropriate tool for the current platform
- G9c: Tool output is normalized to JSON for agent consumption, regardless of the source language

**Milestones:**
- M1 (30 days): All agents reference capability names instead of hardcoded tool paths
- M2 (60 days): Dispatch layer maps all capability → tool mappings
- M3 (90 days): Tool output normalized across all languages

### G10. Self-Documenting System
Every agent, rule, and tool is documented inline. New hunters can read any file and understand what it does, why it exists, and how to use it without external references.

**Signal:** No file in the repo contains only code — every file has a purpose and usage comment.

**Why this matters:** Undocumented tools are dead tools. If a new hunter can't understand what a file does within 30 seconds of opening it, the file might as well not exist. Self-documentation is not optional — it's the difference between a knowledge system and a pile of scripts.

**Sub-goals:**
- G10a: Every file starts with a comment block describing purpose and usage
- G10b: README files exist for every directory (not just the root)
- G10c: Code-level comments explain non-obvious logic (not "what" but "why")

**Milestones:**
- M1 (30 days): Every top-level file has a purpose comment
- M2 (60 days): Every directory has a README
- M3 (90 days): Inline comments cover all non-obvious logic paths

---

## Measuring Success

| Goal | Measurement | Review Cadence |
|------|------------|----------------|
| G1 - Impact validation | N/A ratio on platform | Per submission |
| G2 - Chain before report | % of chain submissions | Per target |
| G3 - Scope discipline | OOS incidents | Per session |
| G4 - Evidence hygiene | Evidence presence in submissions | Per submission |
| G5 - Target depth | Hours per target | Weekly |
| G6 - Technique library | New entries per session | Per session |
| G7 - Time-boxed rotation | Max test duration | Per session |
| G8 - Cross-platform | Install success on each OS | Per release |
| G9 - Language-agnostic | Agent-tool interface tests | Per release |
| G10 - Self-documenting | Doc coverage scan | Per release |

---

## Scoring Your Goals

Each goal is scored 0-10 monthly. Use the median across all 10 as the system health score.

| Score | Meaning |
|-------|---------|
| 10 | Goal achieved consistently, sub-goals exceeded |
| 7-9 | Goal achieved, sub-goals met |
| 4-6 | Goal partially achieved, some sub-goals missed |
| 1-3 | Goal not achieved, significant gaps |
| 0 | No progress |

**Target system health score:** 8+ after 90 days.

---

## Goal Conflicts and Prioritization

Some goals conflict. Here's how to resolve:

**G5 (Depth) vs G7 (Rotation):** Depth means spending time on a single target. Rotation means switching regularly. Resolution: G5 applies per target (spend hours on ONE target), G7 applies per test (spend minutes on ONE test within that target). They operate at different scales.

**G3 (Scope) vs G1 (Impact):** Sometimes the highest-impact test is technically OOS. Resolution: G3 wins. Always. No exception. Impact does not justify OOS testing.

**G6 (Technique capture) vs hunting time:** Capturing techniques takes time away from active hunting. Resolution: G6 wins in the first 90 days (building the library is the highest priority). After 90 days, G6 drops to "capture during natural breaks" (while waiting for scans, during evidence processing).

---

## Short-Term Milestones (30/60/90 Day Plan)

### First 30 Days: Foundation
- G1: N/A ratio < 20%
- G2: Identify 2 chain candidates
- G3: Zero OOS
- G4: Every submission has evidence
- G5: Average 2 hours per target
- G6: 15 technique entries (1 per session)
- G7: Average test duration < 25 minutes
- G8: Linux/macOS install with all bash tools
- G9: Agents reference capabilities, not file paths
- G10: All top-level files have purpose comments

### 31-60 Days: Optimization
- G1: N/A ratio < 15%
- G2: Submit first chain
- G3: Zero OOS
- G4: Redacted evidence on every submission
- G5: Average 3 hours per target
- G6: 40 technique entries
- G7: Average test duration < 20 minutes
- G8: Full cross-platform CI tests
- G9: Dispatch layer operational
- G10: READMEs in all directories

### 61-90 Days: Mastery
- G1: N/A ratio < 10%
- G2: 30%+ submissions are chains
- G3: Zero OOS
- G4: Automate evidence capture
- G5: Average 4+ hours per target
- G6: 75+ technique entries
- G7: Average test duration < 15 minutes
- G8: All install paths validated
- G9: Tool output fully normalized
- G10: Full inline documentation coverage

---

## Review Templates

### Weekly Review

```
# Weekly Review — Week of <date>

## Goals Tracker
| Goal | Score (0-10) | Notes |
|------|-------------|-------|
| G1 - Impact validation | | |
| G2 - Chain before report | | |
| G3 - Scope discipline | | |
| G4 - Evidence hygiene | | |
| G5 - Target depth | | |
| G6 - Technique library | | |
| G7 - Time-boxed rotation | | |
| G8 - Cross-platform | | |
| G9 - Language-agnostic | | |
| G10 - Self-documenting | | |

## Wins
- 

## Misses
- 

## One change for next week
- 

## Next week's primary focus
- Goal(s) to target:
- Specific action:
```

### Monthly Review

```
# Monthly Review — <month>

## Goal Scores
| Goal | Score | Trend (↑ ↓ →) |
|------|-------|---------------|
| G1 | | |
| ... | | |

## Highlight of the month
- Best finding:
- Best technique discovery:
- Best process improvement:

## Lowlight of the month
- Biggest miss:
- What was the root cause?
- What change prevents this from recurring?

## Technique Library Growth
- Entries added this month:
- Total entries:
- Most useful entry added:

## Platform Metrics
- Total submissions:
- Accepted:
- N/A'd:
- N/A ratio:
- Total bounty earned:

## Skill Development
- Which bug class did I improve most at?
- Which bug class needs the most work?

## Next Month Focus
- Primary goal to push:
- One habit to build:
- One habit to break:
```

### Quarterly Review

```
# Quarterly Review — Q<number> <year>

## System Health
Average goal score (all 10): /10

## Accomplishments
- Biggest finding / chain:
- Most significant skill gain:
- Best system improvement:
- Techniques added this quarter:

## Gaps
- What goal(s) consistently scored low?
- What's blocking improvement?
- Do I need different tools, different methodology, or more discipline?

## Platform Health
- Total bounty this quarter:
- Running total all time:
- Average severity this quarter:
- N/A ratio this quarter:

## System Improvements Made
- New agents added:
- New rules written:
- New tools created:
- Technique library growth:

## Next Quarter Goals
- What score do I want each goal at?
- What's the ONE thing that would most improve my hunting?
- Am I still enjoying this? What needs to change?

## Annual Reflection (Q4 only)
- Year-over-year comparison:
  - Findings: [last year] → [this year]
  - Bounty: [last year] → [this year]
  - N/A ratio: [last year] → [this year]
  - Technique library: [last year] → [this year]
- What did I learn about myself as a hunter?
- What would Past Me be surprised about?
```

---

## Long-Term Vision (1-Year / 5-Year)

### 1-Year Goals
- 100+ verified findings across 10+ bug classes
- Technique library with 500+ entries
- N/A ratio maintained below 10%
- 50%+ of submissions are chains
- System adopted by 20+ active hunters
- Cross-platform compatibility at 100%

### 5-Year Goals
- 1,000+ verified findings
- Technique library as a community resource (not just personal)
- Hercules-Hunt methodology integrated into university CTF/security curricula
- Automated chain discovery — AI that identifies chain candidates without manual analysis
- Plugin ecosystem — 100+ community-contributed agents and tools
- Full platform integration — all major bug bounty platforms have native Hercules-Hunt support

---

## The Ultimate Goal

> **To make every hour of hunting more productive than the previous one.**

Not by running more tools. Not by automating more checks. But by deepening understanding, refining methodology, and building a system that learns alongside the hunter.

The system starts where you are. It grows at your pace. After 100 sessions, you have 100 sessions' worth of accumulated knowledge — not 100 sessions' worth of forgotten discoveries.

That is the goal of Hercules-Hunt.
