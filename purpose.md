# Purpose of Hercules-Hunt

## The Problem

Bug bounty hunting suffers from three systemic failures:

**1. Knowledge fragmentation.** The best methodology lives in scattered GitHub repos, Twitter threads, Discord messages, and disclosed reports. Every hunter re-discovers the same techniques. Every session starts from zero.

**2. Theoretical reporting.** Most submissions are killed at triage because they're vague, unproven, or out of scope. The average hunter's N/A ratio climbs with every weak submission, damaging their platform standing and wasting triager time.

**3. Tool isolation.** JavaScript tools can't talk to Python tools. PowerShell scripts can't feed into AI agents. Each tool is an island. The hunter becomes the integration layer — copying output, reformatting, manually connecting dots.

## The Solution

Hercules-Hunt solves all three:

**For knowledge fragmentation:** A unified reference — agents, rules, soul/purpose/goal, SKILL.md — that captures the full methodology in one place. Load one context file (Hercules.md) and every agent, rule, and skill is available. No more hunting for the right prompt or the right checklist.

**For theoretical reporting:** The 7-Question Gate, the 4 pre-submission gates, and the "always rejected" list baked into every agent's behavior. Every finding is validated against real-world impact before a single word of the report is written. Weak findings are killed fast. Strong findings are proven with exact HTTP requests.

**For tool isolation:** A unified agent layer. 17 AI agents (recon-agent → p1-warrior → chain-builder → report-writer) form a pipeline. Agents call tools written in PowerShell, Python, and JavaScript — any language, any platform. The hunter orchestrates, the system executes.

## Who It's For

- **New hunters** who need a structured path from "I want to start bug bounty" to "I found my first real bug"
- **Intermediate hunters** who have some methodology but want to systematize — move from "checklist follower" to "craftsman"
- **Experienced hunters** who want an AI-augmented workflow — agents that handle recon, validation, and reporting so the hunter can focus on the deep, creative work
- **Red teamers** who need battle-tested methodology for authorized engagements
- **Any CLI-based AI** — OpenCode, Claude Code, Codex CLI, Cursor — they all read the same agents, rules, and skills

## What It Is Not

- **Not a vulnerability scanner.** Hercules-Hunt doesn't replace nuclei, Burp Suite, or any active testing tool. It orchestrates them.
- **Not a replacement for skill.** The best agent with the best rules still needs a human who understands the app, the business, and the attack surface.
- **Not a write-and-forget framework.** Hercules-Hunt is alive — it grows with every session, every technique discovered, every rule refined.

## The Core Belief

> **The best bug bounty hunters are not the ones who run the most tools. They are the ones who understand the deepest.**

Hercules-Hunt exists to deepen that understanding — faster, with less friction, and with more consistency.

---

## Deep Dive: Why Knowledge Fragmentation Is Costly

### The Hidden Tax of Rediscovery

Every time a hunter starts a session against a new target without structured methodology, they pay a hidden tax:
- 30 minutes finding the right recon commands
- 20 minutes remembering how to test that specific endpoint type
- 15 minutes searching for the right payload
- 10 minutes deciding which approach to use

One hour per session. Multiply by 300 sessions a year = 300 hours lost to context recovery.

A structured system eliminates this tax by keeping methodology accessible at all times. When the AI knows the rules before the session starts, the hunter spends zero time on setup and 100% of time on hunting.

### The Fragmentation Map

Current hunter methodology is spread across:

| Source | Content | Access Cost |
|--------|---------|-------------|
| Disclosed H1 reports | Specific bug techniques | Searching, reading 20+ irrelevant reports to find the right one |
| Twitter/X | 0-day techniques, WAF bypasses | Scroll-based discovery, ephemeral |
| Discord servers | Real-time methodology discussion | Fragmented across servers, search is terrible |
| Personal notes | Your own hard-won techniques | Unstructured, lost when you switch machines |
| Public GitHub repos | Tool-specific workflows | Abandoned repos, version drift, different CLI expectations |
| YouTube/Patreon | Video walkthroughs | Can't search, can't copy-paste, time-expensive |
| Paid courses | Structured methodology | Paywalled, locked, non-portable |

Hercules-Hunt consolidates the signal from all these sources into one portable, AI-readable format. One install command pulls the entire methodology. No more hunting for the right information.

---

## Deep Dive: Why Theoretical Reporting Happens

### The Three Causes

**1. Premature excitement.** The hunter finds something that LOOKS like a bug and immediately switches to report-writing mode. They skip validation because the rush of discovery feels like confirmation. The report describes what MIGHT happen, not what DID happen.

**2. Fear of missing out (FOMO).** The hunter thinks "if I don't submit this NOW, someone else will submit it first." They rush through validation to get the submission in. The result is a vague report that gets marked N/A.

**3. Skill gap in exploitation.** The hunter knows they've found something unusual but doesn't know how to weaponize it. Instead of documenting that they need to learn the exploitation technique, they submit a theoretical report hoping the triager will do the exploitation work.

### The Solution Built Into Hercules-Hunt

Every agent has the 7-Question Gate hard-coded into its workflow:

1. **Is the target in scope?** — If no, stop.
2. **Can I reproduce this consistently?** — If no, it's a fluke, not a finding.
3. **Is there a real victim action required?** — If yes, how realistic is it? (Having an account is unrealistic. Clicking a link is realistic.)
4. **Can I demonstrate actual harm?** — Not "could potentially." Show the data, the action, the money.
5. **Is this severity-appropriate?** — No inflation, no minimisation.
6. **Is this a chain candidate?** — Can I pair it with another primitive for higher impact?
7. **Would I want to receive this report as a triager?** — The empathy check. Does this report respect the triager's time?

If any question produces the wrong answer, the agent kills the finding before report writing begins.

---

## Deep Dive: Why Tool Isolation Exists

Tools are written in different languages because each language is optimal for its domain:
- **Python:** Cross-platform, rich HTTP libraries, excellent for scanning and automation
- **PowerShell:** Native Windows API access, AD/LDAP, registry, COM objects
- **JavaScript:** Browser DOM access, real-time page inspection, client-side analysis
- **Bash:** Unix-native, pipe-oriented, lightweight orchestration

The traditional solution is "rewrite everything in one language" — which throws away domain-specific advantages. Hercules-Hunt's solution is different: **abstract the language behind the agent layer.**

An agent does not call a Python script or a PowerShell script. An agent calls a **capability** — "fetch URL," "extract JS endpoints," "scan for IDOR" — and the system dispatches to the best tool for the current platform.

This is purpose-driven architecture: tools serve agents, not the other way around.

---

## The Methodology Pyramid

Hercules-Hunt organizes methodology across four layers, each answering a different question:

```
Layer 4: Philosophy          (soul.md, purpose.md, goal.md)
  Why are we doing this? What does "good" look like?

Layer 3: Methodology         (rules/, agents/)
  How do we test for each bug class? What's the workflow?

Layer 2: Reference           (security-arsenal/, reports/, recon/)
  What payloads work? What bypasses exist? What did others find?

Layer 1: Execution           (tools/, mcp/, hooks/)
  Run this command. Call this API. Capture this evidence.
```

Each layer depends on the one above it. Philosophy drives methodology. Methodology determines what reference material is needed. Reference material feeds execution.

Most hunting frameworks only cover Layers 1 and 2 — tools and reference lists. They skip the "why" and the "how." Hercules-Hunt covers all four, which is why it works as a complete system rather than a collection of scripts.

---

## Concrete Example: How the System Works Together

Let's trace a typical IDOR finding through the system:

```
1. SESSION START
   → hooks/hooks.json fires SessionStart event
   → Verifies scope.md exists, tools are installed, environment is ready
   → Loads rules/recon.md and rules/api-testing.md into context

2. RECON PHASE
   → recon-agent.md invokes recon-toolkit.ps1 (Windows) or recon-toolkit.sh (Linux)
   → Output saved to storage/recon-output.md
   → Memory updated: "current_phase = recon"

3. HUNT PHASE
   → p1-warrior agent reads storage/recon-output.md and identifies API endpoints
   → Tests IDOR by modifying user_id parameter in requests
   → Uses curl-hunter.ps1 (or curl-hunter.sh) to send crafted requests
   → Response indicates another user's data was accessible

4. VALIDATION
   → p1-warrior runs the 7-Question Gate from report-writing/report-writing.md
   → Confirms: in scope, reproducible, real harm demonstrated
   → Identifies chain primitive: this IDOR could combine with missing rate limit on /api/user/password

5. EVIDENCE
   → evidence-toolkit.ps1 (or evidence-toolkit.sh) captures screenshot and HAR
   → Cookies redacted, PII blurred
   → Saved to evidence/IDOR-user-profile/

6. REPORT
   → report-writer agent generates report from the finding template
   → CVSS 3.1 scored, impact-first written
   → Submitted to platform

7. POST-SESSION
   → hooks/hooks.json fires SessionStop event
   → Technique captured to technique library
   → notes.md updated with what worked and what didn't
   → Memory hydrated: "lessons_learned = [...]"
```

Every component played its role. No manual copy-paste between tools. No "where did I save that output?" No last-minute evidence scrambling.

---

## Purpose of Each Major Component

### Agents (17 definitions)
Agents exist to **eliminate context-switching.** Each agent defines a complete workflow for a specific task. When you invoke recon-agent, it doesn't just run recon commands — it runs the right recon commands for the current target, in the right order, with the right flags, and interprets the output. The agent is your specialist that never forgets the workflow.

### Rules (14+ files)
Rules exist to **constrain AI behavior.** Without rules, AI agents are too creative — they try interesting but wrong approaches, guess at methodology, or waste time on low-value tests. Rules tell the AI: "You must validate scope first. You must stop after 20 minutes without signal. You must attach evidence to every submission." Rules are the guardrails that keep the AI focused on high-impact work.

### Skills (SKILL.md + installers)
Skills exist for **platform compatibility.** Each AI CLI tool (Claude Code, OpenCode, Codex CLI) has a different skill/plugin format. The skill layer abstracts these differences so the same methodology works everywhere. Install once, hunt on any AI.

### Tools (Python / PowerShell / JavaScript / Bash)
Tools exist to **execute.** They are stateless, single-purpose, and language-agnostic. A tool does one thing well — fetch a URL, parse a JS bundle, test an SSRF endpoint, capture a screenshot. Tools do not make decisions. Agents make decisions using tool output.

### MCP Servers (10 definitions)
MCP servers exist to **bridge the AI with external services.** When an agent needs to check a DNS record, resolve a subdomain, or test a payload, it doesn't need to know how DNS works or how to craft the HTTP request. The MCP server abstracts that. MCP is the AI's API to the internet.

### Hooks
Hooks exist for **session lifecycle management.** When a session starts, hooks check that nuclei, subfinder, and Burp are installed. When a session ends, hooks remind the hunter to capture techniques and update the technique library. Hooks are the system's conscience — they run at the right time and keep the hunter honest.

### Config / Context / Memory / Storage
These four directories form the **session data layer:**
- **Config:** What tools are available and how they're configured
- **Context:** What's happening right now (active target, current phase, next actions)
- **Memory:** What the system has learned (past sessions, techniques discovered, dead ends explored)
- **Storage:** What data has been collected (evidence, credentials, findings, tool outputs)

They exist to make the system stateful. Without them, every session starts from zero.

---

## How Hercules-Hunt Fits Into the Broader Ecosystem

### Relationship With Testing Tools

Hercules-Hunt does not replace:
- **Burp Suite** — Proxying, intercepting, repeating, intruding
- **nuclei** — Template-based scanning
- **subfinder / amass** — Subdomain enumeration
- **ffuf / dirsearch** — Directory/parameter fuzzing
- **Katana / gospider** — URL crawling
- **Interact.sh** — OOB callbacks

Hercules-Hunt orchestrates them. An agent decides WHAT to test, WHEN to run which tool, and HOW to interpret the output. The tools themselves are installed separately. The quality of your hunting is still limited by the quality of your tools — but the quality of your METHODOLOGY is limited by your system.

### Relationship With AI CLIs

Hercules-Hunt is intentionally CLI-agnostic. The same files that work in OpenCode work in Claude Code, Codex CLI, Cursor, Windsurf, and any other AI that reads local files. This is by design — the bug bounty community uses different tools, and Hercules-Hunt should work for everyone.

### Relationship With the Community

Hercules-Hunt is not a closed framework. It's designed to be forked, modified, and extended. If you discover a new technique, you add it to the technique library. If you find a new WAF bypass, you add it to the arsenal. The system grows because the community grows.

---

## The Feedback Loop

Hercules-Hunt is designed around a continuous feedback loop:

```
Hunt → Discover → Capture → Refine → Hunt (improved)
```

1. **Hunt** — use the agents, rules, and tools to test a target
2. **Discover** — find a bug, a technique, a dead end, or a process improvement
3. **Capture** — document it in the technique library, memory, or rules
4. **Refine** — update the relevant agents, rules, or tools
5. **Hunt (improved)** — next session starts from a higher baseline

Every session makes the system smarter. After 10 sessions, the system knows your target preferences, your strongest bug classes, and your weakest methodology areas. After 100 sessions, the system is a personalized hunting partner.

---

## The Educational Mission

Hercules-Hunt exists to **flatten the learning curve** for new hunters.

The typical path to competence in bug bounty takes 12-18 months of trial and error:
- 6 months learning what tools exist
- 6 months learning how to use them effectively
- 6 months developing methodology

Hercules-Hunt compresses this to 3-6 months because:
- The methodology is captured and structured — no rediscovery
- The agents demonstrate correct workflows — learn by watching the AI
- The rules prevent common mistakes — learn from documented failures
- The technique library accumulates community knowledge — stand on others' shoulders

---

## The Community Mission

Bug bounty hunting has a sharing problem. The best hunters guard their methodology because:
- They spent years developing it
- Sharing techniques might increase competition
- They don't have a format for sharing

Hercules-Hunt provides the format. Submit a technique to the technique library. Submit a rule refinement. Submit a payload. The system rewards sharing because:
- Shared techniques are indexed and retrievable
- Credit is tracked in the technique library metadata
- The whole system improves, which improves every hunter's results

A rising tide lifts all boats. Hercules-Hunt is the tide.

---

## Measurement of Purpose

How do we know if Hercules-Hunt is fulfilling its purpose?

| Metric | Target | How to Measure |
|--------|--------|----------------|
| Time from session start to first test | < 2 minutes | Session logs |
| N/A ratio across all submissions | < 10% | Platform profile |
| Time from finding to report | < 30 minutes | Session logs |
| Techniques added per session | > 1 | Technique library git log |
| Cross-platform install success | 100% | CI test results |
| Agent invocation success rate | > 95% | Session logs |
| Hunter satisfaction | > 4/5 | Monthly self-survey |

---

## The Role of AI Augmentation

Hercules-Hunt is designed for the era of AI-augmented hunting. The AI is not the hunter — the human is the hunter. The AI is a force multiplier.

### What the AI Does Well

- **Remembers methodology** — The AI never forgets a step in the workflow. It always checks scope first, always validates findings, always captures evidence.
- **Executes reliably** — The AI runs the same tool the same way every time. No typos, no forgotten flags, no skipped steps.
- **Pattern matching across contexts** — The AI reads 10 disclosed reports and synthesizes the common technique. The AI maps a finding against 17 bug classes simultaneously.
- **Speed** — The AI runs a 10-step recon workflow in seconds. A human takes 30 minutes.

### What the Human Does Better

- **Business understanding** — Why does this feature exist? What's the business model? Where's the money?
- **Creative hypothesis generation** — "What if I chain this with that?" is a human insight, not an algorithmic output.
- **Ethical judgment** — Is this test responsible? Is this disclosure appropriate? Should I stop?
- **Intuition** — "This response feels wrong" is pattern recognition that comes from experience.

### The Partnership Model

```
Human: "Hunt this target for IDOR."
AI: "Scope verified. Starting recon. Found 12 endpoints. Testing each with IDOR payloads."
Human: "That response on /api/users/1337 — dig deeper there."
AI: "Testing deeper on /api/users/1337. Response shows email change without re-auth. Chain candidate with IDOR. 7-Question Gate passed. Generating report."
Human: (reviews report) "Impact is correct. Submit."
AI: "Submitted. Post-session: 2 techniques captured, 1 dead end logged, memory updated."
```

Neither replaces the other. They amplify each other.

---

## The System Design Philosophy

Every design decision in Hercules-Hunt follows these principles:

### 1. Files Over Databases

Everything is a markdown file. No database, no API, no proprietary format. This means:
- Every file is readable by any text editor
- Every file is diffable (git-friendly)
- Every file is portable (copy to any machine, any CLI)
- No vendor lock-in (leave anytime, take everything)

### 2. Convention Over Configuration

File names and directory structure are conventions. An agent in `agents/` is loaded by name. A rule in `rules/` is applied by the agent. A tool in `tools/python/` is dispatachable by capability. You don't configure connections — you follow the naming convention and it works.

### 3. Composability

Each component is independent. Agents don't depend on specific tools — they depend on capabilities. Tools don't depend on agents — they take input, produce output, and exit. This means you can use any component in isolation. The IDOR hunter works standalone. The recon toolkit works standalone. The chain builder works standalone. They're more powerful together, but not dependent on each other.

### 4. The System Serves the Hunter, Not the Other Way Around

Hercules-Hunt never replaces the hunter's judgment. It never submits a report without human review. It never tests an endpoint without scope verification. The system is a tool, not a decision-maker. The hunter remains responsible for every action.

### 5. Continuous Improvement

No version numbers. No releases. The system evolves continuously — every session, every technique added, every rule refined. The git log is the changelog. The technique library is the release notes.

---

## Common Misunderstandings

### "I don't need an AI to hunt"

You don't. You can hunt with Burp Suite and a notebook. Hercules-Hunt is for when you want to:
- Stop re-discovering the same methodology
- Stop losing notes between sessions
- Stop manually connecting tool outputs
- Start hunting faster, with fewer gaps, and with higher consistency

### "This replaces learning the fundamentals"

It doesn't. Hercules-Hunt won't teach you what HTTP headers do, how JWT works, or what a race condition is. You need those fundamentals before the system becomes useful. The system structures what you already know — it doesn't replace knowing it.

### "This is too big"

Hercules-Hunt is ~118K lines across ~200 files. Yes, it's large. But:
- 60% is content (methodology, rules, agents, reference material) — this is the product
- 40% is executable (tools, MCP servers, scripts)
- You don't use all of it at once — you use the agents relevant to your current target
- The size is appropriate for the scope: 17 bug classes × multiple formats × cross-platform support

---

## Anti-Patterns: How NOT to Use Hercules-Hunt

### Load Everything at Once
Reading all agents, rules, and tools in one session overwhelms the AI context window. Load only what you need for the current target and current bug class. The systems directory and file names tell you what each component does — use them.

### Never Update Anything
The system starts useful and decays. Agents reference specific file paths. Tools have specific arguments. Techniques become outdated. If you never update, the system becomes technical debt. Minimum: one rule or one technique refined per week.

### Hunt Without the Philosophy
Jumping straight to tools without internalizing soul.md and goal.md produces a tool user, not a hunter. The philosophy is not decoration — it's the foundation. Read it. Re-read it. Internalize it.

### Never Document Dead Ends
The technique library captures what works. Dead ends capture what doesn't. Both are valuable. A dead end on Target A saves you 30 minutes on Target B. Log every dead end.

### Skip the Validation Gates
The 7-Question Gate exists because every hunter overestimates their findings. Skipping it produces N/As. One N/A wastes more time than 10 validation checks. Run the gate.

---

## Common Myths About Bug Bounty Hunting

### Myth: You Need Advanced Skills to Start
Reality: The highest-volume bug class (IDOR) requires no advanced skills. You modify a user_id parameter and see whose data comes back. Most Critical findings are not technically complex — they're conceptually simple but impact-heavy.

### Myth: Automated Scanners Find the Best Bugs
Reality: Automated scanners find the most SURFACE bugs. They find outdated versions, missing headers, and known CVEs. They almost never find business logic flaws, chain primitives, or auth bypasses — which is where the high payouts are.

### Myth: You Need 10+ Years of Experience
Reality: The learning curve is steep but the ceiling is approachable. Dedicated hunters reach competence in 6-12 months. The methodology exists — you don't need to discover it yourself.

### Myth: More Tools = More Findings
Reality: More tools = more noise. One tool used with understanding is worth 10 tools used without methodology. Master nuclei, Burp Suite, and curl before adding anything else.

### Myth: Bug Bounty Is Easy Money
Reality: Bug bounty pays well for the top 1% of hunters. For everyone else, it pays minimum wage or less when you calculate hours spent versus bounty earned. Don't quit your job. Hunt for skill development first, money second.

---

## System Limitations

Hercules-Hunt has limitations. Knowing them prevents over-reliance.

### What the System Cannot Do

1. **Read the target's mind.** No agent can guess what the target's business priorities are. That requires human context — reading the company's blog, understanding their market, knowing their recent acquisitions.
2. **Test every endpoint simultaneously.** The system is serial by design (one test at a time). It cannot parallelize across attack surfaces.
3. **Guarantee no false positives.** The 7-Question Gate reduces false positives but doesn't eliminate them. Some findings that pass the gate will still be N/A'd. That's hunting.
4. **Replace domain expertise.** If you don't understand how OAuth works, the OAuth testing agent won't help you. The agent assumes you have foundational knowledge.
5. **Automate creativity.** No agent can have the creative insight that a seemingly unrelated feature is actually the chain primitive for a Critical finding. That insight comes from the human.

### When to Not Use the System

- **First week on a new tech stack.** Before using the system, spend time learning the technology. The agent's assumptions about how the tech works may be wrong for this specific implementation.
- **When you're burned out.** The system is a tool, not a motivation engine. If you're burned out, no agent or tool will help. Take the break. Come back later.
- **For emergency response.** If you find a critical vulnerability that's being actively exploited, don't run it through the full workflow. Report it immediately through emergency channels.

---

## The Technical Debt Tradeoff

Hercules-Hunt accumulates technical debt just like any software project. Every technique added without updating the relevant agent creates drift. Every rule added without removing the outdated rule creates confusion.

### Managing Technical Debt

**Weekly maintenance session (30 minutes):**
- Review the git log for the week. What changed?
- Check for orphaned techniques (techniques that reference tools that no longer exist)
- Check for conflicting rules (two rules that give contradictory instructions)
- Check for out-of-date file paths in agents and rules

**Monthly cleanup session (1 hour):**
- Review the technique library. Are there entries that are no longer useful?
- Review the rules directory. Are there rules that could be merged?
- Review the tools directory. Are there tools that never get used?
- Archive unused components instead of deleting them (they may become relevant again).

**The 10% Rule:** Spend 10% of hunting time on system maintenance. If you hunted 10 hours this week, spend 1 hour maintaining the system. This prevents the system from decaying into unusability.

---

## Integrating With Other Systems

Hercules-Hunt is designed to coexist with other tools and frameworks, not replace them.

### With Burp Suite
Hercules-Hunt provides the methodology. Burp Suite provides the interception, repeating, and scanning. The workflow: Hercules-Hunt tells you what to test, Burp Suite executes the test, Hercules-Hunt interprets the response and decides the next action. Neither replaces the other.

### With Nuclei
Nuclei scans for template-based vulnerabilities. Hercules-Hunt uses nuclei output as one DATA POINT in the recon phase, not as the primary finding source. If nuclei finds something, Hercules-Hunt validates it manually before accepting it as a finding.

### With Disclosed Report Databases
Hercules-Hunt references disclosed reports as methodology sources. When an agent says "read 3 disclosed reports for this target," it's pointing to HackerOne Hacktivity, not to an internal database. The system doesn't store disclosed reports — it references them.

### With Other AI CLIs
Hercules-Hunt works in any CLI that reads local files:
- **OpenCode:** Reads agents from AGENTS.md, rules from rules/, tools from tools/
- **Claude Code:** Reads agents and rules from CLAUDE.md
- **Codex CLI:** Reads from local file system
- **Cursor:** Reads from .cursorrules and .mdc files
- **Windsurf:** Reads from .windsurfrules

The same files work everywhere. No format conversion needed.

---

## The Onboarding Path

### Day 1: Install
Run `install.ps1` (Windows) or `install.sh` (Linux/macOS). The agent registry (AGENTS.md) loads all available agents. The rules load into the AI's context. The tools are copied to the appropriate platform directory.

### Day 2-3: Read the Foundation
Read soul.md, purpose.md, and goal.md. These three files define what the system is and why it exists. Skip this step and you're using the tools without context — you'll get surface-level results.

### Day 4-7: Hunt Your First Target
Choose a target with at least 5 disclosed reports (learning from other hunters' findings). Follow the ENGAGEMENT.md workflow. Use recon-agent for the first session, p1-warrior for the second.

### Day 8-14: Systematize
After 3-4 sessions, review what worked and what didn't. Add techniques to the technique library. Refine rules that didn't help. Update agents that made incorrect assumptions.

### Day 15+: Operate
The system is now personalized. Continue hunting. Continue refining. The system grows with you.

---

## How to Convince Someone to Use Hercules-Hunt

### For a New Hunter
"This system compresses the 12-18 month learning curve into 3-6 months. Instead of re-discovering methodology, you start hunting from day one with battle-tested workflows. The technique library accumulates everything you learn. After 100 sessions, you have 100 sessions' worth of knowledge — not 100 sessions' worth of forgotten discoveries."

### For an Intermediate Hunter
"You're finding Mediums consistently but not breaking through to Highs and Criticals. The problem isn't your skill — it's your process. You're testing endpoints in isolation instead of chaining primitives. The chain-builder agent formalizes what you're already doing intuitively. The technique library captures the patterns you've been re-discovering."

### For an Experienced Hunter
"You know the methodology. But you waste 30 minutes every session context-switching between tools, checking what you did last time, finding the right payload. Hercules-Hunt eliminates the overhead. Agents remember the workflow. Tools dispatch to the right language. Rules constrain the AI. You spend 100% of time hunting, 0% on context recovery."

### For a Red Teamer
"You need battle-tested methodology across 20+ attack classes, with chain documentation standards and report templates for client deliverables. Hercules-Hunt gives you the same structured approach that enterprise offensive security teams use, in a portable format that works in any CLI."

---

That is its purpose.
