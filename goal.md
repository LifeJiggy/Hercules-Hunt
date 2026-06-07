# Goals of Hercules-Hunt

## North Star Metric

> **Every session produces one of two outcomes: a verified finding or a documented dead end.**

No wasted sessions. Every hour of hunting either advances a finding toward submission or narrows the attack surface by ruling something out.

---

## Tier 1: Core Goals (Non-Negotiable)

### G1. Impact-First Validation
Every finding must pass the 7-Question Gate before any report writing begins. Theoretical bugs are killed instantly. Only findings with demonstrated real-world harm reach submission.

**Signal:** N/A ratio < 10% across all submissions.

### G2. Chain Before Report
Single low-severity bugs are not submitted alone. Every finding is evaluated for chain potential — can this A pair with a B to create critical impact? Chains are submitted as one report, not separate lows.

**Signal:** At least 30% of submissions involve 2+ chained primitives.

### G3. Scope Discipline
Every asset tested is verified against program scope before a single request is sent. OOS violations are not just bad practice — they destroy platform standing and waste triager trust.

**Signal:** Zero OOS submissions.

### G4. Evidence Hygiene
Every finding has a redacted PoC — screenshot, HAR, or request/response pair — attached at submission time. No finding is submitted with "steps to reproduce" alone.

**Signal:** Every submission includes at least one evidence artifact.

---

## Tier 2: Growth Goals (Session-to-Session)

### G5. Target Depth Over Breadth
One target deeply understood > ten targets shallowly scanned. Minimum 2 hours of active learning (using the app as a real user, reading disclosed reports, mapping the attack surface) before the first probe.

**Signal:** Average 4+ hours per target across all sessions.

### G6. Technique Library Growth
After every session, at least one technique, payload, or bypass is added to the technique library. The system grows because you grow.

**Signal:** Technique library grows by at least 1 entry per session.

### G7. Time-Boxed Rotation
10-20 minutes per test per endpoint. No rabbit holes beyond 30 minutes without a confirmed signal. When stuck, rotate — switch target, switch bug class, switch approach.

**Signal:** No single test exceeds 30 minutes without producing a lead.

---

## Tier 3: System Goals (Platform Health)

### G8. Cross-Platform Compatibility
Hercules-Hunt works identically on Windows (PowerShell), macOS (zsh), and Linux (bash). All agents load, all rules apply, all tools run.

**Signal:** `install.ps1` and `install.sh` both tested clean on their respective platforms.

### G9. Language-Agnostic Tools
Tools are written in the best language for the job — PowerShell for Windows-native workflows, Python for cross-platform scanning, JavaScript for browser-based analysis. The agent layer abstracts the language choice.

**Signal:** All 17 agents can call tools in any language without adapter changes.

### G10. Self-Documenting System
Every agent, rule, and tool is documented inline. New hunters can read any file and understand what it does, why it exists, and how to use it without external references.

**Signal:** No file in the repo contains only code — every file has a purpose and usage comment.

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

## The Ultimate Goal

> **To make every hour of hunting more productive than the previous one.**

Not by running more tools. Not by automating more checks. But by deepening understanding, refining methodology, and building a system that learns alongside the hunter.

That is the goal of Hercules-Hunt.
