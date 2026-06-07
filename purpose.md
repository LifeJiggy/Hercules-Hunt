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

That is its purpose.
