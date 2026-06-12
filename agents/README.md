# Agents Module

Agent definition files for OpenCode and other agentic CLI tools that use AGENTS.md format. 40 agent definitions covering recon, hunting, chaining, validation, and reporting.

## Core Agents

| File | Description |
|------|-------------|
| `recon-agent.md` | Subdomain enumeration and live host discovery |
| `recon-ranker.md` | Attack surface ranking and prioritization |
| `p1-warrior.md` | Priority-1 bug hunter coordinator |
| `chain-builder.md` | Exploit chain builder (IDOR→auth bypass, SSRF→cloud metadata, etc.) |
| `js-analysis.md` | JavaScript bundle analysis for secrets and endpoints |
| `js-deobfuscation.md` | JavaScript deobfuscation and reverse engineering |
| `report-writer.md` | Professional bug bounty report writer (H1, Bugcrowd, etc.) |
| `validator.md` | Finding validator (7-Question Gate, 4-gate checklist) |
| `autopilot.md` | Autonomous hunt loop agent |
| `exploit-researcher.md` | CVE and exploit PoC researcher |
| `network-analyst.md` | Deep network analysis and packet inspection |
| `redteam-planner.md` | Red team engagement planner (MITRE ATT&CK mapped) |
| `reverse-engineer.md` | Binary analysis and reverse engineering |
| `security-reviewer.md` | Deep security audit (OWASP Top 10, CWE Top 25) |
| `ai-researcher.md` | AI/ML security research (prompt injection, LLM red-teaming) |
| `token-auditor.md` | Meme coin and token security auditor (EVM + Solana) |
| `web3-auditor.md` | Smart contract security auditor (10 bug classes) |
| `mobile-testing-agent.md` | Mobile application security testing (Android/iOS) |
| `windows-workflow-agent.md` | Windows-native bug bounty workflow |
| `chain-rules-agent.md` | Vulnerability chaining methodology specialist |
| `program-researcher.md` | Bug bounty program researcher |
| `orchestrator.md` | Recon-to-report pipeline orchestrator |
| `browser-automator.md` | Playwright-based browser automation |
| `evidence-reviewer.md` | Evidence quality control and PoC verification |
| `triage-defender.md` | Triage defense against OOS and downgrade claims |

## Specialist Hunter Sub-Agents

| File | Description |
|------|-------------|
| `idor-hunter.md` | IDOR specialist |
| `ssrf-hunter.md` | SSRF specialist |
| `xss-hunter.md` | XSS specialist |
| `auth-bypass-hunter.md` | Auth bypass specialist |
| `race-condition-hunter.md` | Race condition specialist |
| `business-logic-hunter.md` | Business logic vulnerability specialist |
| `file-upload-hunter.md` | File upload vulnerability specialist |
| `api-misconfig-hunter.md` | API misconfiguration specialist |
| `graphql-hunter.md` | GraphQL vulnerability specialist |
| `ssti-hunter.md` | SSTI specialist |

## Post-Hunt Workflow

| File | Description |
|------|-------------|
| `chain-validator.md` | Exploit chain validator before submission |
| `p1-validator.md` | P1 finding pre-flight validator |
| `scope-enforcer.md` | Scope boundary enforcer |
| `target-onboarding-agent.md` | Target onboarding intelligence gatherer |
| `triage-readiness.md` | Triage readiness checker |

## Supporting Files

| File | Description |
|------|-------------|
| `AGENTS.md` | Agent registry (master index of all agents) |
| `AGENTS_CHANGELOG.md` | Changelog for agent definitions |
