# Agent System Changelog

## 2026-06-08 — v2.0 Major Upgrade

### Removed
- **Static model references**: Removed `model:` field from all 20 agent files and AGENTS.md registry. Model assignment is now handled by the CLI tool (OpenCode, Claude Code, Codex CLI) at runtime.

### Added — 10 Specialist Hunter Sub-Agents
- **idor-hunter**: IDOR specialist — numeric/UUID/Base64 identifier testing
- **ssrf-hunter**: SSRF specialist — URL fetch, cloud metadata, callback detection
- **xss-hunter**: XSS specialist — reflected, stored, DOM, blind XSS all vectors
- **auth-bypass-hunter**: Auth bypass specialist — login, MFA, password reset, session, headers
- **race-condition-hunter**: Race condition specialist — TOCTOU, parallel requests, state overlap
- **business-logic-hunter**: Business logic specialist — workflow, pricing, referral, quota flaws
- **file-upload-hunter**: File upload specialist — RCE, XSS, XXE, path traversal
- **api-misconfig-hunter**: API misconfig specialist — mass assignment, JWT, CORS, prototype pollution
- **graphql-hunter**: GraphQL specialist — introspection, batching, GQL IDOR
- **ssti-hunter**: SSTI specialist — template injection detection, engine fingerprinting, RCE escalation

### Added — 3 Post-Hunt Workflow Agents
- **program-researcher**: Program scope analysis, disclosed report research, tech stack analysis
- **evidence-reviewer**: PoC hygiene, cookie/PII redaction, HAR sanitization, screenshot standards
- **triage-defender**: Triage objection anticipation, OOS rebuttals, severity counter-arguments

### Added — 2 Pipeline & Automation Agents
- **browser-automator**: Playwright-based browser automation for login, OAuth, blind XSS, DOM testing
- **orchestrator**: End-to-end recon-to-report pipeline coordinator

### Updated
- **p1-warrior.md**: Restructured from monolithic 1400-line hunter to coordinator that dispatches specialist sub-agents (idor-hunter, ssrf-hunter, etc.) via Task tool
- **AGENTS.md**: Added all new agents to registry, removed model field from registration format

### Enhancement Summary
| # | Enhancement | Status |
|---|-------------|--------|
| 1 | Specialist sub-agents (10 new) | ✅ Done |
| 2 | Post-hunt workflow agents (3 new) | ✅ Done |
| 3 | Deeper methodology in all agents | 🔄 In progress |
| 4 | Real examples embedded | ✅ In specialist agents |
| 5 | Cross-agent pipeline | ✅ Orchestrator created |
| 6a | Browser automation agent | ✅ Done |
| 6b | Agent self-diagnostics | 🔄 Pending |
| 6c | Context optimization guidance | 🔄 Pending |
| 6d | Agent versioning/changelog | ✅ Done |
| 6e | Recon-to-report pipeline | ✅ Orchestrator created |
