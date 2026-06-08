# Hercules-Hunt

**An operating system for AI-augmented bug bounty hunting.**

Not a tool. Not a scanner. A **hunter's operating system** — 202 source files, 44 directories, ~118K lines across Python, PowerShell, JavaScript, Bash, MCP, and 1,800+ pages of markdown methodology. Designed to work with OpenCode, Claude Code, Codex CLI, Cursor, and any agentic coding CLI.

---

## The Philosophy

Hercules-Hunt treats bug bounty hunting as a **craft**, not a factory process.

Most frameworks give you a checklist — "test for X, test for Y, write it up." Hercules-Hunt gives you an **operating system** — agents that remember the methodology, rules that constrain the AI, tools that execute in any language, and a philosophy that keeps you hunting when the signal is gone.

Three forces drive every great hunter:

- **Curiosity** — Why does this feature work this way? What shortcut did the developer take?
- **Discipline** — 10 minutes per test. 20 if there's signal. Rotate when there isn't.
- **Integrity** — Prove it or drop it. No theoretical findings.

Read the full philosophy: [`soul.md`](soul.md), [`purpose.md`](purpose.md), [`goal.md`](goal.md)

---

## What's Inside

### 17 AI Agents

Every agent is a complete, self-contained workflow — invoke it and the AI knows exactly what to do:

| Agent | Role | File |
|---|---|---|
| **recon-agent** | Subdomain enumeration, live host discovery, tech fingerprinting | [`agents/recon-agent.md`](agents/recon-agent.md) |
| **recon-ranker** | Attack surface prioritization by IDOR likelihood, API surface, tech stack | [`agents/recon-ranker.md`](agents/recon-ranker.md) |
| **p1-warrior** | Systematic P1 hunting — cycles through bug classes, time-boxed | [`agents/p1-warrior.md`](agents/p1-warrior.md) |
| **chain-builder** | Finds B for every A — chains primitives to Critical | [`agents/chain-builder.md`](agents/chain-builder.md) |
| **js-analysis** | Extracts endpoints, secrets, cloud keys from JS bundles | [`agents/js-analysis.md`](agents/js-analysis.md) |
| **js-deobfuscation** | Reverses webpack bundles, eval-based obfuscation, VM-protected code | [`agents/js-deobfuscation.md`](agents/js-deobfuscation.md) |
| **report-writer** | Generates H1/Bugcrowd/Intigriti/Immunefi reports with CVSS 4.0 | [`agents/report-writer.md`](agents/report-writer.md) |
| **validator** | 7-Question Gate + 4-gate checklist — kills weak findings fast | [`agents/validator.md`](agents/validator.md) |
| **autopilot** | Autonomous end-to-end hunt loop with configurable checkpoints | [`agents/autopilot.md`](agents/autopilot.md) |
| **exploit-researcher** | CVE research, PoC matching, exploit development strategies | [`agents/exploit-researcher.md`](agents/exploit-researcher.md) |
| **network-analyst** | Packet inspection, protocol dissection, IDS/IPS rule creation | [`agents/network-analyst.md`](agents/network-analyst.md) |
| **redteam-planner** | Engagement design, C2 infrastructure, MITRE ATT&CK mapped | [`agents/redteam-planner.md`](agents/redteam-planner.md) |
| **reverse-engineer** | Binary analysis, firmware RE, Frida instrumentation | [`agents/reverse-engineer.md`](agents/reverse-engineer.md) |
| **security-reviewer** | Source code audit against OWASP Top 10 + CWE Top 25 | [`agents/security-reviewer.md`](agents/security-reviewer.md) |
| **ai-researcher** | LLM red-teaming, prompt injection, system prompt extraction | [`agents/ai-researcher.md`](agents/ai-researcher.md) |
| **token-auditor** | Meme coin/token security — honeypot, rug pull, LP drain (EVM + Solana) | [`agents/token-auditor.md`](agents/token-auditor.md) |
| **web3-auditor** | Smart contract audit — 10 bug classes, DeFi focus | [`agents/web3-auditor.md`](agents/web3-auditor.md) |

### 13+ Behavioral Rules

Rules are the AI's guardrails — always-active constraints loaded at session start:

| Rule | Domain |
|------|--------|
| `rules/recon.md` | Subdomain enumeration, asset discovery, attack surface mapping (3,363 lines) |
| `rules/api-testing.md` | Mass assignment, JWT attacks, prototype pollution, CORS, verb tampering (2,594 lines) |
| `rules/auth-testing.md` | OAuth, SAML, MFA, password reset, session management (2,024 lines) |
| `rules/mindset.md` | Red-team discipline, conservative-default corrections, stuck protocol |
| `rules/scope.md` | Scope boundaries, wildcard discipline, safe harbor, OOS prevention |
| `rules/evidence.md` | PoC standards, cookie redaction, PII masking, HAR sanitization |
| `rules/chaining.md` | A→B→C chain methodology, primitive taxonomy, severity multiplication |
| `rules/mobile.md` | Android/iOS APK analysis, Frida instrumentation, intent injection |
| `rules/windows.md` | PowerShell-first workflow, curl.exe mastery, WSL integration |
| `rules/web3.md` | DeFi audit methodology, Solidity patterns, flash loan exploit paths |
| `rules/llm-ai.md` | Prompt injection, indirect injection, ASCII smuggling, agentic AI framework |
| `rules/cloud-iam.md` | AWS/Azure/GCP IAM enumeration, privilege escalation, SSRF-to-cloud chains |
| `rules/m365-entra.md` | M365/Entra ID credential attack, user enumeration, CA bypass |
| `rules/js-deobfuscation.md` | Deobfuscation and reverse engineering of JavaScript bundles |

### Executable Tools (4 Languages)

Tools are cross-platform — same capabilities on Windows (PowerShell), Linux/macOS (Bash), and anywhere (Python):

| Tool | Language | Size | Purpose |
|------|----------|------|---------|
| `curl-hunter` | PS1 + Bash | 2,275 + 404 lines | 15 curl-based endpoint testing functions |
| `recon-toolkit` | PS1 + Bash | 2,071 + 460 lines | Automated recon pipeline (subfinder, httpx, wayback) |
| `fuzzer-toolkit` | PS1 + Bash | 847 + 511 lines | Parameter fuzzing, wordlist-driven discovery |
| `js-analyzer` | PS1 + Bash | 1,499 + 380 lines | Secret/URL/endpoint extraction from JS bundles |
| `evidence-toolkit` | PS1 + Bash | 640 + 460 lines | Evidence capture, HAR sanitization, screenshots |
| `lib` | PS1 + Bash | 734 + 576 lines | Shared helper functions (70+ PS, 20+ bash) |
| `jiggy` | PS1 + Bash | 713 + 422 lines | CLI dispatcher — unified interface to all tools |
| `python-hunter.py` | Python | — | Cross-platform scanner with 30+ secret patterns |

**CLI one-liners:**
```powershell
# PowerShell (Windows)
.\tools\powershell\jiggy.ps1 recon target.com
.\tools\powershell\jiggy.ps1 idor https://target.com/api/users/{id}
.\tools\powershell\jiggy.ps1 fuzz https://target.com/api/endpoint
.\tools\powershell\jiggy.ps1 js bundle.js
```

```bash
# Bash (Linux/macOS)
./tools/bash/jiggy.sh recon target.com
./tools/bash/jiggy.sh idor https://target.com/api/users/{id}
./tools/bash/jiggy.sh fuzz https://target.com/api/endpoint
./tools/bash/jiggy.sh js bundle.js
```

### 10 MCP Servers

MCP (Model Context Protocol) servers bridge the AI with external services over JSON-RPC 2.0:

| Server | Purpose | Tools |
|--------|---------|-------|
| `recon-mcp` | Subdomain enumeration, DNS resolution, technology fingerprinting | `resolve_subdomain`, `get_dns_records`, `fingerprint_tech` |
| `dns-recon-mcp` | Deep DNS reconnaissance, zone transfers, record enumeration | `dns_bruteforce`, `dns_zonetransfer`, `dns_reverse_lookup` |
| `url-crawl-mcp` | URL crawling, endpoint discovery, parameter extraction | `crawl_url`, `extract_endpoints`, `discover_parameters` |
| `payload-mcp` | Payload generation, WAF bypass construction, encoding | `generate_payload`, `encode_payload`, `bypass_waf` |
| `interactsh-mcp` | OOB interaction, callback capture, DNS/HTTP logging | `generate_callback`, `poll_interactions`, `get_logs` |
| `report-mcp` | Report generation, CVSS scoring, template management | `calculate_cvss`, `generate_report`, `validate_report` |
| `hercules-hunt-mcp` | Orchestration, session management, workflow dispatching | `start_engagement`, `invoke_agent`, `save_finding` |
| `hackerone-mcp` | HackerOne API integration, submission management | `submit_report`, `check_status`, `list_programs` |
| (2 additional internal servers) | | |

### 50+ Skills

Methodology for every bug class, loaded on-demand during hunts:

IDOR, SSRF, XSS, SQLi, auth bypass, race condition, file upload, GraphQL, HTTP smuggling, cache poisoning, OAuth, SAML, SSTI, JWT, prototype pollution, subdomain takeover, cloud misconfig, ATO chains, MFA bypass, LLM/AI injection, CSRF, business logic, RCE, XXE, NTLM info disclosure, SharePoint enumeration, ASP.NET testing, enterprise VPN attack, supply chain recon, memo coin audit, DeFi smart contracts, and more.

### Session Lifecycle Hooks

Hooks fire at key session events to keep the hunter disciplined:

```json
// hooks/hooks.json — 333 lines of targeted hooks
{
  "SessionStart": ["Check scope exists", "Verify tools installed", "Check environment"],
  "PostToolUse": ["Evaluate chain potential", "Detect signal patterns"],
  "SessionStop": ["Capture techniques", "Log dead ends", "Update memory"]
}
```

### Memory & Context System

Persistent session memory so every session starts from the last session's endpoint:

| File | Purpose |
|------|---------|
| `memory/session-state.md` | Heartbeats, phase transitions, next actions |
| `memory/discoveries.md` | Running log of findings and leads |
| `memory/technique-library.md` | Accumulated techniques, payloads, bypasses |
| `storage/evidence.md` | Evidence schema, redaction protocol |
| `storage/credentials.md` | Credential vault schema |
| `storage/findings.md` | Finding schema with chain tracking |
| `storage/tool-outputs.md` | Tool output normalization schemas |
| `context/active-target.md` | Current engagement context |

---

## Architecture

The project expresses each security domain in **multiple formats for different consumption modes**:

```
                     ┌─────────────────┐
                     │   Hunter (You)    │
                     └────────┬────────┘
                              │
                    ┌─────────▼─────────┐
                    │   AI Agent Layer   │
                    │   (17 agents)      │
                    └─────────┬─────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
   ┌─────▼─────┐      ┌──────▼──────┐      ┌──────▼──────┐
   │  Rules     │      │  Skills     │      │  Tools      │
   │ (13 files) │      │ (50+ files) │      │ (PS/Py/JS/Bash) │
   └───────────┘      └─────────────┘      └─────────────┘
         │                    │                    │
   ┌─────▼─────┐      ┌──────▼──────┐      ┌──────▼──────┐
   │  MCP       │      │  Hooks      │      │  Memory     │
   │ (10 srv)   │      │ (6 files)   │      │  + Storage  │
   └───────────┘      └─────────────┘      └─────────────┘
```

### Format Breakdown

| Format | Role | Consumption Mode | Count |
|--------|------|-----------------|-------|
| `agents/*.md` | Agent instructions | Loaded on agent invocation | 17 |
| `rules/*.md` | Behavioral guardrails | Always-active at session start | 14 |
| `skills/*.md` | Skill definitions | Loaded on `/skill` invocation | 50+ |
| `security-arsenal/*.md` | Reference payloads/bypasses | Looked up when needed | 8 |
| `tools/*` | Executable code | Called by agents | 30+ files |
| `mcp/*/server.py` | JSON-RPC 2.0 services | stdio-based, AI-initiated | 10 |
| `hooks/*.json` | Session lifecycle events | Auto-fire by event | 6 |
| `memory/*.md` | Persistent AI memory | Hydrated per session | 4 |
| `storage/*.md` | Data schemas | Template + data | 5 |

---

## Quick Start

### 1. Install

```powershell
# Windows
.\install.ps1
```

```bash
# Linux / macOS / WSL
chmod +x install.sh
./install.sh
```

### 2. Load the Agent Registry

```powershell
# OpenCode loads AGENTS.md automatically
# For manual reference:
type AGENTS.md
```

### 3. Run Recon

```powershell
# Invoke the recon agent:
# "Run recon on target.com"
# This loads recon-agent.md → dispatches recon-toolkit → saves to storage/
```

```powershell
# Or use the CLI directly:
.\tools\powershell\jiggy.ps1 recon target.com
```

### 4. Hunt

```powershell
# "Hunt target.com for high vulnerabilities"
# p1-warrior cycles through: IDOR → SSRF → XSS → auth bypass → business logic
```

### 5. Report

```powershell
# "Write report for this finding"
# report-writer generates H1/Bugcrowd/Immunefi format with CVSS 4.0
```

---

## Installation Options

### OpenCode
`opencode.json` and `AGENTS.md` are read automatically. Agents are pre-registered.

### Claude Code
```bash
cp .claude/settings.json ~/.claude/settings.json
```

### Codex CLI / Cursor / Windsurf
The adapters directory contains manifests for each platform:
```
adapters/manifest.json          # Master manifest (18+ targets)
adapters/opencode.jsonc         # OpenCode-specific config
adapters/cursor.json            # Cursor rules
adapters/windsurf.json          # Windsurf rules
```

---

## Key Features

### Cross-Platform Tools
Every PowerShell tool has a Bash equivalent in `tools/bash/`. Same capabilities, same interface, different shell.

### Language-Agnostic Architecture
Tools are written in the best language for the job — PowerShell for Windows-native, Python for cross-platform, JavaScript for browser analysis. The agent layer abstracts the language choice.

### MCP Protocol Compliance
Shared MCP protocol library (`mcp/mcp_lib.py`) with standard error codes, request/notification separation, progress notifications, resource subscriptions, and completion support.

### 46/46 Tests Passing
- Jest tests for JS tools (`helpers/browser-mock.js`)
- Pytest tests for Python modules (`tools/python/tests/`)
- CI pipeline in `.github/workflows/ci.yml`

### Session Hydration
- `--in-place` flag for writing back to template files
- Per-folder scripts: `storage/hydrate.py`, `memory/hydrate.py`

### Validation Gates
Every finding passes the "7-Question Gate" and "4 pre-submission gates" before a single word of the report is written. Weak findings are killed fast.

---

## Project Structure

```
Hercules-Hunt/
├── soul.md                    # Hunter philosophy (377 lines)
├── purpose.md                 # Mission statement (355 lines)
├── goal.md                    # 10 tiered goals (377 lines)
├── scope.md                   # Scope parsing template (365 lines)
├── ENGAGEMENT.md              # Engagement workflow (413 lines)
├── Hercules.md                # Full directory catalog
├── AGENTS.md                  # Agent registry (17 agents)
├── SKILL.md                   # Skill registry (50+ skills)
├── project-review.md          # Self-review and roadmap
├── requirements.txt           # Python dependencies
│
├── agents/          (17)      # AI agent definitions
├── rules/           (14)      # Behavioral guardrails
├── skills/          (50+)     # Skill workflows
│
├── tools/
│   ├── python/     (18 files) # Cross-platform hunting modules
│   ├── powershell/ (7 files)  # Windows-native tools
│   ├── javascript/ (17 files) # Browser DevTools snippets
│   ├── bash/       (7 files)  # Linux/macOS equivalents
│   └── helpers/               # Test mocks
│
├── mcp/            (10)       # MCP servers (JSON-RPC 2.0)
├── hooks/          (6)        # Session lifecycle hooks
│
├── memory/         (4)        # Persistent AI memory
├── storage/        (5)        # Data schemas
├── context/                   # Session context
├── config/                    # Hunter configuration
│
├── report-writing/            # H1/Bugcrowd/Immunefi templates
├── triage-validation/         # 7-Question Gate, validation methodology
├── security-arsenal/          # Payloads, bypass tables, wordlists
├── recon/                     # Reconnaissance methodology
│
├── adapters/                  # Cross-CLI manifests (18+ targets)
├── scripts/                   # Installers, utility scripts
│
├── install.ps1                # Windows installer
├── install.sh                 # Linux/macOS installer
├── hunt.sh                    # Hercules-Hunt engagement launcher
├── install-community-skills.sh # Community skill installer
│
├── .github/workflows/ci.yml   # CI pipeline
├── .gitignore
└── README.md                  # This file
```

---

## The Feedback Loop

Every session improves the system:

```
Hunt → Discover → Capture → Refine → Hunt (improved)
```

1. **Hunt** — use agents, rules, and tools to test a target
2. **Discover** — find a bug, a technique, a dead end, or a process improvement
3. **Capture** — document in technique library, memory, or rules
4. **Refine** — update agents, rules, or tools based on what you learned
5. **Hunt (improved)** — next session starts from a higher baseline

---

## The North Star

> **"Can an attacker do this RIGHT NOW against a real user who has taken NO unusual actions — and does it cause real harm?"**

This is the only question that matters. Everything else — the agents, the rules, the tools, the checklists — exists to help you answer this question faster and more accurately.

---

## Development

### Prerequisites
- Python 3.8+ (`pip install -r requirements.txt`)
- Node.js 18+ (for JS tests)
- PowerShell 5.1+ (for Windows tools)
- Bash 4+ (for Linux/macOS tools)

### Running Tests
```bash
# JS tests (46/46)
npx jest

# Python tests
cd tools/python && python -m pytest tests/

# Python syntax check
python -m py_compile tools/python/*.py

# PowerShell syntax check
powershell -Command "Get-ChildItem tools/powershell/*.ps1 | ForEach-Object { \$null = [System.Management.Automation.Language.Parser]::ParseFile(\$_.FullName, [ref]\$null, [ref]\$null) }"
```

### CI Pipeline
`.github/workflows/ci.yml` runs on push to main:
- Python syntax check
- PowerShell syntax check  
- Jest tests (JS)
- Pytest (Python)
- JSON validation (hooks/)

---

## License

MIT
