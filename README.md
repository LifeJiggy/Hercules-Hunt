# Hercules-Hunt

**An operating system for AI-augmented bug bounty hunting.**

Not a tool. Not a scanner. A **hunter's operating system** — 300+ files, 44 directories, ~230K lines across Python, JavaScript, PowerShell, Bash, MCP, and 1,800+ pages of markdown methodology. Designed to work with OpenCode, Claude Code, Codex CLI, Cursor, and any agentic coding CLI.

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

### 40 AI Agents

Every agent is a complete, self-contained workflow — invoke it and the AI knows exactly what to do:

| Agent | Role | File |
|---|---|---|
| **recon-agent** | Subdomain enumeration, live host discovery, tech fingerprinting | [`agents/recon-agent.md`](agents/recon-agent.md) |
| **recon-ranker** | Attack surface prioritization by IDOR likelihood, API surface, tech stack | [`agents/recon-ranker.md`](agents/recon-ranker.md) |
| **p1-warrior** | Systematic P1 hunting — delegates to 10 specialist sub-agents | [`agents/p1-warrior.md`](agents/p1-warrior.md) |
| **chain-builder** | Exploit chain builder — finds B and C for every A | [`agents/chain-builder.md`](agents/chain-builder.md) |
| **chain-validator** | Validates exploit chains are independently reproducible | [`agents/chain-validator.md`](agents/chain-validator.md) |
| **p1-validator** | Pre-flight validation before reaching primary validator | [`agents/p1-validator.md`](agents/p1-validator.md) |
| **scope-enforcer** | Checks findings against program scope before hunting begins | [`agents/scope-enforcer.md`](agents/scope-enforcer.md) |
| **target-onboarding** | Gathers initial intelligence on new targets | [`agents/target-onboarding-agent.md`](agents/target-onboarding-agent.md) |
| **triage-readiness** | Reviews evidence and PoC reproducibility before submission | [`agents/triage-readiness.md`](agents/triage-readiness.md) |
| **js-analysis** | Extracts endpoints, secrets, cloud keys from JS bundles | [`agents/js-analysis.md`](agents/js-analysis.md) |
| **js-deobfuscation** | Reverses webpack bundles, eval-based obfuscation | [`agents/js-deobfuscation.md`](agents/js-deobfuscation.md) |
| **report-writer** | H1/Bugcrowd/Intigriti/Immunefi reports with CVSS scoring | [`agents/report-writer.md`](agents/report-writer.md) |
| **validator** | 7-Question Gate + 4-gate checklist — kills weak findings fast | [`agents/validator.md`](agents/validator.md) |
| **autopilot** | Autonomous end-to-end hunt loop with checkpoints | [`agents/autopilot.md`](agents/autopilot.md) |
| **orchestrator** | Recon-to-report pipeline orchestrator | [`agents/orchestrator.md`](agents/orchestrator.md) |
| **browser-automator** | Playwright-based browser automation for complex flows | [`agents/browser-automator.md`](agents/browser-automator.md) |
| **exploit-researcher** | CVE research, PoC matching, exploit development | [`agents/exploit-researcher.md`](agents/exploit-researcher.md) |
| **network-analyst** | Packet inspection, protocol dissection, IDS rules | [`agents/network-analyst.md`](agents/network-analyst.md) |
| **redteam-planner** | Engagement design, C2, MITRE ATT&CK mapped | [`agents/redteam-planner.md`](agents/redteam-planner.md) |
| **reverse-engineer** | Binary analysis, firmware RE, Frida instrumentation | [`agents/reverse-engineer.md`](agents/reverse-engineer.md) |
| **security-reviewer** | Source code audit against OWASP Top 10 + CWE Top 25 | [`agents/security-reviewer.md`](agents/security-reviewer.md) |
| **ai-researcher** | LLM red-teaming, prompt injection, jailbreak techniques | [`agents/ai-researcher.md`](agents/ai-researcher.md) |
| **token-auditor** | Meme coin/token security — honeypot, rug pull, LP drain | [`agents/token-auditor.md`](agents/token-auditor.md) |
| **web3-auditor** | Smart contract audit — 10 DeFi bug classes | [`agents/web3-auditor.md`](agents/web3-auditor.md) |
| **mobile-testing-agent** | APK/iOS acquisition, decompilation, Frida instrumentation | [`agents/mobile-testing-agent.md`](agents/mobile-testing-agent.md) |
| **windows-workflow-agent** | Windows-native hunting with curl.exe, PowerShell, WSL | [`agents/windows-workflow-agent.md`](agents/windows-workflow-agent.md) |
| **chain-rules-agent** | Chain philosophy and primitive taxonomy | [`agents/chain-rules-agent.md`](agents/chain-rules-agent.md) |
| **+ 10 specialist sub-agents** | IDOR, SSRF, XSS, auth-bypass, race-condition, business-logic, file-upload, api-misconfig, graphql, ssti | `agents/*-hunter.md` |
| **+ 3 post-hunt agents** | program-researcher, evidence-reviewer, triage-defender | `agents/*.md` |

### 13 Behavioral Rules

Rules are the AI's guardrails — always-active constraints loaded at session start:

`rules/hunting.md` · `rules/reporting.md` · `rules/scope.md` · `rules/recon.md` · `rules/chain-rules.md` · `rules/evidence.md` · `rules/mindset.md` · `rules/js-analysis.md` · `rules/js-deobfuscation.md` · `rules/auth-testing.md` · `rules/api-testing.md` · `rules/mobile-testing.md` · `rules/windows-workflow.md`

### 89 Executable Tools (4 Languages × 10 Standard + Legacy)

10 standardized tools across all 4 runtimes plus legacy toolkit scripts:

**Standard Tools (10 × 4 = 40 files):**

| Tool | Python | JS | PS | Bash | Purpose |
|------|--------|-----|-----|-------|---------|
| extract-apis | 889 | 741 | 1,058 | 702 | API endpoint discovery |
| extract-js | 902 | 743 | 948 | 633 | JS extraction & secret scanning |
| deep-hunt | 1,106 | 722 | 1,089 | 620 | Multi-pass systematic hunting |
| fast-hunt | 999 | 597 | 815 | 606 | Quick surface probes |
| https-probing | 1,129 | 676 | 831 | 599 | TLS/cert/header analysis |
| extract-parameters | 1,303 | 666 | 1,007 | 708 | Parameter extraction |
| extract-functionalities | 1,578 | 1,063 | 1,286 | 686 | User function mapping |
| endpoint-fuzzer | 1,503 | 695 | 929 | 589 | Path/method/extension fuzzing |
| auth-tester | 1,649 | 930 | 1,275 | 578 | Auth bypass & session testing |
| report-builder | 1,520 | 848 | 1,498 | 633 | CVSS 3.1 report generation |

**Legacy Tools:** `curl-hunter`, `recon-toolkit`, `fuzzer-toolkit`, `js-analyzer`, `evidence-toolkit`, `powershell-lib`, `jiggy` (PS + Bash), `python-hunter.py`

**Index/loaders:** `tools/bash/index.sh`, `tools/powershell/index.ps1`, `tools/javascript/index.js`, `tools/python/__init__.py`

### 20 MCP Servers

MCP (Model Context Protocol) servers bridge the AI with external services over JSON-RPC 2.0:

`recon-mcp` · `dns-recon-mcp` · `url-crawl-mcp` · `payload-mcp` · `interactsh-mcp` · `report-mcp` · `hercules-hunt-mcp` · `hackerone-mcp` · `burp-mcp-client` · `caido-mcp-client` · `js-analysis-mcp` · `deep-hunt-mcp` · `fast-hunt-mcp` · `orchestrator-mcp` · `batch-mcp` · `hydration-mcp` · `auth-tester-mcp` · `https-mcp` · `evidence-mcp` · `validation-mcp`

### 8 Shared Python Utilities (utils/)

Zero-dependency utility library shared by all modules: `file_utils.py` · `network_utils.py` · `crypto_utils.py` · `logging_utils.py` · `validation_utils.py` · `config_utils.py` · `date_utils.py` · `report_utils.py`

### 50+ Skills & 15 Hydrate Scripts

Methodology for every bug class, loaded on-demand. Hydration scripts (`hydrate.py`) in every module folder auto-discover all `.md` files.

### Session Lifecycle Hooks

Hooks fire at key session events. 6 JSON files: `hooks.json`, `autopilot-hooks.json`, `chain-builder-hooks.json`, `js-analysis-hooks.json`, `recon-ranker-hooks.json`, `security-reviewer-hooks.json`.

### Memory & Context System

Persistent session memory across `memory/` (7 files), `storage/` (10 files), `context/` (7 files), and `task-presistence/` (9 files).

---

## Architecture

```
                     ┌─────────────────┐
                     │   Hunter (You)    │
                     └────────┬────────┘
                              │
                    ┌─────────▼─────────┐
                    │   AI Agent Layer   │
                    │   (40 agents)      │
                    └─────────┬─────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
   ┌─────▼─────┐      ┌──────▼──────┐      ┌──────▼──────┐
   │  Rules     │      │  Skills     │      │  Tools      │
   │ (13 files) │      │ (50+ files) │      │ (89 files)  │
   └───────────┘      └─────────────┘      └─────────────┘
         │                    │                    │
   ┌─────▼─────┐      ┌──────▼──────┐      ┌──────▼──────┐
   │  MCP       │      │  Hooks      │      │  Memory     │
   │ (20 srv)   │      │ (6 files)   │      │  + Storage  │
   └───────────┘      └─────────────┘      └─────────────┘
```

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
# OpenCode loads AGENTS.md automatically (40 agents)
```

### 3. Run Recon

```powershell
# Invoke the recon agent:
# "Run recon on target.com"
```

```powershell
# Or use the CLI directly:
.\tools\powershell\jiggy.ps1 recon target.com
```

### 4. Hunt

```powershell
# "Hunt target.com for high vulnerabilities"
# p1-warrior cycles through 10 bug classes
```

### 5. Report

```powershell
# "Write report for this finding"
# report-writer generates H1/Bugcrowd/Immunefi format with CVSS
```

---

## Key Features

### Cross-Platform 4-Language Tools
Every standard tool exists in Python, JavaScript, PowerShell, and Bash — same capabilities, same interface, different runtime.

### 166 Passing Tests
- 46 Jest tests for JS tools
- 120 pytest tests for 15 Python modules
- CI pipeline: Python syntax → pytest → Jest → Shellcheck → PS syntax

### Security-First Design
- SSL verification enabled by default (`--allow-insecure` to override)
- Path traversal protection on all `--output` parameters
- Input size limits (8K URLs, 10MB files)
- Subprocess call safety with argument arrays

### Validation Gates
Every finding passes "7-Question Gate" + "4 pre-submission gates" before a word of the report is written.

---

## Project Structure

```
Hercules-Hunt/
├── soul.md · purpose.md · goal.md     # Philosophy docs
├── scope.md · ENGAGEMENT.md           # Workflow templates
├── AGENTS.md                  (40)    # Agent registry
├── SKILL.md · hydrate.py              # Skill + hydration
├── plugin.json · opencode.json.bak    # Plugin configs
├── project-review.md                  # Self-review
├── requirements.txt                   # Python deps
│
├── agents/                  (40)      # AI agent definitions
├── rules/                   (13)      # Behavioral guardrails
├── bug-bounty/              (9)       # Skill definitions
├── security-arsenal/        (15)      # Payloads, bypasses
├── recon/                   (10)      # Recon methodology
├── report-writing/          (5)       # Platform templates
├── triage-validation/       (7)       # Finding validation
├── tasks/                   (14)      # Task blueprints
├── task-presistence/        (9)       # Session continuity
├── context/                 (7)       # Session context
├── memory/                  (7)       # Persistent memory
├── storage/                 (10)      # Data schemas
│
├── tools/
│   ├── python/     (27 files, 19.8K)  # Cross-platform
│   ├── javascript/ (27 files, 12.9K)  # Browser + Node.js
│   ├── powershell/ (18 files, 22.8K)  # Windows-native
│   ├── bash/       (19 files, 7.7K)   # Linux/macOS
│   └── helpers/                        # Test mocks
│
├── utils/                   (8)       # Shared Python lib
├── mcp/                    (20)       # MCP servers
├── hooks/                   (6)       # Session hooks
├── config/                  (7)       # JSON configs
├── adapters/                           # Cross-CLI manifests
├── scripts/                            # Installers
│
├── .github/workflows/ci.yml           # CI pipeline
└── README.md                           # This file
```

---

## The Feedback Loop

```
Hunt → Discover → Capture → Refine → Hunt (improved)
```

---

## The North Star

> **"Can an attacker do this RIGHT NOW against a real user who has taken NO unusual actions — and does it cause real harm?"**

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

# Python tests (166/166)
python -m pytest tools/python/tests/

# Python syntax check
python -m py_compile tools/python/*.py
```

### CI Pipeline
`.github/workflows/ci.yml` (11 steps): Python syntax → pytest → npm ci → Jest → JS require check → Shellcheck → PowerShell syntax

---

## License

MIT
