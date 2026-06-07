# Hercules-Hunt — AI-Powered Bug Bounty Framework

A comprehensive, agent-powered bug bounty hunting system compatible with **OpenCode**, **Claude Code**, **Codex CLI**, and any agentic coding CLI. Built from real bug bounty methodology — recon, hunting, chaining, validation, and reporting.

## Quick Start

```powershell
# Load the toolkit
. .\tools\powershell\powershell-lib.ps1
. .\tools\powershell\curl-hunter.ps1

# Full recon pipeline
.\tools\powershell\recon-toolkit.ps1
Invoke-ReconPipeline -Domain target.com

# Hunt endpoints
Test-Endpoint -Url "https://target.com/api/test"
ParameterFuzz -Url "https://target.com/api/endpoint" -Param "id"

# JS analysis
.\tools\powershell\js-analyzer.ps1
Invoke-FullJsScan -BundlePath "bundle.js"

# Python tools
python .\tools\python\python-hunter.py scan --file bundle.js
```

```powershell
# CLI one-liners
.\tools\powershell\jiggy.ps1 recon target.com
.\tools\powershell\jiggy.ps1 idor https://target.com/api/users/{id} -s 1 -e 100
.\tools\powershell\jiggy.ps1 fuzz https://target.com/api/endpoint
.\tools\powershell\jiggy.ps1 js bundle.js
```

## AI Agents (17)

| Agent | Role | Invoke |
|-------|------|--------|
| **recon-agent** | Subdomain enumeration, live host discovery, fingerprinting | "Run recon on target.com" |
| **recon-ranker** | Attack surface ranking & prioritization | "Rank attack surface for target.com" |
| **p1-warrior** | Systematic P1 bug hunting (IDOR, SSRF, XSS, auth bypass) | "Hunt target.com for high bugs" |
| **chain-builder** | Exploit chain construction (A→B→Critical) | "Chain IDOR with auth bypass" |
| **js-analysis** | JS bundle endpoint/secret extraction | "Analyze JS bundles for target.com" |
| **js-deobfuscation** | Reverse minified/obfuscated bundles | "Deobfuscate this JS bundle" |
| **report-writer** | Professional H1/Bugcrowd/Immunefi reports | "Write report for IDOR finding" |
| **validator** | Finding validation (7-Question Gate, 4-gate checklist) | "Validate this finding" |
| **autopilot** | Autonomous end-to-end hunt loop | "Run autopilot on target.com" |
| **exploit-researcher** | CVE research, exploit PoC mapping | "Research CVEs for nginx 1.24" |
| **network-analyst** | Deep packet inspection, protocol analysis | "Analyze this PCAP" |
| **redteam-planner** | Attack path design, C2, persistence, MITRE ATT&CK | "Plan red team engagement" |
| **reverse-engineer** | Binary analysis, firmware RE, protocol RE | "Analyze this binary" |
| **security-reviewer** | Source code audit (OWASP Top 10, CWE Top 25) | "Review this code" |
| **ai-researcher** | LLM red-teaming, prompt injection, jailbreaks | "Test this LLM endpoint" |
| **token-auditor** | Meme coin/token security (honeypot, rug pull, LP) | "Audit this meme coin" |
| **web3-auditor** | Smart contract audit (10 bug classes) | "Audit this smart contract" |

## Behavioral Rules (13)

Rules provide guardrails for consistent, disciplined hunting:

| Rule | Purpose |
|------|---------|
| `scope` | Scope boundaries, wildcard discipline, safe harbor |
| `evidence` | PoC standards, cookie redaction, PII masking, HAR sanitization |
| `chaining` | A→B→C chain construction, primitive tracking |
| `auth-testing` | Auth flow methodology, OAuth/MFA patterns |
| `api-testing` | Mass assignment, JWT, prototype pollution, CORS |
| `mobile` | Android/iOS APK analysis, Frida, intent injection |
| `windows` | PowerShell-first workflow, Obsidian integration |
| + 6 additional specialized rules | |

## Executable Tools (8)

| Tool | Description |
|------|-------------|
| `powershell-lib.ps1` | 70+ helper functions for recon and hunting |
| `curl-hunter.ps1` | 15 curl-based endpoint testing functions |
| `recon-toolkit.ps1` | Automated recon pipeline (subfinder, httpx, wayback) |
| `fuzzer-toolkit.ps1` | Parameter fuzzing, wordlist-driven discovery |
| `js-analyzer.ps1` | Secret/URL/endpoint extraction from JS bundles |
| `python-hunter.py` | Cross-platform Python scanner with secret patterns |
| `evidence-toolkit.ps1` | Evidence capture, HAR sanitization, screenshot |
| `obsidian-sync.ps1` | Obsidian vault synchronization |

## Skill Library (50+ Skills)

Deep methodology for every bug class — IDOR, SSRF, XSS, SQLi, auth bypass, race condition, file upload, GraphQL, HTTP smuggling, cache poisoning, OAuth, SAML, SSTI, JWT, prototype pollution, subdomain takeover, cloud misconfig, ATO chains, MFA bypass, LLM/AI injection, and more. Loaded on-demand during hunting sessions.

## Memory & Context System

- **`memory/target-registry.md`** — Target-level persistence (findings, notes, accounts)
- **`memory/lessons-log.md`** — Cross-session lessons learned
- **`memory/technique-library.md`** — Accumulated technique catalog
- **`context/active-target.md`** — Current target attack surface
- **`context/hunt-session.md`** — Live session tracking (1200+ line template)
- **`context/chain-primitives.md`** — Chain primitive catalog

## Structure

```
Hercules-Hunt/
├── Hercules.md            # Universal AI context
├── AGENTS.md              # Agent registry (17 agents)
├── opencode.json          # OpenCode configuration
├── plugin.json            # Plugin manifest
├── SKILL.md               # Skill registry
├── install.ps1            # Windows installer
├── agents/       (17)     # AI agent definitions
├── rules/        (13)     # Behavioral guardrails
├── tools/        (8)      # Executable hunting tools
├── skills/                # Skill definitions (50+)
├── memory/                # Persistent target memory
├── context/               # Live session context
├── wordlists/             # Fuzzing/brute-force wordlists
├── hooks/                 # Session lifecycle hooks
├── config/                # Configuration files
├── adapters/              # MCP/API adapters
├── mcp/                   # MCP client configs (Burp, Caido)
├── report-writing/        # Report templates & references
├── security-arsenal/      # Payloads & bypass tables
├── triage-validation/     # Scope & validation gate docs
├── bug-bounty/            # Methodology references
├── scripts/               # Utility scripts
├── storage/               # Session storage
├── task-presitence/       # Task persistence
└── tasks/                 # Task definitions
```

## Platform Setup

### OpenCode
```bash
opencode reads opencode.json and AGENTS.md automatically
Agents are pre-registered in AGENTS.md
```

### Claude Code
```bash
cp .claude/settings.json ~/.claude/settings.json
```

### Install
```powershell
.\install.ps1
```

## License

MIT
