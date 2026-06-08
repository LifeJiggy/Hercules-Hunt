# Hercules-Hunt — Full Engagement Walkthrough

## PROMPT — Full Engagement Task

**Date:** June 2026  
**Toolset:** curl.exe, PowerShell, Python, `C:\Users\ADMIN\Python_Project\Prompt_AI-Support\Jiggy-2026` known as Hercules-Hunt  
**Workspace:** `C:\Users\ADMIN\Python_Project\Prompt_AI-Support\Jiggy-2026`

```
Target: [INSERT TARGET DOMAIN]
Scope: [wildcard/*.target.com / specific subdomains / mobile app / API]
Auth: [test credentials / account type / MFA status]
Rules: [automated scanning allowed? / rate limits / testing window]
Goal: [full recon / specific bug class / ATO / RCE / chain]
```

Start by reading `AGENTS.md` for the agent registry, then read the relevant agent files. Follow the pipeline:

```
program-researcher → recon-agent → recon-ranker → p1-warrior
  → chain-builder → validator → evidence-reviewer → report-writer → triage-defender
```

---

## System Walkflow

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Hercules-Hunt System                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  PHILOSOPHY LAYER     soul.md / purpose.md / goal.md / scope.md     │
│  WHY we hunt — craftsman mindset, mission, objectives, rules        │
│                                                                     │
│  METHODOLOGY LAYER    rules/ (13 files) + agents/ (35 agents)       │
│  HOW we test — per-class methodology, agent-driven execution        │
│                                                                     │
│  REFERENCE LAYER      security-arsenal/ + recon/ + report-writing/  │
│  WHAT we use — payloads, bypasses, wordlists, templates             │
│                                                                     │
│  EXECUTION LAYER      tools/ (PS1/PY/JS/SH) + mcp/ (10 servers)    │
│  HOW we run — scripts, APIs, hooks, automation                      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

### The Hunting Pipeline (Agent Flow)

```
┌──────────────┐
│ program-     │  Phase 1: SCOPE RESEARCH
│ researcher   │  Reads program rules, checks disclosed reports,
│              │  fingerprints tech stack, maps attack surface
└──────┬───────┘
       │ target brief with prioritized bug classes
       ▼
┌──────────────┐
│ recon-agent  │  Phase 2: RECONNAISSANCE
│              │  Subdomains, live hosts, URLs, JS endpoints,
│              │  directory fuzzing, tech fingerprints, port scan
└──────┬───────┘
       │ full recon output (asset inventory)
       ▼
┌──────────────┐
│ recon-ranker │  Phase 3: ATTACK SURFACE RANKING
│              │  P1→P3 prioritization by IDOR likelihood, tech stack,
│              │  endpoint type, nuclei findings
└──────┬───────┘
       │ ranked target list with likelihood scores
       ▼
┌──────────────┐
│  p1-warrior  │  Phase 4: HUNTING
│              │  Reads ranked targets, selects top 3 bug classes
│              │  by tech stack, DISPATCHES specialist sub-agents:
│              │
│    ├── idor-hunter           (numeric/UUID/base64 identifiers)
│    ├── ssrf-hunter           (URL fetch, cloud metadata, callbacks)
│    ├── xss-hunter            (reflected/stored/DOM/blind)
│    ├── auth-bypass-hunter    (login, MFA, JWT, OAuth, SAML)
│    ├── race-condition-hunter (TOCTOU, parallel requests)
│    ├── business-logic-hunter (workflow, pricing, referrals)
│    ├── file-upload-hunter    (RCE, XSS, XXE via uploads)
│    ├── api-misconfig-hunter  (mass assignment, JWT, CORS)
│    ├── graphql-hunter        (introspection, batching, GQL IDOR)
│    └── ssti-hunter           (template injection → RCE)
│              │
│  Each sub-agent time-boxed to 10 minutes. Findings → pending dir.
└──────┬───────┘
       │ findings with curl commands + response excerpts
       ▼
┌──────────────┐
│ chain-builder│  Phase 5: EXPLOIT CHAINING
│              │  Takes finding A, systematically finds B and C.
│              │  IDOR→auth bypass, SSRF→cloud metadata, XSS→ATO
└──────┬───────┘
       │ chained exploits with severity multiplication
       ▼
┌──────────────┐
│   validator  │  Phase 6: VALIDATION
│              │  7-Question Gate + 4-gate checklist.
│              │  PASS / KILL / DOWNGRADE / CHAIN-REQUIRED
└──────┬───────┘
       │ validated findings only
       ▼
┌──────────────┐
│ evidence-    │  Phase 7: EVIDENCE REVIEW
│ reviewer     │  Cookie/PII redaction, HAR sanitization,
│              │  screenshot hygiene, reproducibility check
└──────┬───────┘
       │ clean evidence packages
       ▼
┌──────────────┐
│  triage-     │  Phase 8: DEFENSE
│  defender    │  Anticipates triager objections, prepares OOS
│              │  rebuttals, severity counters, VRT mapping
└──────┬───────┘
       │ defense-ready report
       ▼
┌──────────────┐
│ report-      │  Phase 9: REPORT WRITING
│ writer       │  H1/Bugcrowd/Intigriti/Immunefi format.
│              │  Impact-first, CVSS 4.0, no theoretical language
└──────────────┘
       │ SUBMISSION-READY REPORT 🎯
```

---

### Agent Invocation Reference

```
ORCHESTRATOR (full pipeline):
  orchestrator — "Run full pipeline on target.com"

RECON:
  recon-agent     — "Run recon on target.com"
  recon-ranker    — "Rank attack surface for target.com"

RESEARCH:
  program-researcher — "Research target.com program"

HUNT SUB-AGENTS:
  idor-hunter           — "Hunt IDOR on target.com"
  ssrf-hunter           — "Hunt SSRF on target.com"
  xss-hunter            — "Hunt XSS on target.com"
  auth-bypass-hunter    — "Hunt auth bypass on target.com"
  race-condition-hunter — "Hunt race conditions on target.com"
  business-logic-hunter — "Hunt business logic flaws on target.com"
  file-upload-hunter    — "Hunt file upload bugs on target.com"
  api-misconfig-hunter  — "Hunt API misconfigs on target.com"
  graphql-hunter        — "Hunt GraphQL bugs on target.com"
  ssti-hunter           — "Hunt SSTI on target.com"

HUNT COORDINATOR:
  p1-warrior — "Hunt target.com for high vulnerabilities"

CHAIN:
  chain-builder    — "Chain IDOR with auth bypass for higher severity"
  chain-rules-agent — "Analyze chain primitives for these findings"

VALIDATE:
  validator — "Validate this IDOR finding before I write a report"

EVIDENCE:
  evidence-reviewer — "Review evidence for target.com finding"

DEFENSE:
  triage-defender — "Defend target.com finding against triage"

REPORT:
  report-writer — "Write report for IDOR finding on target.com"

AUTOMATION:
  autopilot — "Run autopilot on target.com in normal mode"
  browser-automator — "Automate browser for target.com login"

PLATFORM:
  mobile-testing-agent   — "Test the mobile app for target.com"
  windows-workflow-agent — "Run Windows recon workflow for target.com"

INFRASTRUCTURE:
  exploit-researcher — "Research CVEs for nginx 1.24"
  network-analyst    — "Analyze this packet capture for anomalies"
  security-reviewer  — "Review this code for security vulnerabilities"
  redteam-planner   — "Plan red team engagement for target company"
  reverse-engineer  — "Analyze this binary for vulnerabilities"
  ai-researcher     — "Test this LLM endpoint for prompt injection"

WEB3:
  token-auditor — "Audit this meme coin for rug pull vectors"
  web3-auditor  — "Audit this smart contract for vulnerabilities"

ANALYSIS:
  js-analysis       — "Analyze JS bundles for secrets on target.com"
  js-deobfuscation  — "Deobfuscate this JavaScript bundle"
```

---

### Key Directory Map

```
C:\Users\ADMIN\Python_Project\Prompt_AI-Support\Jiggy-2026\
│
├── AGENTS.md                    # Agent registry (all 35 agents)
├── AGENTS_CHANGELOG.md          # v2.0 upgrade changelog
├── ENGAGEMENT.md                # Per-target engagement template
├── README.md                    # Quick-start guide
├── Hercules.md                  # Universal system reference
├── SKILL.md                     # Master bug-bounty skill (1223 lines)
│
├── agents/                      # 35 agent definitions (.md files)
│   ├── recon-agent.md
│   ├── p1-warrior.md
│   ├── idor-hunter.md
│   ├── ssrf-hunter.md
│   ├── xss-hunter.md
│   ├── auth-bypass-hunter.md
│   ├── race-condition-hunter.md
│   ├── business-logic-hunter.md
│   ├── file-upload-hunter.md
│   ├── api-misconfig-hunter.md
│   ├── graphql-hunter.md
│   ├── ssti-hunter.md
│   ├── chain-builder.md
│   ├── chain-rules-agent.md
│   ├── validator.md
│   ├── report-writer.md
│   ├── evidence-reviewer.md
│   ├── triage-defender.md
│   ├── program-researcher.md
│   ├── browser-automator.md
│   ├── orchestrator.md
│   ├── autopilot.md
│   ├── js-analysis.md
│   ├── js-deobfuscation.md
│   ├── exploit-researcher.md
│   ├── network-analyst.md
│   ├── security-reviewer.md
│   ├── redteam-planner.md
│   ├── reverse-engineer.md
│   ├── ai-researcher.md
│   ├── token-auditor.md
│   ├── web3-auditor.md
│   ├── mobile-testing-agent.md
│   ├── windows-workflow-agent.md
│   ├── recon-ranker.md
│
├── rules/                       # 13 always-active guardrails
│   ├── recon.md                 #   (3,363 lines)
│   ├── api-testing.md           #   (2,594 lines)
│   ├── auth-testing.md          #   (2,024 lines)
│   ├── mindset.md               #   (1,995 lines)
│   ├── js-deobfuscation.md      #   (1,835 lines)
│   ├── js-analysis.md           #   (1,624 lines)
│   ├── windows-workflow.md      #   (1,713 lines)
│   ├── mobile-testing.md        #   (1,309 lines)
│   ├── chain-rules.md           #   (1,230 lines)
│   ├── hunting.md
│   ├── reporting.md
│   ├── scope.md
│   └── evidence.md
│
├── tools/                       # 4 language runtimes
│   ├── powershell/
│   │   ├── curl-hunter.ps1      #   (2,275 lines)
│   │   ├── fuzzer-toolkit.ps1   #   (2,071 lines)
│   │   ├── recon-toolkit.ps1
│   │   ├── powershell-lib.ps1
│   │   ├── js-analyzer.ps1
│   │   ├── evidence-toolkit.ps1
│   │   └── jiggy.ps1
│   ├── python/
│   │   ├── rce_hunter.py        # P1 hunter CLI
│   │   ├── sqli_hunter.py       # P1 hunter CLI
│   │   ├── idor_hunter.py       # P1 hunter CLI
│   │   ├── auth_hunter.py       # P1 hunter CLI
│   │   ├── ssrf_hunter.py       # P1 hunter CLI
│   │   ├── xxe_hunter.py        # P1 hunter CLI
│   │   ├── file_upload_hunter.py # P1 hunter CLI
│   │   ├── python-hunter.py     # Orchestrator
│   │   └── ...                  # 10 core modules
│   ├── javascript/
│   │   ├── xss-hunter.js
│   │   ├── prototype-pollution.js
│   │   ├── browser-automation.js
│   │   └── ...                  # 17 JS modules with Jest tests
│   └── bash/
│       ├── curl-hunter.sh
│       ├── recon-toolkit.sh
│       └── ...                  # 7 bash equivalents
│
├── mcp/                         # 10 MCP servers
│   ├── hercules-hunt-mcp/       #   9 tools: all 7 P1 hunters
│   ├── interactsh-mcp/          #   5 tools: OOB callbacks
│   ├── dns-recon-mcp/           #   4 tools: DNS, crt.sh
│   ├── url-crawl-mcp/           #   4 tools: Wayback, CommonCrawl
│   ├── payload-mcp/             #   8 tools: payload generators
│   ├── report-mcp/              #   6 tools: findings CRUD
│   ├── recon-mcp/               #   5 tools: subdomain, probe
│   ├── hackerone-mcp/           #   3 tools: hacktivity, program
│   ├── burp-mcp-client/         #   Burp Suite integration
│   └── caido-mcp-client/        #   Caido proxy integration
│
├── hooks/                       # 6 session hook configs
│   ├── hooks.json               # Master hooks (SessionStart, etc.)
│   ├── autopilot-hooks.json
│   ├── chain-builder-hooks.json
│   ├── js-analysis-hooks.json
│   ├── recon-ranker-hooks.json
│   └── security-reviewer-hooks.json
│
├── config/                      # 7 JSON configurations
│   ├── hunter-config.json
│   ├── tools-config.json
│   ├── targets.json
│   ├── profiles.json
│   ├── notifications.json
│   ├── wordlists.json
│   └── waf-bypass.json
│
├── context/                     # 7 session-level context files
│   ├── active-target.md
│   ├── target-registry.md
│   ├── hunt-session.md
│   ├── chain-primitives.md
│   ├── vuln-class-checklists.md
│   ├── lessons-log.md
│   └── tool-inventory.md
│
├── memory/                      # 8 cross-session memory files
│   ├── universal.md
│   ├── discoveries.md
│   ├── lessons-log.md
│   ├── persistence.md
│   ├── session-state.md
│   ├── target-registry.md
│   ├── technical-notes.md
│   └── hydrate.py
│
├── storage/                     # 11 data schema files
│   ├── universal.md
│   ├── findings-archive.md
│   ├── evidence-packages.md
│   ├── credentials-vault.md
│   ├── tool-outputs.md
│   ├── hunt-logs.md
│   ├── scope-records.md
│   ├── sessions-index.md
│   ├── config-backups.md
│   ├── persistence.md
│   └── hydrate.py
│
├── recon/                       # 10 recon reference files
│   ├── recon-methodology.md
│   ├── recon-arsenal.md
│   ├── recon-chaining.md
│   ├── scope-validator.md
│   ├── output-parser.md
│   ├── windows-recon-workflow.md
│   ├── quick-recon-cheatsheet.md
│   ├── critical-bug-recon.md
│   └── README
│
├── report-writing/              # 5 platform report templates
│   ├── HackerOne.md
│   ├── Bugcrowd.md
│   ├── Intigriti.md
│   └── Immunefi.md
│
├── security-arsenal/            # 15 payload & reference files
│   ├── payload-manager.md
│   ├── bypass-master.md
│   ├── exploitation-guide.md
│   ├── fuzzing-guide.md
│   ├── METHODOLOGY_CHEATSHEET.md
│   └── ... (10 more)
│
├── triage-validation/           # 7 validation gate files
│   ├── SKILL-1.md               # 7-Question Gate (1,321 lines)
│   ├── deduplication-guide.md
│   ├── evidence-hygiene.md
│   ├── false-positive-hunter.md
│   ├── scope-master.md
│   └── severity-calibration.md
│
├── bug-bounty/                  # 9 platform skills
│   ├── SKILL.md                 # Master skill (1,584 lines)
│   ├── P1-Warrior.md
│   ├── autopilot.md
│   └── ... (6 more)
│
├── scripts/                     # Installation & utilities
│   ├── install.ps1
│   ├── install.sh
│   ├── hunt.sh
│   └── jiggy-adapter.py
│
├── task-presistence/            # Cross-session task tracking
│   ├── active-tasks.md
│   ├── continuity-log.md
│   └── session-states.md
│
├── tasks/                       # Task registry
│   ├── hunt-plans.md
│   ├── recon-tasks.md
│   └── validation-tasks.md
│
├── adapters/                    # Cross-CLI adapter layer
│   ├── manifest.json            # 18+ supported CLIs
│   └── targets.md
│
├── plugin.json                  # Plugin manifest (skills, rules, tools)
└── .github/workflows/ci.yml     # CI pipeline (pytest + coverage)
```

---

### Session Workflow (Quick Start)

```
1. START SESSION:
   Read: AGENTS.md → soul.md → scope.md (5 min)

2. RESEARCH TARGET:
   invoke: program-researcher "Research target.com program" (5 min)

3. RUN RECON:
   invoke: recon-agent "Run recon on target.com" (15 min)

4. RANK ATTACK SURFACE:
   invoke: recon-ranker "Rank attack surface for target.com" (2 min)

5. HUNT (based on tech stack):
   invoke: p1-warrior "Hunt target.com for high vulnerabilities" (34 min)
   OR invoke individual sub-agent:
   invoke: idor-hunter "Hunt IDOR on target.com/api/users"

6. CHAIN FINDINGS:
   invoke: chain-builder "Chain findings in findings/pending-validation/"

7. VALIDATE:
   invoke: validator "Validate findings in findings/pending-validation/"

8. REVIEW EVIDENCE:
   invoke: evidence-reviewer "Review evidence for findings"

9. DEFEND:
   invoke: triage-defender "Review draft reports for objections"

10. WRITE REPORT:
    invoke: report-writer "Write report for finding on target.com"

11. SAVE SESSION STATE:
    Update: memory/session-state.md, storage/hunt-logs.md
```

---

### Quick Reference — Important File Paths

| Action | File |
|--------|------|
| Agent registry | `AGENTS.md` |
| Engagement template | `ENGAGEMENT.md` |
| Scope template | `scope.md` |
| Hunter philosophy | `soul.md` |
| Mission & objectives | `purpose.md` + `goal.md` |
| Plugin manifest | `plugin.json` |
| Project review/status | `project-review.md` |
| Change log | `AGENTS_CHANGELOG.md` |
| Active target | `context/active-target.md` |
| Findings archive | `storage/findings-archive.md` |
| Evidence packages | `storage/evidence-packages.md` |
| Credentials | `storage/credentials-vault.md` |
| Session state | `memory/session-state.md` |
| Hunt memory | `memory/universal.md` |
| Discoveries log | `memory/discoveries.md` |
| Active tasks | `task-presistence/active-tasks.md` |
| Continuity log | `task-presistence/continuity-log.md` |
| Hunter config | `config/hunter-config.json` |
| Target registry | `config/targets.json` |
| WAF bypasses | `config/waf-bypass.json` |
| Master cheat sheet | `security-arsenal/METHODOLOGY_CHEATSHEET.md` |
| Payloads catalog | `security-arsenal/payload-manager.md` |
| Bypass techniques | `security-arsenal/bypass-master.md` |
| Reuse attack chains | `security-arsenal/vulnerability-chaining.md` |
| 7-Question Gate | `triage-validation/SKILL-1.md` |
| Severity calibration | `triage-validation/severity-calibration.md` |
| Report templates | `report-writing/HackerOne.md` (et al.) |
| PowerShell toolkit | `tools/powershell/curl-hunter.ps1` |
| Python hunters | `tools/python/` |
| JS browser tools | `tools/javascript/` |
| CI pipeline | `.github/workflows/ci.yml` |

---

### Pipeline Automation (orchestrator)

The orchestrator runs the full 10-phase pipeline automatically:

```
orchestrator "Run full pipeline on target.com"
```

Phases: `SCOPE → RECON → RANK → RESEARCH → HUNT → CHAIN → VALIDATE → REVIEW → DEFEND → REPORT`

Modes:
- `full-auto` — runs everything without stopping
- `checkpoint` — pauses at critical phases for review
- `manual` — runs only when explicitly invoked per phase

Plugin.json skill registration:
```
OpenCode:    plugin.json → 17 skills registered under opencode-bug-bounty
Claude Code: .claude/settings.json → skills configured
Codex CLI:   AGENTS.md → agent definitions loaded
```

---

### Self-Diagnostics

Every agent file includes a `## Self-Diagnostics` section for post-completion validation and a `## Context Optimization` section for tech-stack-aware methodology trimming. Always check these before ending an agent session.
