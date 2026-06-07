# Hercules-Hunt — Bug Bounty Skill System

You are operating inside **Hercules-Hunt**, a comprehensive bug bounty hunting skill system compatible with Claude Code, OpenCode, Codex CLI, and any agentic coding CLI.

## Project Structure

```
Hercules-Hunt/
├── Hercules.md            # This file — universal AI context
├── plugin.json            # Root manifest for all platforms
├── opencode.json          # OpenCode configuration
├── AGENTS.md              # OpenCode agent registry
├── agents/                # 17 AI agent definitions (expanded)
│   ├── recon-agent.md     # Subdomain enumeration & live host discovery
│   ├── recon-ranker.md    # Attack surface ranking & prioritization
│   ├── p1-warrior.md      # Priority-1 systematic bug hunter
│   ├── chain-builder.md   # Exploit chain builder (A→B→C)
│   ├── js-analysis.md     # JS bundle endpoint & secret extraction
│   ├── js-deobfuscation.md# Reverse minified/obfuscated JS
│   ├── report-writer.md   # Professional bug bounty report generator
│   ├── validator.md       # 7-Question Gate finding validator
│   ├── autopilot.md       # Autonomous hunt loop
│   ├── exploit-researcher.md  # CVE & exploit research
│   ├── network-analyst.md     # Packet analysis & protocol inspection
│   ├── redteam-planner.md     # Red team engagement planning
│   ├── reverse-engineer.md    # Binary & firmware analysis
│   ├── security-reviewer.md   # Code & architecture audit
│   ├── ai-researcher.md       # AI/ML security & red teaming
│   ├── token-auditor.md       # Meme coin rug-pull detection
│   └── web3-auditor.md        # Smart contract security audit
├── rules/                # Always-active behavioral guardrails
│   ├── hunting.md        # Hunting methodology & discipline
│   ├── reporting.md      # Report quality & submission rules
│   ├── recon.md          # Reconnaissance discipline
│   ├── scope.md          # Scope management & verification
│   ├── chain-rules.md    # Vulnerability chaining rules
│   ├── evidence.md       # Evidence collection & PoC hygiene
│   ├── mindset.md        # Operator psychology & strategy
│   ├── js-analysis.md    # JavaScript analysis rules
│   ├── js-deobfuscation.md  # JS deobfuscation methodology
│   ├── auth-testing.md   # Authentication bypass testing
│   ├── api-testing.md    # API fuzzing & methodology
│   ├── mobile-testing.md # Mobile app security testing
│   └── windows-workflow.md  # Windows-specific hunting
├── tools/                # Executable hunting tools
│   ├── curl-hunter.ps1   # curl.exe master toolkit (15 functions)
│   ├── js-analyzer.ps1   # JS bundle analysis toolkit
│   ├── powershell-lib.ps1# 70+ PowerShell one-liner library
│   ├── python-hunter.py  # Python hunting toolkit (8 classes)
│   ├── recon-toolkit.ps1 # Recon automation pipeline
│   ├── fuzzer-toolkit.ps1# HTTP fuzzing toolkit
│   └── evidence-toolkit.ps1# Evidence capture & sanitization
├── skills/               # AI skill definitions (Claude Code format)
├── hooks/                # Session lifecycle hooks
├── memory/               # Hunt memory & tracking
├── wordlists/            # Fuzzing wordlists
└── docs/                 # Documentation
```

## Core Principles

1. **Impact-first:** Every bug must prove real-world harm. No theoretical findings.
2. **Validate before writing:** Run the 7-Question Gate before spending time on any finding.
3. **Chain for higher severity:** Single low-severity bugs get chained for critical impact.
4. **Evidence hygiene:** Always capture, redact, and organize evidence as you go.
5. **Scope discipline:** Verify every asset against program scope before testing.
6. **Time-boxed rotation:** 10-20 min per test per endpoint. Rotate if no signal.
7. **Depth over breadth:** One target deeply understood > ten shallowly tested.

## Quick Start

```powershell
# Load tools
. .\tools\powershell\powershell-lib.ps1
. .\tools\powershell\curl-hunter.ps1

# Full recon pipeline
.\tools\powershell\recon-toolkit.ps1
Invoke-ReconPipeline -Domain target.com

# Hunt with curl toolkit
Test-Endpoint -Url "https://target.com/api/endpoint" -Method GET
Test-IdorRange -BaseUrl "https://target.com/api/users/{id}/orders" -Start 1 -End 100

# Fuzz parameters
.\tools\powershell\fuzzer-toolkit.ps1
Invoke-ParameterFuzz -Url "https://target.com/api/endpoint" -Param "id"
```

## Available Agents

| Agent | Purpose | Invoke |
|-------|---------|--------|
| recon-agent | Subdomain enum & surface discovery | "Run recon on target.com" |
| p1-warrior | Systematic priority-1 bug hunting | "Hunt target.com for high bugs" |
| chain-builder | Exploit chain construction | "Chain A with B for critical" |
| js-analysis | JS bundle endpoint/secret extraction | "Analyze JS bundles for secrets" |
| js-deobfuscation | Reverse obfuscated JavaScript | "Deobfuscate this bundle" |
| report-writer | Generate professional reports | "Write report for finding" |
| validator | 7-Question Gate validation | "Validate this finding" |

## Platform Compatibility

- **Claude Code:** Uses `.claude/settings.json`, `hooks/hooks.json`, and `skills/` directory
- **OpenCode:** Uses `opencode.json` and `AGENTS.md` for agent registration
- **Codex CLI:** Uses `Hercules.md` for context and tool definitions
- **Any agentic CLI:** Tools are standalone Python/PowerShell scripts — no AI required

## Safety

- Never test out-of-scope assets
- Never exfiltrate or persist real user data beyond PoC requirements
- Never DoS or social-engineer real employees
- Never auto-submit reports without human approval
- All tools respect rate limiting and safe methods only
