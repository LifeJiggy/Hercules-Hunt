# Hercules-Hunt — AI-Powered Bug Bounty Framework

You are operating inside **Hercules-Hunt**, a comprehensive bug bounty hunting skill system compatible with Claude Code, OpenCode, Codex CLI, Cursor, Continue.dev, and any agentic coding CLI.

## Directory Reference

```
Hercules-Hunt/                         # Root — universal AI context
│
├── Hercules.md                        # THIS FILE — universal reference
├── README.md                          # Quick-start intro
├── plugin.json                        # Plugin manifest for all platforms
├── opencode.json                      # OpenCode configuration
├── AGENTS.md                          # Agent registry (17 agents)
├── SKILL.md                           # Master bug-bounty skill (1584 lines)
├── soul.md                            # Hunter philosophy & spirit
├── purpose.md                         # Mission statement & why
├── goal.md                            # Measurable objectives & North Star
├── project-review.md                  # Project review / retro notes
├── requirements.txt                   # Python dependencies
├── .gitignore                         # Ignores __pycache__, node_modules, output/
│
├── agents/                            # 17 AI agent definitions (one per .md)
│   ├── recon-agent.md                 #   Subdomain enum & surface discovery
│   ├── recon-ranker.md                #   Attack surface ranking & prioritization
│   ├── p1-warrior.md                  #   Priority-1 systematic bug hunter
│   ├── chain-builder.md               #   Exploit chain builder (A→B→C)
│   ├── js-analysis.md                 #   JS bundle endpoint & secret extraction
│   ├── js-deobfuscation.md            #   Reverse minified/obfuscated JS
│   ├── report-writer.md               #   Professional bug bounty report generator
│   ├── validator.md                   #   7-Question Gate finding validator
│   ├── autopilot.md                   #   Autonomous hunt loop
│   ├── exploit-researcher.md          #   CVE & exploit research
│   ├── network-analyst.md             #   Packet analysis & protocol inspection
│   ├── redteam-planner.md             #   Red team engagement planning
│   ├── reverse-engineer.md            #   Binary & firmware analysis
│   ├── security-reviewer.md           #   Code & architecture audit
│   ├── ai-researcher.md               #   AI/ML security & red teaming
│   ├── token-auditor.md               #   Meme coin rug-pull detection
│   ├── web3-auditor.md                #   Smart contract security audit
│   ├── mobile-testing-agent.md        #   Mobile APK/iOS IPA security testing
│   └── windows-workflow-agent.md      #   Windows-native recon & hunting
│
├── rules/                             # Always-active behavioral guardrails
│   ├── hunting.md                     #   Hunting methodology & discipline
│   ├── reporting.md                   #   Report quality & submission rules
│   ├── recon.md                       #   Reconnaissance discipline
│   ├── scope.md                       #   Scope management & verification
│   ├── chain-rules.md                 #   Vulnerability chaining rules
│   ├── evidence.md                    #   Evidence collection & PoC hygiene
│   ├── mindset.md                     #   Operator psychology & strategy
│   ├── js-analysis.md                 #   JavaScript analysis rules
│   ├── js-deobfuscation.md            #   JS deobfuscation methodology
│   ├── auth-testing.md                #   Authentication bypass testing
│   ├── api-testing.md                 #   API fuzzing & methodology
│   ├── mobile-testing.md              #   Mobile app security testing
│   └── windows-workflow.md            #   Windows-specific hunting workflow
│
├── tools/                             # Executable hunting tools
│   ├── powershell/                    #   PowerShell tools (Windows)
│   │   ├── curl-hunter.ps1            #     curl.exe master toolkit (15 functions)
│   │   ├── js-analyzer.ps1            #     JS bundle analysis toolkit
│   │   ├── powershell-lib.ps1         #     70+ one-liner library
│   │   ├── python-hunter.py           #     Python hunting toolkit (8 classes)
│   │   ├── recon-toolkit.ps1          #     Recon automation pipeline
│   │   ├── fuzzer-toolkit.ps1         #     HTTP fuzzing toolkit
│   │   └── evidence-toolkit.ps1       #     Evidence capture & sanitization
│   └── javascript/                    #   JavaScript browser-based tools
│       ├── package.json               #     Node.js dependencies
│       ├── helpers/                   #     Test helpers
│       └── tests/                     #     Jest test suite (46 tests, all passing)
│
├── adapters/                          # Cross-CLI adapter layer
│   ├── manifest.json                  #   Plugin manifest for all CLI targets
│   └── targets.md                     #   18+ supported CLI install targets
│
├── skill/                             # Platform-specific bug bounty skills
│   ├── P1-Warrior.md                  #   Priority-1 systematic bug hunter
│   ├── autopilot.md                   #   Autonomous hunt loop
│   ├── validator.md                   #   Finding validator (7-Question Gate)
│   ├── Js-analysis.md                 #   JS bundle endpoint/secret extraction
│   ├── Js-deobfuscation.md            #   Reverse minified/obfuscated JS
│   ├── token-auditor.md               #   Meme coin/token security audit
│   ├── skill-report-writer.md         #   Professional report writer
│   └── web3-auditor.md                #   Smart contract security audit
│
├── config/                            # JSON configuration files
│   ├── targets.json                   #   Target registry (domains, scope, status)
│   ├── tools-config.json              #   External tool config (Burp, nuclei, etc.)
│   ├── profiles.json                  #   User/agent role profiles
│   ├── notifications.json             #   Webhook & notification settings
│   ├── wordlists.json                 #   Fuzzing wordlist paths & descriptions
│   └── hunter-config.json             #   Rate limits, delays, timeouts
│
├── context/                           # Session-level context files
│   ├── active-target.md               #   Single source of truth for current target
│   ├── target-registry.md             #   All past/current targets
│   ├── hunt-session.md                #   Current session log & plan
│   ├── chain-primitives.md            #   Bug chaining primitives & patterns
│   ├── vuln-class-checklists.md       #   Per-class testing checklists
│   ├── lessons-log.md                 #   Lessons learned archive
│   └── tool-inventory.md              #   Available tool inventory
│
├── doc/                               # Scratch / documentation notes
│   └── file.md                        #   Enhancement notes (async, error handling)
│
├── hooks/                             # Event-driven session hooks
│   ├── hooks.json                     #   Master hooks (Start, Stop, ToolUse)
│   ├── autopilot-hooks.json           #   Autopilot agent hooks
│   ├── chain-builder-hooks.json       #   Chain builder agent hooks
│   ├── js-analysis-hooks.json         #   JS analysis agent hooks
│   ├── recon-ranker-hooks.json        #   Recon ranker agent hooks
│   └── security-reviewer-hooks.json   #   Security reviewer agent hooks
│
├── mcp/                               # MCP (Model Context Protocol) integrations
│   ├── README.md                      #   MCP overview (10 clients)
│   ├── burp-mcp-client/               #   Burp Suite integration
│   ├── caido-mcp-client/              #   Caido proxy integration
│   ├── hackerone-mcp/                 #   HackerOne API integration
│   ├── hercules-hunt-mcp/             #   Hercules-Hunt self-service MCP (9 tools)
│   ├── interactsh-mcp/                #   OOB callback (blind SSRF/XXE/RCE)
│   ├── dns-recon-mcp/                 #   DNS recon (crt.sh, brute-force)
│   ├── recon-mcp/                     #   General recon operations
│   ├── payload-mcp/                   #   Payload delivery & management
│   ├── report-mcp/                    #   Automated report generation
│   └── url-crawl-mcp/                 #   URL crawling & endpoint discovery
│
├── memory/                            # Persistent cross-session memory
│   ├── universal.md                   #   Master memory index (loaded first, updated last)
│   ├── discoveries.md                 #   All discoveries log
│   ├── lessons-log.md                 #   Patterns & lessons learned
│   ├── persistence.md                 #   Persistence state
│   ├── session-state.md               #   Current session snapshot
│   ├── target-registry.md             #   Memory copy of target registry
│   └── technical-notes.md             #   Technical references
│
├── old/                               # Legacy/deprecated skill files
│   ├── recon.md                       #   Original recon methodology
│   ├── api-testing.md                 #   Original API testing guide
│   ├── auth-testing.md                #   Original auth testing guide
│   └── mindset.md                     #   Original mindset document
│
├── recon/                             # Specialized recon skills
│   ├── SKILL.md                       #   Reconnaissance skill definition
│   ├── recon-methodology.md           #   Detailed recon methodology
│   ├── recon-arsenal.md               #   Tool commands & techniques
│   └── README                         #   Recon module intro
│
├── report-writing/                    # Platform-specific report templates
│   ├── SKILL.md                       #   Master report writing skill
│   ├── HackerOne.md                   #   HackerOne template
│   ├── Bugcrowd.md                    #   Bugcrowd template
│   ├── Intigriti.md                   #   Intigriti template
│   └── Immunefi.md                    #   Immunefi template
│
├── scripts/                           # Install & utility scripts
│   ├── install.ps1                    #   Windows installer (PowerShell)
│   ├── install.sh                     #   Linux/macOS installer (bash)
│   ├── install-community-skills.sh    #   Community skill updater
│   ├── hunt.sh                        #   `hunt` shell function for engagements
│   └── jiggy-adapter.py               #   Python CLI adapter
│
├── security-arsenal/                  # Payloads, bypasses, wordlists
│   ├── SKILL.md                       #   Master arsenal (1966 lines)
│   ├── payload-manager.md             #   Payload organization
│   ├── wordlist-manager.md            #   Wordlist management
│   ├── bypass-master.md               #   Comprehensive bypass techniques
│   ├── fuzzing-guide.md               #   Fuzzing methodology
│   ├── exploitation-guide.md          #   Post-finding exploitation
│   ├── js-analysis.md                 #   JS analysis in arsenal context
│   ├── recon-arsenal.md               #   Recon tool commands
│   ├── api-testing-guide.md           #   API payloads & techniques
│   ├── deobfuscation-guide.md         #   Deobfuscation techniques
│   ├── session-security.md            #   Session security testing
│   ├── vulnerability-chaining.md      #   Bug chaining patterns
│   ├── report-writing.md              #   Report writing references
│   ├── METHODOLOGY_CHEATSHEET.md      #   Quick-reference methodology
│   └── REFERENCES.md                  #   External resources
│
├── storage/                           # Universal storage architecture
│   ├── universal.md                   #   Master storage index (686 lines)
│   ├── findings-archive.md            #   All confirmed findings
│   ├── evidence-packages.md           #   Organized evidence per finding
│   ├── credentials-vault.md           #   Test credentials tracking
│   ├── tool-outputs.md                #   Raw external tool outputs
│   ├── hunt-logs.md                   #   Per-session activity logs
│   ├── scope-records.md               #   Scope boundaries & changes
│   ├── sessions-index.md              #   All sessions with timestamps
│   ├── config-backups.md              #   Config file backups
│   └── persistence.md                 #   Storage persistence state
│
├── task-presistence/                  # Cross-session task persistence
│   ├── active-tasks.md                #   Active tasks tracker (480 lines)
│   ├── progress-tracker.md            #   Progress per task
│   ├── continuity-log.md              #   Session handoff continuity
│   ├── session-states.md              #   State snapshots per session
│   └── task-history.md                #   Completed tasks archive
│
├── tasks/                             # Task registry & management
│   ├── task-registry.md               #   Master task registry (399 lines)
│   ├── hunt-plans.md                  #   Defined hunt plans & strategies
│   ├── recon-tasks.md                 #   Recon task definitions
│   ├── validation-tasks.md            #   Validation task definitions
│   └── maintenance-tasks.md           #   System maintenance tasks
│
├── triage-validation/                 # Finding validation gate system
│   ├── SKILL-1.md                     #   7-Question Gate + 4 gates (1321 lines)
│   ├── SKILL-2.md                     #   Supplementary validation rules
│   ├── deduplication-guide.md         #   Duplicate finding identification
│   ├── evidence-hygiene.md            #   PoC capture & redaction standards
│   ├── false-positive-hunter.md       #   False positive techniques
│   ├── scope-master.md                #   Scope boundary enforcement
│   └── severity-calibration.md        #   Severity calibration guidance
│
└── .claude/                           # Claude Code CLI configuration
    └── settings.json                  #   Hooks, permissions, skill directories
```

## Available Agents

| Agent | Purpose | Invoke |
|-------|---------|--------|
| recon-agent | Subdomain enum & surface discovery | "Run recon on target.com" |
| recon-ranker | Attack surface ranking & prioritization | "Rank attack surface for target.com" |
| p1-warrior | Priority-1 systematic bug hunter | "Hunt target.com for high bugs" |
| chain-builder | Exploit chain construction (A→B→C) | "Chain A with B for critical" |
| js-analysis | JS bundle endpoint/secret extraction | "Analyze JS bundles for secrets" |
| js-deobfuscation | Reverse obfuscated JavaScript | "Deobfuscate this bundle" |
| report-writer | Professional report generator | "Write report for finding" |
| validator | 7-Question Gate validation | "Validate this finding" |
| autopilot | Autonomous hunt loop (full cycle) | "Run autopilot on target.com" |
| exploit-researcher | CVE & exploit research | "Research CVEs for nginx 1.24" |
| network-analyst | Packet inspection & protocol analysis | "Analyze packet capture" |
| redteam-planner | Red team engagement design | "Plan engagement for target" |
| reverse-engineer | Binary & firmware analysis | "Analyze this binary" |
| security-reviewer | Code & architecture audit | "Review code for vulns" |
| ai-researcher | AI/ML security & LLM red-teaming | "Test LLM for prompt injection" |
| token-auditor | Meme coin rug-pull detection | "Audit token for rug pull" |
| web3-auditor | Smart contract security audit | "Audit smart contract" |
| mobile-testing-agent | APK/iOS IPA security testing | "Test the mobile app" |
| windows-workflow-agent | Windows-native recon & hunting | "Run Windows recon workflow" |

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
# Windows — load tools
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

## Platform Compatibility

- **Claude Code:** Uses `.claude/settings.json`, `hooks/hooks.json`, and `skills/` directory
- **OpenCode:** Uses `opencode.json` and `AGENTS.md` for agent registration
- **Codex CLI:** Uses `Hercules.md` for context and tool definitions
- **Cursor / Continue.dev:** Uses `adapters/targets.md` for install paths
- **Any agentic CLI:** Tools are standalone Python/PowerShell/JS scripts — no AI required

## Safety

- Never test out-of-scope assets
- Never exfiltrate or persist real user data beyond PoC requirements
- Never DoS or social-engineer real employees
- Never auto-submit reports without human approval
- All tools respect rate limiting and safe methods only
