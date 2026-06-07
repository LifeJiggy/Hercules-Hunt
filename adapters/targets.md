# Hercules-Hunt Universal Adapter Targets

The Hercules-Hunt Bug Bounty System can be installed into 18+ agentic coding CLI
environments. Each target uses a specific install path and file layout.

| # | Target | Install Path | Entry Point | Strategy |
|---|--------|------------|-------------|----------|
| 1 | Codex CLI | `~/.codex/plugins/jiggy-2026/` | `plugin.json` | Plugin manifest + skill files. Codex loads from `.codex/plugins/`. |
| 2 | Claude Code | `~/.claude/` | `.claude/settings.json` | Claude reads `skills/`, `agents/`, `rules/` subdirectories. Hooks in `hooks/hooks.json`. |
| 3 | OpenCode | `~/.config/opencode/jiggy-2026/` | `opencode.json` | OpenCode uses `opencode.json` for config + `AGENTS.md` for agent registry. |
| 4 | KiloCode | `~/.config/kilocode/jiggy-2026/` | `Hercules.md` | Universal AI context file plus agent definitions. |
| 5 | Kimi Code | `~/.config/kimi-code/jiggy-2026/` | `Hercules.md` | Universal AI context file plus rules. |
| 6 | Hermes Agent | `~/.config/hermes-agent/jiggy-2026/` | `Hercules.md` | Agent instruction files. |
| 7 | Aider | `~/.aider/jiggy-2026/` | `.aider.rules.md` | Aider reads `.aider.rules.md` from project root for rules. |
| 8 | Gemini CLI | `~/.config/gemini-cli/jiggy-2026/` | `Hercules.md` | Context file for Gemini code assistance. |
| 9 | Goose | `~/.config/goose/jiggy-2026/` | `Hercules.md` | Recipe/instruction files. |
| 10 | Cursor | `.cursor/rules/jiggy-2026/` | `rules/*.md` | Project-level rules. Install into your project's `.cursor/rules/` dir. |
| 11 | Windsurf | `.windsurf/rules/jiggy-2026/` | `rules/*.md` | Workspace-level rules. Install into your project's `.windsurf/rules/` dir. |
| 12 | Cline | `~/.config/cline/jiggy-2026/` | `.clinerules` | Custom instructions format. |
| 13 | Roo Code | `~/.config/roo-code/jiggy-2026/` | `Hercules.md` | Modes and rules definitions. |
| 14 | Continue | `~/.continue/jiggy-2026/` | `config.json` | Assistant context configuration. |
| 15 | Zed | `~/.config/zed/jiggy-2026/` | `Hercules.md` | Agent instruction context. |
| 16 | Sourcegraph Cody | `~/.config/sourcegraph-cody/jiggy-2026/` | `Hercules.md` | Custom commands and context rules. |
| 17 | GitHub Copilot | `~/.config/github-copilot/jiggy-2026/` | `Hercules.md` | Repository-level instructions. |
| 18 | JetBrains AI | `~/.config/JetBrains/jiggy-2026/` | `Hercules.md` | Project guideline context. |

## Common Payload

Every adapter installs the same core Hercules-Hunt components, preserving relative
paths from the repository root:

### Agents (17 files)
```
agents/
  recon-agent.md          Subdomain enumeration & surface discovery
  recon-ranker.md         Attack surface ranking & prioritization
  p1-warrior.md           Priority-1 systematic bug hunter
  chain-builder.md        Exploit chain builder (A->B->C)
  js-analysis.md          JS bundle endpoint & secret extraction
  js-deobfuscation.md     Reverse minified/obfuscated JS
  report-writer.md        Professional bug bounty report generator
  validator.md            7-Question Gate finding validator
  autopilot.md            Autonomous hunt loop
  exploit-researcher.md   CVE & exploit research
  network-analyst.md      Packet analysis & protocol inspection
  redteam-planner.md      Red team engagement planning
  reverse-engineer.md     Binary & firmware analysis
  security-reviewer.md    Code & architecture audit
  ai-researcher.md        AI/ML security & red teaming
  token-auditor.md        Meme coin rug-pull detection
  web3-auditor.md         Smart contract security audit
```

### Rules (13 files)
```
rules/
  hunting.md              Hunting methodology & discipline
  reporting.md            Report quality & submission rules
  recon.md                Reconnaissance discipline
  scope.md                Scope management & verification
  chain-rules.md          Vulnerability chaining rules
  evidence.md             Evidence collection & PoC hygiene
  mindset.md              Operator psychology & strategy
  js-analysis.md          JavaScript analysis rules
  js-deobfuscation.md     JS deobfuscation methodology
  auth-testing.md         Authentication bypass testing
  api-testing.md          API fuzzing & methodology
  mobile-testing.md       Mobile app security testing
  windows-workflow.md     Windows-specific hunting
```

### Tools (8 files)
```
tools/
  curl-hunter.ps1         curl.exe master toolkit (15 functions)
  js-analyzer.ps1         JS bundle analysis toolkit
  powershell-lib.ps1      70+ PowerShell one-liner library
  python-hunter.py        Python hunting toolkit (8 classes)
  recon-toolkit.ps1       Recon automation pipeline
  fuzzer-toolkit.ps1      HTTP fuzzing toolkit
  evidence-toolkit.ps1    Evidence capture & sanitization
  jiggy.ps1               Jiggy main entry point
```

### Skills (5+ files)
```
SKILL.md                  Root Claude Code skill
bug-bounty/SKILL.md       Bug bounty master workflow
security-arsenal/SKILL.md Security payloads & bypass tables
triage-validation/SKILL-1.md  Finding validation skill
triage-validation/SKILL-2.md  Evidence hygiene skill
report-writing/SKILL.md   Report writing skill
```

### Config (4 files)
```
Hercules.md                 Universal AI context (all platforms)
plugin.json               Root manifest for Codex / generic installs
AGENTS.md                 OpenCode agent registry
opencode.json             OpenCode configuration
```

### Hooks (2 files)
```
hooks/hooks.json          Session lifecycle hooks
.claude/settings.json     Claude Code settings
```

### MCP (5+ files)
```
mcp/burp-mcp-client/      Burp Suite MCP integration
mcp/caido-mcp-client/      Caido MCP integration
mcp/hackerone-mcp/        HackerOne MCP integration
```

## Target-Specific Notes

### Codex CLI
- **Install**: `~/.codex/plugins/jiggy-2026/`
- Codex loads plugins from `~/.codex/plugins/` directories.
- The `plugin.json` at root serves as the plugin manifest.
- Additional files in the install dir are available to the agent.

### Claude Code
- **Install**: `~/.claude/`
- Claude reads `skills/` directory for skill definitions (SKILL.md).
- Agent definitions in `agents/` are loaded as sub-agents.
- `hooks/hooks.json` configures session lifecycle hooks.
- `.claude/settings.json` configures permissions and defaults.

### OpenCode
- **Install**: `~/.config/opencode/jiggy-2026/`
- OpenCode uses `opencode.json` for tool permissions, agent config, rules.
- `AGENTS.md` registers all 17 agents with tool assignments.
- Rules from `rules/` are referenced in `opencode.json`.

### Aider
- **Install**: `~/.aider/jiggy-2026/`
- Aider reads `.aider.rules.md` from the project root (or home dir).
- The installer copies `Hercules.md` as `.aider.rules.md` in the install dir.
- Copy `.aider.rules.md` to your project root to activate.

### Cursor
- **Install**: `.cursor/rules/jiggy-2026/` (project-level)
- Cursor reads `.cursor/rules/` for project-level AI rules.
- Run the installer from your project directory, or use `--target-root .` to
  point to the current directory.

### Windsurf
- **Install**: `.windsurf/rules/jiggy-2026/` (project-level)
- Windsurf reads `.windsurf/rules/` for workspace rules.
- Same project-level pattern as Cursor.

## Common Workflow

```bash
# Preview installation to all targets
python scripts/jiggy-adapter.py --target all --dry-run

# Install to a single target
python scripts/jiggy-adapter.py --target claude-code --apply

# Install all components to all targets
python scripts/jiggy-adapter.py --target all --apply

# Install only agents to OpenCode
python scripts/jiggy-adapter.py --target opencode --component agents --apply

# Install to custom directory (staging/dry-run testing)
python scripts/jiggy-adapter.py --target all --target-root ./preview --apply

# List supported targets
python scripts/jiggy-adapter.py --list-targets
```
