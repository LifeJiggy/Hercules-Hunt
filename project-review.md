# Hercules-Hunt — Project Review

Generated: 2026-06-07 · Updated: 2026-06-08

## Status of Previously-Identified Issues

### ✅ Addressed
| Issue | Fix |
|-------|-----|
| JS tools untestable without browser | `helpers/browser-mock.js` created — 46/46 Jest tests passing |
| PS tools lack error handling | `try/catch` added to `_Invoke-Curl` (fuzzer-toolkit) and `Invoke-CurlCapture` (evidence-toolkit) |
| Windows-gated PS tools (cross-platform gap) | 7 bash equivalents created in `tools/bash/` — `jiggy.sh` CLI dispatches all |
| No requirements.txt | Exists at root — `requests>=2.28` |
| No philosophy/mission docs | `soul.md`, `purpose.md`, `goal.md` created |
| Hercules.md incomplete | Rewritten to catalog all 30+ directories and 100+ files |
| hunt.sh references Claude | `CLAUDE.md` → `ENGAGEMENT.md` referencing soul/purpose/goal |
| install-community-skills references shuvonsec/claude-bug-bounty | Rewired to `LifeJiggy/Hercules-Hunt` |

### ❌ Still Open
| Issue | Priority |
|-------|----------|
| `recon/README` 0 bytes | Low — delete or fill |
| `doc/file.md` orphan (brainstorming note) | Low — delete |
| No CI / GitHub Actions | Medium |
| No Python tests | Medium |
| Storage/memory templates not hydrated | Low (by design for now) |
| MCP protocol compliance (error codes, progress) | Low |
| Uneven domain coverage (chain-rules has no agent) | Low |

---

## Current Rating: 7.5 / 10

**Why 7.5:**
- Architecture is solid — multi-format, cross-CLI, agent-driven
- Content quality is high — agents average 1K+ lines of real methodology
- JS test infra now works (browser-mock.js, 46/46 passing)
- Bash equivalents close the cross-platform gap
- PS tools now have error handling on all network calls
- Philosphy docs (soul/purpose/goal) give the project identity

**What keeps it from 8-9:**
- No CI pipeline — no automated quality gate
- No Python tests — the heaviest executable code is untested
- `recon/README` 0 bytes and `doc/file.md` orphan are unfinished
- Storage/memory are templates only — no hydration scripts
- MCP servers use non-standard protocol routing

**To reach 9:**
- Add `.github/workflows/ci.yml` with `py_compile` + `pytest` + PS syntax check
- Add pytest tests for non-HTTP Python modules (`secret_scanner.py`, `payload_generator.py`, `base64_utils.py`)
- Clean up dead files (`recon/README`, `doc/file.md`)

---

---

## What This Project Is

Hercules-Hunt is a **multi-format knowledge system for agentic coding CLIs** — not a standalone application. It is designed to be installed into 18+ AI coding CLI environments (Claude Code, OpenCode, Codex CLI, etc.) where its markdown files become AI instructions, its JSON files become tool configurations, and its Python/PowerShell/JS files become executable tools.

The project has 202 source files across 44 directories totaling ~118K lines.

---

## Architecture

The project expresses each security domain (recon, auth testing, API testing, etc.) in **multiple formats for different consumption modes** within the AI ecosystem:

| Format | Role | Consumption Mode |
|--------|------|-----------------|
| `agents/*.md` | Agent task instructions | Loaded when AI invokes a specialized sub-agent |
| `rules/*.md` | Behavioral guardrails | Always-active constraints loaded at session start |
| `skills/*.md` | Skill definitions | Claude Code skill format, loaded on `/skill` invocation |
| `security-arsenal/*.md` | Reference material | Looked up when needed for payloads/bypasses |
| `recon/*.md` | Methodology docs | Human-readable narrative documentation |
| `report-writing/*.md` | Platform templates | Per-platform (H1/Bugcrowd/Immunefi) report formats |
| `triage-validation/*.md` | Validation gates | Finding kill/validate methodology |

The rest of the project provides the operational layer:

| Directory | Role | Key Files |
|-----------|------|-----------|
| `tools/python/` | 18 Python modules | 7 P1 hunters + secret scanner + network utils |
| `tools/powershell/` | 7 PS1 scripts | curl-hunter, recon-toolkit, js-analyzer, fuzzer |
| `tools/javascript/` | 17 JS tools | Browser DevTools snippets (DOM, XSS, CSRF, etc.) |
| `mcp/` | 10 MCP servers | 50+ tools via JSON-RPC 2.0 over stdio |
| `hooks/` | Session lifecycle hooks | SessionStart, Stop, SessionStop events |
| `config/` | Hunt configuration | Hunter config, tools config, profiles, targets |
| `context/` | Session context | Active target, chain primitives, hunt session state |
| `memory/` | Persistent AI memory | Session state, discoveries, technical notes |
| `storage/` | Data schemas | Evidence, credentials, findings, tool outputs |
| `adapters/` | Cross-CLI manifests | 18+ install targets, component definitions |

---

## Strengths

### 1. Multi-Format Knowledge Architecture
The core idea is sound. Each domain is expressed in 3-4 formats (agents/rules/arsenal/docs) for different AI consumption modes. The `.claude/settings.json` loads `skills/`, `agents/`, and `rules/` together — the AI gets task instructions, behavioral constraints, and skill workflows all in context. This is more sophisticated than flat knowledge bases.

### 2. Cross-CLI Support
`adapters/manifest.json` + `scripts/jiggy-adapter.py` covers 18+ CLIs with different install paths, entry points, and file formats. Each target CLI gets the right config files (`opencode.json`, `plugin.json`, `.claude/settings.json`, `AGENTS.md`, etc.). The `install.ps1` handles PowerShell profile injection.

### 3. MCP Layer (10 Servers)
10 self-contained MCP servers, each with README + config.json + (in most cases) server.py. They speak standard JSON-RPC 2.0 over stdio. Coverage spans the full workflow: recon → subdomains → URLs → payloads → OOB callbacks → findings → reports.

### 4. Python Tools Are Functional
7 P1 hunters (rce, sqli, idor, auth, ssrf, xxe, file_upload) + 10 core modules, all pass `python -m py_compile`. Each P1 tool has standalone CLI + `export_json()` + `get_summary()`. The `__init__.py` makes `tools/python` an importable package.

### 5. Hook System
`hooks/hooks.json` at 333 lines with targeted lifecycle events. Not just generic hooks — they check scope, verify environment (nuclei, subfinder, burp, interact.sh), and remind about post-session checklist. These fire automatically in Claude Code.

### 6. Depth of Agent Definitions
The 17 agent definitions average ~1,000 lines of actual methodology. `p1-warrior.md` (1,150 lines), `chain-builder.md` (1,804 lines), `report-writer.md` (1,787 lines) are genuinely useful one-shot AI instructions — a single agent invocation gives the AI everything it needs to run a complete workflow.

### 7. Session Persistence Design
`memory/` and `storage/` define schema templates for session state, discoveries, credentials, evidence, tool outputs. They're designed to be hydrated during a session, not pre-populated. The `session-state.md` includes heartbeats, phase transitions, and next actions — which is more thought out than most ad-hoc setups.

---

## Weaknesses

### 1. Markdown/Content Ratio Is Extreme
122 markdown files = 60% of the codebase. Only 40% is executable code (Python + PS + JS + MCP servers + configs). For a skill system this is somewhat expected (the content IS the product), but some files are disproportionately large:
- `rules/recon.md`: 3,363 lines (largest single file)
- `rules/api-testing.md`: 2,594 lines
- `rules/auth-testing.md`: 2,024 lines
- `rules/mindset.md`: 1,995 lines

These files get loaded into AI context on every session. At this size, they consume significant context window real estate. Consider whether every rule file needs to be loaded every session, or if some could be loaded on-demand.

### 2. Cross-Format Consistency Varies
The agent-to-rule mapping is inconsistent:
- Recon: has agent (911 lines) + rule (3,363 lines) + arsenal (640 lines) + methodology (358 lines) = **4 formats, 5,272 lines total**
- JS analysis: has agent (1,404) + rule (1,624) + deobfuscation agent (1,693) + deobfuscation rule (1,835) = **4 files, 6,556 lines**
- Mobile testing: has rule (1,309) but NO agent
- Windows workflow: has rule (1,713) but NO agent
- Chain rules: has rule (1,230) but NO agent

Some domains have 4 representations, others have 1. The coverage is uneven — either every domain should have every format, or the formats should be rationalized.

### 3. Python-PowerShell Runtime Split
7 PS1 tools (8,779 lines) vs 18 Python modules (8,269 lines). The PS tools are the most code-dense (`curl-hunter.ps1` at 2,275 lines, `fuzzer-toolkit.ps1` at 2,071 lines) and are Windows-only. The `install.ps1` only runs on Windows. The adapter system claims cross-platform but the heaviest tools are PowerShell‑gated. If the project targets Linux/macOS users, equivalent Python versions of the PS tools are needed.

### 4. No Dependency Management
`tools/python/*.py` imports `requests` but there's no `requirements.txt`. Fresh install fails silently. The MCP servers wisely use standard library only, but the P1 hunters don't.

### 5. Code Quality Infrastructure
- **Zero tests** — 27 Python files, 7 PS1 files, 17 JS files, no test runner anywhere
- **No CI** — no GitHub Actions, no linting, no type checking, no automated verification
- **`python -m py_compile`** is the only quality gate, which only catches syntax errors
- The PS1 tools have minimal try/catch — network failures produce red screen exceptions

### 6. Storage/Memory Are Templates, Not Data
The `storage/*.md` and `memory/*.md` files define schemas with YAML frontmatter and detailed section headings, but contain no actual runtime data. This is by design (they're hydrated during sessions), but there's no hydration script that connects tool output → storage files. The session state, evidence packages, and credential vault remain empty unless manually filled.

### 7. JS Tools Are Untestable Without Browser
17 JS files assume `window`, `document`, `fetch` globals. No Node.js wrapper, no headless runner, no test harness. They require copy-pasting into a browser DevTools console.

### 8. MCP Protocol Deviation
The MCP servers implement a custom JSON-RPC 2.0 handler over stdio that matches basic MCP protocol (initialize, tools/list, tools/call, notifications/initialized). This works but uses a simplified router that lacks proper error codes, progress notifications, and logging. The HackerOne and Hercules-Hunt MCP servers mix MCP protocol with direct CLI (`--list-tools`, `--tool` flags) — a design that works but is non-standard.

---

## Improvement Roadmap

### Tier 1: Quick Fixes (this week)

| Issue | Fix |
|-------|-----|
| No `requirements.txt` | Create with `requests>=2.28` + `certifi` |
| `verify_ssl: false` uncommented | Already fixed with `_note` field |
| `recon/README` 0 bytes | Delete or fill |
| `doc/file.md` orphan | Delete (brainstorming note from previous session) |
| `__pycache__/` in `.gitignore` | Already exists — verify no cached staged |

### Tier 2: Quality Infrastructure (1-2 weeks)

| Issue | Fix |
|-------|-----|
| **Tests for non-HTTP Python code** | Add `pytest` tests for `secret_scanner.py`, `payload_generator.py`, `base64_utils.py` — these don't make network calls |
| **GitHub Actions workflow** | `.github/workflows/ci.yml` — run `python -m py_compile` + `pytest` + PS syntax check |
| **PS1 error handling** | Add a `try/catch` wrapper function for `Invoke-WebRequest` calls in all 7 PS tools |
| **requirements.txt** | Already created above |

### Tier 3: Architectural Improvements (1 month)

| Issue | Fix |
|-------|-----|
| **Uneven domain coverage** | Audit which domains have all 4 formats (agent + rule + arsenal + doc) and which are missing. Add missing ones or document the gap. |
| **Context budget concern** | Measure how much context `rules/*.md` consumes when loaded together. Consider splitting into always-active vs on-demand rule files. |
| **MCP protocol compliance** | Add proper error codes, progress notifications, and structured logging to all MCP servers |
| **Storage/Memory hydration** | Write a `scripts/hydrate.py` that reads tool exports (`export_json()`) and writes into `storage/findings-archive.md`, `memory/discoveries.md`, etc. |

### Tier 4: Major Features (3+ months)

| Feature | Why |
|---------|-----|
| **Findings database (SQLite)** | Replace flat `findings.json` with SQLite — enables dedup, search, aggregation, cross-target correlation |
| **PS → Python migration** | Port the 3 most-used PS tools (`recon-toolkit.ps1`, `curl-hunter.ps1`, `js-analyzer.ps1`) to Python so the project is truly cross-platform |
| **JS → Node.js compatibility** | Add a lightweight Node.js runner that injects `window`/`document` mocks so JS tools work headlessly |
| **Plugin system** | Allow community MCP servers to auto-discover when dropped into `mcp/` |

---

## Verdict

**Hercules-Hunt is a well-architected multi-format knowledge system for AI-driven bug bounty hunting.** The core insight — expressing one domain in multiple formats for different AI consumption modes — is sophisticated and correct.

The project's size (118K lines) is appropriate for its scope. 60% is content (markdown), which is the product — it's what the AI reads. The `rules/` directory being the largest single content area at 20K lines makes sense because those are the behavioral guardrails that constrain every AI action.

The real gaps are infrastructure, not architecture:
- No dependency management (`requirements.txt`)
- No tests
- No CI
- Windows-gated PS tools
- Storage/memory templates remain empty unless manually filled

These are the difference between a well-designed knowledge system and a production-ready one. None require restructuring — they require the operational layer to catch up to the design layer.

---

*End of review*
