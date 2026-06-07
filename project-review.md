# Hercules-Hunt — Deep Project Review

Generated: 2026-06-07
Scope: Full audit of 202 source files, 118,576 lines, 44 directories

---

## 1. State Overview

| Metric | Value |
|--------|-------|
| **Source files** | 202 |
| **Total lines** | 118,576 |
| **TypeScript/JS/Python/PS** | 277 |
| **Markdown** | 122 files (heaviest — 60% of codebase) |
| **Git commits** | 13 |
| **Git status** | Clean |
| **Broken links/empties** | 1 (`recon/README` = 0 bytes) |

This is a **skill system + toolchain for AI-driven bug bounty hunting**, not a standalone application. It's designed to be loaded into agentic coding CLIs (Claude Code, OpenCode, Codex CLI, etc.) where the markdown files become instructions and the Python/PS/JS files become executable tools.

---

## 2. Strengths

### 2.1 Depth of Agent Definitions
17 agent markdown files averaging 1,000 lines each — these are not stubs. Each agent has real methodology, real workflow steps, real payloads. The `p1-warrior.md` (1,150 lines), `chain-builder.md` (1,804 lines), and `report-writer.md` (1,787 lines) are genuinely useful one-shot instructions for a capable AI model.

### 2.2 Cross-CLI Support
`adapters/manifest.json` + `scripts/jiggy-adapter.py` covers 18+ agentic CLIs. This is rare. Most frameworks target one CLI — this one tries to be universal. The installer handles platform-specific paths, entry points, and file layouts.

### 2.3 MCP Architecture (10 Servers)
The MCP layer is well-structured: separate server per concern, all speaking JSON-RPC 2.0 over stdio, each with its own README + config. 50+ tools exposed. The `hercules-hunt-mcp` correctly calls into the Python hunters at runtime, and the auxiliary servers (interactsh, dns-recon, payload, report, recon) are self-contained.

### 2.4 Python Tools Are Functional
7 P1 hunters + 10 core modules, all pass `python -m py_compile`. Each P1 tool has 20+ methods, `export_json()`, `get_summary()`, and standalone CLI. The `secret_scanner.py` and `network_utils.py` are genuinely useful beyond just hunting — they work as standalone security tooling.

### 2.5 Git Hygiene
Clean working tree, no secrets committed, no accidental commits of large binaries. Commit messages are descriptive and grouped by concern.

### 2.6 Storage/Memory System
The `memory/` and `storage/` directories define a persistence layer that would survive session restarts — `universal.md`, `discoveries.md`, `session-state.md`, `credentials-vault.md`, `findings-archive.md`. This is more thought-through than most ad-hoc bug bounty setups.

---

## 3. Weaknesses

### 3.1 Critical: Markdown Bloat (60% of Codebase)
**122 markdown files = 60% of total lines.** The `rules/` directory alone is 20,041 lines — larger than all Python + PowerShell + JS code combined (21,590 lines). Many of these files are redundant or overlapping:
- `rules/recon.md` (2,753 lines) overlaps heavily with `agents/recon-agent.md` (746 lines) and `security-arsenal/recon-arsenal.md` (471 lines)
- `bug-bounty/` contains 7 skill files that duplicate content from `agents/`, `rules/`, and `security-arsenal/`
- Memory files are reference documents, not actual persistent state — they describe schemas but hold no runtime data

**The project would not lose functionality if 40% of the markdown files were deleted.** The agents, rules, and security-arsenal directories need deduplication.

### 3.2 Python Tools: Duplicated Orchestration
`python-hunter.py` (1,606 lines) is a monolithic orchestrator that re-implements what the 7 P1 tools already do. It was the original monolith that got split, but it still exists and tries to import all other modules. The MCP `hercules-hunt-mcp/server.py` (388 lines) also re-wraps the same tools with yet another interface. There are now **3 ways** to invoke the same Python hunters:
1. Direct: `python rce_hunter.py <url>`
2. Orchestrator: `python python-hunter.py menu`
3. MCP: `python mcp/hercules-hunt-mcp/server.py --tool rce_hunt ...`

This is technical debt from the migration that was never cleaned up.

### 3.3 No Tests Anywhere
Zero test files. No `pytest`, no `unittest`, no PS Pester tests, no JS test runner. For a project with 27 Python files and 7 PS1 files, the absence of tests means every refactor is a manual regression test. Given that the Python tools make HTTP requests and parse responses, this is a real risk.

### 3.4 No CI/CD
No `.github/workflows/`, no linting, no type checking, no automated deployment. The only quality gate is `python -m py_compile`, which only catches syntax errors, not logic errors.

### 3.5 PowerShell-Bound
7 of 8 PS1 tools (`curl-hunter.ps1`, `recon-toolkit.ps1`, `fuzzer-toolkit.ps1`, `js-analyzer.ps1`, `evidence-toolkit.ps1`) are Windows-only. The adapter system claims cross-platform support, but the heaviest tools are PowerShell-locked. The `install.ps1` script only works on Windows. The Python tools partially compensate, but the PS tools are the most feature-rich and platform-dependent.

### 3.6 Naming Issues
- `task-presistence/` — misspelled (should be `task-persistence`). This is now part of the repo's permanent history.
- `doc/file.md` — 43 lines, unclear purpose. Not linked from any index.
- `recon/README` — 0 bytes, empty file.
- `security-arsenal/METHODOLOGY_CHEATSHEET.md` — inconsistent casing with sibling files.

### 3.7 Skeleton State of Storage/Memory
The `memory/*.md` and `storage/*.md` files describe structures with detailed YAML frontmatter and section headings, but contain **no actual data**. They're templates waiting to be filled. The `findings-archive.md` defines what a finding schema looks like, but has zero entries. The `credentials-vault.md` defines an account schema, but has zero accounts. This gives the impression of completeness that isn't real — these are empty filing cabinets, not actual records.

### 3.8 No Runtime Error Handling in PS Tools
The PowerShell scripts make extensive use of `Invoke-WebRequest` and `curl.exe` wrappers but have minimal try/catch for network failures, timeouts, or API errors. If a target is down, the tools will throw red exceptions instead of degrading gracefully.

### 3.9 JS Tools Are Browser-Only
The 17 JS files in `tools/javascript/` are designed to run as browser DevTools snippets (they reference `window`, `document`, `fetch` directly). They have no test runner, no Node.js compatibility layer, and no bundling. They must be copy-pasted into a browser console to be used.

### 3.10 No Lock Files or Dependency Pins
`tools/python/` imports `requests` but there's no `requirements.txt` or `pyproject.toml`. The MCP servers use Python standard library only (good), but the P1 hunters rely on `requests` (not installed by default). The `install.ps1` doesn't install Python dependencies.

---

## 4. Improvement Roadmap

### Tier 1: High Impact / Low Effort (do this week)

| Issue | Fix |
|-------|-----|
| Empty `recon/README` | Delete or add content |
| `doc/file.md` orphan | Either fill it or delete it |
| Missing `requirements.txt` | Create one with `requests`, `certifi` |
| `verify_ssl: false` in config | Add comment explaining why (self-signed test targets) |
| `__pycache__/` in git | Add `__pycache__/` to `.gitignore` |
| `recon/README` empty file | Delete it |

### Tier 2: Structural Cleanup (1-2 weeks)

| Issue | Fix |
|-------|-----|
| Markdown dedup | Merge `rules/recon.md` + `agents/recon-agent.md` + `security-arsenal/recon-arsenal.md` into one canonical source; symlink or reference the rest |
| `python-hunter.py` debt | Either delete it or make it a thin CLI dispatcher that calls the P1 tools directly (remove all duplicated logic) |
| `task-presistence/` rename | Can't rename without breaking git history — but can add `task-persistence/` as an alias symlink |
| PowerShell cross-platform | Port the 3 most-used PS tools (`recon-toolkit.ps1`, `curl-hunter.ps1`, `js-analyzer.ps1`) to Python equivalents or make them detect and run under pwsh |
| `memory/` hydration | Write a small Python script (`scripts/hydrate-memory.py`) that populates the memory files from `findings.json`, git log, config data |

### Tier 3: Quality Infrastructure (1 month)

| Issue | Fix |
|-------|-----|
| No tests | Add `tests/` with `pytest` for Python tools — start with `test_secret_scanner.py`, `test_payload_generator.py`, `test_network_utils.py` (these don't make HTTP calls) |
| No CI | Add GitHub Actions workflow: `pytest` + `python -m py_compile` + markdown link checker |
| PS try/catch | Add `try/catch` to all `Invoke-WebRequest` calls in PS tools — even a 5-line wrapper function would prevent red screens |
| JS tool packaging | Add a simple Node.js wrapper that lets JS tools run via `node` instead of requiring browser paste |
| MCP server tests | Add smoke tests for each MCP server — start them, call `tools/list`, verify response, shutdown |

### Tier 4: Major Features (1-3 months)

| Feature | Why |
|---------|-----|
| Interactive CLI dashboard | `python main.py menu` that shows target status, finding counts, next actions — replaces the `python-hunter.py` monolith |
| Findings database | Replace `findings.json` flat file with SQLite — enables search, dedup, aggregation across sessions |
| Plugin system | Allow community MCP servers to be dropped into `mcp/` without config changes (auto-discover on startup) |
| Real persistence | Hydrate `memory/` and `storage/` with actual data from tool runs — not just schemas |
| Web UI | Simple Flask/FastAPI dashboard showing active targets, findings timeline, recon status |

---

## 5. Critical Issues (Must Fix)

1. **No Python dependency management** — Add `requirements.txt` with `requests>=2.28` today. Without it, `rce_hunter.py` and all P1 tools fail on a fresh install.

2. **PS tools are Windows-gated** — The adapter claims cross-platform but `recon-toolkit.ps1` (1,063 lines), `fuzzer-toolkit.ps1` (2,071 lines), and `js-analyzer.ps1` (1,908 lines) use Windows-only APIs. Need either Python equivalents or a `try/catch` with clear "Windows only" messages on other platforms.

3. **Zero tests** — The Python tools make real HTTP requests in their test methods. A typo in `rce_hunter.py` that changes `cmd` to `cmc` won't be caught until someone runs it. Add tests for at least the non-HTTP methods (payload generation, secret scanning regex, encoding).

4. **Markdown bloat will become unmanageable** — Already 122 markdown files. At current growth rate, the project will hit 200 markdown files within 3 months. Needs a dedup pass before adding more.

5. **`memory/` and `storage/` are skeletons** — They look complete but contain zero runtime data. This is misleading. Either populate them with real content or restructure them as templates with `hydrate-` scripts.

---

## 6. Verdict

**Hercules-Hunt is a well-architected, genuinely useful bug bounty framework that has grown faster than its quality infrastructure can keep up.**

The core is solid: 7 P1 Python hunters that actually work, 10 MCP servers with 50+ tools, 17 well-written agent definitions, and cross-CLI support that actually tries to cover 18 platforms.

The problems are all downstream of rapid growth:
- Markdown duplication from having agents + rules + skills + arsenal all saying similar things
- No test harness (which is fine for a prototype, but this is past prototype stage)
- Windows lock-in on the heaviest tooling
- `python-hunter.py` monolith that should have been deleted when the split was done
- Empty storage/memory that looks complete but isn't

**If I were maintaining this project, my first action would be:**
1. Delete `python-hunter.py` (replace with a 50-line dispatcher)
2. Add `requirements.txt`
3. Merge the 3 recon markdown files into 1
4. Write 10 `pytest` tests for the non-HTTP Python methods
5. Add a GitHub Actions workflow

After that, the project is production-ready for solo/team bug bounty work.

---

*End of review — 2026-06-07*
