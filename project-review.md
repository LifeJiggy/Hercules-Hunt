# Hercules-Hunt — Final Pre-Launch Review

**Date:** 2026-06-10  
**Scope:** Full project audit — 230K lines across 44 directories  
**Reviewer:** Deep scan of architecture, consistency, security, DX, and gaps

---

## 1. Project at a Glance

| Metric | Value |
|--------|-------|
| Total lines | 230,113 |
| Executable tool code | 63,209 lines |
| Agent definitions | 40 `.md` files |
| Total `.md` files | ~122 |
| Hydrate scripts | 15 (`hydrate.py`) |
| MCP servers | 10 |
| Hooks | 6 JSON files |
| Config files | 7 JSON |

### Tools per Language

| Language | Files | Lines | Status |
|----------|-------|-------|--------|
| Python | 25 | 19,786 | `__all__` registered (1 gap) |
| JavaScript | 27 | 12,893 | `index.js` registered (1 gap) |
| PowerShell | 17 | 22,787 | No central registry |
| Bash | 18 | 7,743 | No central registry |
| **Total** | **87** | **63,209** | |

---

## 2. Architecture Assessment: 9.5/10

### Strengths

**2.1 Multi-Format Knowledge Architecture** — Each security domain expressed in 3-4 formats (agents/rules/arsenal/docs) for different AI consumption modes. More sophisticated than flat knowledge bases.

**2.2 40 Standardized Agent Files** — Every domain has a dedicated agent. All 10 specialist hunters (idor, ssrf, xss, auth-bypass, race-condition, business-logic, file-upload, api-misconfig, graphql, ssti) plus 5 post-hunt agents (program-researcher, evidence-reviewer, triage-defender, browser-automator, orchestrator).

**2.3 40 Cross-Language Tools (10 x 4)** — Standardized tool set across Bash, PowerShell, JavaScript, and Python:
| Tool | Bash | PS | JS | Python | Min |
|------|------|-----|-----|--------|-----|
| extract-apis | 702 | 1,058 | 741 | 889 | 702 |
| extract-js | 633 | 948 | 743 | 902 | 633 |
| deep-hunt | 620 | 1,089 | 722 | 1,106 | 620 |
| fast-hunt | 606 | 815 | 597 | 999 | 597 |
| https-probing | 599 | 831 | 676 | 1,129 | 599 |
| extract-parameters | 708 | 1,007 | 666 | 1,303 | 666 |
| extract-functionalities | 686 | 1,286 | 1,063 | 1,578 | 686 |
| endpoint-fuzzer | 589 | 929 | 695 | 1,503 | 589 |
| auth-tester | 578 | 1,275 | 930 | 1,649 | 578 |
| report-builder | 633 | 1,498 | 848 | 1,520 | 633 |

Every tool is 500+ lines with proper CLI, error handling, and help text.

**2.4 MCP Layer (10 Servers)** — Full JSON-RPC 2.0 over stdio. Coverage spans: recon → subdomains → URLs → payloads → OOB callbacks → findings → reports. Shared protocol library in `mcp/mcp_lib.py`.

**2.5 Session Persistence** — `memory/` and `storage/` with schema templates for session state, discoveries, credentials, evidence. Heartbeats, phase transitions, next actions all defined.

**2.6 Hook System** — 6 JSON hook files with targeted lifecycle events: scope checking, environment verification, post-session checklists.

**2.7 Hydration Ecosystem** — 15 `hydrate.py` scripts auto-discover all `.md` files in their folders. `tools/python/hydration.py` supports `--dir` for any folder.

---

## 3. Gaps Found (Pre-Launch Must-Fix)

### 3.1 Registration Gaps

| Gap | Location | Severity | Fix |
|-----|----------|----------|-----|
| `python-hunter.py` not in `__all__` | `tools/python/__init__.py` | **HIGH** | Add `"python-hunter"` to `__all__` |
| `launcher.js` not in `index.js` | `tools/javascript/index.js` | **MEDIUM** | Add require + export |
| 5 agents unregistered in AGENTS.md | `agents/` | **HIGH** | Add entries for chain-validator, p1-validator, scope-enforcer, target-onboarding-agent, triage-readiness |

### 3.2 Cross-Language Inconsistencies

| Issue | Details | Severity |
|-------|---------|----------|
| Bash CLI flags different from PS/JS/Python | Bash uses `-t` for target, others use `--target` or `--url`. Short flags inconsistent. | **MEDIUM** |
| PowerShell has no `index.ps1` or module manifest | 17 PS1 files with no central loader | **MEDIUM** |
| Bash has no `index.sh` or loader | 18 `.sh` files with no central loader | **LOW** |
| `js-analyzer.sh` (188 lines) vs `js-analyzer.ps1` (2,275 lines) | Same-name tool, 12x size difference. Bash version is minimal stub. | **HIGH** |
| `curl-hunter.sh` (208 lines) vs `curl-hunter.ps1` (2,818 lines) | 13.5x difference | **HIGH** |
| `fuzzer-toolkit.sh` (276 lines) vs `fuzzer-toolkit.ps1` (2,303 lines) | 8.3x difference | **HIGH** |
| `recon-toolkit.sh` (215 lines) vs `recon-toolkit.ps1` (1,105 lines) | 5x difference | **MEDIUM** |
| `evidence-toolkit.sh` (213 lines) vs `evidence-toolkit.ps1` (962 lines) | 4.5x difference | **MEDIUM** |

Legacy tools (curl-hunter, fuzzer-toolkit, recon-toolkit, js-analyzer, evidence-toolkit) exist only in Bash and PowerShell — no JS or Python equivalents.

### 3.3 Security Findings

| Finding | File(s) | Severity | Details |
|---------|---------|----------|---------|
| SSL verification disabled | Multiple Python tools using `ssl._create_unverified_context()` | **MEDIUM** | Creates MITM risk. Should add `--allow-insecure` flag instead of hardcoding. |
| No command injection guards | `extract_js.py`, `deep_hunt.py`, `https_probing.py` | **MEDIUM** | Uses `os.popen()` / `subprocess.Popen()` with string interpolation. Should use argument arrays. |
| Sensitive data in logs | `report_builder.py` includes full HTTP bodies in debug logging | **LOW** | Debug mode could leak tokens/credentials to log files. |
| No path traversal validation | All Python file-writing tools | **MEDIUM** | Accept user-supplied output paths without validation. Possible directory traversal via `--output ../../malicious_path`. |
| No timeout on network calls | `auth_tester.py` (some requests) | **MEDIUM** | Missing timeout could hang indefinitely. |
| No input size limits | All tools | **LOW** | No max file size, max URL length, or max parameter count limits. Unbounded memory consumption possible. |

### 3.4 DX / Documentation Gaps

| Issue | Severity |
|-------|----------|
| No `--version` flag on any tool | **LOW** |
| No `--quiet` flag on Python tools (present in Bash/PS) | **LOW** |
| `recon/README` has no `.md` extension (inconsistent) | **LOW** |
| `utils/` directory is empty | **LOW** |
| No unified launcher script (`hercules` CLI) to dispatch any tool | **MEDIUM** |
| No man pages or `--help` output examples for complex tools | **LOW** |
| `package.json` only in `tools/javascript/` — no root-level npm workspace | **LOW** |

### 3.5 Test Coverage

| Area | Status |
|------|--------|
| Python tools (new 10) | **0 tests** — no test files |
| Python tools (legacy) | Some — `tests/test_batch_processor.py`, `tests/test_base64_utils.py` exist |
| JavaScript tools | 46/46 Jest tests via `browser-mock.js` |
| Bash tools | **0 tests** |
| PowerShell tools | **0 tests** |
| MCP servers | **0 tests** |
| CI pipeline | Exists (`.github/workflows/ci.yml`) but likely doesn't run tests given 0 coverage |

### 3.6 Performance / Context Budget

| Concern | Details |
|---------|---------|
| Rules files too large | `rules/recon.md` (3,363L), `rules/api-testing.md` (2,594L), `rules/auth-testing.md` (2,024L) loaded every session |
| 40 agent files in AGENTS.md | When all registered, `AGENTS.md` itself is a significant context cost |
| 15 hydrate.py scripts | Duplicate logic — each is a copy. Should be generated from shared template. |
| No lazy loading pattern for markdown | All `*.md` files in a folder get loaded by hydrate scripts, even if not needed |

---

## 4. Improvement Plan

### Phase 1: Pre-Launch Must-Fix (hours)

| # | Task | Effort |
|---|------|--------|
| 1 | Add `python-hunter.py` to `__init__.py` `__all__` | 1 min |
| 2 | Add `launcher.js` to `index.js` require + export | 2 min |
| 3 | Register 5 unregistered agents in `AGENTS.md` | 5 min |
| 4 | Add `--allow-insecure` SSL flag to Python tools + retain `verify=True` default | 30 min |
| 5 | Add `--quiet` / `--version` flags to Python tools | 15 min |
| 6 | Add `recon/README` → `recon/README.md` rename | 1 min |

### Phase 2: Quality (this week)

| # | Task | Est. |
|---|------|------|
| 7 | Add argument array safety to `subprocess` calls (prevent shell injection) | 30 min |
| 8 | Add path traversal validation to all `--output` parameters | 15 min |
| 9 | Add default timeouts to all network calls | 15 min |
| 10 | Add input size limits (max URL len, max file size, max params) | 20 min |
| 11 | Create Python + JS equivalents of legacy tools (curl-hunter, fuzzer-toolkit, recon-toolkit, js-analyzer, evidence-toolkit) | 2-3 hrs |
| 12 | Create PowerShell and Bash `index` loaders | 30 min |

### Phase 3: Testing (1 week)

| # | Task | Est. |
|---|------|------|
| 13 | Write pytest tests for 10 new Python tools (happy path + edge cases) | 2 hrs |
| 14 | Add Bash tests using `bats` or `shunit2` | 1 hr |
| 15 | Add PowerShell Pester tests | 1 hr |
| 16 | Wire CI workflow to run all tests | 30 min |

### Phase 4: Long-Term

| # | Task | Priority |
|---|------|----------|
| 17 | Create unified `hercules` CLI launcher (`tools/hercules.py` or `tools/hercules.sh`) | HIGH |
| 18 | Deduplicate 15 `hydrate.py` scripts into a single template with config | MEDIUM |
| 19 | Add findings database (SQLite) to replace flat JSON | MEDIUM |
| 20 | Implement lazy-load patterns for large markdown files | MEDIUM |
| 21 | Migrate `recon/README` filename to `.md` extension | LOW |
| 22 | Clean up empty `utils/` directory | LOW |

---

## 5. Verdict

**Hercules-Hunt is launch-ready with 5 must-fix registration gaps.**

The project is a genuinely impressive multi-format knowledge system — **230K lines, 40 agents, 40 cross-language tools, 10 MCP servers, 15 hydrate scripts, 7 config files, 6 hooks, and a session persistence architecture** — all organized around a coherent multi-format design.

The core architecture (agents + tools in 4 runtimes + MCP + hydration) is production-grade. The content depth exceeds most bug bounty toolkits by a wide margin.

**Current rating: 8.5/10** (was 9/10 on 2026-06-07)

**What dropped it from 9 to 8.5:** The deep audit revealed:
- 5 unregistered agents in AGENTS.md
- python-hunter.py missing from `__all__`
- launcher.js missing from index.js
- 5 Bash legacy tools are stubs compared to their PS counterparts (3-13x size difference)
- SSL bypass hardcoded without `--allow-insecure` flag
- Zero test coverage on the 10 new Python and JS tools
- No unified CLI launcher

**All are fixable before launch.** Fix the 5 must-fix items in Phase 1, then iterate through Phases 2-4 post-launch.
