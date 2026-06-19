# JS Chunk Analysis Toolkit — Roadmap

40 features to add next, grouped by capability domain.

---

## Deobfuscation Engine — 7

| # | Feature | Description |
|---|---------|-------------|
| 1 | **AST-based Deobfuscation** | Parse JS with acorn/walk, apply AST transforms (constant folding, bracket removal, dead branch elimination) instead of regex. Handles nested obfuscation patterns regex can't touch. |
| 2 | **String Array Decoder** | Extract string array + decoder function, emulate via vm.Script to decode all references at once. Covers shift/rotate/reverse/sort-based indices. |
| 3 | **Dead Code Elimination** | Identify and strip unreachable branches (constant conditions, opaque predicates like `!![]`, `![]`), noop functions, empty catch blocks. Reduces noise. |
| 4 | **Control Flow Flattening Recovery** | Convert switch-dispatch CFF back to if/else chains using basic block reconnection. Unlocks readable decompilation of jscrambler/obfuscator.io protected code. |
| 5 | **Opaque Predicate Removal** | Detect and simplify math-based always-true/always-false predicates (`a * 2 === a + a`, `typeof x === 'undefined'` in non-browser contexts). |
| 6 | **Self-Modifying Code Emulation** | Run small code snippets in a sandboxed vm.Script context to resolve dynamically constructed strings, eval calls, and Function() bodies. |
| 7 | **Multi-Packer Chain Resolution** | Detect and recursively unpack nested packers (e.g., Packer inside base64 inside fromCharCode inside eval). Track layers applied and verify output. |

---

## Vulnerability Analysis — 7

| # | Feature | Description |
|---|---------|-------------|
| 8 | **Taint Tracking (Data Flow)** | Trace user-controlled input from entry point (URL param, form field, cookie) to sink (innerHTML, fetch, eval). Report only reachable vulnerabilities with path. |
| 9 | **Sink-Source Mapping Database** | Build a configurable map of 100+ sources (window.location, document.referrer, postMessage) to 50+ sinks (dangerouslySetInnerHTML, exec, SQL query). Score by reachability. |
| 10 | **DOM Clobbering Detection** | Find patterns where attacker-controlled HTML IDs shadow global JS variables (e.g., `<form name="x"><input name="y">` clobbering `window.x.y`). |
| 11 | **Prototype Pollution Gadget Finder** | Beyond `__proto__` detection — find libraries and code paths where polluted properties lead to RCE (e.g., lodash _.merge + template compilation). |
| 12 | **CSP Bypass Analysis** | Scan for known CSP bypass gadgets (JSONP endpoints, CDN script inclusion, Angular expressions, nonce/ hash reuse). |
| 13 | **DOM-based XSS Sink Prioritization** | Rank DOM XSS sinks by exploitability: `eval()` > `setTimeout(string)` > `innerHTML` > `document.write` > `dangerouslySetInnerHTML`. Weight by proximity to user input. |
| 14 | **Indirect Injection Detection** | Find second-order injections where payload is stored and later rendered (localStorage -> innerHTML, cookie -> fetch URL, URL hash -> eval). |

---

## Function & Module Analysis — 5

| # | Feature | Description |
|---|---------|-------------|
| 15 | **Function Call Graph** | Build a directed call graph from extracted functions. Find entry points (exported, event handlers, timers) and trace reachable code paths. Visualize as DOT graph. |
| 16 | **Side-Effect Analysis** | Tag functions as pure vs impure. Pure functions are safe to ignore during deobfuscation; impure ones (DOM writes, network calls, cookie access) need closer inspection. |
| 17 | **Closure Variable Resolution** | Resolve captured closure variables across function boundaries. Essential for understanding webpack module inter-dependencies and scope-hoisted code. |
| 18 | **Webpack Stats-Compatible Export** | Output function/module data in webpack stats JSON format — enables direct import into webpack-bundle-analyzer for visual dependency inspection. |
| 19 | **Minified Name Recovery** | Use statistical analysis (n-gram frequency, common JS identifier patterns) to suggest meaningful names for minified variables. Maps `a`, `b`, `c` -> `module`, `exports`, `require`. |

---

## Secret Detection — 5

| # | Feature | Description |
|---|---------|-------------|
| 20 | **Entropy-Based Secret Scoring** | Beyond regex matching — calculate Shannon entropy of matched strings. High-entropy strings (>4.5 bits/char) flagged even if no regex hit. Catches custom API keys, random tokens. |
| 21 | **Context-Aware Secret Validation** | Check surrounding code before reporting: `if (isProduction) { key = "..." }` vs `const key = "test_..."`. Downrank test/sample/mock context, uprank production-branch code. |
| 22 | **Secret Expiry/Pattern Evolution** | Compare secrets across multiple scans of the same target. Detect rotated keys, new key formats, deprecated patterns. Track version history per secret. |
| 23 | **False Positive Learning** | User marks a finding as FP once → auto-learn the context pattern (file name, surrounding code, variable name) and suppress similar findings in future scans. |
| 24 | **Credential Correlation Engine** | Cross-reference leaked secrets with known breach data (via haveibeenpwned API, dehashed). If a found API key pattern matches an exposed credential, elevate severity. |

---

## Pipeline & Automation — 5

| # | Feature | Description |
|---|---------|-------------|
| 25 | **Watch Mode (fs.watch)** | Continuously monitor a directory for new/changed JS files. Auto-run full pipeline on change. Essential for live-debugging targets that push new bundles frequently. |
| 26 | **Differential Analysis** | Compare two scan outputs (before/after deploy). Report only delta: new findings, removed findings, changed severity. Critical for regression hunting. |
| 27 | **Historical Trend Database** | Store scan results in SQLite (via better-sqlite3) or JSONL. Track finding counts over time, severity regression, recurring vulnerability classes. Export as time-series chart. |
| 28 | **Automated FP Feedback Loop** | When user confirms a finding is valid via a flag (--confirm), re-process it with higher confidence. When user flags as FP, update the FP rules JSON automatically. |
| 29 | **Multi-Repo Orchestration** | Accept a list of target URLs/domains. Auto-download JS bundles from each, run full pipeline, produce per-target and cross-target summary reports. |

---

## Reporting & Integration — 5

| # | Feature | Description |
|---|---------|-------------|
| 30 | **Interactive HTML Report** | Generate a self-contained HTML report with collapsible sections, severity heatmap, search/filter, and embedded code snippets with line highlighting. No server needed. |
| 31 | **SARIF Output** | Export findings in SARIF (Static Analysis Results Interchange Format) — enables importing into GitHub Code Scanning, VS Code Problems panel, Azure DevOps. |
| 32 | **HackerOne/Bugcrowd Draft Submission** | Auto-generate a draft submission from top findings: title, severity, CVSS vector, vulnerable code, impact, PoC. Pre-filled for manual review before submit. |
| 33 | **Webhook Alerting** | POST findings JSON to a configurable webhook (Slack, Discord, Teams) on scan completion. Configurable severity threshold (e.g., only CRITICAL+HIGH). |
| 34 | **GitHub Issue Creator** | For each CRITICAL finding, auto-create a GitHub issue with severity label, finding details, and code reference. Requires GITHUB_TOKEN. |

---

## Performance & Scale — 4

| # | Feature | Description |
|---|---------|-------------|
| 35 | **Worker Thread Pool** | Use Node.js worker_threads to parallelize file scanning across CPU cores. Each worker processes a file chunk independently. Target: 10x speedup on 85-file bundles. |
| 36 | **Incremental Analysis Cache** | Cache per-file results using MD5 of file content. Only re-scan files that changed since last run. First run does full scan; subsequent runs are ~10-50x faster. |
| 37 | **Streaming File Processing** | Process files as read streams instead of loading entire content into memory. Essential for 50MB+ minified bundles. Use Transform streams for pipeline stages. |
| 38 | **Memory-Budgeted Processing** | Track memory usage per stage. If heap exceeds configurable limit (e.g., 512MB), flush results to disk and restart. Prevents OOM on large-scale scans. |

---

## New Analysis Types — 2

| # | Feature | Description |
|---|---------|-------------|
| 39 | **WebAssembly Module Analysis** | Scan WASM sections embedded in JS (WebAssembly.compile, .wasm fetch). Extract import/export signatures, detect suspicious imports (process, exec, shell). |
| 40 | **Service Worker Security Audit** | Extract and analyze Service Worker registration code. Check for: cache-first of auth pages, message event handler injection, fetch event passthrough of credentials, Cache API abuse. |

---

## How to Contribute

Each feature is independent — pick any, implement in `js-chunk-toolkit/analyzers/` or `js-chunk-toolkit/utils/`, add the section to the report output, and verify with `node --check` + sample bundle.
