# JS Chunk Analysis Toolkit — Roadmap

40 features to add next, grouped by capability domain.

---

## Deobfuscation Engine — 7

| # | Feature | Description |
|---|---------|-------------|
| 1 | **AST-based Deobfuscation** | ✅ `analyzers/ast-deobfuscator.js` — constant folding (string concat, math, boolean), array access eval, ternary reduction, dead branch elimination, JSFuck primitive folding. 8 transform types, iterative until stable. |
| 2 | **String Array Decoder** | ✅ `analyzers/string-array-decoder.js` — vm.Script sandbox emulation, decoder function extraction, encoder operation detection (shift/pop/splice), bulk reference replacement. |
| 4 | **Control Flow Flattening Recovery** | ✅ `analyzers/cff-recovery.js` — 3 dispatcher pattern detectors, state reachability analysis, recovery feasibility scoring. Found HEAVY_CFF (score 54) on real bundle. |
| 5 | **Opaque Predicate Removal** | ✅ `analyzers/opaque-predicate-remover.js` — 27 always-true/false predicate patterns, if/else branch elimination, confidence scoring (CERTAIN/HIGH). 25 constant folding patterns + block eliminator. |
| 6 | **Self-Modifying Code Emulation** | ✅ `analyzers/self-modifying-emulator.js` — vm.Script sandbox with 200ms timeout. Resolves eval, Function(), setTimeout strings, atob, fromCharCode. Tracks resolved vs failed. |
| 7 | **Multi-Packer Chain Resolution** | ✅ `analyzers/multi-packer-resolver.js` — 8 packer detectors, iterative unpacking (up to 20 layers), Packer eval, atob→eval, double eval, chained decode. |

---

## Vulnerability Analysis — 7

| # | Feature | Description |
|---|---------|-------------|
| 8 | **Taint Tracking (Data Flow)** | ✅ `analyzers/taint-analyzer.js` — 19 source types, 13 sink types, proximity-based chain detection, DOT graph output, severity weighting. |
| 9 | **Sink-Source Mapping Database** | ✅ `config/sink-source-map.json` + `utils/sink-source-analyzer.js` — 25 sources, 32 sinks, 9 pre-built attack chains. Scores by source proximity. |
| 10 | **DOM Clobbering Detection** | ✅ `analyzers/dom-clobbering-detector.js` — form child clobbering, ID global shadowing, bare global access patterns. Found 3 clobberable globals on real bundle. |
| 11 | **Prototype Pollution Gadget Finder** | ✅ `analyzers/prototype-pollution-finder.js` — 12 PP patterns, 6 post-PP sink chains. Found real __proto__ assignment + child_process chain on webpack runtime. |
| 12 | **CSP Bypass Analysis** | ✅ `analyzers/csp-bypass-analyzer.js` — 15 bypass gadgets, CSP extraction from meta/headers. Found `unsafe-eval` + inline handler bypass on production bundle. |
| 13 | **DOM-based XSS Sink Prioritization** | ✅ `analyzers/xss-prioritizer.js` — 22 sink patterns, 16 proximity sources, exploitability scoring, CVSS weighting. Found CRITICAL chain on real bundle. |
| 14 | **Indirect Injection Detection** | ✅ `analyzers/taint-analyzer.js` — 15 second-order injection patterns (localStorage/cookie/hash/postMessage → innerHTML/eval/fetch/Function). |

---

## Function & Module Analysis — 5

| # | Feature | Description |
|---|---------|-------------|
| 15 | **Function Call Graph** | ✅ `analyzers/call-graph-builder.js` — Extract function defs, map call sites, identify entry points and leaf nodes, DOT graph export. |
| 16 | **Side-Effect Analysis** | ✅ `analyzers/side-effect-analyzer.js` — 13 impure patterns: DOM, network, cookie, storage, eval, console, timer, location, alerts, process, fs. Tags functions as pure/impure. |
| 17 | **Closure Variable Resolution** | ✅ `analyzers/closure-resolver.js` — Captured variable detection across function boundaries. Identifies closure-scoped references and parameter hoisting. |
| 18 | **Webpack Stats-Compatible Export** | ✅ Added to `analyzers/function-extractor.js` — `--webpack-stats` flag outputs webpack 5.0 stats JSON format (compatible with webpack-bundle-analyzer). |
| 19 | **Minified Name Recovery** | ✅ `analyzers/name-recovery.js` — 26-letter n-gram frequency map. Suggests meaningful names (e.g. `a`→`args`, `p`→`param`, `s`→`source`). Detects hex-encoded names from obfuscator.io. |

---

## Secret Detection — 5

| # | Feature | Description |
|---|---------|-------------|
| 20 | **Entropy-Based Secret Scoring** | ✅ `utils/entropy-scorer.js` — Shannon entropy, 3 thresholds (4.5/3.5/2.5), 8 pattern types, integrated into deobfuscate.js feature #31. Catches JWT, GitHub tokens, OpenAI keys. |
| 21 | **Context-Aware Secret Validation** | ✅ `utils/secret-validator.js` — 12 downrank, 8 uprank patterns, context radius scoring, entropy blending. Integrated into vulnerability-analyzer findings. |
| 22 | **Secret Expiry/Pattern Evolution** | ✅ `utils/secret-evolution.js` — JSONL-based scan history, fingerprinting, rotation detection, type classification. Tracks new/rotated/stable secrets across scans. |
| 23 | **False Positive Learning** | ✅ `utils/fp-learner.js` — JSONL-based rule learning with --learn/--check/--confirm commands. Matches by pattern, context, file pattern. Auto-suppresses known FPs. |
| 24 | **Credential Correlation Engine** | ✅ `utils/credential-correlator.js` — 23 secret patterns, context-aware matching, severity scoring (20+→CRITICAL). Standalone CLI + breach DB check. |

---

## Pipeline & Automation — 5

| # | Feature | Description |
|---|---------|-------------|
| 25 | **Watch Mode (fs.watch)** | ✅ `scripts/watch-mode.js` — fs.watch with recursive flag, 500ms debounce, auto-runs configurable command on new/changed JS files. |
| 26 | **Differential Analysis** | ✅ `scripts/diff-analyzer.js` — JSON diff of scan outputs. Reports added/removed/common findings, severity changes, per-file deltas. |
| 27 | **Historical Trend Database** | ✅ `scripts/scan-history.js` — JSONL append-only log. recordScan/getHistory/generateSummary. Tracks scan count, unique targets, severity trends over time. |
| 28 | **Automated FP Feedback Loop** | ✅ Added to `utils/fp-learner.js` — `--confirm` flag increments confirmation count. Supports configurable FP rules JSON at `config/fp-rules.json`. |
| 29 | **Multi-Repo Orchestration** | ✅ `scripts/multi-repo-orchestrator.js` — JSON config or comma-separated targets. Per-target output dirs, deobfuscation + download pipelines, cross-target summary. |

---

## Reporting & Integration — 5

| # | Feature | Description |
|---|---------|-------------|
| 30 | **Interactive HTML Report** | ✅ `analyzers/html-report-generator.js` — dark-theme HTML, severity cards, real-time search/filter, collapsible detail rows, code highlighting. Self-contained 7KB output. |
| 31 | **SARIF Output** | ✅ `scripts/sarif-output.js` — Full SARIF 2.1.0 spec. Maps severity to error/warning/note levels. Artifact tracking, region info, properties block. |
| 32 | **HackerOne/Bugcrowd Draft Submission** | ✅ `scripts/draft-generator.js` — Platform-aware drafts (H1 inline/bugcrowd VRT). Severity-sorted, top-5 CRITICAL/HIGH pre-filled with impact + PoC. |
| 33 | **Webhook Alerting** | ✅ `scripts/webhook-alerter.js` — Slack block-kit formatting. Severity threshold filter, HTTPS POST with timeout. Reports CRITICAL/HIGH findings. |
| 34 | **GitHub Issue Creator** | ✅ `scripts/github-issue-creator.js` — Creates GitHub Issues with severity labels. Falls back to JSONL when no GITHUB_TOKEN set. `curl`-based API calls. |

---

## Performance & Scale — 4

| # | Feature | Description |
|---|---------|-------------|
| 35 | **Worker Thread Pool** | ✅ `scripts/worker-pool.js` — Dynamic worker allocation (up to CPU count). Inline worker script for scanner patterns. Per-file finding aggregation. |
| 36 | **Incremental Analysis Cache** | ✅ `utils/incremental-cache.js` — MD5-based file fingerprinting (size + mtime + first 4KB). Cache stored as JSON at `output/.cache/`. --clear flag to reset. |
| 37 | **Streaming File Processing** | ✅ `scripts/streaming-processor.js` — Node.js Transform stream pipeline. Chunk-level scanning with configurable buffer. Handles files >50MB without loading entire content. |
| 38 | **Memory-Budgeted Processing** | ✅ `utils/memory-budget.js` — `MemoryBudgetTracker` with configurable heap limit. Auto-flush to disk when budget exceeded. `--max-heap` CLI flag. |

---

## New Analysis Types — 2

| # | Feature | Description |
|---|---------|-------------|
| 39 | **WebAssembly Module Analysis** | Scan WASM sections embedded in JS (WebAssembly.compile, .wasm fetch). Extract import/export signatures, detect suspicious imports (process, exec, shell). |
| 40 | **Service Worker Security Audit** | Extract and analyze Service Worker registration code. Check for: cache-first of auth pages, message event handler injection, fetch event passthrough of credentials, Cache API abuse. |

---

## How to Contribute

Each feature is independent — pick any, implement in `js-chunk-toolkit/analyzers/` or `js-chunk-toolkit/utils/`, add the section to the report output, and verify with `node --check` + sample bundle.
