# JS Chunk Toolkit

**Deobfuscate, beautify, and extract secrets from webpack'd, minified, and obfuscated JavaScript bundles.**

Modern web apps ship thousands of lines of JS in webpack chunks — minified, concatenated, and often intentionally obfuscated. Buried inside are hardcoded API keys, internal admin endpoints, cloud credentials, hidden routes, and configuration leaks that produce instant Critical findings.

This toolkit is purpose-built for bug bounty hunters and security researchers who need to go from "I found a JS file" to "I have actionable secrets and endpoints" in one pipeline.

---

## What It Does

| Capability | Tool | Output |
|---|---|---|
| Detect obfuscation type | `deobfuscate.js` | Webpack / obfuscator.io / JSFuck / Packer / etc |
| Extract string arrays | `deobfuscate.js` | Base64, hex, unicode, fromCharCode decoded values |
| Extract webpack module map | `deobfuscate.js` + `webpack-chunk-extractor.js` | Module paths, interesting modules (api/admin/secret) |
| Find hidden chunks | `webpack-chunk-extractor.js` | Chunk hashes, public path, dynamic imports |
| Restore source maps | `source-map-restore.js` | Original variable names, comments, source code |
| Beautify minified JS | `batch-beautify.ps1` | Prettier output with framework detection |
| Scan for 45 secret patterns | `secret-scanner.ps1` | AWS keys, Stripe, JWT, GitHub tokens, OpenAI, endpoints |
| Deep vulnerability analysis | `analyzers/vulnerability-analyzer.js` | 22+ vuln classes, confidence scoring, risk scoring, data classification |
| AST-level deobfuscation | `analyzers/ast-deobfuscator.js` | Constant folding, boolean folding, array access eval, dead branch elimination |
| String array decoding | `analyzers/string-array-decoder.js` | vm.Script decoder emulation for shift/rotate/sort-based arrays |
| CFF recovery | `analyzers/cff-recovery.js` | Control flow flattening dispatcher detection and recovery feasibility |
| XSS prioritization | `analyzers/xss-prioritizer.js` | 22 sinks, 16 sources, proximity scoring — found CRITICAL chain on real bundle |
| Prototype pollution hunting | `analyzers/prototype-pollution-finder.js` | 12 PP patterns, 6 sink chains — found PP→RCE in webpack runtime |
| DOM clobbering detection | `analyzers/dom-clobbering-detector.js` | Form/ID shadowing, bare global access patterns |
| CSP bypass analysis | `analyzers/csp-bypass-analyzer.js` | 15 bypass gadgets, CSP header/meta extraction |
| Taint + indirect injection | `analyzers/taint-analyzer.js` | 19 sources, 13 sinks, 15 second-order injection patterns, DOT graph |
| Opaque predicate removal | `analyzers/opaque-predicate-remover.js` | 27 always-true/false patterns, if/else branch elimination |
| Dead code elimination | `analyzers/dead-code-eliminator.js` | 8 patterns, iterative passes |
| HTML report generation | `analyzers/html-report-generator.js` | Dark-theme HTML, search, collapsible severity cards |
| Entropy-based secret scoring | `utils/entropy-scorer.js` | Shannon entropy, 3 thresholds, JWT/GitHub/OpenAI detection |
| Context-aware validation | `utils/secret-validator.js` | 12 downrank/8 uprank patterns, context radius scoring |
| Secret evolution tracking | `utils/secret-evolution.js` | Cross-scan fingerprinting, rotation detection |
| Full automation | `run-all.ps1` | One-command pipeline: detect → extract → beautify → scan |
| Download bundles from any URL | `download-js.ps1` | HTML extraction + framework path fallback + source maps |

---

## Structure

```
js-chunk-toolkit/
  scripts/
    deobfuscate.js          Static analysis: strings, arrays, packers, webpack modules (30+ features)
    webpack-chunk-extractor.js  Webpack chunk manifest, dynamic imports, module map
    source-map-restore.js   Download .map files, restore original source, extract secrets
    batch-beautify.ps1      Batch prettier beautifier with framework detection
    run-all.ps1             Full pipeline orchestrator
    watch-mode.js           fs.watch-based live monitoring for new/changed JS
    diff-analyzer.js        Before/after scan comparison (added/removed/changed)
    scan-history.js         JSONL-based trend database with summary generation
    multi-repo-orchestrator.js  Batch processing multiple targets with per-target output
    sarif-output.js         SARIF 2.1.0 export (GitHub Code Scanning compatible)
    draft-generator.js      HackerOne/Bugcrowd draft submission pre-filler
    webhook-alerter.js      Slack block-kit webhook alerts with severity filter
    github-issue-creator.js Auto-create GitHub Issues for CRITICAL/HIGH findings
    worker-pool.js          Parallel file scanning via worker_threads
    streaming-processor.js  Transform stream pipeline for 50MB+ files
  scanners/
    secret-scanner.ps1      45 regex patterns — cloud keys, tokens, routes, credentials
  analyzers/
    vulnerability-analyzer.js   22+ vuln classes with confidence scoring + secret validation
    function-extractor.js       12 function types with IIFE/ESM/callback/async analysis
    dead-code-eliminator.js     8 dead code patterns, iterative removal passes
    xss-prioritizer.js          22 sinks, 16 sources, exploitability scoring, CRITICAL chain detection
    dom-clobbering-detector.js  Form/ID global shadowing, bare global access patterns
    prototype-pollution-finder.js  12 PP patterns + 6 post-PP sink chains
    csp-bypass-analyzer.js      15 bypass gadgets, CSP meta/header extraction
    ast-deobfuscator.js         vm.Script sandbox: 8 transform types (folding, eval, dead branch)
    string-array-decoder.js     Decoder function emulation via vm.Script for indexed string arrays
    cff-recovery.js             Control flow flattening: 3 dispatcher patterns, recovery feasibility
    taint-analyzer.js           19 sources, 13 sinks, indirect injection detection, DOT graph
    side-effect-analyzer.js     13 pure/impure pattern matcher, function tagging
    opaque-predicate-remover.js 27 always-true/false patterns, if/else branch elimination
    html-report-generator.js    Self-contained dark-theme HTML report with severity cards + search
    self-modifying-emulator.js  vm.Script sandbox: resolves eval/Function/setTimeout strings
    multi-packer-resolver.js    8 packer detectors, iterative unpacking (up to 20 layers)
    call-graph-builder.js       Function call graph with entry points, leaf nodes, DOT export
    closure-resolver.js         Closure variable capture detection across function boundaries
    name-recovery.js            N-gram frequency map for minified name suggestions
  utils/
    harden-base.js              Shared: ReDoS-safe regex, binary detection, 50MB limit, circular JSON
    entropy-scorer.js           Shannon entropy secret detection (3 thresholds, 8 pattern types)
    secret-validator.js         Context-aware validation (12 downrank, 8 uprank patterns)
    sink-source-analyzer.js     25 sources, 32 sinks, 9 attack chain mapping
    secret-evolution.js         Cross-scan fingerprinting, rotation detection, type classification
    fp-learner.js           JSONL-based false positive learning with --learn/--check/--confirm
    credential-correlator.js  23-pattern secret type detection with context scoring
    incremental-cache.js    MD5-based file caching for 10-50x faster re-scans
    memory-budget.js        MemoryBudgetTracker with auto-flush to prevent OOM
    download-js.ps1         Fetch JS bundles from any URL
  config/
    .prettierrc                 Prettier config for deobfuscation
    patterns.json               All regex patterns in structured JSON
    sink-source-map.json        Source/sink/chain configuration for data flow mapping
  output/                       All generated reports land here
  samples/                      Test files to verify the toolkit
```

---

## Quick Start

### 1. Download JS bundles from a target

```powershell
.\utils\download-js.ps1 -TargetUrl "https://target.com" -SourceMaps
```

Extracts all `<script src>`, `<link preload>`, and `<link modulepreload>` URLs from the HTML, downloads every JS file, and attempts source map download. Falls back to common framework paths (Next.js, CRA, Angular, Vue, Nuxt).

### 2. Run the full analysis pipeline

```powershell
# Against a local directory of JS bundles
.\scripts\run-all.ps1 -Target .\downloaded_js\

# One-liner: download + analyze
.\scripts\run-all.ps1 -Target "https://target.com" -DownloadBundles
```

The pipeline runs 8 steps automatically:

| Step | What It Does |
|---|---|
| 1. Framework Detection | Identifies Webpack, Next.js, Vue, Angular, React, SystemJS |
| 2. Chunk Analysis | Extracts module map, chunk hashes, public path, dynamic imports |
| 3. Deobfuscation | Decodes base64, hex, unicode, fromCharCode, string arrays |
| 4. Beautification | Prettier reformatting of all minified files |
| 5. Source Map Discovery | Finds sourceMappingURL refs and downloads .map files |
| 6. Secret Scanning | 45 patterns across cloud creds, API keys, tokens, internal routes |
| 7. AST Deobfuscation | Constant folding, string array decoding, CFF recovery, opaque predicates |
| 8. Vulnerability Analysis | 22+ vuln classes, XSS prioritization, PP hunting, CSP bypass, taint analysis |

All reports land in `output/<timestamp>/reports/` and `output/<timestamp>/scanner_reports/`.

### 3. Run individual tools

```powershell
# Detect obfuscation type and extract all hidden strings
node .\scripts\deobfuscate.js .\downloaded_js\

# Webpack-specific analysis
node .\scripts\webpack-chunk-extractor.js .\downloaded_js\

# Restore source maps
node .\scripts\source-map-restore.js .\sourcemaps\

# Beautify all JS files
.\scripts\batch-beautify.ps1 -InputPath .\downloaded_js\ -Recurse

# Scan for secrets only
.\scanners\secret-scanner.ps1 -InputPath .\downloaded_js\ -Recurse
```

---

## What Secrets Are Detected

45 patterns organized by severity:

**CRITICAL** — Direct cloud access
- AWS Access Key ID (`AKIA...`)
- AWS Secret Access Key
- GCP API Key (`AIza...`)
- GCP Service Account JSON
- Stripe Live Secret Key (`sk_live_...`)
- GitHub Personal Access Token (`ghp_...`)
- OpenAI API Key (`sk-...`)
- Database Connection Strings (MongoDB, PostgreSQL, MySQL, Redis)

**HIGH** — Privilege escalation / lateral movement
- Stripe Publishable Key
- Slack Bot/User/App/Webhook Tokens
- SendGrid API Keys
- Twilio SID + Auth Token
- GitHub OAuth Secrets
- Google OAuth Client IDs
- Auth0 Client IDs
- Internal IP URLs (10.x, 192.168.x, 172.16-31.x)
- Internal Service URLs
- Admin Routes (`/admin`, `/dashboard`, `/console`, `/panel`)
- API Endpoints (`/api/v1`, `/graphql`, `/rest`)

**MEDIUM** — Information disclosure
- JWT Tokens
- Firebase URLs
- Auth0 Domains
- Development/Staging URLs
- Test Account Credentials
- Algolia API Keys
- Localhost URLs
- Mapbox Tokens

**LOW** — Reconnaissance value
- Google Analytics IDs
- Sentry DSNs
- Datadog App IDs
- High-entropy strings (potential custom keys)

---

## What Obfuscation Types Are Detected

| Type | Detection Signature |
|---|---|
| Webpack | `__webpack_require__` |
| javascript-obfuscator | `_0x[a-f0-9]{4,6}` + string arrays |
| obfuscator.io | Self-defending `_0x... = !![]` |
| JSFuck | Only `[]()!+` characters |
| aaencode | Full-width Unicode + emoticons |
| jjencode | `$ = ~[]` patterns |
| Packer (eval-based) | `eval(function(p,a,c,k,e,d)` |
| Control Flow Flattened | `while(true){switch(...){...}}` |
| Jscrambler | `S139/S162` signatures |
| UglifyJS / Terser | `function(a,b,c){` (minified only) |

---

## Requirements

| Dependency | Required For |
|---|---|
| **Node.js 18+** | `deobfuscate.js`, `webpack-chunk-extractor.js`, `source-map-restore.js` |
| **PowerShell 5.1+** | `batch-beautify.ps1`, `run-all.ps1`, `secret-scanner.ps1`, `download-js.ps1` |
| **curl.exe** (Windows bundled) | Downloading bundles and source maps |
| **npx** (Node.js bundled) | Prettier beautification (auto-downloaded on first run) |

Optional install for better output:
```powershell
npm install -g prettier
```

---

## Usage Examples by Use Case

### Bug Bounty Recon on a New Target

```powershell
# Step 1: Download all JS
.\utils\download-js.ps1 -TargetUrl "https://target.com" -SourceMaps

# Step 2: Full pipeline
.\scripts\run-all.ps1 -Target .\downloaded_js\
```

Check `output/scanner_reports/critical_findings.txt` first — anything Critical goes straight to a report.

### Analyzing a Specific Next.js App

```powershell
.\utils\download-js.ps1 -TargetUrl "https://target.com"
# Then pipeline
.\scripts\run-all.ps1 -Target .\downloaded_js\
```

Next.js pages are at `/_next/static/chunks/pages/`. The webpack extractor will identify per-page chunks.

### Reversing a Heavily Obfuscated Bundle

```powershell
node .\scripts\deobfuscate.js obfuscated-bundle.js
```

Check the "Obfuscation Detection" section first. If it says "obfuscator.io" or "javascript-obfuscator", the string array extractor will dump all hidden strings including API URLs and credentials.

### Scanning an Existing JS Directory for Secrets

```powershell
.\scanners\secret-scanner.ps1 -InputPath .\js-bundles\ -Recurse -CSVOutput -JSONOutput
```

Produces `secrets_report.json`, `secrets_report.csv`, and `critical_findings.txt`.

---

## Output Structure

```
output/
  reports/
    chunk-analysis.txt           Webpack module map + chunk listing
    deobfuscation-report.txt     String extraction results
    sourcemaps.csv               List of discovered source map URLs
    sourcemap-restore.txt        Secrets found in restored source maps
  scanner_reports/
    secrets_report.json          All findings in structured JSON
    secrets_report.csv           All findings in CSV
    critical_findings.txt        Only CRITICAL severity findings
  beautified/
    *.js                         Prettier-formatted versions of all bundles
```

---

## What Gets Found in the Sample

The included sample (`samples/sample-webpack-bundle.js`) simulates a real-world webpack bundle with:

- **3 AWS credentials** (AKIA key, live secrets)
- **2 GCP API keys** (AIza prefix)
- **1 GitHub PAT** (ghp_ format)
- **1 OpenAI key** (sk- format)
- **1 Stripe test key** (base64 encoded)
- **1 Firebase URL** (base64 encoded)
- **4 internal API endpoints** (including staging and 10.x IPs)
- **7 admin routes** (/admin/users, /admin/settings, etc.)
- **2 admin test accounts** with passwords
- **1 SendGrid key** + **1 Twilio SID**
- **1 JWT token**
- **Hex, unicode, and fromCharCode encoded URLs**

Run `.\scanners\secret-scanner.ps1 -InputPath .\samples\` to see 22 findings classified by severity.

---

## Pipeline Demo

```powershell
.\scripts\run-all.ps1 -Target .\samples\ -OutputDir .\output\demo
```

Output:
```
beautified/          → Prettier-formatted JS
reports/             → chunk analysis + deobfuscation results
scanner_reports/     → 22 findings: 3 CRITICAL, 12 HIGH, 5 MEDIUM, 2 LOW
```
