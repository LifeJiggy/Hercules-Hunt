# Jiggy-2026 JavaScript Client-Side Hunting Toolkit

P1 warrior tools for browser control, client-side tracing, and hunting critical/high severity bugs.

## Tools (15 total)

### General Tools
| # | Tool | Description |
|---|------|-------------|
| 1 | **browser-automation** | Playwright browser — navigate, fill forms, screenshot, intercept traffic, HAR export |
| 2 | **dom-manipulation** | DOM querying, mutation observation, element inject/remove, storage/cookie inspection |
| 3 | **user-functionalities** | Login/logout/register flows, multi-account management, OAuth, session save/restore |
| 4 | **parameters** | URL/body parameter extraction, mutation, pollution testing, name fuzzing, attack wordlists |
| 5 | **api-fuzzer** | HTTP method/header/param/content-type fuzzing, rate-limit testing, full API scan |
| 6 | **token-analyzer** | JWT decode, alg=none, brute-force, JWK injection, kid traversal, token confusion |
| 7 | **endpoint-collector** | JS bundle fetch, regex endpoint extraction, secret hunting, source-map parsing, recursive crawl |

### P1 Client-Side Hunter Tools
| # | Tool | Description |
|---|------|-------------|
| 8 | **session-hijacker** | Cookie security audit, session fixation testing, entropy analysis, storage token detection |
| 9 | **xss-hunter** | DOM/reflected/stored XSS detection, mXSS, CSP audit, polyglot payload generator |
| 10 | **csrf-tester** | CSRF token strength, SameSite cookie audit, CORS misconfig, PoC generator |
| 11 | **prototype-pollution** | Prototype pollution detection, DOM clobbering, library gadget identification |
| 12 | **postmessage-explorer** | postMessage listener enumeration, origin validation, XSS chain, window.opener audit |
| 13 | **storage-auditor** | localStorage/IndexedDB/CacheAPI audit, 18 PII/secret patterns, cookie jar, remnants |
| 14 | **event-inspector** | Event listener enumeration, clickjacking test, UI redressing, keyboard/mouse capture |
| 15 | **client-side-scanner** | **Orchestrator** — runs all 14 tools, generates consolidated JSON+Markdown report |

## Quick Start

```bash
# Interactive launcher (asks what you want to do)
node launcher.js

# Full client-side scan (non-interactive)
node client-side-scanner.js https://target.com
node client-side-scanner.js https://target.com --headless
```

## Full Scan Report

Running the orchestrator (`client-side-scanner`) executes all 14 tools against a URL and produces:

- `output/client-side-scan/client-side-scan.json` — full structured report
- `output/client-side-scan/client-side-scan.md` — prioritized findings with action items

Report includes:
- Findings sorted by severity: CRITICAL → HIGH → MEDIUM → LOW
- P1 Warrior action item checklist
- Per-tool raw results for chain analysis

## Architecture

```
launcher.js          — Interactive CLI menu (asks, runs, loops)
index.js             — Central require/exports all 15 tools
client-side-scanner.js — Orchestrator (auto-runs all tools, consolidated report)

browser-automation.js  ─┐
dom-manipulation.js     │
user-functionalities.js ├── General purpose
parameters.js           │
api-fuzzer.js           │
token-analyzer.js       │
endpoint-collector.js  ─┘

session-hijacker.js    ─┐
xss-hunter.js           │
csrf-tester.js          │
prototype-pollution.js  ├── P1 Client-Side Hunter
postmessage-explorer.js │
storage-auditor.js      │
event-inspector.js     ─┘
```

## Usage from Code

```js
const { BrowserAutomation, XSSHunter, ClientSideScanner } = require('./index');

// Use individual tools
const ba = new BrowserAutomation();
await ba.launch();
await ba.navigate('https://target.com');

// Run XSS scan
const xss = new XSSHunter(ba.page);
const results = await xss.fullScan();

// Full automated scan
const scanner = new ClientSideScanner({ headless: true });
await scanner.scan('https://target.com');
```

## Dependencies

- `playwright` — browser automation (required for tools 1-3, 8-15)
- Node.js built-ins: `http`, `https`, `crypto`, `fs`, `path`, `url`

```bash
npm install playwright
```
