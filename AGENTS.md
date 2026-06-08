# Hercules-Hunt Agent Registry

This file registers all agents for OpenCode and other agentic CLI tools that use AGENTS.md format.

## Registration Format

Each agent entry follows:
```yaml
- name: <agent-name>
  description: <short description of what the agent does>
  tools: [tool1, tool2, ...]
  file: <path to agent definition file>
```

## Agent List

### recon-agent
- **description:** Subdomain enumeration and live host discovery specialist. Runs passive/active subdomain enum, URL crawling, technology fingerprinting, and nuclei scanning. Produces prioritized attack surface for a target domain.
- **tools:** Bash, Read, Write, Glob, Grep
- **file:** agents/recon-agent.md
- **invoke:** "Run recon on target.com"

### recon-ranker
- **description:** Attack surface ranking and prioritization agent. Takes recon output and produces a prioritized attack plan. Ranks by IDOR likelihood, API surface, tech stack match, feature age, and nuclei findings.
- **tools:** Read, Bash, Glob, Grep
- **file:** agents/recon-ranker.md
- **invoke:** "Rank attack surface for target.com"

### p1-warrior
- **description:** Priority-1 bug hunter coordinator. Reads recon-ranker output, selects top bug classes by tech stack, and delegates to specialist sub-agents (idor-hunter, ssrf-hunter, xss-hunter, auth-bypass-hunter, race-condition-hunter, business-logic-hunter, file-upload-hunter, api-misconfig-hunter, graphql-hunter, ssti-hunter). Time-boxes 10 min per sub-agent.
- **tools:** Read, Write, Bash, Glob, Grep, WebFetch, Task
- **file:** agents/p1-warrior.md
- **invoke:** "Hunt target.com for high vulnerabilities"

### chain-builder
- **description:** Exploit chain builder. Takes confirmed bug A and systematically finds B and C to chain for higher severity. Covers IDOR→auth bypass, SSRF→cloud metadata, XSS→ATO, open redirect→OAuth theft, S3→bundle→secret→OAuth, prompt injection→IDOR, subdomain takeover→OAuth.
- **tools:** Read, Bash, WebFetch
- **file:** agents/chain-builder.md
- **invoke:** "Chain IDOR with auth bypass for higher severity"

### js-analysis
- **description:** JavaScript bundle analysis specialist. Extracts hidden API endpoints, hardcoded secrets, internal paths, feature flags, cloud keys, OAuth credentials, and configuration leaks from JS bundles. Supports browser DevTools and CLI-based extraction.
- **tools:** Read, Write, Bash, Glob, Grep, WebFetch
- **file:** agents/js-analysis.md
- **invoke:** "Analyze JS bundles for secrets on target.com"

### js-deobfuscation
- **description:** JavaScript deobfuscation and reverse engineering specialist. Reverses minified/obfuscated JS bundles to recover hidden endpoints, secrets, and logic. Handles webpack bundles, obfuscated strings, encoded payloads, eval-based obfuscation, and VM-protected code.
- **tools:** Read, Write, Bash, Glob, Grep, WebFetch
- **file:** agents/js-deobfuscation.md
- **invoke:** "Deobfuscate this JavaScript bundle"

### report-writer
- **description:** Professional bug bounty report writer. Generates HackerOne, Bugcrowd, Intigriti, and Immunefi reports. Impact-first writing, no theoretical language, CVSS 4.0 calculation included. Never uses 'could potentially' language.
- **tools:** Read, Write, Bash
- **file:** agents/report-writer.md
- **invoke:** "Write report for IDOR finding on target.com"

### validator
- **description:** Finding validator that runs the 7-Question Gate and 4-gate checklist. Kills weak/theoretical findings fast before report writing. Prevents N/A submissions. Can PASS, KILL, DOWNGRADE, or CHAIN REQUIRED a finding.
- **tools:** Read, Bash, WebFetch
- **file:** agents/validator.md
- **invoke:** "Validate this IDOR finding before I write a report"

### autopilot
- **description:** Autonomous hunt loop agent. Runs full cycle (scope → recon → rank → hunt → validate → report) without stopping for approval at each step. Configurable checkpoints (--paranoid, --normal, --yolo). Logs all requests to audit.jsonl.
- **tools:** Bash, Read, Write, Glob, Grep
- **file:** agents/autopilot.md
- **invoke:** "Run autopilot on target.com in normal mode"

### exploit-researcher
- **description:** Vulnerability research agent. Identifies CVEs, finds exploit PoCs, maps attack chains, develops custom exploitation strategies. Covers NVD API, GitHub Advisories, Exploit-DB, CISA KEV.
- **tools:** Read, Write, Bash, Glob, Grep, WebFetch
- **file:** agents/exploit-researcher.md
- **invoke:** "Research CVEs for nginx 1.24"

### network-analyst
- **description:** Deep network analysis agent. Packet inspection, protocol dissection, traffic anomaly detection, IDS/IPS rule creation, firewall auditing. Covers TCP/IP, DNS, TLS, HTTP/2/3, SMB, Kerberos.
- **tools:** Read, Write, Bash, Glob, Grep
- **file:** agents/network-analyst.md
- **invoke:** "Analyze this packet capture for anomalies"

### redteam-planner
- **description:** Red team engagement planner. Designs attack paths, C2 infrastructure, persistence strategies, and OPSEC considerations. MITRE ATT&CK mapped. Covers recon, initial access, execution, persistence, privilege escalation, defense evasion, lateral movement.
- **tools:** Read, Write, Bash, Glob, Grep, WebFetch
- **file:** agents/redteam-planner.md
- **invoke:** "Plan red team engagement for target company"

### reverse-engineer
- **description:** Binary analysis and reverse engineering specialist. Static/dynamic analysis, vulnerability discovery in compiled code, firmware analysis, protocol reverse engineering. Uses IDA Pro, Ghidra, radare2, Frida, angr, z3.
- **tools:** Read, Write, Bash, Glob, Grep
- **file:** agents/reverse-engineer.md
- **invoke:** "Analyze this binary for vulnerabilities"

### security-reviewer
- **description:** Deep security audit agent. Reviews code and architecture against OWASP Top 10, CWE Top 25. Language-specific patterns for JavaScript, Python, Ruby, Java, C#, Go. Trust boundary and data flow analysis.
- **tools:** Read, Write, Bash, Glob, Grep
- **file:** agents/security-reviewer.md
- **invoke:** "Review this code for security vulnerabilities"

### ai-researcher
- **description:** AI/ML security research specialist. LLM red-teaming, prompt injection testing, model architecture analysis, training optimization, safety alignment. Covers direct/indirect injection, system prompt extraction, jailbreak techniques.
- **tools:** Read, Write, Bash, Glob, Grep, WebFetch
- **file:** agents/ai-researcher.md
- **invoke:** "Test this LLM endpoint for prompt injection"

### token-auditor
- **description:** Meme coin and token security auditor. Checks 8 token-specific bug classes: hidden mint, honeypot, fee manipulation, LP drain, bonding curve exploits, authority retention, fake renounce, sandwich/MEV amplification. EVM + Solana.
- **tools:** Read, Bash, Glob, Grep
- **file:** agents/token-auditor.md
- **invoke:** "Audit this meme coin for rug pull vectors"

### web3-auditor
- **description:** Smart contract security auditor. Checks 10 bug classes: accounting desync, access control, incomplete path, off-by-one, oracle errors, ERC4626 attacks, reentrancy, flash loan oracle manipulation, signature replay, proxy issues.
- **tools:** Read, Bash, Glob, Grep
- **file:** agents/web3-auditor.md
- **invoke:** "Audit this smart contract for vulnerabilities"

### mobile-testing-agent
- **description:** Mobile application security testing specialist. Android APK & iOS IPA acquisition, decompilation (jadx/apktool), static analysis, secret/endpoint extraction, Frida instrumentation, SSL pinning bypass, WebView attack surface, deep-link injection, Firebase recon, and Burp proxy setup for mobile traffic.
- **tools:** Read, Write, Bash, Glob, Grep
- **file:** agents/mobile-testing-agent.md
- **invoke:** "Test the mobile app for target.com"

### windows-workflow-agent
- **description:** Windows-native bug bounty hunting workflow specialist. curl.exe mastery, PowerShell alternatives to Linux tools, Burp Suite on Windows, ffuf/nuclei/httpx setup, JS bundle analysis, batch scripting, WSL integration.
- **tools:** Read, Write, Bash, Glob, Grep
- **file:** agents/windows-workflow-agent.md
- **invoke:** "Run Windows recon workflow for target.com"

### chain-rules-agent
- **description:** Vulnerability chaining methodology specialist. Chain philosophy, decision tree for chaining vs separate submission, chain primitive taxonomy, common chain patterns (IDOR->auth bypass, SSRF->cloud metadata, XSS->ATO), severity multiplication. Methodology counterpart to chain-builder.
- **tools:** Read, Write, Bash, Glob, Grep
- **file:** agents/chain-rules-agent.md
- **invoke:** "Analyze chain primitives for these findings"

### program-researcher
- **description:** Bug bounty program researcher. Analyzes program scope, rules, past disclosed reports, tech stack, and attack surface before hunting begins. Produces a target brief with in-scope/out-of-scope boundaries, known bugs, and high-likelihood vulnerability classes.
- **tools:** Read, Bash, WebFetch, Grep
- **file:** agents/program-researcher.md
- **invoke:** "Research target.com program"

### orchestrator
- **description:** Recon-to-report pipeline orchestrator. Runs the full hunting cycle end-to-end: scope → recon → rank → research → hunt → chain → validate → review → defend → report. Delegates each phase to the appropriate specialist agent.
- **tools:** Read, Write, Bash, Glob, Grep, Task
- **file:** agents/orchestrator.md
- **invoke:** "Run full pipeline on target.com"

### browser-automator
- **description:** Browser automation specialist. Uses Playwright for multi-step login flows, blind XSS callback detection, DOM-based testing, OAuth flow analysis, and session handling without manual DevTools work.
- **tools:** Read, Write, Bash, Glob, Grep
- **file:** agents/browser-automator.md
- **invoke:** "Automate browser for target.com login"

### evidence-reviewer
- **description:** Evidence quality control agent. Reviews PoC screenshots, HAR files, curl commands, and callback logs. Enforces cookie redaction, PII masking, HAR sanitization, and PoC reproducibility before submission.
- **tools:** Read, Write, Bash, Grep
- **file:** agents/evidence-reviewer.md
- **invoke:** "Review evidence for target.com finding"

### triage-defender
- **description:** Triage defense agent. Anticipates triager objections, rebuts OOS claims, counters severity downgrades, and prepares triage-ready evidence before submission. Reads VRT and past N/A patterns to prevent rejections.
- **tools:** Read, Write, Bash
- **file:** agents/triage-defender.md
- **invoke:** "Defend target.com finding against triage"

## Specialist Hunter Sub-Agents

### idor-hunter
- **description:** IDOR specialist. Hunts horizontal/vertical IDOR across API endpoints, file downloads, profile pages, invoice/order IDs, and UUID-based access patterns.
- **tools:** Read, Write, Bash, Glob, Grep, WebFetch
- **file:** agents/idor-hunter.md
- **invoke:** "Hunt IDOR on target.com"

### ssrf-hunter
- **description:** SSRF specialist. Hunts SSRF in file uploads, URL fetch endpoints, PDF generators, webhook callbacks, redirect followers, proxy endpoints, and image processing services.
- **tools:** Read, Write, Bash, Glob, Grep, WebFetch
- **file:** agents/ssrf-hunter.md
- **invoke:** "Hunt SSRF on target.com"

### xss-hunter
- **description:** XSS specialist. Hunts reflected, stored, DOM-based, and blind XSS across all input vectors: URL params, form fields, headers, file uploads, JSON bodies.
- **tools:** Read, Write, Bash, Glob, Grep, WebFetch
- **file:** agents/xss-hunter.md
- **invoke:** "Hunt XSS on target.com"

### auth-bypass-hunter
- **description:** Auth bypass specialist. Hunts auth flaws across login flows, password resets, MFA/2FA, session handling, JWT validation, OAuth flows, and role-based access control.
- **tools:** Read, Write, Bash, Glob, Grep, WebFetch
- **file:** agents/auth-bypass-hunter.md
- **invoke:** "Hunt auth bypass on target.com"

### race-condition-hunter
- **description:** Race condition specialist. Hunts TOCTOU bugs, concurrent request races on coupon/balance/stock endpoints, parallel action exploits, and boundary condition races.
- **tools:** Read, Write, Bash, Glob, Grep
- **file:** agents/race-condition-hunter.md
- **invoke:** "Hunt race conditions on target.com"

### business-logic-hunter
- **description:** Business logic vulnerability specialist. Hunts logic flaws in multi-step workflows, state transitions, privilege escalation paths, financial operations, cart/checkout flows, and rule enforcement loopholes.
- **tools:** Read, Write, Bash, Glob, Grep, WebFetch
- **file:** agents/business-logic-hunter.md
- **invoke:** "Hunt business logic flaws on target.com"

### file-upload-hunter
- **description:** File upload vulnerability specialist. Hunts RCE via webshell, XSS via SVG/HTML, SSRF via XXE in DOCX, path traversal via filename, and all file-processing exploits.
- **tools:** Read, Write, Bash, Glob, Grep, WebFetch
- **file:** agents/file-upload-hunter.md
- **invoke:** "Hunt file upload bugs on target.com"

### api-misconfig-hunter
- **description:** API misconfiguration specialist. Hunts mass assignment, JWT attacks, prototype pollution, CORS misconfigs, HTTP verb tampering, and GraphQL introspection leaks.
- **tools:** Read, Write, Bash, Glob, Grep, WebFetch
- **file:** agents/api-misconfig-hunter.md
- **invoke:** "Hunt API misconfigs on target.com"

### graphql-hunter
- **description:** GraphQL vulnerability specialist. Hunts introspection leaks, batching attacks, query depth abuse, mass assignment through mutations, IDOR in GraphQL queries, and auth flaws in resolvers.
- **tools:** Read, Write, Bash, Glob, Grep, WebFetch
- **file:** agents/graphql-hunter.md
- **invoke:** "Hunt GraphQL bugs on target.com"

### ssti-hunter
- **description:** SSTI specialist. Hunts template injection in Jinja2, Twig, Freemarker, ERB, Velocity, Mako, Thymeleaf, Smarty, and Pug. Detects via math evaluation probes and escalates to RCE.
- **tools:** Read, Write, Bash, Glob, Grep, WebFetch
- **file:** agents/ssti-hunter.md
- **invoke:** "Hunt SSTI on target.com"
