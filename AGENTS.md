# Hercules-Hunt Agent Registry

This file registers all agents for OpenCode and other agentic CLI tools that use AGENTS.md format.

## Registration Format

Each agent entry follows:
```yaml
- name: <agent-name>
  description: <short description of what the agent does>
  tools: [tool1, tool2, ...]
  model: <model-name>
  file: <path to agent definition file>
```

## Agent List

### recon-agent
- **description:** Subdomain enumeration and live host discovery specialist. Runs passive/active subdomain enum, URL crawling, technology fingerprinting, and nuclei scanning. Produces prioritized attack surface for a target domain.
- **tools:** Bash, Read, Write, Glob, Grep
- **model:** claude-haiku-4-5-20251001
- **file:** agents/recon-agent.md
- **invoke:** "Run recon on target.com"

### recon-ranker
- **description:** Attack surface ranking and prioritization agent. Takes recon output and produces a prioritized attack plan. Ranks by IDOR likelihood, API surface, tech stack match, feature age, and nuclei findings.
- **tools:** Read, Bash, Glob, Grep
- **model:** claude-haiku-4-5-20251001
- **file:** agents/recon-ranker.md
- **invoke:** "Rank attack surface for target.com"

### p1-warrior
- **description:** Priority-1 systematic bug hunter. Combines recon output with intelligent testing to find high/critical bugs fast. Works P1 targets, cycles through bug classes by likelihood, time-boxes 10 min per test. Covers IDOR, SSRF, XSS, auth bypass, mass assignment, business logic.
- **tools:** Read, Write, Bash, Glob, Grep, WebFetch
- **model:** claude-sonnet-4-6
- **file:** agents/p1-warrior.md
- **invoke:** "Hunt target.com for high vulnerabilities"

### chain-builder
- **description:** Exploit chain builder. Takes confirmed bug A and systematically finds B and C to chain for higher severity. Covers IDOR→auth bypass, SSRF→cloud metadata, XSS→ATO, open redirect→OAuth theft, S3→bundle→secret→OAuth, prompt injection→IDOR, subdomain takeover→OAuth.
- **tools:** Read, Bash, WebFetch
- **model:** claude-sonnet-4-6
- **file:** agents/chain-builder.md
- **invoke:** "Chain IDOR with auth bypass for higher severity"

### js-analysis
- **description:** JavaScript bundle analysis specialist. Extracts hidden API endpoints, hardcoded secrets, internal paths, feature flags, cloud keys, OAuth credentials, and configuration leaks from JS bundles. Supports browser DevTools and CLI-based extraction.
- **tools:** Read, Write, Bash, Glob, Grep, WebFetch
- **model:** claude-sonnet-4-6
- **file:** agents/js-analysis.md
- **invoke:** "Analyze JS bundles for secrets on target.com"

### js-deobfuscation
- **description:** JavaScript deobfuscation and reverse engineering specialist. Reverses minified/obfuscated JS bundles to recover hidden endpoints, secrets, and logic. Handles webpack bundles, obfuscated strings, encoded payloads, eval-based obfuscation, and VM-protected code.
- **tools:** Read, Write, Bash, Glob, Grep, WebFetch
- **model:** claude-sonnet-4-6
- **file:** agents/js-deobfuscation.md
- **invoke:** "Deobfuscate this JavaScript bundle"

### report-writer
- **description:** Professional bug bounty report writer. Generates HackerOne, Bugcrowd, Intigriti, and Immunefi reports. Impact-first writing, no theoretical language, CVSS 4.0 calculation included. Never uses 'could potentially' language.
- **tools:** Read, Write, Bash
- **model:** claude-opus-4-6
- **file:** agents/report-writer.md
- **invoke:** "Write report for IDOR finding on target.com"

### validator
- **description:** Finding validator that runs the 7-Question Gate and 4-gate checklist. Kills weak/theoretical findings fast before report writing. Prevents N/A submissions. Can PASS, KILL, DOWNGRADE, or CHAIN REQUIRED a finding.
- **tools:** Read, Bash, WebFetch
- **model:** claude-sonnet-4-6
- **file:** agents/validator.md
- **invoke:** "Validate this IDOR finding before I write a report"

### autopilot
- **description:** Autonomous hunt loop agent. Runs full cycle (scope → recon → rank → hunt → validate → report) without stopping for approval at each step. Configurable checkpoints (--paranoid, --normal, --yolo). Logs all requests to audit.jsonl.
- **tools:** Bash, Read, Write, Glob, Grep
- **model:** claude-sonnet-4-6
- **file:** agents/autopilot.md
- **invoke:** "Run autopilot on target.com in normal mode"

### exploit-researcher
- **description:** Vulnerability research agent. Identifies CVEs, finds exploit PoCs, maps attack chains, develops custom exploitation strategies. Covers NVD API, GitHub Advisories, Exploit-DB, CISA KEV.
- **tools:** Read, Write, Bash, Glob, Grep, WebFetch
- **model:** claude-opus-4-6
- **file:** agents/exploit-researcher.md
- **invoke:** "Research CVEs for nginx 1.24"

### network-analyst
- **description:** Deep network analysis agent. Packet inspection, protocol dissection, traffic anomaly detection, IDS/IPS rule creation, firewall auditing. Covers TCP/IP, DNS, TLS, HTTP/2/3, SMB, Kerberos.
- **tools:** Read, Write, Bash, Glob, Grep
- **model:** claude-sonnet-4-6
- **file:** agents/network-analyst.md
- **invoke:** "Analyze this packet capture for anomalies"

### redteam-planner
- **description:** Red team engagement planner. Designs attack paths, C2 infrastructure, persistence strategies, and OPSEC considerations. MITRE ATT&CK mapped. Covers recon, initial access, execution, persistence, privilege escalation, defense evasion, lateral movement.
- **tools:** Read, Write, Bash, Glob, Grep, WebFetch
- **model:** claude-opus-4-6
- **file:** agents/redteam-planner.md
- **invoke:** "Plan red team engagement for target company"

### reverse-engineer
- **description:** Binary analysis and reverse engineering specialist. Static/dynamic analysis, vulnerability discovery in compiled code, firmware analysis, protocol reverse engineering. Uses IDA Pro, Ghidra, radare2, Frida, angr, z3.
- **tools:** Read, Write, Bash, Glob, Grep
- **model:** claude-opus-4-6
- **file:** agents/reverse-engineer.md
- **invoke:** "Analyze this binary for vulnerabilities"

### security-reviewer
- **description:** Deep security audit agent. Reviews code and architecture against OWASP Top 10, CWE Top 25. Language-specific patterns for JavaScript, Python, Ruby, Java, C#, Go. Trust boundary and data flow analysis.
- **tools:** Read, Write, Bash, Glob, Grep
- **model:** claude-opus-4-6
- **file:** agents/security-reviewer.md
- **invoke:** "Review this code for security vulnerabilities"

### ai-researcher
- **description:** AI/ML security research specialist. LLM red-teaming, prompt injection testing, model architecture analysis, training optimization, safety alignment. Covers direct/indirect injection, system prompt extraction, jailbreak techniques.
- **tools:** Read, Write, Bash, Glob, Grep, WebFetch
- **model:** claude-opus-4-6
- **file:** agents/ai-researcher.md
- **invoke:** "Test this LLM endpoint for prompt injection"

### token-auditor
- **description:** Meme coin and token security auditor. Checks 8 token-specific bug classes: hidden mint, honeypot, fee manipulation, LP drain, bonding curve exploits, authority retention, fake renounce, sandwich/MEV amplification. EVM + Solana.
- **tools:** Read, Bash, Glob, Grep
- **model:** claude-sonnet-4-6
- **file:** agents/token-auditor.md
- **invoke:** "Audit this meme coin for rug pull vectors"

### web3-auditor
- **description:** Smart contract security auditor. Checks 10 bug classes: accounting desync, access control, incomplete path, off-by-one, oracle errors, ERC4626 attacks, reentrancy, flash loan oracle manipulation, signature replay, proxy issues.
- **tools:** Read, Bash, Glob, Grep
- **model:** claude-sonnet-4-6
- **file:** agents/web3-auditor.md
- **invoke:** "Audit this smart contract for vulnerabilities"
