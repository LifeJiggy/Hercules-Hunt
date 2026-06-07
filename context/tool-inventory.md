# Tool Inventory

Complete catalog of all tools, agents, skills, and configurations in the Hercules-Hunt project.

---

## Table of Contents

1. [Python Modules (17)](#1-python-modules)
2. [PowerShell Tools](#2-powershell-tools)
3. [OpenCode Agents](#3-opencode-agents)
4. [Skills Registry](#4-skills-registry)
5. [Hook Configurations](#5-hook-configurations)
6. [Context Files](#6-context-files)
7. [Config Files](#7-config-files)
8. [Agent Integration Matrix](#8-agent-integration-matrix)
9. [Tool Dependency Graph](#9-tool-dependency-graph)
10. [Quick Reference](#10-quick-reference)

---

## 1. Python Modules

| Module | Type | Bug Classes | Methods | CLI |
|--------|------|-------------|---------|-----|
| `rce_hunter.py` | P1 | RCE, CMDi, SSTI, deser | 25+ | `--cmd`, `--output` |
| `sqli_hunter.py` | P1 | SQLi, NoSQLi, JSONi | 22+ | `<url>`, `--output` |
| `idor_hunter.py` | P1 | IDOR, mass assignment | 24+ | `<url>`, `--output` |
| `auth_hunter.py` | P1 | JWT, OAuth, MFA, CSRF | 20+ | `--jwt`, `--output` |
| `ssrf_hunter.py` | P1 | SSRF, cloud metadata | 22+ | `--param`, `--output` |
| `xxe_hunter.py` | P1 | XXE, OOB, SVG, SOAP | 20+ | `<endpoint>`, `--output` |
| `file_upload_hunter.py` | P1 | Upload RCE, XSS, XXE | 22+ | `<endpoint>`, `--output` |
| `python-hunter.py` | Core | Orchestrator | 25+ | `pipeline`, `menu` |
| `js_analyzer.py` | Core | JS analysis | 15+ | `<js_url>` |
| `url_collector.py` | Core | URL crawling | 10+ | `<target>` |
| `endpoint_fuzzer.py` | Core | Fuzzing | 10+ | `<target>` |
| `base64_utils.py` | Core | Encoding | 8+ | `encode`/`decode` |
| `batch_processor.py` | Core | Batch scan | 12+ | `--file` |
| `report_builder.py` | Core | Reports | 10+ | `<findings.json>` |
| `secret_scanner.py` | Core | Secrets | 30+ | `<path>` |
| `payload_generator.py` | Core | Payloads | 20+ | `--type` |
| `network_utils.py` | Core | Network | 15+ | `<domain>` |

## 2. PowerShell Tools

| Tool | Purpose | Key Features |
|------|---------|-------------|
| `powershell-lib.ps1` | Core library | HTTP helpers, logging, JSON export |
| `recon-toolkit.ps1` | Recon | Subdomain enum, DNS, cert, port scan |
| `curl-hunter.ps1` | Request testing | Parameter fuzzing, auth testing |
| `js-analyzer.ps1` | JS analysis | Endpoint extraction, secret grep |

## 3. OpenCode Agents

| Agent | Model | Purpose | Invoke |
|-------|-------|---------|--------|
| recon-agent | claude-haiku | Subdomain enum, live host, fingerprint | "Run recon on target.com" |
| recon-ranker | claude-haiku | Prioritize attack surface | "Rank attack surface for target.com" |
| p1-warrior | claude-sonnet | Systematic P1 bug hunting | "Hunt target.com for high vulns" |
| chain-builder | claude-sonnet | Exploit chain construction | "Chain IDOR with auth bypass" |
| js-analysis | claude-sonnet | JS bundle analysis | "Analyze JS bundles on target.com" |
| js-deobfuscation | claude-sonnet | Reverse obfuscated JS | "Deobfuscate this JS bundle" |
| report-writer | claude-opus | Professional bug reports | "Write report for IDOR finding" |
| validator | claude-sonnet | 7-Question Gate validation | "Validate this IDOR finding" |
| autopilot | claude-sonnet | Autonomous hunt loop | "Run autopilot on target.com" |
| exploit-researcher | claude-opus | CVE/PoC research | "Research CVEs for nginx 1.24" |
| network-analyst | claude-sonnet | Packet / protocol analysis | "Analyze this packet capture" |
| redteam-planner | claude-opus | Engagement planning | "Plan red team engagement" |
| reverse-engineer | claude-opus | Binary analysis | "Analyze this binary" |
| security-reviewer | claude-opus | Code security audit | "Review this code for vulns" |
| ai-researcher | claude-opus | LLM red-teaming | "Test LLM endpoint for injection" |
| token-auditor | claude-sonnet | Meme coin audit | "Audit this meme coin" |
| web3-auditor | claude-sonnet | Smart contract audit | "Audit this smart contract" |

## 4. Skills Registry

| Skill | Purpose |
|-------|---------|
| bb-local-toolkit | Complete bug bounty workflow (CN/EN) |
| bb-methodology | 5-phase non-linear hunting workflow |
| osint-methodology | 5-stage recon pipeline, 29 asset types |
| offensive-osint | Concrete probes, dorks, curl one-liners |
| web2-recon | Subdomain enum, URL crawl, JS analysis |
| web2-vuln-classes | 20 web2 bug class reference |
| web3-audit | DeFi audit methodology |
| hunt-* (20 skills) | Per-bug-class hunting guides |
| report-writing | Bug bounty report templates |
| triage-validation | 7-Question Gate + 4 validation gates |
| evidence-hygiene | PoC redaction, HAR sanitization |
| supply-chain-attack-recon | Package squatting, dep confusion |
| cloud-iam-deep | AWS/Azure/GCP IAM escalation |
| m365-entra-attack | M365 credential attack chains |
| okta-attack | Okta-as-IdP attack chain |
| enterprise-vpn-attack | SSL VPN appliance CVE matrix |
| vmware-vcenter-attack | vCenter external attack matrix |
| hunt-sharepoint | SharePoint on-prem attack surface |
| hunt-aspnet | ASP.NET ViewState, WCF, machineKey |
| apk-redteam-pipeline | Android APK decompile + grep |
| meme-coin-audit | Token rug pull detection |
| redteam-mindset | Operator discipline corrections |
| redteam-report-template | Client-facing deliverable format |
| mid-engagement-ir-detection | SOC detection during engagement |
| customize-opencode | OpenCode configuration editing |

## 5. Hook Configurations

| Hook File | Agent | Trigger |
|-----------|-------|---------|
| `recon-agent-hooks.json` | recon-agent | Post-recon actions |
| `recon-ranker-hooks.json` | recon-ranker | After ranking complete |
| `p1-warrior-hooks.json` | p1-warrior | Post-hunt actions |
| `js-analysis-hooks.json` | js-analysis | After JS analysis |
| `autopilot-hooks.json` | autopilot | Autonomous loop hooks |
| `security-reviewer-hooks.json` | security-reviewer | Post-review actions |

## 6. Current Tool Status

```
Python Modules: 17/17 complete
PowerShell Tools: 4/4 complete
OpenCode Agents: 17/17 registered
Skills: 30+ loaded
Hooks: 6/6 configured
Context Files: 7/7 complete
Config Files: 6/6 configured
```

---

*End of tool-inventory.md*
