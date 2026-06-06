# External Reference Library

When the in-tool methodology runs short, these upstream collections are the
ones to mirror or grep next. They are pulled from the project owner's
GitHub stars list — high-signal repos curated by working bounty hunters.

## Methodology / playbooks

| Repo | Use it for |
|---|---|
| `KathanP19/HowToHunt` | Per-vuln-class methodology checklists (IDOR, race, SSRF, OAuth, GraphQL, business logic) |
| `HolyBugx/HolyTips` | Notes + writeups + per-class checklists |
| `daffainfo/AllAboutBugBounty` | Big bypass + payload reference, organised by class |
| `KingOfBugbounty/KingOfBugBountyTips` | One-line recon recipes from named hunters |
| `dwisiswant0/awesome-oneliner-bugbounty` | Bash/awk one-liners for rapid recon and triage |
| `nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters` | Broad starter library |
| `OWASP/wstg` | OWASP Web Security Testing Guide — definitive coverage matrix |
| `0xRadi/OWASP-Web-Checklist` | Compressed WSTG checklist for tracking coverage during a hunt |
| `aufzayed/HowToHunt`, `sehno/Bug-bounty` | Additional case studies |

## Disclosed reports & writeups

| Repo | Use it for |
|---|---|
| `devanshbatham/Awesome-Bugbounty-Writeups` | Categorised writeups by vuln class |
| `ngalongc/bug-bounty-reference` | Same idea, older but exhaustive |
| `B3nac/Android-Reports-and-Resources` | Big list of Android H1 disclosures |
| `arkadiyt/bounty-targets-data` | Hourly dump of every public scope (H1/Bugcrowd/Intigriti/YWH/Immunefi) |

## Tool catalogues

| Repo | Use it for |
|---|---|
| `vavkamil/awesome-bugbounty-tools` | Curated tool list, broader than this plugin |
| `hahwul/WebHackersWeapons` | Same, with maturity tags |
| `edoardottt/awesome-hacker-search-engines` | Shodan/Censys/etc. alternatives |
| `qazbnm456/awesome-web-security` | Long-form learning resources |
| `arainho/awesome-api-security` | API-specific tools and references |
| `4ndersonLin/awesome-cloud-security` | Cloud-specific tools and references |
| `wong2/awesome-mcp-servers` | MCP server registry — additional servers to wire in |
| `awesome-android-root/awesome-android-root` | Android tooling |

## Dorking / OSINT

| Repo | Use it for |
|---|---|
| `cipher387/Dorks-collections-list` | Master index of dork collections |
| `sushiwushi/bug-bounty-dorks` | Dorks for sites with disclosure programs |
| `techgaun/github-dorks` | Find leaked secrets via GitHub search |
| `obheda12/GitDorker` | Automated GitHub dork scraper |
| `streaak/keyhacks` | How to **verify** every leaked key class (this is the hard part) |

## Subdomain takeover

| Repo | Use it for |
|---|---|
| `EdOverflow/can-i-take-over-xyz` | Authoritative fingerprint + claim-instructions list |
| `punk-security/dnsReaper` | Best-in-class scanner (already wrapped in `tools/takeover_scanner.sh`) |
| `vincentcox/bypass-firewalls-by-DNS-history` | DNS-history origin-IP lookup |
| `m0rtem/CloudFail` | CloudFlare-specific origin discovery |
| `spyboy-productions/CloakQuest3r` | CloudFlare/Sucuri origin IP exposure |

## API key verification

When you find a leaked secret you must prove it works. `streaak/keyhacks` shows
the right curl-one-liner per provider (AWS / Stripe / Slack / Twilio / ...).

## AI / agentic-security skills (cross-pollination)

| Repo | Idea worth borrowing |
|---|---|
| `mukul975/Anthropic-Cybersecurity-Skills` | 754 cybersecurity skills mapped to MITRE ATT&CK / NIST CSF |
| `SnailSploit/Claude-Red` | Curated offensive-security skills for the Claude skills system |
| `0xSteph/pentest-ai-agents` | Specialised Claude Code agents for offsec research |
| `BehiSecc/bugSkills` | Tooling to convert disclosed reports into reusable skills |
| `pikpikcu/airecon` | Self-hosted LLM + tool-router pattern for autonomous recon |
| `Armur-Ai/Pentest-Swarm-AI` | Swarm-of-agents pattern for full-pipeline pentest |
| `BugTraceAI/reconftw-mcp` | reconftw exposed as an MCP server |
| `naebo/mcp-external-recon-server` | External-recon MCP server |

---

## ADVANCED METHODOLOGY RESOURCES

### Reconnaissance Frameworks

| Resource | What It Covers | URL |
|----------|---------------|-----|
| OWASP WSTG | Full web app testing methodology | https://owasp.org/www-project-web-security-testing-guide/ |
| OWASP ASVS | Application security verification standard | https://owasp.org/www-project-application-security-verification-standard/ |
| PTES | Penetration testing execution standard | http://www.pentest-standard.org/ |
| NIST SP 800-115 | Technical guide to information security testing | https://csrc.nist.gov/publications/detail/sp/800-115/final |
| OSSTMM | Open source security testing methodology manual | https://www.isecom.org/OSSTMM.3.pdf |

### Bug Bounty Specific Methodologies

| Resource | What It Covers |
|----------|---------------|
| `KathanP19/HowToHunt` | Per-vuln-class methodology checklists |
| `HolyBugx/HolyTips` | Notes + writeups + per-class checklists |
| `daffainfo/AllAboutBugBounty` | Bypass + payload reference, organized by class |
| `KingOfBugbounty/KingOfBugBountyTips` | One-line recon recipes from named hunters |
| `dwisiswant0/awesome-oneliner-bugbounty` | Bash/awk one-liners for rapid recon |
| `nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters` | Broad starter library |
| `0xRadi/OWASP-Web-Checklist` | Compressed WSTG checklist for tracking coverage |

### Reconnaissance Tool References

| Tool Category | Primary Tools | Alternatives |
|--------------|---------------|--------------|
| Subdomain enum | subfinder, assetfinder, amass, findomain | sublist3r, oneforall |
| DNS | dnsx, massdns, dnsrecon | fierce, dnsenum |
| HTTP probing | httpx, httpstat, curl | httpie, wget |
| Crawling | katana, hakrawler, gospider | gobuster dir, dirsearch |
| URL mining | waybackurls, gau, waymore | urlfinder, otx-urls |
| Screenshot | aquatone, eyewitness, webscreenshot | chromatin, webkit2png |
| JS analysis | jsluice, SecretFinder, LinkFinder | burp JS miner, retire.js |

### Payload Reference Repos

| Repo | Use It For |
|------|-----------|
| `swisskyrepo/PayloadsAllTheThings` | Comprehensive payload reference for every vuln class |
| `danielmiessler/SecLists` | Wordlists for discovery and fuzzing |
| `fuzzdb-project/fuzzdb` | Attack payloads and fuzzing test cases |
| `tennc/webshell` | Web shells for post-exploitation (authorized only) |
| `foospidy/payloads` | Miscellaneous payloads |
| `AlessandroZ/LaZagneProject` | Credential recovery (authorized only) |
| `mzet-/linux-exploit-suggester` | Linux kernel exploit suggestions |
| `codingo/Interlace` | Multi-threaded payload delivery |

### Learning Platforms

| Platform | Focus | URL |
|----------|-------|-----|
| PortSwigger Web Academy | Web security labs (best free resource) | https://portswigger.net/web-security |
| HackTheBox | Enterprise pentest simulation | https://www.hackthebox.com/ |
| TryHackMe | Guided learning paths | https://tryhackme.com/ |
| PentesterLab | Web app pentest exercises | https://pentesterlab.com/ |
| Root Me | Web app challenge platform | https://www.root-me.org/ |
| Cryptohack | Crypto/Web3 challenges | https://cryptohack.org/ |
| Ethernaut | Smart contract hacking | https://ethernaut.openzeppelin.com/ |
| Damn Vulnerable DeFi | DeFi exploit challenges | https://www.damnvulnerabledefi.io/ |
| Google Gruyere | Vulnerable web app by Google | https://google-gruyere.appspot.com/ |
| OWASP Juice Shop | Modern vulnerable web app | https://owasp.org/www-project-juice-shop/ |

### Writeup Collections

| Repo | Use It For |
|------|-----------|
| `devanshbatham/Awesome-Bugbounty-Writeups` | Categorized writeups by vuln class |
| `ngalongc/bug-bounty-reference` | Exhaustive writeup collection |
| `B3nac/Android-Reports-and-Resources` | Android H1 disclosures |
| `arkadiyt/bounty-targets-data` | Hourly dump of public scopes |
| `tredeske/UselessHackersWriteups` | Curated writeup collection |
| `nahamsec/recon-profile` | Recon methodology writeups |

### Disclosure Platforms

| Platform | Focus | URL |
|----------|-------|-----|
| HackerOne | General bug bounty | https://hackerone.com/ |
| Bugcrowd | Crowdsourced security | https://bugcrowd.com/ |
| Intigriti | European bug bounty | https://www.intigriti.com/ |
| Synack | Invitation-only | https://www.synack.com/ |
| Open Bug Bounty | Coordinated disclosure | https://www.openbugbounty.org/ |
| YesWeHack | European platform | https://www.yeswehack.com/ |
| Immunefi | Web3/DeFi bounties | https://immunefi.com/ |
| CodeHaven | Open source bounties | https://codehaven.org/ |

### Subdomain Takeover Resources

| Resource | Use It For |
|----------|-----------|
| `EdOverflow/can-i-take-over-xyz` | Fingerprints + claim instructions |
| `punk-security/dnsReaper` | Subdomain takeover scanner |
| `michenriksen/aquatone` | Subdomain discovery + screenshot |
| `m0rtem/CloudFail` | CloudFlare origin IP discovery |
| `spyboy-productions/CloakQuest3r` | CloudFlare/Sucuri origin exposure |
| `blechschmidt/massdns` | Bulk DNS resolution |
| `dwisiswant0/subfinder` | Passive subdomain enumeration |

### API Security Resources

| Resource | Use It For |
|----------|-----------|
| `arainho/awesome-api-security` | API-specific tools and references |
| OWASP API Security Top 10 | API vulnerability classification | https://owasp.org/www-project-api-security/ |
| `apisecurity.io` | API security news and articles |
| `postman-learning` | API testing tutorials |

### Cloud Security Resources

| Resource | Use It For |
|----------|-----------|
| `4ndersonLin/awesome-cloud-security` | Cloud security tools |
| `awesome-android-root/awesome-android-root` | Android tooling |
| `arkadiyt/aws_iam_enum` | AWS IAM enumeration |
| `dafthack/CloudPentestCheatsheets` | AWS/Azure/GCP pentest cheat sheets |
| `RhinoSecurityLabs/pacu` | AWS penetration testing framework |
| `nccgroup/ScoutSuite` | Multi-cloud auditing |
| `toniblyx/prowler` | AWS security auditing |

### Mobile Security Resources

| Resource | Use It For |
|----------|-----------|
| `B3nac/Android-Reports-and-Resources` | Android H1 disclosures |
| `OWASP/mobile-security-testing-guide` | Mobile app testing methodology |
| `MobSF/Mobile-Security-Framework-MobSF` | Mobile app security analysis |
| `WithSecureLabs/needle` | iOS penetration testing |
| `danb35/iOSpentest` | iOS pentest guide |
| `androidsecurity/bugs-server` | Android bug bounty writeups |

### OSINT Resources

| Resource | Use It For |
|----------|-----------|
| `cipher387/Dorks-collections-list` | Master index of dork collections |
| `sushiwushi/bug-bounty-dorks` | Dorks for disclosure programs |
| `techgaun/github-dorks` | Find leaked secrets via GitHub search |
| `obheda12/GitDorker` | Automated GitHub dork scraper |
| `streaak/keyhacks` | Verify leaked key classes |
| `thehackingsage/hacks` | Recon scripts and dorks |
| `s0md3v/Photon` | Fast web crawler for OSINT |

### AI / Agentic Security Resources

| Resource | Use It For |
|----------|-----------|
| `mukul975/Anthropic-Cybersecurity-Skills` | 754 skills mapped to MITRE ATT&CK/NIST |
| `SnailSploit/Claude-Red` | Offensive security skills for Claude |
| `0xSteph/pentest-ai-agents` | Specialized Claude Code agents |
| `BehiSecc/bugSkills` | Convert reports to reusable skills |
| `pikpikcu/airecon` | Self-hosted LLM + tool-router |
| `Armur-Ai/Pentest-Swarm-AI` | Swarm-of-agents pattern |
| `BugTraceAI/reconftw-mcp` | reconftw as MCP server |
| `naebo/mcp-external-recon-server` | External-recon MCP server |
| `ente0/mcpstrike` | Pentest tool MCP server |
| `OWASP/owasp-top-10-for-large-language-model-applications` | LLM security guide |

### Web3 / Smart Contract Resources

| Resource | Use It For |
|----------|-----------|
| `Consensys/smart-contract-best-practices` | Solidity security guide |
| `OpenZeppelin/openzeppelin-contracts` | Secure contract implementations |
| `trailofbits/not-so-smart-contracts` | Common vulnerability examples |
| `OpenZeppelin/awesome-solidity-security` | Curated security resources |
| `swcregistry/swc | Smart contract weakness classification |
| `immunefi/immunefi-bug-bounty-basics` | Web3 bug bounty guide |
| `solodit/cyfrin/solodit | 50K+ searchable audit findings |
| `rekt.news` | DeFi hack analysis |

### CTF and Practice Resources

| Resource | Focus |
|----------|-------|
| PortSwigger Web Academy | Web security labs |
| HackTheBox | Enterprise pentest |
| TryHackMe | Guided learning |
| Root Me | Web app challenges |
| Cryptohack | Crypto/Web3 |
| OverTheWire | Wargames |
| picoCTF | Beginner CTF |
| CTFtime | CTF event calendar |

### Vulnerability Databases

| Database | URL |
|----------|-----|
| CVE | https://cve.mitre.org/ |
| NVD | https://nvd.nist.gov/ |
| CISA KEV | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| Exploit-DB | https://www.exploit-db.com/ |
| Snyk Vulnerability DB | https://security.snyk.io/ |
| GitHub Advisory | https://github.com/advisories |

---

## QUICK REFERENCE: TOOL INSTALLATION

### Go Tools

```bash
# Reconnaissance
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gau@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/tomnomnom/gf@latest
go install github.com/eth0izzle/sl0t/jsluice/cmd/jsluice@latest
go install github.com/assetnote/kiterunner/cmd/kr@latest
go install github.com/LukaSikic/subzy/cmd/subzy@latest

# Update nuclei templates
nuclei -update
```

### Python Tools

```bash
# Core scanning
pip3 install arjun
pip3 install paramspider
pip3 install cloud_enum
pip3 install semgrep
pip3 install pyjwt[crypto]
pip3 install secretfinder
pip3 install linkfinder
pip3 install xsstrike
pip3 install jsscanner
pip3 install mitmproxy
pip3 install aiohttp
pip3 install requests-ntlm

# Nuclei templates (if needed)
pip3 install nuclei-templates
```

### Node.js Tools

```bash
# Core scanning
npm3 install -g retire
npm3 install -g js-beautify
npm3 install -g webpack-deobfuscator
npm3 install -g @babel/cli
npm3 install -g prettier

# Burp extensions (via BApp Store)
# - HTTP Request Smuggler
# - JSON Web Token Attacker (JOSEPH)
# - Autorize
# - Retire.js
# - Parameter Miner
```

---

## FINAL NOTE

This reference library is designed to be used alongside the security-arsenal skill. When you need more depth on any topic, the linked resources provide comprehensive coverage. The best hunters read these regularly and build their own notes on top of them.

**Pro tip:** Clone these repos locally and grep them when you need specific payloads or techniques. Having them offline means you can reference them during assessments without internet connectivity.
| `ente0/mcpstrike` | Pentest tool MCP server + Ollama autonomous client |
